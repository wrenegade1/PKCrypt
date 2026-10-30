"""PKCrypt: encrypt files so that only the holder of an Ed25519 SSH private
key can decrypt them, using the same public/private key model as SSH.

Author: Warren Zajac

Design
------
A sender encrypts a file using only the recipient's *public* Ed25519 key
(``id_ed25519.pub``). The encrypted payload can only be decrypted by the
recipient's *private* key (``id_ed25519``). It is a hybrid scheme:

1. The OpenSSH Ed25519 key is converted to an X25519 key using the exact,
   OpenSSH-compatible conversions from libsodium
   (``crypto_sign_ed25519_{pk,sk}_to_curve25519``).
2. The *sender* generates a fresh ephemeral X25519 keypair and performs Elliptic
   Curve Diffie-Hellman (ECDH) with the recipient's converted public key to
   derive a shared secret.
3. The shared secret is expanded with HKDF-SHA256 into a 32-byte key that
   encrypts the file with an authenticated AEAD cipher.
4. The output contains the ephemeral public key, a base nonce, and the cipher
   identifier alongside the ciphertext. Only the holder of the recipient's
   private key can recompute the shared secret and decrypt the file.

Container format (v2, interoperable with the C++ pkcrypt binary)
---------------------------------------------------------------
Encrypting produces a *chunked* v2 container so arbitrarily large files stream
through memory without being loaded whole, and the header is authenticated:

    header:
      magic      8 bytes   b"PKCRYPT\\x02"
      cipher     1 byte    0x00 = AES-256-GCM  |  0x01 = XChaCha20-Poly1305
      payload    1 byte    0x00 = single file  |  0x01 = ZIP archive (a folder)
      eph_pub   32 bytes   sender's ephemeral X25519 public key
      nonce     12 | 24 B  base AEAD nonce (12 for AES-GCM, 24 for XChaCha20)
      chunk_len  4 bytes   max plaintext bytes per chunk, big-endian
    payload:
      chunks     each AEAD ciphertext = (chunk plaintext bytes + auth tag)

The plaintext is split into ``chunk_len``-byte chunks. Every chunk but the last
is exactly ``chunk_len`` bytes; the last holds the remaining 0..chunk_len bytes
(so an empty file is one empty chunk, and there is always at least one chunk).
Each chunk is encrypted with the SAME key but a DIFFERENT nonce: chunk ``i``'s
nonce is the base nonce with its final 4 bytes set to the big-endian chunk
index. Each chunk's *associated data* (AAD) is the header followed by one flag
byte, ``0x01`` for the last chunk and ``0x00`` otherwise. So tampering with any
header field fails the authentication tag, and so does truncating or extending
the payload at a chunk boundary (the new last chunk was not sealed as final).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__version__ = "2.0.0"


# ---------------------------------------------------------------------------
# libsodium bindings for the Ed25519 -> X25519 *public* key conversion.
#
# The public-key conversion (Ed25519 -> X25519) uses libsodium's reference
# OpenSSH-compatible math. The *private*-key conversion does NOT need libsodium:
# the X25519 private key is simply SHA-512(seed)[0:32] bit-clamped (RFC 8032),
# computed below in pure Python. We still load libsodium for the public
# conversion, located robustly via ctypes.util.find_library("sodium").
# ---------------------------------------------------------------------------


def _candidate_library_names():
    """Yield candidate libsodium library names / paths."""
    found = ctypes.util.find_library("sodium")
    if found:
        yield found
    yield from [
        "/opt/homebrew/opt/libsodium/lib/libsodium.dylib",
        "/usr/local/lib/libsodium.dylib",
        "/usr/lib/libsodium.dylib",
        "libsodium.dylib",
        "libsodium.so.23",
        "libsodium.so",
    ]


def _load_libsodium():
    tried = []
    for name in _candidate_library_names():
        tried.append(name)
        for cand in (name, name + ".dylib", str(name) + ".so"):
            try:
                return ctypes.CDLL(cand)
            except OSError:
                continue
    raise ImportError(
        "libsodium is required for the Ed25519->X25519 public-key conversion. "
        f"Tried: {', '.join(tried)}. Install it with: brew install libsodium"
    )


_lib = _load_libsodium()

# int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
#                                           const unsigned char *ed25519_pk)
_pk_to_curve = _lib.crypto_sign_ed25519_pk_to_curve25519
_pk_to_curve.restype = ctypes.c_int
_pk_to_curve.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

# --- XChaCha20-Poly1305 (IETF) via libsodium ctypes -------------------------
# The `cryptography` package does not expose XChaCha20-Poly1305 (24-byte
# nonce), so we bind libsodium's implementation directly. This is byte-for-byte
# what the C++ binary uses (crypto_aead_xchacha20poly1305_ietf_*).
_AEAD_ABYTES = 16

_xc_encrypt = _lib.crypto_aead_xchacha20poly1305_ietf_encrypt
_xc_encrypt.restype = ctypes.c_int
_xc_encrypt.argtypes = [
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.c_char_p, ctypes.c_ulonglong,
    ctypes.c_char_p, ctypes.c_ulonglong,
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
]

_xc_decrypt = _lib.crypto_aead_xchacha20poly1305_ietf_decrypt
_xc_decrypt.restype = ctypes.c_int
_xc_decrypt.argtypes = [
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.c_char_p,          # nsec (unused; pass None)
    ctypes.c_char_p, ctypes.c_ulonglong,
    ctypes.c_char_p, ctypes.c_ulonglong,
    ctypes.c_char_p, ctypes.c_char_p,
]


def _xchacha20_encrypt(nonce: bytes, data: bytes, aad: bytes, key: bytes) -> bytes:
    c = ctypes.create_string_buffer(len(data) + _AEAD_ABYTES)
    clen = ctypes.c_ulonglong(0)
    rc = _xc_encrypt(c, ctypes.byref(clen), data, len(data), aad, len(aad),
                     None, nonce, key)
    if rc != 0:
        raise ValueError("XChaCha20-Poly1305 encryption failed")
    return c.raw[:clen.value]


def _xchacha20_decrypt(nonce: bytes, ciphertext: bytes, aad: bytes, key: bytes) -> bytes:
    m = ctypes.create_string_buffer(max(1, len(ciphertext) - _AEAD_ABYTES))
    mlen = ctypes.c_ulonglong(0)
    rc = _xc_decrypt(m, ctypes.byref(mlen), None, ciphertext, len(ciphertext),
                     aad, len(aad), nonce, key)
    if rc != 0:
        raise ValueError(DECRYPT_FAILED)
    return m.raw[:mlen.value]

DECRYPT_FAILED = ("decryption failed: file is not for this private key, "
                  "or it was tampered with or truncated")

_ED_PUBLIC_BYTES = 32


def ed25519_public_to_x25519_public(ed_public: bytes) -> bytes:
    """Convert a 32-byte Ed25519 public key to a 32-byte X25519 public key."""
    if len(ed_public) != _ED_PUBLIC_BYTES:
        raise ValueError("Ed25519 public key must be 32 bytes")
    out = ctypes.create_string_buffer(_ED_PUBLIC_BYTES)
    rc = _pk_to_curve(out, ed_public)
    if rc != 0:
        raise ValueError("conversion of Ed25519 public key failed")
    return out.raw


def ed25519_private_to_x25519_private(seed: bytes, ed_public: bytes) -> bytes:
    """Convert an Ed25519 seed to an X25519 private key, in pure Python.

    This is the standard Ed25519 derivation (RFC 8032): X25519 private key =
    SHA-512(seed)[0:32] with the usual X25519 clamping. It matches libsodium's
    ``crypto_sign_ed25519_sk_to_curve25519`` over the seed||pub secret key, so
    no libsodium call is needed for decryption key derivation. ``ed_public`` is
    accepted (and validated) for signature compatibility only.
    """
    if len(seed) != _ED_PUBLIC_BYTES or len(ed_public) != _ED_PUBLIC_BYTES:
        raise ValueError("Ed25519 seed and public key must each be 32 bytes")
    h = hashlib.sha512(seed).digest()
    curve_sk = bytearray(h[:32])
    curve_sk[0] &= 248
    curve_sk[31] &= 127
    curve_sk[31] |= 64
    return bytes(curve_sk)


# ---------------------------------------------------------------------------
# Hybrid encryption
# ---------------------------------------------------------------------------

# v2 container layout:
#   magic       8 bytes   b"PKCRYPT\x02"
#   cipher      1 byte    AES-256-GCM (0x00) or XChaCha20-Poly1305 (0x01)
#   payload     1 byte    single file (0x00) or ZIP archive of a folder (0x01)
#   eph_pub    32 bytes   sender's ephemeral X25519 public key
#   nonce      12 | 24 B  base AEAD nonce
#   chunk_len   4 bytes   max plaintext bytes per chunk, big-endian
#   payload    chunks     per-chunk AEAD ciphertext + auth tag; always >= 1
#
# Each chunk's AAD is header || final_flag (0x00, or 0x01 for the last chunk).
_MAGIC = b"PKCRYPT\x02"
_MAGIC_BYTES = len(_MAGIC)            # 8
_CIPHER_BYTES = 1
_PAYLOAD_BYTES = 1
_EPH_PUB_BYTES = 32
_CHUNK_LEN_BYTES = 4
_NONCE_AES = 12
_NONCE_XC = 24
_TAG_BYTES = 16

_CIPHER_AES = 0x00
_CIPHER_XCHACHA20 = 0x01

PAYLOAD_FILE = 0x00                 # plaintext is one file's bytes
PAYLOAD_ARCHIVE = 0x01              # plaintext is a ZIP archive of a folder
_PAYLOAD_TYPES = (PAYLOAD_FILE, PAYLOAD_ARCHIVE)
_PREFIX_BYTES = _MAGIC_BYTES + _CIPHER_BYTES + _PAYLOAD_BYTES

_FLAG_MORE = b"\x00"
_FLAG_FINAL = b"\x01"

DEFAULT_CHUNK_LEN = 1 << 20         # 1 MiB of plaintext per chunk
# Largest chunk_len accepted when encrypting or decrypting. A decryptor buffers
# one chunk and chunk_len comes from the (untrusted) header, so a larger value
# is rejected rather than allocated. PKCrypt writes 1 MiB chunks. Matches
# MAX_ACCEPTED_CHUNK_LEN in the C++ implementation.
_MAX_CHUNK_LEN = 16 * 1024 * 1024
_MAX_CHUNKS = 1 << 32               # 4-byte big-endian chunk index

HKDF_SALT = b"PKCrypt"
HKDF_INFO_V2 = b"PKCrypt/v2/x25519-ecdh+aead"

_READ_SIZE = 1 << 20                # bytes per read() when given a file object


def _derive_key(shared_secret: bytes, eph_pub: bytes, recipient_pub: bytes,
                info: bytes) -> bytes:
    """Derive a 32-byte symmetric key from the ECDH shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=info + eph_pub + recipient_pub,
    ).derive(shared_secret)


def _chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    """Per-chunk nonce: base nonce with its final 4 bytes = big-endian index."""
    nonce = bytearray(base_nonce)
    nonce[-4:] = index.to_bytes(4, "big")
    return bytes(nonce)


def _build_header(cipher: int, payload_type: int, eph_pub: bytes,
                  base_nonce: bytes, chunk_len: int) -> bytes:
    return (
        _MAGIC
        + bytes([cipher, payload_type])
        + eph_pub
        + base_nonce
        + chunk_len.to_bytes(_CHUNK_LEN_BYTES, "big")
    )


def _header_size(nonce_len: int) -> int:
    return _PREFIX_BYTES + _EPH_PUB_BYTES + nonce_len + _CHUNK_LEN_BYTES


def _parse_prefix(prefix: bytes) -> tuple[int, int]:
    """Validate magic | cipher | payload; return (cipher, payload_type)."""
    if not prefix.startswith(_MAGIC):
        raise ValueError("not a PKCrypt file (bad header)")
    if len(prefix) < _PREFIX_BYTES:
        raise ValueError("encrypted payload too short or corrupt")
    cipher, payload_type = prefix[_MAGIC_BYTES], prefix[_MAGIC_BYTES + 1]
    _nonce_len_for(cipher)
    if payload_type not in _PAYLOAD_TYPES:
        raise ValueError(f"unsupported payload type: {payload_type:#x}")
    return cipher, payload_type


def peek_payload_type(fileobj) -> int:
    """Return the payload type of the container in seekable ``fileobj``,
    leaving its position unchanged. The byte is only *authenticated* once the
    container decrypts successfully (it is part of every chunk's AAD)."""
    pos = fileobj.tell()
    try:
        return _parse_prefix(fileobj.read(_PREFIX_BYTES))[1]
    finally:
        fileobj.seek(pos)


def _nonce_len_for(cipher: int) -> int:
    if cipher == _CIPHER_AES:
        return _NONCE_AES
    if cipher == _CIPHER_XCHACHA20:
        return _NONCE_XC
    raise ValueError(f"unsupported cipher: {cipher:#x}")


def _pieces(source, read_size: int):
    """Iterate ``source`` as byte pieces. File objects are read in fixed-size
    blocks (iterating a binary file yields *lines*, which can be arbitrarily
    large for binary data)."""
    if hasattr(source, "read"):
        return iter(lambda: source.read(read_size), b"")
    return iter(source)


# ---------------------------------------------------------------------------
# Streaming (chunked) encrypt/decrypt
#
# Files are processed in fixed-size chunks so arbitrarily large inputs never
# need to be loaded into memory all at once. Every chunk but the last holds
# exactly ``chunk_len`` plaintext bytes; the last holds 0..chunk_len bytes and
# is authenticated as final, so truncating or extending the payload at a chunk
# boundary fails decryption. An empty input is a single empty final chunk.
# ---------------------------------------------------------------------------

class Encryptor:
    """Stateful, per-chunk encryptor.

    Write ``.header`` first, then pass each plaintext chunk to
    :meth:`encrypt_chunk`, concatenating the results after the header. Every
    chunk but the last must be exactly ``chunk_len`` bytes; the last (possibly
    empty) must be passed with ``final=True``, after which the encryptor is
    closed.
    """

    def __init__(self, recipient_ed25519_public: bytes,
                 cipher: int = _CIPHER_AES,
                 chunk_len: int = DEFAULT_CHUNK_LEN,
                 payload_type: int = PAYLOAD_FILE):
        nonce_len = _nonce_len_for(cipher)
        if payload_type not in _PAYLOAD_TYPES:
            raise ValueError(f"unsupported payload type: {payload_type:#x}")
        if not 0 < chunk_len <= _MAX_CHUNK_LEN:
            raise ValueError("chunk_len must be between 1 and 16 MiB")

        self.cipher = cipher
        self.payload_type = payload_type
        self.chunk_len = chunk_len
        self._is_aes = (cipher == _CIPHER_AES)
        self._index = 0
        self._closed = False

        recipient_x = ed25519_public_to_x25519_public(recipient_ed25519_public)
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key().public_bytes_raw()
        shared = ephemeral_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(recipient_x)
        )
        self._key = _derive_key(shared, ephemeral_public, recipient_x, HKDF_INFO_V2)

        self._base_nonce = os.urandom(nonce_len)
        self.header = _build_header(cipher, payload_type, ephemeral_public,
                                    self._base_nonce, chunk_len)

    def encrypt_chunk(self, chunk: bytes, final: bool = False) -> bytes:
        """Encrypt one plaintext chunk -> ciphertext (chunk + tag)."""
        if self._closed:
            raise ValueError("Encryptor already closed")
        if final:
            if len(chunk) > self.chunk_len:
                raise ValueError(
                    f"chunk exceeds chunk_len ({len(chunk)} > {self.chunk_len})")
        elif len(chunk) != self.chunk_len:
            raise ValueError("only the final chunk may be shorter than chunk_len")
        if self._index >= _MAX_CHUNKS:
            raise ValueError("too many chunks for this chunk_len")

        nonce = _chunk_nonce(self._base_nonce, self._index)
        aad = self.header + (_FLAG_FINAL if final else _FLAG_MORE)
        if self._is_aes:
            out = AESGCM(self._key).encrypt(nonce, chunk, aad)
        else:
            out = _xchacha20_encrypt(nonce, chunk, aad, self._key)
        self._index += 1
        if final:
            self.close()
        return out

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._key = b"\x00" * 32

    def __enter__(self) -> "Encryptor":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class Decryptor:
    """Stateful, per-chunk decryptor.

    Construct with the full v2 header (magic..chunk_len). Then pass each
    ciphertext block to :meth:`decrypt_chunk`: every block but the last is
    exactly ``block_size`` bytes, and the last must be passed with
    ``final=True``. Call :meth:`close` when done.
    """

    def __init__(self, header: bytes, seed: bytes, ed_public: bytes):
        # Expected header:
        #   magic | cipher | payload | eph_pub | base_nonce | chunk_len
        cipher, payload_type = _parse_prefix(header)
        nonce_len = _nonce_len_for(cipher)
        if len(header) != _header_size(nonce_len):
            raise ValueError("encrypted payload too short or corrupt")
        off = _PREFIX_BYTES
        self.cipher = cipher
        self.payload_type = payload_type
        self._is_aes = (cipher == _CIPHER_AES)

        eph_pub = header[off : off + _EPH_PUB_BYTES]; off += _EPH_PUB_BYTES
        base_nonce = header[off : off + nonce_len]; off += nonce_len
        chunk_len = int.from_bytes(header[off : off + _CHUNK_LEN_BYTES], "big")
        if chunk_len <= 0:
            raise ValueError("invalid chunk size in header")
        if chunk_len > _MAX_CHUNK_LEN:
            raise ValueError("chunk size in header too large (limit 16 MiB)")

        self.chunk_len = chunk_len
        self.block_size = chunk_len + _TAG_BYTES
        self._header = bytes(header)
        self._base_nonce = base_nonce
        self._index = 0
        self._closed = False

        recipient_x_public = ed25519_public_to_x25519_public(ed_public)
        recipient_x_private = ed25519_private_to_x25519_private(seed, ed_public)
        recipient_private = x25519.X25519PrivateKey.from_private_bytes(
            recipient_x_private
        )
        shared = recipient_private.exchange(
            x25519.X25519PublicKey.from_public_bytes(eph_pub)
        )
        self._key = _derive_key(shared, eph_pub, recipient_x_public, HKDF_INFO_V2)

    def decrypt_chunk(self, ct_chunk: bytes, final: bool = False) -> bytes:
        """Decrypt one ciphertext block -> plaintext chunk."""
        if self._closed:
            raise ValueError("Decryptor already closed")
        if final:
            if not _TAG_BYTES <= len(ct_chunk) <= self.block_size:
                raise ValueError("encrypted payload truncated or corrupt")
        elif len(ct_chunk) != self.block_size:
            raise ValueError("encrypted payload truncated or corrupt")
        if self._index >= _MAX_CHUNKS:
            raise ValueError("encrypted payload has too many chunks")

        nonce = _chunk_nonce(self._base_nonce, self._index)
        aad = self._header + (_FLAG_FINAL if final else _FLAG_MORE)
        if self._is_aes:
            out = AESGCM(self._key).decrypt(nonce, ct_chunk, aad)
        else:
            out = _xchacha20_decrypt(nonce, ct_chunk, aad, self._key)
        self._index += 1
        if final:
            self.close()
        return out

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._key = b"\x00" * 32

    def __enter__(self) -> "Decryptor":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class StreamEncryptor:
    """Push-style streaming encryptor: :meth:`write` plaintext in pieces of any
    size and the container (header, then ciphertext chunks) is passed to
    ``sink`` as it is produced. :meth:`close` emits the final chunk; until then
    the last ``chunk_len`` bytes are held back, since only the chunk at EOF may
    be sealed as final.

    It is file-like (``write``/``flush``), so e.g. :class:`zipfile.ZipFile`
    can write an archive straight into it.
    """

    def __init__(self, sink, recipient_ed25519_public: bytes,
                 cipher: int = _CIPHER_AES,
                 chunk_len: int = DEFAULT_CHUNK_LEN,
                 payload_type: int = PAYLOAD_FILE):
        self._enc = Encryptor(recipient_ed25519_public, cipher, chunk_len, payload_type)
        self._sink = sink
        self._chunk_len = chunk_len
        self._pending = bytearray()
        self._sink(self._enc.header)

    def write(self, data) -> int:
        cl = self._chunk_len
        self._pending += data
        # Emit only chunks known to be followed by more data; whatever is left
        # at close (0..chunk_len bytes) becomes the final chunk.
        n = max(0, (len(self._pending) - 1) // cl)
        for i in range(n):
            self._sink(self._enc.encrypt_chunk(bytes(self._pending[i * cl : (i + 1) * cl])))
        del self._pending[: n * cl]
        return len(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        """Emit the final chunk and wipe the key (idempotent)."""
        if not self._enc._closed:
            self._sink(self._enc.encrypt_chunk(bytes(self._pending), final=True))
            self._pending.clear()

    def abort(self) -> None:
        """Wipe the key without emitting the final chunk."""
        self._enc.close()
        self._pending.clear()


def encrypt_stream(plaintext_iter, recipient_ed25519_public: bytes,
                   cipher: int = _CIPHER_AES,
                   chunk_len: int = DEFAULT_CHUNK_LEN,
                   payload_type: int = PAYLOAD_FILE):
    """Stream encrypt: yield the header, then the ciphertext chunks for the
    plaintext read from ``plaintext_iter`` (any iterable of bytes, or a binary
    file object). Reads and encrypts incrementally — the whole input is never
    in memory."""
    out: list[bytes] = []
    writer = StreamEncryptor(out.append, recipient_ed25519_public, cipher,
                             chunk_len, payload_type)
    try:
        for piece in _pieces(plaintext_iter, chunk_len):
            writer.write(piece)
            yield from out
            out.clear()
        writer.close()
        yield from out
    finally:
        writer.abort()


def decrypt_stream(container_iter, recipient_ed25519_seed: bytes,
                   recipient_ed25519_public: bytes, salvage: bool = False):
    """Stream decrypt: yield plaintext chunks from a v2 container supplied as
    ``container_iter`` (a binary file object or iterable of bytes).

    Each chunk is authenticated before it is yielded, but truncation is only
    detected at the end: do not trust or publish the output until the
    generator has finished without raising (or, when salvaging, publish what
    was yielded as a partial result). With ``salvage``, a cut-off stream's
    last full chunk - which fails as final - is also yielded if it verifies as
    the non-final chunk it really is, before the error is raised.
    """
    pieces = _pieces(container_iter, _READ_SIZE)
    pending = bytearray()

    def fill(n: int) -> bool:
        """Read until ``pending`` holds at least ``n`` bytes or input ends."""
        while len(pending) < n:
            piece = next(pieces, None)
            if piece is None:
                return False
            pending.extend(piece)
        return True

    fill(_PREFIX_BYTES)
    cipher, _ = _parse_prefix(bytes(pending[:_PREFIX_BYTES]))
    header_size = _header_size(_nonce_len_for(cipher))
    if not fill(header_size):
        raise ValueError("encrypted payload too short or corrupt")
    header = bytes(pending[:header_size])
    del pending[:header_size]

    dec = Decryptor(header, recipient_ed25519_seed, recipient_ed25519_public)
    block = dec.block_size
    try:
        while True:
            # Same hold-back rule as encrypt_stream: the block at EOF is final.
            n = max(0, (len(pending) - 1) // block)
            for i in range(n):
                yield dec.decrypt_chunk(bytes(pending[i * block : (i + 1) * block]))
            del pending[: n * block]
            if not fill(len(pending) + 1):
                break
        try:
            last = dec.decrypt_chunk(bytes(pending), final=True)
        except (InvalidTag, ValueError):
            if salvage and len(pending) == block:
                # Cut off at a chunk boundary: this chunk was sealed as
                # non-final. Yield it if it verifies as such; the stream is
                # still incomplete, so the error is raised regardless.
                try:
                    yield dec.decrypt_chunk(bytes(pending))
                except (InvalidTag, ValueError):
                    pass
            raise
        yield last
    finally:
        dec.close()


def encrypt_bytes(plaintext: bytes, recipient_ed25519_public: bytes,
                  cipher: int = _CIPHER_AES,
                  chunk_len: int = DEFAULT_CHUNK_LEN,
                  payload_type: int = PAYLOAD_FILE) -> bytes:
    """Encrypt ``plaintext`` for ``recipient_ed25519_public``; return a v2
    chunked container (whole input in memory). ``cipher`` selects AES-256-GCM
    (default, 0x00) or XChaCha20-Poly1305 (0x01)."""
    return b"".join(encrypt_stream([plaintext], recipient_ed25519_public,
                                   cipher, chunk_len, payload_type))


def decrypt_bytes(container: bytes, recipient_ed25519_seed: bytes,
                  recipient_ed25519_public: bytes) -> bytes:
    """Decrypt a container produced by :func:`encrypt_bytes`. Only the
    recipient's private key material (seed + public) can decrypt."""
    return b"".join(decrypt_stream([container], recipient_ed25519_seed,
                                   recipient_ed25519_public))
