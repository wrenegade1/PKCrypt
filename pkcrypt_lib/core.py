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

    header (AAD for every chunk):
      magic      8 bytes   b"PKCRYPT\\x02"
      cipher     1 byte    0x00 = AES-256-GCM  |  0x01 = XChaCha20-Poly1305
      eph_pub   32 bytes   sender's ephemeral X25519 public key
      nonce     12 | 24 B  base AEAD nonce (12 for AES-GCM, 24 for XChaCha20)
      chunk_len  4 bytes   max plaintext bytes per chunk, big-endian
    payload:
      chunks     each AEAD ciphertext = (chunk plaintext bytes + auth tag)

The plaintext is split into ``chunk_len``-byte chunks (the last may be short).
Each chunk is encrypted with the SAME key but a DIFFERENT nonce: chunk ``i``'s
nonce is the base nonce with its final 4 bytes set to the big-endian chunk
index. The fixed header above is passed as *associated data* (AAD) to every
chunk, so any tampering with the magic, cipher byte, ephemeral key, base
nonce, or chunk size fails the authentication tag.

v1 containers (``PKCRYPT\\x01``) remain readable for backwards compatibility;
encrypt always writes v2.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__version__ = "1.0.0"


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
        raise ValueError("decryption failed: file is not for this private key, "
                         "or it was tampered with")
    return m.raw[:mlen.value]

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
#   eph_pub    32 bytes   sender's ephemeral X25519 public key
#   nonce      12 | 24 B  base AEAD nonce
#   chunk_len   4 bytes   max plaintext bytes per chunk, big-endian
#   payload    chunks     per-chunk AEAD ciphertext + auth tag
_MAGIC = b"PKCRYPT\x02"
_MAGIC_BYTES = len(_MAGIC)            # 8
_CIPHER_BYTES = 1
_EPH_PUB_BYTES = 32
_CHUNK_LEN_BYTES = 4
_NONCE_AES = 12
_NONCE_XC = 24
_TAG_BYTES = 16

_CIPHER_AES = 0x00
_CIPHER_XCHACHA20 = 0x01

_MAGIC_V1 = b"PKCRYPT\x01"          # legacy read-only
_NONCE_V1 = 12

DEFAULT_CHUNK_LEN = 1 << 20         # 1 MiB of plaintext per chunk

HKDF_SALT = b"PKCrypt"
HKDF_INFO_V2 = b"PKCrypt/v2/x25519-ecdh+aead"
HKDF_INFO_V1 = b"PKCrypt/v1/x25519-ecdh+aes-256-gcm"


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


def _build_header(cipher: int, eph_pub: bytes, base_nonce: bytes,
                  chunk_len: int) -> bytes:
    return (
        _MAGIC
        + bytes([cipher])
        + eph_pub
        + base_nonce
        + chunk_len.to_bytes(_CHUNK_LEN_BYTES, "big")
    )


def _header_size(nonce_len: int) -> int:
    return _MAGIC_BYTES + _CIPHER_BYTES + _EPH_PUB_BYTES + nonce_len + _CHUNK_LEN_BYTES


def encrypt_bytes(plaintext: bytes, recipient_ed25519_public: bytes,
                  cipher: int = _CIPHER_AES,
                  chunk_len: int = DEFAULT_CHUNK_LEN) -> bytes:
    """Encrypt ``plaintext`` for ``recipient_ed25519_public``; return a v2
    chunked container. ``cipher`` selects AES-256-GCM (default, 0x00) or
    XChaCha20-Poly1305 (0x01)."""
    if cipher not in (_CIPHER_AES, _CIPHER_XCHACHA20):
        raise ValueError(f"unsupported cipher: {cipher:#x}")
    if chunk_len <= 0:
        raise ValueError("chunk_len must be positive")

    recipient_x = ed25519_public_to_x25519_public(recipient_ed25519_public)

    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes_raw()

    shared = ephemeral_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(recipient_x)
    )
    key = _derive_key(shared, ephemeral_public, recipient_x, HKDF_INFO_V2)

    nonce_len = _NONCE_AES if cipher == _CIPHER_AES else _NONCE_XC
    base_nonce = os.urandom(nonce_len)
    header = _build_header(cipher, ephemeral_public, base_nonce, chunk_len)

    out = bytearray(header)
    index = 0
    for i in range(0, len(plaintext), chunk_len):
        chunk = plaintext[i : i + chunk_len]
        nonce = _chunk_nonce(base_nonce, index)
        if cipher == _CIPHER_AES:
            out += AESGCM(key).encrypt(nonce, chunk, header)
        else:
            out += _xchacha20_encrypt(nonce, chunk, header, key)
        index += 1
    return bytes(out)


def decrypt_bytes(container: bytes, recipient_ed25519_seed: bytes,
                  recipient_ed25519_public: bytes) -> bytes:
    """Decrypt a container produced by :func:`encrypt_bytes`.

    Accepts both v2 (current) and v1 (legacy) containers. Only the recipient's
    private key material (seed + public) can decrypt.
    """
    if len(container) < _MAGIC_BYTES or not container.startswith(
        (_MAGIC, _MAGIC_V1)
    ):
        raise ValueError("not a PKCrypt file (bad header)")

    # Minimum container length so a truncated/corrupt file fails with a helpful
    # message. The smallest valid v1/v2 container is magic + eph_pub + nonce +
    # chunk header + a single 16-byte tag.
    _MIN_CONTAINER = (
        _MAGIC_BYTES + _CIPHER_BYTES + _EPH_PUB_BYTES + _NONCE_AES +
        _CHUNK_LEN_BYTES + _TAG_BYTES
    )
    if len(container) < _MIN_CONTAINER:
        raise ValueError("encrypted payload too short or corrupt")

    if container.startswith(_MAGIC):
        return _decrypt_v2(container, recipient_ed25519_seed, recipient_ed25519_public)
    return _decrypt_v1(container, recipient_ed25519_seed, recipient_ed25519_public)


def _decrypt_v2(container: bytes, seed: bytes, ed_public: bytes) -> bytes:
    recipient_x_public = ed25519_public_to_x25519_public(ed_public)
    recipient_x_private = ed25519_private_to_x25519_private(seed, ed_public)
    recipient_private = x25519.X25519PrivateKey.from_private_bytes(
        recipient_x_private
    )

    off = _MAGIC_BYTES
    cipher = container[off]; off += _CIPHER_BYTES
    eph_pub = container[off : off + _EPH_PUB_BYTES]; off += _EPH_PUB_BYTES

    if cipher == _CIPHER_AES:
        nonce_len, is_aes = _NONCE_AES, True
    elif cipher == _CIPHER_XCHACHA20:
        nonce_len, is_aes = _NONCE_XC, False
    else:
        raise ValueError(f"unsupported cipher: {cipher:#x}")

    if len(container) < _header_size(nonce_len):
        raise ValueError("encrypted payload too short or corrupt")
    base_nonce = container[off : off + nonce_len]; off += nonce_len
    chunk_len = int.from_bytes(container[off : off + _CHUNK_LEN_BYTES], "big")
    off += _CHUNK_LEN_BYTES
    header = container[:off]
    if chunk_len <= 0:
        raise ValueError("invalid chunk size in header")

    shared = recipient_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(eph_pub)
    )
    key = _derive_key(shared, eph_pub, recipient_x_public, HKDF_INFO_V2)
    aes = AESGCM(key) if is_aes else None

    payload = memoryview(container)[off:]
    out = bytearray()
    index = 0
    pos = 0
    plen = len(payload)
    while pos < plen:
        # Every chunk is exactly chunk_len plaintext + tag, except the last,
        # which holds the remainder (at least the tag). Reject a truncated or
        # oversized chunk before attempting AEAD (which would raise anyway).
        remaining = plen - pos
        if remaining < _TAG_BYTES:
            raise ValueError("encrypted payload too short or corrupt")
        ct_len = min(chunk_len + _TAG_BYTES, remaining)
        ct_chunk = bytes(payload[pos : pos + ct_len])
        pos += ct_len
        nonce = _chunk_nonce(base_nonce, index)
        if is_aes:
            out += aes.decrypt(nonce, ct_chunk, header)
        else:
            out += _xchacha20_decrypt(nonce, ct_chunk, header, key)
        index += 1
    return bytes(out)


def _decrypt_v1(container: bytes, seed: bytes, ed_public: bytes) -> bytes:
    """Legacy v1 reader: single whole-file AES-256-GCM, no AAD, no chunks."""
    recipient_x_public = ed25519_public_to_x25519_public(ed_public)
    recipient_x_private = ed25519_private_to_x25519_private(seed, ed_public)
    recipient_private = x25519.X25519PrivateKey.from_private_bytes(
        recipient_x_private
    )

    offset = _MAGIC_BYTES
    eph_pub = container[offset : offset + _EPH_PUB_BYTES]
    offset += _EPH_PUB_BYTES
    nonce = container[offset : offset + _NONCE_V1]
    offset += _NONCE_V1
    ciphertext = container[offset:]

    shared = recipient_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(eph_pub)
    )
    key = _derive_key(shared, eph_pub, recipient_x_public, HKDF_INFO_V1)

    return AESGCM(key).decrypt(nonce, ciphertext, None)
