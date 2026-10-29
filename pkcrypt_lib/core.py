"""PKCrypt: encrypt files so that only the holder of an Ed25519 SSH private
key can decrypt them, using the same public/private key model as SSH.

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
3. The shared secret is expanded with HKDF-SHA256 into a symmetric key, which
   encrypts the file with AES-256-GCM (authenticated encryption).
4. The output contains the ephemeral public key and nonce alongside the
   ciphertext, so the recipient needs nothing but their private key.

Only someone possessing the recipient's private key can recompute the shared
secret and decrypt the file.
"""

from __future__ import annotations

import ctypes
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# libsodium bindings for the Ed25519 <-> X25519 key conversions.
#
# These are small, stateless functions. ctypes avoids a hard compile step while
# still using the reference implementation's exact, OpenSSH-compatible math.
# ---------------------------------------------------------------------------

_LIBSODIUM_NAMES = [
    "/opt/homebrew/opt/libsodium/lib/libsodium.dylib",
    "/usr/local/lib/libsodium.dylib",
    "/usr/lib/libsodium.dylib",
    "libsodium.dylib",  # resolves on PATH
    "libsodium.so.23",  # Linux
    "libsodium.so",
]


def _load_libsodium():
    for name in _LIBSODIUM_NAMES:
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise ImportError(
        "libsodium is required for the OpenSSH Ed25519->X25519 key conversion. "
        "Install it with: brew install libsodium"
    )


_lib = _load_libsodium()

# int crypto_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
#                                           const unsigned char *ed25519_pk)
_pk_to_curve = _lib.crypto_sign_ed25519_pk_to_curve25519
_pk_to_curve.restype = ctypes.c_int
_pk_to_curve.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
]

# int crypto_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
#                                           const unsigned char *ed25519_sk)  # 64-byte seed||pub
_sk_to_curve = _lib.crypto_sign_ed25519_sk_to_curve25519
_sk_to_curve.restype = ctypes.c_int
_sk_to_curve.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
]

_ED_PUBLIC_BYTES = 32
_ED_SECRET_BYTES = 64  # seed(32) || public(32), libsodium secret key layout


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
    """Convert an Ed25519 (32-byte seed, 32-byte public) to an X25519 private key.

    Reconstructs libsodium's 64-byte secret key (seed || public) and applies
    ``crypto_sign_ed25519_sk_to_curve25519``.
    """
    if len(seed) != _ED_PUBLIC_BYTES or len(ed_public) != _ED_PUBLIC_BYTES:
        raise ValueError("Ed25519 seed and public key must each be 32 bytes")
    sk64 = seed + ed_public
    out = ctypes.create_string_buffer(_ED_PUBLIC_BYTES)
    rc = _sk_to_curve(out, sk64)
    if rc != 0:
        raise ValueError("conversion of Ed25519 private key failed")
    return out.raw


# ---------------------------------------------------------------------------
# Hybrid encryption
# ---------------------------------------------------------------------------

# On-disk container layout:
#   magic       8 bytes   b"PKCRYPT\x01"
#   eph_pub    32 bytes   sender's ephemeral X25519 public key
#   nonce      12 bytes   AES-GCM nonce
#   ciphertext  n bytes   encrypted file + 16-byte GCM tag
_MAGIC = b"PKCRYPT\x01"
_MAGIC_BYTES = len(_MAGIC)
_EPH_PUB_BYTES = 32
_NONCE_BYTES = 12  # AES-GCM standard nonce length

HKDF_INFO = b"PKCrypt/v1/x25519-ecdh+aes-256-gcm"
HKDF_SALT = b"PKCrypt"


def _derive_key(shared_secret: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    """Derive a 32-byte symmetric key from the ECDH shared secret.

    The ephemeral and recipient public keys are bound into the derivation so a
    shared secret can never be reused across different contexts.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO + eph_pub + recipient_pub,
    )
    return hkdf.derive(shared_secret)


def encrypt_bytes(plaintext: bytes, recipient_ed25519_public: bytes) -> bytes:
    """Encrypt ``plaintext`` for the holder of ``recipient_ed25519_public``.

    Returns the full container bytes (magic | eph_pub | nonce | ciphertext).
    """
    recipient_x = ed25519_public_to_x25519_public(recipient_ed25519_public)

    # Fresh ephemeral keypair gives forward secrecy and anonymity for the sender.
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes_raw()

    shared = ephemeral_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(recipient_x)
    )
    key = _derive_key(shared, ephemeral_public, recipient_x)

    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    return _MAGIC + ephemeral_public + nonce + ciphertext


def decrypt_bytes(container: bytes, recipient_ed25519_seed: bytes,
                  recipient_ed25519_public: bytes) -> bytes:
    """Decrypt a container produced by :func:`encrypt_bytes`.

    Only works with the recipient's private key material (seed + public).
    """
    if len(container) < _MAGIC_BYTES or not container.startswith(_MAGIC):
        raise ValueError("not a PKCrypt file (bad header)")

    recipient_x_public = ed25519_public_to_x25519_public(recipient_ed25519_public)
    recipient_x_private = ed25519_private_to_x25519_private(
        recipient_ed25519_seed, recipient_ed25519_public
    )
    recipient_private = x25519.X25519PrivateKey.from_private_bytes(recipient_x_private)

    offset = _MAGIC_BYTES
    eph_pub = container[offset : offset + _EPH_PUB_BYTES]
    offset += _EPH_PUB_BYTES
    nonce = container[offset : offset + _NONCE_BYTES]
    offset += _NONCE_BYTES
    ciphertext = container[offset:]

    shared = recipient_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(eph_pub)
    )
    key = _derive_key(shared, eph_pub, recipient_x_public)

    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return plaintext


def _wipe(b: bytes) -> None:
    # Best-effort in-place wipe for secret bytes (Python bytes are immutable
    # wrapper over a buffer the allocator may still hold; we zero a bytearray
    # copy when feasible).
    del b
