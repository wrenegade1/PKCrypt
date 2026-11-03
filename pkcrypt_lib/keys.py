"""Loading OpenSSH Ed25519 and RSA key files.

Author: Warren Zajac

Uses ``cryptography``'s native OpenSSH parsing for robustness. Ed25519 is the
modern, default ``ssh-keygen -t ed25519`` key; RSA (``ssh-rsa``) is supported
as a second recipient-key type. Encryption needs only the *public* key;
decryption needs the matching *private* key (which may be passphrase-protected).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


class KeyError_(Exception):
    """Raised when a key file cannot be parsed or is the wrong type."""


@dataclass(frozen=True)
class PublicKey:
    """A parsed recipient public key (Ed25519 or RSA)."""
    type: str                       # "ed25519" | "rsa"
    key: Union[ed25519.Ed25519PublicKey, rsa.RSAPublicKey]


@dataclass(frozen=True)
class PrivateKey:
    """A parsed private key (Ed25519 or RSA)."""
    type: str                       # "ed25519" | "rsa"
    key: Union[ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey]


def load_public_key(path) -> PublicKey:
    """Load a recipient's OpenSSH *public* key (id_ed25519.pub or id_rsa.pub)."""
    data = Path(path).read_bytes()
    try:
        key = serialization.load_ssh_public_key(data)
    except Exception as exc:  # ValueError / UnsupportedAlgorithm
        raise KeyError_(
            f"could not parse public key {path!r}: {exc}\n"
            f"Expected an OpenSSH ed25519 (ssh-ed25519 ...) or RSA "
            f"(ssh-rsa ...) public key."
        ) from exc
    if isinstance(key, ed25519.Ed25519PublicKey):
        return PublicKey("ed25519", key)
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise KeyError_(
                f"RSA public key in {path!r} is only {key.key_size} bits; "
                f"PKCrypt requires RSA keys of at least 2048 bits."
            )
        return PublicKey("rsa", key)
    raise KeyError_(
        f"unsupported key type {type(key).__name__} in {path!r}; "
        f"PKCrypt requires an Ed25519 or RSA key."
    )


def load_private_key(path, password: bytes | None = None) -> PrivateKey:
    """Load an OpenSSH *private* key (id_ed25519 or id_rsa).

    Supports both unencrypted and passphrase-protected keys. For a protected
    key, provide ``password`` (the passphrase bytes); otherwise loading it will
    raise.
    """
    data = Path(path).read_bytes()
    try:
        key = serialization.load_ssh_private_key(data, password=password)
    except TypeError:
        # Older cryptography without password arg — treat as unsupported.
        raise KeyError_("this cryptography version cannot load protected keys")
    except Exception as exc:  # ValueError for wrong password / bad format
        raise KeyError_(f"could not parse private key {path!r}: {exc}") from exc
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return PrivateKey("ed25519", key)
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise KeyError_(
                f"RSA private key in {path!r} is only {key.key_size} bits; "
                f"PKCrypt requires RSA keys of at least 2048 bits."
            )
        return PrivateKey("rsa", key)
    raise KeyError_(
        f"unsupported key type {type(key).__name__} in {path!r}; "
        f"PKCrypt requires an Ed25519 or RSA key."
    )
