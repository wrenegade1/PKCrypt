"""Loading OpenSSH Ed25519 key files.

Uses ``cryptography``'s native OpenSSH parsing for robustness. We deliberately
restrict to Ed25519 keys (the modern, default ``ssh-keygen -t ed25519`` type),
which is what PKCrypt is designed around.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


class KeyError_(Exception):
    """Raised when a key file cannot be parsed or is the wrong type."""


def load_public_key(path) -> ed25519.Ed25519PublicKey:
    """Load a recipient's OpenSSH *public* key (e.g. ``id_ed25519.pub``)."""
    data = Path(path).read_bytes()
    try:
        key = serialization.load_ssh_public_key(data)
    except Exception as exc:  # ValueError / UnsupportedAlgorithm
        raise KeyError_(
            f"could not parse public key {path!r}: {exc}\n"
            f"Expected an OpenSSH ed25519 public key (ssh-ed25519 ...)."
        ) from exc
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise KeyError_(
            f"unsupported key type {type(key).__name__} in {path!r}; "
            f"PKCrypt requires an Ed25519 key."
        )
    return key


def load_private_key(path, password: bytes | None = None) -> ed25519.Ed25519PrivateKey:
    """Load an OpenSSH *private* key (e.g. ``~/.ssh/id_ed25519``).

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
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise KeyError_(
            f"unsupported key type {type(key).__name__} in {path!r}; "
            f"PKCrypt requires an Ed25519 key."
        )
    return key
