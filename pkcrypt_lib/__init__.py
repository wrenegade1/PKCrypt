"""PKCrypt: encrypt files so only the holder of an Ed25519 SSH private key can decrypt them."""

from . import core
from .core import __version__

__all__ = ["core", "__version__"]
