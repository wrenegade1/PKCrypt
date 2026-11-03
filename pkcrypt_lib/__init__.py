# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Warren Zajac
"""PKCrypt: encrypt files so only the holder of an Ed25519 SSH private key can decrypt them.

Author: Warren Zajac
"""

from . import core
from .core import __version__

__all__ = ["core", "__version__"]
