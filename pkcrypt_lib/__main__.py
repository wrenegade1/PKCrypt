# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Warren Zajac
"""PKCrypt entry point for ``python -m pkcrypt_lib``.

Author: Warren Zajac
"""

import sys

from .cli import main

sys.exit(main())
