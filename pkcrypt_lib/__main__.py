"""PKCrypt entry point for ``python -m pkcrypt_lib``.

Author: Warren Zajac
"""

import sys

from .cli import main

sys.exit(main())
