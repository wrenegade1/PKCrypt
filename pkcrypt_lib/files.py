"""File I/O helpers for the PKCrypt CLI.

Author: Warren Zajac

All output files are written with mode ``0600`` (owner read/write only) so that
decrypted plaintext is never world-readable, and are written via a temp file in
the destination directory that is then atomically *linked* into place. Writing
to a temp file means a crash can never leave a half-written file at the
destination, and linking into place (which fails if the destination already
exists) makes overwrite impossible without a separate, explicit check.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Plaintext/output files are private to the user who created them.
_OUTPUT_MODE = 0o600


def read_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def write_bytes(path: str | Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically, refusing to overwrite an existing
    file, and set restrictive ``0600`` permissions.

    Writes go to a temp file in the same directory as ``path``, which is then
    atomically hard-linked into ``path``. Because ``os.link`` fails if ``path``
    already exists, an existing output is never silently overwritten (and the
    check-and-create race in the old code is closed). The temp file is removed
    on any failure so a crash never leaves a partial file behind.
    """
    dest = Path(path)
    dest_dir = dest.parent
    dest_dir.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{dest.name}.", suffix=".tmp", dir=str(dest_dir)
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, _OUTPUT_MODE)
        # Atomic no-clobber publish: hard-link fails if `dest` already exists.
        try:
            os.link(tmp, dest)
        except FileExistsError:
            raise FileExistsError(
                f"refusing to overwrite existing file: {dest}"
            ) from None
    finally:
        # Remove the temp file whether or not we succeeded (mkdirstemp leaves it
        # behind on early failure; a successful link also must not leave it).
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def encrypted_output_path(input_path: str) -> str:
    """Default output path when encrypting: ``<input>.pkcrypt``."""
    return input_path + ".pkcrypt"


def decrypted_output_path(input_path: str) -> str:
    """Default output path when decrypting: strip ``.pkcrypt`` or append
    ``.decrypted``, refusing to overwrite an existing file."""
    p = Path(input_path)
    if p.name.endswith(".pkcrypt"):
        cand = Path(str(p)[: -len(".pkcrypt")])
        if cand.name and not cand.exists():
            return str(cand)
    base = input_path + ".decrypted"
    cand = Path(base)
    i = 1
    while cand.exists():
        cand = Path(f"{base}.{i}")
        i += 1
    return str(cand)
