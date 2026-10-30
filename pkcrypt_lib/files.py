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
    with AtomicOutput(path, must_not_exist=True) as out:
        out.write(data)


class AtomicOutput:
    """A streaming, atomic, no-clobber writer for PKCrypt outputs.

    Provides a file-like ``write`` for writing incrementally (so large files
    never need to live in memory), while preserving all three guarantees of
    :func:`write_bytes`:

    * restrictive ``0600`` permissions,
    * the destination is never silently overwritten: the temp file is
      hard-linked into place only if the destination does not yet exist,
    * a crash never leaves a partial file at the destination (data goes to a
      temp file first).

    Use it as a context manager; on normal exit it finalizes (fsync, then the
    atomic no-clobber link). On an exception inside the block, the temp file is
    removed and the destination is untouched.
    """

    def __init__(self, path: str | Path, must_not_exist: bool = True):
        self._dest = Path(path)
        dest_dir = self._dest.parent
        dest_dir.mkdir(parents=True, exist_ok=True)
        if must_not_exist and self._dest.exists():
            raise FileExistsError(
                f"refusing to overwrite existing file: {self._dest}"
            )
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self._dest.name}.", suffix=".tmp", dir=str(dest_dir)
        )
        self._tmp = Path(tmp_name)
        os.chmod(self._tmp, _OUTPUT_MODE)
        self._fh = os.fdopen(fd, "wb")
        self._committed = False

    def write(self, data: bytes) -> None:
        self._fh.write(data)

    def retarget(self, path: str | Path) -> None:
        """Publish to ``path`` instead of the path given at creation (same
        no-clobber rule; it must be in the same directory)."""
        self._dest = Path(path)

    def close(self) -> None:
        """Finalize: flush + fsync, then atomic no-clobber link into place."""
        if self._committed:
            return
        try:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._fh.close()
            try:
                os.link(self._tmp, self._dest)
            except FileExistsError:
                raise FileExistsError(
                    f"refusing to overwrite existing file: {self._dest}"
                ) from None
            self._committed = True
        finally:
            # Always remove the temp file (a successful link leaves it as an
            # extra link; either way it is no longer needed).
            try:
                self._tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def abort(self) -> None:
        """Discard the pending output: close and remove the temp file."""
        try:
            self._fh.close()
        except OSError:
            pass
        try:
            self._tmp.unlink(missing_ok=True)
        except OSError:
            pass
        self._committed = True  # prevent close() from re-running

    def __enter__(self) -> "AtomicOutput":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None:
            self.abort()
        else:
            self.close()


def encrypted_output_path(input_path: str) -> str:
    """Default output path when encrypting: ``<input>.pkcrypt`` (for a
    folder ``photos/``, ``photos.pkcrypt``)."""
    return (input_path.rstrip("/") or input_path) + ".pkcrypt"


def decrypted_output_path(input_path: str) -> str:
    """Default output path when decrypting: strip ``.pkcrypt`` or append
    ``.decrypted``, refusing to overwrite an existing file."""
    p = Path(input_path)
    if p.name.endswith(".pkcrypt"):
        cand = Path(str(p)[: -len(".pkcrypt")])
        if cand.name and not cand.exists():
            return str(cand)
    return unused_path(input_path + ".decrypted")


def unused_path(base: str) -> str:
    """``base`` if nothing exists there, else the first free of base.1,
    base.2, ..."""
    cand = Path(base)
    i = 1
    while cand.exists():
        cand = Path(f"{base}.{i}")
        i += 1
    return str(cand)
