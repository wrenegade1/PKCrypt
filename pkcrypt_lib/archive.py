"""Folder <-> ZIP archive for PKCrypt, using the standard library's zipfile.

Author: Warren Zajac

Produces and consumes the same archives as the C++ implementation
(src/zip.cpp, src/archive.cpp), with the same safety rules on extraction:

* every member name must be a safe relative path (no absolute paths, no
  empty, ``.`` or ``..`` components) and appear only once;
* only regular files and directories are allowed: symbolic links and special
  files are rejected, as are encrypted entries and unknown compression methods;
* each entry's data must occupy its own byte range (overlapping entries are how
  the most efficient zip bombs work), and sizes and CRCs are enforced;
* the archive must fit in the free disk space;
* files are extracted into a private temporary directory that is renamed into
  place only when everything succeeded, never over an existing path. Files are
  created ``0600`` (``0700`` if owner-executable in the archive), directories
  ``0700``.
"""

from __future__ import annotations

import ctypes
import errno
import os
import shutil
import stat
import struct
import sys
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

_UNIX = 3                       # ZipInfo.create_system for archives made on Unix
_FLAG_ENCRYPTED = 0x0001
_FLAG_DATA_DESCRIPTOR = 0x0008
_FLAG_STRONG_ENCRYPTION = 0x0040
_FLAG_UTF8 = 0x0800
_LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")
_SIG_LOCAL = 0x04034B50
_SIG_CENTRAL = 0x02014B50
_SIG_EOCD = 0x06054B50
_SIG_DATA_DESCRIPTOR = 0x08074B50
_COPY_BLOCK = 1 << 20

# Classic (non-ZIP64) limits. The C++ reader refuses ZIP64 archives, so the
# packer must never produce one. An entry count of 0xFFFF is the ZIP64
# sentinel, hence 65534. With allowZip64=False, zipfile caps member sizes and
# offsets at 2 GiB - 1 (stricter than the C++ packer's 4 GiB), so a Python-made
# archive is limited to ~2 GiB until ZIP64 is implemented.
_ZIP_MAX_ENTRIES = 0xFFFE
_ZIP_MAX_MEMBER = zipfile.ZIP64_LIMIT
_NO_ZIP64 = "ZIP64 is not supported"


class ArchiveError(ValueError):
    """The archive is malformed or unsafe to extract."""


class FileTooLarge(ArchiveError):
    """A file in the folder is over the classic-ZIP member limit."""


@dataclass
class ArchiveStats:
    files: int = 0
    directories: int = 0
    bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    # Left out by ``skip_large``: (archive name, size in bytes).
    too_large: list[tuple[str, int]] = field(default_factory=list)


def has_usable_name(path: str) -> bool:
    """True if a folder path's last component can name the output file."""
    return os.path.basename(path.rstrip("/")) not in ("", ".", "..")


def name_is_safe(name: str) -> str | None:
    """Return why ``name`` is unsafe as a member path, or None if it is safe."""
    if not name:
        return "empty name"
    # Reject C0 control bytes (incl. NUL) and DEL: they are never needed in a
    # real path and are the vehicle for terminal-escape injection when a name
    # is displayed. Characters >= 0x80 are left alone so UTF-8 names stay valid.
    for ch in name:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            return f"control character \\x{ord(ch):02x} in name"
    if name.startswith("/"):
        return "absolute path"
    for part in (name[:-1] if name.endswith("/") else name).split("/"):
        if part == "":
            return "empty path component"
        if part in (".", ".."):
            return "'.' or '..' path component"
    return None


# ---------------------------------------------------------------------------
# Packing
# ---------------------------------------------------------------------------

def pack_directory(directory: str, out, stats: ArchiveStats,
                   skip_large: bool = False,
                   exclude: tuple[int, int] | None = None) -> None:
    """Write a ZIP archive of ``directory``'s contents to the file-like
    ``out`` (which needs only ``write``/``flush``). Paths are relative to the
    folder, in sorted order; symbolic links and special files are skipped and
    listed in ``stats.skipped``.

    A file over the member limit raises ``FileTooLarge`` - or, with
    ``skip_large``, is left out and listed in ``stats.too_large`` (its folder
    is still archived).

    ``exclude`` is the (st_dev, st_ino) of the file being written - the
    output may sit inside ``directory`` (e.g. encrypting ``.``) and must never
    pack its own in-progress temp file."""
    root = Path(directory)
    if not root.is_dir():
        raise ArchiveError(f"not a directory: {directory}")

    items: list[tuple[str, Path, bool, int]] = []

    def walk(d: Path, prefix: str) -> None:
        with os.scandir(d) as it:
            for entry in it:
                rel = prefix + entry.name
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    items.append((rel + "/", Path(entry.path), True, 0))
                    walk(Path(entry.path), rel + "/")
                elif stat.S_ISREG(st.st_mode):
                    if exclude == (st.st_dev, st.st_ino):
                        continue                        # our own output file
                    items.append((rel, Path(entry.path), False, st.st_size))
                else:
                    stats.skipped.append(rel)

    walk(root, "")
    items.sort(key=lambda item: item[0].encode("utf-8", "surrogateescape"))

    # Pre-flight the limits from the sizes already stat'ed, so an oversized
    # folder fails at once instead of after compressing gigabytes. zipfile
    # still enforces them while writing (a file may grow meanwhile).
    for name, _, is_dir, size in items:
        if not is_dir and size > _ZIP_MAX_MEMBER:
            if not skip_large:
                raise FileTooLarge(f"file too large for a ZIP archive "
                                   f"(limit 2 GiB; {_NO_ZIP64}): {name}")
            stats.too_large.append((name, size))
    if stats.too_large:
        left_out = {name for name, _ in stats.too_large}
        items = [item for item in items if item[0] not in left_out]
    if len(items) > _ZIP_MAX_ENTRIES:
        raise ArchiveError(f"too many files and folders for a ZIP archive "
                           f"({len(items)}; limit {_ZIP_MAX_ENTRIES}; {_NO_ZIP64})")

    # strict_timestamps=False clamps pre-1980 mtimes instead of failing.
    # allowZip64=False: never write an archive the C++ reader would refuse.
    try:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, allowZip64=False,
                             strict_timestamps=False) as zf:
            for name, path, is_dir, _ in items:
                # Reject here too (matching the C++ packer), so we never produce an
                # archive the extractor - either implementation - would refuse.
                if why := name_is_safe(name):
                    raise ArchiveError(f"cannot archive '{name}': {why}")
                zf.write(path, name)
                if is_dir:
                    stats.directories += 1
                else:
                    stats.files += 1
                    stats.bytes += path.stat().st_size
    except zipfile.LargeZipFile as exc:
        # The whole archive passed 2 GiB (depends on compression, so only
        # knowable while writing). Not a ValueError, so convert it.
        raise ArchiveError(f"archive too large (limit 2 GiB; {_NO_ZIP64}): {exc}") from None
    except RuntimeError as exc:
        # zipfile's "File size too large, try using force_zip64": a file grew
        # past the limit after pre-flight.
        if "too large" not in str(exc):
            raise
        raise ArchiveError(f"file too large for a ZIP archive (limit 2 GiB; {_NO_ZIP64})") from None


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

Losses = list[tuple[str, str]]


def _member_problem(info: zipfile.ZipInfo, fp, seen: set[str]) -> tuple[str | None, int]:
    """Why this central-directory member can't be extracted (or None), and
    the offset of its data."""
    name = info.filename
    why = name_is_safe(name)
    if why:
        return f"unsafe path in archive {name!r}: {why}", 0
    if name in seen:
        return f"duplicate path in archive: {name}", 0
    seen.add(name)
    if info.flag_bits & (_FLAG_ENCRYPTED | _FLAG_STRONG_ENCRYPTION):
        return f"encrypted ZIP entries are not supported: {name}", 0
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        return f"unsupported compression method {info.compress_type}: {name}", 0

    is_dir = name.endswith("/")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if info.create_system == _UNIX and kind:
        if stat.S_ISLNK(mode):
            return f"symbolic links are not supported: {name}", 0
        if kind not in (stat.S_IFREG, stat.S_IFDIR):
            return f"special files are not supported: {name}", 0
        if stat.S_ISDIR(mode) != is_dir:
            return f"corrupt ZIP archive (directory flag mismatch): {name}", 0
    if is_dir and info.file_size:
        return f"corrupt ZIP archive (directory with data): {name}", 0

    fp.seek(info.header_offset)
    header = fp.read(_LOCAL_HEADER.size)
    if len(header) != _LOCAL_HEADER.size or _LOCAL_HEADER.unpack(header)[0] != _SIG_LOCAL:
        return f"corrupt ZIP archive (bad local header): {name}", 0
    fields = _LOCAL_HEADER.unpack(header)
    method, name_len, extra_len = fields[3], fields[-2], fields[-1]
    local_name = fp.read(name_len)
    if method != info.compress_type or local_name != info.orig_filename.encode(
            "utf-8" if info.flag_bits & _FLAG_UTF8 else "cp437"):
        return f"corrupt ZIP archive (local header disagrees): {name}", 0
    return None, info.header_offset + _LOCAL_HEADER.size + name_len + extra_len


def _validate(zf: zipfile.ZipFile, fp, lost: Losses | None = None):
    """Check every member; return (info, offset of its data) pairs. Any
    problem fails the whole archive - unless ``lost`` is given (salvage): then
    a problem confined to one member drops just that member, recorded in
    ``lost`` as (name, reason)."""
    members = []
    seen: set[str] = set()
    ranges: list[tuple[int, int, int]] = []     # [header, data end), member index
    for info in zf.infolist():
        why, data_start = _member_problem(info, fp, seen)
        if why:
            if lost is None:
                raise ArchiveError(why)
            lost.append((info.filename, why))
            continue
        ranges.append((info.header_offset, data_start + info.compress_size, len(members)))
        members.append((info, data_start))

    # Each entry's bytes must be its own: overlapping entries are how the most
    # efficient zip bombs reuse one compressed stream many times.
    ranges.sort()
    overlapping: set[int] = set()
    furthest, furthest_member = 0, -1
    for i, (start, end, index) in enumerate(ranges):
        if i and start < furthest:
            overlapping |= {index, furthest_member}
        if end > furthest:
            furthest, furthest_member = end, index
    if overlapping:
        why = "corrupt ZIP archive (overlapping entries)"
        if lost is None:
            raise ArchiveError(why)
        lost.extend((members[i][0].filename, why) for i in sorted(overlapping))
        members = [m for i, m in enumerate(members) if i not in overlapping]
    return members


def _copy_member(fp, info: zipfile.ZipInfo, data_start: int, out) -> None:
    """Decompress one member from ``fp`` into ``out``, enforcing exactly its
    declared size and CRC-32, and that a deflate stream ends exactly at the
    member's end. (zipfile's own reader stops at the declared size without
    checking the stream really ended, so a lying size would go unnoticed.)"""
    name, size = info.filename, info.file_size
    written = crc = 0

    def emit(data: bytes) -> None:
        nonlocal written, crc
        written += len(data)
        if written > size:
            raise ArchiveError(
                f"{name}: corrupt compressed data: output larger than declared size")
        crc = zlib.crc32(data, crc)
        out.write(data)

    d = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
    fp.seek(data_start)
    remaining = info.compress_size
    while remaining:
        block = fp.read(min(remaining, _COPY_BLOCK))
        if not block:
            raise ArchiveError(f"{name}: truncated entry data")
        remaining -= len(block)
        if d is None:
            emit(block)
            continue
        try:
            while True:
                if d.eof:
                    if block:
                        raise ArchiveError(f"{name}: trailing data after compressed stream")
                    break
                # At most _COPY_BLOCK bytes per call, so memory stays bounded
                # however compressible the data is, and never more than one
                # byte past the declared size, so a bomb is caught at once.
                cap = min(_COPY_BLOCK, size - written + 1)
                data = d.decompress(block, cap)
                emit(data)
                block = d.unconsumed_tail
                # A call stopped by the cap may leave output pending inside
                # zlib even with no input left: keep going until one returns
                # less than the cap.
                if not block and len(data) < cap:
                    break
        except zlib.error as exc:
            raise ArchiveError(f"{name}: corrupt compressed data: {exc}") from None
    if d is not None and (not d.eof or d.unused_data):
        raise ArchiveError(f"{name}: corrupt compressed data (incomplete stream)")
    if written != size:
        raise ArchiveError(f"{name}: size does not match archive directory")
    if crc != info.CRC:
        raise ArchiveError(f"{name}: CRC-32 mismatch")


def _rename_no_replace(src: str, dst: str) -> None:
    """Rename ``src`` to ``dst`` only if ``dst`` does not exist (os.rename
    would replace an existing empty directory)."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        RENAME_EXCL = 0x4
        if libc.renamex_np(os.fsencode(src), os.fsencode(dst), RENAME_EXCL) == 0:
            return
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), dst)
    if sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        AT_FDCWD, RENAME_NOREPLACE = -100, 1
        if libc.renameat2(AT_FDCWD, os.fsencode(src), AT_FDCWD, os.fsencode(dst),
                          RENAME_NOREPLACE) == 0:
            return
        err = ctypes.get_errno()
        if err not in (errno.ENOSYS, errno.EINVAL):
            raise OSError(err, os.strerror(err), dst)
    if os.path.lexists(dst):
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dst)
    os.rename(src, dst)


def _mtime(info: zipfile.ZipInfo) -> float:
    try:
        return time.mktime(info.date_time + (0, 0, -1))
    except (OverflowError, ValueError):
        return 0


def _extract_member(root: str, fp, info: zipfile.ZipInfo, data_start: int,
                    stats: ArchiveStats, dir_times: list) -> None:
    name = info.filename
    parts = name.rstrip("/").split("/")
    # Create missing parents. Only this module writes under `root` (a fresh
    # 0700 directory), so no symlink can redirect these paths.
    for depth in range(1, len(parts)):
        parent = os.path.join(root, *parts[:depth])
        try:
            os.mkdir(parent, 0o700)
        except FileExistsError:
            if not stat.S_ISDIR(os.lstat(parent).st_mode):
                raise ArchiveError(f"cannot create directory for {name} "
                                   "(a file in the archive has the same name?)") from None
    path = os.path.join(root, *parts)

    if name.endswith("/"):
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            if not stat.S_ISDIR(os.lstat(path).st_mode):
                raise ArchiveError(f"cannot create directory {name}") from None
        dir_times.append((path, _mtime(info)))
        stats.directories += 1
        return

    mode = 0o700 if (info.external_attr >> 16) & stat.S_IXUSR else 0o600
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        raise ArchiveError("two archive entries map to the same file "
                           f"(names differing only in case?): {name}") from None
    try:
        with os.fdopen(fd, "wb") as out:
            _copy_member(fp, info, data_start, out)
            out.flush()
            os.fchmod(out.fileno(), mode)
            os.fsync(out.fileno())
    except BaseException:
        os.unlink(path)                 # never leave a partial file behind
        raise
    if (t := _mtime(info)) > 0:
        os.utime(path, (t, t))
    stats.files += 1
    stats.bytes += info.file_size


def _extract_into(root: str, fp, members, stats: ArchiveStats,
                  lost: Losses | None = None) -> None:
    """Extract ``members`` under ``root``. A failing member fails the whole
    extraction - unless ``lost`` is given (salvage): then it is recorded there
    and extraction continues."""
    dir_times: list[tuple[str, float]] = []
    for info, data_start in members:
        try:
            _extract_member(root, fp, info, data_start, stats, dir_times)
        except (ArchiveError, OSError) as exc:
            if lost is None:
                raise
            lost.append((info.filename, str(exc)))

    # Directory times last (adding entries changes them), deepest first.
    for path, t in sorted(dir_times, key=lambda d: len(d[0]), reverse=True):
        if t > 0:
            os.utime(path, (t, t), follow_symlinks=False)


def _extract_atomically(dest: str, extract, choose_dest) -> None:
    """Run ``extract(tmp)`` into a private temporary directory beside
    ``dest``, then rename it to ``choose_dest()`` (evaluated afterwards, so the
    result can decide the name), never over an existing path. On any failure
    the temporary tree is removed."""
    parent = os.path.dirname(os.path.abspath(dest))
    tmp = tempfile.mkdtemp(prefix=f".{os.path.basename(dest)}.pkcrypt-", dir=parent)
    try:
        extract(tmp)
        final = choose_dest()
        try:
            _rename_no_replace(tmp, final)
        except FileExistsError:
            raise FileExistsError(f"refusing to overwrite existing path: {final}") from None
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def extract_archive(archive_path: str, dest: str, stats: ArchiveStats) -> None:
    """Extract the ZIP at ``archive_path`` into the new directory ``dest``."""
    dest = dest.rstrip("/") or dest
    if os.path.lexists(dest):
        raise FileExistsError(f"refusing to overwrite existing path: {dest}")
    parent = os.path.dirname(os.path.abspath(dest))

    try:
        zf = zipfile.ZipFile(archive_path)
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"not a valid ZIP archive: {exc}") from None
    with zf, open(archive_path, "rb") as fp:
        members = _validate(zf, fp)
        total = sum(info.file_size for info, _ in members)
        free = shutil.disk_usage(parent).free
        if total > free:
            raise ArchiveError(f"not enough disk space: the folder needs {total} "
                               f"bytes, {free} available")
        _extract_atomically(dest, lambda tmp: _extract_into(tmp, fp, members, stats),
                            lambda: dest)


# ---------------------------------------------------------------------------
# Salvage
# ---------------------------------------------------------------------------

@dataclass
class SalvageReport:
    verified_whole: bool = False        # the whole encrypted file authenticated
    stats: ArchiveStats = field(default_factory=ArchiveStats)     # recovered
    lost: Losses = field(default_factory=list)                    # (name, reason)
    # Non-empty: the archive is unreadable from some point on, so later entries
    # (names unknown) are lost too; this says why.
    tail_problem: str = ""

    @property
    def complete(self) -> bool:
        """Nothing lost. Never true if decryption failed part-way, even if
        every entry seen was recovered."""
        return self.verified_whole and not self.lost and not self.tail_problem


class _Discard:
    def write(self, data) -> int:
        return len(data)


class _ScanStop(Exception):
    """The scan can't continue past this point."""


def _inflate_until_end(fp, start: int, available: int, max_out: int) -> tuple[int, int, int]:
    """Decompress the DEFLATE stream at ``start`` until it ends; return
    (compressed length, output length, output CRC-32)."""
    d = zlib.decompressobj(-15)
    fed = out_len = crc = 0
    fp.seek(start)
    try:
        while not d.eof:
            if fed >= available:
                raise _ScanStop("corrupt compressed data: truncated stream")
            block = fp.read(min(_COPY_BLOCK, available - fed))
            fed += len(block)
            while True:
                cap = min(_COPY_BLOCK, max_out - out_len + 1)
                data = d.decompress(block, cap)
                out_len += len(data)
                if out_len > max_out:
                    raise _ScanStop("corrupt compressed data: output larger than allowed")
                crc = zlib.crc32(data, crc)
                block = d.unconsumed_tail
                if d.eof or (not block and len(data) < cap):
                    break
    except zlib.error as exc:
        raise _ScanStop(f"corrupt compressed data: {exc}") from None
    return fed - len(d.unused_data), out_len, crc


def _scan(fp, limit: int, max_entry: int):
    """Salvage scan of an archive whose central directory is missing or
    unusable (e.g. the readable prefix of a damaged file): walk the local
    headers in order over the first ``limit`` bytes, fully verifying each
    entry. Mirrors zip_scan in src/zip.cpp. Returns (members, lost,
    tail_problem); tail_problem is empty if the scan reached the central
    directory, otherwise it says why later entries are unrecoverable."""
    members: list = []
    lost: Losses = []
    seen: set[str] = set()
    pos = 0

    def read_at(offset: int, n: int) -> bytes:
        fp.seek(offset)
        return fp.read(n)

    while True:
        if limit - pos < 4:
            return members, lost, "the archive is cut off"
        sig = struct.unpack("<I", read_at(pos, 4))[0]
        if sig in (_SIG_CENTRAL, _SIG_EOCD):
            return members, lost, ""                    # every entry seen
        if sig != _SIG_LOCAL:
            return members, lost, f"unrecognized data at offset {pos}"
        if limit - pos < _LOCAL_HEADER.size:
            return members, lost, "the archive is cut off inside an entry header"
        (_, _, flags, method, dos_time, dos_date, crc, comp_size, size,
         name_len, extra_len) = _LOCAL_HEADER.unpack(read_at(pos, _LOCAL_HEADER.size))
        if limit - pos - _LOCAL_HEADER.size < name_len + extra_len:
            return members, lost, "the archive is cut off inside an entry header"
        raw_name = read_at(pos + _LOCAL_HEADER.size, name_len)
        name = raw_name.decode("utf-8" if flags & _FLAG_UTF8 else "cp437",
                               errors="surrogateescape")
        label = name or "(unnamed entry)"
        data_start = pos + _LOCAL_HEADER.size + name_len + extra_len
        if flags & (_FLAG_ENCRYPTED | _FLAG_STRONG_ENCRYPTION):
            return members, lost, f"{label}: encrypted ZIP entries are not supported"

        # Where the entry ends: from the header, or - with a data descriptor -
        # by decompressing until the DEFLATE stream ends.
        if not flags & _FLAG_DATA_DESCRIPTOR:
            if 0xFFFFFFFF in (comp_size, size):
                return members, lost, f"{label}: ZIP64 entries are not supported"
            if comp_size > limit - data_start:
                return members, lost, f"{label}: the archive is cut off inside this entry"
            nxt = data_start + comp_size
        else:
            if method != zipfile.ZIP_DEFLATED:
                return members, lost, f"{label}: cannot find the end of this entry"
            try:
                consumed, out_len, out_crc = _inflate_until_end(
                    fp, data_start, limit - data_start, max_entry)
            except _ScanStop as exc:
                return members, lost, f"{label}: {exc}"
            desc_at = data_start + consumed
            if limit - desc_at < 12:
                return members, lost, f"{label}: the archive is cut off inside this entry"
            sig_len = 4 if struct.unpack("<I", read_at(desc_at, 4))[0] == _SIG_DATA_DESCRIPTOR \
                else 0                                  # the signature is optional
            if limit - desc_at < 12 + sig_len:
                return members, lost, f"{label}: the archive is cut off inside this entry"
            crc, comp_size, size = struct.unpack("<III", read_at(desc_at + sig_len, 12))
            if (comp_size, size, crc) != (consumed, out_len, out_crc):
                return members, lost, f"{label}: data descriptor does not match the data"
            nxt = desc_at + sig_len + 12

        info = zipfile.ZipInfo(name, date_time=(
            (dos_date >> 9) + 1980, max((dos_date >> 5) & 0xF, 1), max(dos_date & 0x1F, 1),
            dos_time >> 11, (dos_time >> 5) & 0x3F, (dos_time & 0x1F) * 2))
        info.compress_type, info.compress_size, info.file_size, info.CRC = \
            method, comp_size, size, crc

        # The entry's bounds are known, so a problem with this entry alone
        # loses just this entry.
        problem = None
        if why := name_is_safe(name):
            problem = f"unsafe path: {why}"
        elif name in seen:
            problem = "duplicate path in archive"
        elif method not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            problem = f"unsupported compression method {method}"
        elif method == zipfile.ZIP_STORED and comp_size != size:
            problem = "stored size mismatch"
        elif name.endswith("/") and size:
            problem = "directory with data"
        elif size > max_entry:
            problem = "larger than the free disk space"
        elif not name.endswith("/"):
            try:
                _copy_member(fp, info, data_start, _Discard())
            except ArchiveError as exc:
                problem = str(exc)
        seen.add(name)
        if problem:
            lost.append((label, problem))
        else:
            members.append((info, data_start))
        pos = nxt


def salvage_archive(archive_path: str, verified_whole: bool, dest: str,
                    partial_dest: str) -> SalvageReport:
    """Salvage-mode extraction: recover every entry that can be fully
    verified, skipping the rest. Mirrors salvage_archive in src/archive.cpp.

    With ``verified_whole`` (the whole archive decrypted and authenticated),
    the central directory is used and a bad entry loses only itself;
    otherwise ``archive_path`` holds just the readable prefix of a damaged
    archive, which is scanned entry by entry up to the first entry whose end
    can't be found. Every extraction safety rule still applies to each entry.
    The result goes to ``dest`` if nothing was lost, else to
    ``partial_dest``; neither may exist. Raises ArchiveError, writing nothing,
    if no entry could be recovered at all."""
    dest = dest.rstrip("/") or dest
    partial_dest = partial_dest.rstrip("/") or partial_dest
    if os.path.lexists(dest):
        raise FileExistsError(f"refusing to overwrite existing path: {dest}")
    report = SalvageReport(verified_whole=verified_whole)
    parent = os.path.dirname(os.path.abspath(dest))

    with open(archive_path, "rb") as fp:
        members = None
        if verified_whole:
            try:
                with zipfile.ZipFile(archive_path) as zf:
                    members = _validate(zf, fp, report.lost)
            except (zipfile.BadZipFile, ValueError, NotImplementedError) as exc:
                report.lost = [("(archive index)", str(exc))]
        if members is None:
            max_entry = min(shutil.disk_usage(parent).free, 0xFFFFFFFF)
            members, lost, report.tail_problem = _scan(
                fp, os.path.getsize(archive_path), max_entry)
            report.lost += lost

        def extract(tmp: str) -> None:
            _extract_into(tmp, fp, members, report.stats, report.lost)
            # An empty "partial" result would only mislead: fail instead.
            s = report.stats
            if not s.files and not s.directories and not report.complete:
                why = report.tail_problem or (report.lost[0][1] if report.lost else "no entries")
                raise ArchiveError(f"nothing could be recovered ({why})")

        _extract_atomically(dest, extract, lambda: dest if report.complete else partial_dest)
    return report
