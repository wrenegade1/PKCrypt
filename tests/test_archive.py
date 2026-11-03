"""Tests for encrypting folders (ZIP archive payloads), in both implementations.

Author: Warren Zajac

Every round-trip runs across all four (encryptor, decryptor) pairs of the
Python CLI and the C++ binary. Hostile archives (path traversal, symlinks,
overlapping entries, lying sizes, ...) are encrypted as archive payloads and
must be rejected by both decryptors without writing anything anywhere. The
C++ ZIP reader is also fuzzed under AddressSanitizer/UBSan via the test
harness.
"""

from __future__ import annotations

import io
import os
import random
import shutil
import re
import stat
import struct
import subprocess
import sys
import time
import warnings
import zipfile
import zlib
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.serialization import load_ssh_private_key

from pkcrypt_lib import core

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "pkcrypt"
HARNESS = ROOT / "tests" / "deflate_harness"
TOOLS = ["py", "cpp"] if BIN.exists() else ["py"]

_SAN_ENV = dict(os.environ,
                ASAN_OPTIONS="exitcode=99:abort_on_error=0",
                UBSAN_OPTIONS="halt_on_error=1:exitcode=98:print_stacktrace=1")


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("archive_keys")
    priv = d / "id_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", str(priv)],
                   check=True)
    key = load_ssh_private_key(priv.read_bytes(), password=None)
    return {
        "priv": str(priv),
        "pub": str(priv) + ".pub",
        "seed": key.private_bytes_raw(),
        "public": key.public_key().public_bytes_raw(),
    }


def cli(tool: str, *args) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [str(BIN)]
    return subprocess.run([*cmd, *map(str, args)], capture_output=True, text=True,
                          cwd=ROOT)


def tree(root: Path) -> dict[str, bytes | None]:
    """Relative path -> file contents (None for directories)."""
    out = {}
    for p in sorted(root.rglob("*")):
        out[p.relative_to(root).as_posix()] = None if p.is_dir() else p.read_bytes()
    return out


def make_library(root: Path) -> None:
    rnd = random.Random(7)
    (root / "docs" / "deep" / "er").mkdir(parents=True)
    (root / "empty_dir").mkdir()
    (root / "ünïcødé 📁").mkdir()
    (root / "docs" / "README.md").write_bytes((ROOT / "README.md").read_bytes())
    (root / "docs" / "deep" / "er" / "random.bin").write_bytes(rnd.randbytes(300_000))
    (root / "empty.txt").write_bytes(b"")
    (root / "ünïcødé 📁" / "naïve.txt").write_text("unicode\n")
    run = root / "run.sh"
    run.write_text("#!/bin/sh\necho hi\n")
    run.chmod(0o755)
    os.utime(root / "docs" / "README.md", (1577979000, 1577979000))   # 2020-01-02


def leftovers(parent: Path) -> list[str]:
    """Temp files/dirs our tools create (all dot-prefixed with 'pkcrypt')."""
    return [p.name for p in parent.iterdir() if p.name.startswith(".") and "pkcrypt" in p.name]


# ---------------------------------------------------------------------------
# Classic-ZIP limits (ZIP64 is not supported yet)
# ---------------------------------------------------------------------------

def _many_files(root: Path, n: int) -> Path:
    root.mkdir()
    for i in range(n):
        (root / f"{i:05d}").touch()
    return root


@pytest.fixture(scope="module")
def max_entries_lib(tmp_path_factory):
    """Exactly the classic-ZIP entry limit: 65534 (0xFFFF is the ZIP64 sentinel)."""
    return _many_files(tmp_path_factory.mktemp("maxent") / "lib", 0xFFFE)


@pytest.fixture(scope="module")
def over_entries_lib(tmp_path_factory):
    return _many_files(tmp_path_factory.mktemp("overent") / "lib", 0xFFFF)


@pytest.mark.parametrize("tool", TOOLS)
def test_oversized_file_refused_before_packing(keys, tmp_path, tool):
    """A >4 GiB file fails at once from the pre-flight, not after compressing
    4 GiB of it (a sparse file reads as zeros, so packing it would take minutes)."""
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "small.txt").write_text("x")
    with open(lib / "huge.bak", "wb") as f:
        f.truncate(5 * 1024 ** 3)                    # sparse: no disk space used
    t0 = time.monotonic()
    r = cli(tool, "encrypt", keys["pub"], lib)
    assert time.monotonic() - t0 < 10
    assert r.returncode == 1, r.stderr
    assert "too large" in r.stderr and "ZIP64" in r.stderr and "huge.bak" in r.stderr
    assert "Traceback" not in r.stderr
    assert not (tmp_path / "lib.pkcrypt").exists() and leftovers(tmp_path) == []


def test_python_member_limit_is_2gib(keys, tmp_path):
    """zipfile without ZIP64 caps members at 2 GiB - 1; the Python packer must
    refuse above that rather than write ZIP64 the C++ reader can't open."""
    lib = tmp_path / "lib"
    lib.mkdir()
    with open(lib / "big", "wb") as f:
        f.truncate(zipfile.ZIP64_LIMIT + 1)
    r = cli("py", "encrypt", keys["pub"], lib)
    assert r.returncode == 1 and "limit 2 GiB" in r.stderr, r.stderr
    assert not (tmp_path / "lib.pkcrypt").exists() and leftovers(tmp_path) == []


# Each packer's per-file limit: C++ 4 GiB - 2; Python zipfile 2 GiB - 1.
_MEMBER_LIMIT = {"cpp": 0xFFFFFFFE, "py": zipfile.ZIP64_LIMIT}


@pytest.mark.parametrize("tool", TOOLS)
def test_skip_large_leaves_out_big_files(keys, tmp_path, tool):
    """--skip-large: an oversized file is left out with a warning, its folder
    is still archived, and everything else round-trips through both tools.
    The flag is given last, as users type it."""
    lib = tmp_path / "lib"
    (lib / "backups").mkdir(parents=True)
    (lib / "sql").mkdir()
    (lib / "sql" / "restore.sql").write_text("RESTORE DATABASE x;")
    with open(lib / "backups" / "db.bak", "wb") as f:
        f.truncate(_MEMBER_LIMIT[tool] + 1)              # sparse, just over the limit
    r = cli(tool, "encrypt", keys["pub"], lib)
    assert r.returncode == 1 and "--skip-large" in r.stderr and "\\x0a" not in r.stderr
    assert not (tmp_path / "lib.pkcrypt").exists()
    t0 = time.monotonic()
    r = cli(tool, "encrypt", keys["pub"], lib, "--skip-large")
    assert time.monotonic() - t0 < 10                  # never read the big file
    assert r.returncode == 0, r.stderr
    assert "skipped backups/db.bak" in r.stderr and "NOT in" in r.stderr
    assert re.search(r"left out\s*: 1 ", r.stdout), r.stdout
    for dec in TOOLS:
        out = tmp_path / f"out_{dec}"
        assert cli(dec, "decrypt", keys["priv"], tmp_path / "lib.pkcrypt", out).returncode == 0
        assert tree(out) == {"backups": None, "sql": None,
                             "sql/restore.sql": b"RESTORE DATABASE x;"}


@pytest.mark.parametrize("tool", TOOLS)
def test_output_inside_source_is_not_packed(keys, tmp_path, tool):
    """Encrypting '.' into a file inside it must not pack its own temp file."""
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "f").write_text("x")
    cmd = [sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [str(BIN)]
    r = subprocess.run([*cmd, "encrypt", keys["pub"], ".", "inside.pkcrypt"],
                       cwd=lib, capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.returncode == 0, r.stderr
    out = tmp_path / "out"
    assert cli(tool, "decrypt", keys["priv"], lib / "inside.pkcrypt", out).returncode == 0
    assert tree(out) == {"f": b"x"}


@pytest.mark.parametrize("tool", TOOLS)
def test_too_many_entries_refused_before_packing(keys, tmp_path, over_entries_lib, tool):
    out = tmp_path / "lib.pkcrypt"
    r = cli(tool, "encrypt", keys["pub"], over_entries_lib, out)
    assert r.returncode == 1, r.stderr
    assert "too many files" in r.stderr and "65534" in r.stderr
    assert not out.exists() and leftovers(tmp_path) == []


@pytest.mark.parametrize("enc,dec", [(e, d) for e in TOOLS for d in TOOLS])
def test_max_entries_round_trip(keys, tmp_path, max_entries_lib, enc, dec):
    """At exactly the limit, an archive one tool writes the other can read
    (the C++ writer used to allow 65535, which its own reader then refused)."""
    container = tmp_path / "lib.pkcrypt"
    r = cli(enc, "encrypt", keys["pub"], max_entries_lib, container)
    assert r.returncode == 0, r.stderr
    dest = tmp_path / "out"
    r = cli(dec, "decrypt", keys["priv"], container, dest)
    assert r.returncode == 0, r.stderr
    assert sorted(p.name for p in dest.iterdir()) == sorted(
        p.name for p in max_entries_lib.iterdir())


# ---------------------------------------------------------------------------
# Round-trips
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("enc", TOOLS)
@pytest.mark.parametrize("dec", TOOLS)
def test_folder_roundtrip(keys, tmp_path, enc, dec):
    lib = tmp_path / "library"
    make_library(lib)
    (lib / "link").symlink_to("docs/README.md")

    r = cli(enc, "encrypt", keys["pub"], f"{lib}/")     # trailing slash on purpose
    assert r.returncode == 0, r.stderr
    assert "skipped link" in r.stderr
    container = tmp_path / "library.pkcrypt"
    assert container.exists()

    out = tmp_path / "restored"
    r = cli(dec, "decrypt", keys["priv"], container, out)
    assert r.returncode == 0, r.stderr

    expected = tree(lib)
    del expected["link"]                                # symlinks are skipped
    assert tree(out) == expected
    assert leftovers(tmp_path) == []

    # Private permissions, owner-exec preserved, mtimes restored.
    assert stat.S_IMODE((out / "empty.txt").stat().st_mode) == 0o600
    assert stat.S_IMODE((out / "run.sh").stat().st_mode) == 0o700
    assert stat.S_IMODE((out / "docs").stat().st_mode) == 0o700
    assert abs((out / "docs" / "README.md").stat().st_mtime - 1577979000) <= 2


@pytest.mark.parametrize("enc", TOOLS)
@pytest.mark.parametrize("dec", TOOLS)
def test_empty_folder_and_multichunk(keys, tmp_path, enc, dec):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli(enc, "encrypt", keys["pub"], empty).returncode == 0
    assert cli(dec, "decrypt", keys["priv"], tmp_path / "empty.pkcrypt",
               tmp_path / "empty.out").returncode == 0
    assert tree(tmp_path / "empty.out") == {}

    # > 2 MiB of incompressible data spans several 1 MiB encryption chunks.
    big = tmp_path / "big"
    big.mkdir()
    (big / "a.bin").write_bytes(os.urandom(2 * 1024 * 1024 + 123))
    (big / "b.txt").write_bytes(b"hello\n" * 100_000)
    assert cli(enc, "encrypt", keys["pub"], big).returncode == 0
    assert cli(dec, "decrypt", keys["priv"], tmp_path / "big.pkcrypt",
               tmp_path / "big.out").returncode == 0
    assert tree(tmp_path / "big.out") == tree(big)


@pytest.mark.parametrize("tool", TOOLS)
def test_zip_file_is_not_extracted(keys, tmp_path, tool):
    # A .zip encrypted as a *file* must come back as that file, not a folder.
    z = tmp_path / "data.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("inner.txt", "x")
    assert cli(tool, "encrypt", keys["pub"], z, tmp_path / "data.pkcrypt").returncode == 0
    out = tmp_path / "data.out"
    assert cli(tool, "decrypt", keys["priv"], tmp_path / "data.pkcrypt", out).returncode == 0
    assert out.is_file() and out.read_bytes() == z.read_bytes()


@pytest.mark.parametrize("tool", TOOLS)
def test_payload_type_is_authenticated(keys, tmp_path, tool):
    src = tmp_path / "plain.bin"
    src.write_bytes(b"PK\x03\x04 not really a zip")
    container = core.encrypt_bytes(src.read_bytes(), keys["public"])
    tampered = bytearray(container)
    tampered[9] = core.PAYLOAD_ARCHIVE                  # flip file -> archive
    bad = tmp_path / "bad.pkcrypt"
    bad.write_bytes(bytes(tampered))
    r = cli(tool, "decrypt", keys["priv"], bad, tmp_path / "bad.out")
    assert r.returncode != 0
    assert not (tmp_path / "bad.out").exists()


@pytest.mark.parametrize("tool", TOOLS)
def test_existing_destination_refused(keys, tmp_path, tool):
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "f").write_text("new")
    assert cli(tool, "encrypt", keys["pub"], lib).returncode == 0
    dest = tmp_path / "dest"
    dest.mkdir()                                        # even an EMPTY folder
    r = cli(tool, "decrypt", keys["priv"], tmp_path / "lib.pkcrypt", dest)
    assert r.returncode != 0 and "overwrite" in (r.stderr + r.stdout)
    assert list(dest.iterdir()) == []
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize("tool", TOOLS)
def test_default_output_names(keys, tmp_path, tool):
    lib = tmp_path / "photos"
    lib.mkdir()
    (lib / "a.jpg").write_bytes(b"jpeg")
    assert cli(tool, "encrypt", keys["pub"], f"{lib}/").returncode == 0
    lib.rename(tmp_path / "photos.orig")
    assert cli(tool, "decrypt", keys["priv"], tmp_path / "photos.pkcrypt").returncode == 0
    assert (tmp_path / "photos" / "a.jpg").read_bytes() == b"jpeg"
    # "." has no usable name: an explicit output path is required.
    r = subprocess.run([*([sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [str(BIN)]),
                        "encrypt", keys["pub"], "."], cwd=lib.parent / "photos",
                       capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=str(ROOT)))
    assert r.returncode != 0 and "output path" in r.stderr


# ---------------------------------------------------------------------------
# Hostile archives
# ---------------------------------------------------------------------------

def _local(name: bytes, data: bytes, crc: int, size: int, method: int = 0) -> bytes:
    return struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, method, 0, 0x21,
                       crc, len(data), size, len(name), 0) + name + data


def _central(name: bytes, comp: int, crc: int, size: int, offset: int,
             method: int = 0, attr: int = 0o100644 << 16) -> bytes:
    return struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 20, 20, 0, method,
                       0, 0x21, crc, comp, size, len(name), 0, 0, 0, 0, attr,
                       offset) + name


def _eocd(count: int, cd_size: int, cd_offset: int) -> bytes:
    return struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count, count, cd_size, cd_offset, 0)


def _zip(entries) -> bytes:
    """Build a ZIP from (name, data, attr) with zipfile, allowing duplicates."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data, attr in entries:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = attr << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, data)
    return buf.getvalue()


def _overlapping_zip() -> bytes:
    # Entry "a" is stored and its data *is* entry "b" (local header + data):
    # each entry is valid alone, but they share bytes - the zip-bomb trick.
    inner = _local(b"b", b"hello", zlib.crc32(b"hello"), 5)
    outer = _local(b"a", inner, zlib.crc32(inner), len(inner))
    cd = (_central(b"a", len(inner), zlib.crc32(inner), len(inner), 0) +
          _central(b"b", 5, zlib.crc32(b"hello"), 5, 30 + 1))
    return outer + cd + _eocd(2, len(cd), len(outer))


def _lying_size_zip() -> bytes:
    # 1 MiB of zeros declared as 10 bytes (with the CRC of those 10 bytes).
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    data = c.compress(bytes(1 << 20)) + c.flush()
    crc = zlib.crc32(bytes(10))
    body = _local(b"bomb", data, crc, 10, method=8)
    cd = _central(b"bomb", len(data), crc, 10, 0, method=8)
    return body + cd + _eocd(1, len(cd), len(body))


def _bad_crc_zip() -> bytes:
    body = _local(b"f", b"hello", zlib.crc32(b"hellp"), 5)
    cd = _central(b"f", 5, zlib.crc32(b"hellp"), 5, 0)
    return body + cd + _eocd(1, len(cd), len(body))


REG, DIR, LNK = 0o100644, 0o040755, 0o120777
HOSTILE = {
    "parent traversal": _zip([("../escaped.txt", b"pwned", REG)]),
    "nested traversal": _zip([("ok/../../escaped.txt", b"pwned", REG)]),
    "absolute path": _zip([("/tmp/pkcrypt-escaped.txt", b"pwned", REG)]),
    "dot component": _zip([("./x", b"x", REG)]),
    "empty component": _zip([("a//b", b"x", REG)]),
    "symlink entry": _zip([("link", b"/etc/passwd", LNK)]),
    "symlink then write through": _zip([("d", b"..", LNK), ("d/escaped.txt", b"pwned", REG)]),
    "fifo entry": _zip([("fifo", b"", 0o010644)]),
    "duplicate names": _zip([("same", b"1", REG), ("same", b"2", REG)]),
    "file then dir same name": _zip([("x", b"1", REG), ("x/y", b"2", REG)]),
    "overlapping entries": _overlapping_zip(),
    "lying size (bomb)": _lying_size_zip(),
    "bad crc": _bad_crc_zip(),
    "not a zip": b"this is not a zip archive at all",
}


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("case", list(HOSTILE))
def test_hostile_archive_rejected(keys, tmp_path, tool, case):
    work = tmp_path / "work"
    work.mkdir()
    container = work / "evil.pkcrypt"
    container.write_bytes(core.encrypt_bytes(HOSTILE[case], keys["public"],
                                             payload_type=core.PAYLOAD_ARCHIVE))
    out = work / "out"
    r = cli(tool, "decrypt", keys["priv"], container, out)

    assert r.returncode != 0, f"{case} was accepted: {r.stdout}"
    assert not out.exists()
    assert not (tmp_path / "escaped.txt").exists()
    assert not Path("/tmp/pkcrypt-escaped.txt").exists()
    assert leftovers(work) == []
    assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# C++ ZIP reader under sanitizers
# ---------------------------------------------------------------------------

needs_harness = pytest.mark.skipif(not HARNESS.exists(),
                                   reason="run `make tests/deflate_harness` first")


def _harness_extract(archive: bytes, dest: Path) -> subprocess.CompletedProcess:
    r = subprocess.run([str(HARNESS), "zip-extract", str(dest)], input=archive,
                       capture_output=True, env=_SAN_ENV, timeout=60)
    assert r.returncode not in (98, 99), r.stderr.decode(errors="replace")
    return r


@needs_harness
@pytest.mark.parametrize("case", list(HOSTILE))
def test_hostile_archive_rejected_under_sanitizers(tmp_path, case):
    r = _harness_extract(HOSTILE[case], tmp_path / "out")
    assert r.returncode == 1
    assert not (tmp_path / "out").exists()


@needs_harness
def test_streamed_zip_readable_by_other_tools(tmp_path):
    # Our streamed archives use data descriptors; independent readers must
    # accept them and see exactly the folder's contents.
    lib = tmp_path / "lib"
    make_library(lib)
    r = subprocess.run([str(HARNESS), "zip-pack", str(lib)], capture_output=True,
                       env=_SAN_ENV, timeout=60)
    assert r.returncode == 0, r.stderr
    archive = tmp_path / "lib.zip"
    archive.write_bytes(r.stdout)
    with zipfile.ZipFile(archive) as zf:
        assert zf.testzip() is None
        files = {i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()}
        assert all(i.flag_bits & 0x08 for i in zf.infolist() if not i.is_dir())
    expected = {k: v for k, v in tree(lib).items() if v is not None}
    assert files == expected
    if shutil.which("unzip"):                        # skip if unzip is missing
        unzip = subprocess.run(["unzip", "-tq", str(archive)], capture_output=True)
        assert unzip.returncode == 0, unzip.stdout + unzip.stderr


def _peak_rss_mb(cmd) -> float:
    """Peak memory of `cmd`, measured in a fresh wrapper process so only
    this command counts."""
    code = ("import resource, subprocess, sys; "
            "r = subprocess.run(sys.argv[1:], capture_output=True); "
            "assert r.returncode == 0, r.stderr; "
            "print(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)")
    out = subprocess.run([sys.executable, "-c", code, *map(str, cmd)],
                         capture_output=True, text=True, check=True).stdout
    rss = int(out)
    return rss / (1 << 20) if sys.platform == "darwin" else rss / 1024   # bytes vs KiB


@pytest.mark.skipif("cpp" not in TOOLS, reason="C++ binary not built")
def test_cpp_memory_stays_flat(keys, tmp_path):
    # 128 MiB of input; the old in-memory implementation needed several times
    # that. Streaming keeps the C++ binary to a few MiB of buffers.
    big = tmp_path / "big.bin"
    with open(big, "wb") as f:
        for _ in range(128):
            f.write(os.urandom(1 << 20))
    folder = tmp_path / "folder"
    (folder / "sub").mkdir(parents=True)
    os.link(big, folder / "sub" / "big.bin")
    (folder / "text.txt").write_bytes((ROOT / "README.md").read_bytes() * 1000)

    limit_mb = 48
    for src in (big, folder):
        enc, out = tmp_path / f"{src.name}.pk", tmp_path / f"{src.name}.out"
        assert _peak_rss_mb([BIN, "encrypt", keys["pub"], src, enc]) < limit_mb
        assert _peak_rss_mb([BIN, "decrypt", keys["priv"], enc, out]) < limit_mb
    assert (tmp_path / "big.bin.out").read_bytes() == big.read_bytes()
    assert tree(tmp_path / "folder.out") == tree(folder)


@needs_harness
def test_zip_reader_fuzz_under_sanitizers(tmp_path):
    # Mutated archives must never crash the reader or write outside `dest`.
    lib = tmp_path / "lib"
    make_library(lib)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(lib.rglob("*")):
            zf.write(p, p.relative_to(lib).as_posix())
    seeds = [buf.getvalue(), *HOSTILE.values()]
    rnd = random.Random(99)
    outcomes = set()
    for i in range(150):
        data = bytearray(rnd.choice(seeds))
        for _ in range(rnd.randint(1, 4)):
            j = rnd.randrange(len(data))
            data[j] ^= 1 << rnd.randrange(8)
        r = _harness_extract(bytes(data), tmp_path / f"out{i}")
        assert r.returncode in (0, 1)
        outcomes.add(r.returncode)
    assert not (tmp_path / "escaped.txt").exists()
    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.startswith("out")) == ["lib"]
    assert outcomes == {0, 1}


@pytest.mark.parametrize("tool", TOOLS)
def test_huge_chunk_len_in_header_rejected(keys, tmp_path, tool):
    # chunk_len comes from the sender; a decryptor buffers one chunk, so an
    # absurd value must be refused up front rather than allocated.
    container = bytearray(core.encrypt_bytes(b"hello", keys["public"]))
    off = core._PREFIX_BYTES + core._EPH_PUB_BYTES + core._NONCE_AES
    container[off:off + 4] = (0x7FFFFFFF).to_bytes(4, "big")
    bad = tmp_path / "huge.pkcrypt"
    bad.write_bytes(bytes(container))
    r = cli(tool, "decrypt", keys["priv"], bad, tmp_path / "huge.out")
    assert r.returncode != 0 and "too large" in r.stderr
    assert not (tmp_path / "huge.out").exists()


# ---------------------------------------------------------------------------
# Multi-file folders: cross-language round-trips and corruption
# ---------------------------------------------------------------------------

def make_multichunk_library(root: Path) -> None:
    """Several files of different kinds, ~3.5 MB: the archive spans several
    1 MiB encryption chunks, so corruption can land mid-container."""
    rnd = random.Random(5)
    (root / "notes").mkdir(parents=True)
    (root / "data").mkdir()
    (root / "notes" / "readme.txt").write_bytes((ROOT / "README.md").read_bytes())
    (root / "notes" / "log.csv").write_bytes(
        b"".join(f"{i},{rnd.random():.6f},ok\n".encode() for i in range(60000)))
    (root / "data" / "photo.jpg").write_bytes(rnd.randbytes(1_500_000))
    (root / "data" / "model.bin").write_bytes(rnd.randbytes(900_000))
    (root / "data" / "empty.dat").write_bytes(b"")
    (root / "config.json").write_bytes(b'{"name": "demo", "version": 2}\n')


@pytest.fixture(scope="module")
def multichunk(tmp_path_factory, keys):
    """The library plus a container of it made by each available tool."""
    d = tmp_path_factory.mktemp("multichunk")
    lib = d / "lib"
    make_multichunk_library(lib)
    containers = {}
    for tool in TOOLS:
        c = d / f"lib.{tool}.pkcrypt"
        r = cli(tool, "encrypt", keys["pub"], lib, c)
        assert r.returncode == 0, r.stderr
        assert "6 files, 2 folders" in r.stdout
        containers[tool] = c.read_bytes()
    return lib, containers


def _decrypt_expect_failure(tool, keys, tmp_path, blob, expect_in_error):
    container = tmp_path / "case.pkcrypt"
    container.write_bytes(blob)
    out = tmp_path / "out"
    r = cli(tool, "decrypt", keys["priv"], container, out)
    assert r.returncode != 0, f"corrupt container was accepted: {r.stdout}"
    assert expect_in_error in r.stderr, r.stderr
    # All or nothing: no folder, no partial files, no temp files.
    assert not out.exists()
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize("enc", TOOLS)
@pytest.mark.parametrize("dec", TOOLS)
def test_multifile_folder_cross_language(keys, tmp_path, multichunk, enc, dec):
    lib, containers = multichunk
    blob = containers[enc]
    hdr = core._header_size(core._NONCE_AES)
    assert len(blob) > hdr + 2 * (core.DEFAULT_CHUNK_LEN + core._TAG_BYTES)   # 3+ chunks
    (tmp_path / "c.pkcrypt").write_bytes(blob)
    r = cli(dec, "decrypt", keys["priv"], tmp_path / "c.pkcrypt", tmp_path / "out")
    assert r.returncode == 0, r.stderr
    assert "6 files, 2 folders" in r.stdout
    assert tree(tmp_path / "out") == tree(lib)


@pytest.mark.parametrize("enc", TOOLS)
@pytest.mark.parametrize("dec", TOOLS)
@pytest.mark.parametrize("damage", ["middle chunk bit", "final chunk bit", "truncated"])
def test_multifile_container_damage_rejected(keys, tmp_path, multichunk, enc, dec, damage):
    # Any damage to the encrypted container fails authentication: nothing is
    # extracted, not even files whose chunks came before the damage.
    _, containers = multichunk
    blob = bytearray(containers[enc])
    hdr = core._header_size(core._NONCE_AES)
    block = core.DEFAULT_CHUNK_LEN + core._TAG_BYTES
    if damage == "middle chunk bit":
        blob[hdr + block + 500_000] ^= 0x01
    elif damage == "final chunk bit":
        blob[-10] ^= 0x01
    else:
        del blob[hdr + 2 * block:]
    _decrypt_expect_failure(dec, keys, tmp_path, bytes(blob), "decryption failed")


@pytest.mark.parametrize("enc", TOOLS)
@pytest.mark.parametrize("dec", TOOLS)
@pytest.mark.parametrize("member,offset", [("data/photo.jpg", 700_000),
                                           ("notes/log.csv", 5_000),
                                           ("data/model.bin", 10)])
def test_multifile_corrupt_member_rejected(keys, tmp_path, multichunk, enc, dec, member, offset):
    # The encryption is intact but one file's data inside the archive is bad
    # (e.g. corrupted on the sender's disk before encrypting). Decryption
    # succeeds, the archive check names the bad file, and nothing is written.
    _, containers = multichunk
    raw = core.decrypt_bytes(containers[enc], keys["seed"], keys["public"])
    info = zipfile.ZipFile(io.BytesIO(raw)).getinfo(member)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        assert zf.testzip() is None                          # intact before damage
    data_start = info.header_offset + 30 + len(info.orig_filename.encode())
    damaged = bytearray(raw)
    damaged[data_start + offset] ^= 0xFF
    blob = core.encrypt_bytes(bytes(damaged), keys["public"],
                              payload_type=core.PAYLOAD_ARCHIVE)
    _decrypt_expect_failure(dec, keys, tmp_path, blob, member)


@pytest.mark.skipif("cpp" not in TOOLS, reason="C++ binary not built")
def test_python_extraction_memory_bounded_on_compressible_data(keys, tmp_path):
    # 256 MiB of zeros compresses ~1000:1, so one 1 MiB block of compressed
    # data expands to ~1 GiB. Each decompress call must be capped, or the
    # extractor buffers a whole file's worth of output at once.
    folder = tmp_path / "zeros"
    folder.mkdir()
    with open(folder / "zeros.bin", "wb") as f:
        for _ in range(256):
            f.write(bytes(1 << 20))
    container, out = tmp_path / "zeros.pkcrypt", tmp_path / "out"
    assert cli("cpp", "encrypt", keys["pub"], folder, container).returncode == 0
    assert container.stat().st_size < 2 << 20
    assert _peak_rss_mb([sys.executable, "-m", "pkcrypt_lib", "decrypt",
                         keys["priv"], container, out]) < 80
    assert (out / "zeros.bin").stat().st_size == 256 << 20


# ---------------------------------------------------------------------------
# --salvage: recover what still verifies
# ---------------------------------------------------------------------------

CHUNK = core.DEFAULT_CHUNK_LEN
BLOCK = CHUNK + core._TAG_BYTES
HDR = core._header_size(core._NONCE_AES)


def _salvage(tool, keys, tmp_path, blob, *extra):
    container = tmp_path / "case.pkcrypt"
    container.write_bytes(blob)
    return cli(tool, "decrypt", "--salvage", keys["priv"], container, *extra)


def _files(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


def _entry_ends(raw: bytes) -> dict[str, int]:
    """Offset in the archive where each entry (header, data, descriptor) ends."""
    zf = zipfile.ZipFile(io.BytesIO(raw))
    infos = sorted(zf.infolist(), key=lambda i: i.header_offset)
    nexts = [i.header_offset for i in infos[1:]] + [zf.start_dir]
    return {i.filename: end for i, end in zip(infos, nexts)}


def _assert_no_symlinks_or_escapes(tmp_path: Path) -> None:
    assert not (tmp_path / "escaped.txt").exists()
    assert not Path("/tmp/pkcrypt-escaped.txt").exists()
    for root, dirs, names in os.walk(tmp_path):
        for n in dirs + names:
            assert not os.path.islink(os.path.join(root, n)), os.path.join(root, n)


@pytest.mark.parametrize("enc", TOOLS)
@pytest.mark.parametrize("dec", TOOLS)
@pytest.mark.parametrize("damage", ["middle chunk bit", "truncated after 2 chunks"])
def test_salvage_damaged_container(keys, tmp_path, multichunk, enc, dec, damage):
    # Exactly the files whose entries end inside the verified prefix come
    # back, byte-identical; the rest are reported lost.
    lib, containers = multichunk
    blob = bytearray(containers[enc])
    if damage == "middle chunk bit":
        blob[HDR + BLOCK + 500_000] ^= 0x01          # chunk 1 fails: chunk 0 verified
        verified = CHUNK
    else:
        del blob[HDR + 2 * BLOCK:]                   # chunks 0 and 1 verified
        verified = 2 * CHUNK
    raw = core.decrypt_bytes(containers[enc], keys["seed"], keys["public"])
    expected = {n for n, end in _entry_ends(raw).items()
                if end <= verified and not n.endswith("/")}
    assert expected and len(expected) < 6

    r = _salvage(dec, keys, tmp_path, bytes(blob))
    assert r.returncode == 3, r.stderr
    assert "PARTIAL" in r.stderr and "lost: everything after that point" in r.stderr
    assert not (tmp_path / "case").exists()           # never under the real name
    got = _files(tmp_path / "case.partial")
    assert set(got) == expected
    assert all(got[n] == (lib / n).read_bytes() for n in got)
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize("enc", TOOLS)
@pytest.mark.parametrize("dec", TOOLS)
def test_salvage_corrupt_member(keys, tmp_path, multichunk, enc, dec):
    # Encryption intact, one file bad inside: every other file is recovered.
    lib, containers = multichunk
    raw = core.decrypt_bytes(containers[enc], keys["seed"], keys["public"])
    info = zipfile.ZipFile(io.BytesIO(raw)).getinfo("notes/log.csv")
    damaged = bytearray(raw)
    damaged[info.header_offset + 30 + len("notes/log.csv") + 5000] ^= 0xFF
    blob = core.encrypt_bytes(bytes(damaged), keys["public"], payload_type=core.PAYLOAD_ARCHIVE)

    r = _salvage(dec, keys, tmp_path, blob)
    assert r.returncode == 3, r.stderr
    assert "lost: notes/log.csv (" in r.stderr
    assert "damaged" not in r.stderr                  # the encryption itself was fine
    expected = {k: v for k, v in _files(lib).items() if k != "notes/log.csv"}
    assert _files(tmp_path / "case.partial") == expected


@pytest.mark.parametrize("tool", TOOLS)
def test_salvage_intact_is_a_normal_decrypt(keys, tmp_path, multichunk, tool):
    lib, containers = multichunk
    r = _salvage(tool, keys, tmp_path, containers[tool])
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("Decrypted") and r.stderr == ""
    assert tree(tmp_path / "case") == tree(lib)
    assert not (tmp_path / "case.partial").exists()


@pytest.mark.parametrize("tool", TOOLS)
def test_salvage_explicit_output_path(keys, tmp_path, multichunk, tool):
    _, containers = multichunk
    blob = bytearray(containers[tool])
    blob[HDR + BLOCK + 500_000] ^= 0x01
    r = _salvage(tool, keys, tmp_path, bytes(blob), tmp_path / "chosen")
    assert r.returncode == 3
    assert (tmp_path / "chosen" / "config.json").exists()   # the name you asked for


@pytest.mark.parametrize("tool", TOOLS)
def test_salvage_single_file(keys, tmp_path, tool):
    data = os.urandom(3 * CHUNK + 777)
    good = core.encrypt_bytes(data, keys["public"])

    # Cut off at a chunk boundary: the last full chunk (sealed non-final) is
    # authentic and kept, so two whole chunks come back.
    r = _salvage(tool, keys, tmp_path, good[:HDR + 2 * BLOCK])
    assert r.returncode == 3 and "PARTIAL" in r.stderr
    assert (tmp_path / "case.partial").read_bytes() == data[:2 * CHUNK]
    (tmp_path / "case.partial").unlink()

    bad = bytearray(good)
    bad[HDR + BLOCK + 10] ^= 0x01                     # chunk 1 damaged
    r = _salvage(tool, keys, tmp_path, bytes(bad))
    assert r.returncode == 3
    assert (tmp_path / "case.partial").read_bytes() == data[:CHUNK]
    (tmp_path / "case.partial").unlink()

    bad = bytearray(good)
    bad[HDR + 10] ^= 0x01                             # chunk 0 damaged: nothing verifies
    r = _salvage(tool, keys, tmp_path, bytes(bad))
    assert r.returncode == 1 and "decryption failed" in r.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == ["case.pkcrypt"]


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("case", list(HOSTILE))
def test_salvage_hostile_archive_stays_safe(keys, tmp_path, tool, case):
    # Salvage relaxes "all or nothing", never the safety rules: unsafe entries
    # are dropped, symlinks are never created, nothing lands outside.
    work = tmp_path / "work"
    work.mkdir()
    blob = core.encrypt_bytes(HOSTILE[case], keys["public"], payload_type=core.PAYLOAD_ARCHIVE)
    r = _salvage(tool, keys, work, blob)
    assert r.returncode in (1, 3), r.stdout
    assert "Traceback" not in r.stderr
    if r.returncode == 1:
        assert sorted(p.name for p in work.iterdir()) == ["case.pkcrypt"]
    _assert_no_symlinks_or_escapes(tmp_path)
    assert leftovers(work) == []


@pytest.mark.parametrize("tool", TOOLS)
def test_exit_codes(keys, tmp_path, tool):
    src = tmp_path / "f.txt"
    src.write_text("hello")
    assert cli(tool, "encrypt", keys["pub"], src).returncode == 0
    container = tmp_path / "f.txt.pkcrypt"
    bad_key = tmp_path / "not_a_key"
    bad_key.write_text("garbage")
    assert cli(tool, "decrypt", bad_key, container).returncode == 2          # key error
    assert cli(tool, "decrypt", keys["priv"]).returncode == 2                # usage
    damaged = tmp_path / "damaged.pkcrypt"
    blob = bytearray(container.read_bytes())
    blob[-3] ^= 1
    damaged.write_bytes(bytes(blob))
    assert cli(tool, "decrypt", keys["priv"], damaged, tmp_path / "x").returncode == 1
    assert cli(tool, "decrypt", keys["priv"], container, tmp_path / "ok").returncode == 0


@needs_harness
def test_salvage_scanner_fuzz_under_sanitizers(tmp_path, multichunk, keys):
    # The scanner parses attacker-controlled bytes: mutated archives and
    # random-length prefixes must never crash it, escape, or create symlinks.
    _, containers = multichunk
    raw = core.decrypt_bytes(containers[TOOLS[0]], keys["seed"], keys["public"])
    small = io.BytesIO()
    with zipfile.ZipFile(small, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "alpha " * 500)
        zf.writestr("dir/", "")
        zf.writestr("dir/b.bin", os.urandom(3000))
    seeds = [raw[:300_000], small.getvalue(), *HOSTILE.values()]
    rnd = random.Random(1234)
    outcomes = set()
    for i in range(120):
        data = bytearray(rnd.choice(seeds))
        if rnd.random() < 0.5:
            del data[rnd.randrange(len(data)):]
        for _ in range(rnd.randint(0, 3)):
            if data:
                data[rnd.randrange(len(data))] ^= 1 << rnd.randrange(8)
        r = subprocess.run([str(HARNESS), "zip-salvage", str(tmp_path / f"o{i}"),
                            str(rnd.randint(0, 1))], input=bytes(data),
                           capture_output=True, env=_SAN_ENV, timeout=60)
        assert r.returncode in (0, 1, 3), r.stderr.decode(errors="replace")
        outcomes.add(r.returncode)
    _assert_no_symlinks_or_escapes(tmp_path)
    assert {1, 3} <= outcomes


# ---------------------------------------------------------------------------
# Terminal-escape injection via archive filenames
# ---------------------------------------------------------------------------

def _archive_with_name(name: str, attr: int, data: bytes = b"x") -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = attr << 16
            zf.writestr(info, data)
    return buf.getvalue()


# A filename is attacker-controlled; it must never put raw control bytes on the
# terminal. REG with a bad name is dropped (unsafe/lost); a symlink name is
# reported in a hard error. Both reach a print path.
ESCAPE_NAME = "report.txt\x1b[2K\x1b[31;5mHACKED\x07\x08\r done"


@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("salvage", [False, True])
def test_filename_escape_sequences_neutralized(keys, tmp_path, tool, salvage):
    blob = core.encrypt_bytes(_archive_with_name(ESCAPE_NAME, 0o120777, b"/etc/passwd"),
                              keys["public"], payload_type=core.PAYLOAD_ARCHIVE)
    container = tmp_path / "evil.pkcrypt"
    container.write_bytes(blob)
    args = ["decrypt"] + (["--salvage"] if salvage else []) + \
           [keys["priv"], container, tmp_path / "out"]
    r = subprocess.run([*( [sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [str(BIN)]),
                        *map(str, args)], capture_output=True, cwd=ROOT)
    combined = r.stdout + r.stderr
    # No raw C0 control byte (except the newlines we print) and no DEL.
    for bad in (b"\x1b", b"\x07", b"\x08", b"\x00", b"\x7f"):
        assert bad not in combined, f"{bad!r} reached the terminal (tool={tool})"
    assert b"\\x1b" in combined                    # shown as visible text instead
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("tool", TOOLS)
def test_unicode_filename_preserved_in_messages(keys, tmp_path, tool):
    name = "ünïcødé_📁_café.txt"
    blob = core.encrypt_bytes(_archive_with_name(name, 0o120777), keys["public"],
                              payload_type=core.PAYLOAD_ARCHIVE)
    container = tmp_path / "uni.pkcrypt"
    container.write_bytes(blob)
    r = subprocess.run([*([sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [str(BIN)]),
                        "decrypt", str(keys["priv"]), str(container), str(tmp_path / "out")],
                       capture_output=True, cwd=ROOT)
    assert name.encode() in r.stderr              # legitimate UTF-8 shown as-is


# ---------------------------------------------------------------------------
# Control characters in member names are rejected (not just display-escaped)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool", TOOLS)
@pytest.mark.parametrize("salvage", [False, True])
@pytest.mark.parametrize("ctrl", ["\t", "\x01", "\x1b", "\x7f", "\n"])
def test_control_char_name_rejected_on_extract(keys, tmp_path, tool, salvage, ctrl):
    blob = core.encrypt_bytes(_archive_with_name(f"dir/evil{ctrl}.txt", REG),
                              keys["public"], payload_type=core.PAYLOAD_ARCHIVE)
    container = tmp_path / "c.pkcrypt"
    container.write_bytes(blob)
    args = ["decrypt"] + (["--salvage"] if salvage else []) + \
           [str(keys["priv"]), str(container), str(tmp_path / "out")]
    r = subprocess.run([*([sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [str(BIN)]),
                        *args], capture_output=True, cwd=ROOT)
    # Sole entry is unsafe: normal decrypt fails; salvage recovers nothing.
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert b"control character" in r.stderr
    assert not (tmp_path / "out").exists()
    assert leftovers(tmp_path) == []


@pytest.mark.parametrize("tool", TOOLS)
def test_control_char_name_rejected_on_encrypt(keys, tmp_path, tool):
    # A locally-legal but control-char filename must fail at pack time in both
    # implementations, rather than yield an archive the extractor refuses.
    lib = tmp_path / "lib"
    lib.mkdir()
    (lib / "normal.txt").write_text("ok")
    try:
        (lib / "wei\trd.txt").write_text("tab-named")   # tab is legal on the FS
    except OSError:
        pytest.skip("filesystem rejects control chars in names")
    r = subprocess.run([*([sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [str(BIN)]),
                        "encrypt", str(keys["pub"]), str(lib), str(tmp_path / "out.pkcrypt")],
                       capture_output=True, cwd=ROOT)
    assert r.returncode != 0
    assert b"control character" in r.stderr and b"\x09" not in r.stderr   # shown as \x09
    assert not (tmp_path / "out.pkcrypt").exists()                        # nothing produced
    assert leftovers(tmp_path) == []
