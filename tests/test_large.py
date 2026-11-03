# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Warren Zajac
"""Large-input tests (1 GiB by default). Opt-in: they take a while and need a
few GB of free disk.

Author: Warren Zajac

Run with:
    make test-large
    PKCRYPT_LARGE_TESTS=1 python3 -m pytest tests/test_large.py -s
    PKCRYPT_LARGE_TESTS=1 PKCRYPT_LARGE_MIB=256 python3 -m pytest tests/test_large.py -s

The input comes from tests/make_test_data.py: deterministic repeating
patterns. Each combination of encryptor and decryptor (C++ -> Python,
Python -> C++), as a single file and inside a folder, must reproduce it exactly
(compared by SHA-256), within a memory ceiling, and must reject a corrupted
copy without leaving any output behind.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
from pathlib import Path

import pytest

from make_test_data import generate
from test_archive import BIN, TOOLS, _peak_rss_mb, cli, keys, leftovers  # noqa: F401
from pkcrypt_lib import core

SIZE_MIB = int(os.environ.get("PKCRYPT_LARGE_MIB", "1024"))
MEMORY_LIMIT_MB = {"cpp": 64, "py": 128}

pytestmark = [
    pytest.mark.skipif(os.environ.get("PKCRYPT_LARGE_TESTS") != "1",
                       reason="large tests are opt-in: set PKCRYPT_LARGE_TESTS=1"),
    pytest.mark.skipif("cpp" not in TOOLS, reason="C++ binary not built"),
]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(1 << 20):
            h.update(block)
    return h.hexdigest()


def command(tool: str, *args) -> list:
    import sys
    base = [sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [BIN]
    return [*base, *args]


@pytest.fixture(scope="module")
def big_input(tmp_path_factory):
    d = tmp_path_factory.mktemp("large")
    data = d / "patterns.bin"
    start = time.monotonic()
    generate(data, SIZE_MIB << 20)
    print(f"\n  generated {SIZE_MIB} MiB of repeating patterns "
          f"in {time.monotonic() - start:.1f}s")
    folder = d / "library"
    (folder / "nested").mkdir(parents=True)
    os.link(data, folder / "nested" / "patterns.bin")          # no second copy
    (folder / "small.txt").write_text("a small file next to a big one\n")
    (folder / "empty.dat").write_bytes(b"")
    return d, data, folder, sha256_of(data)


@pytest.mark.parametrize("mode", ["file", "folder"])
@pytest.mark.parametrize("enc,dec", [("cpp", "py"), ("py", "cpp")])
def test_large_roundtrip(keys, big_input, enc, dec, mode):
    d, data, folder, digest = big_input
    work = d / f"{enc}-{dec}-{mode}"
    work.mkdir()
    src = data if mode == "file" else folder
    container, out = work / "c.pkcrypt", work / "out"

    t0 = time.monotonic()
    enc_mb = _peak_rss_mb(command(enc, "encrypt", keys["pub"], src, container))
    t1 = time.monotonic()
    dec_mb = _peak_rss_mb(command(dec, "decrypt", keys["priv"], container, out))
    t2 = time.monotonic()

    restored = out if mode == "file" else out / "nested" / "patterns.bin"
    assert sha256_of(restored) == digest
    if mode == "folder":
        assert (out / "small.txt").read_text() == "a small file next to a big one\n"
        assert (out / "empty.dat").read_bytes() == b""
    ratio = container.stat().st_size / (SIZE_MIB << 20)
    print(f"\n  {mode:6} {enc:>3} -> {dec:<3}  container {container.stat().st_size / 2**20:7.1f} MiB "
          f"({ratio:.1%})  encrypt {t1 - t0:5.1f}s {enc_mb:5.1f} MB  "
          f"decrypt {t2 - t1:5.1f}s {dec_mb:5.1f} MB")
    assert enc_mb < MEMORY_LIMIT_MB[enc], f"{enc} encrypt used {enc_mb:.0f} MB"
    assert dec_mb < MEMORY_LIMIT_MB[dec], f"{dec} decrypt used {dec_mb:.0f} MB"
    shutil.rmtree(out) if out.is_dir() else out.unlink()

    # Corrupt one bit in the middle of the container: the decryptor must
    # reject it and leave nothing behind (it may have written gigabytes to a
    # temp file before reaching the damage).
    blob_size = container.stat().st_size
    with open(container, "r+b") as f:
        f.seek(blob_size // 2)
        byte = f.read(1)[0]
        f.seek(blob_size // 2)
        f.write(bytes([byte ^ 0x01]))
    r = cli(dec, "decrypt", keys["priv"], container, out)
    assert r.returncode != 0 and "decryption failed" in r.stderr
    assert not out.exists()
    assert leftovers(work) == []
    container.unlink()
