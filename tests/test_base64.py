"""Tests for the in-house C++ base64 codec, checked against Python's ``base64``.

Author: Warren Zajac

Driven through ``tests/deflate_harness`` (built with AddressSanitizer + UBSan
by ``make test``). base64 feeds every SSH key PKCrypt parses, so it is run
under the sanitizers here: a long non-zero base64 string used to overflow the
signed-int bit accumulator in ``base64_decode`` (undefined behavior on every
key parse, benign only by luck at ``-O2``). These differential tests against an
independent implementation would catch that overflow, or any wrong output.
"""

from __future__ import annotations

import base64
import os
import random
import subprocess
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parent / "deflate_harness"

pytestmark = pytest.mark.skipif(
    not HARNESS.exists(), reason="run `make tests/deflate_harness` (or `make test`) first"
)

_ENV = dict(os.environ,
            ASAN_OPTIONS="exitcode=99:abort_on_error=0",
            UBSAN_OPTIONS="halt_on_error=1:exitcode=98:print_stacktrace=1")


def _run(args, data: bytes) -> subprocess.CompletedProcess:
    r = subprocess.run([str(HARNESS), *args], input=data, capture_output=True,
                       env=_ENV, timeout=60)
    assert r.returncode not in (98, 99), r.stderr.decode(errors="replace")
    return r


def _corpus() -> list[bytes]:
    rnd = random.Random(2026)
    sizes = [0, 1, 2, 3, 4, 5, 31, 32, 33, 68, 100, 255, 256, 1000, 100_000]
    data = [bytes(n) for n in sizes]                 # all-zero (never overflowed)
    data += [bytes([0xFF]) * n for n in sizes]       # all-ones  (overflowed fast)
    data += [rnd.randbytes(n) for n in sizes]        # random    (realistic keys)
    return data


CORPUS = _corpus()


@pytest.mark.parametrize("data", CORPUS, ids=lambda d: f"{len(d)}B")
def test_encode_matches_python(data):
    assert _run(["base64-encode"], data).stdout == base64.b64encode(data)


@pytest.mark.parametrize("data", CORPUS, ids=lambda d: f"{len(d)}B")
def test_decode_matches_python(data):
    # Standard padded base64 (what ssh-keygen writes) must decode exactly.
    encoded = base64.b64encode(data)
    r = _run(["base64-decode"], encoded)
    assert r.returncode == 0, r.stderr
    assert r.stdout == data


def test_decode_ignores_whitespace():
    # OpenSSH wraps base64 at 70 columns; embedded newlines must be ignored.
    data = os.urandom(300)
    wrapped = b"\n".join(base64.b64encode(data)[i:i + 70]
                         for i in range(0, len(base64.b64encode(data)), 70))
    assert _run(["base64-decode"], wrapped + b"\n").stdout == data


@pytest.mark.parametrize("bad", [
    b"abc!def", b"@@@@", b"\x00\x01\x02\x03", b"ab\xffcd", b"....",
    bytes(range(33, 127)),                           # all printable ASCII at once
])
def test_decode_rejects_invalid(bad):
    # A character outside the alphabet must be rejected cleanly (exit 1),
    # never trip a sanitizer.
    assert _run(["base64-decode"], bad).returncode == 1


def test_decode_stops_at_padding():
    # '=' marks the end of data; our decoder stops there rather than erroring
    # (the downstream length check rejects a too-short key). Leading padding
    # therefore decodes to empty.
    assert _run(["base64-decode"], b"====").stdout == b""
    assert _run(["base64-decode"], b"QUJD====junk").stdout == b"ABC"


def test_decode_long_nonzero_no_overflow():
    # The original bug: a long run of high-value base64 symbols drove the
    # signed-int accumulator past INT_MAX. "///////..." is all 0x3F symbols.
    for n in (10, 100, 10_000, 1_000_000):
        r = _run(["base64-decode"], b"/" * (n - n % 4))
        assert r.returncode == 0, r.stderr
        assert r.stdout == base64.b64decode(b"/" * (n - n % 4))


def test_decode_then_encode_roundtrip():
    rnd = random.Random(7)
    for _ in range(50):
        data = rnd.randbytes(rnd.randint(0, 500))
        encoded = _run(["base64-encode"], data).stdout
        assert encoded == base64.b64encode(data)
        assert _run(["base64-decode"], encoded).stdout == data
