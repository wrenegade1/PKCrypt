# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Warren Zajac
"""Tests for the in-house C++ DEFLATE and CRC-32 implementation.

Author: Warren Zajac

The C++ code is exercised through ``tests/deflate_harness`` (built with
AddressSanitizer + UBSan by ``make test``) and checked against an independent
implementation, Python's ``zlib``:

* our compressor's output must decompress with zlib to the original bytes;
* zlib's output (every level and strategy) must decompress with ours;
* on mutated and random streams, ours must succeed exactly when zlib does,
  with identical output, and must never crash.
"""

from __future__ import annotations

import os
import random
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parent / "deflate_harness"

pytestmark = pytest.mark.skipif(
    not HARNESS.exists(), reason="run `make tests/deflate_harness` (or `make test`) first"
)

# Distinct exit codes so a sanitizer report can't look like a clean "error".
_ENV = dict(os.environ,
            ASAN_OPTIONS="exitcode=99:abort_on_error=0",
            UBSAN_OPTIONS="halt_on_error=1:exitcode=98:print_stacktrace=1")


def _run(args, data: bytes) -> subprocess.CompletedProcess:
    r = subprocess.run([str(HARNESS), *args], input=data, capture_output=True,
                       env=_ENV, timeout=120)
    assert r.returncode not in (98, 99), r.stderr.decode(errors="replace")
    return r


def ours_compress(data: bytes) -> bytes:
    r = _run(["compress"], data)
    assert r.returncode == 0, r.stderr
    return r.stdout


def ours_inflate(stream: bytes, max_out: int) -> bytes | None:
    r = _run(["inflate", str(max_out)], stream)
    assert r.returncode in (0, 1), r.stderr
    return r.stdout if r.returncode == 0 else None


def ours_inflate_batch(streams, max_out: int):
    blob = b"".join(struct.pack("<I", len(s)) + s for s in streams)
    r = _run(["inflate-batch", str(max_out)], blob)
    assert r.returncode == 0, r.stderr
    lines = r.stdout.decode().splitlines()
    assert len(lines) == len(streams)
    return [None if ln == "err" else (int(ln.split()[1], 16), int(ln.split()[2]))
            for ln in lines]


def zlib_raw_compress(data: bytes, level=6, strategy=zlib.Z_DEFAULT_STRATEGY,
                      mem_level=8) -> bytes:
    c = zlib.compressobj(level, zlib.DEFLATED, -15, mem_level, strategy)
    return c.compress(data) + c.flush()


def zlib_raw_inflate(stream: bytes) -> bytes | None:
    """zlib's verdict: the full output, or None if the stream is invalid,
    truncated, or has bytes left over after the final block."""
    d = zlib.decompressobj(wbits=-15)
    try:
        out = d.decompress(stream)
    except zlib.error:
        return None
    return out if d.eof and not d.unused_data else None


def _corpus() -> dict[str, bytes]:
    rnd = random.Random(1234)
    text = (Path(__file__).resolve().parent.parent / "README.md").read_bytes()
    block = bytes(rnd.getrandbits(8) for _ in range(32768))
    return {
        "empty": b"",
        "one byte": b"x",
        "all byte values": bytes(range(256)) * 4,
        "zeros 1 MiB": bytes(1 << 20),
        "random 200 KiB": rnd.randbytes(200_000),
        "text": text,
        "text x20": text * 20,
        # Exact distance 32768 (the maximum) and long 258-byte matches.
        "max distance": block + block,
        "long runs": b"".join(bytes([i % 7]) * rnd.randint(1, 600) for i in range(2000)),
        # Stored-block size boundaries (65535 bytes per stored block).
        "stored 65535": rnd.randbytes(65535),
        "stored 65536": rnd.randbytes(65536),
        "stored 131071": rnd.randbytes(131071),
        "mixed": rnd.randbytes(5000) + bytes(5000) + text[:5000] + rnd.randbytes(5000),
        "short repeats": b"abcabcabd" * 9000,
    }


CORPUS = _corpus()


@pytest.mark.parametrize("name", list(CORPUS))
def test_ours_compress_zlib_decompress(name):
    data = CORPUS[name]
    stream = ours_compress(data)
    assert zlib_raw_inflate(stream) == data
    # Our compressor should be in zlib's league, not just correct.
    assert len(stream) <= len(zlib_raw_compress(data, 6)) * 1.05 + 16
    # And our decompressor reads our own output.
    assert ours_inflate(stream, len(data)) == data


@pytest.mark.parametrize("level,strategy", [
    (0, zlib.Z_DEFAULT_STRATEGY), (1, zlib.Z_DEFAULT_STRATEGY),
    (6, zlib.Z_DEFAULT_STRATEGY), (9, zlib.Z_DEFAULT_STRATEGY),
    (6, zlib.Z_FILTERED), (6, zlib.Z_HUFFMAN_ONLY), (6, zlib.Z_RLE),
    (6, zlib.Z_FIXED),
])
def test_zlib_compress_ours_decompress(level, strategy):
    streams, expected = [], []
    for data in CORPUS.values():
        streams.append(zlib_raw_compress(data, level, strategy))
        expected.append((zlib.crc32(data), len(data)))
    assert ours_inflate_batch(streams, 1 << 24) == expected


def test_small_memlevel_many_blocks():
    # memLevel=1 forces tiny blocks, so block transitions get exercised.
    data = CORPUS["text x20"]
    assert ours_inflate(zlib_raw_compress(data, 9, mem_level=1), len(data)) == data


def test_crc32_matches_zlib():
    for data in CORPUS.values():
        r = _run(["crc32"], data)
        assert int(r.stdout, 16) == zlib.crc32(data)


def test_output_limit_enforced():
    data = bytes(1 << 20)
    stream = zlib_raw_compress(data, 9)        # ~1 KiB -> 1 MiB: bomb-shaped
    assert ours_inflate(stream, len(data)) == data
    assert ours_inflate(stream, len(data) - 1) is None
    assert ours_inflate(zlib_raw_compress(b"abc"), 2) is None


def _bits(*fields) -> bytes:
    """Pack (value, nbits) fields LSB-first; pass msb=True-style Huffman codes
    pre-reversed via _huff()."""
    acc = n = 0
    for value, nbits in fields:
        acc |= value << n
        n += nbits
    return acc.to_bytes((n + 7) // 8, "little")


def _huff(code: int, nbits: int):
    """A Huffman code (defined MSB-first) as an LSB-first bit field."""
    return int(format(code, f"0{nbits}b")[::-1], 2), nbits


# Fixed-Huffman block: final=1, type=01, then symbols.
_FIXED_HDR = [(1, 1), (1, 2)]
_EOB = _huff(0b0000000, 7)
_LEN3 = _huff(0b0000001, 7)          # symbol 257: match length 3
_DIST1 = _huff(0b00000, 5)           # distance symbol 0: distance 1
_LIT_A = _huff(0x30 + ord("a"), 8)   # literals 0..143 are 8-bit, 0x30 + byte


@pytest.mark.parametrize("stream,why", [
    (b"", "empty input"),
    (b"\x07", "block type 3 is reserved"),
    (b"\x01\x05\x00\xfb\xff", "stored LEN/NLEN mismatch"),
    (b"\x01\x05\x00\xfa\xffabc", "stored block truncated"),
    (b"\x03\x00\x00", "trailing byte after final block"),
    (_bits(*_FIXED_HDR, _LEN3, _DIST1, _EOB), "distance too far back"),
    (_bits(*_FIXED_HDR, _huff(0b11000110, 8), _EOB), "length symbol 286"),
    (_bits(*_FIXED_HDR, _LIT_A, _LEN3, _huff(0b11110, 5), _EOB), "distance symbol 30"),
])
def test_rejects_malformed(stream, why):
    assert zlib_raw_inflate(stream) is None, why
    assert ours_inflate(stream, 1 << 20) is None, why


def test_hand_built_fixed_block_accepted():
    # Positive control for the vectors above: "a" then a 3-byte match at
    # distance 1 gives "aaaa".
    stream = _bits(*_FIXED_HDR, _LIT_A, _LEN3, _DIST1, _EOB)
    assert zlib_raw_inflate(stream) == b"aaaa"
    assert ours_inflate(stream, 100) == b"aaaa"


def test_fixed_blocks_with_high_literals():
    # Bytes 144..255 use 9-bit fixed codes; short inputs pick fixed blocks.
    for data in (bytes(range(256)), bytes(range(144, 256)) * 3, b"\xff\x90\x00"):
        stream = ours_compress(data)
        assert zlib_raw_inflate(stream) == data


def test_every_truncation_rejected():
    data = CORPUS["text"][:3000]
    for stream in (ours_compress(data), zlib_raw_compress(data, 9),
                   zlib_raw_compress(data, 0)):
        prefixes = [stream[:n] for n in range(len(stream))]
        assert all(r is None for r in ours_inflate_batch(prefixes, 1 << 20))


def _mutations(rnd: random.Random, stream: bytes):
    b = bytearray(stream)
    kind = rnd.randrange(5)
    if kind == 0 or not b:                      # random bytes
        return rnd.randbytes(rnd.randint(1, 64))
    if kind == 1:                               # flip 1-3 bits
        for _ in range(rnd.randint(1, 3)):
            i = rnd.randrange(len(b))
            b[i] ^= 1 << rnd.randrange(8)
    elif kind == 2:                             # overwrite a byte
        b[rnd.randrange(len(b))] = rnd.getrandbits(8)
    elif kind == 3:                             # truncate
        del b[rnd.randrange(len(b)):]
    else:                                       # insert a byte
        b.insert(rnd.randrange(len(b) + 1), rnd.getrandbits(8))
    return bytes(b)


def test_differential_fuzz_against_zlib():
    rnd = random.Random(20261029)
    seeds = []
    for data in (b"", b"a", CORPUS["text"][:400], CORPUS["text"][:4000],
                 bytes(range(256)), b"ab" * 300, rnd.randbytes(300)):
        seeds.append(ours_compress(data))
        for strategy in (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED, zlib.Z_HUFFMAN_ONLY):
            seeds.append(zlib_raw_compress(data, 9, strategy))
        seeds.append(zlib_raw_compress(data, 0))

    cases = [_mutations(rnd, rnd.choice(seeds)) for _ in range(6000)]
    got = ours_inflate_batch(cases, 1 << 24)
    mismatches = []
    for case, ours in zip(cases, got):
        ref = zlib_raw_inflate(case)
        ref = None if ref is None else (zlib.crc32(ref), len(ref))
        if ours != ref:
            mismatches.append((case.hex(), ours, ref))
    accepted = sum(r is not None for r in got)
    assert not mismatches, mismatches[:5]
    # Sanity: the fuzz exercised both outcomes.
    assert 100 < accepted < len(cases) - 100


# ---------------------------------------------------------------------------
# Streaming: results must not depend on how input arrives
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("piece", [1, 7, 4096, 65537, 1 << 20])
def test_streamed_compression_identical_to_one_shot(piece):
    # The compressor only processes positions with full lookahead and never
    # drops window bytes, so output is independent of the write sizes.
    for name in ("text x20", "max distance", "long runs", "mixed", "stored 131071"):
        data = CORPUS[name]
        if piece == 1 and len(data) > 200_000:
            data = data[:200_000]
        r = _run(["compress-stream", str(piece)], data)
        assert r.returncode == 0, r.stderr
        assert r.stdout == ours_compress(data), (name, piece)
        assert zlib_raw_inflate(r.stdout) == data


@pytest.mark.parametrize("piece", [1, 3, 4096])
def test_streamed_decompression_small_reads(piece):
    # Every buffer boundary of the input reader gets crossed with tiny reads,
    # including inside stored blocks and the bytes after them.
    for data in (CORPUS["text"], CORPUS["stored 65536"], CORPUS["mixed"], b""):
        for stream in (ours_compress(data), zlib_raw_compress(data, 0),
                       zlib_raw_compress(data, 9, zlib.Z_FIXED)):
            r = _run(["inflate-stream", str(len(data)), str(piece)], stream)
            assert r.returncode == 0, r.stderr
            assert r.stdout == data
            # Truncated or extended, it must still be rejected.
            if stream:
                assert _run(["inflate-stream", str(len(data)), str(piece)],
                            stream[:-1]).returncode == 1
            assert _run(["inflate-stream", str(len(data)), str(piece)],
                        stream + b"\x00").returncode == 1


def test_streamed_decompression_output_window():
    # Long output (well past the flush threshold) with back-references that
    # reach exactly 32768 bytes back across flushes.
    data = CORPUS["max distance"] * 8 + CORPUS["text x20"]
    for stream in (ours_compress(data), zlib_raw_compress(data, 9)):
        r = _run(["inflate-stream", str(len(data)), "65536"], stream)
        assert r.returncode == 0 and r.stdout == data
