#!/usr/bin/env python3
"""Generate a large, deterministic test file made of repeating patterns.

Author: Warren Zajac

Usage:
    python3 tests/make_test_data.py <output> [size_mib]     (default 1024 = 1 GiB)

The file is built from 1 MiB segments cycling through kinds of repetition, each
aimed at a different part of the DEFLATE compressor:

    run        one byte repeated                 long overlapping matches
    phrase     a 3..60 byte phrase repeated      short-period matches
    window     a random 32768-byte block, twice  matches at the maximum
                                                 distance DEFLATE allows
    beyond     a random 40000-byte block         repeats too far apart to be
               repeated                          matched: incompressible, so
                                                 stored blocks get used
    text       README lines with counters        realistic, mostly compressible

It is seeded, so the same size always produces the same bytes, and it is
written one segment at a time, so generating it needs almost no memory.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

SEGMENT = 1 << 20
KINDS = ("run", "phrase", "window", "beyond", "text")


def segments(size: int, seed: int = 2026):
    rnd = random.Random(seed)
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_bytes().splitlines()
    produced = 0
    index = 0
    while produced < size:
        kind = KINDS[index % len(KINDS)]
        if kind == "run":
            seg = bytes([rnd.randrange(256)]) * SEGMENT
        elif kind == "phrase":
            seg = (rnd.randbytes(rnd.randint(3, 60)) * (SEGMENT // 3 + 1))[:SEGMENT]
        elif kind == "window":
            seg = rnd.randbytes(32768) * (SEGMENT // 32768)
        elif kind == "beyond":
            seg = (rnd.randbytes(40000) * (SEGMENT // 40000 + 1))[:SEGMENT]
        else:
            lines, n = [], 0
            while n < SEGMENT:
                line = b"%08d %s\n" % (index * 100000 + len(lines), rnd.choice(readme))
                lines.append(line)
                n += len(line)
            seg = b"".join(lines)[:SEGMENT]
        seg = seg[: size - produced]
        produced += len(seg)
        index += 1
        yield seg


def generate(path: str | Path, size: int) -> None:
    with open(path, "wb") as f:
        for seg in segments(size):
            f.write(seg)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    size_mib = int(sys.argv[2]) if len(sys.argv) > 2 else 1024
    generate(sys.argv[1], size_mib * SEGMENT)
    print(f"wrote {size_mib} MiB to {sys.argv[1]}")
