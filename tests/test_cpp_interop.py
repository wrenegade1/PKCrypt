#!/usr/bin/env python3
"""Cross-language interoperability tests for PKCrypt.

Author: Warren Zajac

Verifies that the compiled C++ binary (./pkcrypt) and the Python package
(pkcrypt_lib) produce and consume files interchangeably, i.e. a file encrypted
by either tool can be decrypted by the other, using the same Ed25519 SSH keys.

Usage:
    make test          # builds ./pkcrypt then runs this suite
    python3 tests/test_cpp_interop.py

Requires: cryptography (for the Python side), libsodium (for both), and the
C++ binary built at ./pkcrypt.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "pkcrypt"

PY = sys.executable


def run(*args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, **kwargs)


def make_test_keypair(tmp: Path, comment: str = "test@example",
                      name: str = "id_ed25519"):
    """Generate a throwaway Ed25519 SSH keypair; return (priv, pub) paths."""
    priv = tmp / name
    pub = tmp / (name + ".pub")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-q",
         "-f", str(priv), "-C", comment],
        check=True,
    )
    return str(priv), str(pub)


def results():
    passed = failed = 0

    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"  PASS  {name}")
        else:
            failed += 1
            print(f"  FAIL  {name}  {detail}")

    return check, lambda: (passed, failed)


def main() -> int:
    if not BIN.exists():
        print(f"error: C++ binary not found at {BIN}. Run `make` first.")
        return 1

    check, tally = results()
    tmp = Path(tempfile.mkdtemp(prefix="pkcrypt_interop_"))
    payload = tmp / "payload.bin"
    payload.write_bytes(
        b"Cross-language PKCrypt interop payload.\n" + os.urandom(256)
    )

    try:
        priv, pub = make_test_keypair(tmp)

        # --- A) C++ encrypt -> Python decrypt -------------------------------
        c2p = tmp / "c2p.pkcrypt"
        r = run(str(BIN), "encrypt", pub, str(payload), str(c2p))
        check("C++ encrypt exits 0", r.returncode == 0, r.stderr)
        if r.returncode == 0:
            out = tmp / "c2p.out"
            r2 = run(PY, "-m", "pkcrypt_lib", "decrypt", priv, str(c2p), str(out))
            check("Python decrypts C++ ciphertext",
                  r2.returncode == 0 and out.read_bytes() == payload.read_bytes(),
                  r2.stderr)

        # --- B) Python encrypt -> C++ decrypt -------------------------------
        p2c = tmp / "p2c.pkcrypt"
        r = run(PY, "-m", "pkcrypt_lib", "encrypt", pub, str(payload), str(p2c))
        check("Python encrypt exits 0", r.returncode == 0, r.stderr)
        if r.returncode == 0:
            out = tmp / "p2c.out"
            r2 = run(str(BIN), "decrypt", priv, str(p2c), str(out))
            check("C++ decrypts Python ciphertext",
                  r2.returncode == 0 and out.read_bytes() == payload.read_bytes(),
                  r2.stderr)

        # --- C) C++ self round-trip -----------------------------------------
        cc = tmp / "cc.pkcrypt"
        inc = tmp / "cc.in"      # keep original present to force .decrypted path
        inc.write_bytes(payload.read_bytes())
        r = run(str(BIN), "encrypt", pub, str(inc), str(cc))
        check("C++ self-encrypt exits 0", r.returncode == 0, r.stderr)
        if r.returncode == 0:
            outc = tmp / "cc.out"
            r2 = run(str(BIN), "decrypt", priv, str(cc), str(outc))
            check("C++ self-roundtrip", r2.returncode == 0 and
                  outc.read_bytes() == payload.read_bytes(), r2.stderr)

        # --- E) Wrong key must fail (C++ side) --------------------------------
        # Encrypt for a DIFFERENT recipient, decrypt with the other private key.
        priv2, pub2 = make_test_keypair(tmp, "other@example", "other_ed25519")
        other = tmp / "other.pkcrypt"
        run(str(BIN), "encrypt", pub2, str(payload), str(other))
        r = run(str(BIN), "decrypt", priv, str(other), tmp / "e.out")
        check("C++ rejects wrong private key", r.returncode != 0,
              "unexpectedly decrypted!")

        # --- F) Tamper detection (C++ side) ----------------------------------
        tampered = tmp / "tampered.pkcrypt"
        data = bytearray(p2c.read_bytes())
        data[len(data) // 2] ^= 0xFF
        tampered.write_bytes(bytes(data))
        r = run(str(BIN), "decrypt", priv, str(tampered), tmp / "f.out")
        check("C++ detects tampered ciphertext", r.returncode != 0,
              "unexpectedly decrypted!")

        # --- G) Non-PKCrypt file rejected (C++ side) -------------------------
        junk = tmp / "junk.txt"
        junk.write_bytes(b"this is not a pkcrypt file")
        r = run(str(BIN), "decrypt", priv, str(junk), tmp / "g.out")
        check("C++ rejects non-PKCrypt file", r.returncode != 0)

    finally:
        pass  # tmp cleaned on exit by tempfile caller

    passed, failed = tally()
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
