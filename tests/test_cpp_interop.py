#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Warren Zajac
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


def make_passphrase_keypair(tmp: Path, passphrase: str,
                            comment: str = "prot@example",
                            name: str = "prot_ed25519"):
    """Generate a passphrase-protected Ed25519 key; return (priv, pub)."""
    priv = tmp / name
    pub = tmp / (name + ".pub")
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", passphrase, "-q",
         "-f", str(priv), "-C", comment],
        check=True,
    )
    return str(priv), str(pub)


def run_with_input(input_bytes: bytes, *cmd):
    """Run `cmd`, answering any terminal prompts with `input_bytes`
    (allocates a real controlling pty, so getpass() reads the answer)."""
    import pty as _pty

    pid, fd = _pty.fork()
    if pid == 0:
        os.execvp(cmd[0], list(cmd))
    import select
    import time

    def drain(timeout: float = 8.0) -> bytes:
        end = time.time() + timeout
        out = b""
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    d = os.read(fd, 1024)
                except OSError:
                    break
                if not d:
                    break
                out += d
        return out

    # Wait for the prompt before typing: getpass() turns echo off with
    # TCSAFLUSH, which DISCARDS input typed before that point, and only then
    # prints the prompt. A fixed sleep raced it on slow CI runners (Python's
    # startup + `cryptography` import can exceed it), losing the passphrase.
    seen = b""
    end = time.time() + 30
    while b"assphrase" not in seen and time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                d = os.read(fd, 1024)
            except OSError:
                break
            if not d:
                break
            seen += d
    try:
        os.write(fd, input_bytes)
    except OSError:
        pass
    out = seen + drain(15.0)
    os.close(fd)
    _pid, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    return code, out.decode("utf-8", "replace")


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

        # --- H) Chunk edge cases, both directions ----------------------------
        # Empty, exactly two 1 MiB chunks (last chunk full), and two + a bit.
        mib = 1024 * 1024
        tools = {"C++": [str(BIN)], "Python": [PY, "-m", "pkcrypt_lib"]}
        for label, data in [("empty", b""), ("2 MiB", os.urandom(2 * mib)),
                            ("2 MiB + 5", os.urandom(2 * mib + 5))]:
            src = tmp / f"h_{len(data)}.in"
            src.write_bytes(data)
            for enc_name, dec_name in [("C++", "Python"), ("Python", "C++")]:
                tag = f"{enc_name}->{dec_name} {label}"
                ct = tmp / f"h_{len(data)}_{enc_name}.pkcrypt"
                r = run(*tools[enc_name], "encrypt", pub, str(src), str(ct))
                if r.returncode != 0:
                    check(f"{tag} round-trip", False, r.stderr)
                    continue
                out = tmp / f"h_{len(data)}_{enc_name}.out"
                r = run(*tools[dec_name], "decrypt", priv, str(ct), str(out))
                check(f"{tag} round-trip",
                      r.returncode == 0 and out.read_bytes() == data, r.stderr)

                # Dropping the final chunk leaves only valid-looking chunks;
                # it must still be rejected, with no output file left behind.
                if len(data) > mib:
                    blob = ct.read_bytes()
                    last = (len(data) - 1) % mib + 1 + 16
                    cut = tmp / f"h_{len(data)}_{enc_name}.cut.pkcrypt"
                    cut.write_bytes(blob[:-last])
                    cut_out = tmp / f"h_{len(data)}_{enc_name}.cut.out"
                    r = run(*tools[dec_name], "decrypt", priv, str(cut), str(cut_out))
                    check(f"{tag} truncation rejected",
                          r.returncode != 0 and not cut_out.exists(),
                          "truncated file decrypted!")

        # --- I) Passphrase-protected private keys (C++ binary) ---------------
        pprt, ppub = make_passphrase_keypair(tmp, "correct horse battery")
        prot_payload = tmp / "prot_payload.bin"
        prot_payload.write_bytes(b"protected payload " + os.urandom(128))

        # C++ self round-trip with --passphrase.
        pp_ct = tmp / "pp_ct.pkcrypt"
        r = run(str(BIN), "encrypt", ppub, str(prot_payload), str(pp_ct))
        check("passphrase: C++ encrypt exits 0", r.returncode == 0, r.stderr)
        pp_out = tmp / "pp_out.bin"
        code, _ = run_with_input(b"correct horse battery\n", str(BIN),
                                 "decrypt", "--passphrase", pprt, str(pp_ct),
                                 str(pp_out))
        check("passphrase: C++ --passphrase round-trip",
              code == 0 and pp_out.read_bytes() == prot_payload.read_bytes(),
              f"exit {code}")

        # Cross-tool: Python encrypt -> C++ decrypt with --passphrase.
        pp_cross = tmp / "pp_cross.pkcrypt"
        r = run(PY, "-m", "pkcrypt_lib", "encrypt", ppub, str(prot_payload),
                str(pp_cross))
        pp_xout = tmp / "pp_xout.bin"
        code, _ = run_with_input(b"correct horse battery\n", str(BIN),
                                 "decrypt", "--passphrase", pprt, str(pp_cross),
                                 str(pp_xout))
        check("passphrase: Python->C++ --passphrase round-trip",
              r.returncode == 0 and code == 0 and
              pp_xout.read_bytes() == prot_payload.read_bytes(),
              f"exit {code}")

        # Cross-tool: C++ encrypt -> Python decrypt with --passphrase.
        pp_pyout = tmp / "pp_pyout.bin"
        code, _ = run_with_input(b"correct horse battery\n", PY, "-m",
                                 "pkcrypt_lib", "decrypt", "--passphrase", pprt,
                                 str(pp_ct), str(pp_pyout))
        check("passphrase: C++->Python --passphrase round-trip",
              code == 0 and pp_pyout.read_bytes() == prot_payload.read_bytes(),
              f"exit {code}")

        # Wrong passphrase must fail, no output, on the C++ side.
        pp_bad = tmp / "pp_bad.pkcrypt"
        r = run(str(BIN), "encrypt", ppub, str(prot_payload), str(pp_bad))
        pp_badout = tmp / "pp_bad.out"
        code, _ = run_with_input(b"wrong passphrase\n", str(BIN),
                                 "decrypt", "--passphrase", pprt, str(pp_bad),
                                 str(pp_badout))
        check("passphrase: wrong passphrase rejected",
              code != 0 and not pp_badout.exists(), f"decrypted with exit {code}")

        # Encrypted key without --passphrase must be rejected clearly.
        pp_none = tmp / "pp_none.pkcrypt"
        r = run(str(BIN), "encrypt", ppub, str(prot_payload), str(pp_none))
        pp_noneout = tmp / "pp_none.out"
        r = run(str(BIN), "decrypt", pprt, str(pp_none), str(pp_noneout))
        check("passphrase: protected key without --passphrase rejected",
              r.returncode != 0 and not pp_noneout.exists() and
              "passphrase" in r.stderr.lower(), r.stderr)

    finally:
        pass  # tmp cleaned on exit by tempfile caller

    passed, failed = tally()
    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
