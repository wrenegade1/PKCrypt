#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Warren Zajac
"""Generate throwaway test keys and oracle containers for the Swift tests.

No key material is committed to the repository. The Swift test suites call
this script once per run with a fresh temporary directory:

    python3 make_test_fixtures.py <dir>

It creates, under <dir>, the same layout the tests read:

    ed25519_fixture, ed25519_fixture.pub
    RSA/rsa2048, RSA/rsa2048_other, RSA/rsa4096, RSA/small_rsa (+ .pub)
    Containers/{empty,short,1MiB,1MiBplus1,xc_ed_*}.pkcrypt     (Ed25519, v2)
    RSA/Containers/{rsa2048_*,rsa2048_xc_*,rsa4096_*}.pkcrypt   (RSA, v3)
    short_derived_key.hex   HKDF key the Python reference derives for "short"

Keys come from ssh-keygen; containers are written by this repository's Python
implementation (pkcrypt_lib, found via PYTHONPATH), so the Swift tests still
prove they decrypt containers made by a different implementation. Plaintexts
use the shared deterministic pattern (i*7+3) & 0xFF.
"""
import os
import subprocess
import sys
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from pkcrypt_lib import core, keys

M = 1 << 20


def pattern(n: int) -> bytes:
    return bytes((i * 7 + 3) & 0xFF for i in range(n))


def keygen(path: str, kind: str, bits: Optional[int] = None) -> None:
    # A neutral, per-key comment ("<name>@pkcrypt-test"): never a user or host name.
    comment = os.path.basename(path) + "@pkcrypt-test"
    cmd = ["ssh-keygen", "-q", "-N", "", "-C", comment, "-t", kind, "-f", path]
    if bits:
        cmd += ["-b", str(bits)]
    subprocess.run(cmd, check=True, stdin=subprocess.DEVNULL)


def main(root: str) -> None:
    rsa_dir = os.path.join(root, "RSA")
    os.makedirs(os.path.join(root, "Containers"))
    os.makedirs(os.path.join(rsa_dir, "Containers"))

    keygen(os.path.join(root, "ed25519_fixture"), "ed25519")
    keygen(os.path.join(rsa_dir, "rsa2048"), "rsa", 2048)
    keygen(os.path.join(rsa_dir, "rsa2048_other"), "rsa", 2048)
    keygen(os.path.join(rsa_dir, "rsa4096"), "rsa", 4096)
    keygen(os.path.join(rsa_dir, "small_rsa"), "rsa", 1024)   # must be rejected

    ed_pub = keys.load_public_key(os.path.join(root, "ed25519_fixture.pub")).key.public_bytes_raw()
    for name, n, cipher in [("empty", 0, 0), ("short", 40, 0), ("1MiB", M, 0),
                            ("1MiBplus1", M + 1, 0), ("xc_ed_empty", 0, 1),
                            ("xc_ed_1MiB", M, 1), ("xc_ed_1MiBplus1", M + 1, 1)]:
        with open(os.path.join(root, "Containers", f"{name}.pkcrypt"), "wb") as f:
            f.write(core.encrypt_bytes(pattern(n), ed_pub, cipher=cipher))

    for kind in ("rsa2048", "rsa4096"):
        pub = keys.load_public_key(os.path.join(rsa_dir, f"{kind}.pub")).key
        ciphers = [("", 0), ("_xc", 1)] if kind == "rsa2048" else [("", 0)]
        for tag, cipher in ciphers:
            for suffix, n in (("empty", 0), ("1MiB", M), ("1MiBplus1", M + 1)):
                path = os.path.join(rsa_dir, "Containers", f"{kind}{tag}_{suffix}.pkcrypt")
                with open(path, "wb") as f:
                    f.write(core.encrypt_bytes_rsa(pattern(n), pub, cipher=cipher))

    # The HKDF key the Python reference derives for the "short" container, so
    # the Swift key-derivation vector test compares against an independent
    # implementation rather than a value frozen to a committed key.
    priv = keys.load_private_key(os.path.join(root, "ed25519_fixture")).key
    seed = priv.private_bytes_raw()
    ed = priv.public_key().public_bytes_raw()
    with open(os.path.join(root, "Containers", "short.pkcrypt"), "rb") as f:
        header = f.read(58)
    eph = header[10:42]                      # magic(8) | cipher | payload | eph_pub(32)
    x_pub = core.ed25519_public_to_x25519_public(ed)
    x_priv = core.ed25519_private_to_x25519_private(seed, ed)
    shared = x25519.X25519PrivateKey.from_private_bytes(x_priv).exchange(
        x25519.X25519PublicKey.from_public_bytes(eph))
    key = core._derive_key(shared, eph, x_pub, core.HKDF_INFO_V2)
    with open(os.path.join(root, "short_derived_key.hex"), "w") as f:
        f.write(key.hex())


if __name__ == "__main__":
    main(sys.argv[1])
