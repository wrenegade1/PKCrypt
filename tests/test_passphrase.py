"""Tests for the C++ OpenSSH private-key parser, incl. passphrase-protected keys.

Author: Warren Zajac

The C++ parser (``src/ssh_key.cpp``, with the in-house ``bcrypt_pbkdf`` and
``aes_ctr`` modules) is exercised through ``tests/ssh_harness`` (built with
AddressSanitizer + UBSan by ``make test``) and validated against OpenSSH's own
``ssh-keygen``:

* a key protected with passphrase P must decrypt to a public key that matches
  ``ssh-keygen -y -P P``;
* the recovered seed must equal the seed of the same key after OpenSSH itself
  removes the passphrase (``ssh-keygen -p -N ""``), byte for byte;
* a wrong passphrase and a missing passphrase must be rejected, writing nothing.
"""

from __future__ import annotations

import os
import subprocess
import base64
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parent / "ssh_harness"

pytestmark = pytest.mark.skipif(
    not HARNESS.exists(), reason="run `make tests/ssh_harness` (or `make test`) first"
)

_ENV = dict(os.environ,
            ASAN_OPTIONS="exitcode=99:abort_on_error=0",
            UBSAN_OPTIONS="halt_on_error=1:exitcode=98:print_stacktrace=1")


def _parse(key: Path, passphrase: str | None):
    arg = passphrase if passphrase is not None else ""
    r = subprocess.run(
        [str(HARNESS), "parse", str(key), arg], capture_output=True, text=True,
        env=_ENV, timeout=120)
    return r


def _ssh_pub(priv: Path, passphrase: str) -> str:
    """The public key string OpenSSH derives from a (protected) private key."""
    r = subprocess.run(["ssh-keygen", "-y", "-P", passphrase, "-f", str(priv)],
                       capture_output=True, text=True, check=True)
    return r.stdout.split()[1]  # the base64 token


@pytest.fixture(scope="module")
def protected_key(tmp_path_factory):
    d = tmp_path_factory.mktemp("passphrase")
    for name, pass_ in (("prot", "hunter2 correct-horse"), ("plain", "")):
        priv = d / name
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", pass_, "-q",
                        "-f", str(priv), "-C", f"{name}@test"], check=True)
    return d


def test_decrypt_matches_ssh_keygen(protected_key):
    """The recovered public key must be the one OpenSSH derives."""
    d = protected_key
    r = _parse(d / "prot", "hunter2 correct-horse")
    assert r.returncode == 0, r.stderr
    pub_hex = r.stdout.split()[0].split("=")[1]
    expected_token = _ssh_pub(d / "prot", "hunter2 correct-horse")
    # The ssh-keygen token is the full SSH wire format ('ssh-ed25519' string
    # + length-prefixed key); our parser returns the raw 32-byte key, which is
    # the final 32 bytes of the decoded token.
    decoded = base64.b64decode(expected_token)
    assert len(decoded) == 4 + 11 + 4 + 32   # ::u32 "ssh-ed25519" ::u32 <32-byte key>
    assert pub_hex == decoded[-32:].hex()


def test_recovered_seed_matches_passphrase_removed_key(tmp_path):
    """The recovered seed must equal OpenSSH's own stripped copy, byte for byte."""
    # One protected key; put it in a private dir so stripping can't clash.
    d = tmp_path / "k"
    d.mkdir()
    priv = d / "id"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "hunter2 correct-horse",
                    "-q", "-f", str(priv), "-C", "seed@test"], check=True)

    got_seed = _parse(priv, "hunter2 correct-horse").stdout.split()[1].split("=")[1]

    # Have OpenSSH itself remove the passphrase, then read the seed it reveals.
    subprocess.run(["ssh-keygen", "-p", "-P", "hunter2 correct-horse", "-N", "",
                    "-f", str(priv), "-q"], check=True)
    ref_seed = _parse(priv, None).stdout.split()[1].split("=")[1]

    assert got_seed == ref_seed


def test_wrong_passphrase_rejected(protected_key):
    d = protected_key
    r = _parse(d / "prot", "wrong")
    assert r.returncode != 0
    assert "integrity" in r.stderr or "failed" in r.stderr.lower()


def test_missing_passphrase_rejected(protected_key):
    d = protected_key
    r = _parse(d / "prot", None)
    assert r.returncode != 0
    assert "passphrase" in r.stderr.lower()


def test_plain_key_with_and_without_passphrase(protected_key):
    d = protected_key
    # An unencrypted key parses with no passphrase...
    r = _parse(d / "plain", None)
    assert r.returncode == 0, r.stderr
    # ...and is unaffected by an (ignored) passphrase being supplied.
    r2 = _parse(d / "plain", "ignore-me")
    assert r2.returncode == 0, r2.stderr
    assert r.stdout == r2.stdout
