"""End-to-end tests for PKCrypt.

Author: Warren Zajac

Run with:  python3 -m pytest tests/ -v
(or:       python3 tests/test_roundtrip.py)

Uses a freshly generated throwaway Ed25519 OpenSSH keypair so no real keys
are touched.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.serialization import (
    load_ssh_private_key,
    load_ssh_public_key,
)

from pkcrypt_lib import core
from pkcrypt_lib.cli import main as cli_main
from pkcrypt_lib import files

# ---------------------------------------------------------------------------
# Fixtures: a throwaway keypair and scratch dir
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def keypair(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    priv = d / "id_ed25519"
    pub = d / "id_ed25519.pub"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-q",
         "-f", str(priv), "-C", "test@example.com"],
        check=True,
    )
    private_key = load_ssh_private_key(priv.read_bytes(), password=None)
    public_key = load_ssh_public_key(pub.read_bytes())
    return {
        "priv_path": str(priv),
        "pub_path": str(pub),
        "seed": private_key.private_bytes_raw(),
        "public": public_key.public_bytes_raw(),
    }


@pytest.fixture(scope="session")
def other_keypair(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys2")
    priv = d / "other_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", str(priv)],
        check=True,
    )
    private_key = load_ssh_private_key(priv.read_bytes(), password=None)
    return {
        "priv_path": str(priv),
        "seed": private_key.private_bytes_raw(),
        "public": private_key.public_key().public_bytes_raw(),
    }


# ---------------------------------------------------------------------------
# Core crypto tests
# ---------------------------------------------------------------------------

def test_roundtrip(keypair):
    plaintext = b"the quick brown fox\n" * 20
    blob = core.encrypt_bytes(plaintext, keypair["public"])
    assert blob.startswith(core._MAGIC)
    assert core.decrypt_bytes(blob, keypair["seed"], keypair["public"]) == plaintext


def test_wrong_key_cannot_decrypt(keypair, other_keypair):
    plaintext = b"secret"
    blob = core.encrypt_bytes(plaintext, keypair["public"])
    with pytest.raises(Exception) as e:
        core.decrypt_bytes(blob, other_keypair["seed"], other_keypair["public"])
    assert "InvalidTag" in type(e.value).__name__


def test_ciphertext_is_non_deterministic(keypair):
    plaintext = b"same input"
    a = core.encrypt_bytes(plaintext, keypair["public"])
    b = core.encrypt_bytes(plaintext, keypair["public"])
    assert a != b  # fresh ephemeral key + nonce per call


def test_magic_required(keypair):
    with pytest.raises(ValueError, match="not a PKCrypt file"):
        core.decrypt_bytes(b"garbage", keypair["seed"], keypair["public"])


def test_ed25519_to_x25519_consistency(keypair):
    """The converted keypair must be internally consistent (sk.pub == pk)."""
    from cryptography.hazmat.primitives.asymmetric import x25519
    x_pk = core.ed25519_public_to_x25519_public(keypair["public"])
    x_sk = core.ed25519_private_to_x25519_private(
        keypair["seed"], keypair["public"])
    derived = x25519.X25519PrivateKey.from_private_bytes(x_sk).public_key().public_bytes_raw()
    assert derived == x_pk


# ---------------------------------------------------------------------------
# Full-fidelity CLI tests (invoke main() directly, capture output)
# ---------------------------------------------------------------------------

def _encrypt(pub_path, in_path, out_path=None, capsys=None):
    args = ["encrypt", pub_path, in_path] + ([out_path] if out_path else [])
    return cli_main(args)


def test_cli_encrypt_decrypt_roundtrip(keypair, tmp_path, capsys):
    src = tmp_path / "secret.txt"
    src.write_bytes(b"hello from the test suite\n" * 3)

    # Encrypt with only the public key.
    rc = cli_main(["encrypt", keypair["pub_path"], str(src)])
    assert rc == 0
    encrypted = tmp_path / "secret.txt.pkcrypt"
    assert encrypted.exists()
    assert not b"hello from the test suite" in encrypted.read_bytes()

    # Decrypt with the private key.
    rc = cli_main(["decrypt", keypair["priv_path"], str(encrypted)])
    assert rc == 0
    decrypted = tmp_path / "secret.txt.pkcrypt.decrypted"
    assert decrypted.read_bytes() == src.read_bytes()


def test_cli_wrong_key_fails_cleanly(keypair, other_keypair, tmp_path, capsys):
    src = tmp_path / "s.txt"
    src.write_bytes(b"data")
    cli_main(["encrypt", keypair["pub_path"], str(src)])
    encrypted = tmp_path / "s.txt.pkcrypt"
    rc = cli_main(["decrypt", other_keypair["priv_path"], str(encrypted)])
    assert rc != 0
    assert "decryption failed" in capsys.readouterr().err.lower()


def test_output_path_nonexistent_for_decrypt(keypair, tmp_path):
    src = tmp_path / "report.tar.gz"
    src.write_bytes(b"\x00" * 100)
    cli_main(["encrypt", keypair["pub_path"], str(src)])  # -> report.tar.gz.pkcrypt
    cli_main(["decrypt", keypair["priv_path"], str(src) + ".pkcrypt"])
    # Since original is still present, a non-clobbering path is used.
    dec = tmp_path / "report.tar.gz.pkcrypt.decrypted"
    assert dec.exists()
    assert dec.read_bytes() == b"\x00" * 100


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
