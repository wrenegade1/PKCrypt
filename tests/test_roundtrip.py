# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Warren Zajac
"""End-to-end tests for PKCrypt.

Author: Warren Zajac

Run with:  python3 -m pytest tests/ -v
(or:       python3 tests/test_roundtrip.py)

Uses a freshly generated throwaway Ed25519 OpenSSH keypair so no real keys
are touched.
"""

from __future__ import annotations

import io
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from cryptography.exceptions import InvalidTag
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


# ---------------------------------------------------------------------------
# Streaming tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cipher", [core._CIPHER_AES, core._CIPHER_XCHACHA20])
@pytest.mark.parametrize("size", [0, 1, 63, 64, 65, 64 * 5, 64 * 5 + 7])
def test_stream_matches_bytes_api(keypair, cipher, size):
    # Small chunk_len so the inputs span several chunks, incl. exact multiples.
    plaintext = os.urandom(size)
    container = b"".join(core.encrypt_stream(
        [plaintext[i:i + 10] for i in range(0, size, 10)],
        keypair["public"], cipher=cipher, chunk_len=64,
    ))
    assert len(container) == len(core.encrypt_bytes(
        plaintext, keypair["public"], cipher=cipher, chunk_len=64))
    # Stream output decrypts with the stream API, fed in odd-sized pieces...
    pieces = [container[i:i + 37] for i in range(0, len(container), 37)]
    out = b"".join(core.decrypt_stream(pieces, keypair["seed"], keypair["public"]))
    assert out == plaintext
    # ...and with the whole-buffer API.
    assert core.decrypt_bytes(container, keypair["seed"],
                              keypair["public"]) == plaintext


def test_stream_reads_binary_file_in_blocks(keypair, tmp_path):
    # No newlines: line iteration would read this in one piece.
    src = tmp_path / "blob.bin"
    src.write_bytes(b"\xff" * 1000)
    reads = []

    class Spy:
        def __init__(self, fh):
            self._fh = fh
        def read(self, n):
            reads.append(n)
            return self._fh.read(n)

    with open(src, "rb") as fh:
        container = b"".join(core.encrypt_stream(Spy(fh), keypair["public"],
                                                 chunk_len=100))
    assert max(reads) == 100
    out = b"".join(core.decrypt_stream(io.BytesIO(container), keypair["seed"],
                                       keypair["public"]))
    assert out == src.read_bytes()


CHUNK = 64
BLOCK = CHUNK + core._TAG_BYTES
HEADER_AES = core._header_size(core._NONCE_AES)


def _split(container):
    """Return (header, [ciphertext blocks]) for an AES container."""
    payload = container[HEADER_AES:]
    return container[:HEADER_AES], [payload[i:i + BLOCK]
                                    for i in range(0, len(payload), BLOCK)]


def _assert_rejected(keypair, container):
    with pytest.raises((InvalidTag, ValueError)):
        core.decrypt_bytes(container, keypair["seed"], keypair["public"])


def test_empty_plaintext_is_one_final_chunk(keypair):
    container = core.encrypt_bytes(b"", keypair["public"], chunk_len=CHUNK)
    header, blocks = _split(container)
    assert [len(b) for b in blocks] == [core._TAG_BYTES]
    assert core.decrypt_bytes(container, keypair["seed"], keypair["public"]) == b""
    # A bare header (no chunks at all) is not a valid container.
    _assert_rejected(keypair, header)


@pytest.mark.parametrize("size", [CHUNK * 3, CHUNK * 3 + 10])
def test_truncation_at_chunk_boundary_rejected(keypair, size):
    container = core.encrypt_bytes(os.urandom(size), keypair["public"],
                                   chunk_len=CHUNK)
    header, blocks = _split(container)
    for keep in range(len(blocks)):
        _assert_rejected(keypair, header + b"".join(blocks[:keep]))
    # Cutting inside the last block is also rejected.
    _assert_rejected(keypair, container[:-1])


def test_extension_and_reordering_rejected(keypair):
    container = core.encrypt_bytes(os.urandom(CHUNK * 3), keypair["public"],
                                   chunk_len=CHUNK)
    header, blocks = _split(container)
    _assert_rejected(keypair, container + blocks[-1])          # replay final
    _assert_rejected(keypair, container + blocks[0])           # append non-final
    _assert_rejected(keypair, header + blocks[1] + blocks[0] + blocks[2])
    _assert_rejected(keypair, container + b"\x00")             # trailing byte


def test_cli_empty_file_roundtrip(keypair, tmp_path):
    src = tmp_path / "empty"
    src.write_bytes(b"")
    assert cli_main(["encrypt", keypair["pub_path"], str(src)]) == 0
    assert cli_main(["decrypt", keypair["priv_path"],
                     str(tmp_path / "empty.pkcrypt")]) == 0
    assert (tmp_path / "empty.pkcrypt.decrypted").read_bytes() == b""


def test_cli_truncated_file_leaves_no_output(keypair, tmp_path, capsys):
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(core.DEFAULT_CHUNK_LEN * 2))
    assert cli_main(["encrypt", keypair["pub_path"], str(src)]) == 0
    enc = tmp_path / "big.bin.pkcrypt"
    # Drop the final chunk: the remaining chunks are all individually valid.
    enc.write_bytes(enc.read_bytes()[:-(core.DEFAULT_CHUNK_LEN + core._TAG_BYTES)])

    assert cli_main(["decrypt", keypair["priv_path"], str(enc)]) != 0
    assert not (tmp_path / "big.bin.pkcrypt.decrypted").exists()


def test_cli_tampered_chunk_leaves_no_output(keypair, tmp_path, capsys):
    src = tmp_path / "big.bin"
    src.write_bytes(os.urandom(core.DEFAULT_CHUNK_LEN * 2 + 5))
    assert cli_main(["encrypt", keypair["pub_path"], str(src)]) == 0
    enc = tmp_path / "big.bin.pkcrypt"
    data = bytearray(enc.read_bytes())
    data[-3] ^= 0x01  # corrupt the last chunk; earlier chunks still decrypt
    enc.write_bytes(bytes(data))

    rc = cli_main(["decrypt", keypair["priv_path"], str(enc)])
    assert rc != 0
    # Plaintext from the authentic early chunks must not be published.
    assert not (tmp_path / "big.bin.pkcrypt.decrypted").exists()
    assert not list(tmp_path.glob(".*.tmp"))


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
