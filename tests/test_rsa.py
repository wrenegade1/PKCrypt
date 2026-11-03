"""Tests for RSA recipient-key support (the "PKCRYPT\\x03" container).

Author: Warren Zajac

Anyone can encrypt to a recipient's RSA *public* key; only the holder of the
matching RSA *private* key can decrypt (RSA-OAEP wrapping a fresh 32-byte
session key, then the usual chunked AES-GCM payload). RSA and Ed25519 are
separate, explicitly-tagged container kinds, and a private key of one kind
cannot decrypt the other's file.
"""

from __future__ import annotations

import base64
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_ssh_private_key,
    load_ssh_public_key,
)

from pkcrypt_lib import core, keys


@pytest.fixture(scope="session")
def keypair(tmp_path_factory):
    """A throwaway Ed25519 keypair (the other recipient-key type)."""
    d = tmp_path_factory.mktemp("keys")
    priv = d / "id_ed25519"
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-q",
                    "-f", str(priv), "-C", "ed@example.com"], check=True)
    k = load_ssh_private_key(priv.read_bytes(), password=None)
    return {"seed": k.private_bytes_raw(),
            "public": k.public_key().public_bytes_raw()}


@pytest.fixture(scope="session")
def rsa4096(tmp_path_factory):
    """A throwaway RSA-4096 keypair (the size commonly used in the field)."""
    d = tmp_path_factory.mktemp("rsa4096")
    priv = d / "id_rsa"
    subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "4096", "-N", "", "-q",
                    "-f", str(priv), "-C", "rsa@example.com"], check=True)
    return {
        "priv_path": str(priv),
        "pub_path": str(priv) + ".pub",
        "priv": load_ssh_private_key(priv.read_bytes(), password=None),
        "pub": load_ssh_public_key(Path(str(priv) + ".pub").read_bytes()),
    }


@pytest.fixture(scope="session")
def rsa2048(tmp_path_factory):
    d = tmp_path_factory.mktemp("rsa2048")
    priv = d / "id_rsa"
    subprocess.run(["ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-q",
                    "-f", str(priv), "-C", "rsa2048@example.com"], check=True)
    return {
        "priv_path": str(priv),
        "priv": load_ssh_private_key(priv.read_bytes(), password=None),
        "pub": load_ssh_public_key(Path(str(priv) + ".pub").read_bytes()),
    }


def test_keys_loader_detects_type(rsa4096):
    pk = keys.load_public_key(rsa4096["pub_path"])
    assert pk.type == "rsa"
    assert pk.key.key_size == 4096
    prv = keys.load_private_key(rsa4096["priv_path"])
    assert prv.type == "rsa"


def test_core_roundtrip(rsa4096):
    data = b"RSA round trip " * 50
    blob = core.encrypt_bytes_rsa(data, rsa4096["pub"])
    assert blob.startswith(core._MAGIC_RSA)
    assert core.decrypt_bytes_rsa(blob, rsa4096["priv"]) == data


def test_nontrivial_sizes_and_ciphers(rsa4096, rsa2048):
    # Both RSA sizes, both payload ciphers, and a range of lengths (empty,
    # a couple bytes, just over one chunk, and a few MiB spanning many chunks).
    sizes = [b"", b"x", b"y" * 32, b"z" * ((1 << 20) + 5), b"w" * (2 * (1 << 20))]
    pairs = [(rsa4096["pub"], rsa4096["priv"]),
             (rsa2048["pub"], rsa2048["priv"])]
    for plaintext in sizes:
        for pub, priv in pairs:
            for cipher in (core._CIPHER_AES, core._CIPHER_XCHACHA20):
                blob = core.encrypt_bytes_rsa(plaintext, pub, cipher=cipher)
                assert core.decrypt_bytes_rsa(blob, priv) == plaintext


def test_wrong_rsa_key_rejected(rsa4096, rsa2048):
    blob = core.encrypt_bytes_rsa(b"secret", rsa4096["pub"])
    with pytest.raises(ValueError):
        core.decrypt_bytes_rsa(blob, rsa2048["priv"])


def test_ed25519_and_rsa_are_disjoint(rsa4096, keypair):
    rsa_blob = core.encrypt_bytes_rsa(b"a", rsa4096["pub"])
    ed_blob = core.encrypt_bytes(b"a", keypair["public"])
    # RSA container can't be decrypted with an Ed25519 key...
    with pytest.raises(ValueError):
        core.decrypt_bytes(rsa_blob, keypair["seed"], keypair["public"])
    # ...and an Ed25519 container can't be decrypted with an RSA key.
    with pytest.raises(ValueError):
        core.decrypt_bytes_rsa(ed_blob, rsa4096["priv"])


def test_tampering_detected(rsa4096):
    data = b"a" * 64
    blob = bytearray(core.encrypt_bytes_rsa(data, rsa4096["pub"]))
    blob[len(blob) // 2] ^= 0xFF
    with pytest.raises(ValueError):
        core.decrypt_bytes_rsa(bytes(blob), rsa4096["priv"])


def _cli_encrypt(pub, src, out):
    import os
    import sys
    from pkcrypt_lib.cli import main
    sys.argv = ["pkcrypt", "encrypt", str(pub), str(src), str(out)]
    return main()


def _cli_decrypt(priv, container, out):
    import sys
    from pkcrypt_lib.cli import main
    sys.argv = ["pkcrypt", "decrypt", str(priv), str(container), str(out)]
    return main()


def test_cli_encrypt_decrypt_file(rsa4096, tmp_path):
    src = tmp_path / "in.txt"
    src.write_bytes(b"file payload via RSA " * 4)
    ct = tmp_path / "ct.pkcrypt"
    out = tmp_path / "out.txt"
    assert _cli_encrypt(rsa4096["pub_path"], src, ct) == 0
    assert ct.read_bytes().startswith(core._MAGIC_RSA)
    assert _cli_decrypt(rsa4096["priv_path"], ct, out) == 0
    assert out.read_bytes() == src.read_bytes()


def test_cli_folder_roundtrip(rsa4096, tmp_path):
    folder = tmp_path / "folder"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_bytes(b"alpha")
    (folder / "sub" / "b.bin").write_bytes(b"beta beta")
    ct = tmp_path / "folder.pkcrypt"
    out = tmp_path / "restored"
    assert _cli_encrypt(rsa4096["pub_path"], folder, ct) == 0
    assert _cli_decrypt(rsa4096["priv_path"], ct, out) == 0
    assert (out / "a.txt").read_bytes() == b"alpha"
    assert (out / "sub" / "b.bin").read_bytes() == b"beta beta"


# ---------------------------------------------------------------------------
# Malformed RSA public keys are refused by both implementations
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent
_BIN = _ROOT / "pkcrypt"


def _mpint(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")    # keeps a leading 0x00 if the top bit is set
    return struct.pack(">I", len(b)) + b


def _ssh_rsa_pub(e: int, n: int) -> str:
    t = b"ssh-rsa"
    blob = struct.pack(">I", len(t)) + t + _mpint(e) + _mpint(n)
    return f"ssh-rsa {base64.b64encode(blob).decode()} bogus\n"


@pytest.mark.parametrize("tool", ["py", "cpp"])
@pytest.mark.parametrize("case", ["e=1", "e=2", "e even", "e=n"])
def test_malformed_rsa_public_key_refused(tmp_path, tool, case):
    """e = 1 would make RSA-OAEP the identity (the session key in the clear);
    even e, e < 3 or e >= n are not valid RSA keys. Encryption must refuse."""
    if tool == "cpp" and not _BIN.exists():
        pytest.skip("C++ binary not built")
    n = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers().n
    e = {"e=1": 1, "e=2": 2, "e even": 65536, "e=n": n}[case]
    pub = tmp_path / "bad.pub"
    pub.write_text(_ssh_rsa_pub(e, n))
    payload = tmp_path / "p.txt"
    payload.write_text("secret")
    cmd = [sys.executable, "-m", "pkcrypt_lib"] if tool == "py" else [str(_BIN)]
    r = subprocess.run([*cmd, "encrypt", str(pub), str(payload)], capture_output=True,
                       text=True, cwd=_ROOT)
    assert r.returncode == 2, r.stdout + r.stderr          # key error, both tools
    assert "Traceback" not in r.stderr
    assert not (tmp_path / "p.txt.pkcrypt").exists()
