"""Cryptographic integrity tests: the container must resist tampering.

Author: Warren Zajac

These assert the core security promise - that an attacker who can modify a
``.pkcrypt`` cannot get the recipient to accept anything but the exact bytes
the sender encrypted. Every chunk's nonce is bound to its position and its
AAD is the header plus a final-chunk flag, so reordering, duplicating,
dropping, splicing, or editing chunks, and editing any header field, must all
fail the AEAD tag. Checked at the library level (fast, exhaustive) across both
ciphers and both payload types; the CLI-level "no output on rejection"
behavior is covered in test_roundtrip.py and test_archive.py.
"""

from __future__ import annotations

import os

import pytest

from cryptography.exceptions import InvalidTag

from pkcrypt_lib import core

from test_roundtrip import keypair, other_keypair  # noqa: F401  (fixtures)

CIPHERS = [core._CIPHER_AES, core._CIPHER_XCHACHA20]
CIPHER_IDS = ["aes", "xchacha20"]
CHUNK = 64


def _split(container: bytes, cipher: int):
    """Return (header, [ciphertext blocks]) for a container made with CHUNK."""
    nonce_len = core._NONCE_AES if cipher == core._CIPHER_AES else core._NONCE_XC
    hdr = core._header_size(nonce_len)
    block = CHUNK + core._TAG_BYTES
    body = container[hdr:]
    return container[:hdr], [body[i:i + block] for i in range(0, len(body), block)]


def _rejects(keypair, container: bytes):
    with pytest.raises((InvalidTag, ValueError)):
        core.decrypt_bytes(container, keypair["seed"], keypair["public"])


@pytest.fixture(params=CIPHERS, ids=CIPHER_IDS)
def cipher(request):
    return request.param


@pytest.fixture
def container(keypair, cipher):
    # Four full chunks plus a genuine short final chunk.
    plaintext = os.urandom(CHUNK * 4 + 11)
    blob = core.encrypt_bytes(plaintext, keypair["public"], cipher=cipher, chunk_len=CHUNK)
    assert core.decrypt_bytes(blob, keypair["seed"], keypair["public"]) == plaintext
    return blob, plaintext


def test_baseline_roundtrips(keypair, container):
    blob, plaintext = container
    assert core.decrypt_bytes(blob, keypair["seed"], keypair["public"]) == plaintext


def test_reorder_rejected(keypair, cipher, container):
    blob, _ = container
    hdr, blocks = _split(blob, cipher)
    assert len(blocks) >= 3
    _rejects(keypair, hdr + blocks[1] + blocks[0] + b"".join(blocks[2:]))   # swap 0,1
    _rejects(keypair, hdr + b"".join(reversed(blocks)))                     # reverse all
    _rejects(keypair, hdr + blocks[-1] + b"".join(blocks[1:-1]) + blocks[0])  # ends swap


def test_replay_and_append_rejected(keypair, cipher, container):
    blob, _ = container
    hdr, blocks = _split(blob, cipher)
    _rejects(keypair, hdr + blocks[0] + b"".join(blocks))     # duplicate first
    _rejects(keypair, blob + blocks[0])                       # append after final
    _rejects(keypair, blob + blocks[-1])                      # replay final past end


def test_drop_and_truncate_rejected(keypair, cipher, container):
    blob, _ = container
    hdr, blocks = _split(blob, cipher)
    _rejects(keypair, hdr + b"".join(blocks[:2] + blocks[3:]))   # delete a middle chunk
    _rejects(keypair, hdr + b"".join(blocks[:-1]))              # drop final chunk
    _rejects(keypair, hdr + blocks[0])                         # first chunk alone as "file"
    _rejects(keypair, blob[:-1])                               # nibble the last tag


def test_bitflip_in_each_chunk_rejected(keypair, cipher, container):
    blob, _ = container
    hdr, blocks = _split(blob, cipher)
    for i in range(len(blocks)):
        pos = len(hdr) + sum(len(b) for b in blocks[:i])       # first byte of chunk i
        _rejects(keypair, blob[:pos] + bytes([blob[pos] ^ 1]) + blob[pos + 1:])


def test_every_header_byte_is_authenticated(keypair, cipher, container):
    # Flipping any single header byte must make decryption fail (bad parse or
    # failed tag), never silently decrypt. The magic is covered too.
    blob, _ = container
    hdr_len = len(_split(blob, cipher)[0])
    for pos in range(hdr_len):
        _rejects(keypair, blob[:pos] + bytes([blob[pos] ^ 0x01]) + blob[pos + 1:])


def test_cross_file_splice_rejected(keypair, cipher, container):
    # A chunk from another container to the same recipient (fresh ephemeral key,
    # fresh base nonce) cannot be spliced in.
    blob, _ = container
    hdr, blocks = _split(blob, cipher)
    other = core.encrypt_bytes(os.urandom(CHUNK * 4 + 11), keypair["public"],
                               cipher=cipher, chunk_len=CHUNK)
    _, oblocks = _split(other, cipher)
    _rejects(keypair, hdr + blocks[0] + oblocks[1] + b"".join(blocks[2:]))


def test_wrong_recipient_rejected(keypair, other_keypair, cipher, container):
    blob, _ = container
    with pytest.raises((InvalidTag, ValueError)):
        core.decrypt_bytes(blob, other_keypair["seed"], other_keypair["public"])


def test_archive_payload_tampering_rejected(keypair, cipher):
    # Same guarantees when the payload is a folder archive.
    plaintext = os.urandom(CHUNK * 3 + 5)
    blob = core.encrypt_bytes(plaintext, keypair["public"], cipher=cipher,
                              chunk_len=CHUNK, payload_type=core.PAYLOAD_ARCHIVE)
    hdr, blocks = _split(blob, cipher)
    # Payload-type byte is authenticated, so this still fails the tag.
    _rejects(keypair, hdr + blocks[1] + blocks[0] + b"".join(blocks[2:]))
    # And it must not be mistakable for a plain-file payload either.
    assert core.peek_payload_type(__import__("io").BytesIO(blob)) == core.PAYLOAD_ARCHIVE
