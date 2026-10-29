# Changelog

All notable changes to PKCrypt are documented here. This project follows
[Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH).

## [Unreleased]

### Added

- Interoperable **C++ implementation** (`src/`, `include/`, `Makefile`):
  - Produces and consumes the **same file format** as the Python version, so
    the C++ and Python tools can decrypt each other's files interchangeably.
  - Uses libsodium (X25519 ECDH + HKDF-SHA256 + AES-256-GCM) matching the
    Python scheme exactly.
  - Base64 decoding for OpenSSH key parsing
    (`include/pkcrypt/base64.hpp`).
  - `make test` runs a 9-case cross-language interop suite
    (`tests/test_cpp_interop.py`).

## [1.0.0] - 2026-10-28

### Added

- `pkcrypt encrypt <recipient.pub> <file>` — encrypt a file so only the holder
  of the recipient's Ed25519 SSH private key can decrypt it. Needs only the
  recipient's **public** key.
- `pkcrypt decrypt <private.key> <file.pkcrypt>` — decrypt on the recipient's
  machine with their **private** key.
- Hybrid encryption scheme: fresh ephemeral X25519 keypair → ECDH → HKDF-SHA256 →
  AES-256-GCM (authenticated encryption).
- Ed25519 → X25519 key conversion via libsodium's reference implementation
  (`crypto_sign_ed25519_{pk,sk}_to_curve25519`), matching OpenSSH.
- OpenSSH key parsing (public and private, including passphrase-protected keys
  via `--passphrase`) using the `cryptography` library.
- Container format: `PKCRYPT\x01 | ephemeral_pub | nonce | ciphertext+tag`.
- Wrong-key and tamper detection (AES-GCM authentication).
- Non-clobbering output paths.
- Packaging (`pyproject.toml`) exposing the `pkcrypt` command.
- Test suite (`tests/test_roundtrip.py`) covering round-trips, wrong-key rejection,
  tamper detection, and non-deterministic ciphertext.
- `README.md` documenting usage, design, and security notes.
