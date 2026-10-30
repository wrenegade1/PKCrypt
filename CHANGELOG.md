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
  - **Own base64 encoder/decoder** (`src/base64.cpp`, `include/pkcrypt/base64.h`)
    written in-house, verified byte-for-byte against the reference (Python
    `base64`) over real OpenSSH keys, all input-length classes, padding
    variants, and embedded newline wrapping.
  - `make test` runs a 9-case cross-language interop suite
    (`tests/test_cpp_interop.py`).

### Changed

- Expanded `README.md` into a detailed guide covering quick start, install for
  both implementations, full usage and workflow, the crypto design, the on-disk
  file format specification, threat model and security considerations,
  interoperability, development/testing, troubleshooting, project layout,
  roadmap, and license/attribution.
- Replaced the previously vendored third-party `tobiaslocker/base64` header with
  our own in-house base64 implementation (no bundled third-party code remains).
- Added author attribution (Warren Zajac) to file headers, comments, and pyproject
  metadata across the codebase.
- Added the `LICENSE` file (Apache License 2.0).

### Security

- **File permissions** — all output files (encrypted containers and decrypted
  plaintext) are now written with restrictive `0600` permissions in both the
  Python and C++ implementations, so decrypted plaintext is never world-readable.
- **No silent overwrite / atomic writes** — writing to an existing output path is
  refused rather than silently overwriting it, and writes go to a temp file that
  is atomically linked into place, so a crash can never leave a half-written or
  partial file. Applies to both Python and C++.
- **Passphrase-key guidance** — the README and C++ `--help` no longer advise
  stripping a key's passphrase (`ssh-keygen -p -f ... -N ""`). They now point
  passphrase-protected-key users to the Python CLI's `decrypt --passphrase`.

### Added

- **v2 container format** (`PKCRYPT\x02`) with, interoperably in both Python and
  C++:
  - **Chunked encryption** — plaintext is split into 1 MiB chunks, each encrypted
    with a distinct per-chunk nonce, so the format supports arbitrarily large
    files without a single AEAD message limit.
  - **Authenticated header** — the fixed header (magic, cipher byte, ephemeral
    key, base nonce, chunk size) is passed as associated data (AAD) to every
    chunk, so any tampering with the header fails the authentication tag.
  - **Cipher byte** selects AES-256-GCM (`0x00`) or XChaCha20-Poly1305 (`0x01`),
    the latter as a fallback for CPUs without AES hardware acceleration
    (C++ uses libsodium; Python binds libsodium for XChaCha20).
  - **Backwards compatible** — v1 (`PKCRYPT\x01`) containers remain readable.
- **Pure-Python private-key conversion** — the Ed25519 seed → X25519 private key
  (SHA-512 + bit-clamping) no longer requires libsodium; the public-key
  conversion still uses libsodium, now located robustly via
  `ctypes.util.find_library("sodium")`.
- **C++ private-key validation** — the parser now confirms the redundant public
  key stored in an OpenSSH private key matches the seed, and wipes the raw seed
  buffers from memory after parsing.

### Fixed

- **Python decrypt** now rejects truncated/too-short containers with a clear
  "too short" error instead of a less helpful one.
- **Unified test command** — `make test` (and CMake `check`) now run BOTH the
  Python unit suite and the C++ interop suite in one command.
- **README threat model** now explicitly states that sender identity is not
  verified (anyone with your public key can encrypt to you; signing is future
  work).

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
