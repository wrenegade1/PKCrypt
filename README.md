# PKCrypt

**Author:** Warren Zajac

Encrypt a file so that **only the holder of a specific Ed25519 SSH private key** can
decrypt it — using the same public / private key model as SSH.

[![CI](https://github.com/wrenegade1/PKCrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/wrenegade1/PKCrypt/actions/workflows/ci.yml)

```
  SENDER (any machine)                  RECIPIENT (any machine)
  ─────────────────────                 ─────────────────────────
  pkcrypt encrypt alice.pub file.txt    pkcrypt decrypt ~/.ssh/id_ed25519 file.txt.pkcrypt
         │                                         ▲
         │   needs only Alice's PUBLIC key         │  needs only Alice's PRIVATE key
         ▼                                         │
      file.txt.pkcrypt ───────── send ─────────────┘
```

> You give someone your **public** key (`id_ed25519.pub`). They encrypt a file with it.
> You decrypt it on your machine with your **private** key (`id_ed25519`). Nobody else
> can — not even the person who encrypted it.

---

## Table of contents

- [Highlights](#highlights)
- [Background](#background)
- [Quick start](#quick-start)
- [Installation](#installation)
  - [Python implementation](#python-implementation)
  - [C++ implementation (compiled)](#c-implementation-compiled)
- [Usage](#usage)
  - [Realistic end-to-end workflow](#realistic-end-to-end-workflow)
  - [Command reference](#command-reference)
  - [Output paths](#output-paths)
  - [Key requirements](#key-requirements)
- [How it works: the crypto](#how-it-works-the-crypto)
  - [Ed25519 → X25519 key conversion](#ed25519--x25519-key-conversion)
  - [Hybrid encryption](#hybrid-encryption)
  - [Key derivation (HKDF)](#key-derivation-hkdf)
- [File format specification](#file-format-specification)
- [Threat model & security considerations](#threat-model--security-considerations)
  - [What PKCrypt protects against](#what-pkcrypt-protects-against)
  - [What PKCrypt does not protect against](#what-pkcrypt-does-not-protect-against)
- [Interoperability](#interoperability)
- [Development](#development)
  - [Building & testing](#building--testing)
  - [Running the test suites](#running-the-test-suites)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Roadmap](#roadmap)
- [License & attribution](#license--attribution)

---

## Highlights

- **Two interchangeable implementations** — a Python package and a compiled C++
  binary — that produce the **same file format** and can decrypt each other's output.
- **Reuses your existing SSH keys.** No new key management, no shared passwords.
- **Sender never holds a secret.** Encryption needs only the recipient's public key,
  so you can encrypt from anywhere and never receive private material.
- **Forward secrecy.** A fresh ephemeral key is used per file; even the sender can't
  decrypt after the fact.
- **Authenticated encryption.** Tampered files and wrong keys are detected and
  rejected — never partially decrypted.
- **No crypto invented here.** Built entirely on libsodium and `cryptography`, the
  reference implementations of X25519, HKDF-SHA256, and AES-256-GCM.

---

## Background

Traditional approaches to sending someone a secret file have real weaknesses:

| Approach | Problem |
|----------|---------|
| Password-protected zip | You must exchange the password over a second, insecure channel. |
| Password over email/chat | Intercepted at rest or in transit; both parties must coordinate. |
| Uploading to the cloud | The cloud provider can read your data. |
| Password manager sharing | Heavily tied to one product/ecosystem. |

PKCrypt flips this: **anyone who knows only your public key can send you an encrypted
file that only you can open.** There is no secret to share. This is exactly the trust
model behind SSH, Signal, and PGP — minus the key-management overhead.

---

## Quick start

```bash
# 1. Get the recipient's public key (one line, nothing secret)
cat ~/.ssh/id_ed25519.pub   # on the recipient's machine

# 2. Encrypt a file for them (needs only that public key)
pkcrypt encrypt alice_id_ed25519.pub report.pdf
# -> report.pdf.pkcrypt

# 3. Send it however you like (email, chat, USB, cloud)

# 4. Recipient decrypts on their machine with their private key
pkcrypt decrypt ~/.ssh/id_ed25519 report.pdf.pkcrypt
# -> report.pdf
```

That's it. Same keys you use for SSH, no new infrastructure.

---

## Installation

Both implementations share the same on-disk format and CLI. Install whichever you
prefer — or both; they interoperate.

### Python implementation

Requires **Python 3.9+**.

```bash
# System dependency: libsodium (for the OpenSSH Ed25519->X25519 key conversion)
brew install libsodium

# Python dependency: cryptography (X25519, HKDF, AES-GCM)
pip install cryptography

# Install the package (creates the `pkcrypt` command)
cd PKCrypt
pip install .

# Or run without installing
python3 -m pkcrypt_lib --help
```

### C++ implementation (compiled)

Requires a **C++17** compiler and **libsodium**.

```bash
brew install libsodium

cd PKCrypt
make          # builds ./pkcrypt
make test     # builds + runs the cross-language interop suite
```

The resulting single binary `./pkcrypt` has no Python dependency at runtime.

---

## Usage

```bash
# ENCRYPT a file for someone (needs only their PUBLIC key)
pkcrypt encrypt alice_id_ed25519.pub secrets.tgz
# -> secrets.tgz.pkcrypt

# DECRYPT (their PRIVATE key)
pkcrypt decrypt ~/.ssh/id_ed25519 secrets.tgz.pkcrypt
# -> secrets.tgz
```

Both `./pkcrypt` (C++) and `pkcrypt` / `python3 -m pkcrypt_lib` (Python) accept the
same commands, and files encrypted by either are decryptable by either.

### Realistic end-to-end workflow

Imagine **Alice** wants to send a sensitive archive to **Bob**, who has the SSH keys
in `~/.ssh`.

**On Bob's machine**, Alice gets one thing — the public key (nothing secret):

```bash
# Bob:
cat ~/.ssh/id_ed25519.pub
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... bob@macbook
```

Bob sends that single line to Alice (email, chat — it's public anyway).

**On Alice's machine**, she encrypts **without Bob's private key ever being present**:

```bash
# Alice: save Bob's public key to a file, then
pkcrypt encrypt bob_id_ed25519.pub sensitive-project.tar.gz
# Encrypted sensitive-project.tar.gz -> sensitive-project.tar.gz.pkcrypt
#   recipient: bob_id_ed25519.pub
#   size: 2041 bytes
# Hand sensitive-project.tar.gz.pkcrypt to the recipient; only they can decrypt it.
```

Alice sends `sensitive-project.tar.gz.pkcrypt` to Bob over any channel.

**Back on Bob's machine**, he decrypts with his private key:

```bash
# Bob:
pkcrypt decrypt ~/.ssh/id_ed25519 sensitive-project.tar.gz.pkcrypt
# Decrypted sensitive-project.tar.gz.pkcrypt -> sensitive-project.tar.gz
```

### Command reference

| Command | Description |
|---------|-------------|
| `pkcrypt encrypt <pub> <file> [out]` | Encrypt `file` for the holder of the public key `<pub>`. |
| `pkcrypt decrypt <priv> <file> [out]` | Decrypt `<file>` (a `.pkcrypt` container) with private key `<priv>`. |
| `pkcrypt version` | Print the version. |
| `pkcrypt --help` / `-h` | Show usage. |

Encrypt-only options:

| Flag | Meaning |
|------|---------|
| `encrypt <pub> <file> [out]` | Third positional arg overrides the output path. |

Decrypt-only options:

| Flag | Meaning |
|------|---------|
| `decrypt <priv> <file> [out]` | Third positional arg overrides the output path. |
| `--passphrase` | Prompt for a passphrase-protected private key (Python only). |

Exit codes: `0` success, `1` runtime/security error, `2` usage/key-parse error.

### Output paths

- **Encrypt** defaults to `<input>.pkcrypt`.
- **Decrypt** defaults to:
  - stripping a trailing `.pkcrypt`, or
  - appending `.decrypted` if the original name already exists.
- PKCrypt **never overwrites** an existing file. If the default output path is taken,
  it appends a numeric suffix (`file.1`, `file.2`, …).

### Key requirements

- The recipient's key must be an **Ed25519** SSH key (the modern
  `ssh-keygen -t ed25519`). RSA, ECDSA, Ed448, etc. are rejected with a clear message.
- **Python** supports passphrase-protected private keys via `decrypt --passphrase`.
- **C++** supports unencrypted private keys only. To use a protected key with the C++
  binary, decrypt it once first:
  ```bash
  ssh-keygen -p -f ~/.ssh/id_ed25519 -N ""
  ```

---

## How it works: the crypto

PKCrypt uses **hybrid public-key encryption** — a standard, battle-tested scheme
(a blend of the constructions used by age, minisign, and OpenSSH itself).

### Ed25519 → X25519 key conversion

Ed25519 keys are designed for *signing*, not *encryption*. To encrypt, PKCrypt
converts the Ed25519 key to an **X25519** key — the Diffie-Hellman key type on the
same Curve25519. The conversion uses libsodium's reference implementation, which is
byte-for-byte what OpenSSH uses:

```
crypto_sign_ed25519_pk_to_curve25519(recipient_x_pk, ed25519_pub)   # public
crypto_sign_ed25519_sk_to_curve25519(recipient_x_sk, ed25519_sk)    # private
```

Both implementations call these exact functions — natively in C++, and through a thin
`ctypes` binding in Python — so the keys, conversions, and ciphertexts are identical
across languages.

### Hybrid encryption

Symmetric encryption (AES) is fast but needs a shared key; asymmetric encryption
(X25519) solves key exchange but is not meant to encrypt bulk data directly. PKCrypt
combines both:

1. **Ephemeral keypair.** The sender generates a brand-new X25519 keypair
   (`eph_pk`, `eph_sk`) for this file only. It is discarded after one use.
2. **ECDH.** The sender computes the shared secret
   `S = eph_sk · recipient_x_pk`. The recipient computes the *same*
   `S = recipient_x_sk · eph_pk`. Only the recipient's private key can produce `S`.
3. **Key derivation.** `S` is passed through HKDF-SHA256 (with the ephemeral and
   recipient public keys bound in) to produce a 256-bit AES key. This adds domain
   separation and prevents any re-use across different file/recipient contexts.
4. **Authenticated encryption.** The file is encrypted with **AES-256-GCM**, which
   produces ciphertext plus a 16-byte authentication tag. Any modification to the
   ciphertext — or decryption with the wrong key — fails the tag check and is
   rejected outright.

### Key derivation (HKDF)

Following [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869), HKDF-SHA256 has two
phases:

```
PRK = HMAC-SHA256(salt = "PKCrypt", IKM = shared_secret)
OKM = HMAC-SHA256(PRK, info || 0x01)   # 32-byte AES-256 key
```

where `info = "PKCrypt/v1/x25519-ecdh+aes-256-gcm" || eph_pk || recipient_x_pk`.
Binding the two public keys into `info` guarantees a distinct key for every
(sender, recipient, file) combination.

---

## File format specification

The `.pkcrypt` file is a single self-contained container. The recipient needs nothing
but their private key to open it.

```
 Format version 1
 ┌────────────────┬────────────────────┬──────────────────────┬───────────────────────────┐
 │ magic (8 B)    │ ephemeral pub (32) │ nonce (12 B)         │ ciphertext + GCM tag (n B) │
 │ "PKCRYPT\x01"  │ sender's X25519 pk │ AES-256-GCM nonce    │ encrypted file + 16-byte   │
 │                │                    │                      │ authentication tag         │
 └────────────────┴────────────────────┴──────────────────────┴───────────────────────────┘
```

| Field | Size | Description |
|-------|------|-------------|
| `magic` | 8 B | ASCII `PKCRYPT` followed by `0x01` (format version). |
| `ephemeral public key` | 32 B | The sender's one-time X25519 public key. |
| `nonce` | 12 B | Random, unique AES-GCM nonce (never reused). |
| `ciphertext` | n B | AES-256-GCM ciphertext, including the 16-byte tag. |

Total overhead over plaintext is a constant **68 bytes** (8 + 32 + 12 + 16).

The format is identical between the Python and C++ implementations, which is what makes
them fully interoperable.

---

## Threat model & security considerations

This section states honestly what PKCrypt does and does not guarantee.

### What PKCrypt protects against

- **Eavesdropping on file transfer.** A `.pkcrypt` file is indecipherable without the
  private key, so it is safe to send over email, chat, USB, or cloud storage.
- **The wrong person decrypting.** Only the recipient's private key can recover the
  shared secret. A different private key produces a different key and fails the GCM
  authenticity check.
- **Tampering.** AES-GCM is an *authenticated* cipher; altering a single bit of the
  file is detected and rejected.
- **The sender later reading the file.** Because the ephemeral key is discarded, the
  sender cannot recompute the AES key after encryption.
- **Theft of the *public* key.** The public key is, well, public. Compromise of it
  reveals nothing.

### What PKCrypt does **not** protect against

- **Compromise of the *private* key.** If someone acquires the recipient's private
  key (or passphrase), they can decrypt. Protect it as you would any SSH key.
- **The recipient's machine being compromised while decrypting.** PKCrypt decrypts
  into plaintext in memory and writes it to disk; a keylogger, active malware, or
  memory dump on the recipient's machine could capture it.
- **Forward secrecy against the *recipient*.** The recipient can decrypt at any time
  (past, present, future) as long as they hold the private key — by design.
- **Denial of service.** Anyone with the public key can encrypt files *for* the
  recipient; nothing prevents spam or huge files.
- **Non-repudiation of sender.** PKCrypt authenticates the *ciphertext* but does not
  prove *who* encrypted it. It is not a digital signature.

### Cryptography hygiene

- All primitives come from libsodium and OpenSSL's `cryptography` bindings — the
  reference libraries. PKCrypt invokes them; it does not implement any crypto itself.
- A fresh ephemeral key and a fresh random nonce are generated for **every** file,
  so the same plaintext encrypted twice yields entirely different ciphertexts.
- Sensitive intermediates (shared secrets, derived keys) are wiped from memory as
  soon as they are no longer needed.

---

## Interoperability

The Python and C++ implementations are drop-in replacements for each other:

| | encrypt | decrypt | where the output opens |
|---|---|---|---|
| Python → Python | ✅ | ✅ | anywhere |
| C++ → C++ | ✅ | ✅ | anywhere |
| **Python → C++** | ✅ | ✅ | cross-language |
| **C++ → Python** | ✅ | ✅ | cross-language |

Interoperability is enforced automatically by `make test`, which encrypts with one
tool and decrypts with the other. And because the Ed25519→X25519 conversion matches
OpenSSH, PKCrypt keys are the same keys you already use for SSH — no new secret to
manage.

---

## Development

### Building & testing

```bash
# Build the C++ binary
make

# Remove build artifacts
make clean

# Build + run the C++ interop suite
make test
```

The repo is intentionally simple: no submodules, no generated code, and no network
needed at build time — every source file (C++ and Python) is written in-house. The
only external dependency is the libsodium and `cryptography` libraries you install.

### Running the test suites

```bash
# Python unit tests (8): round-trip, wrong key, tamper, non-determinism, CLI
python3 -m pytest tests/ -v

# C++ cross-language interop (9): each direction, wrong key, tamper, bad magic
make test
```

Both suites generate throwaway keys in a temp directory and never touch your real
`~/.ssh` keys.

---

## Troubleshooting

### `error: decryption failed: file is not for this private key, or it was tampered with`
You are using the **wrong private key**, or the `.pkcrypt` file was **modified** since
creation, or the decrypted bit was corrupted in transit. Verify you have the correct
key and an intact file.

### `error: not a PKCrypt file (bad header)` / `encrypted payload too short`
The input is not a PKCrypt container, or it is truncated. Confirm the file was
created by `pkcrypt encrypt` and transferred completely (binary-safe).

### `error: unsupported key type 'ssh-rsa' (expected ssh-ed25519)`
PKCrypt only accepts **Ed25519** keys. Generate one with:
```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
```

### `error: encrypted/passphrase-protected private keys are not supported`
(Common with the C++ binary.) The private key has a passphrase. Either use the Python
implementation with `--passphrase`, or remove the passphrase for this key once:
```bash
ssh-keygen -p -f ~/.ssh/id_ed25519 -N ""
```

### `import error: libsodium is required ...`
(Python, at import time.) Install libsodium:
```bash
brew install libsodium
```

### Feeling stuck?
Open an issue on the repository with the exact command and error message (redact any
keys and the file contents).

---

## Project layout

```
PKCrypt/
├── pkcrypt_lib/            # Python implementation
│   ├── core.py             #   Ed25519->X25519 + hybrid encrypt/decrypt (crypto)
│   ├── keys.py             #   OpenSSH key-file parsing
│   ├── files.py            #   file I/O + output-path handling
│   ├── cli.py              #   command-line interface
│   ├── __init__.py
│   └── __main__.py         #   enables `python3 -m pkcrypt_lib`
├── src/                    # C++ implementation
│   ├── pkcrypt.cpp         #   CLI (encrypt / decrypt)
│   ├── ssh_key.cpp         #   OpenSSH key parsing
│   ├── crypto.cpp          #   X25519 + HKDF-SHA256 + AES-256-GCM
│   ├── fileio.cpp          #   file I/O
│   └── base64.cpp          #   own base64 decoder/encoder (RFC 4648)
├── include/pkcrypt/        # C++ headers
│   ├── crypto.h  ssh_key.h  fileio.h  version.h
│   └── base64.h            #   own base64 API
├── tests/                  # test suites
│   ├── test_roundtrip.py   #   Python unit tests (pytest)
│   └── test_cpp_interop.py #   cross-language interop (make test)
├── Makefile                # builds ./pkcrypt; `make test`
├── pyproject.toml          # Python packaging (console script: pkcrypt)
├── .gitignore
├── README.md
└── CHANGELOG.md
```

---

## Roadmap

Planned / suggested improvements:

- **`generate` command** — mint a fresh Ed25519 keypair for someone who doesn't yet
  have SSH keys.
- **Affine signing** — also sign the plaintext so recipients can verify *who* sent it
  (adds sender authenticity / non-repudiation).
- **Wipe-on-delete option** — optionally shred the plaintext after encryption.
- **Double-clickable app wrappers** — package the decrypt tool as a Mac .app for
  non-technical recipients.
- **`--armor` output** — base64-encode the container so it survives text-only
  channels (e.g., pasting into chat).
- **CI workflow** — run both test suites on GitHub Actions for macOS and Linux.

Contributions and ideas are welcome — open an issue or a pull request.

---

## License & attribution

**Author and maintainer:** Warren Zajac

PKCrypt is released under the **Apache License, Version 2.0**. See the repository license file for the
full text.

The base64 encoder/decoder in `src/base64.cpp` is **our own** implementation,
written in-house and verified byte-for-byte against the standard reference (the
Python `base64` module) over real OpenSSH keys, all input-length classes, padding
variants, and embedded newline wrapping.

The implementation relies on (but does not bundle) these third-party libraries:

| Component | License | Purpose |
|-----------|---------|---------|
| [libsodium](https://doc.libsodium.org/) | ISC | Ed25519→X25519 conversion, X25519, HKDF, AES-GCM primitives. |
| [cryptography](https://cryptography.io/) | Apache-2.0 / BSD | OpenSSH key parsing and Python crypto primitives. |

PKCrypt is an independent project and is not affiliated with or endorsed by OpenSSH,
libsodium, or the Python `cryptography` project.
