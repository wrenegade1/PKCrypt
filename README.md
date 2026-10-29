# PKCrypt

Encrypt a file so that **only the holder of a specific Ed25519 SSH private key** can
decrypt it — using the same public/private key model as SSH.

> You give someone your **public** key (`id_ed25519.pub`). They encrypt a file with it.
> You decrypt it on your machine with your **private** key (`id_ed25519`). Nobody else
> can — not even the person who encrypted it.

```
  SENDER (any machine)                RECIPIENT (Mac)
  ─────────────────────               ─────────────────
  pkcrypt encrypt alice.pub file.txt  pkcrypt decrypt ~/.ssh/id_ed25519 file.txt.pkcrypt
         │                                    ▲
         │   needs only Alice's               │  needs only Alice's
         │   PUBLIC key                       │  PRIVATE key
         ▼                                    │
      file.txt.pkcrypt ─────── send ──────────┘
```

## Why it matters

- **No shared password** to exchange over a phone call or chat.
- **Encrypt from anywhere** — the sender never sees or handles a secret. Only the
  public key leaves Alice's control.
- Reuses keys you **already have** from SSH (`~/.ssh/id_ed25519`). No new key
  infrastructure to manage.

## How it works (the crypto)

PKCrypt uses **hybrid encryption** with the Ed25519→X25519 key conversion that
OpenSSH itself uses:

1. The recipient's Ed25519 key is converted to an X25519 key using libsodium's
   reference `crypto_sign_ed25519_{pk,sk}_to_curve25519` conversions.
2. The sender generates a **fresh ephemeral** X25519 keypair and runs Elliptic-Curve
   Diffie-Hellman (ECDH) against the recipient's public key → a shared secret.
3. The shared secret is expanded with **HKDF-SHA256** into a symmetric key that
   encrypts the file with **AES-256-GCM** (authenticated — tampering is detected).
4. The output embeds the ephemeral public key + nonce, so the recipient needs
   nothing but their private key.

Because only the recipient's private key can recompute the shared secret, only they
can decrypt. The sender's own ephemeral key also means **even the sender can't
decrypt it after the fact** — a nice property for sensitive file handoff.

Both the Python and C++ implementations realize this exact scheme and produce the
same on-disk container, so a file encrypted by one tool decrypts with the other. The
key conversion is done by libsodium in both (natively in C++, via a thin binding in
Python) so the keys, conversions, and ciphertexts are identical.

## Install

Two interchangeable implementations are provided: a **Python** package and a
compiled **C++** binary. They use the **same file format**, so you can mix them
freely (encrypt with one, decrypt with the other).

### Python

```bash
# dependency
brew install libsodium
pip install cryptography

# install pkcrypt (creates the `pkcrypt` command)
cd PKCrypt
pip install .
```

### C++ (compiled)

Requires a C++17 compiler and libsodium:

```bash
brew install libsodium
cd PKCrypt
make          # builds ./pkcrypt
make test     # runs the cross-language interop suite
```

## Usage

```bash
# 1) ENCRYPT a file for someone (needs only their PUBLIC key)
pkcrypt encrypt alice_id_ed25519.pub secrets.tgz
# -> secrets.tgz.pkcrypt

# 2) DECRYPT on the recipient's Mac (their PRIVATE key)
pkcrypt decrypt ~/.ssh/id_ed25519 secrets.tgz.pkcrypt
# -> secrets.tgz
```

Both `./pkcrypt` (C++) and `pkcrypt` / `python3 -m pkcrypt_lib` (Python) accept
the same commands. Files encrypted by either are decryptable by either.

### Options

| Flag | Meaning |
|------|---------|
| `encrypt <pub> <file> [out]` | Encrypt `file` for the pub-key holder. Default out: `<file>.pkcrypt` |
| `decrypt <priv> <file> [out]` | Decrypt. Default out: strips `.pkcrypt` (won't overwrite an existing file) |
| `decrypt --passphrase` | Prompt for a passphrase-protected private key |

### Key requirements

- The recipient's key must be an **Ed25519** key (the modern `ssh-keygen -t ed25519`).
  RSA, ECDSA etc. are rejected with a clear message.
- **Python** supports passphrase-protected private keys via `decrypt --passphrase`.
- **C++** supports unencrypted private keys only; decrypt a protected key once first:
  `ssh-keygen -p -f <key> -N ""`.

## Tests

Both implementations come with automated suites:

```bash
# Python implementation (round-trips, wrong-key, tamper, non-determinism)
python3 -m pytest tests/ -v

# C++ implementation (9 cross-language interop cases via make)
make test
```

The C++ interop suite generates throwaway keys and verifies that the Python and
C++ tools decrypt each other's output, plus wrong-key rejection and tamper
detection.

## Security notes

- This is a thin, standard construction (X25519 + HKDF-SHA256 + AES-256-GCM) built on
  the well-audited `cryptography` (Python) and libsodium (C++) libraries. It does not
  invent crypto.
- AES-GCM provides authenticated encryption: a tampered or wrong-key file is rejected,
  never partially decrypted.
- The Ed25519→X25519 conversion matches OpenSSH (libsodium's reference
  `crypto_sign_ed25519_{pk,sk}_to_curve25519`), so keys interoperate with the rest of
  your SSH identity without any new secret to manage.

## Project layout

```
PKCrypt/
├── pkcrypt_lib/            # Python implementation
│   ├── core.py             #   key conversion + hybrid encrypt/decrypt
│   ├── keys.py             #   OpenSSH key file parsing
│   ├── files.py            #   file I/O + path handling
│   └── cli.py              #   command-line interface
├── src/                    # C++ implementation
│   ├── pkcrypt.cpp         #   CLI (encrypt/decrypt)
│   ├── ssh_key.cpp         #   OpenSSH key parsing
│   ├── crypto.cpp          #   X25519 + HKDF-SHA256 + AES-256-GCM
│   └── fileio.cpp          #   file I/O
├── include/pkcrypt/        # C++ headers
│   ├── crypto.h  ssh_key.h  fileio.h  version.h
│   └── base64.hpp          #   base64 decoding
├── tests/                  # pytest suite + C++ interop suite
├── Makefile                # builds ./pkcrypt; `make test`
├── pyproject.toml          # Python packaging (console script: pkcrypt)
├── README.md, CHANGELOG.md
```

