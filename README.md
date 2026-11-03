# PKCrypt

**Author:** Warren Zajac

Encrypt a file so that **only the holder of a specific Ed25519 or RSA SSH private key** can
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

```
                 ░░░░░░░░░▒▒▒
            ░░░░░░░░░░░░░░░░░▒▒▒▒▓
         ░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▓▓█
       ░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓█
      ░░░░░░░░░░░░░░▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓█
     ░░░░░░░░░░░░░███    █▒▒▒▒▒▒▒▒▒▒▒▒▓▓█
    ░░░░░░░░░░░░▒██        ▒▒▒▒▒▒▒▒▒▒▒▓▓██
   ░░░░░░░░░░▒▒▒▒█          ▒▒▒▒▒▒▒▒▒▒▒▓▓██
  ▒░░░░░░░▒▒▒▒▒▒▒▒          ░▒▒▒▒▒▒▒▒▒▒▓▓███
  ▒░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒      ░░▒▒▒▒▒▒▒▒▒▒▓▓▓███
  ▒░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒█    ░░▒▒▒▒▒▒▒▒▒▓▓▓▓▓███
  ▒▒░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒█    ░▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓███
  ▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██    ░▒▒▒▒▒▒▓▓▓▓▓▓▓▓████
   ▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒█      ▒▒▒▓▓▓▓▓▓▓▓▓▓████
    ▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒█      ░▓▓▓▓▓▓▓▓▓▓▓████
     ▓▓▒▒▒▒▒▒▒▒▒▒▒▒█      ░▓▓▓▓▓▓▓▓▓▓████
      █▓▓▓▒▒▒▒▒▒▒▒▒▒▒░░░░░░▓▓▓▓▓▓▓▓█████
       ███▓▓▓▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██████
         █████▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓███████
            ██████████████████████
                 ████████████

             only one key fits
```

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
  - [Encrypting folders](#encrypting-folders)
  - [Recovering from a damaged file (`--salvage`)](#recovering-from-a-damaged-file---salvage)
  - [Output paths](#output-paths)
  - [Key requirements](#key-requirements)
- [How it works: the crypto](#how-it-works-the-crypto)
  - [RSA recipient keys](#rsa-recipient-keys)
  - [Ed25519 → X25519 key conversion](#ed25519--x25519-key-conversion)
  - [Hybrid encryption](#hybrid-encryption)
  - [Key derivation (HKDF)](#key-derivation-hkdf)
- [File format specification](#file-format-specification)
  - [Folder archives](#folder-archives)
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
- **Reuses your existing SSH keys.** Supports Ed25519 and RSA (2048 bits or more),
  including passphrase-protected private keys.
- **Whole folders, compressed.** Encrypt a folder and it is packed into a standard
  ZIP archive (with in-house DEFLATE compression) inside one `.pkcrypt` file, and
  recreated as a folder on decryption. File names are encrypted too.
- **Sender never holds a secret.** Encryption needs only the recipient's public key,
  so you can encrypt from anywhere and never receive private material.
- **Fresh encryption keys per file.** Ed25519 uses ephemeral X25519 key exchange;
  RSA wraps a fresh random session key with RSA-OAEP. Compromise of the
  recipient's private key can expose previously encrypted files.
- **Any size, flat memory.** Both implementations stream: files and folders are
  read, compressed, encrypted and written a chunk at a time, so a multi-gigabyte
  input uses a few MiB of memory.
- **Authenticated encryption.** Tampered files and wrong keys are detected and
  rejected — never partially decrypted.
- **No crypto invented here.** Built entirely on libsodium and `cryptography`, the
  implementations of X25519, HKDF-SHA256, RSA-OAEP, and authenticated encryption
  (C++ RSA uses OpenSSL libcrypto).

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

For a passphrase-protected RSA-4096 key, use the same commands with RSA paths:

```bash
# Recipient: generate a key; enter a non-empty passphrase when prompted
ssh-keygen -t rsa -b 4096 -f ~/.ssh/pkcrypt_rsa

# Sender: encrypt using only the recipient's public key
pkcrypt encrypt recipient_rsa.pub report.pdf

# Recipient: unlock the private key at the terminal and decrypt
pkcrypt decrypt --passphrase ~/.ssh/pkcrypt_rsa report.pdf.pkcrypt
```

Share `pkcrypt_rsa.pub` with the sender as `recipient_rsa.pub`. The Python
CLI accepts the same arguments via `python3 -m pkcrypt_lib`. Install `bcrypt`
alongside `cryptography` to load passphrase-protected OpenSSH keys in Python.

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
pip install cryptography bcrypt

# Install the package (creates the `pkcrypt` command)
cd PKCrypt
pip install .

# Or run without installing
python3 -m pkcrypt_lib --help
```

### C++ implementation (compiled)

Requires a **C++17** compiler and **libsodium**. RSA additionally requires
**OpenSSL 3 libcrypto**. The Makefile detects OpenSSL through `pkg-config`;
CMake uses `find_package(OpenSSL)`. Without OpenSSL, Ed25519 still works and
RSA operations report that the build lacks OpenSSL.

```bash
brew install libsodium openssl@3 pkg-config

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

# A whole FOLDER: compressed and encrypted into one file...
pkcrypt encrypt alice_id_ed25519.pub photos/
# -> photos.pkcrypt
# ...and recreated as a folder when decrypted
pkcrypt decrypt ~/.ssh/id_ed25519 photos.pkcrypt
# -> photos/
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
# ssh-ed25519 XXXXYYYYZZZZ... bob@macbook
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
| `pkcrypt encrypt <pub> <file\|folder> [out]` | Encrypt a file or a whole folder for the holder of the public key `<pub>`. |
| `pkcrypt decrypt <priv> <file> [out]` | Decrypt `<file>` (a `.pkcrypt` container) with private key `<priv>`; a folder is recreated as a folder. |
| `pkcrypt version` | Print the version. |
| `pkcrypt --help` / `-h` | Show usage. |

Encrypt-only options:

| Flag | Meaning |
|------|---------|
| `encrypt <pub> <file> [out]` | Third positional arg overrides the output path. |
| `--skip-large` | When encrypting a folder, leave out files too large for its ZIP archive instead of failing; each is named in a warning (see [Encrypting folders](#encrypting-folders)). Flags may go anywhere on the command line. |

Decrypt-only options:

| Flag | Meaning |
|------|---------|
| `decrypt <priv> <file> [out]` | Third positional arg overrides the output path. |
| `--passphrase` | Prompt for a passphrase to unlock a passphrase-protected private key. |
| `--salvage` | Recover what still verifies from a damaged file instead of refusing it (see below). |

Exit codes (the same in both implementations):

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Failed: wrong key, damaged or tampered file, unsafe archive, I/O error. Nothing was written. |
| `2` | Usage error, or the key file couldn't be read. |
| `3` | `--salvage` produced a partial result. |

### Encrypting folders

Give `encrypt` a folder instead of a file and its contents are packed into a ZIP
archive, compressed, and encrypted as a single `.pkcrypt`. Decrypting it recreates
the folder. Both implementations do this and read each other's output.

- **What's included:** every regular file and folder (including empty ones), with
  paths relative to the folder you named, in sorted order. **Symbolic links and
  special files are skipped** with a warning; links are never followed.
- **Size limits (no ZIP64 yet):** the archive uses classic ZIP, which holds up to
  65,534 files and folders, and files up to **4 GiB** each (C++) or **2 GiB** each
  (Python, whose `zipfile` cannot go higher without ZIP64). A folder over a
  limit fails immediately, before anything is compressed. Pass `--skip-large` to
  leave oversized files out instead: each is named in a `warning: skipped …` line
  and the summary shows how many were left out; their folders are still kept.
  Encrypt a large file **on its own**: single files have no size limit.

  ```bash
  pkcrypt encrypt --skip-large ~/.ssh/id_ed25519.pub T10Restore     # folder minus the big .bak
  pkcrypt encrypt ~/.ssh/id_ed25519.pub T10Restore/backups/db.bak ~/db.bak.pkcrypt
  ```
- **The output can live inside the folder** (e.g. `pkcrypt encrypt key.pub . out.pkcrypt`):
  the container being written is recognised by device and inode and never packed into itself.
- **What's restored:** contents, folder structure, and modification times. Files are
  created `0600` (`0700` if they were owner-executable), folders `0700`: decrypted
  data is private to you, like any PKCrypt output.
- **All or nothing:** the archive is fully decrypted and validated, then extracted
  into a hidden temporary folder beside the destination that is renamed into place
  only if every file succeeded. A failure leaves nothing behind, and an existing
  file or folder (even an empty one) is never overwritten.
- **Names are private too:** the archive, including its list of file names and
  sizes, is inside the encryption. An observer sees only the total size.
- A `.zip` you encrypt as a *file* comes back as that `.zip` file; only folders are
  extracted (the container's authenticated header records which it is).

The compression is an in-house DEFLATE (RFC 1951) and ZIP (PKWARE APPNOTE)
implementation in C++; Python uses its standard library's `zipfile`/`zlib`. The
decrypted archive is a standard ZIP, so you can also verify one with any ZIP tool.

Everything streams, so memory use stays small whatever the folder size (within the
ZIP limits above). When encrypting, files are compressed straight into the encryptor, so no plaintext
archive is written to disk. When decrypting, a ZIP's index sits at its end, so
the decrypted archive goes to a private (`0600`) temporary file beside the
destination; it is extracted from there and always deleted afterwards.

### Recovering from a damaged file (`--salvage`)

By default decryption is all-or-nothing: any damage, even one flipped bit, and
nothing is written. If you would rather keep what survived:

```bash
pkcrypt decrypt --salvage ~/.ssh/id_ed25519 photos.pkcrypt
# Salvaged photos.pkcrypt -> photos.partial/
#   recovered: 3 files, 1 folders, 900031 bytes
# warning: the encrypted file is damaged: decryption failed: ...
# lost: everything after that point (data/photo.jpg: corrupt compressed data: ...)
# warning: this is a PARTIAL result
```

- **Only authenticated data is ever written.** Salvage never uses bytes that
  failed decryption; it recovers what the *verified* part can still yield.
- **One bad file inside an intact folder:** every other file is recovered; the
  bad one is listed as lost.
- **The encrypted file itself is damaged or cut short:** the chunks before the
  damage verify, and every file stored entirely within them is recovered. Files
  after the damage are lost (a ZIP's index is at its end, so even their names
  are). A single file comes back as its verified first part.
- **The result is marked:** it goes to `<name>.partial` (unless you give an
  output path), the exit status is `3`, and the losses are listed on stderr. If
  nothing at all can be recovered, it fails as usual (status `1`, nothing written).
- **Safety rules still apply** to every file: unsafe paths, symlinks and
  overlapping entries are dropped, never written.
- On an undamaged file, `--salvage` is just a normal decrypt (status `0`).

### Output paths

- **Encrypt** defaults to `<input>.pkcrypt` (`photos/` → `photos.pkcrypt`). Encrypting
  `.` or `..` requires an explicit output path.
- **Decrypt** defaults to:
  - stripping a trailing `.pkcrypt`, or
  - appending `.decrypted` if the original name already exists.
- PKCrypt **never overwrites** an existing file or folder. If the default output path
  is taken, it appends a numeric suffix (`file.1`, `file.2`, …); an explicit output
  path that already exists is refused.

### Key requirements

- The recipient must use an OpenSSH **Ed25519** or **RSA** key. RSA keys must
  be at least **2048 bits**; RSA-4096 is supported. ECDSA and Ed448 are unsupported.
- C++ RSA operations require **OpenSSL 3**; the bundled AES fallback supports
  Ed25519 key unlocking but does not provide RSA encryption/decryption.
- **Python** supports passphrase-protected private keys via `decrypt --passphrase`.
- **C++** also supports passphrase-protected private keys via `decrypt --passphrase`
  (it unlocks the key with the passphrase, using an in-house `bcrypt_pbkdf` and
  AES-CTR; OpenSSL is used for AES when available, with a bundled fallback
  otherwise). Either way, do not remove your key's passphrase — that weakens your
  SSH key and is unnecessary.

---

## How it works: the crypto

PKCrypt uses **hybrid public-key encryption** — a standard, battle-tested scheme
(a blend of the constructions used by age, minisign, and OpenSSH itself).

### RSA recipient keys

RSA uses a fresh random 32-byte session key per container. The recipient's
public key wraps it using **RSA-OAEP with SHA-256 and MGF1-SHA-256** (empty
label). The private key unwraps it during decryption. The session key encrypts
the payload with AES-256-GCM or XChaCha20-Poly1305, using the same chunk and
final-chunk authentication rules as Ed25519. RSA does not use X25519 or HKDF.

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

where `info = "PKCrypt/v2/x25519-ecdh+aead" || eph_pk || recipient_x_pk`.
Binding the two public keys into `info` guarantees a distinct key for every
(sender, recipient, file) combination.

---

## File format specification

The `.pkcrypt` file is a single self-contained container. The recipient needs nothing
but their private key (and its passphrase, if protected) to open it.

Ed25519 uses format version 2 (`PKCRYPT\x02`), detailed below. RSA uses
format version 3 (`PKCRYPT\x03`) with this header, in order:

| RSA header field | Size | Description |
|------------------|------|-------------|
| `magic` | 8 B | `PKCRYPT` followed by `0x03`. |
| `cipher`, `payload` | 1 B each | Same values as version 2. |
| `algorithm` | 1 B | `0x00` = RSA-OAEP with SHA-256 and MGF1-SHA-256. |
| `wrapped session key` | RSA modulus size in bytes | 256 B for RSA-2048; 512 B for RSA-4096. |
| `base nonce` | 12 or 24 B | Selected by the payload cipher. |
| `chunk_len` | 4 B | Big-endian maximum plaintext chunk size. |

The wrapped-key length is inferred from the recipient's RSA key. The complete
RSA header is authenticated as AAD for each chunk, followed by the same
final-chunk flag used in version 2.

### Ed25519 container (version 2)

```
 Format version 2
 ┌─────────────┬────────┬─────────┬────────────────────┬──────────────────────┬──────────────────────┐
 │ magic (8 B) │ cipher │ payload │ ephemeral pub (32) │ base nonce (12|24 B) │ chunk_len (4 B, BE)  │
 │"PKCRYPT\x02"│  1 B   │   1 B   │ sender's X25519 pk │ AES-GCM / XChaCha20  │ max plaintext/chunk  │
 └─────────────┴────────┴─────────┴────────────────────┴──────────────────────┴──────────────────────┘
    header (part of every chunk's AAD)                         then: one or more AEAD chunks
```

| Field | Size | Description |
|-------|------|-------------|
| `magic` | 8 B | ASCII `PKCRYPT` followed by `0x02` (format version). |
| `cipher` | 1 B | `0x00` = AES-256-GCM, `0x01` = XChaCha20-Poly1305. |
| `payload` | 1 B | What the plaintext is: `0x00` = one file's bytes, `0x01` = a ZIP archive of a folder. |
| `ephemeral public key` | 32 B | The sender's one-time X25519 public key. |
| `base nonce` | 12–24 B | Random AEAD base nonce (12 for AES-GCM, 24 for XChaCha20). |
| `chunk_len` | 4 B | Max plaintext bytes per chunk, big-endian. PKCrypt writes 1 MiB; readers reject values above 16 MiB (a decryptor buffers one chunk, so the limit stops a crafted header from demanding a huge allocation). |
| payload | n B | One or more chunks, each = plaintext bytes + a 16-byte tag. Every chunk but the last holds exactly `chunk_len` bytes; the last holds 0..`chunk_len`. |

The plaintext is split into `chunk_len`-byte chunks. Each chunk is encrypted with the
**same** key but a **different** nonce: chunk *i*'s nonce is the base nonce with its final
4 bytes set to the big-endian chunk index. Each chunk's **associated data** is the
fixed header followed by one flag byte: `0x01` for the last chunk, `0x00` for every
other. So altering the magic, cipher byte, payload type, ephemeral key, base nonce, or chunk size
fails the authentication tag, and so does **truncating** the file at a chunk boundary
(the new last chunk was not sealed as final) or appending data after the real last
chunk. An empty file is encoded as a single empty final chunk. `0x01` (XChaCha20-Poly1305) is the fallback
cipher for CPUs without AES hardware acceleration.

The format is identical between the Python and C++ implementations, which is what makes
them fully interoperable.

### Folder archives

A `payload` of `0x01` means the plaintext is a standard ZIP archive (classic format,
not ZIP64) of the folder's contents:

- Member names are UTF-8 relative paths with `/` separators; folders end in `/`.
- Files use method 8 (DEFLATE), or 0 (stored) when compression would not shrink them.
- Unix permission bits are recorded in the external attributes ("made by" Unix).
- Limits of the classic format: at most 65,535 entries and 4 GiB per file and per
  archive. Larger folders are refused with a clear error (ZIP64 is not yet supported).

Archives are treated as **untrusted input** on extraction, because anyone with your
public key can send you one. Both implementations reject: absolute paths and `.`, `..`
or empty path components (path traversal); symbolic links, devices and other special
files; duplicate names; encrypted or ZIP64 entries; compression methods other than 0/8;
local headers that disagree with the central directory; and **entries whose data
overlap** (the trick behind the most efficient zip bombs). Each entry must decompress
to exactly its declared size and CRC-32, decompression stops at the declared size, and
the total must fit in the free disk space before anything is written.

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
- **Compression reveals a little about content.** A folder's archive is compressed
  before encryption, so the `.pkcrypt` size reflects how compressible the contents
  are (as with any compress-then-encrypt tool). This matters only if an attacker can
  get their own data compressed alongside your secrets and observe sizes; it does
  not apply to files encrypted on their own, which are not compressed.
- **Sender identity is not verified.** Anyone who knows your *public* key can
  encrypt a file *to* you, and nothing in the format proves who sent it — PKCrypt
  authenticates the ciphertext but not the sender. This is a deliberate property
  of the public-key model. Signing the plaintext with the sender's key (as
  sketched in the Roadmap as "affine signing") would be optional future work.

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

This includes folders: an archive packed by either implementation is extracted
identically by the other.

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

# Build, then run every suite (Python unit tests + C++ interop)
make test
```

The repo is intentionally simple: no submodules, no generated code, and no network
needed at build time — every source file (C++ and Python) is written in-house. The
only external dependency is the libsodium and `cryptography` libraries you install.

### Running the test suites

```bash
# Everything: builds ./pkcrypt and the sanitizer-instrumented test harness first
make test

# Or individually (after `make test` has built the binaries):
python3 -m pytest tests/test_roundtrip.py -v   # container format, truncation, CLI
python3 -m pytest tests/test_deflate.py -v     # C++ DEFLATE vs zlib, fuzzing
python3 -m pytest tests/test_archive.py -v     # folders, both CLIs, hostile archives
python3 tests/test_cpp_interop.py              # cross-language file interop

# Opt-in, slower: 1 GiB of repeating patterns through every C++/Python
# combination, as a file and as a folder, with memory ceilings and a
# corrupted-copy check (needs ~3 GB free disk; PKCRYPT_LARGE_MIB changes the size)
make test-large

# Just the test input, e.g. to try things by hand
python3 tests/make_test_data.py /tmp/patterns.bin 1024
```

The in-house C++ DEFLATE and ZIP code is checked against independent
implementations rather than only against itself: our compressed output must
decompress with zlib, zlib's output at every level and strategy must decompress
with ours, and on thousands of mutated streams ours must succeed exactly when zlib
does. Archives are also checked with Python's `zipfile`. These tests drive
`tests/deflate_harness`, built with AddressSanitizer and UBSan, so a memory error
on malformed input fails the suite even if the answer looks right.

All suites generate throwaway keys in a temp directory and never touch your real
`~/.ssh` keys.

---

## Troubleshooting

### `error: file too large for a ZIP archive (limit 4 GiB; ZIP64 is not supported)`
A file in the folder is over the archive's per-file limit (4 GiB in C++, 2 GiB in
Python). Re-run with `--skip-large` to encrypt the folder without it, and encrypt
that file on its own (single files have no size limit).

### `error: [Errno 2] No such file or directory: 'ssh-ed25519'`
The key argument is the **path to the key file** (`~/.ssh/id_ed25519.pub`), not the
key's text. Pasting the key splits it into several arguments.

### `error: decryption failed: file is not for this private key, or it was tampered with or truncated`
You are using the **wrong private key**, or the `.pkcrypt` file was **modified** or
**cut short** since creation (e.g. an interrupted transfer), or it was corrupted in transit.
No output file is written in this case. Verify you have the correct
key and an intact file.

### `error: not a PKCrypt file (bad header)` / `encrypted payload too short`
The input is not a PKCrypt container, or it is truncated. Confirm the file was
created by `pkcrypt encrypt` and transferred completely (binary-safe).

### `error: unsafe path in archive ...` / `symbolic links are not supported` / `overlapping entries`
The folder archive inside the file was rejected as unsafe to extract. PKCrypt never
produces such archives, so the file was made by another tool or crafted deliberately.
Nothing was written.

### `error: refusing to overwrite existing path`
The destination folder already exists (even if empty). Remove or rename it, or pass a
different output path as the third argument.

### RSA key rejected or build lacks OpenSSL
RSA requires the updated Python package or a C++ binary built with OpenSSL 3.
If an older binary reports that only Ed25519 is accepted, rebuild the current
sources. For C++, install `openssl@3` and `pkg-config` before rebuilding.
RSA keys smaller than 2048 bits are rejected.

### I have a passphrase-protected private key
Both implementations accept one via `decrypt --passphrase`, which prompts for the
passphrase at a terminal (it is never echoed or stored):

```bash
pkcrypt decrypt --passphrase ~/.ssh/id_ed25519 secret.pkcrypt
python3 -m pkcrypt_lib decrypt --passphrase ~/.ssh/id_ed25519 secret.pkcrypt
```

The C++ binary unlocks the key with an in-house `bcrypt_pbkdf` and AES-CTR
(using OpenSSL's AES when available, and a bundled fallback otherwise), so it
supports Ed25519 on systems without OpenSSL. RSA operations still require
OpenSSL 3. Use `~/.ssh/id_rsa` in the commands above for an RSA key. Do **not**
empty your key's passphrase (for
example with `ssh-keygen -p -f ~/.ssh/id_ed25519 -N ""` just to use a tool) —
that weakens your SSH key.

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
│   ├── archive.py          #   folder <-> ZIP (stdlib zipfile/zlib), safe extraction
│   ├── cli.py              #   command-line interface
│   ├── __init__.py
│   └── __main__.py         #   enables `python3 -m pkcrypt_lib`
├── src/                    # C++ implementation
│   ├── pkcrypt.cpp         #   CLI (encrypt / decrypt)
│   ├── ssh_key.cpp         #   OpenSSH key parsing
│   ├── crypto.cpp          #   X25519 + HKDF-SHA256 + AES-256-GCM
│   ├── fileio.cpp          #   file I/O
│   ├── base64.cpp          #   own base64 decoder/encoder (RFC 4648)
│   ├── crc32.cpp           #   own CRC-32
│   ├── deflate.cpp         #   own DEFLATE compressor (RFC 1951)
│   ├── inflate.cpp         #   own DEFLATE decompressor (RFC 1951)
│   ├── deflate_tables.h    #   RFC 1951 constants shared by the two
│   ├── zip.cpp             #   own ZIP writer/reader (PKWARE APPNOTE)
│   └── archive.cpp         #   folder <-> ZIP, safe atomic extraction
├── include/pkcrypt/        # C++ headers
│   ├── crypto.h  ssh_key.h  fileio.h  version.h
│   ├── base64.h            #   own base64 API
│   └── deflate.h  zip.h  archive.h
├── tests/                  # test suites
│   ├── test_roundtrip.py   #   container format + CLI (pytest)
│   ├── test_deflate.py     #   C++ DEFLATE/CRC-32 vs zlib, differential fuzzing
│   ├── test_archive.py     #   folders across both CLIs, hostile archives
│   ├── deflate_harness.cpp #   test-only binary exposing the C++ codecs (sanitized)
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
- **ZIP64** — lift the 65,535-entry / 4 GiB limits on folder archives.

Contributions and ideas are welcome — open an issue or a pull request.

---

## License & attribution

**Author and maintainer:** Warren Zajac

PKCrypt is released under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE)
for the full text and [`NOTICE`](NOTICE) for attribution. Every source file carries an
`SPDX-License-Identifier: Apache-2.0` header.

In short, you may use, modify, and redistribute PKCrypt, including in commercial and
closed-source products, provided you keep the license and `NOTICE`, and mark any files
you change. The license includes an explicit patent grant from contributors and does
not grant rights to the names "PKCrypt" or "CryptFile".

The base64 encoder/decoder in `src/base64.cpp` is **our own** implementation,
written in-house and verified byte-for-byte against the standard reference (the
Python `base64` module) over real OpenSSH keys, all input-length classes, padding
variants, and embedded newline wrapping.

The implementation relies on (but does not bundle) these third-party libraries:

| Component | License | Purpose |
|-----------|---------|---------|
| [libsodium](https://doc.libsodium.org/) | ISC | Ed25519→X25519 conversion, X25519, HKDF, AES-GCM primitives. |
| [cryptography](https://cryptography.io/) | Apache-2.0 / BSD | OpenSSH key parsing and Python crypto primitives. |
| [bcrypt](https://github.com/pyca/bcrypt) | Apache-2.0 | Unlocking passphrase-protected OpenSSH keys (Python). |
| [OpenSSL 3](https://www.openssl.org/) (libcrypto) | Apache-2.0 | RSA-OAEP in the C++ binary (optional; Ed25519 works without it). |

PKCrypt is an independent project and is not affiliated with or endorsed by OpenSSH,
libsodium, or the Python `cryptography` project.
