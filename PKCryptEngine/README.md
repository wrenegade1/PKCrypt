# PKCryptEngine

A separate SwiftPM library that re-implements the PKCrypt v2 (Ed25519) and v3 (RSA)
container protocol natively in Swift, byte-for-byte against the Python/C++ reference
implementations. Phase 3's CryptFile app imports this library.

**Audited primitive split (Phase 1):** CryptoKit (X25519 ECDH / HKDF-SHA256 /
AES-256-GCM), Apple `SecKey` (RSA-OAEP SHA-256 + MGF1-SHA-256, empty label), and a
statically-linked libsodium (Ed25519→X25519 public conversion + XChaCha20-Poly1305
IETF **read**). The engine never hand-rolls cryptography.

## Safety guarantees

- **SAFE-01** — wrong keys, tampering, truncation, and appended data are rejected with a
  single generic `EngineError.authFailure` and **no plaintext is ever published** (the
  chunked-AEAD hold-back/lookahead state machine and publish-gated-on-full-auth).
- **SAFE-02** — an existing destination is never overwritten; output is staged in a
  0600-at-creation temp in the destination's own directory and published atomically via
  `renamex_np(RENAME_EXCL)`.

## Build

```bash
cd PKCryptEngine
swift build            # builds the PKCryptEngine library (statically-linked libsodium)
```

## Test — quick vs full

The engine splits its tests so the fast per-commit gate needs no oracle subprocess:

```bash
# Quick (deterministic byte-vectors + negative suite + safe-output; no oracle needed)
swift test --filter FormatVectorTests
swift test --filter NegativeSuiteTests
swift test --filter SafeOutputPublisherTests

# Full suite (includes the live COMP-03 differential interop matrix)
swift test
```

The full suite's `InteropMatrixTests` shells out to the Python and C++ oracles through a
**test-time git submodule / dev checkout** at `PKCryptEngine/oracle-repo/` (D-04). Before
running it, initialize the oracle and build the C++ binary:

```bash
git submodule update --init      # populate oracle-repo/ (or set PKCRYPT_ORACLE_REPO)
cd oracle-repo && make           # build ./pkcrypt for the C++ oracle cells
```

If the C++ binary is absent, C++ interop cells are recorded **UNAVAILABLE**, never failed
and never counted as a pass.

## COMP-03 interop matrix census

The bidirectional differential matrix runs in-engine as the phase's primary verification
(`swift test --filter InteropMatrixTests`). It exercises Swift→Python, Swift→C++,
Python/C++→Swift for Ed25519 × RSA-2048 × RSA-4096 × AES-GCM, plus XChaCha20 read via
oracle-library-produced fixtures. CLI capability gaps (neither CLI exposes a cipher-select
flag) are recorded `UNAVAILABLE(reason)`, never a pass and never silently skipped.
(Full census for this plan is recorded at the bottom of `02-04-SUMMARY.md`.)
