# PKCrypt CryptFile — Phase 1 Feasibility Verdict

**Document:** FEASIBILITY-VERDICT.md (tracked durable artifact — `docs/feasibility/`)
**Phase:** 01-native-cryptography-feasibility
**Plan:** 01-05
**Date drafted:** 2026-11-01
**Status:** **APPROVED — GO (2026-11-01, owner-approval checkpoint satisfied).** The blocking SUCCESS-1
owner-approval checkpoint at the end of Plan 01-05 was approved by the owner: the audited-primitive
dependency approach and the sandboxed + security-scoped-bookmark distribution approach are both approved.
The `<verdict>` line below and the `<decision_gate>` section are finalized and committed.

---

<verdict>

VERDICT: GO

**Feasibility passes.** The evidence collected across Plans 01-01 through 01-04 demonstrates that a Swift
implementation of the PKCrypt protocol — using the approved audited-primitive dependency split
(CryptoKit + `SecKey` + statically-linked libsodium) and the sandboxed, security-scoped-bookmark
distribution posture — is viable against the Python and C++ PKCrypt oracles and the Mac App Store
sandbox, at the macOS 13+ deployment target.

**Rationale:** Every runnable interoperability cell in the phase's differential matrix passes
(**26 PASS / 0 FAIL**, with the 4 non-passing cells being explicit *UNAVAILABLE* capability gaps in the
reference CLI oracles, never failures of the Swift candidate). The two historically-uncertain primitives
are the ones this phase was chartered to resolve: (a) Apple `SecKey .rsaEncryptionOAEPSHA256` is proven
byte-identical to PKCrypt's RSA-OAEP(SHA-256, MGF1-SHA-256, empty label) at both 2048- and 4096-bit
against both independent oracles (closing D-04 / Open Question 1); and (b) XChaCha20-Poly1305 **read**
(cipher `0x01`, 24-byte nonce) decrypts byte-identically via statically-linked libsodium for both the v2
Ed25519 and v3 RSA containers (read-only — XChaCha write stays deferred per D-02). The sandboxed signed
probe (D-05 / SUCCESS-3) completed a full user-granted access-and-relaunch encrypt→decrypt through
app-scoped security-scoped bookmarks with `codesign --verify --deep --strict` passing and no
`disable-library-validation` needed (static-linked libsodium). No unresolved FAIL gate or blocking
limitation supports a NO-GO. The only open items are non-blocking, release-time risks (macOS-13 runtime
equivalence not yet confirmed on an actual 13 VM; App Store notarization deferred to release).

**This GO is contingent on** the owner's explicit approval of the audited-primitive dependency approach
(including the libsodium ISC license and static-link packaging) and the sandboxed distribution approach.
See `<decision_gate>`. A NO-GO would stop subsequent implementation for reassessment per the phase
contract — never falling back to hand-rolled primitives or dropping cipher support.

</verdict>

---

<approved_decisions>

## Approved Decisions (subject to owner confirmation in `<decision_gate>`)

The two one-way/costly gated decisions this phase validated are recorded here with their locked decision
IDs. These are the foundation on which Phase 2 plans.

### 1. Audited-primitive dependency approach — [D-01 / D-02 / D-04]

The Swift engine anchors on an **audited-providers-only** dependency split with a minimal native
footprint:

| Provider | Primitives | Decision | Evidence |
|----------|-----------|----------|----------|
| **Apple CryptoKit** (built-in, macOS 13+) | X25519 ECDH, HKDF-SHA256, AES-256-GCM | D-01 (locked) | Plan 01-01/01-04 — AES-256-GCM chunked AEAD byte-identical to `core.py` |
| **Apple Security framework `SecKey`** (built-in, macOS 13+) | RSA-OAEP wrap/unwrap (`.rsaEncryptionOAEPSHA256`) | D-04 (locked) | Plan 01-02 — byte-identical at 2048 AND 4096 vs Python + C++ oracles |
| **libsodium** (bundled, statically-linked) | Ed25519→X25519 public-key conversion; XChaCha20-Poly1305 **read** | D-02 (locked) | Plans 01-01/01-03 — `crypto_sign_ed25519_pk_to_curve25519` + `crypto_aead_xchacha20poly1305_ietf_decrypt` |

- **Licensing:** libsodium is **ISC-licensed** — manually verified against the official repository
  `LICENSE` (see RESEARCH "Package Legitimacy Audit": both libsodium and the optional swift-sodium
  wrapper are long-established ISC projects, verified manually because they are not in the
  `npm|pypi|crates` registries the legitimacy seam covers). No registry packages are needed.
- **macOS 13+ deployment target:** CryptoKit and `SecKey` are available on macOS 13+; the spike and probe
  are built with `MACOSX_DEPLOYMENT_TARGET=13.0` and the availability-annotated APIs used are all
  macOS-13-compatible.
- **Static-link packaging:** libsodium is linked as a static archive directly into the signed main binary
  (no runtime dylib), confirmed by `otool -L` (no sodium dylib) and `nm` (`T _sodium_init` defined in the
  binary). This eliminates separate-library code signing and the `disable-library-validation` entitlement
  entirely (Plan 01-04).
- **No hand-rolled crypto:** the only hand-written code is *format* work — OpenSSH key parsing (a custom
  non-DER format) and the minimal ASN.1 PKCS#1 DER encoder to feed `SecKey` — neither of which is
  cryptography (RESEARCH "Don't Hand-Roll").

### 2. Sandboxed + app-scoped security-scoped bookmarks — [D-05]

The app targets the **Mac App Store sandbox**, using **app-scoped security-scoped bookmarks** for
user-granted access to input files, SSH keys, and output destinations.

- **Entitlements (exactly three):** `com.apple.security.app-sandbox`,
  `com.apple.security.files.user-selected.read-write`,
  `com.apple.security.files.bookmarks.app-scope`. **No** `disable-library-validation` is needed or applied
  (static-linked libsodium — see above).
- **Proven through completion:** a signed sandboxed probe completed a full user-granted
  `NSOpenPanel`-based encrypt→decrypt with a persisted app-scoped bookmark that resolved and read the file
  successfully after relaunch (no "Operation not permitted after relaunch" — Pitfall 4 disproven for this
  flow, T-01-16 mitigated). See `<sandbox_results>`.
- **Signing:** `codesign --verify --deep --strict` passes with the three entitlements embedded. (Apple
  Distribution identity is present for release-side signing; notarization is a release-time item.)

</approved_decisions>

---

<spike_results>

## Spike Results — Differential Interop Matrix (D-08)

The full spike matrix (below, from `SPIKE_ROOT/matrix-results.txt`) covers Swift→CLI and CLI→Swift for
Ed25519 and RSA, exercising both read ciphers (AES-GCM emit; AES-GCM and XChaCha20 read), files only.
Result census: **26 PASS, 0 FAIL, 4 UNAVAILABLE** (the 4 UNAVAILABLE are CLI capability gaps, recorded
explicitly and never counted as passes — see "CLI capability limitation" note below).

**Ed25519 AES-256-GCM (v2) — 16 PASS** (Plans 01-01): Swift→Python, Swift→C++, Python→Swift, C++→Swift
at empty / exact-chunk (1 MiB) / multi-chunk (1 MiB+1) sizes — all pass and decrypt to byte-identical
plaintext.

**RSA-OAEP (v3) — 8 PASS** (Plan 01-02): 2048-bit and 4096-bit × Swift→Python, Swift→C++, Python→Swift,
C++→Swift — all pass, confirming `SecKey` OAEP equivalence (SUCCESS-2).

**XChaCha20-Poly1305 read (cipher 0x01) — 2 PASS** (Plan 01-03): `xchacha-read-ed` and `xchacha-read-rsa`
— Swift reads Python-library-produced XChaCha containers byte-identically for both v2 Ed25519 and v3 RSA.

**CLI XChaCha capability limitation (COMP-03):** neither the Python nor the C++ CLI exposes a cipher-selection
flag, so the XChaCha oracle is the in-repo Python library API, and the four `xchacha-sw2cli-*` /
`xchacha-py2sw-cli` / `xchacha-cpp2sw-cli` cells are recorded `UNAVAILABLE:<reason>` (not passes). The C++
*library* supports XChaCha but the CLI does not expose a selector. This is a reference-CLI capability gap,
not a Swift limitation, and does **not** block the GO.

**Non-pass cells (verbatim from `matrix-results.txt`):** all 4 are `UNAVAILABLE: <reason>` lines for the
CLI XChaCha cipher-flag gap listed above; there are zero `FAIL` cells in the matrix.

**Negative/robustness evidence:** wrong-key, truncated, tampered data, and malformed/undersize keys surface
the single generic `DECRYPT_FAILED` with no plaintext published (SAFE-01) — consistently across Ed25519
(Plan 01-01), RSA (Plan 01-02), and XChaCha read (Plan 01-03).

</spike_results>

---

<sandbox_results>

## Sandbox Results — Signed Sandboxed Probe (D-05 / SUCCESS-3)

From `SANDBOX_ROOT/README-SANDBOX-FINDINGS.txt` (Plan 01-04):

| Gate | Result |
|------|--------|
| Static libsodium linked into signed single binary | ✅ PASS (`otool -L` no dylib; `nm` `T _sodium_init`) |
| No `disable-library-validation` needed | ✅ PASS (absent from plist + effective entitlements) |
| Exactly three sandbox entitlements applied | ✅ PASS |
| `codesign --verify --deep --strict` | ✅ PASS (valid on disk / satisfies DR) |
| Sandbox boundary engages on signed binary | ✅ PASS (direct `/tmp` access denied — sandbox is real) |
| Unsandboxed CryptoKit file round-trip | ✅ PASS (byte-identical) |
| Full user-granted bookmark encrypt→decrypt + relaunch | ✅ **PASS** (open-panel grant; byte-identical; bookmark survives relaunch) |

The full SUCCESS-3 pass was completed [2026-11-01]: a user granted access to a scratch fixture file and a
destination through macOS `NSOpenPanel`, the signed sandboxed app ran a CryptoKit AES-256-GCM
encrypt→decrypt to completion (`ROUNDTRIP_OK bytes=4096`, byte-identical output), persisted an app-scoped
security-scoped bookmark (796 B), and a relaunch resolving **only** the persisted bookmark read the file
successfully (`RELAUNCH_OK bytes=4096`) — confirming user-granted access survives start/stop and relaunch.

**Unresolved items (non-blocking):** notarization is not performed in feasibility (a release-time item only,
and `spctl -a` rejection of an un-notarized local CLI is expected). All SUCCESS-3 gates themselves green.

</sandbox_results>

---

<review_evidence>

## Reviewer-Inspectable Evidence (SUCCESS-4)

A reviewer can inspect the phase artifacts to confirm each of the four requirements:

1. **Protocol logic is Swift.** The protocol container codec (header/AAD/rolling chunk AEAD, per-chunk
   nonce derivation, wrapped-session-key handling), OpenSSH key parsing, and all orchestration are
   implemented in Swift (`PKCryptSwiftSpike/Sources/Spike/{ContainerCodec,KeyMaterial,Primitives,main}.swift`,
   throwaway scratch by D-07). The C++/Python CLIs are invoked only from the differential test harness.
2. **Primitives come from audited providers only (no hand-rolled crypto).** All cryptographic primitives
   resolve to CryptoKit (`X25519 ECDH, HKDF-SHA256, AES-256-GCM`), Apple `SecKey`
   (`.rsaEncryptionOAEPSHA256` RSA-OAEP), or statically-linked libsodium (`crypto_sign_ed25519_pk_to_curve25519`,
   `crypto_aead_xchacha20poly1305_ietf_decrypt`). The only hand-written code is format parsing (OpenSSH keys)
   and the minimal PKCS#1 DER encoder to import into `SecKey` — parsing, not cryptography (RESEARCH
   "Don't Hand-Roll"; D-02).
3. **Targets macOS 13+.** All plans build with `MACOSX_DEPLOYMENT_TARGET=13.0`; CryptoKit and `SecKey`
   APIs used are available on macOS 13+. (Runtime equivalence on an actual macOS 13 host remains an
   unresolved, non-blocking risk — see `<remaining_risks>`.)
4. **No CLI runtime dependency.** The existing Python/C++ CLI tools are **test oracles only** (D-03),
   invoked solely from the spike's differential harness. The Swift container codec produces and consumes
   the PKCRYPT file format entirely in-process; the CLIs are never a runtime dependency of the app.

**Inspectable evidence files** (all throwaway scratch per D-07, outside the repo tree):
`PKCryptSwiftSpike/Sources/Spike/*.swift`, `PKCryptSwiftSpike/matrix-results.txt`, and
`PKCryptSandboxProbe/{Package.swift, entitlements.plist, Sources/SandboxProbe/main.swift,
README-SANDBOX-FINDINGS.txt}`.

</review_evidence>

---

<remaining_risks>

## Remaining Risks & Open Items

Carried forward from RESEARCH (Assumptions/Open Questions) that are **not fully resolved** by this phase.
None of these lift a GO, but they must be tracked into Phase 2/Phase 3.

| # | Risk / Open Item | Source | Impact / Mitigation |
|---|------------------|--------|---------------------|
| A3 | **macOS-13 runtime equivalence unconfirmed on an actual macOS 13 host.** Host is macOS 26; the macOS-13 minimum is covered by deployment target + availability annotations, but no physical/VM macOS 13 run of SecKey OAEP or the sandbox bookmarks was performed. | RESEARCH A3 / Open Question 2 | MEDIUM. Could surface subtle `SecKey` DES import or bookmark differences on 13. Mitigate in Phase 2/3 with a macOS 13 VM/CI confirmation of the Phase 2 engine + Phase 3 app before release. |
| — | **App Store notarization & release signing not exercised.** Probe used an Apple Development identity; notarization (and the Apple Distribution path) are release-time items. | Plan 01-04 notes | LOW for feasibility; a Phase 3 release blocker to prove before ship. |
| — | **Swift 6 strict concurrency** not stress-tested in the small throwaway spike. | RESEARCH A5 | Only affects the durable Phase 2 engine, not feasibility. Must be addressed in Phase 2 planning. |
| — | **XChaCha20 writing** remains deferred (read-only posture). CryptFile writes AES-GCM, reads AES-GCM and XChaCha20. | D-02 / CONTEXT Deferred | By design; no impact on the compat posture for the app's own writes. |

</remaining_risks>

---

<throwaway_notice>

## Throwaway Notice (D-07)

The interop spike (`PKCryptSwiftSpike/`) and the sandbox probe (`PKCryptSandboxProbe/`) executed during
this phase are **throwaway scratch artifacts** located outside the repo's shipped tree. Their purpose was
to produce the evidence recorded above. They are **NOT** the seed of the Phase 2 engine, and **NOT** part
of the CryptFile product. Phase 2 will plan its engine **from this written evidence**, not from spike
code. The single durable artifact this phase produces is this `FEASIBILITY-VERDICT.md`.

</throwaway_notice>

---

<decision_gate>

## Decision Gate — Blocking Owner Approval (SUCCESS-1)

This document's **`VERDICT: GO` is conditional** and becomes final only upon the owner's explicit approval
via the blocking (non-auto-approvable) checkpoint at the end of Plan 01-05. The question for the owner:

> **Approve the audited-primitive dependency approach** — CryptoKit (X25519/HKDF/AES-256-GCM) +
> `SecKey` (RSA-OAEP) + statically-linked libsodium (Ed→X conversion + XChaCha20 read), including the
> **libsodium ISC license** (manually verified per RESEARCH Package Legitimacy / A6), macOS 13+ deployment
> target, and static-link packaging — **and the sandboxed + security-scoped-bookmark distribution
> approach (D-05)** — given the recorded spike and sandbox results above?

**Decision: APPROVED — GO** on both items.

**Approved [2026-11-01] by the owner** (blocking SUCCESS-1 owner-approval checkpoint, Plan 01-05):

1. **Audited-primitive dependency approach** — CryptoKit (X25519/HKDF/AES-256-GCM) + `SecKey`
   (RSA-OAEP) + statically-linked libsodium (Ed→X conversion + XChaCha20 read), including the **libsodium
   ISC license** (manually verified per RESEARCH Package Legitimacy / A6), macOS 13+ deployment target, and
   static-link packaging (no `disable-library-validation`).
2. **Sandboxed + security-scoped-bookmark distribution approach (D-05).**

**Consequence:** the `<verdict>` above (`VERDICT: GO`) is finalized as approved, the audited/sandbox
decisions above are recorded as **approved**, and subsequent Phase 2 planning proceeds from this written
evidence. Remaining non-blocking risks (A3 macOS-13 runtime equivalence, notarization) are tracked into
Phase 2/3.

</decision_gate>

---

*Phase: 01-native-cryptography-feasibility · Plan: 01-05 · Date: 2026-11-01 · Status: APPROVED — GO (owner approval recorded)*
