# CryptFile — Mac App Store / Distribution Release Blockers

**Phase:** 03-cryptfile-application · **Plan:** 03-05 (distribution-gate record)
**Date:** 2026-11-01

This is the Phase-3 distribution gate record mapping every
`docs/feasibility/FEASIBILITY-VERDICT.md` remaining risk and Mac App Store (MAS)
constraint to either **VALIDATED** (evidence location given) or **RELEASE
BLOCKER** (reason given). Per success criterion 4, no item below is claimed
ship-ready unless it is genuinely validated. Signing/entitlements/static-link
evidence lives in `CryptFile/scripts/README-SANDBOX-FINDINGS.txt`.

| # | Risk / MAS constraint | Status | Evidence / Reason |
|---|-----------------------|--------|-------------------|
| 1 | macOS-13 runtime equivalence of `SecKey` RSA-OAEP + security-scoped bookmarks (FEASIBILITY risk A3) | RELEASE BLOCKER | Builds set `MACOSX_DEPLOYMENT_TARGET=13.0` + availability annotations, but the app has NOT been run on an actual macOS 13 host (only macOS 26 here). A macOS-13 host (VM/CI) run of the engine + sandboxed app is required before ship. |
| 2 | Apple Distribution signing identity for `com.pkcrypt.CryptFile` | RELEASE BLOCKER | An "Apple Distribution: Warren Zajac" identity IS present in the keychain, but NO distribution provisioning profile exists for `com.pkcrypt.CryptFile` (profiles present are for other apps), so the App Store / Developer ID export path is unvalidated. The Task-1 verification build is dev-signed (Apple Development identity), which embeds `get-task-allow` and is not a ship signature. |
| 3 | Notarization + App Store submission | RELEASE BLOCKER | Not performed; deferred to release-time. Requires a Distribution-signed archive, `xcrun notarytool` submission, and App Store Connect validation. |
| 4 | Sandbox entitlements + static-link posture (Phase-1 D-02 / D-05; MAS requires sandbox, no disable-library-validation) | VALIDATED | `codesign --verify --deep --strict` exits 0; entitlement dump shows exactly app-sandbox + files.user-selected.read-write + files.bookmarks.app-scope (no downloads.read-write, no disable-library-validation); `otool -L` shows no libsodium dylib (statically linked). Evidence: `CryptFile/scripts/README-SANDBOX-FINDINGS.txt` §A. |
| 5 | User-granted sandboxed access through completion incl. relaunch (app-scoped bookmark survival) | RELEASE BLOCKER | PENDING — requires the human manual round-trip (Plan 03-05 Task 2): encrypt + decrypt + relaunch re-decrypt without re-granting under the signed sandbox. Phase-1 D-05 proved this at probe level, but the in-app signed-sandboxed run is not yet recorded. Once the human completes it, this row is re-assessed as VALIDATED. |

**Status summary:** 1 of 5 validated (sandbox entitlements + static-link posture);
4 release blockers remain (macOS-13 runtime, distribution signing, notarization,
and the in-app user-granted round-trip). No MAS readiness is claimed for any
dev-signed or macOS-13-unverified item.

**Next step to clear blockers:** the human completes the signed-sandboxed manual
round-trip (Plan 03-05 Task 2) and records it in
`CryptFile/scripts/README-SANDBOX-FINDINGS.txt` §B; a macOS-13 host run and a
Distribution signing/notarization pass are release-time gated items.
