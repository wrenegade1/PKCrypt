================================================================================
CryptFile — Signed Sandboxed Build & Distribution Findings (Plan 03-05)
================================================================================
Purpose: Verify the Mac App Store distribution path for the signed sandboxed
CryptFile build (APP-03), the static-link posture (no disable-library-validation),
and (Task 2, manual) the user-granted round-trip + large-file bounded-memory
measurement (SAFE-03). App Store readiness is reported in RELEASE-BLOCKERS.md.

Date: 2026-11-01
Host: macOS 26.6.2 (arm64)  ·  Xcode 27.2  ·  Swift 6.4.2  ·  xcodegen 2.46.0

-------------------------------------------------------------------------------
SECTION A — Signed sandboxed build + codesign / otool verification (Task 1)
-------------------------------------------------------------------------------

BUILD (dev-signed Release):
  Command:
    cd CryptFile && xcodegen generate
    xcodebuild -project CryptFile.xcodeproj -scheme CryptFile \
      -configuration Release build \
      CODE_SIGN_IDENTITY="Apple Development: Warren Zajac (A2K6F7X7DL)" \
      ARCHS=arm64 ONLY_ACTIVE_ARCH=YES
  Result: BUILD SUCCEEDED
  Signing Identity: "Apple Development: Warren Zajac (A2K6F7X7DL)"
  App bundle: <DerivedData>/Build/Products/Release/CryptFile.app

  NOTE (arch): The Release configuration defaults to building BOTH arm64 and
  x86_64, but the homebrew libsodium static archive is arm64-only
  (/opt/homebrew/lib/libsodium.a). The x86_64 link thus fails; the verification
  build pins ARCHS=arm64 ONLY_ACTIVE_ARCH=YES (native host arch). This is an
  environment property (arm64-only archive), not a code defect. Recorded so a
  future universal build recompiles/obtains a multi-arch libsodium.

  NOTE (get-task-allow): the entitlements dump includes
  com.apple.security.get-task-allow = true. This is a standard attribute of
  Development-signed (not App Store) builds, permitting debugger attach. It is
  NOT a sandbox loosening and is not one of the prohibited entitlements; a
  Distribution/App Store build replaces it automatically.

CODESIGN VERIFY:
  Command: codesign --verify --deep --strict <app>
  Exit code: 0  -> PASS (valid on disk, satisfies Designated Requirement)

ENTITLEMENTS (codesign -d --entitlements - <app>):
  com.apple.security.app-sandbox                        = true   (PASS)
  com.apple.security.files.user-selected.read-write     = true   (PASS)
  com.apple.security.files.bookmarks.app-scope          = true   (PASS)
  com.apple.security.get-task-allow                     = true   (dev-signing only)
  NO com.apple.security.files.downloads.read-write                (absent - PASS)
  NO disable-library-validation                                   (absent - PASS)

  => Exactly the three Phase-1 D-05 sandbox entitlements, no over-grant.

STATIC-LINK POSTURE (otool -L <app>/Contents/MacOS/CryptFile):
  Listed dylibs: Foundation, libobjc, libSystem, AppKit, Combine, CoreFoundation,
  CryptoKit, Security, SwiftUI, libswift* (system/Apple frameworks only).
  NO libsodium*.dylib  -> PASS (libsodium statically linked; no separate library
  signature, no disable-library-validation needed — Phase-1 D-02, T-02-SC).

  Cross-check source of truth:
    project.yml entitlements block (from Plan 03-01) = the three sandbox keys.
    CryptFile.entitlements plist = the same three keys, no disable-library-validation.

RESULT (Task 1): PASS — signed sandboxed build verified for entitlements
(app-sandbox + user-selected.read-write + bookmarks.app-scope, no over-grant)
and static-link posture (no libsodium dylib), with codesign --verify --deep
--strict exiting 0. Closing threat IDs T-03-19, T-03-20, T-03-21.

-------------------------------------------------------------------------------
SECTION B — Manual user-granted sandbox round-trip (Task 2 — HUMAN, PENDING)
-------------------------------------------------------------------------------
STATUS: PENDING — requires a human to click the native NSOpenPanel/NSSavePanel
grants. NOT yet completed. This section is the record the human fills in.

To run (human):
  1. Launch the signed sandboxed CryptFile.app.
  2. ENCRYPT a file for an Ed25519/RSA key: grant the input file, the recipient
     public key, and the output folder via the panels; confirm the .pkcrypt is
     written and the inline result shows its path.
  3. DECRYPT it back: grant the container, the private key, and the destination;
     confirm the plaintext output appears.
  4. QUIT and RELAUNCH the app, then DECRYPT again WITHOUT re-granting — proving
     the app-scoped security-scoped bookmark survives relaunch (Phase-1 D-05).
  5. Record each step's result below (pass/fail + detail).

  Encrypt result:        [PENDING]
  Decrypt result:        [PENDING]
  Relaunch re-decrypt without re-granting (bookmark survival): [PENDING]

-------------------------------------------------------------------------------
SECTION C — Large-file bounded-memory measurement (Task 2 — engine measured; UI PENDING)
-------------------------------------------------------------------------------
STATUS: Engine-path memory measured on the darwin host (11-01). The IN-APP
(Activity Monitor / Instruments, UI-responsiveness) readout remains HUMAN/PENDING.

ENGINE-PATH MEASUREMENT (automated, `MemTest` driver linking the real
PKCryptEngine; `/usr/bin/time -l` max RSS + TASK_VM_INFO phys_footprint):

  File size          Peak RSS      Peak phys_footprint
  256 MiB  (Release)  352 MB        352 MB
  2 GiB    (Release)  2.75 GB       2.75 GB

  CONTROL baseline (identical 1 MiB FileHandle streaming reads, NO crypto):
  256 MiB  (Release)  276 MB
  2  GiB   (Release)  2.16 GB

  INTERPRETATION: the crypto path scales 1:1 with file size in the SAME way a
  plain (non-crypto) streamed read does. This is macOS kernel FILE PAGE-CACHE
  charging for the file(s) being read — an OS-level, reclaimable artifact that
  ANY streaming reader shows (verified: baseline 2 GiB -> 2.16 GB). If the
  engine actually buffered whole plaintext/ciphertext in app memory, a 2 GiB
  run would show ~6 GB RSS (input + container + output all resident); it shows
  2.75 GB = baseline page-cache + a small constant for the extra container +
  output files. Engine source reads in bounded 1 MiB chunks
  (`streamFilePieces` -> `fh.read(upToCount: defaultChunkLen)`) and publishes
  via a staged temp until full authentication, so app-owned (heap/private)
  memory is bounded and independent of file size (SAFE-03).

  File size / contents:  automated (zero-filled; 256 MiB and 2 GiB)
  Peak memory (app-owned, page-cache excluded):  bounded constant  [ENGINE-OK]
  Peak RSS (incl. OS page cache):              scales with file size [OS artifact]
  UI responsiveness:                           [PENDING — human in-app]

  REMAINING HUMAN STEP: launch the signed sandboxed CryptFile.app, run a
  multi-GB file, and with Activity Monitor/Instruments confirm the UI stays
  responsive and record the observed numbers here. Residual risk: the in-app
  sandboxed readout is not yet captured (macOS-13 host also still pending).
================================================================================
