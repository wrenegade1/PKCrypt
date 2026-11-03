// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import XCTest
@testable import CryptFile
import PKCryptEngine

/// Fixture locator for the committed PKCryptEngine key fixtures, resolved from
/// the test source file's checked-in path. Keys and containers are generated
/// for each run by PKCryptEngine/Scripts/make_test_fixtures.py (the same
/// generator the engine tests use), via the scheme's test pre-action; no key
/// material is committed.
enum TestFixtures {
    static let repoRoot = URL(fileURLWithPath: #filePath)   // .../CryptFile/Tests/CryptFileTests/FacadeRoutingTests.swift
        .deletingLastPathComponent()                          // CryptFile/Tests/CryptFileTests
        .deletingLastPathComponent()                          // CryptFile/Tests
        .deletingLastPathComponent()                          // CryptFile
        .deletingLastPathComponent()                          // repo root
    /// Generated before the run by the CryptFile scheme's test pre-action
    /// (the sandboxed test host cannot launch python3/ssh-keygen itself).
    static let fixtureDir: URL = {
        let dir = repoRoot.appendingPathComponent(".test-fixtures/cryptfile")
        guard FileManager.default.fileExists(atPath: dir.appendingPathComponent("ed25519_fixture").path) else {
            fatalError("test fixtures missing at \(dir.path): run the tests through the CryptFile "
                       + "scheme, whose test pre-action generates them (see .test-fixtures/cryptfile.log)")
        }
        return dir
    }()
    static let publicKeyFile = fixtureDir.appendingPathComponent("ed25519_fixture.pub")
    static let privateKeyFile = fixtureDir.appendingPathComponent("ed25519_fixture")
    static let publicKeyData: Data = try! Data(contentsOf: publicKeyFile)
    static let privateKeyData: Data = try! Data(contentsOf: privateKeyFile)

    // Read-only container fixtures (RSA + XChaCha read paths for the union facade).
    static let containersDir = fixtureDir.appendingPathComponent("Containers")
    static let rsaContainersDir = fixtureDir.appendingPathComponent("RSA/Containers")
    static var xcEd1MiB: Data { try! Data(contentsOf: containersDir.appendingPathComponent("xc_ed_1MiB.pkcrypt")) }
    static var rsaXc1MiB: Data { try! Data(contentsOf: rsaContainersDir.appendingPathComponent("rsa2048_xc_1MiB.pkcrypt")) }
}

/// Wave-0 EE24519 tracer battery: drives the REAL PKCryptEngine facade end-to-end
/// through the app's OutputPath/KeySelection wrappers so the app-level wiring is
/// proven (FILE-01 / FILE-03 / APP-02 / SAFE-03 progress path) before any expansion.
final class FacadeRoutingTests: XCTestCase {

    /// Unique scratch directory per test.
    func scratchDir() -> URL {
        let d = FileManager.default.temporaryDirectory
            .appendingPathComponent("crft-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    /// An Ed25519 public key + one file run through the real engine encrypt -> the
    /// output is published at `<input>.pkcrypt`, the progress callback reports
    /// monotonically non-decreasing bytes, and decrypt round-trips the original bytes.
    func testEncryptPublishesPkcryptAndProgressIsMonotonic() async {
        let dir = scratchDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let input = dir.appendingPathComponent("in.bin")
        let payload = Data(repeating: 0x41, count: 2 * 1_048_576 + 100)   // > 2 chunks -> >1 progress callback
        try! payload.write(to: input)

        let recipient = try! KeyMaterial.parseEd25519Public(TestFixtures.publicKeyData)
        let dest = dir.appendingPathComponent("in.bin.pkcrypt")

        var samples: [Int64] = []
        let result = await PKCryptEngine.encrypt(
            fileURL: input,
            recipient: recipient,
            destinationURL: dest,
            progress: { p in samples.append(p.bytesProcessed) }
        )
        guard case .success(let url) = result else {
            XCTFail("expected encrypt success, got \(result)")
            return
        }
        XCTAssertEqual(url, dest, "the published result URL must be the requested destination")
        XCTAssertTrue(FileManager.default.fileExists(atPath: dest.path),
                      "the .pkcrypt output must be published (SafeOutputPublisher no-replace)")

        XCTAssertGreaterThanOrEqual(samples.count, 1, "the progress callback must fire at least once (per chunk)")
        for i in 1 ..< samples.count {
            XCTAssertGreaterThanOrEqual(samples[i], samples[i - 1],
                                        "bytesProcessed must be monotonically non-decreasing")
        }

        // Round-trip decrypt back to the original bytes (proves the tracer decrypt path).
        let privateKey = try! KeyMaterial.parseEd25519Private(TestFixtures.privateKeyData)
        let out = dir.appendingPathComponent("out.bin")
        let decResult = await PKCryptEngine.decrypt(containerURL: dest, privateKey: privateKey, destinationURL: out)
        guard case .success = decResult else {
            XCTFail("decrypt round-trip failed: \(decResult)")
            return
        }
        let recovered = try! Data(contentsOf: out)
        XCTAssertEqual(recovered, payload, "round-trip must recover the original bytes")
    }

    /// OutputPath.destination(encrypting:) must mirror the engine's CLI-derived
    /// name (D-14): `<input>.pkcrypt`.
    func testOutputPathEncryptAppendsPkcrypt() throws {
        XCTAssertEqual(OutputPath.destination(encrypting: URL(fileURLWithPath: "/tmp/a/b.bin")).path,
                       "/tmp/a/b.bin.pkcrypt")
        XCTAssertEqual(OutputPath.destination(encrypting: URL(fileURLWithPath: "/tmp/a/report.pdf")).path,
                       "/tmp/a/report.pdf.pkcrypt")
    }

    /// KeySelection.detectAndParsePublic delegates to the engine and returns the
    /// parsed Ed25519 PublicKeyMaterial (union .ed25519); comment(of:) extracts
    /// the D-08 identity comment (the third+ whitespace token: `ed25519_fixture@pkcrypt-test`).
    func testKeySelectionParsesEd25519PublicAndComment() throws {
        let key = try KeySelection.detectAndParsePublic(TestFixtures.publicKeyData)
        guard case .ed25519(let mat) = key else {
            return XCTFail("expected .ed25519, got \(key)")
        }
        XCTAssertEqual(mat.ed25519Public.count, 32)
        XCTAssertEqual(KeySelection.comment(of: TestFixtures.publicKeyData),
                       "ed25519_fixture@pkcrypt-test")
    }

    // MARK: - Union-facade app contract (RSA + XChaCha + cross-key; Task 2)

    /// The committed fixture plaintext pattern (byte-identical to the engine's
    /// fixture generator `(i*7+3) & 0xFF`), used to assert XChaCha reads.
    private func fixturePattern(_ n: Int) -> Data {
        Data((0 ..< n).map { UInt8(($0 * 7 + 3) & 0xFF) })
    }

    /// App contract: RSA recipient parsed via KeySelection.detectAndParsePublic
    /// (.rsa) → union encrypt → v3 container; RSA private key parsed via
    /// detectAndParsePrivate (.rsa) → union decrypt recovers the plaintext
    /// (FILE-01 / FILE-02 through the union facade).
    func testRSAEncryptDecryptRoundTripThroughAppUnion() async {
        let dir = scratchDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let input = dir.appendingPathComponent("in.bin")
        let payload = Data(repeating: 0x41, count: 4096)
        try! payload.write(to: input)

        let recipient = try! KeySelection.detectAndParsePublic(TestFixtures.rsaPublicData)
        guard case .rsa = recipient else { return XCTFail("expected .rsa recipient") }
        let container = dir.appendingPathComponent("in.bin.pkcrypt")
        guard case .success = await PKCryptEngine.encrypt(fileURL: input, recipient: recipient, destinationURL: container),
              FileManager.default.fileExists(atPath: container.path) else {
            return XCTFail("RSA union encrypt failed")
        }

        let privateKey = try! KeySelection.detectAndParsePrivate(TestFixtures.rsaPrivateData)
        guard case .rsa = privateKey else { return XCTFail("expected .rsa private key") }
        let out = dir.appendingPathComponent("out.bin")
        guard case .success = await PKCryptEngine.decrypt(containerURL: container, privateKey: privateKey, destinationURL: out) else {
            return XCTFail("RSA union decrypt failed")
        }
        XCTAssertEqual(try! Data(contentsOf: out), payload, "RSA round-trip must recover the original plaintext")
    }

    /// A v3 (RSA) container cannot be decrypted by an Ed25519 key — the union
    /// decrypt returns typed `unsupportedFormat`, NOT `authFailure` (PITFALL #10).
    func testCrossKeyMismatchIsTypedUnsupportedFormat() async {
        let dir = scratchDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let input = dir.appendingPathComponent("in.bin")
        try! Data([0x41]).write(to: input)
        let rsaRecipient = try! KeySelection.detectAndParsePublic(TestFixtures.rsaPublicData)
        let container = dir.appendingPathComponent("c.pkcrypt")
        guard case .success = await PKCryptEngine.encrypt(fileURL: input, recipient: rsaRecipient, destinationURL: container),
              FileManager.default.fileExists(atPath: container.path) else {
            return XCTFail("RSA encrypt for the mismatch test failed")
        }
        let edKey = try! KeySelection.detectAndParsePrivate(TestFixtures.privateKeyData)  // .ed25519
        let result = await PKCryptEngine.decrypt(containerURL: container,
                                                 privateKey: edKey,
                                                 destinationURL: dir.appendingPathComponent("out"))
        guard case .failure(let e) = result else { return XCTFail("expected cross-key failure, got \(result)") }
        guard case .unsupportedFormat = e else {
            return XCTFail("cross-key mismatch must be typed unsupportedFormat, got \(e)")
        }
    }

    /// XChaCha20 (cipher 0x01) reads through the private-key union, both v2
    /// (Ed25519) and v3 (RSA) — the cipher dispatch the app relies on (FILE-02).
    func testXChaChaReadViaAppPrivateKeyUnion() async {
        let d1 = scratchDir(); defer { try? FileManager.default.removeItem(at: d1) }
        try! TestFixtures.xcEd1MiB.write(to: d1.appendingPathComponent("in.pkcrypt"))
        let edKey = try! KeySelection.detectAndParsePrivate(TestFixtures.privateKeyData)
        let r1 = await PKCryptEngine.decrypt(containerURL: d1.appendingPathComponent("in.pkcrypt"),
                                             privateKey: edKey,
                                             destinationURL: d1.appendingPathComponent("out"))
        guard case .success = r1 else { return XCTFail("v2 XChaCha read failed: \(r1)") }
        XCTAssertEqual(try! Data(contentsOf: d1.appendingPathComponent("out")), fixturePattern(1 << 20))

        let d2 = scratchDir(); defer { try? FileManager.default.removeItem(at: d2) }
        try! TestFixtures.rsaXc1MiB.write(to: d2.appendingPathComponent("in.pkcrypt"))
        let rsaKey = try! KeySelection.detectAndParsePrivate(TestFixtures.rsaPrivateData)
        let r2 = await PKCryptEngine.decrypt(containerURL: d2.appendingPathComponent("in.pkcrypt"),
                                             privateKey: rsaKey,
                                             destinationURL: d2.appendingPathComponent("out"))
        guard case .success = r2 else { return XCTFail("v3 XChaCha read failed: \(r2)") }
        XCTAssertEqual(try! Data(contentsOf: d2.appendingPathComponent("out")), fixturePattern(1 << 20))
    }

    /// The D-08/D-11 identity summary shows type + comment + truncated
    /// fingerprint and NEVER the raw key line/blob (T-03-11). Mirrors the
    /// summary string the Encrypt/Decrypt views build.
    func testIdentitySummaryShowsTypeCommentFingerprintNotRawBlob() {
        let data = TestFixtures.rsaPublicData
        let summary = ["RSA",
                       KeySelection.comment(of: data).map { "· \($0)" },
                       "· \(KeySelection.fingerprint(of: data))"]
            .compactMap { $0 }
            .joined(separator: " ")
        XCTAssertTrue(summary.hasPrefix("RSA"))
        XCTAssertTrue(summary.contains("rsa2048@pkcrypt-test"),
                      "identity summary should surface the key comment (D-08)")
        XCTAssertTrue(summary.contains("SHA256:"),
                      "identity summary should surface the truncated fingerprint (D-08)")
        let line = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        XCTAssertFalse(summary.contains(line),
                       "identity summary must never include the raw key line/blob (T-03-11)")
    }

    // MARK: - D-16 destinationExists → alternate-destination flow (Task 3)

    /// D-16 / SAFE-02: a real `.destinationExists` collision enters the
    /// alternate-destination state (NOT failure, NOT overwrite); a second run to
    /// a fresh destination publishes there and never clobbers the first file.
    @MainActor
    func testDestinationExistsEntersAlternateFlowThenRunsToAlternate() async {
        let dir = scratchDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let input = dir.appendingPathComponent("in.bin")
        let payload = Data(repeating: 0x41, count: 256)
        try! payload.write(to: input)

        let vm = WorkflowViewModel()
        vm.setMode(.encrypt)
        vm.setInput(input)
        vm.selectRecipient(try! KeySelection.detectAndParsePublic(TestFixtures.publicKeyData), summary: "Ed25519")

        // Pre-existing destination -> first run must collide.
        let first = dir.appendingPathComponent("in.bin.pkcrypt")
        try! Data("occupied".utf8).write(to: first)
        vm.setDestination(first)

        vm.run()
        await vm.task?.value

        XCTAssertTrue(vm.pendingAlternateDestination,
                      "a collision must enter the alternate-destination state (D-16)")
        XCTAssertNil(vm.outputPath, "no destination may be published on a collision")
        XCTAssertNil(vm.errorTitle, "a collision is not an error banner")
        XCTAssertEqual(try! Data(contentsOf: first), Data("occupied".utf8),
                       "the existing destination must stay untouched (no overwrite)")

        // Re-run to a fresh alternate destination — same selections, new path.
        let alt = dir.appendingPathComponent("alternate.pkcrypt")
        vm.run(toAlt: alt)
        await vm.task?.value

        XCTAssertEqual(vm.outputPath, alt.path, "the alternate re-run must publish there")
        XCTAssertFalse(vm.pendingAlternateDestination, "the D-16 state resets after a successful alternate run")
        XCTAssertTrue(FileManager.default.fileExists(atPath: alt.path))
        XCTAssertEqual(try! Data(contentsOf: first), Data("occupied".utf8),
                       "the first destination must never be overwritten/clobbered")
        XCTAssertNil(vm.errorTitle)
    }

    // MARK: - Throttled progress bridge + cooperative cancel (SAFE-03, D-17/D-18)

    /// The ProgressBridge coalesces engine @Sendable progress, preserving
    /// monotonic bytesProcessed and forwarding the latest sample on the main actor.
    func testProgressBridgeCoalescesAndPreservesMonotonicLatest() {
        let bridge = ProgressBridge()
        // An in-memory @Sendable producer stream of monotonically increasing bytes.
        let updates: [EngineProgress] = [
            .init(bytesProcessed: 0, totalBytes: 1000),
            .init(bytesProcessed: 250, totalBytes: 1000),
            .init(bytesProcessed: 500, totalBytes: 1000),
            .init(bytesProcessed: 1000, totalBytes: 1000)
        ]
        for u in updates { bridge.record(u) }

        // The first take() always forwards and must reflect the monotonic latest.
        let first = bridge.take()
        XCTAssertNotNil(first)
        XCTAssertEqual(first?.bytesProcessed, 1000, "the bridge must forward the latest sample")

        // Subsequent takes within the throttle window coalesce (nil)…
        _ = bridge.take()
        XCTAssertNil(bridge.take(), "within the throttle window the bridge must coalesce")

        // …until the throttle interval elapses, when the newest reported value flows.
        Thread.sleep(forTimeInterval: 0.06)   // > minInterval (0.04s)
        bridge.record(.init(bytesProcessed: 1000, totalBytes: 1000))
        let later = bridge.take()
        XCTAssertNotNil(later, "after the throttle window the latest sample must forward")
        XCTAssertGreaterThanOrEqual(later!.bytesProcessed, first!.bytesProcessed,
                                    "bytesProcessed must never decrease across forwarded samples")
    }

    /// D-18 / FILE-03: cancelling a run mid-operation returns the tab to ready with
    /// the inline "Cancelled" note and no destination published, and Run re-enables.
    @MainActor
    func testCancelMidRunReturnsToReadyWithNoDestination() async {
        let dir = scratchDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let input = dir.appendingPathComponent("big.bin")
        // Large enough that the engine is mid-stream when we cancel.
        try! Data(repeating: 0x44, count: 64 * 1_048_576 + 1).write(to: input)

        let vm = WorkflowViewModel()
        vm.setMode(.encrypt)
        vm.setInput(input)
        vm.selectRecipient(try! KeySelection.detectAndParsePublic(TestFixtures.publicKeyData), summary: "Ed25519")
        vm.setDestination(dir.appendingPathComponent("big.bin.pkcrypt"))

        XCTAssertTrue(vm.canRun)
        vm.run()
        vm.cancel()                       // cooperative cancel between chunks
        await vm.task?.value

        XCTAssertFalse(vm.isRunning, "cancel must return the tab to ready (D-18)")
        XCTAssertTrue(vm.didCancel, "cancel must surface the inline Cancelled note (D-20)")
        XCTAssertNil(vm.outputPath, "cancel must NOT publish a destination")
        XCTAssertNil(vm.errorTitle, "cancel is not an error banner")
        XCTAssertTrue(vm.canRun, "Run must re-enable after cancel (D-21)")
    }
}
