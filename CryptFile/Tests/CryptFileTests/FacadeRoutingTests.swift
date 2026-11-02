import XCTest
@testable import CryptFile
import PKCryptEngine

/// Fixture locator for the committed PKCryptEngine key fixtures, resolved from
/// the test source file's checked-in path (the engine fixtures are read from the
/// source tree, mirroring PKCryptEngine's own `Fixtures` pattern).
enum TestFixtures {
    static let repoRoot = URL(fileURLWithPath: #filePath)   // .../CryptFile/Tests/CryptFileTests/FacadeRoutingTests.swift
        .deletingLastPathComponent()                          // CryptFile/Tests/CryptFileTests
        .deletingLastPathComponent()                          // CryptFile/Tests
        .deletingLastPathComponent()                          // CryptFile
        .deletingLastPathComponent()                          // repo root
    static let fixtureDir = repoRoot
        .appendingPathComponent("PKCryptEngine/Tests/PKCryptEngineTests/Fixtures")
    static let publicKeyFile = fixtureDir.appendingPathComponent("ed25519_fixture.pub")
    static let privateKeyFile = fixtureDir.appendingPathComponent("ed25519_fixture")
    static let publicKeyData: Data = try! Data(contentsOf: publicKeyFile)
    static let privateKeyData: Data = try! Data(contentsOf: privateKeyFile)
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
    /// parsed Ed25519 PublicKeyMaterial; comment(of:) extracts the D-08 identity
    /// comment (the third+ whitespace token: `pkcrypt-engine-fixture@local`).
    func testKeySelectionParsesEd25519PublicAndComment() throws {
        let key = try KeySelection.detectAndParsePublic(TestFixtures.publicKeyData)
        XCTAssertEqual(key.ed25519Public.count, 32)
        XCTAssertEqual(KeySelection.comment(of: TestFixtures.publicKeyData),
                       "pkcrypt-engine-fixture@local")
    }
}
