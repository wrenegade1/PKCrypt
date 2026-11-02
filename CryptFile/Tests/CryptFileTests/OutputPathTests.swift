import XCTest
@testable import CryptFile
import PKCryptEngine

/// FILE-03 / D-14 naming contract: mirrors `SafeOutputPublisherTests` — encrypt
/// appends `.pkcrypt`, decrypt strips it else appends `.decrypted`, and there is
/// never a numeric-suffix auto-retry (the CLI's forbidden `unused_path`) — a real
/// collision stays `destinationExists` (D-16).
final class OutputPathTests: XCTestCase {

    func testEncryptedOutputAppendsPkcrypt() {
        XCTAssertEqual(OutputPath.destination(encrypting: URL(fileURLWithPath: "/tmp/a/b.bin")).path,
                       "/tmp/a/b.bin.pkcrypt")
        XCTAssertEqual(OutputPath.destination(encrypting: URL(fileURLWithPath: "/tmp/a/report.pdf")).path,
                       "/tmp/a/report.pdf.pkcrypt")
    }

    func testDecryptedOutputStripsPkcryptElseAppendsDecrypted() {
        XCTAssertEqual(OutputPath.destination(decrypting: URL(fileURLWithPath: "/tmp/a/b.pkcrypt")).path,
                       "/tmp/a/b")
        XCTAssertEqual(OutputPath.destination(decrypting: URL(fileURLWithPath: "/tmp/a/b.txt")).path,
                       "/tmp/a/b.txt.decrypted")
    }

    func testDecryptedStripDoesNotAutoNumberOnExistingStem() {
        // A stripped stem that already exists still returns the plain stem — no
        // numeric-suffix retry (D-16); a real collision surfaces as destinationExists.
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("op-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try! Data("already here".utf8).write(to: dir.appendingPathComponent("x"))
        XCTAssertEqual(OutputPath.destination(decrypting: dir.appendingPathComponent("x.pkcrypt")).path,
                       dir.appendingPathComponent("x").path)
    }
}
