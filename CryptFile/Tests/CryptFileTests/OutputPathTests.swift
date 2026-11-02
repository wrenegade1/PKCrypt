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

    // MARK: - Security-scoped bookmark lifecycle (APP-03 / D-05)

    /// A temporary URL round-trips `persistBookmark` → `resolveBookmark` through
    /// UserDefaults with the same path (non-stale), and `access(_:)` returns the
    /// closure's value with a balanced start/stop scope (Pitfall 1 / T-03-15).
    func testBookmarkStoreResolveRoundTripOnTempURL() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("scoped-\(UUID().uuidString).bin")
        try! Data("bookmark-payload".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let key = "test.bookmark.\(UUID().uuidString)"
        // Clean any prior value for a stable baseline.
        UserDefaults.standard.removeObject(forKey: key)
        defer { UserDefaults.standard.removeObject(forKey: key) }

        XCTAssertNoThrow(try SecurityScopedAccess.persistBookmark(for: url, key: key))
        let stored = UserDefaults.standard.data(forKey: key)
        XCTAssertNotNil(stored, "persistBookmark must write bookmark data to UserDefaults")

        let resolved = SecurityScopedAccess.resolveBookmark(for: key)
        XCTAssertNotNil(resolved, "resolveBookmark must recover a URL")
        XCTAssertEqual(resolved!.path, url.path, "resolve must recover the same URL (non-stale)")

        // access(_:) runs the closure inside a balanced start/stop scope and returns
        // its value.
        let value = SecurityScopedAccess.access(resolved!) { scoped in
            XCTAssertEqual(scoped.path, url.path, "access must hand the resolved URL to the closure")
            return 42
        }
        XCTAssertEqual(value, 42, "access must return the closure's value")
    }

    /// The WorkflowViewModel best-effort persistence helper persists a granted URL
    /// and resolves it back to the same path (best-effort, non-fatal).
    @MainActor
    func testViewModelPersistGrantedWritesAndResolvesBookmark() {
        let vm = WorkflowViewModel()
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("granted-\(UUID().uuidString).txt")
        try! Data("hi".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let key = SecurityScopedAccess.bookmarkKey(for: .input)
        UserDefaults.standard.removeObject(forKey: key)
        vm.persistGranted(url, scope: .input)
        defer { UserDefaults.standard.removeObject(forKey: key) }

        let resolved = SecurityScopedAccess.resolveBookmark(for: key)
        XCTAssertEqual(resolved?.path, url.path, "the granted URL must be persistable + resolvable")
    }

    // MARK: - D-14 live default / D-15 custom re-target contract

    /// A Change… override (D-15) sets a custom destination and persists it as a
    /// bookmark; a CLI-derived live default (D-14) clears the custom flag.
    @MainActor
    func testCustomDestinationOverrideIsFlaggedAndPersisted() {
        let vm = WorkflowViewModel()
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent("rt-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        let input = tempDir.appendingPathComponent("a.bin")
        try! Data("x".utf8).write(to: input)

        let key = SecurityScopedAccess.bookmarkKey(for: .destination)
        UserDefaults.standard.removeObject(forKey: key)
        defer { UserDefaults.standard.removeObject(forKey: key) }

        // Live default (D-14): CLI-derived, not custom.
        let defaultDest = tempDir.appendingPathComponent("a.bin.pkcrypt")
        vm.setDestination(defaultDest)
        XCTAssertFalse(vm.isCustomDestination, "a CLI-derived default is not a user override")

        // Change… override (D-15): custom flag set + persisted as a bookmark.
        let custom = tempDir.appendingPathComponent("custom.bin.pkcrypt")
        try! Data("".utf8).write(to: custom)
        vm.setCustomDestination(custom)
        XCTAssertTrue(vm.isCustomDestination, "an NSSavePanel override must mark the destination custom")
        XCTAssertEqual(SecurityScopedAccess.resolveBookmark(for: key)?.path, custom.path,
                       "the custom destination must be persisted as a security-scoped bookmark")
    }
}
