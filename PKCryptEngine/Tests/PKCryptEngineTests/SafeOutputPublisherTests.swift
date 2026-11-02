import Testing
import Foundation
@testable import PKCryptEngine

// MARK: - SAFE-02 / SafeOutputPublisher filesystem tests
//
// These tests exercise the real SafeOutputPublisher on the actual filesystem:
// atomic no-replace publication via renamex_np(RENAME_EXCL), 0600-at-creation
// temp staging in the destination's OWN directory, D-09 naming WITHOUT the
// forbidden D-10 auto-numbering, temp cleanup that touches only the engine's
// own file, and the collision/0600/isolation edges (SAFE-02 / D-06/D-07/D-08/D-09/D-10).

/// A unique scratch directory per test (self-contained, with `.tmp` scanning).
struct SafeDir {
    let url: URL
    init() {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("pkpub-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
    func file(_ name: String) -> URL { url.appendingPathComponent(name) }
    func tempArtifacts() -> [URL] {
        ((try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? [])
            .filter { $0.lastPathComponent.hasSuffix(".tmp") }
    }
    func contains(_ name: String) -> Bool {
        FileManager.default.fileExists(atPath: file(name).path)
    }
    func cleanup() { try? FileManager.default.removeItem(at: url) }
}

/// POSIX permission bits (0o600 etc.) as an Int for comparison.
func posixMode(_ url: URL) -> Int {
    (try? FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue ?? -1
}

@Suite("SafeOutputPublisher — atomic no-replace publish & 0600 staging")
struct SafeOutputPublisherTests {

    // MARK: publish to a fresh destination

    @Test("publishing to a non-existent destination succeeds; the destination exists afterward with mode 0600")
    func publishNewDestination() throws {
        let d = SafeDir(); defer { d.cleanup() }
        let dest = d.file("out")
        let pub = SafeOutputPublisher(destinationURL: dest)
        let fh = try pub.start()
        try fh.write(contentsOf: Data("hello plaintext".utf8))
        try pub.publish(fh: fh)
        #expect(FileManager.default.fileExists(atPath: dest.path))
        #expect(posixMode(dest) & 0o777 == 0o600, "published destination must be 0600")
        #expect(try Data(contentsOf: dest) == Data("hello plaintext".utf8))
        #expect(d.tempArtifacts().isEmpty, "the staging temp must be consumed by a successful publish")
    }

    // MARK: collision with an existing destination

    @Test("publishing to an EXISTING destination returns destinationExists and leaves the existing file unchanged")
    func publishExistingDestination() throws {
        let d = SafeDir(); defer { d.cleanup() }
        let dest = d.file("out.pkcrypt")
        try Data("existing content".utf8).write(to: dest)   // pre-existing destination
        let pub = SafeOutputPublisher(destinationURL: dest)
        let fh = try pub.start()
        try fh.write(contentsOf: Data("would-be new content".utf8))
        do {
            try pub.publish(fh: fh)
            Issue.record("expected destinationExists for an existing destination (D-10, no auto-rename)")
        } catch let e {
            guard case .destinationExists = e as! EngineError else {
                Issue.record("expected .destinationExists, got \(e)")
                return
            }
        }
        // Existing content untouched, temp cleaned.
        #expect(try Data(contentsOf: dest) == Data("existing content".utf8))
        #expect(d.tempArtifacts().isEmpty, "the failed publish must not leave a temp behind")
    }

    // MARK: 0600-at-creation staging in the destination's own directory

    @Test("the staging temp is created in the SAME directory as the destination and is 0600 from creation")
    func temp0600AtCreationInSameDirectory() throws {
        let d = SafeDir(); defer { d.cleanup() }
        let dest = d.file("out.pkcrypt")
        let pub = SafeOutputPublisher(destinationURL: dest)
        _ = try pub.start()
        let temps = d.tempArtifacts()
        #expect(temps.count == 1, "exactly one staging temp in the destination's own directory")
        guard let tmp = temps.first else { return }
        #expect(tmp.deletingLastPathComponent().lastPathComponent == d.url.lastPathComponent,
                "the temp must live in the destination's own directory for an atomic rename")
        #expect(posixMode(tmp) & 0o777 == 0o600,
                "the temp must be 0600 from creation — never chmod-after-exposure (D-07)")
        // No world-readable window: 0600 means no group/other bits while staging.
        pub.abort()
        #expect(d.tempArtifacts().isEmpty, "abort must remove the tracked temp")
    }

    // MARK: abort / cleanup

    @Test("abort() removes the temp file and leaves no .tmp artifact and no destination file")
    func abortLeavesNoArtifacts() throws {
        let d = SafeDir(); defer { d.cleanup() }
        let dest = d.file("out.pkcrypt")
        let pub = SafeOutputPublisher(destinationURL: dest)
        let fh = try pub.start()
        try fh.write(contentsOf: Data("partial".utf8))
        pub.abort()
        #expect(!FileManager.default.fileExists(atPath: dest.path), "no destination may be published")
        #expect(d.tempArtifacts().isEmpty, "no .tmp artifact may remain")
    }

    // MARK: D-09 naming (no D-10 auto-numbering)

    @Test("encryptedOutputPath appends .pkcrypt (D-09)")
    func namingEncrypted() {
        #expect(SafeOutputPublisher.encryptedOutputPath(for: URL(fileURLWithPath: "/tmp/a/b.bin")).path == "/tmp/a/b.bin.pkcrypt")
        #expect(SafeOutputPublisher.encryptedOutputPath(for: URL(fileURLWithPath: "/tmp/a/report.pdf")).path == "/tmp/a/report.pdf.pkcrypt")
    }

    @Test("decryptedOutputPath strips .pkcrypt else appends .decrypted — never auto-numbers (D-09/D-10)")
    func namingDecrypted() {
        // strip a trailing .pkcrypt
        #expect(SafeOutputPublisher.decryptedOutputPath(for: URL(fileURLWithPath: "/tmp/a/b.pkcrypt")).path == "/tmp/a/b")
        // else append .decrypted
        #expect(SafeOutputPublisher.decryptedOutputPath(for: URL(fileURLWithPath: "/tmp/a/b.txt")).path == "/tmp/a/b.txt.decrypted")
    }

    @Test("a stripped stem that already exists still returns the plain stem — no numeric-suffix retry (D-10)")
    func namingDecryptedNoAutoNumbering() {
        let d = SafeDir(); defer { d.cleanup() }
        // The destination `x` already exists on disk.
        try! Data("already here".utf8).write(to: d.file("x"))
        _ = d.file("x.pkcrypt") // (container may or may not exist; naming doesn't depend on it)
        // decryptedOutputPath must return the PLAIN stem (x), NOT x.1 / x.2 (unused_path is forbidden by D-10).
        #expect(SafeOutputPublisher.decryptedOutputPath(for: d.file("x.pkcrypt")).path == d.file("x").path,
                "naming must NOT reuse the CLI's unused_path() numeric-suffix fallback")
    }

    // MARK: sequential publishes to the same destination (idempotency / COMP-01*COMP-02 probe)

    @Test("two sequential publishes to the same destination: first succeeds, second returns destinationExists")
    func sequentialPublishes() throws {
        let d = SafeDir(); defer { d.cleanup() }
        let dest = d.file("out")

        let p1 = SafeOutputPublisher(destinationURL: dest)
        let f1 = try p1.start()
        try f1.write(contentsOf: Data("first".utf8))
        try p1.publish(fh: f1)
        #expect(try Data(contentsOf: dest) == Data("first".utf8))

        let p2 = SafeOutputPublisher(destinationURL: dest)
        let f2 = try p2.start()
        try f2.write(contentsOf: Data("second".utf8))
        do {
            try p2.publish(fh: f2)
            Issue.record("expected the second publish to return destinationExists")
        } catch let e {
            guard case .destinationExists = e as! EngineError else {
                Issue.record("expected .destinationExists, got \(e)")
                return
            }
        }
        #expect(try Data(contentsOf: dest) == Data("first".utf8), "the first result must never be overwritten")
        #expect(d.tempArtifacts().isEmpty)
    }
}
