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

    // MARK: - Task 2: public async Result API — progress & cooperative cancellation (D-12/D-15/D-16)

    @Test("decrypt/encrypt return EngineResult (success/failure); no error throws escape the public API")
    func resultContractNoThrow() async {
        let d = SafeDir(); defer { d.cleanup() }
        let input = d.file("in")
        try! pattern(64).write(to: input)
        let enc: EngineResult<URL> = await PKCryptEngine.encrypt(fileURL: input,
                                                                  recipient: Fixtures.publicKey,
                                                                  destinationURL: d.file("out.pkcrypt"))
        #expect(enc == .success(d.file("out.pkcrypt")))
        let dec: EngineResult<URL> = await PKCryptEngine.decrypt(containerURL: d.file("out.pkcrypt"),
                                                                  privateKey: Fixtures.privateKey,
                                                                  destinationURL: d.file("out"))
        #expect(dec == .success(d.file("out")))
        #expect(try! Data(contentsOf: d.file("out")) == pattern(64))
    }

    @Test("the progress callback fires at least once with monotonically non-decreasing bytesProcessed")
    func progressMonotonic() async throws {
        let d = SafeDir(); defer { d.cleanup() }
        let big = 2 * ContainerCodec.defaultChunkLen + 100   // > 2 chunks so >1 callback
        let input = d.file("in")
        try pattern(big).write(to: input)
        _ = try await PKCryptEngine.encrypt(fileURL: input, recipient: Fixtures.publicKey,
                                            destinationURL: d.file("out.pkcrypt")).get()
        let box = ProgressBox()
        let result = await PKCryptEngine.decrypt(containerURL: d.file("out.pkcrypt"),
                                                 privateKey: Fixtures.privateKey,
                                                 destinationURL: d.file("out")) { p in
            box.record(p)
        }
        #expect(result == .success(d.file("out")))
        let samples = box.samples
        #expect(samples.count >= 1, "the progress callback must fire at least once (per chunk)")
        for i in 1 ..< samples.count {
            #expect(samples[i].bytesProcessed >= samples[i - 1].bytesProcessed,
                    "bytesProcessed must be monotonically non-decreasing")
        }
        #expect(samples.last?.totalBytes != nil, "totalBytes is known for a real file")
    }

    @Test("cancelling the operation mid-stream returns .failure(.cancelled), removes the temp, and publishes nothing")
    func cancellationMidStream() async {
        let d = SafeDir(); defer { d.cleanup() }
        let big = 8 * ContainerCodec.defaultChunkLen   // 8 MiB -> many chunks
        let input = d.file("in")
        try! pattern(big).write(to: input)
        _ = try! await PKCryptEngine.encrypt(fileURL: input, recipient: Fixtures.publicKey,
                                             destinationURL: d.file("out.pkcrypt")).get()

        let box = CancelBox()
        let task: Task<EngineResult<URL>, Never> = Task {
            await PKCryptEngine.decrypt(containerURL: d.file("out.pkcrypt"),
                                        privateKey: Fixtures.privateKey,
                                        destinationURL: d.file("out")) { _ in
                // Cancel as soon as decryption has begun writing a chunk (D-16
                // between-chunk checkpoint): the NEXT chunk observes the cancel.
                box.cancel()
            }
        }
        box.set(task)   // register immediately so the first-callback cancel lands
        let result = await task.value
        guard case .failure(let err) = result else {
            Issue.record("expected .failure after cancellation, got \(result)")
            return
        }
        #expect(err == .cancelled)
        #expect(!FileManager.default.fileExists(atPath: d.file("out").path), "no destination may be published on cancel")
        #expect(d.tempArtifacts().isEmpty, "cancel must remove the owning temp (D-08)")
    }

    @Test("an operation cancelled before it runs returns .failure(.cancelled) and publishes nothing")
    func cancellationBeforeStart() async {
        let d = SafeDir(); defer { d.cleanup() }
        let input = d.file("in")
        try! pattern(64).write(to: input)
        _ = try! await PKCryptEngine.encrypt(fileURL: input, recipient: Fixtures.publicKey,
                                             destinationURL: d.file("out.pkcrypt")).get()
        let task: Task<EngineResult<URL>, Never> = Task {
            await PKCryptEngine.decrypt(containerURL: d.file("out.pkcrypt"),
                                        privateKey: Fixtures.privateKey,
                                        destinationURL: d.file("out"))
        }
        task.cancel()
        let result = await task.value
        guard case .failure(let err) = result, err == .cancelled else {
            Issue.record("expected .cancelled, got \(result)")
            return
        }
        #expect(!FileManager.default.fileExists(atPath: d.file("out").path))
        #expect(d.tempArtifacts().isEmpty)
    }

    @Test("crypto-stage failures surface as .failure(.authFailure) with no distinguishing detail and publish nothing")
    func authFailureNoDetail() async throws {
        let d = SafeDir(); defer { d.cleanup() }
        var data = Fixtures.container("1MiBplus1")
        data[data.count / 2] ^= 0x01   // flip one byte mid-body -> an AEAD chunk fails to authenticate
        try data.write(to: d.file("tampered.pkcrypt"))
        let result = await PKCryptEngine.decrypt(containerURL: d.file("tampered.pkcrypt"),
                                                 privateKey: Fixtures.privateKey,
                                                 destinationURL: d.file("out"))
        guard case .failure(let err) = result else {
            Issue.record("expected a crypto-stage failure, got success")
            return
        }
        // Single generic authFailure, no distinguishing detail (D-11/D-13).
        #expect(err == .authFailure)
        #expect(!FileManager.default.fileExists(atPath: d.file("out").path), "no plaintext may be published")
        #expect(d.tempArtifacts().isEmpty, "auth failure must remove the temp")
    }

    // MARK: - Task 3: cancellation-mid-write / failure-before-publish / concurrency safety

    @Test("a simulated failure after staging but before publish leaves the destination absent and removes the temp")
    func failureAfterStagingBeforePublish() async throws {
        let d = SafeDir(); defer { d.cleanup() }
        let big = 2 * ContainerCodec.defaultChunkLen   // 2 MiB -> 2 chunks
        let input = d.file("in")
        try pattern(big).write(to: input)
        _ = try await PKCryptEngine.encrypt(fileURL: input, recipient: Fixtures.publicKey,
                                            destinationURL: d.file("out.pkcrypt")).get()

        // Corrupt one byte inside the SECOND chunk's ciphertext so the first
        // chunk still authenticates (its plaintext is staged to the temp) but
        // the final chunk fails auth -> the operation aborts before publish.
        var container = try Data(contentsOf: d.file("out.pkcrypt"))
        let headerSize = ContainerCodec.prefixBytes + ContainerCodec.ephPubBytes
            + ContainerCodec.nonceAES + ContainerCodec.chunkLenBytes   // 58
        let chunk0Len = ContainerCodec.defaultChunkLen + ContainerCodec.tagBytes
        container[headerSize + chunk0Len + 200] ^= 0x01   // inside chunk 1
        try container.write(to: d.file("tampered.pkcrypt"))

        let result = await PKCryptEngine.decrypt(containerURL: d.file("tampered.pkcrypt"),
                                                 privateKey: Fixtures.privateKey,
                                                 destinationURL: d.file("out"))
        guard case .failure(let err) = result else {
            Issue.record("expected an auth-stage failure after staging")
            return
        }
        #expect(err == .authFailure)
        #expect(!FileManager.default.fileExists(atPath: d.file("out").path),
                "destination must stay absent — publish is gated on full-stream auth")
        #expect(d.tempArtifacts().isEmpty, "the staged partial temp must be removed on the failed publish")
    }

    @Test("two concurrent decrypts to the same destination: exactly one success, one destinationExists, no corrupt output")
    func concurrentSameDestinationRace() async throws {
        let d = SafeDir(); defer { d.cleanup() }
        let plainA = Data(repeating: 0xAA, count: 2 * ContainerCodec.defaultChunkLen)
        let plainB = Data(repeating: 0xBB, count: 2 * ContainerCodec.defaultChunkLen)
        try plainA.write(to: d.file("a")); try plainB.write(to: d.file("b"))
        _ = try await PKCryptEngine.encrypt(fileURL: d.file("a"), recipient: Fixtures.publicKey,
                                            destinationURL: d.file("a.pkcrypt")).get()
        _ = try await PKCryptEngine.encrypt(fileURL: d.file("b"), recipient: Fixtures.publicKey,
                                            destinationURL: d.file("b.pkcrypt")).get()

        let dest = d.file("out")
        let results = await withTaskGroup(of: EngineResult<URL>.self) { group -> [EngineResult<URL>] in
            group.addTask {
                await PKCryptEngine.decrypt(containerURL: d.file("a.pkcrypt"),
                                            privateKey: Fixtures.privateKey, destinationURL: dest)
            }
            group.addTask {
                await PKCryptEngine.decrypt(containerURL: d.file("b.pkcrypt"),
                                            privateKey: Fixtures.privateKey, destinationURL: dest)
            }
            var out: [EngineResult<URL>] = []
            for await r in group { out.append(r) }
            return out
        }
        let successes = results.filter { if case .success = $0 { true } else { false } }.count
        let destExists = results.filter { if case .failure(.destinationExists) = $0 { true } else { false } }.count
        #expect(successes == 1, "exactly one concurrent publish may win (renamex_np RENAME_EXCL atomically)")
        #expect(destExists == 1, "the loser must surface .destinationExists, never an overwrite")
        #expect(results.allSatisfy {
            if case .success = $0 { true } else if case .failure(.destinationExists) = $0 { true } else { false }
        }, "every outcome must be success or destinationExists")

        // The published destination is exactly ONE complete, uncorrupted plaintext.
        let out = try Data(contentsOf: dest)
        #expect(out == plainA || out == plainB, "the winner's output must be complete and never interleaved")
        #expect(d.tempArtifacts().isEmpty, "neither the winner nor the loser may leave a staging temp")
    }

    @Test("after any failed run the destination directory contains no leftover .tmp files (D-08)")
    func noLeftoverTempAfterFailures() async throws {
        let d = SafeDir(); defer { d.cleanup() }
        let input = d.file("in")
        try pattern(ContainerCodec.defaultChunkLen + 100).write(to: input)
        _ = try await PKCryptEngine.encrypt(fileURL: input, recipient: Fixtures.publicKey,
                                            destinationURL: d.file("good.pkcrypt")).get()
        var tampered = try Data(contentsOf: d.file("good.pkcrypt"))
        tampered[tampered.count - 1] ^= 0xFF     // corrupt the final tag
        try tampered.write(to: d.file("bad.pkcrypt"))

        // (a) Collision: decrypt to a destination that already exists -> destinationExists.
        let occupied = d.file("occupied")
        try Data("occupied".utf8).write(to: occupied)
        _ = await PKCryptEngine.decrypt(containerURL: d.file("good.pkcrypt"),
                                        privateKey: Fixtures.privateKey, destinationURL: occupied)
        // (b) Auth failure (tampered final tag).
        _ = await PKCryptEngine.decrypt(containerURL: d.file("bad.pkcrypt"),
                                        privateKey: Fixtures.privateKey, destinationURL: d.file("out"))
        // (c) Cancellation.
        let t: Task<EngineResult<URL>, Never> = Task {
            await PKCryptEngine.decrypt(containerURL: d.file("good.pkcrypt"),
                                        privateKey: Fixtures.privateKey, destinationURL: d.file("cancelled"))
        }
        t.cancel()
        _ = await t.value

        // After every failed run: zero stale .tmp artifacts remain (D-08).
        #expect(d.tempArtifacts().isEmpty, "no failed run may leave a stale .tmp")
        #expect(d.contains("occupied"), "a pre-existing destination is never touched")
    }
}

// MARK: - Concurrency helpers (thread-safe, @unchecked Sendable for cross-closure capture)

/// Lets a test cancel its own operation from inside the engine's progress callback.
final class CancelBox: @unchecked Sendable {
    private let lock = NSLock()
    private var task: Task<EngineResult<URL>, Never>?
    func set(_ t: Task<EngineResult<URL>, Never>) { lock.lock(); task = t; lock.unlock() }
    func cancel() { lock.lock(); let t = task; lock.unlock(); t?.cancel() }
}

/// Records progress samples safely across the @Sendable progress callback.
final class ProgressBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _samples: [EngineProgress] = []
    var samples: [EngineProgress] { lock.lock(); defer { lock.unlock() }; return _samples }
    func record(_ p: EngineProgress) { lock.lock(); _samples.append(p); lock.unlock() }
}
