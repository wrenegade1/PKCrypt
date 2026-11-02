import Foundation
import Darwin

/// Stages plaintext in an exclusively-created (O_EXCL) 0600 temporary file in the
/// destination's OWN directory, then atomically publishes it with
/// `renamex_np(RENAME_EXCL)` — a kernel-enforced no-replace rename (D-06/D-07/D-10).
/// Plaintext is never written to the real destination before the whole stream
/// authenticates (SAFE-02 / T-02-02).
///
/// This is the tracer's minimal working publish; the full mechanism/error-handling
/// and collision/cancellation coverage is finalized in Plan 03.
public final class SafeOutputPublisher {
    public let destinationURL: URL
    private var tempURL: URL?

    public init(destinationURL: URL) {
        self.destinationURL = destinationURL
    }

    /// Create the private 0600 temp file via `open(O_WRONLY|O_CREAT|O_EXCL, 0o600)`
    /// — mode 0600 baked into creation, never chmod-after-exposure (D-07/Pitfall 6).
    /// Returns a handle for writing the staged plaintext.
    public func start() throws -> FileHandle {
        let destDir = destinationURL.deletingLastPathComponent().path
        let base = destinationURL.lastPathComponent
        let tmpName = ".\(base).\(UUID().uuidString).tmp"
        let tmpPath = destDir + "/" + tmpName
        let fd = open(tmpPath, O_WRONLY | O_CREAT | O_EXCL, mode_t(0o600))
        guard fd >= 0 else {
            throw EngineError.permissionError("could not create output file (errno \(errno))")
        }
        tempURL = URL(fileURLWithPath: tmpPath)
        return FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }

    /// Publish: flush + fsync, close, then `renamex_np(tmp, dest, RENAME_EXCL)`.
    /// `EEXIST` -> `EngineError.destinationExists` (D-10); no overwrite ever.
    public func publish(fh: FileHandle) throws {
        guard let tmp = tempURL else { throw EngineError.ioError("no staged temp file") }
        do { try fh.synchronize() } catch {
            fh.closeFile(); cleanup(); throw EngineError.ioError("fsync failed")
        }
        fh.closeFile()
        let RENAME_EXCL: UInt32 = 0x0004
        guard renamex_np(tmp.path, destinationURL.path, RENAME_EXCL) == 0 else {
            let e = errno
            cleanup()
            if e == EEXIST { throw EngineError.destinationExists }
            throw EngineError.ioError("rename failed (errno \(e))")
        }
        tempURL = nil
    }

    /// Discard the staged temp file (nothing published) — D-08 cleanup of the
    /// engine's own tracked temp only.
    public func abort() { cleanup() }

    private func cleanup() {
        if let tmp = tempURL {
            try? FileManager.default.removeItem(at: tmp)
        }
        tempURL = nil
    }
}

// MARK: - Output filename derivation (D-09, WITHOUT D-10 auto-numbering)

extension SafeOutputPublisher {
    /// D-09: the default encrypted output path is `<input>.pkcrypt`.
    /// Mirrors `files.py` `encrypted_output_path` (strip any trailing `/`,
    /// then append `.pkcrypt`). No collision handling here: if that name is
    /// taken at publication time, `renamex_np(RENAME_EXCL)` returns EEXIST and
    /// the caller receives `EngineError.destinationExists` (D-10) — never a
    /// silent `.1`/`.2` fallback.
    public static func encryptedOutputPath(for input: URL) -> URL {
        let path = input.path.hasSuffix("/") ? String(input.path.dropLast()) : input.path
        return URL(fileURLWithPath: path + ".pkcrypt")
    }

    /// D-09: the default decrypted output path strips a trailing `.pkcrypt`
    /// else appends `.decrypted` — the CLI's *candidate-name* rule. Critically,
    /// it does NOT reproduce `files.py` `unused_path()`'s numeric-suffix retry
    /// (D-10): the plain stem is returned even if it already exists, and a real
    /// collision surfaces as `EngineError.destinationExists` from the publisher
    /// so the app can prompt the user for a new name.
    public static func decryptedOutputPath(for input: URL) -> URL {
        let path = input.path
        if (path as NSString).lastPathComponent.hasSuffix(".pkcrypt") {
            let stripped = String(path.dropLast(".pkcrypt".count))
            if !(stripped as NSString).lastPathComponent.isEmpty {
                return URL(fileURLWithPath: stripped)
            }
        }
        return URL(fileURLWithPath: path + ".decrypted")
    }
}
