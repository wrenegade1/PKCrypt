// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Foundation

/// Throwaway test keys and oracle containers, generated once per test run so
/// that no key material is ever committed. The layout (key names, container
/// names, plaintext pattern) is what the committed fixtures used to provide;
/// see PKCryptEngine/Scripts/make_test_fixtures.py.
///
/// Keys come from ssh-keygen and containers from this repository's Python
/// implementation, so decrypting them still proves cross-implementation
/// compatibility. Override the interpreter with PKCRYPT_PYTHON.
enum GeneratedFixtures {
    /// This repository's root (…/Tests/PKCryptEngineTests/<file> → up four).
    static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()   // PKCryptEngineTests
        .deletingLastPathComponent()   // Tests
        .deletingLastPathComponent()   // PKCryptEngine
        .deletingLastPathComponent()   // repo root

    /// A fresh directory holding the generated fixtures (created on first use;
    /// `static let` initialisation is thread-safe, so parallel tests share it).
    static let dir: URL = {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pkcrypt-fixtures-\(UUID().uuidString)")
        let env = ProcessInfo.processInfo.environment
        let p = Process()
        p.executableURL = URL(fileURLWithPath: env["PKCRYPT_PYTHON"] ?? "/usr/bin/python3")
        p.arguments = [repoRoot.appendingPathComponent("PKCryptEngine/Scripts/make_test_fixtures.py").path,
                       dir.path]
        var childEnv = env
        childEnv["PYTHONPATH"] = repoRoot.path
        p.environment = childEnv
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { fatalError("cannot run the test fixture generator: \(error)") }
        let output = pipe.fileHandleForReading.readDataToEndOfFile()   // drain before waiting
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            fatalError("test fixture generator failed:\n" + String(decoding: output, as: UTF8.self))
        }
        return dir
    }()
}
