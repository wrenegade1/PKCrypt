import Foundation

// MARK: - Shared oracle-shell plumbing (test-time only, D-04)
//
// The Python and C++ oracles are TEST-TIME dependencies consumed by the differential
// interop matrix (COMP-03). The production PKCryptEngine library target has ZERO
// dependency on these files or on the oracle repo (asserted by a grep of Package.swift).

/// Result of invoking an oracle CLI / library snippet.
///
/// `unavailable(reason)` is the explicit record for a cell a CLI genuinely cannot
/// exercise (e.g. neither CLI exposes a cipher-select flag for XChaCha writes) or
/// when an oracle cannot be located. COMP-03 forbids counting an UNAVAILABLE cell as
/// a PASS and forbids silently skipping it — the matrix records these explicitly.
enum OracleOutcome: Equatable {
    /// The oracle ran and exited 0; `outputURL` is where its output artifact landed.
    case success(outputURL: URL?)
    /// The oracle ran but exited non-zero (a real interop failure — never UNAVAILABLE).
    case failure(exitCode: Int32, detail: String)
    /// The oracle genuinely cannot exercise this cell. NEVER a pass, NEVER a silent skip.
    case unavailable(String)
}

/// Minimal subprocess helper shared by both oracle wrappers.
enum OracleShell {
    static func run(executable: URL, arguments: [String],
                    env: [String: String]) -> (code: Int32, output: String) {
        let p = Process()
        p.executableURL = executable
        p.arguments = arguments
        var e = ProcessInfo.processInfo.environment
        for (k, v) in env { e[k] = v }
        p.environment = e
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (-999, "launch failed: \(error)") }
        p.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}

/// Resolve the PKCrypt oracle repo root — the test-time git submodule / dev checkout
/// (D-04). Resolution order:
///   1. `PKCRYPT_ORACLE_REPO` environment variable;
///   2. `PKCryptEngine/oracle-repo/` (the D-04 submodule / documented dev checkout);
///   3. the sibling repo root derived from this source file (single-repo layout).
/// The production library never calls this — tests only.
enum OracleRepo {
    static func resolve() -> URL? {
        if let env = ProcessInfo.processInfo.environment["PKCRYPT_ORACLE_REPO"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        // .../PKCryptEngine/Tests/PKCryptEngineTests/Oracles/PythonOracle.swift
        let engineRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // Oracles
            .deletingLastPathComponent()   // PKCryptEngineTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // PKCryptEngine
        // oracle-repo submodule / documented dev checkout
        let sub = engineRoot.appendingPathComponent("oracle-repo")
        if FileManager.default.fileExists(atPath: sub.appendingPathComponent("pkcrypt_lib/core.py").path) {
            return sub
        }
        // sibling repo root (this PKCrypt repo)
        let root = engineRoot.deletingLastPathComponent()
        if FileManager.default.fileExists(atPath: root.appendingPathComponent("pkcrypt_lib/core.py").path) {
            return root
        }
        return nil
    }
}

// MARK: - PythonOracle

/// Wraps `python3 -m pkcrypt_lib` (the Python reference oracle) for the COMP-03
/// differential matrix. Also exposes the Python LIBRARY API for XChaCha20 fixture
/// generation (cipher 0x01), which the CLI cannot write (no cipher-select flag).
enum PythonOracle {
    /// Root whose `pkcrypt_lib` package is importable (or nil if unavailable).
    static var root: URL? { OracleRepo.resolve() }
    static var isAvailable: Bool { root != nil }

    private static var pythonPath: [String: String] {
        guard let root else { return [:] }
        return ["PYTHONPATH": root.path]
    }

    /// Run an arbitrary python `-c` snippet with the oracle repo on PYTHONPATH.
    static func runSnippet(_ script: String, _ args: [String]) -> OracleOutcome {
        guard let _ = root else { return .unavailable("oracle repo not found (set PKCRYPT_ORACLE_REPO or populate oracle-repo/)") }
        let (code, out) = OracleShell.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                                          arguments: ["-c", script] + args, env: pythonPath)
        if code == 0 { return .success(outputURL: nil) }
        return .failure(exitCode: code, detail: out)
    }

    /// Invoke the Python CLI (`python3 -m pkcrypt_lib ...`). Handles both Ed25519 and
    /// RSA automatically (the CLI dispatches on the key type in the containers).
    static func cli(_ args: [String], output: URL? = nil) -> OracleOutcome {
        guard let root else { return .unavailable("oracle repo not found (set PKCRYPT_ORACLE_REPO or populate oracle-repo/)") }
        let (code, out) = OracleShell.run(executable: URL(fileURLWithPath: "/usr/bin/python3"),
                                          arguments: ["-m", "pkcrypt_lib"] + args,
                                          env: ["PYTHONPATH": root.path])
        if code == 0 { return .success(outputURL: output) }
        return .failure(exitCode: code, detail: out)
    }

    /// Oracle decrypts `container` with `privKey` to `output`. Returns `.success(outputURL: output)` on exit 0.
    static func decrypt(privKey: URL, container: URL, output: URL) -> OracleOutcome {
        cli(["decrypt", privKey.path, container.path, output.path], output: output)
    }

    /// Oracle encrypts `input` for `pubKey` to `output`.
    static func encrypt(pubKey: URL, input: URL, output: URL) -> OracleOutcome {
        cli(["encrypt", pubKey.path, input.path, output.path], output: output)
    }

    /// Generate an XChaCha20 (cipher 0x01) container via the Python LIBRARY API —
    /// the ONLY way to produce cipher-0x01 containers (neither CLI exposes a
    /// cipher-select flag). Used for the XChaCha-READ matrix cells (COMP-01/COMP-03).
    static func libraryEncryptXChaCha(pubKey: URL, plaintextSize: Int, rsa: Bool, output: URL) -> OracleOutcome {
        let script = """
        import sys, hashlib
        from pkcrypt_lib import keys, core
        mode, pubpath, n_s, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
        n = int(n_s)
        pub = keys.load_public_key(pubpath)
        pt = bytes((i * 7 + 3) & 0xFF for i in range(n))
        if mode == 'ed':
            ed = pub.key.public_bytes_raw()
            ct = core.encrypt_bytes(pt, ed, cipher=0x01)
        else:
            ct = core.encrypt_bytes_rsa(pt, pub.key, cipher=0x01)
        open(out, 'wb').write(ct)
        print(hashlib.sha256(pt).hexdigest())
        """
        let mode = rsa ? "rsa" : "ed"
        let outcome = runSnippet(script, [mode, pubKey.path, "\(plaintextSize)", output.path])
        switch outcome {
        case .success: return .success(outputURL: output)
        default: return outcome
        }
    }
}
