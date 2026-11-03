// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Foundation

// MARK: - CppOracle
//
// Wraps the compiled C++ reference CLI (`./pkcrypt`) for the COMP-03 differential
// matrix. Mirrors tests/test_cpp_interop.py's explicit binary-existence guard:
// if the binary is absent the oracle is recorded `unavailable(reason)` — never a
// crash, never a silent skip, never a PASS (D-04 / COMP-03).
//
// The C++ CLI exposes NO cipher-select flag, so XChaCha-write cells are recorded
// UNAVAILABLE (Phase 1 D-08) — the matrix never presents them as a pass.

enum CppOracle {
    /// Root containing the `pkcrypt` binary (the oracle repo root).
    static var root: URL? { OracleRepo.resolve() }
    static var bin: URL? { root?.appendingPathComponent("pkcrypt") }

    /// Available only when the binary actually exists on disk.
    static var isAvailable: Bool {
        guard let bin else { return false }
        return FileManager.default.isExecutableFile(atPath: bin.path)
    }

    private static func guardBinary() -> OracleOutcome? {
        guard let bin, isAvailable else {
            return .unavailable("C++ oracle binary ./pkcrypt not found — run `git submodule update --init && make` in the oracle repo, or set PKCRYPT_ORACLE_REPO")
        }
        return nil
    }

    /// Invoke `./pkcrypt ...`. Handles both Ed25519 and RSA automatically.
    static func run(_ args: [String], output: URL? = nil) -> OracleOutcome {
        if let blocked = guardBinary() { return blocked }
        let (code, out) = OracleShell.run(executable: bin!.standardizedFileURL,
                                          arguments: args, env: [:])
        if code == 0 { return .success(outputURL: output) }
        return .failure(exitCode: code, detail: out)
    }

    /// C++ oracle decrypts `container` with `privKey` to `output`.
    static func decrypt(privKey: URL, container: URL, output: URL) -> OracleOutcome {
        run(["decrypt", privKey.path, container.path, output.path], output: output)
    }

    /// C++ oracle encrypts `input` for `pubKey` to `output`.
    static func encrypt(pubKey: URL, input: URL, output: URL) -> OracleOutcome {
        run(["encrypt", pubKey.path, input.path, output.path], output: output)
    }
}
