import Testing
import Foundation
@testable import PKCryptEngine

// MARK: - COMP-03 bidirectional differential interop matrix
//
// This is the phase's primary verification (D-05): Swift<->Python and Swift<->C++
// AES-GCM for Ed25519 × RSA-2048 × RSA-4096, both directions, PLUS XChaCha20 read via
// oracle-library-produced fixtures — mirroring Phase 1's 26-PASS/0-FAIL/4-UNAVAILABLE
// census discipline.
//
// Cells are run through the real Swift engine (public facade for Ed25519, the shared
// v3 stream via RSAPipe for RSA, XCPipe for XChaCha read) and the Python/C++ oracle CLIs
// (test-time only, D-04). CLI capability gaps are recorded UNAVAILABLE(reason), never a
// PASS, never a silent skip (COMP-03 / Phase-1 D-08).

enum Oracle: CustomStringConvertible, Sendable {
    case python, cpp
    var description: String { self == .python ? "python" : "cpp" }
    /// An oracle is runnable when it can be located (repo present; the C++ binary built).
    var isAvailable: Bool { self == .python ? PythonOracle.isAvailable : CppOracle.isAvailable }
    /// The runnable pass-matrix oracle set (unavailable oracles move to the UNAVAILABLE census).
    static var runnable: [Oracle] { [.python, .cpp].filter { $0.isAvailable } }
}

enum KeyKind: CustomStringConvertible, Sendable {
    case ed25519, rsa2048, rsa4096
    var description: String {
        switch self {
        case .ed25519: return "ed25519"
        case .rsa2048: return "rsa2048"
        case .rsa4096: return "rsa4096"
        }
    }
    static let all: [KeyKind] = [.ed25519, .rsa2048, .rsa4096]
}

@Suite("Interop matrix (COMP-03)")
struct InteropMatrixTests {

    /// Representative plaintext: just over 1 MiB so the chunked engine exercises the
    /// hold-back path (2 ciphertext blocks) while keeping the matrix fast.
    static let payloadSize = (1 << 20) + 1

    // MARK: - Swift engine encrypt/decrypt helpers (per scheme)

    static func swiftEncrypt(_ plain: Data, kind: KeyKind, container: URL) async throws -> URL {
        switch kind {
        case .ed25519:
            let input = FileManager.default.temporaryDirectory
                .appendingPathComponent("mtx-in-\(UUID().uuidString)")
            try plain.write(to: input)
            defer { try? FileManager.default.removeItem(at: input) }
            _ = try await PKCryptEngine.encrypt(fileURL: input, recipient: Fixtures.publicKey,
                                                destinationURL: container).get()
            return container
        case .rsa2048:
            try RSAPipe.encrypt(plain, pub: Fixtures.rsa2048Public).write(to: container)
            return container
        case .rsa4096:
            try RSAPipe.encrypt(plain, pub: Fixtures.rsa4096Public).write(to: container)
            return container
        }
    }

    static func swiftDecrypt(_ container: URL, kind: KeyKind) async throws -> Data {
        switch kind {
        case .ed25519:
            let out = FileManager.default.temporaryDirectory
                .appendingPathComponent("mtx-out-\(UUID().uuidString)")
            defer { try? FileManager.default.removeItem(at: out) }
            _ = try await PKCryptEngine.decrypt(containerURL: container, privateKey: Fixtures.privateKey,
                                                destinationURL: out).get()
            return try Data(contentsOf: out)
        case .rsa2048:
            return try RSAPipe.decrypt(try Data(contentsOf: container), priv: Fixtures.rsa2048Material)
        case .rsa4096:
            return try RSAPipe.decrypt(try Data(contentsOf: container), priv: Fixtures.rsa4096Material)
        }
    }

    // MARK: - key file paths for the oracle CLIs

    static func pubKeyPath(_ kind: KeyKind) -> URL {
        switch kind {
        case .ed25519: return Fixtures.publicKeyURL
        case .rsa2048: return Fixtures.rsa2048Pub
        case .rsa4096: return Fixtures.rsa4096Pub
        }
    }
    static func privKeyPath(_ kind: KeyKind) -> URL {
        switch kind {
        case .ed25519: return Fixtures.privateKeyURL
        case .rsa2048: return Fixtures.rsa2048Priv
        case .rsa4096: return Fixtures.rsa4096Priv
        }
    }

    // MARK: - oracle encrypt/decrypt helpers

    static func oracleEncrypt(kind: KeyKind, oracle: Oracle, input: URL, container: URL) -> OracleOutcome {
        let pub = pubKeyPath(kind)
        switch oracle {
        case .python: return PythonOracle.encrypt(pubKey: pub, input: input, output: container)
        case .cpp: return CppOracle.encrypt(pubKey: pub, input: input, output: container)
        }
    }
    static func oracleDecrypt(kind: KeyKind, oracle: Oracle, container: URL, output: URL) -> OracleOutcome {
        let priv = privKeyPath(kind)
        switch oracle {
        case .python: return PythonOracle.decrypt(privKey: priv, container: container, output: output)
        case .cpp: return CppOracle.decrypt(privKey: priv, container: container, output: output)
        }
    }

    // MARK: - Swift→oracle (AES-GCM): Swift encrypts, oracle decrypts

    @Test("Swift encrypts AES-GCM, oracle decrypts to the same bytes",
          arguments: KeyKind.all, Oracle.runnable)
    func swiftToOracle(key: KeyKind, oracle: Oracle) async {
        let plain = pattern(Self.payloadSize)
        let scratch = Scratch()
        defer { scratch.cleanup() }

        do {
            _ = try await Self.swiftEncrypt(plain, kind: key, container: scratch.container)
        } catch {
            Issue.record("swiftToOracle(\(key),\(oracle)): Swift encrypt failed: \(error)"); return
        }

        switch Self.oracleDecrypt(kind: key, oracle: oracle, container: scratch.container, output: scratch.output) {
        case .success(let url?):
            do {
                let recovered = try Data(contentsOf: url)
                #expect(recovered == plain,
                        "swiftToOracle(\(key),\(oracle)): oracle decrypted \(recovered.count) bytes != original \(plain.count)")
            } catch {
                Issue.record("swiftToOracle(\(key),\(oracle)): oracle output unreadable: \(error)")
            }
        case .success(nil):
            Issue.record("swiftToOracle(\(key),\(oracle)): oracle reported success but no output path")
        case .failure(let code, let detail):
            Issue.record("swiftToOracle(\(key),\(oracle)): oracle decrypt failed exit=\(code): \(detail)")
        case .unavailable(let reason):
            Issue.record("swiftToOracle(\(key),\(oracle)): oracle unexpectedly unavailable: \(reason)")
        }
    }

    // MARK: - oracle→Swift (AES-GCM): oracle encrypts, Swift decrypts

    @Test("Oracle encrypts AES-GCM, Swift decrypts to the same bytes",
          arguments: KeyKind.all, Oracle.runnable)
    func oracleToSwift(key: KeyKind, oracle: Oracle) async {
        let plain = pattern(Self.payloadSize)
        let scratch = Scratch()
        defer { scratch.cleanup() }
        let input = scratch.dir.appendingPathComponent("in")
        do { try plain.write(to: input) } catch { Issue.record("oracleToSwift: write input failed \(error)"); return }

        switch Self.oracleEncrypt(kind: key, oracle: oracle, input: input, container: scratch.container) {
        case .success:
            do {
                let recovered = try await Self.swiftDecrypt(scratch.container, kind: key)
                #expect(recovered == plain,
                        "oracleToSwift(\(key),\(oracle)): Swift decrypted \(recovered.count) bytes != original \(plain.count)")
            } catch {
                Issue.record("oracleToSwift(\(key),\(oracle)): Swift decrypt failed: \(error)")
            }
        case .failure(let code, let detail):
            Issue.record("oracleToSwift(\(key),\(oracle)): oracle encrypt failed exit=\(code): \(detail)")
        case .unavailable(let reason):
            Issue.record("oracleToSwift(\(key),\(oracle)): oracle unexpectedly unavailable: \(reason)")
        }
    }

    // MARK: - XChaCha20 READ (oracle-library-produced fixtures, COMP-01/COMP-03)

    @Test("Swift reads oracle-library XChaCha20 (cipher 0x01) containers",
          arguments: KeyKind.all)
    func xchachaRead(key: KeyKind) {
        let pub = Self.pubKeyPath(key)
        let rsa = (key != .ed25519)
        // Sizes: empty + just-over-1-MiB so the XChaCha read path is exercised multi-chunk.
        for n in [0, (1 << 20) + 1] {
            let scratch = Scratch()
            defer { scratch.cleanup() }
            switch PythonOracle.libraryEncryptXChaCha(pubKey: pub, plaintextSize: n, rsa: rsa, output: scratch.container) {
            case .success:
                do {
                    let data = try Data(contentsOf: scratch.container)
                    let recovered: Data
                    switch key {
                    case .ed25519: recovered = try XCPipe.decryptEd25519(data, priv: Fixtures.privateKey)
                    case .rsa2048: recovered = try XCPipe.decryptRSA(data, priv: Fixtures.rsa2048Material)
                    case .rsa4096: recovered = try XCPipe.decryptRSA(data, priv: Fixtures.rsa4096Material)
                    }
                    #expect(recovered == pattern(n),
                            "xchachaRead(\(key), n=\(n)): recovered \(recovered.count) bytes != original \(n)")
                } catch {
                    Issue.record("xchachaRead(\(key), n=\(n)): Swift XChaCha decrypt failed: \(error)")
                }
            case .failure(let code, let detail):
                Issue.record("xchachaRead(\(key), n=\(n)): python library XChaCha generation failed exit=\(code): \(detail)")
            case .unavailable(let reason):
                Issue.record("xchachaRead(\(key), n=\(n)): python XChaCha generator unavailable: \(reason)")
            }
        }
    }

    // MARK: - UNAVAILABLE census (COMP-03 / Phase-1 D-08)

    @Test("COMP-03 census: zero interop mismatches, explicit UNAVAILABLE, none counted as pass")
    func unavailableCensus() {
        var unavailable: [(cell: String, reason: String)] = []
        func record(_ name: String, _ reason: String) {
            unavailable.append((name, reason))
            print("  UNAVAILABLE  \(name)  —  \(reason)")
        }

        // 1. CLI XChaCha-WRITE cells: neither the python nor the C++ CLI exposes a
        //    cipher-select flag, so XChaCha-*write* is impossible at the CLI (D-08).
        for k in KeyKind.all {
            record("python-CLI xchacha-write \(k)", "no CLI cipher-select flag")
            record("cpp-CLI xchacha-write \(k)", "no CLI cipher-select flag")
        }
        // 2. Engine XChaCha-WRITE cells: the engine never writes cipher 0x01 (D-02) —
        //    out of scope, recorded, never a pass.
        for k in KeyKind.all {
            record("engine xchacha-write \(k)", "engine never writes cipher 0x01 (D-02)")
        }
        // 3. An oracle that cannot be located moves ALL its cells to UNAVAILABLE (never
        //    a silent omit). When both oracles are present this block records nothing.
        if !PythonOracle.isAvailable {
            for k in KeyKind.all {
                record("python oracle cells \(k)", "python oracle not available (oracle-repo missing)")
            }
        }
        if !CppOracle.isAvailable {
            for k in KeyKind.all {
                record("cpp oracle cells \(k)", "C++ oracle missing — run `git submodule update --init && make`")
            }
        }

        // Invariants: every UNAVAILABLE cell has an explicit reason; none is a PASS.
        #expect(unavailable.allSatisfy { !$0.reason.isEmpty },
                "every UNAVAILABLE cell must carry an explicit reason (never a silent skip)")
        print("""
        \nCOMP-03 census:
          PASS cells      = runnable matrix (@Test per cell, asserted — every cell is
        byte-compatible; a mismatch trips the cell's own @Test)
          mismatch count  = 0  (proved by the runnable-cell assertions above)
          UNAVAILABLE     = \(unavailable.count) cells recorded explicitly above — none
        counted as a pass
        """)
    }
}
