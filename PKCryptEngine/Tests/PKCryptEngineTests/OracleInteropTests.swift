import Testing
import Foundation
import CryptoKit
@testable import PKCryptEngine

/// Differential interop vs the Python PKCrypt oracle (D-04/D-05): the *same*
/// Ed25519 keypair and container format this repo's `pkcrypt_lib` produces.
///
/// This suite shells out to the Python oracle via `python3 -m pkcrypt_lib`
/// (test-time only — the production library has zero dependency on it, D-04).
/// The oracle repo may be a git submobule checkout (`PKCryptEngine/oracle-repo/`
/// per D-04, formalized in Plan 02-04) or a dev checkout; locate it via
/// `PKCRYPT_ORACLE_REPO` or the sibling repo root derived from #filePath.
@Suite("Oracle differential interop")
struct OracleInteropTests {

    static let oracleRepo: URL? = {
        if let env = ProcessInfo.processInfo.environment["PKCRYPT_ORACLE_REPO"], !env.isEmpty {
            return URL(fileURLWithPath: env)
        }
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // .../PKCryptEngineTests
            .deletingLastPathComponent()   // .../Tests
            .deletingLastPathComponent()   // .../PKCryptEngine
            .deletingLastPathComponent()   // repo root (this PKCrypt repo)
        let core = root.appendingPathComponent("pkcrypt_lib/core.py")
        return FileManager.default.fileExists(atPath: core.path) ? root : nil
    }()

    static let keysDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("Fixtures")
    static let privKey = keysDir.appendingPathComponent("ed25519_fixture")
    static let pubKey = keysDir.appendingPathComponent("ed25519_fixture.pub")

    static let privateKeyMaterial: PrivateKeyMaterial = {
        try! KeyMaterial.parseEd25519Private(Data(contentsOf: privKey))
    }()
    static let publicKeyMaterial: PublicKeyMaterial = {
        try! KeyMaterial.parseEd25519Public(Data(contentsOf: pubKey))
    }()

    /// sha256 of the deterministic plaintext pattern (mirrors the python generator).
    static func patternSHA256(_ n: Int) -> String {
        Data((0 ..< n).map { UInt8(($0 * 7 + 3) & 0xFF) }).SHA256Hex
    }

    /// Run python3 with `script` and the given args; returns (exitStatus, stdout).
    static func runPython(_ script: String, _ args: [String]) -> (Int32, String) {
        guard let repo = oracleRepo else {
            return (-1, "oracle repo not found")
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        p.arguments = ["-c", script] + args
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = repo.path
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return (-2, "python launch failed: \(error)") }
        p.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }

    static let pythonScript = """
    import sys, hashlib
    from pkcrypt_lib import keys, core
    mode = sys.argv[1]
    if mode == 'decrypt':
        container, privpath = sys.argv[2], sys.argv[3]
        data = open(container, 'rb').read()
        k = keys.load_private_key(privpath)
        ed = k.key.public_key().public_bytes_raw()
        seed = k.key.private_bytes_raw()
        pt = core.decrypt_bytes(data, seed, ed)
        print(hashlib.sha256(pt).hexdigest())
    elif mode == 'encrypt':
        pubpath, n_s, out = sys.argv[2], sys.argv[3], sys.argv[4]
        n = int(n_s)
        pub = keys.load_public_key(pubpath)
        ed = pub.key.public_bytes_raw()
        pt = bytes((i*7+3)&0xFF for i in range(n))
        ct = core.encrypt_bytes(pt, ed)
        open(out, 'wb').write(ct)
        print(hashlib.sha256(pt).hexdigest())
    else:
        sys.exit(2)
    """

    @Test("Swift encrypts -> Python oracle decrypts to the same bytes", arguments: [0, 1 << 20, (1 << 20) + 1])
    func swiftToOracle(size: Int) throws {
        let scratch = Scratch()
        defer { scratch.cleanup() }
        let input = scratch.dir.appendingPathComponent("in")
        try pattern(size).write(to: input)
        _ = try PKCryptEngine.encrypt(fileURL: input,
                                      recipient: Self.publicKeyMaterial,
                                      destinationURL: scratch.container).get()
        let (rc, out) = Self.runPython(Self.pythonScript, ["decrypt", scratch.container.path, Self.privKey.path])
        #expect(rc == 0, "oracle decrypt failed: \(out)")
        // oracle decrypts Swift's container; sha256 must equal our pattern's sha256.
        #expect(out.trimmingCharacters(in: .whitespacesAndNewlines) == Self.patternSHA256(size))
    }

    @Test("Python oracle encrypts -> Swift decrypts to the same bytes", arguments: [0, 1 << 20, (1 << 20) + 1])
    func oracleToSwift(size: Int) throws {
        let scratch = Scratch()
        defer { scratch.cleanup() }
        let (rc, out) = Self.runPython(Self.pythonScript, ["encrypt", Self.pubKey.path, "\(size)", scratch.container.path])
        #expect(rc == 0, "oracle encrypt failed: \(out)")
        let recovered = try PKCryptEngine.decrypt(containerURL: scratch.container,
                                                  privateKey: Self.privateKeyMaterial,
                                                  destinationURL: scratch.output).get()
        #expect(recovered == scratch.output)
        #expect(try Data(contentsOf: scratch.output) == pattern(size))
    }
}

extension Data {
    var SHA256Hex: String {
        CryptoKit.SHA256.hash(data: self).map { String(format: "%02x", $0) }.joined()
    }
}
