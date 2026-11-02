import Testing
import Foundation
import CryptoKit
import CSodium
@testable import PKCryptEngine

// MARK: - Test helpers

extension Data {
    init?(hex: String) {
        var out = [UInt8]()
        var s = hex
        while s.count >= 2 {
            let end = s.index(s.startIndex, offsetBy: 2)
            guard let b = UInt8(s[s.startIndex ..< end], radix: 16) else { return nil }
            out.append(b)
            s = String(s[end...])
        }
        guard s.isEmpty else { return nil }
        self.init(out)
    }
    var hexString: String { map { String(format: "%02x", $0) }.joined() }
}

/// Deterministic plaintext generator — byte-identical to the fixture generator
/// used to produce the oracle containers (pattern `(i*7+3) & 0xFF`).
func pattern(_ n: Int) -> Data {
    Data((0 ..< n).map { UInt8(($0 * 7 + 3) & 0xFF) })
}

/// Suite-level test resources: the committed keypair + fixture directory.
struct Fixtures {
    static let dir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("Fixtures")
    static let privateKeyURL = dir.appendingPathComponent("ed25519_fixture")
    static let publicKeyURL = dir.appendingPathComponent("ed25519_fixture.pub")
    static let containersDir = dir.appendingPathComponent("Containers")

    static func container(_ name: String) -> Data {
        try! Data(contentsOf: containersDir.appendingPathComponent("\(name).pkcrypt"))
    }
    static let privateKey: PrivateKeyMaterial = {
        try! KeyMaterial.parseEd25519Private(Data(contentsOf: privateKeyURL))
    }()
    static let publicKey: PublicKeyMaterial = {
        try! KeyMaterial.parseEd25519Public(Data(contentsOf: publicKeyURL))
    }()
}

/// A unique scratch destination directory per test.
struct Scratch {
    let dir: URL
    init() {
        dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pkcrypt-test-\(UUID().uuidString)")
        try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }
    var container: URL { dir.appendingPathComponent("out.pkcrypt") }
    var output: URL { dir.appendingPathComponent("out") }
    func cleanup() { try? FileManager.default.removeItem(at: dir) }
}

// MARK: - Format vectors (deterministic byte-exactness)

@Suite("FormatVectorTests")
struct FormatVectorTests {

    // MARK: header byte vector

    @Test("header bytes are byte-exact to the v2 layout")
    func headerByteVector() throws {
        let eph = Data((1 ... 32).map { UInt8($0) })          // 0x01..0x20
        let nonce = Data((0x21 ... 0x2c).map { UInt8($0) })   // 0x21..0x2c (12 bytes)
        let header = try V2Header(cipher: 0x00, payloadType: 0x00,
                                  ephemeralPublicKey: eph, baseNonce: nonce,
                                  chunkLen: 1 << 20).bytes
        let expected = Data(hex: "504b43525950540200000102030405060708090a0b0c0d0e0f"
                                + "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c00100000")!
        #expect(header.count == 58)
        #expect(header == expected)
    }

    // MARK: per-chunk nonce (replace, not increment)

    @Test("per-chunk nonce replaces the last 4 bytes with the big-endian index")
    func chunkNonceVector() throws {
        let base = Data((0x21 ... 0x2c).map { UInt8($0) })    // 12 bytes
        #expect(ContainerCodec.chunkNonce(baseNonce: base, index: 0).hexString == "212223242526272800000000")
        #expect(ContainerCodec.chunkNonce(baseNonce: base, index: 1).hexString == "212223242526272800000001")
        #expect(ContainerCodec.chunkNonce(baseNonce: base, index: 0x01020304).hexString == "212223242526272801020304")
    }

    // MARK: AAD = header + flag

    @Test("AAD is header bytes plus the final-chunk flag byte")
    func aadVector() throws {
        let header = Data(hex: "504b43525950540200")!   // arbitrary 10-byte header prefix
        #expect(ContainerCodec.aad(header: header, final: false).suffix(1).first == 0x00)
        #expect(ContainerCodec.aad(header: header, final: true).suffix(1).first == 0x01)
        #expect(ContainerCodec.aad(header: header, final: false).prefix(header.count) == header)
        #expect(ContainerCodec.aad(header: header, final: true).count == header.count + 1)
    }

    // MARK: HKDF / ECDH / Ed->X key derivation matches the oracle

    @Test("derived key matches the Python oracle for the committed short-container header")
    func hkdfKeyVector() throws {
        let shortHeader = FitHeader.fromContainer(Fixtures.container("short"), headerSize: 58)
        let v2 = try V2Header.parse(shortHeader)
        let xPriv = KeyMaterial.x25519Private(fromSeed: Fixtures.privateKey.seed,
                                              ed25519Public: Fixtures.privateKey.ed25519Public)
        let xPub = try KeyMaterial.x25519Public(fromEd25519: Fixtures.privateKey.ed25519Public)
        let shared = try KeyMaterial.sharedSecret(x25519Private: xPriv, ephemeralPublic: v2.ephemeralPublicKey)
        let key = KeyMaterial.deriveKey(sharedSecret: shared, ephemeralPublicKey: v2.ephemeralPublicKey,
                                        recipientXPublic: xPub)
        let expected = "REMOVED-TEST-KEY"
        #expect(key.hexString == expected)
    }

    // MARK: committed oracle-produced containers decrypt to the deterministic plaintext

    @Test("decrypts oracle-produced containers at 0 / 1 MiB / 1 MiB+1")
    func decryptOracleFixtures() throws {
        let cases: [(String, Int)] = [("empty", 0), ("1MiB", 1 << 20), ("1MiBplus1", (1 << 20) + 1)]
        for (name, n) in cases {
            // Recreate the oracle container in a scratch file and decrypt it.
            let scratch = Scratch()
            defer { scratch.cleanup() }
            try Fixtures.container(name).write(to: scratch.container)
            let result = PKCryptEngine.decrypt(containerURL: scratch.container,
                                               privateKey: Fixtures.privateKey,
                                               destinationURL: scratch.output)
            let recovered = try result.get()
            #expect(recovered == scratch.output)
            #expect(try Data(contentsOf: scratch.output) == pattern(n))
        }
    }

    // MARK: Swift self round-trip

    @Test("Swift encrypt then Swift decrypt round-trips at 0 / 1 MiB / 1 MiB+1")
    func swiftSelfRoundTrip() throws {
        for n in [0, 1 << 20, (1 << 20) + 1] {
            let scratch = Scratch()
            defer { scratch.cleanup() }
            let input = scratch.dir.appendingPathComponent("in")
            try pattern(n).write(to: input)
            let enc = try PKCryptEngine.encrypt(fileURL: input,
                                                 recipient: Fixtures.publicKey,
                                                 destinationURL: scratch.container).get()
            #expect(enc == scratch.container)
            #expect(try Data(contentsOf: scratch.container) != pattern(n))
            let dec = try PKCryptEngine.decrypt(containerURL: scratch.container,
                                                 privateKey: Fixtures.privateKey,
                                                 destinationURL: scratch.output).get()
            #expect(dec == scratch.output)
            #expect(try Data(contentsOf: scratch.output) == pattern(n))
        }
    }

    // MARK: truncation guard (minimal; full negative suite in Plan 04)

    @Test("decrypting a container with the final chunk cut returns authFailure and writes no destination")
    func truncationGuard() throws {
        // Cut 5 bytes off the committed 1MiB+1 container (corrupts the final chunk's tag).
        var data = Fixtures.container("1MiBplus1")
        data.removeLast(5)
        let scratch = Scratch()
        defer { scratch.cleanup() }
        try data.write(to: scratch.container)
        let result = PKCryptEngine.decrypt(containerURL: scratch.container,
                                           privateKey: Fixtures.privateKey,
                                           destinationURL: scratch.output)
        guard case .failure(let err) = result else {
            Issue.record("expected authFailure, got success")
            return
        }
        #expect(err == .authFailure)
        #expect(!FileManager.default.fileExists(atPath: scratch.output.path))
    }
}

/// Small helper to slice the header bytes off a raw container.
enum FitHeader {
    static func fromContainer(_ data: Data, headerSize: Int) -> Data {
        Data(data.prefix(headerSize))
    }
}

// MARK: - libsodium static-link smoke (Task 1, kept)

@Suite("libsodium FFI + static link")
struct LibsodiumLinkSmokeTests {
    @Test("sodium_init returns 0/1 and pk_to_curve matches the oracle x_pub")
    func libsodiumLinkSmoke() throws {
        let initRC = sodium_init()
        #expect(initRC == 0 || initRC == 1)
        let edPub = try #require(Data(hex: "REMOVED-TEST-KEY"))
        var out = [UInt8](repeating: 0, count: 32)
        let rc = edPub.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> Int32 in
            crypto_sign_ed25519_pk_to_curve25519(&out, buf.bindMemory(to: UInt8.self).baseAddress!)
        }
        #expect(rc == 0)
        #expect(out.count == 32)
        #expect(Data(out).hexString == "REMOVED-TEST-KEY")
    }
}
