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

    // RSA fixtures
    static let rsaDir = dir.appendingPathComponent("RSA")
    static let rsa2048Priv = rsaDir.appendingPathComponent("rsa2048")
    static let rsa2048Pub = rsaDir.appendingPathComponent("rsa2048.pub")
    static let rsa4096Priv = rsaDir.appendingPathComponent("rsa4096")
    static let rsa4096Pub = rsaDir.appendingPathComponent("rsa4096.pub")
    static let rsaOtherPriv = rsaDir.appendingPathComponent("rsa2048_other")
    static let rsaContainersDir = rsaDir.appendingPathComponent("Containers")

    static let rsa2048Material: RSAPrivateKeyMaterial = {
        try! KeyMaterial.parseRSAPrivate(Data(contentsOf: rsa2048Priv))
    }()
    static let rsa2048Public: RSAPublicKeyMaterial = {
        try! KeyMaterial.parseRSAPublic(Data(contentsOf: rsa2048Pub))
    }()
    static let rsa4096Material: RSAPrivateKeyMaterial = {
        try! KeyMaterial.parseRSAPrivate(Data(contentsOf: rsa4096Priv))
    }()
    static let rsa4096Public: RSAPublicKeyMaterial = {
        try! KeyMaterial.parseRSAPublic(Data(contentsOf: rsa4096Pub))
    }()
    static let rsaOtherMaterial: RSAPrivateKeyMaterial = {
        try! KeyMaterial.parseRSAPrivate(Data(contentsOf: rsaOtherPriv))
    }()

    static func rsaContainer(_ name: String) -> Data {
        try! Data(contentsOf: rsaContainersDir.appendingPathComponent("\(name).pkcrypt"))
    }
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

/// Composers/decomposers for a complete v3 (RSA) AES-GCM container, exercised in
/// these tests through the public building blocks (RSAHeader + KeyMaterial RSA
/// wrap/unwrap + AesGcmChunkCrypto + ChunkedEncryptor/Decryptor).
enum RSAPipe {
    static func random(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0 ..< n).map { _ in UInt8.random(in: .min ... .max, using: &g) })
    }

    /// Encrypt `plaintext` into a complete v3 AES-GCM container for an RSA public
    /// key (a fresh random 32-byte session key per encrypt, T-02-17).
    static func encrypt(_ plaintext: Data, pub: RSAPublicKeyMaterial,
                        chunkLen: UInt32 = UInt32(ContainerCodec.defaultChunkLen)) throws -> Data {
        let sessionKey = random(32)
        let wrapped = try KeyMaterial.rsaWrap(sessionKey: sessionKey, publicKey: pub)
        let nonce = random(ContainerCodec.nonceAES)
        let header = try RSAHeader(cipher: ContainerCodec.cipherAES,
                                   payloadType: ContainerCodec.payloadFile,
                                   alg: ContainerCodec.rsaAlgOAEPSHA256,
                                   wrappedKey: wrapped, baseNonce: nonce,
                                   chunkLen: chunkLen, modulusBytes: pub.modulusBytes).bytes
        let crypto = AesGcmChunkCrypto(key: sessionKey, header: header,
                                       baseNonce: nonce, chunkLen: Int(chunkLen))
        var body = Data()
        let enc = ChunkedEncryptor(crypto: crypto) { body.append($0) }
        try enc.write(plaintext)
        try enc.finish()
        return header + body
    }

    /// Decrypt a complete v3 container with an RSA private key, returning the
    /// recovered plaintext.
    static func decrypt(_ container: Data, priv: RSAPrivateKeyMaterial) throws -> Data {
        let header = try RSAHeader.parse(container, modulusBytes: priv.modulusBytes)
        let sessionKey = try KeyMaterial.rsaUnwrap(wrapped: header.wrappedKey, privateKey: priv)
        let headerBytes = Data(container.prefix(
            RSAHeader.headerSize(nonceLen: header.baseNonce.count, modulusBytes: priv.modulusBytes)))
        let crypto = AesGcmChunkCrypto(key: sessionKey, header: headerBytes,
                                       baseNonce: header.baseNonce, chunkLen: Int(header.chunkLen))
        let dec = ChunkedDecryptor(crypto: crypto)
        var out = Data()
        var first = true
        let body = Data(container[headerBytes.count...])
        try dec.run(reader: {
            if first { first = false; return body }
            return nil
        }) { out.append($0) }
        return out
    }
}

/// Decrypt helpers for cipher-0x01 (XChaCha20-Poly1305) containers, routing
/// exclusively through libsodium via `XChaCha20ChunkCrypto` (24-byte nonce).
enum XCPipe {
    /// Decrypt a v2 (Ed25519) XChaCha container: ECDH+HKDF key, then XChaCha.
    static func decryptEd25519(_ container: Data, priv: PrivateKeyMaterial) throws -> Data {
        let cipher = container[ContainerCodec.magicBytes]
        guard cipher == ContainerCodec.cipherXChaCha20 else {
            throw EngineError.unsupportedFormat("not an XChaCha20 container")
        }
        let headerSize = ContainerCodec.prefixBytes + ContainerCodec.ephPubBytes
            + ContainerCodec.nonceXC + ContainerCodec.chunkLenBytes
        let header = Data(container.prefix(headerSize))
        let v2 = try V2Header.parse(header)
        let xPriv = KeyMaterial.x25519Private(fromSeed: priv.seed, ed25519Public: priv.ed25519Public)
        let xPub = try KeyMaterial.x25519Public(fromEd25519: priv.ed25519Public)
        let shared = try KeyMaterial.sharedSecret(x25519Private: xPriv, ephemeralPublic: v2.ephemeralPublicKey)
        let key = KeyMaterial.deriveKey(sharedSecret: shared, ephemeralPublicKey: v2.ephemeralPublicKey,
                                        recipientXPublic: xPub)
        let crypto = XChaCha20ChunkCrypto(key: key, header: header, baseNonce: v2.baseNonce,
                                          chunkLen: Int(v2.chunkLen))
        return try run(crypto, container: container, headerSize: headerSize)
    }

    /// Decrypt a v3 (RSA) XChaCha container: OAEP-unwrapped session key, then XChaCha.
    static func decryptRSA(_ container: Data, priv: RSAPrivateKeyMaterial) throws -> Data {
        let rsaHeader = try RSAHeader.parse(container, modulusBytes: priv.modulusBytes)
        let sessionKey = try KeyMaterial.rsaUnwrap(wrapped: rsaHeader.wrappedKey, privateKey: priv)
        let headerSize = RSAHeader.headerSize(nonceLen: rsaHeader.baseNonce.count, modulusBytes: priv.modulusBytes)
        let header = Data(container.prefix(headerSize))
        let crypto = XChaCha20ChunkCrypto(key: sessionKey, header: header, baseNonce: rsaHeader.baseNonce,
                                          chunkLen: Int(rsaHeader.chunkLen))
        return try run(crypto, container: container, headerSize: headerSize)
    }

    private static func run(_ crypto: any ChunkDecrypting, container: Data,
                            headerSize: Int) throws -> Data {
        let dec = ChunkedDecryptor(crypto: crypto)
        var out = Data()
        var first = true
        let body = Data(container[headerSize...])
        try dec.run(reader: {
            if first { first = false; return body }
            return nil
        }) { out.append($0) }
        return out
    }
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

    // MARK: v3 RSA header byte vectors

    @Test("v3 header layout is byte-exact: magic PKCRYPT\\x03 | cipher | payload | alg | wrapped | nonce | chunk_len")
    func rsa2048HeaderByteVector() throws {
        // Deterministic 256-byte wrapped key (values 1..255, then 0x00).
        let wrapped = Data((1 ... 256).map { UInt8($0 & 0xFF) })
        let nonce = Data((0x21 ... 0x2c).map { UInt8($0) })   // 12 bytes
        let header = try RSAHeader(cipher: 0x00, payloadType: 0x00, alg: 0x00,
                                   wrappedKey: wrapped, baseNonce: nonce,
                                   chunkLen: 1 << 20, modulusBytes: 256).bytes
        #expect(header.count == 8 + 1 + 1 + 1 + 256 + 12 + 4)
        #expect(Array(header[0 ..< 8]) == Array("PKCRYPT\u{03}".utf8))
        #expect(header[8] == 0x00)    // cipher AES
        #expect(header[9] == 0x00)    // payload file
        #expect(header[10] == 0x00)   // alg rsa-oaep-sha256
        #expect(header[11] == 0x01)   // first wrapped-key byte (value 1)
        #expect(header[11 + 255] == 0x00)  // 256th wrapped byte (256 & 0xFF)
        #expect(header[11 + 256] == 0x21)  // nonce starts right after wrapped key
        #expect(Array(header.suffix(4)) == [0x00, 0x10, 0x00, 0x00])  // chunk_len = 1 MiB BE
    }

    @Test("a v3 header for RSA-4096 has a 512-byte wrapped key computed from the modulus, not hardcoded 256")
    func rsa4096WrappedKeyIs512() throws {
        // Real encryption with the RSA-4096 key: the wrapped-key field must be
        // 512 bytes = (4096+7)/8, proving (modulus_bits+7)/8 is used.
        let container = try RSAPipe.encrypt(pattern(64), pub: Fixtures.rsa4096Public)
        let header = try RSAHeader.parse(container, modulusBytes: Fixtures.rsa4096Material.modulusBytes)
        #expect(Fixtures.rsa4096Material.modulusBytes == 512)
        #expect(header.wrappedKey.count == 512)
        // And RSA-2048 is 256, not mistaken for 512.
        let c2048 = try RSAPipe.encrypt(pattern(64), pub: Fixtures.rsa2048Public)
        let h2048 = try RSAHeader.parse(c2048, modulusBytes: Fixtures.rsa2048Material.modulusBytes)
        #expect(h2048.wrappedKey.count == 256)
    }

    // MARK: RSA round-trips against committed oracle containers

    @Test("decrypts oracle-produced RSA AES-GCM containers at 0 / 1 MiB / 1 MiB+1, both key sizes")
    func decryptOracleRsaFixtures() throws {
        let aes: [(String, Int)] = [("empty", 0), ("1MiB", 1 << 20), ("1MiBplus1", (1 << 20) + 1)]
        for (kind, material) in [("rsa2048", Fixtures.rsa2048Material), ("rsa4096", Fixtures.rsa4096Material)] {
            for (suffix, n) in aes {
                let container = Fixtures.rsaContainer("\(kind)_\(suffix)")
                let recovered = try RSAPipe.decrypt(container, priv: material)
                #expect(recovered == pattern(n), "\(kind) \(suffix) recovered != original (\(recovered.count) vs \(n))")
            }
        }
    }

    @Test("Swift RSA encrypt produces a container that round-trips back at 0 / 1 MiB / 1 MiB+1")
    func swiftRsaSelfRoundTrip() throws {
        for (pub, priv) in [(Fixtures.rsa2048Public, Fixtures.rsa2048Material),
                            (Fixtures.rsa4096Public, Fixtures.rsa4096Material)] {
            for n in [0, 1 << 20, (1 << 20) + 1] {
                let container = try RSAPipe.encrypt(pattern(n), pub: pub)
                let recovered = try RSAPipe.decrypt(container, priv: priv)
                #expect(recovered == pattern(n), "size \(n) recovered != original")
            }
        }
    }

    // MARK: RSA negative boundary (D-13)

    @Test("an RSA key with modulus < 2048 bits returns keyError before any crypto")
    func rsaShortKeyRejected() throws {
        // Committed RSA-1024 public key (ssh-keygen -b 1024).
        let smallPub = Fixtures.rsaDir.appendingPathComponent("small_rsa.pub")
        do {
            _ = try KeyMaterial.parseRSAPublic(Data(contentsOf: smallPub))
            Issue.record("expected keyError for a short (1024-bit) RSA modulus")
        } catch let e {
            // Parsing/size failure is a pre-crypto keyError (D-13).
            guard case .keyError? = e as? EngineError else {
                Issue.record("expected keyError, got \(e)")
                return
            }
        }
    }

    @Test("RSA-OAEP unwrap with the wrong private key folds into the single generic authFailure")
    func rsaWrongKeyAuthFailure() throws {
        // Encrypt with rsa2048's public key, then try to decrypt with a different
        // same-size RSA-2048 private key (rsa2048_other).
        let container = try RSAPipe.encrypt(pattern(128), pub: Fixtures.rsa2048Public)
        do {
            _ = try RSAPipe.decrypt(container, priv: Fixtures.rsaOtherMaterial)
            Issue.record("expected authFailure for wrong RSA key")
        } catch let e {
            // Wrong-key unwrap folds into the single generic authFailure (T-02-09/D-13).
            guard case .authFailure? = e as? EngineError else {
                Issue.record("expected authFailure, got \(e)")
                return
            }
        }
    }

    // MARK: RSA session-key freshness (T-02-17)

    @Test("two RSA encrypts of identical plaintext to the same key differ in wrapped-key AND ciphertext bytes")
    func rsaEncryptFreshness() throws {
        let c1 = try RSAPipe.encrypt(pattern(64), pub: Fixtures.rsa2048Public)
        let c2 = try RSAPipe.encrypt(pattern(64), pub: Fixtures.rsa2048Public)
        let h1 = try RSAHeader.parse(c1, modulusBytes: 256)
        let h2 = try RSAHeader.parse(c2, modulusBytes: 256)
        #expect(h1.wrappedKey != h2.wrappedKey,
                "a fresh random 32-byte session key per encrypt must produce different wrapped keys")
        #expect(c1 != c2, "different session keys/nonces must produce different full containers")
    }

    // MARK: XChaCha20-Poly1305 read path (cipher 0x01, 24-byte nonce)

    @Test("cipher 0x01 parses with a 24-byte base nonce and routes to the libsodium XChaCha path")
    func xchachaCipherRoute() throws {
        let ed = Fixtures.container("xc_ed_empty")
        let rsa = Fixtures.rsaContainer("rsa2048_xc_empty")
        for c in [ed, rsa] {
            #expect(c[ContainerCodec.magicBytes] == ContainerCodec.cipherXChaCha20)
            // 24-byte nonce, not 12.
            let nonceLen = try ContainerCodec.nonceLen(forCipher: c[ContainerCodec.magicBytes])
            #expect(nonceLen == ContainerCodec.nonceXC && nonceLen != ContainerCodec.nonceAES)
        }
        // Ed25519 v2 header carries a 24-byte base nonce.
        let v2 = try V2Header.parse(Data(ed.prefix(ContainerCodec.prefixBytes + ContainerCodec.ephPubBytes
            + ContainerCodec.nonceXC + ContainerCodec.chunkLenBytes)))
        #expect(v2.baseNonce.count == 24)
        // RSA v3 header carries a 24-byte base nonce.
        let rh = try RSAHeader.parse(rsa, modulusBytes: Fixtures.rsa2048Material.modulusBytes)
        #expect(rh.baseNonce.count == 24)
    }

    @Test("per-chunk XChaCha nonce = 24-byte base nonce with the last 4 bytes replaced by the BE index")
    func xchachaNonceVector() throws {
        // 24-byte base: 0x21..0x38.
        let base = Data((0x21 ... 0x38).map { UInt8($0) })
        // First 20 bytes stay, last 4 (0x35..0x38) are replaced.
        let prefix = "2122232425262728292a2b2c2d2e2f3031323334"
        #expect(ContainerCodec.chunkNonce(baseNonce: base, index: 0).hexString == prefix + "00000000")
        #expect(ContainerCodec.chunkNonce(baseNonce: base, index: 1).hexString == prefix + "00000001")
        #expect(ContainerCodec.chunkNonce(baseNonce: base, index: 0x01020304).hexString == prefix + "01020304")
    }

    @Test("decrypts oracle-produced XChaCha20 v2 (Ed25519) containers at 0 / 1 MiB / 1 MiB+1")
    func decryptOracleXcEd25519() throws {
        for (suffix, n) in [("empty", 0), ("1MiB", 1 << 20), ("1MiBplus1", (1 << 20) + 1)] {
            let container = Fixtures.container("xc_ed_\(suffix)")
            let recovered = try XCPipe.decryptEd25519(container, priv: Fixtures.privateKey)
            #expect(recovered == pattern(n), "xc_ed \(suffix) recovered != original")
        }
    }

    @Test("decrypts oracle-produced XChaCha20 v3 (RSA) containers")
    func decryptOracleXcRsa() throws {
        for (suffix, n) in [("empty", 0), ("1MiB", 1 << 20), ("1MiBplus1", (1 << 20) + 1)] {
            let container = Fixtures.rsaContainer("rsa2048_xc_\(suffix)")
            let recovered = try XCPipe.decryptRSA(container, priv: Fixtures.rsa2048Material)
            #expect(recovered == pattern(n), "rsa2048_xc \(suffix) recovered != original")
        }
    }

    @Test("the engine's public encrypt only writes AES-GCM (cipher 0x00); no XChaCha write path is exposed")
    func noXChaChaWritePath() throws {
        let scratch = Scratch()
        defer { scratch.cleanup() }
        let input = scratch.dir.appendingPathComponent("in")
        try pattern(16).write(to: input)
        _ = try PKCryptEngine.encrypt(fileURL: input, recipient: Fixtures.publicKey,
                                      destinationURL: scratch.container).get()
        let data = try Data(contentsOf: scratch.container)
        #expect(data[ContainerCodec.magicBytes] == ContainerCodec.cipherAES,
                "the only public encrypt emits cipher 0x00 (AES-GCM)")
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
