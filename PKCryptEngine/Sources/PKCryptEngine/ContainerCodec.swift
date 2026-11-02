import Foundation

/// Byte-exact v2 (Ed25519) container format constants, matching pkcrypt_lib/core.py
/// (READ.  File format specification: magic, header offsets, nonce/AAD rules are
/// dictated by the existing format — never agent choice).
public enum ContainerCodec {
    public static let magic: [UInt8] = Array("PKCRYPT\u{02}".utf8)   // 8 bytes (Ed25519 v2)
    public static let magicRSA: [UInt8] = Array("PKCRYPT\u{03}".utf8) // 8 bytes (RSA v3)
    public static let magicBytes = 8
    public static let cipherBytes = 1
    public static let payloadBytes = 1
    public static let ephPubBytes = 32
    public static let chunkLenBytes = 4
    /// magic | cipher | payload
    public static let prefixBytes = magicBytes + cipherBytes + payloadBytes  // 10

    public static let nonceAES = 12
    public static let nonceXC = 24
    public static let tagBytes = 16

    public static let cipherAES: UInt8 = 0x00
    public static let cipherXChaCha20: UInt8 = 0x01
    public static let payloadFile: UInt8 = 0x00
    public static let payloadArchive: UInt8 = 0x01
    /// v3 (RSA) algorithm byte after magic|cipher|payload: RSA-OAEP with SHA-256.
    public static let rsaAlgOAEPSHA256: UInt8 = 0x00

    public static let flagMore: UInt8 = 0x00
    public static let flagFinal: UInt8 = 0x01

    public static let defaultChunkLen = 1 << 20          // 1 MiB
    public static let maxChunkLen = 16 * 1024 * 1024     // DoS guard (T-02-03)

    public static let hkdfSalt = Data("PKCrypt".utf8)
    public static let hkdfInfoV2 = Data("PKCrypt/v2/x25519-ecdh+aead".utf8)

    public static func nonceLen(forCipher cipher: UInt8) throws -> Int {
        switch cipher {
        case cipherAES: return nonceAES
        case cipherXChaCha20: return nonceXC
        default: throw EngineError.unsupportedFormat("unsupported cipher: \(cipher)")
        }
    }

    /// Per-chunk nonce: base nonce with its final 4 bytes REPLACED by the
    /// big-endian chunk index (never increment / XOR — T-02-04 / Pitfall 5).
    public static func chunkNonce(baseNonce: Data, index: UInt32) -> Data {
        var nb = [UInt8](baseNonce)
        var big = index.bigEndian  // 4 bytes, big-endian
        withUnsafeBytes(of: &big) { src in
            for i in 0..<4 { nb[nb.count - 4 + i] = src[i] }
        }
        return Data(nb)
    }

    /// AAD per chunk = full header bytes + one flag byte (0x00 more, 0x01 final).
    public static func aad(header: Data, final: Bool) -> Data {
        var a = header
        a.append(final ? flagFinal : flagMore)
        return a
    }
}

/// A parsed/built v2 header. Every field doubles as the authenticated AAD base.
public struct V2Header: Sendable, Equatable {
    public let cipher: UInt8
    public let payloadType: UInt8
    public let ephemeralPublicKey: Data  // 32 bytes X25519
    public let baseNonce: Data           // 12 (AES) / 24 (XChaCha) bytes
    public let chunkLen: UInt32

    public static func headerSize(nonceLen: Int) -> Int {
        ContainerCodec.prefixBytes + ContainerCodec.ephPubBytes + nonceLen + ContainerCodec.chunkLenBytes
    }

    /// Build a header for a freshly-encrypted container (validates input).
    public init(cipher: UInt8, payloadType: UInt8, ephemeralPublicKey: Data, baseNonce: Data, chunkLen: UInt32) throws {
        let nonceLen = try ContainerCodec.nonceLen(forCipher: cipher)
        guard ephemeralPublicKey.count == ContainerCodec.ephPubBytes else {
            throw EngineError.unsupportedFormat("invalid ephemeral public key length")
        }
        guard baseNonce.count == nonceLen else {
            throw EngineError.unsupportedFormat("invalid base nonce length")
        }
        try Self.validateChunkLen(chunkLen)
        self.cipher = cipher
        self.payloadType = payloadType
        self.ephemeralPublicKey = ephemeralPublicKey
        self.baseNonce = baseNonce
        self.chunkLen = chunkLen
    }

    /// The exact wire header bytes (also the AAD base for every chunk).
    public var bytes: Data {
        var d = Data(ContainerCodec.magic)
        d.append(cipher)
        d.append(payloadType)
        d.append(ephemeralPublicKey)
        d.append(baseNonce)
        var cl = chunkLen.bigEndian  // 4 bytes, big-endian on the wire
        withUnsafeBytes(of: &cl) { d.append(contentsOf: $0) }
        return d
    }

    static func validateChunkLen(_ cl: UInt32) throws {
        // 1 <= chunk_len <= 16 MiB, validated from the (untrusted) header BEFORE
        // any buffer is sized by it (T-02-03 / Pitfall 5).
        guard cl >= 1 && cl <= UInt32(ContainerCodec.maxChunkLen) else {
            throw EngineError.unsupportedFormat("invalid chunk size in header (must be 1..16 MiB)")
        }
    }

    /// Parse an untrusted header Data blob (magic .. chunk_len), validating every
    /// field before any buffer sized by the header is allocated.
    public static func parse(_ data: Data) throws -> V2Header {
        guard data.count >= ContainerCodec.magicBytes else {
            throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
        }
        let magic = Array(data[0..<ContainerCodec.magicBytes])
        if magic == Array("PKCRYPT\u{01}".utf8) {
            throw EngineError.unsupportedFormat("this file uses the removed v1 format; re-encrypt it")
        }
        guard magic == ContainerCodec.magic else {
            throw EngineError.unsupportedFormat("not a PKCrypt file (bad header)")
        }
        guard data.count >= ContainerCodec.prefixBytes else {
            throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
        }
        let cipher = data[ContainerCodec.magicBytes]
        let payloadType = data[ContainerCodec.magicBytes + 1]
        let nonceLen = try ContainerCodec.nonceLen(forCipher: cipher)
        guard payloadType == ContainerCodec.payloadFile || payloadType == ContainerCodec.payloadArchive else {
            throw EngineError.unsupportedFormat("unsupported payload type: \(payloadType)")
        }
        guard data.count >= headerSize(nonceLen: nonceLen) else {
            throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
        }
        let off = ContainerCodec.prefixBytes
        let eph = data[off ..< off + ContainerCodec.ephPubBytes]
        let baseNonce = data[off + ContainerCodec.ephPubBytes ..< off + ContainerCodec.ephPubBytes + nonceLen]
        let clBytes = data[off + ContainerCodec.ephPubBytes + nonceLen ..< off + ContainerCodec.ephPubBytes + nonceLen + ContainerCodec.chunkLenBytes]
        let chunkLen = clBytes.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian
        try validateChunkLen(chunkLen)
        return try V2Header(cipher: cipher, payloadType: payloadType,
                            ephemeralPublicKey: Data(eph), baseNonce: Data(baseNonce), chunkLen: chunkLen)
    }
}

/// A parsed/built v3 (RSA) header. Matches pkcrypt_lib/core.py `RSAEncryptor`/
/// `RSADecryptor`: magic PKCRYPT\\x03 | cipher | payload | alg | wrapped_key(N) |
/// base_nonce | chunk_len(4, BE). `N` is the RSA modulus size `(bits+7)/8` —
/// 256 for RSA-2048, 512 for RSA-4096 — NEVER a hardcoded 256 (T-02-06).
public struct RSAHeader: Sendable, Equatable {
    public let cipher: UInt8
    public let payloadType: UInt8
    public let alg: UInt8              // 0x00 = rsa-oaep-sha256
    public let wrappedKey: Data        // variable length = modulus bytes
    public let baseNonce: Data         // 12 (AES) / 24 (XChaCha)
    public let chunkLen: UInt32

    /// Fixed header size for the given nonce length and RSA modulus byte count.
    public static func headerSize(nonceLen: Int, modulusBytes: Int) -> Int {
        ContainerCodec.magicBytes            // magic
            + ContainerCodec.cipherBytes      // cipher
            + ContainerCodec.payloadBytes     // payload
            + 1                              // alg
            + modulusBytes                    // wrapped key
            + nonceLen                        // base nonce
            + ContainerCodec.chunkLenBytes    // chunk_len
    }

    /// Build a header for a freshly-encrypted v3 container (validates input).
    public init(cipher: UInt8, payloadType: UInt8, alg: UInt8,
                wrappedKey: Data, baseNonce: Data, chunkLen: UInt32,
                modulusBytes: Int) throws {
        let nonceLen = try ContainerCodec.nonceLen(forCipher: cipher)
        guard alg == ContainerCodec.rsaAlgOAEPSHA256 else {
            throw EngineError.unsupportedFormat("unsupported RSA algorithm: \(alg)")
        }
        guard wrappedKey.count == modulusBytes else {
            throw EngineError.unsupportedFormat("invalid wrapped-key length")
        }
        guard baseNonce.count == nonceLen else {
            throw EngineError.unsupportedFormat("invalid base nonce length")
        }
        try Self.validateChunkLen(chunkLen)
        self.cipher = cipher
        self.payloadType = payloadType
        self.alg = alg
        self.wrappedKey = wrappedKey
        self.baseNonce = baseNonce
        self.chunkLen = chunkLen
    }

    /// The exact wire header bytes (also the AAD base for every chunk).
    public var bytes: Data {
        var d = Data(ContainerCodec.magicRSA)
        d.append(cipher)
        d.append(payloadType)
        d.append(alg)
        d.append(wrappedKey)
        d.append(baseNonce)
        var cl = chunkLen.bigEndian
        withUnsafeBytes(of: &cl) { d.append(contentsOf: $0) }
        return d
    }

    static func validateChunkLen(_ cl: UInt32) throws {
        guard cl >= 1 && cl <= UInt32(ContainerCodec.maxChunkLen) else {
            throw EngineError.unsupportedFormat("invalid chunk size in header (must be 1..16 MiB)")
        }
    }

    /// Parse an untrusted v3 header, validating every field before any buffer
    /// sized by it is allocated (T-02-03 / T-02-08).
    ///
    /// The wrapped-key length is NOT decodable from the header alone; it must
    /// be supplied from the recipient's RSA key (`(bits+7)/8`), exactly as the
    /// oracle does (`core.py` `RSADecryptor.__init__` reads `mod_bytes` from the
    /// private key).
    public static func parse(_ data: Data, modulusBytes: Int) throws -> RSAHeader {
        guard data.count >= ContainerCodec.magicBytes else {
            throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
        }
        let magic = Array(data[0..<ContainerCodec.magicBytes])
        guard magic == ContainerCodec.magicRSA else {
            throw EngineError.unsupportedFormat("not a PKCrypt file (bad header)")
        }
        guard data.count >= ContainerCodec.prefixBytes else {
            throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
        }
        let cipher = data[ContainerCodec.magicBytes]
        let payloadType = data[ContainerCodec.magicBytes + 1]
        let alg = data[ContainerCodec.prefixBytes]          // after magic|cipher|payload
        let nonceLen = try ContainerCodec.nonceLen(forCipher: cipher)
        guard payloadType == ContainerCodec.payloadFile || payloadType == ContainerCodec.payloadArchive else {
            throw EngineError.unsupportedFormat("unsupported payload type: \(payloadType)")
        }
        guard alg == ContainerCodec.rsaAlgOAEPSHA256 else {
            throw EngineError.unsupportedFormat("unsupported RSA algorithm: \(alg)")
        }
        let off = ContainerCodec.prefixBytes + 1            // skip alg
        let size = headerSize(nonceLen: nonceLen, modulusBytes: modulusBytes)
        guard data.count >= size else {
            throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
        }
        let wrapped = data[off ..< off + modulusBytes]
        let baseNonce = data[off + modulusBytes ..< off + modulusBytes + nonceLen]
        let offCL = off + modulusBytes + nonceLen
        let clBytes = data[offCL ..< offCL + ContainerCodec.chunkLenBytes]
        let chunkLen = clBytes.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian
        try validateChunkLen(chunkLen)
        return try RSAHeader(cipher: cipher, payloadType: payloadType, alg: alg,
                             wrappedKey: Data(wrapped), baseNonce: Data(baseNonce),
                             chunkLen: chunkLen, modulusBytes: modulusBytes)
    }
}
