import Foundation

/// Byte-exact v2 (Ed25519) container format constants, matching pkcrypt_lib/core.py
/// (READ.  File format specification: magic, header offsets, nonce/AAD rules are
/// dictated by the existing format — never agent choice).
public enum ContainerCodec {
    public static let magic: [UInt8] = Array("PKCRYPT\u{02}".utf8)   // 8 bytes
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
