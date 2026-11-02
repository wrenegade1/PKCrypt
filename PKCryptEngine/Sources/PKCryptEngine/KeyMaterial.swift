import Foundation
import CryptoKit
import Security
import CSodium

/// Parsed recipient/public key material.
public struct PublicKeyMaterial: Sendable, Equatable {
    public let ed25519Public: Data   // 32 bytes
    public init(ed25519Public: Data) { self.ed25519Public = ed25519Public }
}

/// Parsed private key material (Ed25519 seed + public).
public struct PrivateKeyMaterial: Sendable, Equatable {
    public let seed: Data            // 32 bytes Ed25519 seed
    public let ed25519Public: Data   // 32 bytes
    public init(seed: Data, ed25519Public: Data) { self.seed = seed; self.ed25519Public = ed25519Public }
}

/// Parsed RSA *public* key material (OpenSSH `ssh-rsa`). Components are stored
/// as big-endian magnitudes; the SecKey is built on demand (not stored — SecKey
/// is not Sendable/Equatable). `modulusBytes` = `(key_size + 7) / 8` — 256 for
/// RSA-2048, 512 for RSA-4096 — computed from the parsed modulus, never
/// hardcoded (T-02-06).
public struct RSAPublicKeyMaterial: Sendable, Equatable {
    public let modulusBytes: Int
    public let n: Data   // modulus, big-endian magnitude
    public let e: Data   // public exponent, big-endian magnitude
    public init(modulusBytes: Int, n: Data, e: Data) {
        self.modulusBytes = modulusBytes
        self.n = n
        self.e = e
    }
}

/// Parsed RSA *private* key material (OpenSSH `openssh-key-v1`). Components are
/// big-endian magnitudes in PKCS#1 terms (PCKS#1 order: n, e, d, p, q, and the
/// CRT params dP/dQ/qInv are derived at SecKey-build time). Same modulus floor.
public struct RSAPrivateKeyMaterial: Sendable, Equatable {
    public let modulusBytes: Int
    public let n: Data
    public let e: Data
    public let d: Data
    public let p: Data
    public let q: Data
    public let iqmp: Data   // q^-1 mod p (OpenSSH coefficient)
    public init(modulusBytes: Int, n: Data, e: Data, d: Data,
                p: Data, q: Data, iqmp: Data) {
        self.modulusBytes = modulusBytes
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.iqmp = iqmp
    }
}

/// OpenSSH Ed25519 key parsing + Ed25519→X25519 conversions + HKDF, matching
/// pkcrypt_lib/keys.py and core.py (D-13: parsing failures are keyError, raised
/// BEFORE any crypto; crypto-stage failures fold into authFailure).
public enum KeyMaterial {

    // MARK: - OpenSSH wire parsing (pre-crypto -> keyError)

    private enum ParseIssue: Error { case truncated, unsupported, mismatch }

    private struct Reader {
        let bytes: [UInt8]
        var pos = 0
        mutating func readString() throws -> [UInt8] {
            guard pos + 4 <= bytes.count else { throw ParseIssue.truncated }
            let len = Int(bytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: pos, as: UInt32.self) }.bigEndian)
            pos += 4
            let end = pos + len
            guard end <= bytes.count else { throw ParseIssue.truncated }
            defer { pos = end }
            return Array(bytes[pos ..< end])
        }
        mutating func readUInt32() throws -> UInt32 {
            guard pos + 4 <= bytes.count else { throw ParseIssue.truncated }
            defer { pos += 4 }
            return bytes.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: pos, as: UInt32.self) }.bigEndian
        }
    }

    private static func ed25519PublicFromSSHBlob(_ blob: [UInt8]) throws -> Data {
        var r = Reader(bytes: blob)
        let name = try r.readString()
        guard String(decoding: name, as: UTF8.self) == "ssh-ed25519" else { throw ParseIssue.unsupported }
        let key = try r.readString()
        guard key.count == 32 else { throw ParseIssue.unsupported }
        return Data(key)
    }

    /// Parse an OpenSSH ed25519 *public* key file: `ssh-ed25519 <b64> [comment]`.
    public static func parseEd25519Public(_ fileData: Data) throws -> PublicKeyMaterial {
        let s = String(decoding: fileData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = s.split(separator: " ").map(String.init)
        guard parts.count >= 2, let b64 = Data(base64Encoded: parts[1]) else {
            throw EngineError.keyError("could not parse public key: expected an OpenSSH ed25519 public key")
        }
        do {
            return PublicKeyMaterial(ed25519Public: try ed25519PublicFromSSHBlob([UInt8](b64)))
        } catch {
            throw EngineError.keyError("could not parse public key: unsupported type or format")
        }
    }

    /// Parse an unencrypted OpenSSH ed25519 *private* key file.
    /// (Passphrase-protected keys are not supported — no passphrase UI in scope, D-11.)
    public static func parseEd25519Private(_ fileData: Data) throws -> PrivateKeyMaterial {
        let text = String(decoding: fileData, as: UTF8.self)
        guard text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") else {
            throw EngineError.keyError("could not parse private key: expected an OpenSSH ed25519 private key")
        }
        var b64 = ""
        var inBlock = false
        for line in text.components(separatedBy: .newlines) {
            if line.hasPrefix("-----BEGIN") { inBlock = true; continue }
            if line.hasPrefix("-----END") { break }
            if inBlock { b64 += line.trimmingCharacters(in: .whitespaces) }
        }
        guard let decoded = Data(base64Encoded: b64) else {
            throw EngineError.keyError("could not parse private key (base64)")
        }
        let b = [UInt8](decoded)
        let magic = Array("openssh-key-v1\u{0}".utf8)
        guard b.count >= magic.count, Array(b[0 ..< magic.count]) == magic else {
            throw EngineError.keyError("could not parse private key (bad magic)")
        }
        var r = Reader(bytes: b)
        r.pos = magic.count
        let cipherName: String
        let kdfName: String
        do {
            cipherName = String(decoding: try r.readString(), as: UTF8.self)
            kdfName = String(decoding: try r.readString(), as: UTF8.self)
            _ = try r.readString()                    // kdfoptions
            let nkeys = try r.readUInt32()
            guard nkeys == 1 else { throw ParseIssue.unsupported }
            let pubBlob = try r.readString()
            let privBlob = try r.readString()
            guard cipherName == "none", kdfName == "none" else {
                throw EngineError.keyError("passphrase-protected keys are not supported")
            }
            var p = Reader(bytes: privBlob)
            let c1 = try p.readUInt32()
            let c2 = try p.readUInt32()
            guard c1 == c2 else { throw ParseIssue.mismatch }
            let kt = String(decoding: try p.readString(), as: UTF8.self)
            guard kt == "ssh-ed25519" else { throw ParseIssue.unsupported }
            let edPub = try p.readString()
            guard edPub.count == 32 else { throw ParseIssue.mismatch }
            let edPriv = try p.readString()
            guard edPriv.count == 64 else { throw ParseIssue.mismatch }
            // consistency: private blob's embedded public == its pubkey field
            guard Array(edPriv[32 ..< 64]) == edPub else { throw ParseIssue.mismatch }
            // and the outer header's public blob matches too
            guard try ed25519PublicFromSSHBlob(pubBlob) == Data(edPub) else { throw ParseIssue.mismatch }
            let seed = Data(edPriv[0 ..< 32])
            return PrivateKeyMaterial(seed: seed, ed25519Public: Data(edPub))
        } catch let e as EngineError {
            throw e
        } catch {
            throw EngineError.keyError("could not parse private key: unsupported, malformed, or wrong type")
        }
    }

    // MARK: - Ed25519 -> X25519 (crypto stage -> authFailure, T-02-05 / D-13)

    /// Public Ed→X via libsodium (Phase-1 D-02). Crypto-stage failure -> authFailure.
    public static func x25519Public(fromEd25519 ed: Data) throws -> Data {
        guard ed.count == 32 else { throw EngineError.authFailure }
        var out = [UInt8](repeating: 0, count: 32)
        let rc = ed.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> Int32 in
            crypto_sign_ed25519_pk_to_curve25519(&out, buf.bindMemory(to: UInt8.self).baseAddress!)
        }
        guard rc == 0 else { throw EngineError.authFailure }
        return Data(out)
    }

    /// Private Ed→X: SHA-512(seed)[0:32] with X25519 clamping (RFC 8032), pure
    /// Swift — matches core.py's own computation (A3; no second libsodium call).
    public static func x25519Private(fromSeed seed: Data, ed25519Public _: Data) -> Data {
        var h = [UInt8](SHA512.hash(data: seed))
        var curve = Array(h[0 ..< 32])
        curve[0] &= 248
        curve[31] &= 127
        curve[31] |= 64
        h.removeAll(keepingCapacity: false)
        return Data(curve)
    }

    /// X25519 ECDH shared secret (CryptoKit). Crypto-stage failure -> authFailure.
    public static func sharedSecret(x25519Private priv: Data, ephemeralPublic other: Data) throws -> Data {
        do {
            let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv)
            let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: other)
            let shared = try privKey.sharedSecretFromKeyAgreement(with: pubKey)
            return shared.withUnsafeBytes { Data($0) }
        } catch {
            throw EngineError.authFailure
        }
    }

    /// HKDF-SHA256 -> 32-byte key, exactly matching core.py `_derive_key`
    /// (salt `PKCrypt`, info `HKDF_INFO_V2 || eph_pub || recipient_x_pub`).
    public static func deriveKey(sharedSecret: Data, ephemeralPublicKey: Data, recipientXPublic: Data) -> Data {
        let info = ContainerCodec.hkdfInfoV2 + ephemeralPublicKey + recipientXPublic
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: sharedSecret),
            salt: ContainerCodec.hkdfSalt,
            info: info,
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    // MARK: - OpenSSH RSA parsing (pre-crypto -> keyError, D-13)

    private static func rsaMpint(_ r: inout Reader) throws -> [UInt8] {
        // OpenSSH mpint: length-prefixed big-endian two's complement with an
        // optional leading 0x00 sign byte on positives whose high bit is set.
        var b = try r.readString()
        if b.count > 0 && b[0] == 0x00 { b.removeFirst() }
        return b
    }

    /// Parse an OpenSSH RSA *public* key file: `ssh-rsa <b64> [comment]`.
    public static func parseRSAPublic(_ fileData: Data) throws -> RSAPublicKeyMaterial {
        let s = String(decoding: fileData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = s.split(separator: " ").map(String.init)
        guard parts.count >= 2, let b64 = Data(base64Encoded: parts[1]) else {
            throw EngineError.keyError("could not parse public key: expected an OpenSSH RSA public key")
        }
        do {
            var r = Reader(bytes: [UInt8](b64))
            let name = String(decoding: try r.readString(), as: UTF8.self)
            guard name == "ssh-rsa" else { throw ParseIssue.unsupported }
            let e = try rsaMpint(&r)
            let n = try rsaMpint(&r)
            let keySize = rsaBitLength(n)
            guard keySize >= 2048 else {
                throw EngineError.keyError("RSA public key is only \(keySize) bits; PKCrypt requires at least 2048 bits")
            }
            return RSAPublicKeyMaterial(modulusBytes: n.count, n: Data(n), e: Data(e))
        } catch let e as EngineError {
            throw e
        } catch {
            throw EngineError.keyError("could not parse public key: unsupported type or format")
        }
    }

    /// Parse an unencrypted OpenSSH RSA *private* key file
    /// (`openssh-key-v1`, cipher "none"). Passphrase-protected keys are not
    /// supported (no passphrase UI in scope, D-11).
    public static func parseRSAPrivate(_ fileData: Data) throws -> RSAPrivateKeyMaterial {
        let text = String(decoding: fileData, as: UTF8.self)
        guard text.contains("-----BEGIN OPENSSH PRIVATE KEY-----") else {
            throw EngineError.keyError("could not parse private key: expected an OpenSSH RSA private key")
        }
        var b64 = ""
        var inBlock = false
        for line in text.components(separatedBy: .newlines) {
            if line.hasPrefix("-----BEGIN") { inBlock = true; continue }
            if line.hasPrefix("-----END") { break }
            if inBlock { b64 += line.trimmingCharacters(in: .whitespaces) }
        }
        guard let decoded = Data(base64Encoded: b64) else {
            throw EngineError.keyError("could not parse private key (base64)")
        }
        let b = [UInt8](decoded)
        let magic = Array("openssh-key-v1\u{0}".utf8)
        guard b.count >= magic.count, Array(b[0 ..< magic.count]) == magic else {
            throw EngineError.keyError("could not parse private key (bad magic)")
        }
        var r = Reader(bytes: b)
        r.pos = magic.count
        do {
            let cipherName = String(decoding: try r.readString(), as: UTF8.self)
            let kdfName = String(decoding: try r.readString(), as: UTF8.self)
            _ = try r.readString()                  // kdfoptions
            let nkeys = try r.readUInt32()
            guard nkeys == 1 else { throw ParseIssue.unsupported }
            _ = try r.readString()                  // public blob
            let privBlob = try r.readString()
            guard cipherName == "none", kdfName == "none" else {
                throw EngineError.keyError("passphrase-protected keys are not supported")
            }
            var p = Reader(bytes: privBlob)
            let c1 = try p.readUInt32()
            let c2 = try p.readUInt32()
            guard c1 == c2 else { throw ParseIssue.mismatch }
            let kt = String(decoding: try p.readString(), as: UTF8.self)
            guard kt == "ssh-rsa" else { throw ParseIssue.unsupported }
            // OpenSSH private RSA blob order: n, e, d, iqmp, p, q, comment
            let n = try rsaMpint(&p)
            let e = try rsaMpint(&p)
            let d = try rsaMpint(&p)
            let iqmp = try rsaMpint(&p)
            let pPrime = try rsaMpint(&p)
            let qPrime = try rsaMpint(&p)
            _ = try p.readString()                  // comment
            let keySize = rsaBitLength(n)
            guard keySize >= 2048 else {
                throw EngineError.keyError("RSA private key is only \(keySize) bits; PKCrypt requires at least 2048 bits")
            }
            return RSAPrivateKeyMaterial(modulusBytes: n.count,
                                         n: Data(n), e: Data(e), d: Data(d),
                                         p: Data(pPrime), q: Data(qPrime), iqmp: Data(iqmp))
        } catch let e as EngineError {
            throw e
        } catch {
            throw EngineError.keyError("could not parse private key: unsupported, malformed, or wrong type")
        }
    }

    // MARK: - RSA-OAEP wrap/unwrap via SecKey (crypto stage -> authFailure, T-02-09)

    /// Wrap a fresh 32-byte session key for an RSA recipient with SecKey
    /// `.rsaEncryptionOAEPSHA256` (SHA-256 OAEP + MGF1-SHA-256 + empty label —
    /// matching the oracle; NEVER a SHA-1 default, Pitfall 3). Returns
    /// `modulusBytes` bytes.
    public static func rsaWrap(sessionKey: Data, publicKey: RSAPublicKeyMaterial) throws -> Data {
        let key = try rsaSecKeyPublic(publicKey)
        var err: Unmanaged<CFError>?
        guard let wrapped = SecKeyCreateEncryptedData(key, .rsaEncryptionOAEPSHA256,
                                                      sessionKey as CFData, &err) as Data? else {
            throw EngineError.authFailure
        }
        return wrapped
    }

    /// Unwrap the session key from a v3 header. ANY OAEP failure (wrong private
    /// key, garbage wrapped key) folds into the single generic `authFailure`,
    /// never a distinct wrongKey case (T-02-09 / D-13; mirrors core.py's
    /// `DECRYPT_FAILED` unification at lines 858-866).
    public static func rsaUnwrap(wrapped: Data, privateKey: RSAPrivateKeyMaterial) throws -> Data {
        let key = try rsaSecKeyPrivate(privateKey)
        var err: Unmanaged<CFError>?
        guard let session = SecKeyCreateDecryptedData(key, .rsaEncryptionOAEPSHA256,
                                                      wrapped as CFData, &err) as Data? else {
            throw EngineError.authFailure
        }
        return session
    }

    // MARK: - SecKey construction + PKCS#1 DER (pre-crypto -> keyError)

    private static func rsaSecKeyPublic(_ mat: RSAPublicKeyMaterial) throws -> SecKey {
        let der = rsaPublicKeyDER(mat)
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(Data(der) as CFData, attrs as CFDictionary, &err) else {
            throw EngineError.keyError("could not import RSA public key (invalid or unsupported)")
        }
        return key
    }

    private static func rsaSecKeyPrivate(_ mat: RSAPrivateKeyMaterial) throws -> SecKey {
        let der = try rsaPrivateKeyDER(mat)
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(Data(der) as CFData, attrs as CFDictionary, &err) else {
            throw EngineError.keyError("could not import RSA private key (invalid or unsupported)")
        }
        return key
    }

    /// PKCS#1 RSAPublicKey ::= SEQUENCE { INTEGER n, INTEGER e }.
    private static func rsaPublicKeyDER(_ m: RSAPublicKeyMaterial) -> [UInt8] {
        derSequence([derInteger([UInt8](m.n)), derInteger([UInt8](m.e))])
    }

    /// PKCS#1 RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }.
    /// dP = d mod (p-1), dQ = d mod (q-1) — macOS may require the CRT params for
    /// OAEP decryption (Pitfall 2). qInv = OpenSSH's iqmp = q^-1 mod p.
    private static func rsaPrivateKeyDER(_ m: RSAPrivateKeyMaterial) throws -> [UInt8] {
        let pLE = toLE([UInt8](m.p))
        let qLE = toLE([UInt8](m.q))
        let pMinus1 = bigSubOne(pLE)
        let qMinus1 = bigSubOne(qLE)
        let dLE = toLE([UInt8](m.d))
        let dP = bigRem(dLE, pMinus1)
        let dQ = bigRem(dLE, qMinus1)
        return derSequence([
            derInteger([0x00]),                      // version = 0
            derInteger([UInt8](m.n)),
            derInteger([UInt8](m.e)),
            derInteger([UInt8](m.d)),
            derInteger([UInt8](m.p)),
            derInteger([UInt8](m.q)),
            derInteger(fromBigEndianLE: dP),
            derInteger(fromBigEndianLE: dQ),
            derInteger([UInt8](m.iqmp)),
        ])
    }

    // MARK: - Minimal ASN.1 DER encoder (format work, not crypto)

    private static func derLength(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        var bytes = [UInt8]()
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return [0x80 | UInt8(bytes.count)] + bytes
    }

    /// DER INTEGER from a big-endian *magnitude* (adds the 0x00 prefix when the
    /// high bit is set so the integer stays positive).
    private static func derInteger(_ magnitudeBE: [UInt8]) -> [UInt8] {
        var v = magnitudeBE
        while v.count > 1 && v[0] == 0x00 { v.removeFirst() }
        if let first = v.first, first & 0x80 != 0 { v.insert(0x00, at: 0) }
        return [0x02] + derLength(v.count) + v
    }

    private static func derInteger(fromBigEndianLE le: [UInt8]) -> [UInt8] {
        derInteger(le.reversed())
    }

    private static func derSequence(_ parts: [[UInt8]]) -> [UInt8] {
        let body = parts.flatMap { $0 }
        return [0x30] + derLength(body.count) + body
    }

    // MARK: - Minimal unsigned big-integer arithmetic (little-endian limbs)

    /// Bit length of a big-endian magnitude (number of significant bits).
    private static func rsaBitLength(_ be: [UInt8]) -> Int {
        var s = 0
        while s < be.count && be[s] == 0x00 { s += 1 }
        if s >= be.count { return 0 }
        let fb = be[s]
        return (be.count - s - 1) * 8 + (8 - fb.leadingZeroBitCount)
    }

    private static func toLE(_ be: [UInt8]) -> [UInt8] { bigNormalize(be.reversed()) }
    private static func bigNormalize(_ a: [UInt8]) -> [UInt8] {
        var r = a
        while r.count > 1 && r.last == 0x00 { r.removeLast() }
        return r.count == 0 ? [0x00] : r
    }
    private static func bigSubOne(_ a: [UInt8]) -> [UInt8] {
        var r = a
        var i = 0
        while i < r.count {
            if r[i] > 0 { r[i] -= 1; break }
            r[i] = 0xFF
            i += 1
        }
        return bigNormalize(r)
    }
    /// `b <= a` (little-endian, normalized).
    private static func bigGE(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        if a.count != b.count { return a.count > b.count }
        for i in (0 ..< a.count).reversed() { if a[i] != b[i] { return a[i] > b[i] } }
        return true
    }
    /// Little-endian × 2.
    private static func bigShl1(_ a: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: a.count + 1)
        var carry: UInt16 = 0
        for i in 0 ..< a.count {
            let v = (UInt16(a[i]) << 1) | carry
            out[i] = UInt8(v & 0xFF)
            carry = v >> 8
        }
        out[a.count] = UInt8(carry & 0xFF)
        return bigNormalize(out)
    }
    /// `a -= b` in place (requires `a >= b`).
    private static func bigSubInPlace(_ a: inout [UInt8], _ b: [UInt8]) {
        var borrow: UInt16 = 0            // borrow INTO the current byte
        for i in 0 ..< a.count {
            let ai: UInt16 = UInt16(a[i])
            let bi: UInt16 = i < b.count ? UInt16(b[i]) : 0
            let subtrahend = bi &+ borrow  // uses INCOMING borrow for this byte
            let outBorrow: UInt16 = ai < subtrahend ? 1 : 0
            a[i] = UInt8((ai &- subtrahend) & 0xFF)
            borrow = outBorrow            // becomes INCOMING for the next byte
        }
        a = bigNormalize(a)
    }
    /// `a mod b` via bitwise long division (only run at key-parse time).
    private static func bigRem(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var r: [UInt8] = [0x00]
        guard !a.isEmpty else { return [0x00] }
        let totalBits = a.count * 8
        for bitIdx in (0 ..< totalBits).reversed() {
            let byteIdx = bitIdx / 8
            let bit = (a[byteIdx] >> (bitIdx % 8)) & 1
            r = bigShl1(r)
            r[0] = r[0] | bit
            if bigGE(r, b) { bigSubInPlace(&r, b) }
        }
        return bigNormalize(r)
    }
}
