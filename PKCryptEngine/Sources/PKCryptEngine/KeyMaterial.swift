import Foundation
import CryptoKit
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
}
