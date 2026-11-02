import Foundation
import CryptoKit
import PKCryptEngine

/// D-07 / D-08 / D-11: auto-detect an OpenSSH key's type and delegate parsing to
/// the engine. This wave issues `detectAndParsePublic/Private` through the union
/// facade (`CryptRecipient`/`CryptPrivateKey`), auto-detecting Ed25519 vs RSA
/// from the leading type token. Comment extraction mirrors the engine's OpenSSH
/// convention (the third+ whitespace token of the "TYPE <b64> [comment]" line);
/// the fingerprint is an engine-independent 8-byte truncated SHA-256 hex digest
/// of the decoded blob (RESEARCH Open Question 2), so the UI never renders a
/// raw key.
enum KeySelection {
    /// Parse an OpenSSH *public* key blob (`ssh-ed25519 <b64> [comment]` /
    /// `ssh-rsa <b64> [comment]`) and return the normalized `CryptRecipient`
    /// union. An unknown/unsupported type, malformed blob, or passphrase guard
    /// throws `EngineError.keyError` (D-07 / D-13) — never `authFailure`.
    static func detectAndParsePublic(_ data: Data) throws -> CryptRecipient {
        if String(decoding: data.prefix(64), as: UTF8.self).hasPrefix("ssh-ed25519") {
            return .ed25519(try KeyMaterial.parseEd25519Public(data))
        }
        throw EngineError.keyError("not implemented (stub)")
    }

    /// Parse an OpenSSH *private* key blob and return the normalized
    /// `CryptPrivateKey` union (`.ed25519`/`.rsa`). Passphrase-protected and
    /// malformed/unsupported keys throw `EngineError.keyError` (D-13), never
    /// `authFailure`.
    static func detectAndParsePrivate(_ data: Data) throws -> CryptPrivateKey {
        throw EngineError.keyError("not implemented (stub)")
    }

    /// The key's comment (the third+ whitespace token of the OpenSSH line), for
    /// the D-08/D-11 recipient/private-key identity summary.
    static func comment(of data: Data) -> String? {
        let text = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = text.split(separator: " ").map(String.init)
        guard parts.count >= 3 else { return nil }
        return parts.dropFirst(2).joined(separator: " ")
    }

    /// An 8-byte truncated SHA-256 hex digest of a key's decoded blob, formatted
    /// as `SHA256:<16-hex-chars>` — a compact, stable identity for the D-08/D-11
    /// summary. Never echoes the raw key line/blob (T-03-11).
    static func fingerprint(of data: Data) -> String {
        "SHA256:"
    }
}
