// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
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
        let first = String(decoding: data.prefix(64), as: UTF8.self)
        if first.hasPrefix("ssh-ed25519") {
            return .ed25519(try KeyMaterial.parseEd25519Public(data))
        }
        if first.hasPrefix("ssh-rsa") {
            return .rsa(try KeyMaterial.parseRSAPublic(data))
        }
        throw EngineError.keyError("unsupported key type — expected an OpenSSH Ed25519 or RSA key")
    }

    /// Parse an OpenSSH *private* key blob and return the normalized
    /// `CryptPrivateKey` union (`.ed25519`/`.rsa`). Both engine parsers reject
    /// passphrase-protected and malformed/unsupported keys with `keyError`
    /// BEFORE any crypto (D-13) — never `authFailure` — so a wrong-type guess
    /// always lands on a `keyError` from the other parser, and a
    /// passphrase-protected key surfaces the engine's passphrase diagnostic.
    static func detectAndParsePrivate(_ data: Data) throws -> CryptPrivateKey {
        let ed = Result { try KeyMaterial.parseEd25519Private(data) }
        if case .success(let key) = ed { return .ed25519(key) }

        let rsa = Result { try KeyMaterial.parseRSAPrivate(data) }
        if case .success(let key) = rsa { return .rsa(key) }

        // Neither known type parsed. Route a passphrase-protected key to the
        // specific D-13 diagnostic if either parser reported it; otherwise give
        // the generic unsupported/parse guard.
        var details: [String] = []
        if case .failure(let e as EngineError) = ed, case .keyError(let d) = e { details.append(d) }
        if case .failure(let e as EngineError) = rsa, case .keyError(let d) = e { details.append(d) }
        if details.contains(where: { $0.contains("passphrase") }) {
            throw EngineError.keyError("passphrase-protected keys are not supported")
        }
        throw EngineError.keyError(details.first ?? "could not parse private key: unsupported type or format")
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
    /// summary. For a public OpenSSH line the decoded blob is the base64 token;
    /// any other data (e.g. a PEM private key) is hashed as-is. Never echoes the
    /// raw key line/blob (T-03-11).
    static func fingerprint(of data: Data) -> String {
        let blob = decodedBlob(of: data)
        let digest = SHA256.hash(data: blob).prefix(8).map { String(format: "%02x", Int($0)) }.joined()
        return "SHA256:\(digest)"
    }

    /// The OpenSSH key blob to fingerprint: the base64-decoded second token of a
    /// `TYPE <b64> [comment]` public line, else the raw bytes given.
    private static func decodedBlob(of data: Data) -> Data {
        let text = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let parts = text.split(separator: " ").map(String.init)
        if parts.count >= 2, parts[0] == "ssh-ed25519" || parts[0] == "ssh-rsa",
           let b64 = Data(base64Encoded: parts[1]) {
            return b64
        }
        return data
    }
}
