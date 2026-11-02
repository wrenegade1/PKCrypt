import Foundation
import PKCryptEngine

/// D-07 / D-08 / D-11: auto-detect an OpenSSH key's type and delegate parsing to
/// the engine. This wave supports Ed25519 public keys via the existing engine
/// overload; RSA auto-detect enters through the union facade in Plan 03-03.
/// Comment extraction mirrors the engine's OpenSSH convention: the third+
/// whitespace token of the "TYPE <b64> [comment...]" line.
enum KeySelection {
    /// Parse an OpenSSH public key blob and return an Ed25519 `PublicKeyMaterial`,
    /// delegating to the engine's `KeyMaterial.parseEd25519Public`. A
    /// non-Ed25519/unparseable key throws an `EngineError.keyError` (D-07/D-13).
    static func detectAndParsePublic(_ data: Data) throws -> PublicKeyMaterial {
        try KeyMaterial.parseEd25519Public(data)
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
}
