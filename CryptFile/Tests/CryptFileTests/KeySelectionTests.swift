import XCTest
@testable import CryptFile
import PKCryptEngine

/// D-07 / D-11 / D-12 / D-13: feeding the committed Ed25519 fixtures through
/// `KeySelection` / the engine parsers — parse success, comment extraction
/// (D-08/D-11 identity summary), and passphrase-protected-key rejection as a
/// typed `keyError` (D-13) rather than `authFailure`.
final class KeySelectionTests: XCTestCase {

    func testParsesEd25519PublicViaKeySelection() throws {
        let key = try KeySelection.detectAndParsePublic(TestFixtures.publicKeyData)
        XCTAssertEqual(key.ed25519Public.count, 32)
    }

    func testParsesEd25519PrivateViaEngine() throws {
        let priv = try KeyMaterial.parseEd25519Private(TestFixtures.privateKeyData)
        XCTAssertEqual(priv.seed.count, 32)
        XCTAssertEqual(priv.ed25519Public.count, 32)
    }

    func testCommentExtraction() {
        XCTAssertEqual(KeySelection.comment(of: TestFixtures.publicKeyData),
                       "pkcrypt-engine-fixture@local")
        XCTAssertNil(KeySelection.comment(of: Data("ssh-ed25519 REMOVED-TEST-KEY".utf8)),
                     "a key line with no comment returns nil")
    }

    func testPassphraseProtectedPrivateKeyRejectedAsKeyError() {
        // Craft an openssh-key-v1 blob whose cipher/KDF are NOT "none"/"none",
        // PEM-armored the way a real OpenSSH private key file is: the engine
        // rejects it BEFORE any crypto with keyError (D-13), never authFailure.
        let blob = opensshKeyV1Blob(cipher: "aes256-ctr", kdf: "bcrypt")
        let pemText = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + blob.base64EncodedString()
            + "\n-----END OPENSSH PRIVATE KEY-----\n"
        let data = Data(pemText.utf8)

        let error = extractError { try KeyMaterial.parseEd25519Private(data) }
        guard case .keyError(let detail)? = error else {
            return XCTFail("expected .keyError for a passphrase-protected key, got \(String(describing: error))")
        }
        XCTAssertTrue(detail.contains("passphrase"),
                      "the keyError detail should reference the passphrase limitation: \(detail)")
    }

    // MARK: - helpers

    /// Runs a throwing closure and returns the error (or nil on success) as an
    /// `EngineError` when possible.
    private func extractError(_ body: () throws -> Void) -> EngineError? {
        do { try body(); return nil }
        catch let e as EngineError { return e }
        catch { return .ioError(String(describing: error)) }
    }

    /// Builds an OpenSSH `openssh-key-v1` private-key blob with the given
    /// cipher/KDF names (structure only — the passphrase-protection guard in
    /// `parseEd25519Private` fires on the cipher/KDF pair before blob contents matter).
    private func opensshKeyV1Blob(cipher: String, kdf: String) -> Data {
        var out = Data()
        out.append(contentsOf: "openssh-key-v1\u{0}".utf8)
        out.append(contentsOf: pkcryptLengthPrefixed(cipher))
        out.append(contentsOf: pkcryptLengthPrefixed(kdf))
        out.append(contentsOf: pkcryptLengthPrefixed(""))                     // kdfoptions
        out.append(contentsOf: pkcryptBigEndianData(UInt32(1)))               // nkeys
        out.append(contentsOf: pkcryptLengthPrefixed(String(repeating: "A", count: 8)))  // public blob
        out.append(contentsOf: pkcryptLengthPrefixed(String(repeating: "B", count: 8)))  // private blob
        return out
    }
}

/// Big-endian length-prefixed OpenSSH byte string (4-byte length + bytes),
/// built as standalone helpers to avoid a naming clash with Foundation's `Data.append`.
private func pkcryptLengthPrefixed(_ s: String) -> [UInt8] {
    let bytes = Array(s.utf8)
    return pkcryptBigEndianData(UInt32(bytes.count)) + bytes
}

private func pkcryptBigEndianData(_ value: UInt32) -> [UInt8] {
    [UInt8((value >> 24) & 0xff), UInt8((value >> 16) & 0xff),
     UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
}


