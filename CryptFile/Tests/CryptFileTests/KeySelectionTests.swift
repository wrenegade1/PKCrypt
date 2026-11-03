// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import XCTest
import CryptoKit
@testable import CryptFile
import PKCryptEngine

/// RSA fixture accessors (Fixtures/RSA under the engine test tree), layered onto
/// the shared `TestFixtures` enum so KeySelectionTests exercises Ed25519 AND RSA.
extension TestFixtures {
    static let rsaPublicFile = fixtureDir.appendingPathComponent("RSA/rsa2048.pub")
    static let rsaPrivateFile = fixtureDir.appendingPathComponent("RSA/rsa2048")
    static let rsaOtherPublicFile = fixtureDir.appendingPathComponent("RSA/rsa2048_other.pub")
    static let rsaPublicData: Data = try! Data(contentsOf: rsaPublicFile)
    static let rsaPrivateData: Data = try! Data(contentsOf: rsaPrivateFile)
    static let rsaOtherPublicData: Data = try! Data(contentsOf: rsaOtherPublicFile)
}

/// D-07 / D-11 / D-12 / D-13: feeding the committed Ed25519 + RSA fixtures
/// through `KeySelection` / the engine parsers — Ed+RSA auto-detect, comment
/// extraction (D-08/D-11 identity summary), an 8-byte truncated SHA-256
/// fingerprint (never the raw blob), and passphrase-protected/malformed-key
/// rejection as a typed `keyError` (D-13) rather than `authFailure`.
final class KeySelectionTests: XCTestCase {

    // MARK: - Public-key auto-detect (D-07)

    func testParsesEd25519PublicViaKeySelection() throws {
        let recipient = try KeySelection.detectAndParsePublic(TestFixtures.publicKeyData)
        guard case .ed25519(let mat) = recipient else {
            return XCTFail("expected .ed25519, got \(recipient)")
        }
        XCTAssertEqual(mat.ed25519Public.count, 32)
    }

    func testDetectAndParsePublicAutoDetectsRSA() throws {
        let recipient = try KeySelection.detectAndParsePublic(TestFixtures.rsaPublicData)
        guard case .rsa(let mat) = recipient else {
            return XCTFail("expected .rsa, got \(recipient)")
        }
        XCTAssertEqual(mat.modulusBytes, 256, "RSA-2048 -> 256 modulus bytes")
    }

    func testDetectAndParsePublicUnknownTypeThrowsKeyError() {
        let unknown = Data("ssh-dsa REMOVED-TEST-KEY".utf8)
        let error = extractError { _ = try KeySelection.detectAndParsePublic(unknown) }
        guard case .keyError(let detail)? = error else {
            return XCTFail("expected .keyError for an unknown key type, got \(String(describing: error))")
        }
        XCTAssertTrue(detail.lowercased().contains("unsupported"),
                      "the keyError detail should say the type is unsupported: \(detail)")
    }

    // MARK: - Private-key auto-detect (D-11)

    func testDetectAndParsePrivateAutoDetectsEd25519() throws {
        let key = try KeySelection.detectAndParsePrivate(TestFixtures.privateKeyData)
        guard case .ed25519(let mat) = key else {
            return XCTFail("expected .ed25519, got \(key)")
        }
        XCTAssertEqual(mat.seed.count, 32)
        XCTAssertEqual(mat.ed25519Public.count, 32)
    }

    func testDetectAndParsePrivateAutoDetectsRSA() throws {
        let key = try KeySelection.detectAndParsePrivate(TestFixtures.rsaPrivateData)
        guard case .rsa(let mat) = key else {
            return XCTFail("expected .rsa, got \(key)")
        }
        XCTAssertEqual(mat.modulusBytes, 256, "RSA-2048 private -> 256 modulus bytes")
    }

    func testDetectAndParsePrivatePassphraseProtectedThrowsKeyError() {
        // A passphrase-protected key (cipher/KDF != "none"/"none") must surface a
        // typed keyError (D-13) via detectAndParsePrivate — never authFailure.
        let blob = opensshKeyV1Blob(cipher: "aes256-ctr", kdf: "bcrypt")
        let pemText = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + blob.base64EncodedString()
            + "\n-----END OPENSSH PRIVATE KEY-----\n"
        let data = Data(pemText.utf8)

        let error = extractError { _ = try KeySelection.detectAndParsePrivate(data) }
        guard case .keyError? = error else {
            return XCTFail("expected .keyError for a passphrase-protected key, got \(String(describing: error))")
        }
    }

    // MARK: - Comment + fingerprint identity summary (D-08 / D-11)

    func testCommentExtraction() {
        XCTAssertEqual(KeySelection.comment(of: TestFixtures.publicKeyData),
                       "pkcrypt-engine-fixture@local")
        XCTAssertEqual(KeySelection.comment(of: TestFixtures.rsaPublicData),
                       "rsa2048@pkcrypt-test")
        XCTAssertNil(KeySelection.comment(of: Data("ssh-ed25519 REMOVED-TEST-KEY".utf8)),
                     "a key line with no comment returns nil")
    }

    func testFingerprintEightByteSHA256HexNoRawBlob() {
        let fp = KeySelection.fingerprint(of: TestFixtures.publicKeyData)
        XCTAssertTrue(fp.hasPrefix("SHA256:"), "fingerprint carries the SHA256: prefix")
        let hex = String(fp.dropFirst("SHA256:".count))
        XCTAssertEqual(hex.count, 16, "fingerprint truncated to 8 bytes = 16 hex chars")

        // Independent verification of the documented spec: SHA-256 of the decoded
        // OpenSSH blob, first 8 bytes, lowercase hex.
        let line = String(decoding: TestFixtures.publicKeyData, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let decoded = Data(base64Encoded: String(line.split(separator: " ")[1]))!
        let expected = SHA256.hash(data: decoded).prefix(8).map { String(format: "%02x", Int($0)) }.joined()
        XCTAssertEqual(hex, expected, "fingerprint must be SHA-256 of the decoded blob, truncated to 8 bytes")

        // Determinism + distinctness across keys.
        XCTAssertEqual(KeySelection.fingerprint(of: TestFixtures.publicKeyData), fp)
        XCTAssertNotEqual(KeySelection.fingerprint(of: TestFixtures.rsaPublicData),
                          KeySelection.fingerprint(of: TestFixtures.rsaOtherPublicData),
                          "different RSA keys must yield different fingerprints")

        // The fingerprint must never echo the raw key line/blob (T-03-11).
        XCTAssertFalse(fp.contains(line), "fingerprint must not echo the raw key line/blob")
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
    /// cipher/KDF names (structure only — the passphrase-protection guard in the
    /// engine parsers fires on the cipher/KDF pair before blob contents matter).
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
