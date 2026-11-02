import XCTest
@testable import CryptFile
import PKCryptEngine

/// D-20 / FILE-04: `UserMessage.message(for:)` is the single seam every engine
/// failure passes through. `authFailure` must map to the fixed generic tuple and
/// never reveal a technical reason (T-03-02 / PITFALL #9); the typed cases must
/// surface their detail (including the D-13 passphrase guard).
final class ErrorMessageTests: XCTestCase {

    func testAuthFailureIsGenericAndLeaksNoDetail() {
        let msg = UserMessage.message(for: .authFailure)
        XCTAssertEqual(msg.title, "Couldn't decrypt")
        XCTAssertEqual(msg.detail, "Wrong key or corrupted file.")
    }

    func testAuthFailureHasNoTechnicalDetail() {
        let msg = UserMessage.message(for: .authFailure)
        let combined = (msg.title + " " + (msg.detail ?? "")).lowercased()
        for technical in ["tag mismatch", "truncated", "appended", "ed25519", "rsa",
                          "oaep", "aead", "ecdh", "x25519", "hkdf", "ciphertext"] {
            XCTAssertFalse(combined.contains(technical),
                           "authFailure must not leak technical detail: \(technical)")
        }
    }

    func testKeyErrorSurfacesTypedDetail() {
        let msg = UserMessage.message(for: .keyError("passphrase-protected keys are not supported"))
        XCTAssertEqual(msg.title, "Invalid key")
        XCTAssertEqual(msg.detail, "passphrase-protected keys are not supported")
    }

    func testUnsupportedFormatSurfacesDetail() {
        let msg = UserMessage.message(for: .unsupportedFormat("unknown container version"))
        XCTAssertEqual(msg.title, "Unsupported file")
        XCTAssertEqual(msg.detail, "unknown container version")
    }

    func testPermissionErrorSurfacesDetail() {
        let msg = UserMessage.message(for: .permissionError("destination is not writable"))
        XCTAssertEqual(msg.title, "Can't write there")
        XCTAssertEqual(msg.detail, "destination is not writable")
    }

    func testIOErrorSurfacesDetail() {
        let msg = UserMessage.message(for: .ioError("read failed"))
        XCTAssertEqual(msg.title, "File error")
        XCTAssertEqual(msg.detail, "read failed")
    }

    func testDestinationExistsRoutesToAlternateNameMessage() {
        let msg = UserMessage.message(for: .destinationExists)
        XCTAssertEqual(msg.title, "File already exists")
        XCTAssertEqual(msg.detail, "Choose a different name or location.")
    }

    func testCancelledMessage() {
        let msg = UserMessage.message(for: .cancelled)
        XCTAssertEqual(msg.title, "Cancelled")
        XCTAssertNil(msg.detail, "cancelled has no detail; the flat 'Cancelled' note is rendered")
    }
}
