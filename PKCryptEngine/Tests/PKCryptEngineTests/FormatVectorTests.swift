import Testing
import Foundation
import CSodium

// MARK: - Test helpers (hex)

extension Data {
    init?(hex: String) {
        var out = [UInt8]()
        var s = hex
        while s.count >= 2 {
            let end = s.index(s.startIndex, offsetBy: 2)
            guard let b = UInt8(s[s.startIndex..<end], radix: 16) else { return nil }
            out.append(b)
            s = String(s[end...])
        }
        guard s.isEmpty else { return nil }
        self.init(out)
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Task 1: libsodium static-link + single-FFI-call smoke

/// Proves the statically-linked libsodium archive (Phase-1 A5) is actually in
/// the binary and that the one FFI call REQUIRED by the engine works with a
/// known vector: the committed fixture Ed25519 public key converts to the known
/// X25519 public key previously derived by the Python oracle (26-PASS baseline).
@Suite("libsodium FFI + static link")
struct LibsodiumLinkSmokeTests {

    @Test("sodium_init returns 0/1 and pk_to_curve matches the oracle x_pub")
    func libsodiumLinkSmoke() throws {
        // sodium_init returns 0 or 1 (1 if already initialized); must not crash.
        let initRC = sodium_init()
        #expect(initRC == 0 || initRC == 1)

        // Committed fixture Ed25519 public key (ed25519_fixture.pub raw bytes).
        let edPub = try #require(Data(hex: "REMOVED-TEST-KEY"))
        var out = [UInt8](repeating: 0, count: 32)
        let rc = edPub.withUnsafeBytes { edBuf -> Int32 in
            crypto_sign_ed25519_pk_to_curve25519(
                &out,
                edBuf.bindMemory(to: UInt8.self).baseAddress!
            )
        }
        #expect(rc == 0)
        #expect(out.count == 32)

        // Must equal the Python oracle's `ed25519_public_to_x25519_public` output.
        let expected = "REMOVED-TEST-KEY"
        #expect(Data(out).hexString == expected)
    }
}
