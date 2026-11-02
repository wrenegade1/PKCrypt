import Testing
import Foundation
@testable import PKCryptEngine

// MARK: - FacadeRoutingTests (Plan 03-02)
//
// Proves RSA encrypt/decrypt and XChaCha20-read reach the app through the
// normalized CryptRecipient / CryptPrivateKey facade unions, so the app never
// goes around the streaming/safety path. Also proves the key/algorithm
// cross-mismatch property (PITFALL #10 / T-03-09): a v2 container fed an RSA
// key (or a v3 fed an Ed25519 key) returns typed `unsupportedFormat`, NOT
// `authFailure`, while every crypto-stage failure (wrong RSA key, tampered/
// truncated v3) folds into the single generic `authFailure`.

@Suite("FacadeRoutingTests — RSA + XChaCha read through the union facade")
struct FacadeRoutingTests {

    // MARK: - RSA encrypt (Task 1)

    @Test("FK: .rsa encrypt yields a v3 PKCRYPT\\x03 container whose wrapped-key length == modulusBytes")
    func fkRsaEncryptProducesV3Container() async throws {
        let d = SafeDir(); defer { d.cleanup() }
        let input = d.file("in")
        try pattern(64).write(to: input)
        let recipient = CryptRecipient.rsa(Fixtures.rsa2048Public)
        let result = await PKCryptEngine.encrypt(fileURL: input, recipient: recipient,
                                                 destinationURL: d.file("out.pkcrypt"))
        guard case .success(let url) = result else {
            Issue.record("expected success, got \(result)")
            return
        }
        #expect(url == d.file("out.pkcrypt"))
        let container = try Data(contentsOf: url)
        #expect(Array(container.prefix(8)) == Array("PKCRYPT\u{03}".utf8),
                "an RSA encrypt must produce a PKCRYPT\\x03 (v3) container")
        // wrapped-key length == modulusBytes (256 for RSA-2048, never hardcoded).
        let rsaHeader = try RSAHeader.parse(container, modulusBytes: Fixtures.rsa2048Material.modulusBytes)
        #expect(Fixtures.rsa2048Material.modulusBytes == 256)
        #expect(rsaHeader.wrappedKey.count == Fixtures.rsa2048Material.modulusBytes)
        #expect(rsaHeader.cipher == ContainerCodec.cipherAES, "facade RSA write is AES-GCM (cipher 0x00)")
    }

    @Test("FK: two RSA encrypts of identical plaintext differ in wrapped-key AND ciphertext bytes")
    func fkRsaEncryptNonDeterministic() async throws {
        let d = SafeDir(); defer { d.cleanup() }
        let input = d.file("in")
        try pattern(64).write(to: input)
        let recipient = CryptRecipient.rsa(Fixtures.rsa2048Public)
        let r1 = await PKCryptEngine.encrypt(fileURL: input, recipient: recipient,
                                             destinationURL: d.file("c1.pkcrypt"))
        let r2 = await PKCryptEngine.encrypt(fileURL: input, recipient: recipient,
                                             destinationURL: d.file("c2.pkcrypt"))
        guard case .success = r1, case .success = r2 else {
            Issue.record("expected both RSA encrypts to succeed")
            return
        }
        let c1 = try Data(contentsOf: d.file("c1.pkcrypt"))
        let c2 = try Data(contentsOf: d.file("c2.pkcrypt"))
        let h1 = try RSAHeader.parse(c1, modulusBytes: Fixtures.rsa2048Material.modulusBytes)
        let h2 = try RSAHeader.parse(c2, modulusBytes: Fixtures.rsa2048Material.modulusBytes)
        #expect(h1.wrappedKey != h2.wrappedKey,
                "a fresh random 32-byte session key per encrypt must produce different wrapped keys (T-02-17)")
        #expect(c1 != c2, "a fresh session key/nonce must produce different full containers")
    }

    @Test("FK: RSA encrypt publishes only after full success; a pre-existing destination returns destinationExists (no overwrite)")
    func fkRsaEncryptPublishesOnlyOnSuccessAndNoClobber() async throws {
        let d = SafeDir(); defer { d.cleanup() }
        let input = d.file("in")
        try pattern(64).write(to: input)
        let recipient = CryptRecipient.rsa(Fixtures.rsa2048Public)

        // Pre-existing destination must NOT be overwritten -> `.destinationExists`.
        let dest = d.file("out.pkcrypt")
        try Data("occupied".utf8).write(to: dest)
        let result = await PKCryptEngine.encrypt(fileURL: input, recipient: recipient, destinationURL: dest)
        guard case .failure(let err) = result else {
            Issue.record("expected destinationExists on a collision, got \(result)")
            return
        }
        #expect(err == .destinationExists, "no clobber: an existing destination yields .destinationExists")
        #expect(try Data(contentsOf: dest) == Data("occupied".utf8), "the existing file must stay untouched")
        #expect(d.tempArtifacts().isEmpty, "a destinationExists run must leave no .tmp")

        // A fresh destination publishes in full.
        let ok = await PKCryptEngine.encrypt(fileURL: input, recipient: recipient,
                                             destinationURL: d.file("ok.pkcrypt"))
        #expect(ok == .success(d.file("ok.pkcrypt")))
        #expect(d.tempArtifacts().isEmpty)
    }
}
