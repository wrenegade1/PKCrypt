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

    private static func isUnsupported(_ e: EngineError) -> Bool {
        if case .unsupportedFormat = e { return true }
        return false
    }

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

    // MARK: - RSA decrypt + XChaCha read + cross-algorithm rejection (Task 2)

    @Test("FK: .rsa decrypt recovers plaintext from v3 AES-GCM containers at 0/1MiB/1MiB+1, RSA-2048 and RSA-4096")
    func fkRsaDecryptRecoversPlaintext() async throws {
        let cases: [(String, Int, RSAPrivateKeyMaterial)] = [
            ("rsa2048_empty", 0, Fixtures.rsa2048Material),
            ("rsa2048_1MiB", 1 << 20, Fixtures.rsa2048Material),
            ("rsa2048_1MiBplus1", (1 << 20) + 1, Fixtures.rsa2048Material),
            ("rsa4096_empty", 0, Fixtures.rsa4096Material),
            ("rsa4096_1MiB", 1 << 20, Fixtures.rsa4096Material),
            ("rsa4096_1MiBplus1", (1 << 20) + 1, Fixtures.rsa4096Material),
        ]
        for (name, n, key) in cases {
            let d = SafeDir(); defer { d.cleanup() }
            try Fixtures.rsaContainer(name).write(to: d.file("in.pkcrypt"))
            let result = await PKCryptEngine.decrypt(containerURL: d.file("in.pkcrypt"),
                                                     privateKey: .rsa(key),
                                                     destinationURL: d.file("out"))
            guard case .success = result else {
                Issue.record("\(name): expected success, got \(result)")
                continue
            }
            #expect(try Data(contentsOf: d.file("out")) == pattern(n),
                    "rsa \(name) recovered != original (\(n) bytes)")
            #expect(d.tempArtifacts().isEmpty, "\(name): no .tmp may remain")
        }
    }

    @Test("FK: XChaCha20 (cipher 0x01) v2 and v3 containers decrypt through the facade via libsodium ietf_decrypt")
    func fkXChaChaReadViaFacade() async throws {
        // v3 RSA XChaCha (read-only; no encrypt path is exposed).
        let d1 = SafeDir(); defer { d1.cleanup() }
        try Fixtures.rsaContainer("rsa2048_xc_1MiB").write(to: d1.file("in.pkcrypt"))
        let r = await PKCryptEngine.decrypt(containerURL: d1.file("in.pkcrypt"),
                                            privateKey: .rsa(Fixtures.rsa2048Material),
                                            destinationURL: d1.file("out"))
        guard case .success = r else { Issue.record("v3 XChaCha decrypt failed: \(r)"); return }
        #expect(try Data(contentsOf: d1.file("out")) == pattern(1 << 20))
        #expect(d1.tempArtifacts().isEmpty)

        // v2 Ed25519 XChaCha.
        let d2 = SafeDir(); defer { d2.cleanup() }
        try Fixtures.container("xc_ed_1MiB").write(to: d2.file("in.pkcrypt"))
        let r2 = await PKCryptEngine.decrypt(containerURL: d2.file("in.pkcrypt"),
                                             privateKey: .ed25519(Fixtures.privateKey),
                                             destinationURL: d2.file("out"))
        guard case .success = r2 else { Issue.record("v2 XChaCha decrypt failed: \(r2)"); return }
        #expect(try Data(contentsOf: d2.file("out")) == pattern(1 << 20))
        #expect(d2.tempArtifacts().isEmpty)
    }

    @Test("FK: v2-container/RSA-key and v3-container/Ed25519-key mismatches return typed unsupportedFormat — NOT authFailure")
    func fkCrossAlgorithmMismatchIsTyped() async throws {
        // v2 container + RSA private key -> typed unsupportedFormat (PITFALL #10).
        let d1 = SafeDir(); defer { d1.cleanup() }
        try Fixtures.container("1MiB").write(to: d1.file("in.pkcrypt"))
        let r = await PKCryptEngine.decrypt(containerURL: d1.file("in.pkcrypt"),
                                            privateKey: .rsa(Fixtures.rsa2048Material),
                                            destinationURL: d1.file("out"))
        guard case .failure(let err) = r else { Issue.record("expected failure, got \(r)"); return }
        #expect(Self.isUnsupported(err), "a v2/RSA mismatch is a typed unsupportedFormat, got \(err)")
        #expect(!FileManager.default.fileExists(atPath: d1.file("out").path))

        // v3 container + Ed25519 private key -> typed unsupportedFormat.
        let d2 = SafeDir(); defer { d2.cleanup() }
        try Fixtures.rsaContainer("rsa2048_empty").write(to: d2.file("in.pkcrypt"))
        let r2 = await PKCryptEngine.decrypt(containerURL: d2.file("in.pkcrypt"),
                                             privateKey: .ed25519(Fixtures.privateKey),
                                             destinationURL: d2.file("out"))
        guard case .failure(let err2) = r2 else { Issue.record("expected failure, got \(r2)"); return }
        #expect(Self.isUnsupported(err2), "a v3/Ed25519 mismatch is a typed unsupportedFormat, got \(err2)")
        #expect(!FileManager.default.fileExists(atPath: d2.file("out").path))
    }

    @Test("FK: wrong RSA key and tampered/truncated v3 return the single generic authFailure with no destination")
    func fkRsaWrongKeyAndTamperReturnAuthFailure() async throws {
        // Wrong same-size RSA key -> generic authFailure, no dest, no .tmp.
        let d1 = SafeDir(); defer { d1.cleanup() }
        try Fixtures.rsaContainer("rsa2048_1MiB").write(to: d1.file("in.pkcrypt"))
        let wrong = await PKCryptEngine.decrypt(containerURL: d1.file("in.pkcrypt"),
                                                privateKey: .rsa(Fixtures.rsaOtherMaterial),
                                                destinationURL: d1.file("out"))
        guard case .failure(let werr) = wrong else { Issue.record("expected authFailure, got \(wrong)"); return }
        #expect(werr == .authFailure, "wrong RSA key must fold into the single generic authFailure (T-02-09)")
        #expect(!FileManager.default.fileExists(atPath: d1.file("out").path))
        #expect(d1.tempArtifacts().isEmpty)

        // Tampered v3 (flip a mid-body byte) -> authFailure, no dest.
        let d2 = SafeDir(); defer { d2.cleanup() }
        var tampered = try Fixtures.rsaContainer("rsa2048_1MiBplus1")
        tampered[tampered.count / 2] ^= 0xFF
        try tampered.write(to: d2.file("in.pkcrypt"))
        let t = await PKCryptEngine.decrypt(containerURL: d2.file("in.pkcrypt"),
                                            privateKey: .rsa(Fixtures.rsa2048Material),
                                            destinationURL: d2.file("out"))
        guard case .failure(let terr) = t else { Issue.record("expected authFailure, got \(t)"); return }
        #expect(terr == .authFailure)
        #expect(!FileManager.default.fileExists(atPath: d2.file("out").path))
        #expect(d2.tempArtifacts().isEmpty)

        // Truncated v3 (cut the final tag) -> authFailure, no dest.
        let d3 = SafeDir(); defer { d3.cleanup() }
        var truncated = try Fixtures.rsaContainer("rsa2048_1MiBplus1")
        truncated.removeLast(5)
        try truncated.write(to: d3.file("in.pkcrypt"))
        let tr = await PKCryptEngine.decrypt(containerURL: d3.file("in.pkcrypt"),
                                             privateKey: .rsa(Fixtures.rsa2048Material),
                                             destinationURL: d3.file("out"))
        guard case .failure(let trerr) = tr else { Issue.record("expected authFailure, got \(tr)"); return }
        #expect(trerr == .authFailure)
        #expect(!FileManager.default.fileExists(atPath: d3.file("out").path))
        #expect(d3.tempArtifacts().isEmpty)
    }
}
