// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Testing
import Foundation
@testable import PKCryptEngine

/// Regression tests for the security-review findings: malformed RSA public
/// numbers, a wrong-length RSA-unwrapped session key, and wrong-length
/// XChaCha20 key/nonce buffers handed to libsodium.
@Suite("Security hardening")
struct SecurityHardeningTests {
    private static func sshString(_ d: Data) -> Data {
        var len = UInt32(d.count).bigEndian
        return Data(bytes: &len, count: 4) + d
    }
    private static func mpint(_ d: Data) -> Data {
        let m = Data(d.drop(while: { $0 == 0 }))
        return sshString((m.first ?? 0) & 0x80 != 0 ? Data([0]) + m : m)
    }
    /// A synthetic `ssh-rsa` public key line with the given exponent and modulus.
    private static func rsaLine(e: Data, n: Data) -> Data {
        let blob = sshString(Data("ssh-rsa".utf8)) + mpint(e) + mpint(n)
        return Data("ssh-rsa \(blob.base64EncodedString()) synthetic".utf8)
    }
    private static func isAuthFailure(_ body: () throws -> Void) -> Bool {
        do { try body() } catch EngineError.authFailure { return true } catch { return false }
        return false
    }

    @Test("rsaPublicNumbersOK accepts a real key and rejects malformed numbers")
    func rsaNumbers() {
        let n = [UInt8](Fixtures.rsa2048Public.n), e = [UInt8](Fixtures.rsa2048Public.e)
        #expect(KeyMaterial.rsaPublicNumbersOK(n: n, e: e))
        #expect(!KeyMaterial.rsaPublicNumbersOK(n: n, e: [1]))           // identity
        #expect(!KeyMaterial.rsaPublicNumbersOK(n: n, e: [2]))           // even, < 3
        #expect(!KeyMaterial.rsaPublicNumbersOK(n: n, e: [1, 0, 0]))     // 65536: even
        #expect(!KeyMaterial.rsaPublicNumbersOK(n: n, e: n))             // e = n
        var evenN = n; evenN[evenN.count - 1] &= 0xFE
        #expect(!KeyMaterial.rsaPublicNumbersOK(n: evenN, e: e))         // even modulus
        #expect(!KeyMaterial.rsaPublicNumbersOK(n: [], e: e))
    }

    @Test("parseRSAPublic refuses an e = 1 key with a keyError")
    func parseRejectsIdentityExponent() {
        let line = Self.rsaLine(e: Data([1]), n: Fixtures.rsa2048Public.n)
        do {
            _ = try KeyMaterial.parseRSAPublic(line)
            Issue.record("an e = 1 RSA key must be refused")
        } catch EngineError.keyError(let detail) {
            #expect(detail.contains("invalid RSA public key"))
        } catch {
            Issue.record("expected keyError, got \(error)")
        }
    }

    @Test("rsaUnwrap refuses a session key that is not 32 bytes")
    func unwrapRejectsWrongLength() throws {
        let wrapped = try KeyMaterial.rsaWrap(sessionKey: Data(repeating: 7, count: 16),
                                              publicKey: Fixtures.rsa2048Public)
        #expect(Self.isAuthFailure {
            _ = try KeyMaterial.rsaUnwrap(wrapped: wrapped, privateKey: Fixtures.rsa2048Material)
        })
    }

    @Test("xchacha20Decrypt refuses short key or nonce buffers instead of over-reading")
    func xchachaRejectsShortBuffers() {
        let ct = Data(repeating: 0, count: 32)
        #expect(Self.isAuthFailure {
            _ = try XChaCha20ChunkCrypto.xchacha20Decrypt(ciphertextAndTag: ct, aad: Data(),
                                                          nonce: Data(count: 24), key: Data(count: 16))
        })
        #expect(Self.isAuthFailure {
            _ = try XChaCha20ChunkCrypto.xchacha20Decrypt(ciphertextAndTag: ct, aad: Data(),
                                                          nonce: Data(count: 12), key: Data(count: 32))
        })
        #expect(Self.isAuthFailure {
            _ = try XChaCha20ChunkCrypto.xchacha20Decrypt(ciphertextAndTag: Data(count: 8), aad: Data(),
                                                          nonce: Data(count: 24), key: Data(count: 32))
        })
    }
}
