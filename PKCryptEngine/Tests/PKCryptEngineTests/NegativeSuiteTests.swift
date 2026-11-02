import Testing
import Foundation
import CryptoKit
@testable import PKCryptEngine

// MARK: - NegativeSuiteTests (SAFE-01)
//
// Proves — not asserts — that every malformed-input class is rejected with the
// single generic EngineError.authFailure and that NO plaintext is ever published:
//
//   * truncation at EVERY chunk-count prefix (0..N blocks) and cutting inside the
//     final block
//   * appended / replayed / reordered data  (replay final block, append a non-final
//     block, a single trailing byte)
//   * single-byte tamper at the start / middle / end of a container
//   * wrong private key (same scheme) and cross-scheme rejection
//
// For the Ed25519 (v2/AES-GCM) path the malformed containers are driven through the
// REAL public async facade (PKCryptEngine.decrypt), so these are true end-to-end
// SAFE-01 assertions: `authFailure`, no destination file, and no `.tmp` artifact in
// the destination directory (the hold-back/lookahead guarantee under test, T-02-14).
// The RSA (v3/AES-GCM) path reuses the identical stream state machine via RSAPipe and
// asserts the same single generic authFailure.
//
// The plan's must-have: every rejected path leaves the destination absent and no .tmp.

@Suite("NegativeSuiteTests — SAFE-01")
struct NegativeSuiteTests {

    static let chunkLen = ContainerCodec.defaultChunkLen   // 1 MiB
    static let blockSize = ContainerCodec.defaultChunkLen + ContainerCodec.tagBytes   // 1048592
    static let edHeaderSize = ContainerCodec.prefixBytes + ContainerCodec.ephPubBytes
        + ContainerCodec.nonceAES + ContainerCodec.chunkLenBytes   // 58

    // MARK: - container builders

    /// Split a container into (header, body-blocks) given the header size and block size.
    static func split(_ container: Data, headerSize: Int) -> (header: Data, blocks: [Data]) {
        let header = Data(container.prefix(headerSize))
        let body = Data(container[headerSize...])
        var blocks: [Data] = []
        var off = 0
        while off < body.count {
            let end = Swift.min(off + blockSize, body.count)
            blocks.append(body.subdata(in: off ..< end))
            off = end
        }
        return (header, blocks)
    }

    static func concat(_ parts: [Data]) -> Data {
        parts.reduce(Data(), { $0 + $1 })
    }

    /// Build a 3-chunk Ed25519 v2 AES-GCM container through the real facade.
    static func ed25519Container3Chunk() async throws -> Data {
        let input = FileManager.default.temporaryDirectory
            .appendingPathComponent("neg-in-\(UUID().uuidString)")
        try pattern(3 * chunkLen).write(to: input)
        defer { try? FileManager.default.removeItem(at: input) }
        let out = FileManager.default.temporaryDirectory
            .appendingPathComponent("neg-\(UUID().uuidString).pkcrypt")
        _ = try await PKCryptEngine.encrypt(fileURL: input, recipient: Fixtures.publicKey,
                                            destinationURL: out).get()
        defer { try? FileManager.default.removeItem(at: out) }
        return try Data(contentsOf: out)
    }

    /// A distinct Ed25519 private key (never the container's recipient) for wrong-key tests.
    static var wrongEd25519Key: PrivateKeyMaterial {
        let fresh = Curve25519.Signing.PrivateKey()
        return PrivateKeyMaterial(seed: fresh.rawRepresentation,
                                  ed25519Public: fresh.publicKey.rawRepresentation)
    }

    // MARK: - facade rejection helper (authFailure + no dest + no .tmp)

    /// Drive a malformed container through the real async facade and assert rejection.
    func assertFacadeRejects(_ container: Data, privateKey: PrivateKeyMaterial,
                             dir: SafeDir, label: String) async {
        try? container.write(to: dir.file("in.pkcrypt"))
        let result = await PKCryptEngine.decrypt(containerURL: dir.file("in.pkcrypt"),
                                                 privateKey: privateKey,
                                                 destinationURL: dir.file("out"))
        guard case .failure(let err) = result else {
            Issue.record("\(label): expected authFailure, got SUCCESS (plaintext PUBLISHED!)")
            return
        }
        #expect(err == .authFailure, "\(label): expected authFailure, got \(err)")
        #expect(!FileManager.default.fileExists(atPath: dir.file("out").path),
                "\(label): destination must stay absent (no plaintext published)")
        #expect(dir.tempArtifacts().isEmpty,
                "\(label): no .tmp artifact may remain in the destination directory")
    }

    // MARK: - Ed25519 truncation at EVERY chunk-count prefix + inside the final block

    @Test("Ed25519: truncation at every chunk-count prefix AND inside the final block -> authFailure, no dest, no .tmp")
    func ed25519TruncationEveryBoundary() async throws {
        let container = try await Self.ed25519Container3Chunk()
        let (header, blocks) = Self.split(container, headerSize: Self.edHeaderSize)
        #expect(blocks.count == 3, "test precondition: 3 MiB plaintext -> 3 ciphertext blocks")

        // Truncate at every chunk-count prefix: keep = 0, 1, 2 (NOT 3 — that is the full, valid container).
        for keep in 0 ..< blocks.count {
            let truncated = header + Self.concat(Array(blocks[0 ..< keep]))
            let d = SafeDir()
            defer { d.cleanup() }
            await assertFacadeRejects(truncated, privateKey: Fixtures.privateKey,
                                      dir: d, label: "ed-idx-truncate-prefix-\(keep)")
        }

        // Cutting one byte inside the final block (mid-final-block cut).
        let full = header + Self.concat(blocks)
        let cut1 = Data(full.dropLast(1))
        let c1 = SafeDir(); defer { c1.cleanup() }
        await assertFacadeRejects(cut1, privateKey: Fixtures.privateKey,
                                  dir: c1, label: "ed-idx-mid-final-cut-1")
        // Cutting the final block's tag plus a couple ciphertext bytes.
        let cut2 = Data(full.dropLast(ContainerCodec.tagBytes + 3))
        let c2 = SafeDir(); defer { c2.cleanup() }
        await assertFacadeRejects(cut2, privateKey: Fixtures.privateKey,
                                  dir: c2, label: "ed-idx-mid-final-cut-deep")
    }

    // MARK: - Ed25519 appended / replayed / reordered / trailing data

    @Test("Ed25519: replay-final, append-non-final, trailing byte, and reordered blocks -> authFailure, no dest, no .tmp")
    func ed25519AppendReorderTrailing() async throws {
        let container = try await Self.ed25519Container3Chunk()
        let (header, blocks) = Self.split(container, headerSize: Self.edHeaderSize)
        let full = header + Self.concat(blocks)

        // Replay the final block (append a copy of the last block).
        let replay = full + blocks[blocks.count - 1]
        let r = SafeDir(); defer { r.cleanup() }
        await assertFacadeRejects(replay, privateKey: Fixtures.privateKey, dir: r, label: "ed-idx-append-replay-final")

        // Append a non-final block (re-encrypt source: append the first block).
        let appendNonFinal = full + blocks[0]
        let an = SafeDir(); defer { an.cleanup() }
        await assertFacadeRejects(appendNonFinal, privateKey: Fixtures.privateKey, dir: an, label: "ed-idx-append-non-final")

        // A single trailing byte.
        let trailing = full + Data([0x00])
        let t = SafeDir(); defer { t.cleanup() }
        await assertFacadeRejects(trailing, privateKey: Fixtures.privateKey, dir: t, label: "ed-idx-trailing-byte")

        // Reorder: swap the first two blocks.
        let reordered = header + blocks[1] + blocks[0] + blocks[2]
        let o = SafeDir(); defer { o.cleanup() }
        await assertFacadeRejects(reordered, privateKey: Fixtures.privateKey, dir: o, label: "ed-idx-reorder")
    }

    // MARK: - Ed25519 single-byte tamper at start / middle / end

    @Test("Ed25519: single-byte tamper at start, middle, and end -> authFailure, no dest, no .tmp")
    func ed25519TamperAtStartMiddleEnd() async throws {
        let container = try await Self.ed25519Container3Chunk()
        let (header, blocks) = Self.split(container, headerSize: Self.edHeaderSize)
        let full = header + Self.concat(blocks)

        // Tamper at the start of the first ciphertext block (header itself stays valid).
        var start = full
        start[header.count] ^= 0x01
        let s = SafeDir(); defer { s.cleanup() }
        await assertFacadeRejects(start, privateKey: Fixtures.privateKey, dir: s, label: "ed-idx-tamper-start")

        // Tamper in the middle of the stream.
        var middle = full
        middle[full.count / 2] ^= 0x01
        let m = SafeDir(); defer { m.cleanup() }
        await assertFacadeRejects(middle, privateKey: Fixtures.privateKey, dir: m, label: "ed-idx-tamper-middle")

        // Tamper the last byte (inside the final block's AEAD tag).
        var end = full
        end[full.count - 1] ^= 0x01
        let e = SafeDir(); defer { e.cleanup() }
        await assertFacadeRejects(end, privateKey: Fixtures.privateKey, dir: e, label: "ed-idx-tamper-end")
    }

    // MARK: - Ed25519 wrong private key

    @Test("Ed25519: decrypting with the WRONG Ed25519 private key -> authFailure, no dest, no .tmp")
    func ed25519WrongPrivateKey() async throws {
        let container = try await Self.ed25519Container3Chunk()
        let d = SafeDir()
        defer { d.cleanup() }
        let wrongKey = Self.wrongEd25519Key   // a fresh, unrelated Ed25519 key
        // Cross-sanity: the wrong key is NOT the intended recipient.
        #expect(wrongKey.ed25519Public != Fixtures.publicKey.ed25519Public)
        await assertFacadeRejects(container, privateKey: wrongKey, dir: d, label: "ed-wrong-private-key")
    }

    // MARK: - RSA 3-chunk negative battery (same streaming state machine, via RSAPipe)

    @Test("RSA: truncation at every prefix + mid-final cut -> authFailure (single generic)")
    func rsaTruncationEveryBoundary() throws {
        let container = try RSAPipe.encrypt(pattern(3 * Self.chunkLen), pub: Fixtures.rsa2048Public)
        let headerSize = RSAHeader.headerSize(nonceLen: ContainerCodec.nonceAES,
                                              modulusBytes: Fixtures.rsa2048Material.modulusBytes)
        let (header, blocks) = Self.split(container, headerSize: headerSize)
        #expect(blocks.count == 3, "test precondition: 3 MiB plaintext -> 3 blocks")

        for keep in 0 ..< blocks.count {
            do {
                _ = try RSAPipe.decrypt(header + Self.concat(Array(blocks[0 ..< keep])),
                                        priv: Fixtures.rsa2048Material)
                Issue.record("rsa-truncate-prefix-\(keep): decrypted a truncated container!")
            } catch let e as EngineError {
                #expect(e == .authFailure, "rsa-truncate-prefix-\(keep): expected authFailure, got \(e)")
            } catch {
                Issue.record("rsa-truncate-prefix-\(keep): unexpected \(error)")
            }
        }

        let full = header + Self.concat(blocks)
        do {
            _ = try RSAPipe.decrypt(Data(full.dropLast(1)), priv: Fixtures.rsa2048Material)
            Issue.record("rsa-mid-final-cut: decrypted a truncated container!")
        } catch let e as EngineError {
            #expect(e == .authFailure, "rsa-mid-final-cut: expected authFailure, got \(e)")
        } catch {
            Issue.record("rsa-mid-final-cut: unexpected \(error)")
        }
    }

    @Test("RSA: append/replay/trailing/reorder and tamper -> authFailure (single generic)")
    func rsaAppendReorderTamper() throws {
        let container = try RSAPipe.encrypt(pattern(3 * Self.chunkLen), pub: Fixtures.rsa2048Public)
        let headerSize = RSAHeader.headerSize(nonceLen: ContainerCodec.nonceAES,
                                              modulusBytes: Fixtures.rsa2048Material.modulusBytes)
        let (header, blocks) = Self.split(container, headerSize: headerSize)
        let full = header + Self.concat(blocks)

        let cases: [(Data, String)] = [
            (full + blocks[blocks.count - 1], "rsa-append-replay-final"),
            (full + blocks[0], "rsa-append-non-final"),
            (full + Data([0x00]), "rsa-trailing-byte"),
            (header + blocks[1] + blocks[0] + blocks[2], "rsa-reorder"),
        ]
        for (blob, name) in cases {
            do {
                _ = try RSAPipe.decrypt(blob, priv: Fixtures.rsa2048Material)
                Issue.record("\(name): decrypted malformed data!")
            } catch let e as EngineError {
                #expect(e == .authFailure, "\(name): expected authFailure, got \(e)")
            } catch {
                Issue.record("\(name): unexpected \(error)")
            }
        }

        // Single-byte tamper at start / middle / end (header stays intact).
        var start = full
        start[headerSize] ^= 0xFF
        var middle = full
        middle[full.count / 2] ^= 0xFF
        var end = full
        end[full.count - 1] ^= 0xFF
        for (blob, name) in [(start, "rsa-tamper-start"), (middle, "rsa-tamper-middle"), (end, "rsa-tamper-end")] {
            do {
                _ = try RSAPipe.decrypt(blob, priv: Fixtures.rsa2048Material)
                Issue.record("\(name): decrypted tampered data!")
            } catch let e as EngineError {
                #expect(e == .authFailure, "\(name): expected authFailure, got \(e)")
            } catch {
                Issue.record("\(name): unexpected \(error)")
            }
        }
    }

    @Test("RSA: wrong private key -> authFailure (single generic)")
    func rsaWrongKey() throws {
        // Encrypt with rsa2048's public key; decrypt with a different same-size RSA-2048 key.
        // The OAEP unwrap fails and folds into the single generic authFailure (T-02-09/D-13).
        let container = try RSAPipe.encrypt(pattern(128), pub: Fixtures.rsa2048Public)
        do {
            _ = try RSAPipe.decrypt(container, priv: Fixtures.rsaOtherMaterial)
            Issue.record("rsa-wrong-key: decrypted with the wrong private key!")
        } catch let e as EngineError {
            #expect(e == .authFailure, "rsa-wrong-key: expected authFailure, got \(e)")
        } catch {
            Issue.record("rsa-wrong-key: unexpected \(error)")
        }
    }

    // MARK: - Cross-scheme rejection (Ed25519-vs-RSA containers)

    @Test("cross-scheme: an Ed25519 container is rejected by the RSA path and vice versa — no plaintext leak")
    func crossSchemeRejection() async throws {
        // Ed25519 v2 AES container driven through the RSA decrypt path.
        let edContainer = try await Self.ed25519Container3Chunk()
        do {
            _ = try RSAPipe.decrypt(edContainer, priv: Fixtures.rsa2048Material)
            Issue.record("cross-scheme: RSA path decrypted an Ed25519 container (plaintext LEAKED)!")
        } catch let e as EngineError {
            // The RSA path rejects a non-PKCRYPT\\x03 container at header dispatch before any
            // crypto — a safe, non-leaking rejection. It is surfaced as unsupportedFormat
            // (a format/type mismatch, distinct from a crypto-stage auth failure per D-13),
            // never a plaintext leak.
            if case .authFailure = e { /* crypto-stage mismatch folded to authFailure */ }
            else if case .unsupportedFormat = e { /* safe dispatch rejection */ }
            else { Issue.record("cross-scheme ed-via-rsa: unexpected \(e)") }
        } catch {
            Issue.record("cross-scheme ed-via-rsa: unexpected non-EngineError \(error)")
        }

        // RSA v3 AES container driven through the Ed25519 public facade.
        let rsaContainer = try RSAPipe.encrypt(pattern(64), pub: Fixtures.rsa2048Public)
        let d = SafeDir()
        defer { d.cleanup() }
        try rsaContainer.write(to: d.file("in.pkcrypt"))
        let result = await PKCryptEngine.decrypt(containerURL: d.file("in.pkcrypt"),
                                                 privateKey: Fixtures.privateKey,
                                                 destinationURL: d.file("out"))
        guard case .failure(let err) = result else {
            Issue.record("cross-scheme rsa-via-ed: decrypted an RSA container (plaintext LEAKED)!")
            return
        }
        if case .authFailure = err { /* fine */ }
        else if case .unsupportedFormat = err { /* safe dispatch rejection */ }
        else { Issue.record("cross-scheme rsa-via-ed: unexpected \(err)") }
        #expect(!FileManager.default.fileExists(atPath: d.file("out").path),
                "cross-scheme rsa-via-ed: no plaintext may be published")
        #expect(d.tempArtifacts().isEmpty,
                "cross-scheme rsa-via-ed: no .tmp may remain")
    }
}
