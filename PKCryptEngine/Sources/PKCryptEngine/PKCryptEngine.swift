import Foundation
import CryptoKit

/// Public facade for `PKCryptEngine` (D-01/D-03): the only entry surface Phase 3's
/// app imports. Every encrypt/decrypt flows through ContainerCodec -> KeyMaterial
/// -> ChunkedAEADStream -> SafeOutputPublisher — the app can never bypass the
/// streaming/safety paths.
///
/// Signatures are the tracer form; progress/cancellation and final API shape are
/// finalized in Plan 03 (D-15/D-16). Output naming follows the caller-supplied
/// destinationURL; no-replace publication returns `.destinationExists` on a
/// collision (D-09/D-10).
public enum PKCryptEngine {

    // MARK: - Encrypt

    /// Encrypt `fileURL` for an Ed25519 recipient, publishing a v2 AES-GCM container
    /// to `destinationURL`. Returns the destination URL on success.
    public static func encrypt(fileURL: URL, recipient: PublicKeyMaterial, destinationURL: URL) -> EngineResult<URL> {
        do {
            let recipientXPub = try KeyMaterial.x25519Public(fromEd25519: recipient.ed25519Public)

            // Fresh ephemeral X25519 keypair + ECDH + HKDF (forward secrecy, T-02-04).
            let ephPriv = Curve25519.KeyAgreement.PrivateKey()
            let ephPub = ephPriv.publicKey.rawRepresentation
            let shared = try ephPriv.sharedSecretFromKeyAgreement(
                with: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientXPub)
            )
            let key = KeyMaterial.deriveKey(sharedSecret: shared.withUnsafeBytes { Data($0) },
                                            ephemeralPublicKey: ephPub,
                                            recipientXPublic: recipientXPub)

            let cipher = ContainerCodec.cipherAES
            let baseNonce = randomBytes(ContainerCodec.nonceAES)
            let chunkLen = UInt32(ContainerCodec.defaultChunkLen)
            let header = try V2Header(cipher: cipher, payloadType: ContainerCodec.payloadFile,
                                      ephemeralPublicKey: ephPub, baseNonce: baseNonce, chunkLen: chunkLen).bytes

            let publisher = SafeOutputPublisher(destinationURL: destinationURL)
            let fh: FileHandle
            do { fh = try publisher.start() } catch { throw error }
            do {
                try fh.write(contentsOf: header)
                let crypto = AesGcmChunkCrypto(key: key, header: header, baseNonce: baseNonce, chunkLen: Int(chunkLen))
                let enc = ChunkedEncryptor(crypto: crypto) { try fh.write(contentsOf: $0) }
                try streamFilePieces(fileURL) { try enc.write($0) }
                try enc.finish()
                try publisher.publish(fh: fh)
                return .success(destinationURL)
            } catch {
                publisher.abort()
                throw error
            }
        } catch let e as EngineError {
            return .failure(e)
        } catch {
            return .failure(.ioError(String(describing: error)))
        }
    }

    // MARK: - Decrypt

    /// Decrypt a v2 Ed25519 AES-GCM container to `destinationURL` using the
    /// recipient's private key material. Publishes ONLY after the whole AEAD
    /// stream authenticates (SAFE-01).
    public static func decrypt(containerURL: URL, privateKey: PrivateKeyMaterial, destinationURL: URL) -> EngineResult<URL> {
        do {
            let reader = try FileHandle(forReadingFrom: containerURL)
            defer { try? reader.close() }

            let prefix = try reader.read(upToCount: ContainerCodec.prefixBytes) ?? Data()
            guard prefix.count >= ContainerCodec.prefixBytes else {
                throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
            }
            let cipher = prefix[ContainerCodec.magicBytes]
            let nonceLen = try ContainerCodec.nonceLen(forCipher: cipher)
            let headerSize = ContainerCodec.prefixBytes + ContainerCodec.ephPubBytes + nonceLen + ContainerCodec.chunkLenBytes
            var header = prefix
            if header.count < headerSize {
                let rest = try reader.read(upToCount: headerSize - header.count) ?? Data()
                header.append(rest)
            }
            guard header.count >= headerSize else {
                throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
            }
            let v2 = try V2Header.parse(header)

            // Key establishment (Ed25519 -> X25519 -> ECDH -> HKDF).
            let xPriv = KeyMaterial.x25519Private(fromSeed: privateKey.seed, ed25519Public: privateKey.ed25519Public)
            let xPub = try KeyMaterial.x25519Public(fromEd25519: privateKey.ed25519Public)
            let shared = try KeyMaterial.sharedSecret(x25519Private: xPriv, ephemeralPublic: v2.ephemeralPublicKey)
            let key = KeyMaterial.deriveKey(sharedSecret: shared, ephemeralPublicKey: v2.ephemeralPublicKey, recipientXPublic: xPub)

            let publisher = SafeOutputPublisher(destinationURL: destinationURL)
            let fh: FileHandle
            do { fh = try publisher.start() } catch { throw error }
            do {
                let crypto = AesGcmChunkCrypto(key: key, header: header, baseNonce: v2.baseNonce, chunkLen: Int(v2.chunkLen))
                let dec = ChunkedDecryptor(crypto: crypto)
                let blockSize = dec.blockSize
                try dec.run(reader: { try? reader.read(upToCount: blockSize) }) { plain in
                    try fh.write(contentsOf: plain)
                }
                try publisher.publish(fh: fh)
                return .success(destinationURL)
            } catch {
                publisher.abort()
                throw error
            }
        } catch let e as EngineError {
            return .failure(e)
        } catch {
            return .failure(.ioError(String(describing: error)))
        }
    }

    // MARK: - Internal helpers

    /// Read a file in bounded pieces (chunk_len) so memory use is independent of
    /// file size (D-14). An empty file emits no pieces; the encryptor's `finish()`
    /// seals the single empty final chunk.
    private static func streamFilePieces(_ url: URL, _ body: (Data) throws -> Void) throws {
        let fh = try FileHandle(forReadingFrom: url)
        defer { try? fh.close() }
        let pieceSize = ContainerCodec.defaultChunkLen
        while true {
            let piece = try fh.read(upToCount: pieceSize) ?? Data()
            if piece.isEmpty { break }
            try body(piece)
        }
    }

    /// Cryptographically random bytes (SystemRandomNumberGenerator is CSPRNG-backed
    /// on Apple platforms) — used for the base nonce of a fresh container.
    private static func randomBytes(_ n: Int) -> Data {
        var gen = SystemRandomNumberGenerator()
        return Data((0 ..< n).map { _ in UInt8.random(in: .min ... .max, using: &gen) })
    }
}
