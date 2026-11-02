import Foundation
import CryptoKit

/// Public facade for `PKCryptEngine` (D-01/D-03): the only entry surface Phase
/// 3's app imports. Every encrypt/decrypt flows through ContainerCodec ->
/// KeyMaterial -> ChunkedAEADStream -> SafeOutputPublisher — the app can never
/// bypass the streaming/safety paths.
///
/// Finalized API (D-12/D-15/D-16): each operation is `async` and returns
/// `EngineResult<T>` (no thrown error escapes the public surface), reports
/// per-chunk progress through an optional `@Sendable` callback, and honors
/// cooperative cancellation between chunks (`Task.checkCancellation()`): a
/// cancelled operation aborts the staging temp and publishes nothing.
/// Normalized recipient key-type union. The app passes ONE of these to the
/// single union-based `encrypt` so the facade dispatches internally on the
/// algorithm (Ed25519 vs RSA) — the app never touches codec internals.
public enum CryptRecipient: Sendable {
    case ed25519(PublicKeyMaterial)
    case rsa(RSAPublicKeyMaterial)
}

/// Normalized private key-type union for the single union-based `decrypt`.
public enum CryptPrivateKey: Sendable {
    case ed25519(PrivateKeyMaterial)
    case rsa(RSAPrivateKeyMaterial)
}

public enum PKCryptEngine {

    // MARK: - Encrypt

    /// Encrypt `fileURL` for an Ed25519 recipient, publishing a v2 AES-GCM
    /// container to `destinationURL`. Thin delegate to the union path (Plan
    /// 03-02 keeps the Ed25519-only overload for backward compatibility with
    /// Plan 03-01's app trace).
    public static func encrypt(fileURL: URL,
                               recipient: PublicKeyMaterial,
                               destinationURL: URL,
                               progress: ProgressHandler? = nil) async -> EngineResult<URL> {
        await encrypt(fileURL: fileURL, recipient: .ed25519(recipient),
                      destinationURL: destinationURL, progress: progress)
    }

    /// Encrypt `fileURL` for a normalized `CryptRecipient` (.ed25519 -> v2
    /// AES-GCM; .rsa -> v3 RSA-OAEP AES-GCM). Publishes only after the whole
    /// stream is sealed; an existing destination yields `.destinationExists`
    /// (D-10, no overwrite ever).
    public static func encrypt(fileURL: URL,
                               recipient: CryptRecipient,
                               destinationURL: URL,
                               progress: ProgressHandler? = nil) async -> EngineResult<URL> {
        do {
            let url: URL
            switch recipient {
            case .ed25519(let mat):
                url = try encryptEd25519(fileURL: fileURL, recipient: mat,
                                         destinationURL: destinationURL, progress: progress)
            case .rsa(let mat):
                url = try encryptRSA(fileURL: fileURL, recipient: mat,
                                     destinationURL: destinationURL, progress: progress)
            }
            return .success(url)
        } catch is CancellationError {
            return .failure(.cancelled)
        } catch let e as EngineError {
            return .failure(e)
        } catch {
            return .failure(.ioError(String(describing: error)))
        }
    }

    /// Ed25519 AES-GCM v2 encrypt body (shared by both overloads). Throws; the
    /// caller applies the 3-way error fold.
    private static func encryptEd25519(fileURL: URL, recipient: PublicKeyMaterial,
                                       destinationURL: URL,
                                       progress: ProgressHandler?) throws -> URL {
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
        var processed: Int64 = 0
        let total = fileSize(of: fileURL)
        do {
            try fh.write(contentsOf: header)
            let crypto = AesGcmChunkCrypto(key: key, header: header, baseNonce: baseNonce, chunkLen: Int(chunkLen))
            let enc = ChunkedEncryptor(crypto: crypto) { chunk in
                try Cancellation.checkChunkCancellation()   // D-16: between chunks
                processed += Int64(chunk.count)
                progress?(EngineProgress(bytesProcessed: processed, totalBytes: total))
                try fh.write(contentsOf: chunk)
            }
            try streamFilePieces(fileURL) { try enc.write($0) }
            try enc.finish()
            try publisher.publish(fh: fh)                  // only after full success
            return destinationURL
        } catch {
            publisher.abort()                              // remove temp, publish nothing
            throw error
        }
    }

    /// RSA v3 encrypt body: a fresh random 32-byte session key wrapped via
    /// `KeyMaterial.rsaWrap` (SecKey `.rsaEncryptionOAEPSHA256`; failure folds
    /// into `authFailure`), then an AES-GCM chunked stream sealed into a v3
    /// container and published only after full success.
    private static func encryptRSA(fileURL: URL, recipient: RSAPublicKeyMaterial,
                                   destinationURL: URL,
                                   progress: ProgressHandler?) throws -> URL {
        // Fresh random 32-byte session key per encrypt (T-02-17 non-determinism).
        let sessionKey = randomBytes(32)
        let wrapped = try KeyMaterial.rsaWrap(sessionKey: sessionKey, publicKey: recipient)

        let baseNonce = randomBytes(ContainerCodec.nonceAES)
        let chunkLen = UInt32(ContainerCodec.defaultChunkLen)
        let header = try RSAHeader(cipher: ContainerCodec.cipherAES,
                                   payloadType: ContainerCodec.payloadFile,
                                   alg: ContainerCodec.rsaAlgOAEPSHA256,
                                   wrappedKey: wrapped, baseNonce: baseNonce,
                                   chunkLen: chunkLen, modulusBytes: recipient.modulusBytes).bytes

        let publisher = SafeOutputPublisher(destinationURL: destinationURL)
        let fh: FileHandle
        do { fh = try publisher.start() } catch { throw error }
        var processed: Int64 = 0
        let total = fileSize(of: fileURL)
        do {
            try fh.write(contentsOf: header)
            let crypto = AesGcmChunkCrypto(key: sessionKey, header: header,
                                           baseNonce: baseNonce, chunkLen: Int(chunkLen))
            let enc = ChunkedEncryptor(crypto: crypto) { chunk in
                try Cancellation.checkChunkCancellation()   // D-16: between chunks
                processed += Int64(chunk.count)
                progress?(EngineProgress(bytesProcessed: processed, totalBytes: total))
                try fh.write(contentsOf: chunk)
            }
            try streamFilePieces(fileURL) { try enc.write($0) }
            try enc.finish()
            try publisher.publish(fh: fh)                  // only after full success
            return destinationURL
        } catch {
            publisher.abort()                              // remove temp, publish nothing
            throw error
        }
    }

    // MARK: - Decrypt

    /// Decrypt a v2 Ed25519 AES-GCM container to `destinationURL` using the
    /// recipient's private key material. Publishes ONLY after the whole AEAD
    /// stream authenticates (SAFE-01); an existing destination is never
    /// overwritten (`.destinationExists`, D-10).
    public static func decrypt(containerURL: URL,
                               privateKey: PrivateKeyMaterial,
                               destinationURL: URL,
                               progress: ProgressHandler? = nil) async -> EngineResult<URL> {
        do {
            let reader = try FileHandle(forReadingFrom: containerURL)
            defer { try? reader.close() }
            let containerSize = fileSize(of: containerURL)

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
            let key = KeyMaterial.deriveKey(sharedSecret: shared, ephemeralPublicKey: v2.ephemeralPublicKey,
                                            recipientXPublic: xPub)

            let publisher = SafeOutputPublisher(destinationURL: destinationURL)
            let fh: FileHandle
            do { fh = try publisher.start() } catch { throw error }
            var processed: Int64 = 0
            let total = max(0, containerSize - Int64(headerSize))
            do {
                let crypto = AesGcmChunkCrypto(key: key, header: header, baseNonce: v2.baseNonce, chunkLen: Int(v2.chunkLen))
                let dec = ChunkedDecryptor(crypto: crypto)
                let blockSize = dec.blockSize
                try dec.run(reader: { try? reader.read(upToCount: blockSize) }) { plain in
                    try Cancellation.checkChunkCancellation()   // D-16: between chunks
                    processed += Int64(plain.count)
                    progress?(EngineProgress(bytesProcessed: processed, totalBytes: total))
                    try fh.write(contentsOf: plain)
                }
                try publisher.publish(fh: fh)                  // only after full authentication
                return .success(destinationURL)
            } catch {
                publisher.abort()                              // remove temp, publish nothing
                throw error
            }
        } catch is CancellationError {
            return .failure(.cancelled)
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

    /// Byte count of a file on disk, or 0 if it cannot be stat'd (used only as a
    /// best-effort progress `totalBytes`).
    private static func fileSize(of url: URL) -> Int64 {
        (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.int64Value ?? 0
    }

    /// Cryptographically random bytes (SystemRandomNumberGenerator is CSPRNG-backed
    /// on Apple platforms) — used for the base nonce of a fresh container.
    private static func randomBytes(_ n: Int) -> Data {
        var gen = SystemRandomNumberGenerator()
        return Data((0 ..< n).map { _ in UInt8.random(in: .min ... .max, using: &gen) })
    }
}
