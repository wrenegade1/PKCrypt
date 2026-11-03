// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
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

    /// Decrypt a container for an Ed25519 private key. Thin delegate to the
    /// union path (Plan 03-02 compatibility overload).
    public static func decrypt(containerURL: URL,
                               privateKey: PrivateKeyMaterial,
                               destinationURL: URL,
                               progress: ProgressHandler? = nil) async -> EngineResult<URL> {
        await decrypt(containerURL: containerURL, privateKey: .ed25519(privateKey),
                      destinationURL: destinationURL, progress: progress)
    }

    /// Decrypt a container for a normalized `CryptPrivateKey` (.ed25519 / .rsa).
    /// Dispatches on the 8-byte container magic (PKCRYPT\\x02 -> v2 Ed25519,
    /// PKCRYPT\\x03 -> v3 RSA) — a magic/key algorithm mismatch is a typed,
    /// non-leaking `unsupportedFormat`, NOT `authFailure` (PITFALL #10). Publishes
    /// only after the whole AEAD stream authenticates; never overwrites.
    public static func decrypt(containerURL: URL,
                               privateKey: CryptPrivateKey,
                               destinationURL: URL,
                               progress: ProgressHandler? = nil) async -> EngineResult<URL> {
        do {
            let magic = try readMagic(containerURL)
            let url: URL
            if magic == ContainerCodec.magic {
                guard case .ed25519(let mat) = privateKey else {
                    throw EngineError.unsupportedFormat("container key algorithm does not match the selected key")
                }
                url = try decryptEd25519(containerURL: containerURL, privateKey: mat,
                                         destinationURL: destinationURL, progress: progress)
            } else if magic == ContainerCodec.magicRSA {
                guard case .rsa(let mat) = privateKey else {
                    throw EngineError.unsupportedFormat("container key algorithm does not match the selected key")
                }
                url = try decryptRSA(containerURL: containerURL, privateKey: mat,
                                     destinationURL: destinationURL, progress: progress)
            } else {
                throw EngineError.unsupportedFormat("not a PKCrypt file (bad header)")
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

    private static func decryptEd25519(containerURL: URL, privateKey: PrivateKeyMaterial,
                                       destinationURL: URL,
                                       progress: ProgressHandler?) throws -> URL {
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
            // Cipher dispatch (cipher 0x01 XChaCha read is exclusive via libsodium).
            let crypto: any ChunkDecrypting
            switch v2.cipher {
            case ContainerCodec.cipherAES:
                crypto = AesGcmChunkCrypto(key: key, header: header, baseNonce: v2.baseNonce, chunkLen: Int(v2.chunkLen))
            case ContainerCodec.cipherXChaCha20:
                crypto = XChaCha20ChunkCrypto(key: key, header: header, baseNonce: v2.baseNonce, chunkLen: Int(v2.chunkLen))
            default:
                throw EngineError.unsupportedFormat("unsupported cipher: \(v2.cipher)")
            }
            let dec = ChunkedDecryptor(crypto: crypto)
            let blockSize = dec.blockSize
            try dec.run(reader: { try? reader.read(upToCount: blockSize) }) { plain in
                try Cancellation.checkChunkCancellation()   // D-16: between chunks
                processed += Int64(plain.count)
                progress?(EngineProgress(bytesProcessed: processed, totalBytes: total))
                try fh.write(contentsOf: plain)
            }
            try publisher.publish(fh: fh)                  // only after full authentication
            return destinationURL
        } catch {
            publisher.abort()                              // remove temp, publish nothing
            throw error
        }
    }

    private static func decryptRSA(containerURL: URL, privateKey: RSAPrivateKeyMaterial,
                                   destinationURL: URL,
                                   progress: ProgressHandler?) throws -> URL {
        let reader = try FileHandle(forReadingFrom: containerURL)
        defer { try? reader.close() }
        let containerSize = fileSize(of: containerURL)

        // Derive the wrapped-key length from the parsed private key FIRST (Pitfall 2
        // / T-03-08): RSA-2048 -> 256, RSA-4096 -> 512. Never a hardcoded 256.
        let modulusBytes = privateKey.modulusBytes

        let prefix = try reader.read(upToCount: ContainerCodec.prefixBytes) ?? Data()
        guard prefix.count >= ContainerCodec.prefixBytes else {
            throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
        }
        let cipher = prefix[ContainerCodec.magicBytes]
        let nonceLen = try ContainerCodec.nonceLen(forCipher: cipher)
        let headerSize = RSAHeader.headerSize(nonceLen: nonceLen, modulusBytes: modulusBytes)
        var header = prefix
        if header.count < headerSize {
            let rest = try reader.read(upToCount: headerSize - header.count) ?? Data()
            header.append(rest)
        }
        guard header.count >= headerSize else {
            throw EngineError.unsupportedFormat("encrypted payload too short or corrupt")
        }
        let rsaHeader = try RSAHeader.parse(header, modulusBytes: modulusBytes)

        // Unwrap the session key. ANY OAEP failure (wrong key, garbage wrapped
        // key) folds into the single generic authFailure (T-02-09 / T-03-06).
        let session = try KeyMaterial.rsaUnwrap(wrapped: rsaHeader.wrappedKey, privateKey: privateKey)

        let publisher = SafeOutputPublisher(destinationURL: destinationURL)
        let fh: FileHandle
        do { fh = try publisher.start() } catch { throw error }
        var processed: Int64 = 0
        let total = max(0, containerSize - Int64(headerSize))
        do {
            // Cipher dispatch: cipher 0x00 -> AES-GCM; cipher 0x01 -> XChaCha20
            // read (libsodium ietf_decrypt only — Pitfall 1/3, T-03-07).
            let crypto: any ChunkDecrypting
            switch rsaHeader.cipher {
            case ContainerCodec.cipherAES:
                crypto = AesGcmChunkCrypto(key: session, header: header,
                                           baseNonce: rsaHeader.baseNonce, chunkLen: Int(rsaHeader.chunkLen))
            case ContainerCodec.cipherXChaCha20:
                crypto = XChaCha20ChunkCrypto(key: session, header: header,
                                              baseNonce: rsaHeader.baseNonce, chunkLen: Int(rsaHeader.chunkLen))
            default:
                throw EngineError.unsupportedFormat("unsupported cipher: \(rsaHeader.cipher)")
            }
            let dec = ChunkedDecryptor(crypto: crypto)
            let blockSize = dec.blockSize
            try dec.run(reader: { try? reader.read(upToCount: blockSize) }) { plain in
                try Cancellation.checkChunkCancellation()   // D-16: between chunks
                processed += Int64(plain.count)
                progress?(EngineProgress(bytesProcessed: processed, totalBytes: total))
                try fh.write(contentsOf: plain)
            }
            try publisher.publish(fh: fh)                  // only after full authentication
            return destinationURL
        } catch {
            publisher.abort()                              // remove temp, publish nothing
            throw error
        }
    }

    // MARK: - Internal helpers

    /// Read the first 8 bytes (the container magic) for v2/v3 decrypt dispatch.
    /// An unreadable/empty file is a flat format rejection — never a crypto leak.
    private static func readMagic(_ url: URL) throws -> [UInt8] {
        let fh = try FileHandle(forReadingFrom: url)
        defer { try? fh.close() }
        let prefix = try fh.read(upToCount: ContainerCodec.magicBytes) ?? Data()
        if prefix.isEmpty { throw EngineError.unsupportedFormat("not a PKCrypt file (bad header)") }
        return Array(prefix.prefix(ContainerCodec.magicBytes))
    }

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
