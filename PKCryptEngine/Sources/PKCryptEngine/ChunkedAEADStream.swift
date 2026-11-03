// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Foundation
import CryptoKit
import CSodium

/// Common decrypt surface shared by the AES-GCM and XChaCha20 chunk cryptos so
/// the hold-back/lookahead streaming state machine (ChunkedDecryptor) is
/// identical regardless of cipher (Patterns: Shared Patterns).
public protocol ChunkDecrypting {
    var chunkLen: Int { get }
    var blockSize: Int { get }
    func decryptChunk(_ ct: Data, final: Bool) throws -> Data
}

/// AES-256-GCM per-chunk AEAD with the PKCrypt nonce/AAD rules. Every chunk is
/// built/read from its three separate components (never `.combined` — the wire
/// format never transmits the nonce per-chunk; T-02-04 / Pitfall 5).
public final class AesGcmChunkCrypto: ChunkDecrypting {
    let key: SymmetricKey
    let header: Data
    let baseNonce: Data
    public let chunkLen: Int
    private(set) var index: UInt32 = 0
    private var closed = false

    public var blockSize: Int { chunkLen + ContainerCodec.tagBytes }

    public init(key: Data, header: Data, baseNonce: Data, chunkLen: Int) {
        self.key = SymmetricKey(data: key)
        self.header = header
        self.baseNonce = baseNonce
        self.chunkLen = chunkLen
    }

    private func nonce(for index: UInt32) throws -> AES.GCM.Nonce {
        let raw = ContainerCodec.chunkNonce(baseNonce: baseNonce, index: index)
        return try AES.GCM.Nonce(data: raw)
    }

    /// Encrypt one plaintext chunk -> `ciphertext || tag` (never `.combined`).
    public func encryptChunk(_ chunk: Data, final: Bool) throws -> Data {
        if closed { throw EngineError.authFailure }
        let nonce = try nonce(for: index)
        let aad = ContainerCodec.aad(header: header, final: final)
        let sealed = try AES.GCM.seal(chunk, using: key, nonce: nonce, authenticating: aad)
        index += 1
        if final { closed = true }
        return sealed.ciphertext + sealed.tag
    }

    /// Decrypt one ciphertext block (`ciphertext || tag`). Crypto-stage failures
    /// (wrong key / tamper / truncation) -> single generic authFailure (D-11).
    public func decryptChunk(_ ct: Data, final: Bool) throws -> Data {
        if closed { throw EngineError.authFailure }
        let tagLen = ContainerCodec.tagBytes
        if final {
            guard ct.count >= tagLen && ct.count <= chunkLen + tagLen else { throw EngineError.authFailure }
        } else {
            guard ct.count == chunkLen + tagLen else { throw EngineError.authFailure }
        }
        let nonce = try nonce(for: index)
        let aad = ContainerCodec.aad(header: header, final: final)
        let sealed = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: Data(ct.prefix(ct.count - tagLen)),
            tag: Data(ct.suffix(tagLen))
        )
        do {
            let plain = try AES.GCM.open(sealed, using: key, authenticating: aad)
            index += 1
            if final { closed = true }
            return plain
        } catch {
            throw EngineError.authFailure
        }
    }
}

/// XChaCha20-Poly1305 (IETF, 24-byte nonce) chunk decrypt — the ONLY correct
/// provider for PKCrypt cipher 0x01. Read-only this phase (D-02): no encrypt
/// path is exposed. Routes exclusively through libsodium
/// `crypto_aead_xchacha20poly1305_ietf_decrypt`, NEVER CryptoKit ChaChaPoly
/// (12-byte nonce, not interchangeable — T-02-07 / Pitfall 1).
public final class XChaCha20ChunkCrypto: ChunkDecrypting {
    let key: Data
    let header: Data
    let baseNonce: Data
    public let chunkLen: Int
    private(set) var index: UInt32 = 0
    private var closed = false

    public var blockSize: Int { chunkLen + ContainerCodec.tagBytes }

    public init(key: Data, header: Data, baseNonce: Data, chunkLen: Int) {
        self.key = key
        self.header = header
        self.baseNonce = baseNonce
        self.chunkLen = chunkLen
    }

    /// `ct` is the FULL combined `ciphertext || tag` chunk body (the wire format
    /// transmits ciphertext||tag together). libsodium's ietf_decrypt requires
    /// ct||tag as ONE authenticated buffer, so it is passed whole — this is the
    /// Phase-1 "recombine split ct/tag before the FFI call" adapter.
    public func decryptChunk(_ ct: Data, final: Bool) throws -> Data {
        if closed { throw EngineError.authFailure }
        let tagLen = ContainerCodec.tagBytes
        if final {
            guard ct.count >= tagLen && ct.count <= chunkLen + tagLen else { throw EngineError.authFailure }
        } else {
            guard ct.count == chunkLen + tagLen else { throw EngineError.authFailure }
        }
        let nonce = ContainerCodec.chunkNonce(baseNonce: baseNonce, index: index)
        let aad = ContainerCodec.aad(header: header, final: final)
        let plain = try Self.xchacha20Decrypt(ciphertextAndTag: ct, aad: aad, nonce: nonce, key: key)
        index += 1
        if final { closed = true }
        return plain
    }

    /// libsodium `crypto_aead_xchacha20poly1305_ietf_decrypt` FFI call on the
    /// combined ct||tag buffer. Any auth/tamper failure -> the single generic
    /// `authFailure` (D-11). Returns libsodium's own decrypted bytes.
    public static func xchacha20Decrypt(ciphertextAndTag: Data, aad: Data,
                                        nonce: Data, key: Data) throws -> Data {
        // libsodium reads exactly 32 key bytes and 24 nonce bytes from the raw
        // pointers below; anything else would be an out-of-bounds read.
        guard key.count == 32, nonce.count == ContainerCodec.nonceXC,
              ciphertextAndTag.count >= ContainerCodec.tagBytes else {
            throw EngineError.authFailure
        }
        var out = [UInt8](repeating: 0, count: max(1, ciphertextAndTag.count - ContainerCodec.tagBytes))
        var mlen: UInt64 = 0
        let rc = ciphertextAndTag.withUnsafeBytes { (cb: UnsafeRawBufferPointer) -> Int32 in
            aad.withUnsafeBytes { (ab: UnsafeRawBufferPointer) -> Int32 in
                nonce.withUnsafeBytes { (nb: UnsafeRawBufferPointer) -> Int32 in
                    key.withUnsafeBytes { (kb: UnsafeRawBufferPointer) -> Int32 in
                        crypto_aead_xchacha20poly1305_ietf_decrypt(
                            &out, &mlen, nil,
                            cb.bindMemory(to: UInt8.self).baseAddress!, UInt64(cb.count),
                            ab.bindMemory(to: UInt8.self).baseAddress!, UInt64(ab.count),
                            nb.bindMemory(to: UInt8.self).baseAddress!,
                            kb.bindMemory(to: UInt8.self).baseAddress!)
                    }
                }
            }
        }
        guard rc == 0 else { throw EngineError.authFailure }
        return Data(out.prefix(Int(mlen)))
    }
}

/// Encrypt-side hold-back streaming (core.py:538-547): only chunks known to be
/// followed by more data are emitted as non-final; whatever remains at `finish()`
/// becomes the final chunk. Memory stays bounded and truncation is never sealed
/// as a full final-flag stream (SAFE-01 / T-02-01).
public final class ChunkedEncryptor {
    private let crypto: AesGcmChunkCrypto
    private let chunkLen: Int
    private var pending = Data()
    private let sink: (Data) throws -> Void

    public init(crypto: AesGcmChunkCrypto, sink: @escaping (Data) throws -> Void) {
        self.crypto = crypto
        self.chunkLen = crypto.chunkLen
        self.sink = sink
    }

    public func write(_ data: Data) throws {
        pending.append(data)
        let cl = chunkLen
        let n = max(0, (pending.count - 1) / cl)   // (len-1)//cl hold-back rule
        if n > 0 {
            // Emit the (n) full non-final blocks. Use `subdata(in:)` (fresh copy)
            // rather than `Data[...]`/`removeFirst` — after `removeFirst` the
            // Data becomes a region/slice whose subsequent range-subscript can
            // trap in Foundation (T-02-01 / crash on multi-chunk inputs).
            for i in 0 ..< n {
                let start = i * cl
                let block = pending.subdata(in: start ..< (start + cl))
                try sink(try crypto.encryptChunk(block, final: false))
            }
            let kept = n * cl
            pending = pending.subdata(in: kept ..< pending.count)
        }
    }

    public func finish() throws {
        let finalChunk = pending
        pending.removeAll()
        try sink(try crypto.encryptChunk(finalChunk, final: true))
    }
}

/// Decrypt-side streaming with one-block hold-back (core.py:586-647). A block is
/// only returned (as non-final) once more data is known to follow; the block held
/// at EOF is authenticated as *final*. This makes truncation-at-a-chunk-boundary
/// detectable before any plaintext reaches the safe publisher (SAFE-01/T-02-01).
public final class ChunkedDecryptor {
    private let crypto: any ChunkDecrypting
    public let blockSize: Int

    public init(crypto: any ChunkDecrypting) {
        self.crypto = crypto
        self.blockSize = crypto.blockSize
    }

    /// Drive the stream: `reader` returns successive ciphertext pieces (exactly
    /// blockSize bytes when available), `sink` receives authenticated plaintext.
    public func run(reader: () -> Data?, sink: (Data) throws -> Void) throws {
        var pending = Data()
        while true {
            guard let piece = reader(), !piece.isEmpty else { break }
            pending.append(piece)
            let n = max(0, (pending.count - 1) / blockSize)
            if n > 0 {
                // Same fix as encrypt: use `subdata(in:)` (fresh copy) instead of
                // `Data[...]`/`removeFirst` — a post-`removeFirst` region Data can
                // trap on a later range-subscript in Foundation (T-02-01).
                for i in 0 ..< n {
                    let start = i * blockSize
                    let block = pending.subdata(in: start ..< (start + blockSize))
                    try sink(try crypto.decryptChunk(block, final: false))
                }
                let kept = n * blockSize
                pending = pending.subdata(in: kept ..< pending.count)
            }
        }
        // pending now holds the final block (0..blockSize bytes). The format
        // requires >= 1 chunk, so an empty trailing body is corrupt.
        guard !pending.isEmpty else { throw EngineError.authFailure }
        try sink(try crypto.decryptChunk(pending, final: true))
    }
}
