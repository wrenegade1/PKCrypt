import Foundation
import CryptoKit

/// AES-256-GCM per-chunk AEAD with the PKCrypt nonce/AAD rules. Every chunk is
/// built/read from its three separate components (never `.combined` — the wire
/// format never transmits the nonce per-chunk; T-02-04 / Pitfall 5).
public final class AesGcmChunkCrypto {
    let key: SymmetricKey
    let header: Data
    let baseNonce: Data
    public let chunkLen: Int
    private(set) var index: UInt32 = 0
    private var closed = false

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
        for i in 0 ..< n {
            let block = Data(pending[i * cl ..< (i + 1) * cl])
            try sink(try crypto.encryptChunk(block, final: false))
        }
        if n > 0 { pending.removeFirst(n * cl) }
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
    private let crypto: AesGcmChunkCrypto
    public let blockSize: Int

    public init(crypto: AesGcmChunkCrypto) {
        self.crypto = crypto
        self.blockSize = crypto.chunkLen + ContainerCodec.tagBytes
    }

    /// Drive the stream: `reader` returns successive ciphertext pieces (exactly
    /// blockSize bytes when available), `sink` receives authenticated plaintext.
    public func run(reader: () -> Data?, sink: (Data) throws -> Void) throws {
        var pending = Data()
        while true {
            guard let piece = reader(), !piece.isEmpty else { break }
            pending.append(piece)
            let n = max(0, (pending.count - 1) / blockSize)
            for i in 0 ..< n {
                let block = Data(pending[i * blockSize ..< (i + 1) * blockSize])
                try sink(try crypto.decryptChunk(block, final: false))
            }
            if n > 0 { pending.removeFirst(n * blockSize) }
        }
        // pending now holds the final block (0..blockSize bytes). The format
        // requires >= 1 chunk, so an empty trailing body is corrupt.
        guard !pending.isEmpty else { throw EngineError.authFailure }
        try sink(try crypto.decryptChunk(pending, final: true))
    }
}
