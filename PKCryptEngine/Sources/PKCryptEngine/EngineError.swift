import Foundation

/// Typed error taxonomy for the PKCryptEngine (D-11 / D-12 / D-13).
///
/// The boundary is deliberate:
/// - `keyError` is reserved for **pre-crypto** OpenSSH key *parsing* failures
///   (unreadable, malformed, unsupported type, passphrase-protected) — D-13.
/// - `authFailure` is the **single generic** case for every *crypto-stage*
///   failure (Ed→X conversion, X25519 ECDH exchange, AEAD tag mismatch,
///   truncation, appended data). It carries no distinguishing detail so a
///   wrong key, a tampered file, and a truncated file are indistinguishable
///   to a caller — exactly mirroring the Python oracle's unified
///   `DECRYPT_FAILED` message (D-11).
public enum EngineError: Error, Sendable, Equatable {
    /// Wrong key / tampered / truncated / appended data. Generic, never leaks reasons.
    case authFailure
    /// Unknown version, cipher, payload type, or algorithm — non-sensitive detail OK.
    case unsupportedFormat(String)
    /// Key file unreadable / malformed / unsupported / passphrase-protected (D-13).
    case keyError(String)
    /// Destination is not writable / access denied.
    case permissionError(String)
    /// A file I/O failure occurred.
    case ioError(String)
    /// SAFE-02 / D-10: the resolved destination already exists; nothing overwritten.
    case destinationExists
    /// D-16: the operation was cancelled cooperatively; temp output removed.
    case cancelled
}

/// Public result contract for engine operations (D-12): `Result<T, EngineError>`.
public typealias EngineResult<T> = Result<T, EngineError>
