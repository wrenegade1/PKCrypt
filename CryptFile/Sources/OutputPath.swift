// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Foundation
import PKCryptEngine

/// App-side wrapper around the engine's CLI-derived output-name rules (D-14).
/// The app always delegates to the engine's `SafeOutputPublisher` helpers and
/// never re-derives the naming contract. A collision at publication time is
/// surfaced as `EngineError.destinationExists` (D-16) — the app never auto-numbers
/// or overwrites.
enum OutputPath {
    /// Default encrypted output: `<input>.pkcrypt` (mirrors the engine helper).
    static func destination(encrypting input: URL) -> URL {
        SafeOutputPublisher.encryptedOutputPath(for: input)
    }

    /// Default decrypted output: strips a trailing `.pkcrypt`, else appends
    /// `.decrypted` (no auto-numbering — a real collision stays `destinationExists`).
    static func destination(decrypting input: URL) -> URL {
        SafeOutputPublisher.decryptedOutputPath(for: input)
    }
}
