// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Foundation
import PKCryptEngine

/// D-20: the SINGLE seam every engine failure passes through so the UI maps a
/// typed `EngineError` to a plain-language, security-safe user message.
///
/// `authFailure` maps to the fixed generic tuple — "Couldn't decrypt" / "Wrong
/// key or corrupted file." — and NEVER attaches a distinguishing reason (a wrong
/// key, tampering, truncation and appended data are indistinguishable, mirroring
/// the engine's unified `DECRYPT_FAILED`; PITFALL #9 / T-03-02). The typed cases
/// surface their detail (including the D-13 passphrase guard). `destinationExists`
/// routes to the D-16 alternate-name flow; `cancelled` maps to a flat "Cancelled" note.
enum UserMessage {
    static func message(for error: EngineError) -> (title: String, detail: String?) {
        switch error {
        case .authFailure:
            return ("Couldn't decrypt", "Wrong key or corrupted file.")
        case .unsupportedFormat(let detail):
            return ("Unsupported file", detail)
        case .keyError(let detail):
            return ("Invalid key", detail)
        case .permissionError(let detail):
            return ("Can't write there", detail)
        case .ioError(let detail):
            return ("File error", detail)
        case .destinationExists:
            return ("File already exists", "Choose a different name or location.")
        case .cancelled:
            return ("Cancelled", nil)
        }
    }
}
