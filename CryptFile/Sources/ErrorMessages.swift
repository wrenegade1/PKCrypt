import Foundation
import PKCryptEngine

/// D-20: the single seam every engine failure passes through so the UI maps a
/// typed `EngineError` to a plain-language, security-safe user message.
///
/// Task 2 ships a compile-enabling stub so the encrypt view can be built and the
/// tracer verified; the exhaustive 7-case mapping (with `authFailure` kept
/// intentionally generic — "Wrong key or corrupted file." — never leaking a
/// reason) lands in Task 3 together with its `ErrorMessageTests`.
enum UserMessage {
    static func message(for error: EngineError) -> (title: String, detail: String?) {
        ("Error", nil)
    }
}
