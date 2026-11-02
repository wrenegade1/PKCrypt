import Foundation
import PKCryptEngine

// MARK: - RED scaffold stub (Plan 03-01 Task 2)
//
// Compile-enabling stub so FacadeRoutingTests builds and genuinely fails on the
// planned key-parsing/comment assertion. The real implementation (delegating to
// KeyMaterial.parseEd25519Public + OpenSSH comment extraction, D-07/D-11) lands
// in the Task-2 GREEN commit.
enum KeySelection {
    static func detectAndParsePublic(_ data: Data) throws -> PublicKeyMaterial {
        throw EngineError.keyError("not implemented")   // TODO stub: parse via KeyMaterial
    }
    static func comment(of data: Data) -> String? {
        nil   // TODO stub: third+ whitespace token of the OpenSSH line
    }
}
