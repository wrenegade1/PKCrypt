import Foundation

// MARK: - RED scaffold stub (Plan 03-01 Task 2)
//
// Compile-enabling stub so FacadeRoutingTests builds and genuinely fails on the
// planned output-naming assertion. The real implementation (delegating to the
// engine's SafeOutputPublisher helpers, D-14) lands in the Task-2 GREEN commit.
enum OutputPath {
    static func destination(encrypting input: URL) -> URL {
        URL(fileURLWithPath: "")   // TODO stub: real impl returns <input>.pkcrypt
    }
}
