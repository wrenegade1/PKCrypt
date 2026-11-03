// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Foundation

/// Progress report for a long-running engine operation (D-15): how many bytes
/// have been processed vs. a best-effort total. `bytesProcessed` is
/// monotonically non-decreasing across successive reports; `totalBytes` is
/// `nil` when the total cannot be known up front.
public struct EngineProgress: Sendable, Equatable {
    public let bytesProcessed: Int64
    public let totalBytes: Int64?
    public init(bytesProcessed: Int64, totalBytes: Int64?) {
        self.bytesProcessed = bytesProcessed
        self.totalBytes = totalBytes
    }
}

/// Progress callback shape (D-15): invoked by the engine after each chunk with
/// monotonically non-decreasing `bytesProcessed`. `@Sendable` so the caller's
/// UI layer can capture it safely (Phase 3 SwiftUI progress).
public typealias ProgressHandler = @Sendable (EngineProgress) -> Void
