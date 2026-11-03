// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Foundation

/// Cooperative cancellation integration (D-16). Cancellation is observed
/// BETWEEN chunks via `Task.checkCancellation()` so a long stream aborts at
/// chunk granularity — never mid-buffer — and the facade's `abort()` then
/// removes the staging temp and publishes nothing (no partial plaintext).
public enum Cancellation {
    /// Throw `CancellationError` if the current `Task` has been cancelled.
    /// Call once per chunk boundary in the streaming loops. The caller's
    /// `Task.cancel()` only sets the `isCancelled` flag; the engine actually
    /// acts on it at these checkpoints.
    @inline(__always)
    public static func checkChunkCancellation() throws {
        try Task.checkCancellation()
    }
}
