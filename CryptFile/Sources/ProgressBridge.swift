import Foundation
import PKCryptEngine

/// Coalesces the engine's high-frequency `@Sendable` per-chunk progress into a
/// low-rate latest sample and hands it to the main actor on demand (SAFE-03,
/// RESEARCH Pitfall 4). Modeled on the Phase-2 `ProgressBox` thread-safe receiver:
/// `record(_:)` is called from any engine thread; `take()` is called from the main
/// actor and throttles to ~25 Hz so a multi-GB run never floods the UI thread.
final class ProgressBridge: @unchecked Sendable {
    private let lock = NSLock()
    private var latest: EngineProgress?
    private var lastForward: EngineProgress?
    private var lastForwardTime = Date.distantPast
    private let minInterval: TimeInterval = 0.04   // ~25 Hz

    /// Called from the engine's `@Sendable` progress callback on any thread.
    func record(_ p: EngineProgress) {
        lock.lock()
        latest = p
        lock.unlock()
    }

    /// Returns the latest sample when at least `minInterval` has elapsed since the
    /// last forwarded sample (and always for the very first sample); otherwise nil.
    /// The engine guarantees monotonically non-decreasing `bytesProcessed`, so only
    /// the latest sample matters.
    func take() -> EngineProgress? {
        lock.lock()
        defer { lock.unlock() }
        guard let latest else { return nil }
        let now = Date()
        if lastForward == nil || now.timeIntervalSince(lastForwardTime) >= minInterval {
            lastForward = latest
            lastForwardTime = now
            return latest
        }
        return nil
    }
}
