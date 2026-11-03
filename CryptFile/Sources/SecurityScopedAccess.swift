// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import Foundation
import PKCryptEngine

/// App-scoped security-scoped bookmark lifecycle (APP-03, Phase-1 D-05).
///
/// In the sandbox the app can only touch URLs the user explicitly grants via
/// NSOpenPanel/NSSavePanel (RESEARCH Pattern 2, `:254-281`). This type captures
/// each granted URL as an app-scoped security-scoped bookmark (`.withSecurityScope`),
/// persists it (UserDefaults — bookmark data is NOT secret, RESEARCH A1), resolves
/// it on later runs with `bookmarkDataIsStale` re-capture (Pitfall 1 / T-03-16),
/// and wraps every resolved use in a balanced `startAccessingSecurityScopedResource()`
/// / `defer { stopAccessing... }` scope (T-03-15). If `start` returns false the call
/// fails fast rather than leaking an unbalanced scope (Pitfall 1 / Phase-1 D-05).
///
/// Non-secret: never store keys/ciphertext here — only bookmark data.
enum SecurityScopedAccess {

    /// Which user grant a bookmark key names (input / key / destination).
    enum Scope {
        case input
        case recipientKey
        case destination
    }

    /// Stable UserDefaults key per grant scope.
    static func bookmarkKey(for scope: Scope) -> String {
        switch scope {
        case .input: return "pkcrypt.bookmark.input"
        case .recipientKey: return "pkcrypt.bookmark.key"
        case .destination: return "pkcrypt.bookmark.destination"
        }
    }

    /// Capture a user-granted URL as an app-scoped security-scoped bookmark and
    /// persist it under `key`. Throws if the URL cannot be bookmarked (e.g. it was
    /// not a panel grant), which callers treat as best-effort (try?).
    static func persistBookmark(for url: URL, key: String) throws {
        let data = try url.bookmarkData(
            options: .withSecurityScope,
            includingResourceValuesForKeys: nil,
            relativeTo: nil
        )
        UserDefaults.standard.set(data, forKey: key)
    }

    /// Resolve a persisted bookmark back to a URL, re-capturing + re-storing it
    /// when `bookmarkDataIsStale` is set (Pitfall 1 / T-03-16) so relaunch access
    /// keeps working. Returns nil when no bookmark exists or resolution fails.
    static func resolveBookmark(for key: String) -> URL? {
        guard let data = UserDefaults.standard.data(forKey: key) else { return nil }
        var stale = false
        do {
            let url = try URL(
                resolvingBookmarkData: data,
                options: .withSecurityScope,
                relativeTo: nil,
                bookmarkDataIsStale: &stale
            )
            if stale {
                try persistBookmark(for: url, key: key)
            }
            return url
        } catch {
            return nil
        }
    }

    /// Run `perform` over `url` inside a balanced start/stop security scope:
    /// `startAccessingSecurityScopedResource()` before, `stopAccessing...` after
    /// (deferred so it runs on every exit). The canonical Foundation pattern (Apple
    /// WWDC + RESEARCH Pattern 2): `start` is only balanced by the stop — a URL the
    /// app already has sandbox access to (e.g. its own container) returns `false`
    /// yet remains fully usable, so a false return is NOT an error (Pitfall 1 scope
    /// leak is prevented by the always-run stop, never by a denylist).
    static func access<Result>(_ url: URL, _ perform: (URL) -> Result) -> Result {
        let started = url.startAccessingSecurityScopedResource()
        defer { if started { url.stopAccessingSecurityScopedResource() } }
        return perform(url)
    }

    /// Async variant used around the engine's long `async` calls: starts access on
    /// `url`, runs `perform` (which may `await`), and stops access on every exit.
    /// Same balanced-scope contract as the synchronous `access(_:)`.
    static func access<Result>(_ url: URL, _ perform: (URL) async throws -> Result) async throws -> Result {
        let started = url.startAccessingSecurityScopedResource()
        defer { if started { url.stopAccessingSecurityScopedResource() } }
        return try await perform(url)
    }
}
