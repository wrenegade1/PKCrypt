import Foundation
import SwiftUI
import PKCryptEngine

/// Per-app operation state (D-21: at most one operation in flight across both
/// tabs). A single `@MainActor` view model drives Encrypt and Decrypt by holding
/// the current `mode` and the selections, bridging the engine's `@Sendable`
/// progress onto a throttled main-actor fraction, and mapping `EngineError`
/// through the D-20 `UserMessage` seam. The app only ever passes URLs (and the
/// small parsed keys) — never whole file buffers (SAFE-03).
@MainActor
final class WorkflowViewModel: ObservableObject {

    enum Mode: String {
        case encrypt
        case decrypt
    }

    // Selections (kept in context across runs so the user can tweak and re-run, D-02)
    @Published var mode: Mode = .encrypt
    @Published var inputURL: URL?
    @Published var inputSummary: String?
    @Published var destination: URL?

    // Parsed-key caches (keys are small; kept so a second run doesn't re-parse).
    // The union facade types (CryptRecipient/CryptPrivateKey) let both Ed25519
    // and RSA flow through one normalized call (D-07 / FILE-01 / FILE-02).
    @Published var recipient: CryptRecipient?
    @Published var privateKey: CryptPrivateKey?
    @Published var keySummary: String?          // D-08 / D-11 identity summary

    // Run / feedback state
    @Published var isRunning = false
    @Published private(set) var isCustomDestination = false   // D-15 override vs D-14 live default
    @Published private(set) var fraction: Double = 0
    @Published private(set) var progressText: String?
    @Published private(set) var outputPath: String?   // success path (D-19)
    @Published private(set) var errorTitle: String?
    @Published private(set) var errorDetail: String?
    @Published private(set) var didCancel = false
    @Published private(set) var pendingAlternateDestination = false   // D-16 prompt state

    var task: Task<Void, Never>?
    private let bridge = ProgressBridge()

    var canRun: Bool {
        guard !isRunning, inputURL != nil, destination != nil else { return false }
        switch mode {
        case .encrypt: return recipient != nil
        case .decrypt: return privateKey != nil
        }
    }

    // MARK: - Selection setters

    func setMode(_ mode: Mode) {
        self.mode = mode
        resetFeedback()
    }

    func setInput(_ url: URL) {
        inputURL = url
        inputSummary = url.lastPathComponent
        persistGranted(url, scope: .input)
        resetFeedback()
    }

    func setDestination(_ url: URL) {
        destination = url
        // D-14: this is the live default (CLI-derived); any Change… override clears
        // this flag via setCustomDestination(D-15).
        isCustomDestination = false
        persistGranted(url, scope: .destination)
        resetFeedback()
    }

    /// D-15: a user 'Change…' NSSavePanel override — full folder+filename control.
    /// Persisted as a security-scoped bookmark and kept as the active destination.
    func setCustomDestination(_ url: URL) {
        destination = url
        isCustomDestination = true
        persistGranted(url, scope: .destination)
        resetFeedback()
    }

    /// Best-effort persistence of a user-granted URL as an app-scoped security-scoped
    /// bookmark (APP-03 / D-05). Non-fatal: if the URL can't be bookmarked (e.g. a
    /// derived default path that was never a panel grant) we simply don't persist it
    /// and fall back to the in-memory URL. Keys/ciphertext are never stored — only
    /// bookmark data.
    func persistGranted(_ url: URL, scope: SecurityScopedAccess.Scope) {
        try? SecurityScopedAccess.persistBookmark(
            for: url,
            key: SecurityScopedAccess.bookmarkKey(for: scope)
        )
    }

    func selectRecipient(_ key: CryptRecipient, summary: String?) {
        recipient = key
        keySummary = summary
        resetFeedback()
    }

    func selectRecipientFailure() {
        recipient = nil
        keySummary = nil
        resetFeedback()
    }

    func selectKeyFailure() {
        privateKey = nil
        keySummary = nil
        resetFeedback()
    }

    /// Surfaces a picker/validation-level engine error (e.g. the D-13
    /// passphrase guard) through the same D-20 seam as run-time failures.
    func reportPickerError(_ error: EngineError) {
        resetFeedback()
        let msg = UserMessage.message(for: error)
        errorTitle = msg.title
        errorDetail = msg.detail
    }

    func selectPrivateKey(_ key: CryptPrivateKey, summary: String?) {
        privateKey = key
        keySummary = summary
        resetFeedback()
    }

    // MARK: - Run / cancel (D-18 / D-21)

    func run() {
        guard canRun else { return }
        resetFeedback()
        guard let input = inputURL, let dest = destination else { return }
        isRunning = true
        switch mode {
        case .encrypt:
            guard let recipient else { isRunning = false; return }
            startEncrypt(input: input, recipient: recipient, destination: dest)
        case .decrypt:
            guard let privateKey else { isRunning = false; return }
            startDecrypt(container: input, privateKey: privateKey, destination: dest)
        }
    }

    func cancel() {
        task?.cancel()   // engine checks Task.checkCancellation() between chunks
    }

    /// D-16: after a `.destinationExists` collision the user picks an alternate
    /// destination and we re-run the SAME operation there. Never renames the
    /// staged temp and never overwrites (Pitfall 5 / SAFE-02); the user's other
    /// selections are kept in context (D-02).
    func run(toAlt destination: URL) {
        guard pendingAlternateDestination, !isRunning else { return }
        // D-16 alternate is a user-chosen destination → persist as a bookmark
        // (setCustomDestination) so it stays accessible on relaunch (APP-03).
        setCustomDestination(destination)
        pendingAlternateDestination = false
        run()
    }

    private func startEncrypt(input: URL, recipient: CryptRecipient, destination: URL) {
        // APP-03 / D-05: every URL the engine touches (input + destination) is used
        // inside a balanced start/stop security scope (Pitfall 1 / T-03-15) — never
        // outside one. The in-memory URL is authoritative in-session (the D-16
        // run(toAlt:) flow replaces it); bookmark persistence handles relaunch, it
        // does not substitute the run URL.
        task = Task { @MainActor in
            do {
                let result = try await SecurityScopedAccess.access(destination) { (dest: URL) async throws -> EngineResult<URL> in
                    try await SecurityScopedAccess.access(input) { (input: URL) async throws -> EngineResult<URL> in
                        await PKCryptEngine.encrypt(
                            fileURL: input, recipient: recipient, destinationURL: dest
                        ) { [bridge] p in
                            bridge.record(p)
                            Task { @MainActor [weak self] in
                                guard let self, let sample = bridge.take() else { return }
                                self.updateProgress(sample)
                            }
                        }
                    }
                }
                self.apply(result)
            } catch {
                // A false access start fails fast (Pitfall 1 / T-03-15).
                self.apply(.failure(error is EngineError ? error as! EngineError : .permissionError("could not start scoped access")))
            }
        }
    }

    private func startDecrypt(container: URL, privateKey: CryptPrivateKey, destination: URL) {
        task = Task { @MainActor in
            do {
                let result = try await SecurityScopedAccess.access(destination) { (dest: URL) async throws -> EngineResult<URL> in
                    try await SecurityScopedAccess.access(container) { (input: URL) async throws -> EngineResult<URL> in
                        await PKCryptEngine.decrypt(
                            containerURL: input, privateKey: privateKey, destinationURL: dest
                        ) { [bridge] p in
                            bridge.record(p)
                            Task { @MainActor [weak self] in
                                guard let self, let sample = bridge.take() else { return }
                                self.updateProgress(sample)
                            }
                        }
                    }
                }
                self.apply(result)
            } catch {
                self.apply(.failure(error is EngineError ? error as! EngineError : .permissionError("could not start scoped access")))
            }
        }
    }

    private func updateProgress(_ p: EngineProgress) {
        let total = p.totalBytes ?? 0
        fraction = total > 0 ? Double(p.bytesProcessed) / Double(total) : 0
        progressText = p.totalBytes.map { "\(p.bytesProcessed) of \($0) bytes" } ?? "\(p.bytesProcessed) bytes"
    }

    private func apply(_ result: EngineResult<URL>) {
        isRunning = false
        switch result {
        case .success(let url):
            outputPath = url.path
            fraction = 1.0
            progressText = nil
        case .failure(let error):
            switch error {
            case .destinationExists:
                // D-16: block the run and prompt for an alternate destination —
                // never overwrite or auto-rename (Pitfall 5 / SAFE-02). The user's
                // selections stay in context so they can re-run via run(toAlt:).
                pendingAlternateDestination = true
            case .cancelled:
                didCancel = true   // tab returns to ready with an inline "Cancelled" note (D-20)
            default:
                // Every remaining case through the D-20 seam: authFailure stays
                // generic, typed cases surface detail.
                let msg = UserMessage.message(for: error)
                errorTitle = msg.title
                errorDetail = msg.detail
            }
            progressText = nil
        }
    }

    private func resetFeedback() {
        fraction = 0
        progressText = nil
        outputPath = nil
        errorTitle = nil
        errorDetail = nil
        didCancel = false
        pendingAlternateDestination = false
    }
}
