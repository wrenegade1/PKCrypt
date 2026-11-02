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

    // Parsed-key caches (keys are small; kept so a second run doesn't re-parse)
    @Published var recipient: PublicKeyMaterial?
    @Published var privateKey: PrivateKeyMaterial?
    @Published var keySummary: String?          // D-08 / D-11 identity summary

    // Run / feedback state
    @Published var isRunning = false
    @Published private(set) var fraction: Double = 0
    @Published private(set) var progressText: String?
    @Published private(set) var outputPath: String?   // success path (D-19)
    @Published private(set) var errorTitle: String?
    @Published private(set) var errorDetail: String?
    @Published private(set) var didCancel = false

    private var task: Task<Void, Never>?
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
        resetFeedback()
    }

    func setDestination(_ url: URL) {
        destination = url
        resetFeedback()
    }

    func selectRecipient(_ key: PublicKeyMaterial, summary: String?) {
        recipient = key
        keySummary = summary
        resetFeedback()
    }

    func selectRecipientFailure() {
        recipient = nil
        keySummary = nil
        resetFeedback()
    }

    func selectPrivateKey(_ key: PrivateKeyMaterial, summary: String?) {
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

    private func startEncrypt(input: URL, recipient: PublicKeyMaterial, destination: URL) {
        task = Task { @MainActor in
            let result = await PKCryptEngine.encrypt(
                fileURL: input, recipient: recipient, destinationURL: destination
            ) { [bridge] p in
                bridge.record(p)
                Task { @MainActor [weak self] in
                    guard let self, let sample = bridge.take() else { return }
                    self.updateProgress(sample)
                }
            }
            self.apply(result)
        }
    }

    private func startDecrypt(container: URL, privateKey: PrivateKeyMaterial, destination: URL) {
        task = Task { @MainActor in
            let result = await PKCryptEngine.decrypt(
                containerURL: container, privateKey: privateKey, destinationURL: destination
            ) { [bridge] p in
                bridge.record(p)
                Task { @MainActor [weak self] in
                    guard let self, let sample = bridge.take() else { return }
                    self.updateProgress(sample)
                }
            }
            self.apply(result)
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
            if error == .cancelled {
                didCancel = true
            } else {
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
    }
}
