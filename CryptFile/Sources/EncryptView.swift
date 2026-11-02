import SwiftUI
import AppKit
import PKCryptEngine

/// Encrypt workflow (D-05/D-09/D-12/D-14/D-17/D-18/D-19/D-20): pick a file + the
/// recipient's public key in any order, confirm/redirect the destination, and Run
/// through the real engine facade with determinate progress and an inline result.
/// A file-only `NSOpenPanel` rejects folder selection up front (D-13); errors
/// render inline through the D-20 `UserMessage` seam, keeping selections in context.
struct EncryptView: View {
    @ObservedObject var viewModel: WorkflowViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Choose a file and the recipient's public key. The encrypted file can only be decrypted by the holder of the matching private key.")
                .foregroundStyle(.secondary)

            sourcePicker
            recipientPicker
            destinationRow

            if viewModel.isRunning {
                progressSection
            }

            actionRow

            resultSection
        }
        .padding()
        .onAppear { viewModel.setMode(.encrypt) }
    }

    // MARK: - Form rows

    private var sourcePicker: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("File").font(.headline)
                Text(viewModel.inputSummary ?? "No file selected")
                    .font(.callout)
                    .foregroundStyle(viewModel.inputURL == nil ? .secondary : .primary)
            }
            Spacer()
            Button("Choose File…") { openSourceFile() }
        }
    }

    private var recipientPicker: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Recipient public key").font(.headline)
                Text(viewModel.keySummary ?? "No key selected")
                    .font(.callout)
                    .foregroundStyle(viewModel.recipient == nil ? .secondary : .primary)
            }
            Spacer()
            Button("Choose Recipient Key…") { openRecipientKey() }
        }
    }

    private var destinationRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Save to").font(.headline)
                Text(viewModel.destination?.path ?? "Choose a file to set the default")
                    .font(.callout)
                    .foregroundStyle(viewModel.destination == nil ? .secondary : .primary)
                    .textSelection(.enabled)
            }
            Spacer()
            if let url = viewModel.destination {
                Button("Change…") { redirectDestination(defaultsTo: url) }
            }
        }
    }

    private var progressSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            ProgressView(value: viewModel.fraction)
            Text(viewModel.progressText ?? "Encrypting…")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var actionRow: some View {
        HStack {
            if viewModel.isRunning {
                Button("Cancel") { viewModel.cancel() }
                Spacer()
            } else {
                Spacer()
                Button("Run") { viewModel.run() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!viewModel.canRun)
            }
        }
    }

    @ViewBuilder private var resultSection: some View {
        if viewModel.didCancel {
            Text("Cancelled")
                .font(.callout)
                .foregroundStyle(.secondary)
        } else if let title = viewModel.errorTitle {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline).foregroundStyle(.red)
                if let detail = viewModel.errorDetail {
                    Text(detail).font(.callout).foregroundStyle(.red)
                }
            }
        } else if let path = viewModel.outputPath {
            VStack(alignment: .leading, spacing: 6) {
                Text("Encrypted").font(.headline)
                Text(path)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Button("Show in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                }
            }
        }
    }

    // MARK: - Panels

    private func openSourceFile() {
        let panel = NSOpenPanel()
        panel.title = "Choose a file to encrypt"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false   // D-13: reject folder selection
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        viewModel.setInput(url)
        if viewModel.destination == nil {
            // D-14: default the destination to <input>.pkcrypt immediately.
            viewModel.setDestination(OutputPath.destination(encrypting: url))
        }
    }

    private func openRecipientKey() {
        let panel = NSOpenPanel()
        panel.title = "Choose the recipient's public key"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard let data = try? Data(contentsOf: url) else { return }
        do {
            let recipient = try KeySelection.detectAndParsePublic(data)
            switch recipient {
            case .ed25519(let mat):
                let summary = KeySelection.comment(of: data).map { "Ed25519 · \($0)" } ?? "Ed25519 key"   // D-08
                viewModel.selectRecipient(mat, summary: summary)
            case .rsa(let mat):
                // RSA recipient wiring + identity summary complete in Task 2
                // (union state); keep Run disabled this wave (compile-cohesion
                // interim so the tree builds after KeySelection returns the union).
                _ = mat
                viewModel.selectRecipientFailure()
            }
        } catch {
            // D-12: an unparseable key simply leaves Run disabled; the D-20 error
            // banner path is exercised on engine failures and refined in Task 3.
            viewModel.selectRecipientFailure()
        }
    }

    private func redirectDestination(defaultsTo defaultURL: URL) {
        let panel = NSSavePanel()
        panel.title = "Choose where to save the encrypted file"
        panel.directoryURL = defaultURL.deletingLastPathComponent()
        panel.nameFieldStringValue = defaultURL.lastPathComponent
        guard panel.runModal() == .OK, let url = panel.url else { return }
        viewModel.setDestination(url)
    }
}
