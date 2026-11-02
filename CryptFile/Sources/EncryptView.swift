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
        } else if viewModel.pendingAlternateDestination {
            // D-16: a destination collision blocks the run and prompts for an
            // alternate — nothing overwritten, no silent auto-rename (SAFE-02).
            VStack(alignment: .leading, spacing: 6) {
                Text("File already exists").font(.headline).foregroundStyle(.orange)
                Text("Nothing was overwritten. Choose a different name or location.")
                    .font(.callout)
                    .foregroundStyle(.orange)
                Button("Choose alternate location…") { chooseAlternateDestination() }
            }
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
        if viewModel.destination == nil || !viewModel.isCustomDestination {
            // D-14: the default destination follows the input live (CLI-derived) unless
            // the user has overridden it with a Change… NSSavePanel (D-15).
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
            let comment = KeySelection.comment(of: data)
            let fp = KeySelection.fingerprint(of: data)
            let typeName: String
            switch recipient {
            case .ed25519: typeName = "Ed25519"
            case .rsa: typeName = "RSA"
            }
            // D-08 recipient identity summary: type + comment + truncated
            // fingerprint — never the raw key bytes (T-03-11).
            var parts = [typeName]
            if let comment { parts.append("· \(comment)") }
            parts.append("· \(fp)")
            viewModel.selectRecipient(recipient, summary: parts.joined(separator: " "))
        } catch let e as EngineError {
            // D-12/D-13: an unknown/unsupported key surfaces inline via the D-20
            // seam; Run stays disabled.
            viewModel.reportPickerError(e)
        } catch {
            viewModel.reportPickerError(.keyError("could not read the recipient key"))
        }
    }

    private func redirectDestination(defaultsTo defaultURL: URL) {
        // D-15: full output-path control — BOTH folder and filename — pre-filled with
        // the current default name. Full folder control is granted via canCreateDirectories;
        // on accept the chosen URL is persisted as a security-scoped bookmark and becomes
        // the active (custom) destination.
        let panel = NSSavePanel()
        panel.title = "Choose where to save the encrypted file"
        panel.canCreateDirectories = true
        panel.allowsOtherFileTypes = true
        panel.directoryURL = defaultURL.deletingLastPathComponent()
        panel.nameFieldStringValue = defaultURL.lastPathComponent
        guard panel.runModal() == .OK, let url = panel.url else { return }
        viewModel.setCustomDestination(url)
    }

    /// D-16: after a destination collision, let the user pick a fresh alternate
    /// path and re-run the same operation there (no overwrite, no auto-rename).
    private func chooseAlternateDestination() {
        let panel = NSSavePanel()
        panel.title = "Choose an alternate destination"
        panel.canCreateDirectories = true
        panel.allowsOtherFileTypes = true
        panel.directoryURL = viewModel.destination?.deletingLastPathComponent()
        panel.nameFieldStringValue = viewModel.destination?.lastPathComponent ?? "output"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        viewModel.run(toAlt: url)
    }
}
