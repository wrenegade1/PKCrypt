// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Warren Zajac
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import PKCryptEngine

/// Decrypt workflow (D-10/D-11/D-13/D-14/D-17/D-18/D-19/D-20): pick a `.pkcrypt`
/// container (default-filtered, with an "All files" escape so renamed containers
/// still load — the engine's magic-header + codec validation is the real check) +
/// the matching private key, confirm/redirect the destination, and Run through the
/// real engine facade. Passphrase-protected private keys are rejected up front via
/// the D-20 seam (D-13).
struct DecryptView: View {
    @ObservedObject var viewModel: WorkflowViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("Choose an encrypted (.pkcrypt) file and the matching private key. Only the holder of the key that matches the encryption can open it.")
                .foregroundStyle(.secondary)

            containerPicker
            keyPicker
            destinationRow

            if viewModel.isRunning {
                progressSection
            }

            actionRow

            resultSection
        }
        .padding()
        .onAppear { viewModel.setMode(.decrypt) }
    }

    // MARK: - Form rows

    private var containerPicker: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Encrypted file").font(.headline)
                Text(viewModel.inputSummary ?? "No .pkcrypt file selected")
                    .font(.callout)
                    .foregroundStyle(viewModel.inputURL == nil ? .secondary : .primary)
            }
            Spacer()
            Button("Choose File…") { openContainer() }
        }
    }

    private var keyPicker: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Private key").font(.headline)
                Text(viewModel.keySummary ?? "No private key selected")
                    .font(.callout)
                    .foregroundStyle(viewModel.privateKey == nil ? .secondary : .primary)
            }
            Spacer()
            Button("Choose Private Key…") { openPrivateKey() }
        }
    }

    private var destinationRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Save to").font(.headline)
                Text(viewModel.destination?.path ?? "Choose a .pkcrypt file to set the default")
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
            Text(viewModel.progressText ?? "Decrypting…")
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
            Text("Cancelled").font(.callout).foregroundStyle(.secondary)
        } else if viewModel.pendingAlternateDestination {
            // D-16: block + prompt for an alternate destination (no overwrite).
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
                Text("Decrypted").font(.headline)
                Text(path).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                Button("Show in Finder") {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
                }
            }
        }
    }

    // MARK: - Panels

    private func openContainer() {
        let panel = NSOpenPanel()
        panel.title = "Choose an encrypted file to decrypt"
        panel.allowsMultipleSelection = false
        if let pkcryptType = UTType(filenameExtension: "pkcrypt") {
            // D-10: default-filter to .pkcrypt but allow "All files" (.data).
            panel.allowedContentTypes = [pkcryptType, .data]
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        viewModel.setInput(url)
        if viewModel.destination == nil || !viewModel.isCustomDestination {
            // D-14: the default destination follows the input live (CLI-derived) unless
            // the user has overridden it with a Change… NSSavePanel (D-15).
            viewModel.setDestination(OutputPath.destination(decrypting: url))
        }
    }

    private func openPrivateKey() {
        let panel = NSOpenPanel()
        panel.title = "Choose the private key"
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard let data = try? Data(contentsOf: url) else { return }
        do {
            let priv = try KeySelection.detectAndParsePrivate(data)
            let comment = KeySelection.comment(of: data)
            let fp = KeySelection.fingerprint(of: data)
            let typeName: String
            switch priv {
            case .ed25519: typeName = "Ed25519"
            case .rsa: typeName = "RSA"
            }
            // D-11 private-key identity summary: type + comment + truncated
            // fingerprint — never the raw private key bytes (T-03-11).
            var parts = ["\(typeName) private key"]
            if let comment { parts.append("· \(comment)") }
            parts.append("· \(fp)")
            viewModel.selectPrivateKey(priv, summary: parts.joined(separator: " "))
        } catch let e as EngineError {
            viewModel.reportPickerError(e)   // D-13 passphrase guard via the D-20 seam
        } catch {
            viewModel.reportPickerError(.keyError("could not read the private key"))
        }
    }

    private func redirectDestination(defaultsTo defaultURL: URL) {
        // D-15: full output-path control — BOTH folder and filename — pre-filled with
        // the current default name. Full folder control via canCreateDirectories; on
        // accept the chosen URL is persisted as a security-scoped bookmark and becomes
        // the active (custom) destination.
        let panel = NSSavePanel()
        panel.title = "Choose where to save the decrypted file"
        panel.canCreateDirectories = true
        panel.allowsOtherFileTypes = true
        panel.directoryURL = defaultURL.deletingLastPathComponent()
        panel.nameFieldStringValue = defaultURL.lastPathComponent
        guard panel.runModal() == .OK, let url = panel.url else { return }
        viewModel.setCustomDestination(url)
    }

    /// D-16: after a destination collision, choose a fresh alternate path and
    /// re-run the same operation there (no overwrite, no auto-rename).
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
