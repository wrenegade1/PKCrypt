import SwiftUI

/// Top-level two-tab shell (D-01): an "Encrypt" tab and a "Decrypt" tab, with
/// the last-open tab remembered across launches via `@AppStorage("selectedTab")`
/// (D-03) and a Help/About affordance that explains, in plain language for
/// non-technical recipients, that only the holder of the intended private key can
/// decrypt an encrypted file (D-06).
struct ContentView: View {
    @AppStorage("selectedTab") private var selectedTab = 0
    @State private var showingHelp = false

    var body: some View {
        TabView(selection: $selectedTab) {
            EncryptView()
                .tabItem { Label("Encrypt", systemImage: "lock.fill") }
                .tag(0)
            DecryptView()
                .tabItem { Label("Decrypt", systemImage: "lock.open.fill") }
                .tag(1)
        }
        .frame(minWidth: 560, minHeight: 460)
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button {
                    showingHelp.toggle()
                } label: {
                    Label("Help", systemImage: "questionmark.circle")
                }
                .popover(isPresented: $showingHelp) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("About CryptFile")
                            .font(.headline)
                        Text("When you encrypt a file, only the holder of the intended private key can decrypt it. You can share encrypted files freely — without the right private key, no one else can open them.")
                            .font(.body)
                            .frame(width: 320, alignment: .leading)
                    }
                    .padding()
                }
            }
        }
    }
}
