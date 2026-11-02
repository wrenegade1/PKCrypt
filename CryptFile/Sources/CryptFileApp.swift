import SwiftUI

/// CryptFile application entry point (D-04): a single main window app.
///
/// The default `WindowGroup` scene provides exactly one window; because no
/// "New Window" command is exposed, activating the app again (Dock click,
/// Cmd-Tab) brings the existing window to front rather than spawning duplicates.
@main
struct CryptFileApp: App {
    @AppStorage("selectedTab") private var selectedTab = 0

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
