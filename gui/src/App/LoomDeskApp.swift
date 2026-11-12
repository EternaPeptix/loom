import SwiftUI

/// loom-desk: a menu-bar macOS app around a loom daemon's web UI. See gui/DESIGN.md (normative).
///
/// This skeleton compiles and shows a menu-bar item and a window. The implementer fills in the
/// connection flow (`Tunnel`, `DaemonClient`, `Connection` persistence), the web pane's real
/// navigation, and notifications, per DESIGN.md. Keep it building at every step.
@main
struct LoomDeskApp: App {
    @StateObject private var state = AppState()

    var body: some Scene {
        // The main window, opened on demand and on first launch.
        WindowGroup("loom", id: "main") {
            RootView()
                .environmentObject(state)
                .frame(minWidth: 900, minHeight: 600)
        }
        .defaultSize(width: 1200, height: 800)

        // The menu-bar presence: counts + quick actions. Lives even with no window open.
        MenuBarExtra {
            MenuBarMenu()
                .environmentObject(state)
        } label: {
            Text(state.counts.menuLabel)
        }
    }
}

/// The menu-bar dropdown. CONTRACT: show the active connection and `state.status`; an "Open loom"
/// item that focuses the window; a connections submenu that switches connection; Disconnect; Quit.
struct MenuBarMenu: View {
    @EnvironmentObject var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            Text(state.active.map { "Connection: \($0.name)" } ?? "No connection")
            Text(state.status).font(.caption)
            Divider()
            Button("Open loom") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
            if case .connected = state.link {
                Button("Disconnect") { state.disconnect() }
            }
            Divider()
            Button("Quit loom-desk") { NSApp.terminate(nil) }
        }
    }
}
