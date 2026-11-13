import SwiftUI
import UserNotifications

/// loom-desk: a menu-bar macOS app around a loom daemon's web UI. See gui/DESIGN.md (normative).
@main
struct LoomDeskApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @ObservedObject private var state = AppState.shared

    init() {
        #if DEBUG
        if CommandLine.arguments.contains("--self-check") { exit(SelfCheck.run()) }
        if let i = CommandLine.arguments.firstIndex(of: "--tunnel-check"), i + 1 < CommandLine.arguments.count {
            exit(SelfCheck.tunnel(host: CommandLine.arguments[i + 1]))
        }
        if let i = CommandLine.arguments.firstIndex(of: "--live-check"), i + 1 < CommandLine.arguments.count {
            exit(SelfCheck.live(baseURL: CommandLine.arguments[i + 1], token: ProcessInfo.processInfo.environment["LOOM_TOKEN"]))
        }
        #endif
    }

    var body: some Scene {
        // The main window, opened on demand and on first launch. A single `Window`, so "Open loom"
        // and notification activation always find the same one.
        Window("loom", id: "main") {
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
            MenuBarLabel().environmentObject(state)
        }
    }
}

/// The menu-bar label. It is alive for the whole run, so it also owns "open the window" requests
/// that come from AppKit callbacks (notification activation) where `openWindow` is not reachable.
struct MenuBarLabel: View {
    @EnvironmentObject var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        content
            .onChange(of: state.openWindowTick) { _, _ in openWindow(id: "main") }
    }

    @ViewBuilder private var content: some View {
        let stale = state.feedStatus.stale && state.link != .none
        let text = stale ? "loom · state unknown" : state.counts.menuLabel
        if state.counts.waiting > 0 && !stale {
            // The menu bar tints plain text as a template; a rendered, non-template image keeps the red.
            let r = ImageRenderer(content: Text(text).font(.system(size: 13, weight: .semibold)).foregroundColor(.red).padding(.horizontal, 2))
            let _ = { r.scale = NSScreen.main?.backingScaleFactor ?? 2 }()
            if let img = r.nsImage {
                let _ = { img.isTemplate = false }()
                Image(nsImage: img)
            } else {
                Text(text).foregroundStyle(.red)
            }
        } else {
            Text(text)
        }
    }
}

/// The menu-bar dropdown: connection + status, Open, switch, Disconnect, Quit.
struct MenuBarMenu: View {
    @EnvironmentObject var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            Text(state.active.map { "Connection: \($0.name)" } ?? "No connection")
            Text(state.status)
            if state.link != .none {
                TimelineView(.periodic(from: .now, by: 5)) { context in
                    Text(state.feedStatus.label(at: context.date))
                }
                if state.feedStatus.lastUpdated != nil {
                    Text((state.feedStatus.stale ? "Last known: " : "") + state.counts.summary)
                    if state.counts.waiting > 0 { Text("\(state.counts.waiting) blocking \(state.counts.waiting == 1 ? "item" : "items") need an answer") }
                }
            }
            Divider()
            Button("Open loom") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
            if !state.connections.isEmpty {
                Menu("Connections") {
                    ForEach(state.connections) { c in
                        Button(c.name.isEmpty ? c.sshHost : c.name) { state.connect(c) }
                    }
                }
            }
            if state.link != .none {
                Button("Disconnect") { state.disconnect() }
            }
            Button("Enable notifications…") { Notifier.requestAuthorization() }
            Divider()
            Button("Quit loom-desk") { NSApp.terminate(nil) }
        }
    }
}

/// Lifecycle: notification setup, restore the last connection, tear the tunnel down on quit.
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        if Bundle.main.bundleURL.pathExtension == "app" {
            UNUserNotificationCenter.current().delegate = self
        }
        Task { @MainActor in AppState.shared.restoreLast() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationWillTerminate(_ notification: Notification) {
        // Runs on the main thread; kill the ssh child before the process goes.
        MainActor.assumeIsolated { AppState.shared.shutdown() }
    }

    // Show banners even while the app is frontmost.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    // Activation: foreground the window and navigate the pane to the session.
    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let session = response.notification.request.content.userInfo["session"] as? String
        Task { @MainActor in
            AppState.shared.openWindow(focus: session)
            completionHandler()
        }
    }
}
