import Foundation
import SwiftUI

/// Live counts shown in the menu bar and the status line.
struct Counts: Equatable {
    var running = 0
    var waiting = 0   // open blocking inbox items
    var active = 0    // sessions not ended/archived

    /// Menu-bar label, e.g. "◆ 2▸ 1!". Red when `waiting > 0` (the caller decides colour).
    var menuLabel: String {
        var s = "◆"
        if running > 0 { s += " \(running)▸" }
        if waiting > 0 { s += " \(waiting)!" }
        return s
    }
}

/// How the app is currently attached to a daemon.
enum Link: Equatable {
    case none
    case connecting(String)       // a human phrase: "opening tunnel to 512S1…"
    case connected(baseURL: String)
    case failed(String)           // the error to show, with a retry affordance
}

/// The single observable the UI reads. Everything that mutates it does so on the main actor.
///
/// CONTRACT for the implementer (fields may be added; these are what the UI and menu bar bind to):
/// - `connections` is loaded from and saved to Application Support by `Connection` (see that file).
/// - `active` is the connection currently selected (not necessarily connected).
/// - `link` reflects the tunnel/daemon state; `baseURL`/`token` are set once `connected`.
/// - `counts` and `status` are updated by `DaemonClient` as events arrive.
/// - `connect(_:)` / `disconnect()` drive `Tunnel` + `DaemonClient`; `focusSession` is set when a
///   notification is activated so the web pane can navigate to it (cleared after it is consumed).
@MainActor
final class AppState: ObservableObject {
    @Published var connections: [Connection] = []
    @Published var active: Connection? = nil
    @Published var link: Link = .none
    @Published var counts = Counts()
    @Published var status: String = "not connected"
    @Published var baseURL: String? = nil
    @Published var focusSession: String? = nil

    /// The URL the web pane should load for the current connection, token included
    /// (`<baseURL>/?token=<token>`), or nil when not connected.
    var webEntryURL: URL? {
        // Implemented alongside Tunnel/DaemonClient; see DESIGN.md "Web pane".
        nil
    }

    func connect(_ connection: Connection) { /* see DESIGN.md; drives Tunnel then DaemonClient */ }
    func disconnect() { /* tear down DaemonClient then Tunnel; link = .none */ }
}
