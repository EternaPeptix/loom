import Foundation

/// Read-only client to the active daemon: derives the menu-bar counts and fires notifications when a
/// mission needs a human. See gui/DESIGN.md "Daemon client". It never writes to the daemon — answering
/// and stopping happen in the web UI.
///
/// CONTRACT for the implementer:
/// - `start(baseURL:token:onCounts:onBlockingInbox:)` opens `GET /api/events` (SSE) with the bearer
///   token, keeps a session map and an open-inbox set, and calls `onCounts` whenever the derived
///   counts change. On a new *blocking* inbox item (question / blocker / parked) it calls
///   `onBlockingInbox`. If the stream drops it polls `/api/sessions` and `/api/inbox` every few
///   seconds and keeps retrying the stream.
/// - `stop()` cancels the stream and any polling. Idempotent.
/// - `sseLines(from:)` and `derive(sessions:inbox:)` are factored out so they can be checked without
///   a live daemon (see DESIGN.md "Tests / checks").
final class DaemonClient {
    private var task: Task<Void, Never>?

    func start(baseURL: String,
               token: String?,
               onCounts: @escaping (Counts) -> Void,
               onBlockingInbox: @escaping (_ sessionId: String, _ title: String, _ text: String) -> Void) {
    }

    func stop() { task?.cancel(); task = nil }

    /// Split a byte stream of SSE into complete `data:` payload strings (one per event). Pure helper.
    static func sseEvents(appending chunk: String, to buffer: inout String) -> [String] { [] }

    /// Derive counts from the current session summaries and open blocking inbox items. Pure helper.
    static func derive(running: Int, waiting: Int, active: Int) -> Counts {
        Counts(running: running, waiting: waiting, active: active)
    }
}
