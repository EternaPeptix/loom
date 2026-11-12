import Foundation
import SwiftUI
import UserNotifications

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
    case connecting(String)       // a human phrase: "opening tunnel to studio…"
    case connected(baseURL: String)
    case failed(String)           // the error to show, with a retry affordance
}

/// The single observable the UI reads. Everything that mutates it does so on the main actor.
@MainActor
final class AppState: ObservableObject {
    static let shared = AppState()

    @Published var connections: [Connection] = []
    @Published var active: Connection? = nil
    @Published var link: Link = .none
    @Published var counts = Counts()
    @Published var status: String = "not connected"
    @Published var baseURL: String? = nil
    @Published var focusSession: String? = nil

    /// What the web view reports; drives the loading / failure overlay.
    @Published var webState: WebState = .idle {
        didSet { if webState == .loaded { webLoadedOnce = true } }
    }
    @Published var webLoadedOnce = false
    /// The URL the web pane loads: `<base>/#code=<one-time code>` (or, for an old daemon, the token URL).
    /// Replaced by a URL with a fresh code on every reload; nil when not connected.
    @Published var webEntryURL: URL? = nil
    /// Bumped on every connect so the web pane is rebuilt with a fresh data store.
    @Published var connectionEpoch = 0
    /// Bumped to ask the always-alive menu-bar label to open the main window.
    @Published var openWindowTick = 0
    /// The last problem saving connections / the Keychain, shown by the editor.
    @Published var storageError: String? = nil

    /// The bearer token of the live connection. Memory only; never logged or written to JSON.
    private var token: String?
    private let tunnel = Tunnel()
    private let client = DaemonClient()
    private var connectTask: Task<Void, Never>?
    private var generation = 0
    private var restored = false
    /// True once `tunnel.open` has returned for the current connect; before that `open` reports an ssh
    /// exit itself (with a better message, e.g. a busy port).
    private var tunnelOpened = false

    private static let lastKey = "loom-desk.lastConnection"

    init() {
        connections = ConnectionStore.load()
        tunnel.onUnexpectedExit = { [weak self] msg in
            Task { @MainActor in self?.tunnelDied(msg) }
        }
    }

    /// Reconnect the last-used connection (once, at launch).
    func restoreLast() {
        guard !restored else { return }
        restored = true
        guard let s = UserDefaults.standard.string(forKey: Self.lastKey),
              let id = UUID(uuidString: s),
              let c = connections.first(where: { $0.id == id }) else { return }
        connect(c)
    }

    // MARK: URLs

    /// A fresh entry URL for the live connection: asks the daemon for a one-time login code
    /// (`POST /api/login-codes`, bearer token) and builds `<base>/#code=<code>`. A daemon that answers 404
    /// predates the route; only then is the token placed in a URL (`<base>/?token=<token>`). Refuses when
    /// the ssh child of a tunnel connection is gone, so the web view is never pointed at a dead forward.
    private func makeEntryURL(base: String, token: String) async throws -> URL {
        let url: URL?
        switch await DaemonClient.requestLoginCode(baseURL: base, token: token) {
        case .code(let c): url = DaemonClient.codeEntryURL(base: base, code: c)
        case .notFound: url = DaemonClient.tokenEntryURL(base: base, token: token)
        case .failed(let m): throw ConnectError(m)
        }
        if active?.mode == .sshTunnel && !tunnel.isRunning {
            throw ConnectError("the SSH tunnel is no longer running. Reconnect to open it again.")
        }
        guard let url else { throw ConnectError("could not build the web address from the daemon URL") }
        return url
    }

    func copyWebURL() {
        guard let base = baseURL, let token else { return }
        let gen = generation
        Task { [weak self] in
            guard let self else { return }
            do {
                let u = try await self.makeEntryURL(base: base, token: token)
                guard gen == self.generation else { return }
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(u.absoluteString, forType: .string)
                self.status = u.query == nil ? "web URL copied (single use, valid for 60 s)" : "web URL copied (it carries the token)"
            } catch {
                guard gen == self.generation else { return }
                self.status = "\(error)"
            }
        }
    }

    /// Reload = a new one-time code, hence a new URL; the web pane loads whatever URL it is given.
    func reload() {
        guard let base = baseURL, let token else { return }
        let gen = generation
        webState = .loading
        Task { [weak self] in
            guard let self else { return }
            do {
                let u = try await self.makeEntryURL(base: base, token: token)
                guard gen == self.generation else { return }
                self.webEntryURL = u
            } catch {
                guard gen == self.generation else { return }
                self.webState = .failed("\(error)")
            }
        }
    }

    // MARK: connect / disconnect

    func connect(_ connection: Connection) {
        teardown()
        generation += 1
        let gen = generation
        tunnelOpened = false
        connectionEpoch += 1
        active = connection
        counts = Counts()
        webState = .idle
        webLoadedOnce = false
        UserDefaults.standard.set(connection.id.uuidString, forKey: Self.lastKey)
        let name = connection.name.isEmpty ? connection.sshHost : connection.name
        link = .connecting(connection.mode == .sshTunnel ? "opening tunnel to \(name)…" : "connecting to \(name)…")
        status = "connecting…"

        connectTask = Task { [weak self] in
            guard let self else { return }
            do {
                let base: String
                var tok: String?
                switch connection.mode {
                case .sshTunnel:
                    let r = try await self.tunnel.open(connection)
                    self.tunnelOpened = true
                    base = r.baseURL
                    if let fetched = r.token {
                        tok = fetched
                        _ = ConnectionStore.setToken(fetched, for: connection.id)
                    } else {
                        tok = ConnectionStore.token(for: connection.id)
                    }
                case .direct:
                    guard let b = ConnectionStore.normalizedBaseURL(connection.baseURL) else {
                        throw ConnectError("the base URL is not a valid http(s) URL")
                    }
                    base = b
                    tok = ConnectionStore.token(for: connection.id)
                }
                guard let tok, ConnectionStore.isValidToken(tok) else {
                    throw ConnectError("no valid token stored for this connection — edit it and paste the 64-character token")
                }
                self.token = tok
                self.baseURL = base
                let entry = try await self.makeEntryURL(base: base, token: tok)
                try Task.checkCancellation()
                guard gen == self.generation else { return }
                self.webEntryURL = entry
                self.link = .connected(baseURL: base)
                self.status = "connected"
                self.startClient(base: base, token: tok, gen: gen)
            } catch is CancellationError {
                return
            } catch {
                guard gen == self.generation else { return }
                self.tunnel.close()
                self.token = nil
                self.baseURL = nil
                let msg = (error as? ConnectError)?.description ?? (error as? Tunnel.TunnelError)?.description ?? error.localizedDescription
                self.link = .failed(msg)
                self.status = "failed"
            }
        }
    }

    func disconnect() {
        teardown()
        generation += 1
        link = .none
        status = "not connected"
        counts = Counts()
        webState = .idle
    }

    /// Called on app quit: stop everything, kill the ssh child before returning.
    func shutdown() {
        connectTask?.cancel()
        client.stop()
        tunnel.closeBlocking()
    }

    private func teardown() {
        connectTask?.cancel()
        connectTask = nil
        client.stop()
        tunnel.close()
        token = nil
        baseURL = nil
        webEntryURL = nil
    }

    private func startClient(base: String, token: String, gen: Int) {
        client.start(
            baseURL: base, token: token,
            onCounts: { [weak self] c in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    self.counts = c
                }
            },
            onBlockingInbox: { [weak self] session, title, text in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    Notifier.post(session: session, title: title, text: text)
                }
            },
            onMode: { [weak self] mode in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    self.status = mode == "live" ? "connected · live" : "connected · \(mode)"
                }
            })
    }

    private func tunnelDied(_ msg: String) {
        switch link {
        case .connected: break
        case .connecting: if !tunnelOpened { return }
        default: return
        }
        // Also while still connecting: end the connect task so the web view is never loaded on a dead forward.
        connectTask?.cancel()
        generation += 1
        client.stop()
        token = nil
        baseURL = nil
        webEntryURL = nil
        counts = Counts()
        link = .failed("the SSH tunnel closed: \(msg)")
        status = "tunnel closed"
    }

    // MARK: connections list

    /// Insert or replace, persist, and (optionally) store a manually entered token in the Keychain.
    func upsert(_ c: Connection, token newToken: String?) {
        if let i = connections.firstIndex(where: { $0.id == c.id }) { connections[i] = c } else { connections.append(c) }
        if active?.id == c.id { active = c }
        var problems: [String] = []
        if !ConnectionStore.save(connections) { problems.append("could not write connections.json") }
        if let t = newToken, !t.isEmpty, !ConnectionStore.setToken(t, for: c.id) {
            problems.append("could not store the token in the Keychain")
        }
        storageError = problems.isEmpty ? nil : problems.joined(separator: "; ")
    }

    func remove(_ c: Connection) {
        if active?.id == c.id { disconnect(); active = nil }
        connections.removeAll { $0.id == c.id }
        ConnectionStore.clearToken(for: c.id)
        storageError = ConnectionStore.save(connections) ? nil : "could not write connections.json"
        if UserDefaults.standard.string(forKey: Self.lastKey) == c.id.uuidString {
            UserDefaults.standard.removeObject(forKey: Self.lastKey)
        }
    }

    // MARK: window / notification routing

    /// Bring the window forward; navigate the pane to `session` when given.
    func openWindow(focus session: String? = nil) {
        openWindowTick += 1
        if let session { focusSession = session }
        NSApp.activate(ignoringOtherApps: true)
        for w in NSApp.windows where w.canBecomeMain { w.makeKeyAndOrderFront(nil) }
    }

    struct ConnectError: Error, CustomStringConvertible {
        var description: String
        init(_ d: String) { description = d }
    }
}

/// Local notifications for sessions that need a human.
enum Notifier {
    private static var available: Bool { Bundle.main.bundleURL.pathExtension == "app" }

    static func requestAuthorization() {
        guard available else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Title names the mission (the session title), body is the item text, cut.
    static func post(session: String, title: String, text: String) {
        guard available else { return }
        let c = UNMutableNotificationContent()
        c.title = cut(title.isEmpty ? "loom" : title, 80)
        c.body = cut(text, 180)
        c.sound = .default
        c.userInfo = ["session": session]
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil)
        UNUserNotificationCenter.current().add(req) { _ in }
    }

    static func cut(_ s: String, _ n: Int) -> String {
        let one = s.split(whereSeparator: \.isNewline).joined(separator: " ")
        return one.count <= n ? one : String(one.prefix(n - 1)) + "…"
    }
}

#if DEBUG
enum SelfCheck {
    /// Opens a real ssh tunnel to `host` (daemon on 7878 there), fetches the token, prints whether it
    /// validates (never the token itself), then closes.
    static func tunnel(host: String) -> Int32 {
        final class Box: @unchecked Sendable { var code: Int32 = 1 }
        let box = Box()
        let sem = DispatchSemaphore(value: 0)
        let t = Tunnel()
        Task.detached {
            var c = Connection(name: "check"); c.sshHost = host
            do {
                let r = try await t.open(c)
                print("tunnel up at \(r.baseURL); token valid: \(r.token.map(ConnectionStore.isValidToken) ?? false)")
                box.code = 0
            } catch { print("tunnel failed: \(error)") }
            t.close()
            try? await Task.sleep(nanoseconds: 500_000_000)
            sem.signal()
        }
        sem.wait()
        return box.code
    }

    /// Runs the real DaemonClient against a daemon for a few seconds (token from $LOOM_TOKEN).
    static func live(baseURL: String, token: String?) -> Int32 {
        let c = DaemonClient()
        c.start(baseURL: baseURL, token: token,
                onCounts: { print("counts: \($0)") },
                onBlockingInbox: { print("blocking: \($0) \($1) \($2)") },
                onMode: { print("mode: \($0)") })
        Thread.sleep(forTimeInterval: 4)
        c.stop()
        return 0
    }

    /// Runs every pure-helper check; returns the process exit status (0 = all passed).
    static func run() -> Int32 {
        var failures: [String] = []
        failures += ConnectionStore.selfCheck()
        failures += Tunnel.selfCheck()
        failures += DaemonClient.selfCheck()
        failures += WebPane.selfCheck()
        if Counts(running: 2, waiting: 1, active: 3).menuLabel != "◆ 2▸ 1!" { failures.append("Counts.menuLabel") }
        if Counts().menuLabel != "◆" { failures.append("Counts.menuLabel empty") }
        if Notifier.cut("a\nb", 10) != "a b" || Notifier.cut(String(repeating: "x", count: 20), 5).count != 5 {
            failures.append("Notifier.cut")
        }
        for f in failures { print("FAIL \(f)") }
        print(failures.isEmpty ? "self-check: all passed" : "self-check: \(failures.count) failed")
        return failures.isEmpty ? 0 : 1
    }
}
#endif
