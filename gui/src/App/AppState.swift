import Foundation
import SwiftUI
import UserNotifications
import Network

/// Live counts shown in the menu bar and the status line.
struct Counts: Equatable {
    var running = 0   // missions whose lead or an agent is running
    var waiting = 0   // open blocking inbox items
    var active = 0    // root missions not ended/archived
    var requests = 0  // open scope requests: agents asking for hosts, which do not stop the session
    var runningAgents = 0

    var summary: String {
        "\(running) \(running == 1 ? "mission" : "missions") running · \(runningAgents) \(runningAgents == 1 ? "agent" : "agents") running"
    }

    /// Attention is text rather than a connection-health signal.
    var menuLabel: String {
        var parts: [String] = []
        if running > 0 { parts.append("\(running) \(running == 1 ? "mission" : "missions")") }
        if runningAgents > 0 { parts.append("\(runningAgents) \(runningAgents == 1 ? "agent" : "agents")") }
        if waiting > 0 { parts.append("\(waiting) needs you") }
        if requests > 0 { parts.append("\(requests) asking for hosts") }
        return parts.isEmpty ? "loom" : parts.joined(separator: " · ")
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
    @Published var feedStatus = DaemonClient.FeedStatus()
    /// The OS notification permission, so the menu can show it and guide the operator when it is off.
    @Published var notifStatus: UNAuthorizationStatus = .notDetermined
    @Published var status: String = "not connected"
    /// True while the client's identity check cannot reach the daemon (it keeps retrying); the bar then
    /// shows the link as not connected.
    @Published var daemonUnreachable = false
    @Published var baseURL: String? = nil
    /// Bumped when a notification click or badge tap requests an in-app SPA route via `takeRoute()`.
    @Published private(set) var routeTick = 0

    /// The bearer token of the live connection. Memory only; never logged or written to JSON.
    private var token: String?
    private let tunnel = Tunnel()
    private let client = DaemonClient()
    private var connectTask: Task<Void, Never>?
    private var generation = 0
    private var restored = false
    var offeredFirstRun = false
    /// `<base>/#code=<one-time code>` minted for the web pane of `paneEpoch`. Handed out once: the code is single use.
    private var pendingEntry: URL?
    private var pendingRoute: WebPane.Route?

    /// Auto-reconnect: an SSH tunnel dies on sleep or a network change, so reopen it on wake and when the
    /// network path returns instead of leaving a dead screen with counts and notifications stopped. Set
    /// false after a manual disconnect or a daemon-identity mismatch, where reconnecting would not help.
    private var reconnectable = false
    private var pendingNetworkReconnect = false
    private var lastReconnectAt = Date.distantPast
    private let pathMonitor = NWPathMonitor()
    private var networkSatisfied = true
    private var watching = false

    /// What the web view reports; drives the loading / failure overlay.
    @Published var webState: WebState = .idle {
        didSet { if webState == .loaded { webLoadedOnce = true } }
    }
    @Published var webLoadedOnce = false
    /// Bumped on every connect and every reload so the web pane is rebuilt: a fresh WKWebView and data
    /// store, which asks for its own one-time code (`requestWebEntry`) before it loads anything.
    @Published var paneEpoch = 0
    /// Bumped when a fresh entry URL waits for the web pane in `takeEntryURL()`.
    @Published private(set) var entryTick = 0
    /// Bumped to ask the always-alive menu-bar label to open the main window.
    @Published var openWindowTick = 0
    /// The last problem saving connections / the Keychain, shown by the editor.
    @Published var storageError: String? = nil

    private static let lastKey = "loom-desk.lastConnection"

    init() {
        connections = ConnectionStore.load()
        tunnel.onUnexpectedExit = { [weak self] msg, isCurrent in
            // Checked again on the main actor: a switch of connection in between makes this exit stale.
            Task { @MainActor in if isCurrent() { self?.tunnelDied(msg) } }
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

    private enum EntryOutcome {
        case url(URL)
        case identityMismatch(String)
    }

    /// A fresh entry URL for the live connection: first makes the daemon prove its identity (the token is
    /// not sent to anything that cannot), then asks it for a one-time login code (`POST /api/login-codes`,
    /// bearer token) and builds `<base>/#code=<code>`. The token is never put in a URL. Refuses when
    /// the ssh child of a tunnel connection is gone, so the web view is never pointed at a dead forward.
    private func makeEntryURL(base: String, token: String) async throws -> EntryOutcome {
        let idOutcome = await DaemonClient.verifyIdentity(baseURL: base, token: token)
        try checkTunnelAlive()
        switch idOutcome {
        case .proven:
            break
        case .mismatch(let m):
            return .identityMismatch(m)
        case .unreachable:
            if let m = idOutcome.failure { throw ConnectError(m) }
        }
        let outcome = await DaemonClient.requestLoginCode(baseURL: base, token: token)
        // Before the outcome: when the request failed because the forward is gone, that is the reason.
        try checkTunnelAlive()
        let url: URL?
        switch outcome {
        case .code(let c): url = DaemonClient.codeEntryURL(base: base, code: c)
        case .failed(let m): throw ConnectError(m)
        }
        guard let url else { throw ConnectError("could not build the web address from the daemon URL") }
        return .url(url)
    }

    var isConnected: Bool {
        if case .connected = link { return true }
        return false
    }

    var isTunnelAlive: Bool { active?.mode != .sshTunnel || tunnel.isRunning }

    func isCurrentlyActive(_ connection: Connection) -> Bool {
        guard active?.id == connection.id else { return false }
        switch link {
        case .connecting, .connected: return true
        case .none, .failed: return false
        }
    }

    /// Throws when the active connection is an SSH tunnel whose ssh child is gone.
    private func checkTunnelAlive() throws {
        if !isTunnelAlive {
            let why = tunnel.lastErrorLine
            throw ConnectError("the SSH tunnel closed: \(why.isEmpty ? "ssh is no longer running" : why). Reconnect to open it again.")
        }
    }

    /// Copies the daemon's base address (e.g. `http://127.0.0.1:7878`) and nothing else: no login code, no
    /// token ever reaches the pasteboard. The web UI asks for a login on its own.
    func copyAddress() {
        guard let base = baseURL else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(DaemonClient.addressForPasteboard(base: base), forType: .string)
    }

    /// Reload (and Retry) = a new web pane, which asks for a fresh one-time code. Loading another `#code=`
    /// URL into the old view would change only its fragment and run nothing; a new view always loads.
    func reload() {
        guard case .connected = link else { return }
        pendingEntry = nil
        webLoadedOnce = false
        webState = .loading
        paneEpoch += 1
    }

    /// Navigate the active web pane to the web UI's `#/inbox` route without injecting scripts.
    func openInbox() {
        guard case .connected = link else { return }
        pendingRoute = .inbox
        routeTick += 1
    }

    /// Called once by every newly created web pane (connect, reload, the window built again): asks the
    /// daemon for a one-time code and hands the entry URL to that pane. Nothing is minted ahead of time,
    /// so a pane never gets a spent or expired code.
    func requestWebEntry(for epoch: Int) {
        guard case .connected = link, epoch == paneEpoch, let base = baseURL, let token else { return }
        let gen = generation
        pendingEntry = nil
        webLoadedOnce = false
        webState = .loading
        Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await self.makeEntryURL(base: base, token: token)
                guard gen == self.generation, epoch == self.paneEpoch else { return }
                switch result {
                case .url(let u):
                    self.pendingEntry = u
                    self.entryTick += 1
                case .identityMismatch(let why):
                    self.failIdentity(why)
                }
            } catch {
                guard gen == self.generation, epoch == self.paneEpoch else { return }
                self.webState = .failed("\(error)")
            }
        }
    }

    /// The minted entry URL, once. Nil when there is none, or when the tunnel's ssh has exited since:
    /// checked right before the pane loads, so it never loads against a forward whose ssh is gone
    /// (`tunnelDied` reports that). Called from the pane's update: changes nothing published.
    func takeEntryURL() -> URL? {
        defer { pendingEntry = nil }
        guard isTunnelAlive else { return nil }
        return pendingEntry
    }

    /// The pending SPA route (notification session focus or inbox jump), consumed once without mutating published state.
    func takeRoute() -> WebPane.Route? {
        defer { pendingRoute = nil }
        guard isTunnelAlive else { return nil }
        return pendingRoute
    }

    // MARK: connect / disconnect

    func connect(_ connection: Connection) {
        let switchingConnection = active?.id != connection.id
        teardown()
        generation += 1
        let gen = generation
        paneEpoch += 1
        active = connection
        // A tunnel connection is worth reopening by itself after a drop; a direct one has nothing to reopen.
        reconnectable = connection.mode == .sshTunnel
        pendingNetworkReconnect = false
        daemonUnreachable = false
        if switchingConnection {
            pendingRoute = nil
            Notifier.withdrawAll()
        }
        counts = Counts()
        feedStatus = DaemonClient.FeedStatus()
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
                    base = r.baseURL
                    if let fetched = r.token {
                        tok = fetched
                        if !ConnectionStore.setToken(fetched, for: connection.id) {
                            self.storageError = "connected, but could not store the fetched token in the Keychain"
                        }
                    } else {
                        tok = ConnectionStore.token(for: connection.id)
                    }
                case .direct:
                    if let problem = ConnectionStore.baseURLProblem(connection.baseURL) { throw ConnectError(problem) }
                    guard let b = ConnectionStore.normalizedBaseURL(connection.baseURL) else {
                        throw ConnectError("the base URL is not a valid http(s) URL")
                    }
                    base = b
                    tok = ConnectionStore.token(for: connection.id)
                }
                guard let tok, ConnectionStore.isValidToken(tok) else {
                    throw ConnectError("no valid token stored for this connection — edit it and paste the 64-character token")
                }
                // The token goes to nothing that cannot prove it is this token's daemon.
                if let m = await DaemonClient.verifyIdentity(baseURL: base, token: tok).failure {
                    // An ssh that died meanwhile is the real reason, with its own last error line.
                    if gen == self.generation { try self.checkTunnelAlive() }
                    throw ConnectError(m)
                }
                try Task.checkCancellation()
                guard gen == self.generation else { return }
                try self.checkTunnelAlive()
                // No await from here on: an ssh exit is either seen by open() above or, once the link
                // is .connected, by tunnelDied. The web pane mints its login code when it is built.
                self.token = tok
                self.baseURL = base
                self.link = .connected(baseURL: base)
                self.status = "connected"
                self.daemonUnreachable = false
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
                if self.pendingNetworkReconnect && self.reconnectable {
                    self.pendingNetworkReconnect = false
                    self.lastReconnectAt = Date()
                    self.connect(connection)
                }
            }
        }
    }

    func disconnect() {
        teardown()
        generation += 1
        reconnectable = false   // the operator chose to stop; do not reopen it on wake
        pendingNetworkReconnect = false
        active = nil
        daemonUnreachable = false
        pendingRoute = nil
        Notifier.withdrawAll()
        link = .none
        status = "not connected"
        counts = Counts()
        feedStatus = DaemonClient.FeedStatus()
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
        pendingEntry = nil
    }

    /// The daemon was replaced by something that cannot prove itself: drop the token and fail the link.
    private func failIdentity(_ why: String) {
        generation += 1
        reconnectable = false
        pendingNetworkReconnect = false
        client.stop()
        tunnel.close()
        token = nil
        baseURL = nil
        pendingEntry = nil
        pendingRoute = nil
        counts = Counts()
        daemonUnreachable = false
        link = .failed(why)
        status = "daemon not verified"
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
            onNotify: { [weak self] n in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    Notifier.post(n)
                }
            },
            onResolve: { [weak self] itemId in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    Notifier.withdraw(itemId: itemId)
                }
            },
            onMode: { [weak self] mode in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    if mode.hasPrefix(DaemonClient.identityModePrefix) {
                        self.failIdentity(String(mode.dropFirst(DaemonClient.identityModePrefix.count)))
                        return
                    }
                    if mode.hasPrefix(DaemonClient.unreachableModePrefix) {
                        self.daemonUnreachable = true
                        self.status = mode
                        return
                    }
                    if self.daemonUnreachable {
                        self.daemonUnreachable = false
                        self.status = self.feedStatus.label(at: Date())
                    }
                }
            },
            onFeedStatus: { [weak self] feed in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    self.feedStatus = feed
                    if !self.daemonUnreachable {
                        self.status = feed.label(at: Date())
                    }
                }
            })
    }

    private func tunnelDied(_ msg: String) {
        // While connecting, open() reports the exit itself (with a better message, e.g. a busy port).
        guard case .connected = link else { return }
        generation += 1          // drops in-flight code requests and late client callbacks
        client.stop()
        token = nil
        baseURL = nil
        pendingEntry = nil
        counts = Counts()
        feedStatus.failed("stream", reason: msg)
        link = .failed("the SSH tunnel closed: \(msg). Reconnecting when the network returns…")
        status = "tunnel closed"
        // The tunnel typically dies on sleep or a network change; try now in case the network is already
        // back, and the wake / network-path watchers will try again when it returns.
        maybeAutoReconnect("tunnel closed")
    }

    // MARK: auto-reconnect

    /// Watch for system wake, network-path changes, and menu opens. Called once at launch (idempotent).
    func beginWatching() {
        guard !watching else { return }
        watching = true
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let up = path.status == .satisfied
            Task { @MainActor in
                guard let self else { return }
                let cameBack = up && !self.networkSatisfied
                self.networkSatisfied = up
                if cameBack { self.handleNetworkReturned() }
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "loom-desk.path"))
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.maybeAutoReconnect("woke") }
        }
        NotificationCenter.default.addObserver(
            forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refreshNotificationStatus() }
        }
    }

    /// Network path just transitioned from unsatisfied to satisfied: never let the 4 s debounce drop it,
    /// and if an earlier connect is still in flight, retry once if it fails.
    private func handleNetworkReturned() {
        guard reconnectable, let a = active, a.mode == .sshTunnel else { return }
        switch link {
        case .failed:
            pendingNetworkReconnect = false
            lastReconnectAt = Date()
            connect(a)
        case .connecting:
            pendingNetworkReconnect = true
        case .none, .connected:
            break
        }
    }

    /// Reopen a dropped tunnel connection. Event-driven (wake / the drop itself) and debounced, never a
    /// tight loop; a connect that fails leaves `.failed` and waits for the next event.
    private func maybeAutoReconnect(_ reason: String) {
        guard reconnectable, case .failed = link, let a = active, a.mode == .sshTunnel else { return }
        guard Date().timeIntervalSince(lastReconnectAt) > 4 else { return }
        lastReconnectAt = Date()
        connect(a)
    }

    // MARK: connections list

    /// Insert or replace, persist, and optionally store or clear a token in the Keychain.
    func upsert(_ c: Connection, token newToken: String?, clearToken: Bool = false) {
        if let i = connections.firstIndex(where: { $0.id == c.id }) { connections[i] = c } else { connections.append(c) }
        if active?.id == c.id { active = c }
        var problems: [String] = []
        if !ConnectionStore.save(connections) { problems.append("could not write connections.json") }
        if let t = newToken, !t.isEmpty {
            if !ConnectionStore.setToken(t, for: c.id) {
                problems.append("could not store the token in the Keychain")
            }
        } else if clearToken {
            ConnectionStore.clearToken(for: c.id)
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

    /// Read the OS notification permission into `notifStatus` (so the menu can reflect it). Called at
    /// launch, when the app becomes active, and when a menu opens.
    func refreshNotificationStatus() {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return }
        UNUserNotificationCenter.current().getNotificationSettings { s in
            let status = s.authorizationStatus
            Task { @MainActor in self.notifStatus = status }
        }
    }

    /// Bring the window forward; navigate the pane to `session` when given while a link is active/opening.
    func openWindow(focus session: String? = nil) {
        openWindowTick += 1
        if let session {
            switch link {
            case .connected, .connecting:
                pendingRoute = .session(session)
                routeTick += 1
            case .none, .failed:
                break
            }
        }
        NSApp.activate(ignoringOtherApps: true)
        for w in NSApp.windows where w.canBecomeMain {
            if w.isMiniaturized { w.deminiaturize(nil) }
            w.makeKeyAndOrderFront(nil)
        }
    }

    struct ConnectError: Error, CustomStringConvertible {
        var description: String
        init(_ d: String) { description = d }
    }
}

/// Local notifications for sessions that need a human.
enum Notifier {
    private static var available: Bool { Bundle.main.bundleURL.pathExtension == "app" }

    @MainActor
    static func requestAuthorization() {
        guard available else { return }
        NSApp.activate(ignoringOtherApps: true)
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in
            Task { @MainActor in AppState.shared.refreshNotificationStatus() }
        }
    }

    /// Title names the mission (the session title), body is the item text, cut. Keyed by the item id,
    /// so re-notifying the same item replaces its banner rather than stacking, and `withdraw` can clear
    /// it once the item is answered.
    static func post(_ n: DaemonClient.InboxNotice) {
        guard available else { return }
        let c = UNMutableNotificationContent()
        let prefix = n.isScope ? "Host request · " : ""
        c.title = cut(prefix + (n.title.isEmpty ? "loom" : n.title), 80)
        c.body = cut(n.text, 180)
        c.sound = .default
        c.userInfo = ["session": n.session]
        let req = UNNotificationRequest(identifier: n.itemId, content: c, trigger: nil)
        UNUserNotificationCenter.current().add(req) { _ in }
    }

    /// Remove a notification once its item is answered/dismissed, so Notification Center does not keep a
    /// stale "needs you" banner for something already handled.
    static func withdraw(itemId: String) {
        guard available else { return }
        let center = UNUserNotificationCenter.current()
        center.removeDeliveredNotifications(withIdentifiers: [itemId])
        center.removePendingNotificationRequests(withIdentifiers: [itemId])
    }

    static func withdrawAll() {
        guard available else { return }
        let center = UNUserNotificationCenter.current()
        center.removeAllDeliveredNotifications()
        center.removeAllPendingNotificationRequests()
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
                onNotify: { print("notify: \($0)") },
                onResolve: { print("resolved: \($0)") },
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
        if Counts(running: 2, waiting: 1, active: 3, runningAgents: 4).menuLabel != "2 missions · 4 agents · 1 needs you" { failures.append("Counts.menuLabel") }
        if Counts(running: 0, waiting: 0, active: 1, requests: 2).menuLabel != "2 asking for hosts" { failures.append("Counts.menuLabel requests") }
        if Counts().menuLabel != "loom" { failures.append("Counts.menuLabel empty") }
        if Counts(running: 1, runningAgents: 1).summary != "1 mission running · 1 agent running" { failures.append("Counts.summary singular") }
        if Notifier.cut("a\nb", 10) != "a b" || Notifier.cut(String(repeating: "x", count: 20), 5).count != 5 {
            failures.append("Notifier.cut")
        }
        for f in failures { print("FAIL \(f)") }
        print(failures.isEmpty ? "self-check: all passed" : "self-check: \(failures.count) failed")
        return failures.isEmpty ? 0 : 1
    }
}
#endif
