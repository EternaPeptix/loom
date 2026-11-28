import AppKit
import Foundation
import Network
import Security
import SwiftUI
import UserNotifications
import WebKit

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

    /// Full verbose label (used for VoiceOver and when compact menu bar is off).
    var menuLabel: String {
        var parts: [String] = []
        if running > 0 { parts.append("\(running) \(running == 1 ? "mission" : "missions")") }
        if runningAgents > 0 { parts.append("\(runningAgents) \(runningAgents == 1 ? "agent" : "agents")") }
        if waiting > 0 { parts.append("\(waiting) needs you") }
        if requests > 0 { parts.append("\(requests) asking for hosts") }
        return parts.isEmpty ? "ferret" : parts.joined(separator: " · ")
    }

    /// Notch-safe compact label for MacBook menu bars: urgent count comes first so it survives truncation.
    var compactMenuLabel: String {
        var parts: [String] = []
        if waiting > 0 { parts.append("!\(waiting)") }
        if running > 0 { parts.append("\(running)m") }
        if runningAgents > 0 { parts.append("\(runningAgents)a") }
        if requests > 0 { parts.append("?\(requests)") }
        return parts.isEmpty ? "ferret" : parts.joined(separator: " ")
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
    @Published var link: Link = .none {
        didSet { updateDockBadge() }
    }
    @Published var counts = Counts() {
        didSet { updateDockBadge() }
    }
    @Published var feedStatus = DaemonClient.FeedStatus() {
        didSet { updateDockBadge() }
    }
    /// The OS notification permission, so the menu and connection bar can reflect it.
    @Published var notifStatus: UNAuthorizationStatus = .notDetermined
    @Published var status: String = "not connected"
    /// True while the client's identity check cannot reach the daemon (it keeps retrying); the bar then
    /// shows the link as not connected.
    @Published var daemonUnreachable = false {
        didSet { updateDockBadge() }
    }
    @Published var baseURL: String? = nil
    /// Bumped when a notification click, badge tap, or reload-restore requests an in-app SPA route via `takeRoute()`.
    @Published private(set) var routeTick = 0

    /// The bearer token of the live connection. Memory only; never logged or written to JSON.
    private var token: String?
    private let tunnel = Tunnel()
    private let client = DaemonClient()
    private var connectTask: Task<Void, Never>?
    private var backoffTask: Task<Void, Never>?
    private var wakeProbeTask: Task<Void, Never>?
    private var backoffAttempt = 0
    private var generation = 0
    private var restored = false
    var offeredFirstRun = false
    /// `<base>/#code=<one-time code>` minted for the web pane of `paneEpoch`. Handed out once: the code is single use.
    private var pendingEntry: URL?
    private var pendingRoute: WebPane.Route?
    /// Last non-code `#/...` SPA fragment observed on the active web view, restored across reloads/re-auth.
    private var lastRouteFragment: String?
    /// Per-connection ephemeral data store: never touches disk, preserved across reloads of the SAME connection,
    /// replaced on disconnect / connection switch / identity failure.
    private(set) var webDataStore: WKWebsiteDataStore = .nonPersistent()
    /// Preserves seen/notified inbox sets across reconnects of the SAME connection.
    private var notificationSeeds: [UUID: DaemonClient.NotificationSeed] = [:]
    /// Guards automatic relogin / crash-recovery reloads against infinite loops.
    private var autoReloadCount = 0
    private var lastAutoReloadAt = Date.distantPast
    /// App Nap prevention token while monitoring a live connection with no visible window.
    private var backgroundActivity: NSObjectProtocol?

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
    /// Bumped on every connect and every reload so the web pane is rebuilt: a fresh WKWebView
    /// which asks for its own one-time code (`requestWebEntry`) before it loads anything.
    @Published var paneEpoch = 0
    /// Bumped when a fresh entry URL waits for the web pane in `takeEntryURL()`.
    @Published private(set) var entryTick = 0
    /// Bumped to ask the always-alive menu-bar label to open the main window.
    @Published var openWindowTick = 0
    struct DownloadNotice: Equatable {
        let text: String
        let fileURL: URL?
    }

    /// FIFO queue for navigation/focus/zoom commands so back-to-back mutations in one turn never overwrite each other.
    struct NavActionQueue: Equatable {
        private var items: [WebPane.NavAction] = []
        mutating func enqueue(_ action: WebPane.NavAction) { items.append(action) }
        mutating func drain() -> [WebPane.NavAction] {
            let out = items
            items.removeAll(keepingCapacity: true)
            return out
        }
        mutating func clear() { items.removeAll(keepingCapacity: false) }
    }

    /// The last problem saving connections / the Keychain, shown in ConnectionsView and the status banner.
    @Published var storageError: String? = nil
    /// Non-blocking status toast for completed/failed downloads (with optional file URL for "Reveal in Finder").
    @Published var downloadNotice: DownloadNotice? = nil
    private var downloadNoticeTask: Task<Void, Never>?
    /// When transient SSH auto-reconnect backoff is counting down, when the next attempt fires.
    @Published var nextReconnectAt: Date? = nil
    /// True when transient SSH auto-reconnect is paused waiting for the network path to return.
    @Published var waitingForNetwork = false
    /// Bumped whenever a Keychain token is stored or cleared so ConnectionsView refreshes its cached token map.
    @Published private(set) var tokenPresenceEpoch = 0

    // MARK: desktop UX state (zoom, find, nav, connections sheet, compact menu bar)

    @Published var pageZoom: CGFloat {
        didSet { UserDefaults.standard.set(Double(pageZoom), forKey: Self.zoomKey) }
    }
    @Published var compactMenuBar: Bool {
        didSet { UserDefaults.standard.set(compactMenuBar, forKey: Self.compactMenuBarKey) }
    }
    @Published var findVisible = false
    @Published var findQuery = ""
    @Published var findNotFound = false
    @Published private(set) var findTick = 0
    @Published private(set) var findFocusTick = 0
    private var pendingFindAction: WebPane.FindAction?
    private var findDebounceTask: Task<Void, Never>?

    @Published var canGoBack = false
    @Published var canGoForward = false
    @Published private(set) var navTick = 0
    private var navQueue = NavActionQueue()

    @Published var showingConnectionsSheet = false
    @Published var editingConnection: Connection? = nil

    nonisolated static let backoffDelays: [TimeInterval] = [2, 5, 10, 20, 30]
    private static let lastKey = "ferret-desk.lastConnection"
    private static let zoomKey = "ferret-desk.pageZoom"
    private static let compactMenuBarKey = "ferret-desk.compactMenuBar"

    init() {
        let savedZoom = UserDefaults.standard.double(forKey: Self.zoomKey)
        self.pageZoom = (savedZoom >= 0.5 && savedZoom <= 2.5) ? CGFloat(savedZoom) : 1.0
        if UserDefaults.standard.object(forKey: Self.compactMenuBarKey) != nil {
            self.compactMenuBar = UserDefaults.standard.bool(forKey: Self.compactMenuBarKey)
        } else {
            self.compactMenuBar = true
        }
        connections = ConnectionStore.load()
        tunnel.onUnexpectedExit = { [weak self] msg, isCurrent in
            // Checked again on the main actor: a switch of connection in between makes this exit stale.
            Task { @MainActor in if isCurrent() { self?.tunnelDied(msg) } }
        }
    }

    /// Dynamic window title reflecting the active connection and urgent count.
    var windowTitle: String {
        guard let active else { return "ferret" }
        let stale = feedStatus.stale || daemonUnreachable
        if case .connected = link, !stale, counts.waiting > 0 {
            return "(\(counts.waiting)) \(active.displayName) — ferret"
        }
        return "\(active.displayName) — ferret"
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

    /// Mints a fresh one-time login code (preserving the `/healthz` HMAC proof) and opens the daemon UI
    /// in the default browser. Never writes any code or token to the pasteboard.
    func openInDefaultBrowser() {
        guard case .connected = link, let base = baseURL, let token, isTunnelAlive else { return }
        let gen = generation
        Task { [weak self] in
            guard let self else { return }
            do {
                let result = try await self.makeEntryURL(base: base, token: token)
                guard gen == self.generation else { return }
                switch result {
                case .url(let u):
                    NSWorkspace.shared.open(u)
                case .identityMismatch(let why):
                    self.failIdentity(why)
                }
            } catch {
                guard gen == self.generation else { return }
                self.showDownloadNotice("Could not open browser: \(error)")
            }
        }
    }

    /// Reload (and Retry) = a new web pane, which asks for a fresh one-time code while preserving the
    /// operator's current `#/...` mission/tab route and per-connection ephemeral web store.
    func reload(preserveRoute: Bool = true) {
        guard case .connected = link else { return }
        pendingEntry = nil
        webLoadedOnce = false
        webState = .loading
        if preserveRoute, pendingRoute == nil, let frag = lastRouteFragment {
            pendingRoute = .fragment(frag)
            routeTick += 1
        }
        paneEpoch += 1
    }

    /// Navigate the active web pane to the web UI's `#/inbox` route without injecting scripts.
    func openInbox() {
        guard case .connected = link else { return }
        pendingRoute = .inbox
        routeTick += 1
    }

    func openWindowToInbox() {
        openWindow()
        openInbox()
    }

    func openConnectionsManager() {
        openWindow()
        if link != .none {
            showingConnectionsSheet = true
        }
    }

    // MARK: web pane zoom / find / navigation / recovery

    func zoomIn() {
        pageZoom = min(2.5, (pageZoom * 10 + 1).rounded() / 10)
    }

    func zoomOut() {
        pageZoom = max(0.5, (pageZoom * 10 - 1).rounded() / 10)
    }

    func zoomReset() {
        pageZoom = 1.0
        guard isConnected else { return }
        enqueueNav(.resetZoom)
    }

    func openFind() {
        guard isConnected else { return }
        findVisible = true
        findNotFound = false
        findFocusTick += 1
    }

    func closeFind() {
        findDebounceTask?.cancel()
        findDebounceTask = nil
        findVisible = false
        findNotFound = false
        clearFindHighlight()
        focusWebPane()
    }

    func clearFindHighlight() {
        findDebounceTask?.cancel()
        findDebounceTask = nil
        findNotFound = false
        guard isConnected else { return }
        pendingFindAction = .clear
        findTick += 1
    }

    /// Debounced live-type search so typing a full word lands on the first match instead of advancing on every keystroke.
    func findQueryChanged(_ newValue: String) {
        findDebounceTask?.cancel()
        findDebounceTask = nil
        if newValue.isEmpty {
            clearFindHighlight()
            return
        }
        findNotFound = false
        findDebounceTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(150))
            guard !Task.isCancelled, let self, self.findVisible, self.findQuery == newValue else { return }
            self.findNext()
        }
    }

    func findNext() {
        findDebounceTask?.cancel()
        findDebounceTask = nil
        guard isConnected, !findQuery.isEmpty else { return }
        pendingFindAction = .find(query: findQuery, backwards: false)
        findTick += 1
    }

    func findPrevious() {
        findDebounceTask?.cancel()
        findDebounceTask = nil
        guard isConnected, !findQuery.isEmpty else { return }
        pendingFindAction = .find(query: findQuery, backwards: true)
        findTick += 1
    }

    func takeFindAction() -> WebPane.FindAction? {
        defer { pendingFindAction = nil }
        return pendingFindAction
    }

    private func enqueueNav(_ action: WebPane.NavAction) {
        navQueue.enqueue(action)
        navTick += 1
    }

    func goBack() {
        guard isConnected else { return }
        enqueueNav(.back)
    }

    func goForward() {
        guard isConnected else { return }
        enqueueNav(.forward)
    }

    func focusWebPane() {
        guard isConnected, !findVisible else { return }
        enqueueNav(.focus)
    }

    func takeNavActions() -> [WebPane.NavAction] {
        navQueue.drain()
    }

    func noteRouteFragment(_ fragment: String) {
        guard fragment.hasPrefix("/") else { return }
        lastRouteFragment = fragment
    }

    /// Called when `WebPane` KVO observes `document.title == "ferret · not signed in"` (daemon restarted or
    /// web-session evicted) or when `DaemonClient` detects a new daemon `pid`/`started_ms`.
    func handleWebSessionExpired() {
        guard isConnected else { return }
        // Coalesce concurrent triggers (e.g. DaemonClient.onDaemonRestart + WebPane KVO firing back-to-back)
        // when a fresh reload is already in flight so we don't abort it mid-load or burn autoReloadCount.
        if webState == .loading && !webLoadedOnce { return }
        let now = Date()
        if now.timeIntervalSince(lastAutoReloadAt) > 15 {
            autoReloadCount = 0
        }
        guard autoReloadCount < 2 else {
            webState = .failed("The web session could not stay signed in. Click Reconnect to establish a fresh link.")
            return
        }
        autoReloadCount += 1
        lastAutoReloadAt = now
        reload(preserveRoute: true)
    }

    /// Called when WebKit terminates the WebContent process (prevents permanent blank white screens).
    func handleWebProcessTerminated() {
        guard isConnected else { return }
        let now = Date()
        if now.timeIntervalSince(lastAutoReloadAt) > 15 {
            autoReloadCount = 0
        }
        if autoReloadCount < 1 {
            autoReloadCount += 1
            lastAutoReloadAt = now
            reload(preserveRoute: true)
        } else {
            webState = .failed("The web view process stopped unexpectedly. Click Retry to reload.")
        }
    }

    func showDownloadNotice(_ text: String?, fileURL: URL? = nil) {
        downloadNoticeTask?.cancel()
        guard let text else {
            downloadNotice = nil
            return
        }
        downloadNotice = DownloadNotice(text: text, fileURL: fileURL)
        let ttl: Duration = fileURL != nil ? .seconds(6) : .seconds(4)
        downloadNoticeTask = Task { [weak self] in
            try? await Task.sleep(for: ttl)
            guard !Task.isCancelled else { return }
            self?.downloadNotice = nil
        }
    }

    func revealDownloadInFinder() {
        guard let url = downloadNotice?.fileURL else { return }
        NSWorkspace.shared.activateFileViewerSelecting([url])
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

    /// The pending SPA route (notification session focus, inbox jump, or reload-preserved route), consumed once.
    func takeRoute() -> WebPane.Route? {
        defer { pendingRoute = nil }
        guard isTunnelAlive else { return nil }
        return pendingRoute
    }

    // MARK: connect / disconnect

    func connect(_ connection: Connection, resetBackoff: Bool = true) {
        let switchingConnection = active?.id != connection.id
        teardown()
        if resetBackoff { backoffAttempt = 0 }
        generation += 1
        let gen = generation
        paneEpoch += 1
        active = connection
        // A tunnel connection is worth reopening by itself after a drop; a direct one has nothing to reopen.
        reconnectable = connection.mode == .sshTunnel
        pendingNetworkReconnect = false
        daemonUnreachable = false
        canGoBack = false
        canGoForward = false
        navQueue.clear()
        findDebounceTask?.cancel()
        findDebounceTask = nil
        findVisible = false
        findNotFound = false
        nextReconnectAt = nil
        waitingForNetwork = false
        if switchingConnection {
            pendingRoute = nil
            lastRouteFragment = nil
            webDataStore = .nonPersistent()
            notificationSeeds.removeAll()
            Notifier.withdrawAll()
        } else if pendingRoute == nil, let frag = lastRouteFragment {
            // Reconnecting the same connection (e.g., after sleep/wake): return to the mission the operator had open.
            pendingRoute = .fragment(frag)
            routeTick += 1
        }
        counts = Counts()
        feedStatus = DaemonClient.FeedStatus()
        webState = .idle
        webLoadedOnce = false
        UserDefaults.standard.set(connection.id.uuidString, forKey: Self.lastKey)
        let name = connection.displayName
        link = .connecting(connection.mode == .sshTunnel ? "opening tunnel to \(name)…" : "connecting to \(name)…")
        status = "connecting…"

        connectTask = Task { [weak self] in
            guard let self else { return }
            let connID = connection.id
            do {
                let base: String
                var tok: String?
                var verifiedIdentity = false
                switch connection.mode {
                case .sshTunnel:
                    let cached: String?
                    if connection.tokenSource == .fetchOverSsh {
                        let stored = await Task.detached(priority: .userInitiated) {
                            ConnectionStore.token(for: connID)
                        }.value
                        try Task.checkCancellation()
                        cached = stored.flatMap { ConnectionStore.isValidToken($0) ? $0 : nil }
                    } else {
                        cached = nil
                    }
                    // Skip the second SSH connection when we already hold a Keychain token that proves against /healthz.
                    let r = try await self.tunnel.open(connection, fetchRemoteToken: connection.tokenSource == .fetchOverSsh && cached == nil)
                    base = r.baseURL
                    if let cached {
                        let cachedOutcome = await DaemonClient.verifyIdentity(baseURL: base, token: cached)
                        if gen == self.generation { try self.checkTunnelAlive() }
                        switch cachedOutcome {
                        case .proven:
                            tok = cached
                            verifiedIdentity = true
                            self.storageError = nil
                        case .mismatch(let m):
                            if DaemonClient.isHostRefusal(cachedOutcome) {
                                self.reconnectable = false
                                throw ConnectError(m)
                            }
                            // Remote daemon rotated its token: fetch fresh ~/.ferret/token over SSH and store it.
                            let fetched = try await self.tunnel.fetchToken(host: connection.sshHost)
                            if gen == self.generation { try self.checkTunnelAlive() }
                            tok = fetched
                            let kcStatus = await Task.detached(priority: .userInitiated) {
                                ConnectionStore.setTokenDetailed(fetched, for: connID)
                            }.value
                            self.tokenPresenceEpoch += 1
                            if kcStatus == errSecSuccess {
                                self.storageError = nil
                            } else {
                                self.storageError = ConnectionStore.keychainFailureMessage(status: kcStatus, action: "store the fetched token")
                            }
                        case .unreachable:
                            if let m = cachedOutcome.failure { throw ConnectError(m) }
                        }
                    } else if let fetched = r.token {
                        tok = fetched
                        let kcStatus = await Task.detached(priority: .userInitiated) {
                            ConnectionStore.setTokenDetailed(fetched, for: connID)
                        }.value
                        self.tokenPresenceEpoch += 1
                        if kcStatus == errSecSuccess {
                            self.storageError = nil
                        } else {
                            self.storageError = ConnectionStore.keychainFailureMessage(status: kcStatus, action: "store the fetched token")
                        }
                    } else {
                        tok = await Task.detached(priority: .userInitiated) {
                            ConnectionStore.token(for: connID)
                        }.value
                    }
                case .direct:
                    if let problem = ConnectionStore.baseURLProblem(connection.baseURL) { throw ConnectError(problem) }
                    guard let b = ConnectionStore.normalizedBaseURL(connection.baseURL) else {
                        throw ConnectError("the base URL is not a valid http(s) URL")
                    }
                    base = b
                    if connection.tokenSource == .localFile {
                        let local = await Task.detached(priority: .userInitiated) {
                            ConnectionStore.readLocalToken()
                        }.value
                        guard let local else {
                            throw ConnectError("could not read a valid 64-character hex token from \(ConnectionStore.ferretHome.appendingPathComponent("token").path)")
                        }
                        tok = local
                    } else {
                        tok = await Task.detached(priority: .userInitiated) {
                            ConnectionStore.token(for: connID)
                        }.value
                    }
                }
                guard let tok, ConnectionStore.isValidToken(tok) else {
                    self.reconnectable = false
                    throw ConnectError("no valid token stored for this connection — edit it and paste the 64-character token")
                }
                if !verifiedIdentity {
                    // The token goes to nothing that cannot prove it is this token's daemon.
                    let idOutcome = await DaemonClient.verifyIdentity(baseURL: base, token: tok)
                    if gen == self.generation { try self.checkTunnelAlive() }
                    switch idOutcome {
                    case .proven:
                        break
                    case .mismatch(let m):
                        self.reconnectable = false
                        throw ConnectError(m)
                    case .unreachable:
                        if let m = idOutcome.failure { throw ConnectError(m) }
                    }
                }
                try Task.checkCancellation()
                guard gen == self.generation else { return }
                try self.checkTunnelAlive()
                // No await from here on: an ssh exit is either seen by open() above or, once the link
                // is .connected, by tunnelDied. The web pane mints its login code when it is built.
                self.backoffAttempt = 0
                self.autoReloadCount = 0
                self.nextReconnectAt = nil
                self.waitingForNetwork = false
                self.token = tok
                self.baseURL = base
                self.link = .connected(baseURL: base)
                self.status = "connected"
                self.daemonUnreachable = false
                self.beginBackgroundActivity()
                self.startClient(connectionID: connection.id, base: base, token: tok, gen: gen)
            } catch is CancellationError {
                return
            } catch {
                guard gen == self.generation else { return }
                self.endBackgroundActivity()
                self.tunnel.close()
                self.token = nil
                self.baseURL = nil
                self.nextReconnectAt = nil
                self.waitingForNetwork = false
                if let te = error as? Tunnel.TunnelError, te.isPermanent {
                    self.reconnectable = false
                }
                let msg = (error as? ConnectError)?.description ?? (error as? Tunnel.TunnelError)?.description ?? error.localizedDescription
                self.link = .failed(msg)
                self.status = "failed"
                if self.pendingNetworkReconnect && self.reconnectable {
                    self.pendingNetworkReconnect = false
                    self.lastReconnectAt = Date()
                    self.connect(connection, resetBackoff: true)
                } else if self.reconnectable && connection.mode == .sshTunnel {
                    self.scheduleBackoffReconnect(for: connection, gen: gen)
                }
            }
        }
    }

    func disconnect() {
        teardown()
        generation += 1
        reconnectable = false   // the operator chose to stop; do not reopen it on wake
        pendingNetworkReconnect = false
        backoffAttempt = 0
        active = nil
        daemonUnreachable = false
        pendingRoute = nil
        lastRouteFragment = nil
        webDataStore = .nonPersistent()
        notificationSeeds.removeAll()
        canGoBack = false
        canGoForward = false
        navQueue.clear()
        findVisible = false
        findNotFound = false
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
        backoffTask?.cancel()
        wakeProbeTask?.cancel()
        findDebounceTask?.cancel()
        endBackgroundActivity()
        client.stop()
        tunnel.closeBlocking()
        if Bundle.main.bundleURL.pathExtension == "app" {
            NSApp.dockTile.badgeLabel = nil
        }
    }

    private func teardown() {
        connectTask?.cancel()
        connectTask = nil
        backoffTask?.cancel()
        backoffTask = nil
        wakeProbeTask?.cancel()
        wakeProbeTask = nil
        findDebounceTask?.cancel()
        findDebounceTask = nil
        nextReconnectAt = nil
        waitingForNetwork = false
        endBackgroundActivity()
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
        backoffTask?.cancel()
        backoffTask = nil
        wakeProbeTask?.cancel()
        wakeProbeTask = nil
        findDebounceTask?.cancel()
        findDebounceTask = nil
        nextReconnectAt = nil
        waitingForNetwork = false
        endBackgroundActivity()
        client.stop()
        tunnel.close()
        token = nil
        baseURL = nil
        pendingEntry = nil
        pendingRoute = nil
        lastRouteFragment = nil
        webDataStore = .nonPersistent()
        notificationSeeds.removeAll()
        counts = Counts()
        daemonUnreachable = false
        link = .failed(why)
        status = "daemon not verified"
    }

    private func startClient(connectionID: UUID, base: String, token: String, gen: Int) {
        let initialSeed = notificationSeeds[connectionID]
        client.start(
            baseURL: base, token: token,
            initialNotifications: initialSeed,
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
            },
            onNotificationState: { [weak self] seed in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    self.notificationSeeds[connectionID] = seed
                }
            },
            onDaemonRestart: { [weak self] in
                Task { @MainActor in
                    guard let self, self.generation == gen else { return }
                    self.handleWebSessionExpired()
                }
            })
    }

    private func tunnelDied(_ msg: String) {
        // While connecting, open() reports the exit itself (with a better message, e.g. a busy port).
        guard case .connected = link else { return }
        generation += 1          // drops in-flight code requests and late client callbacks
        let gen = generation
        endBackgroundActivity()
        client.stop()
        token = nil
        baseURL = nil
        pendingEntry = nil
        counts = Counts()
        feedStatus.failed("stream", reason: msg)
        link = .failed("the SSH tunnel closed: \(msg). Reconnecting…")
        status = "tunnel closed"
        if reconnectable, let a = active, a.mode == .sshTunnel {
            if networkSatisfied && Date().timeIntervalSince(lastReconnectAt) > 4 {
                lastReconnectAt = Date()
                connect(a, resetBackoff: false)
            } else {
                scheduleBackoffReconnect(for: a, gen: gen)
            }
        }
    }

    // MARK: App Nap & Dock badge

    private func beginBackgroundActivity() {
        guard backgroundActivity == nil else { return }
        backgroundActivity = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiatedAllowingIdleSystemSleep],
            reason: "Monitoring live ferret daemon events and notifications"
        )
    }

    private func endBackgroundActivity() {
        if let token = backgroundActivity {
            ProcessInfo.processInfo.endActivity(token)
            backgroundActivity = nil
        }
    }

    private func updateDockBadge() {
        guard Bundle.main.bundleURL.pathExtension == "app" else { return }
        let stale = feedStatus.stale || daemonUnreachable
        if case .connected = link, !stale, counts.waiting > 0 {
            NSApp.dockTile.badgeLabel = "\(counts.waiting)"
        } else {
            NSApp.dockTile.badgeLabel = nil
        }
    }

    // MARK: auto-reconnect & sleep/wake probing

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
                if cameBack {
                    self.handleNetworkReturned()
                } else if !up, case .failed = self.link, self.reconnectable, self.active?.mode == .sshTunnel {
                    self.backoffTask?.cancel()
                    self.backoffTask = nil
                    self.nextReconnectAt = nil
                    self.waitingForNetwork = true
                }
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "ferret-desk.path"))
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.handleSystemWake() }
        }
        NotificationCenter.default.addObserver(
            forName: NSMenu.didBeginTrackingNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.refreshNotificationStatus() }
        }
    }

    /// On system wake, `ssh` was suspended during sleep so `link` is often still `.connected` with a
    /// half-open socket. Actively probe `/healthz` (2.5s) instead of waiting 30–45s for ServerAlive/SSE timeout.
    private func handleSystemWake() {
        switch link {
        case .failed:
            if reconnectable, let a = active, a.mode == .sshTunnel, networkSatisfied {
                backoffTask?.cancel()
                backoffTask = nil
                backoffAttempt = 0
                lastReconnectAt = Date()
                connect(a, resetBackoff: true)
            }
        case .connected(let base):
            probeActiveLinkAfterWake(base: base)
        case .connecting, .none:
            break
        }
    }

    /// Network path just transitioned from unsatisfied to satisfied: never let the 4 s debounce drop it,
    /// cancel sleeping backoff, probe live links, and if a connect is in flight, retry once if it fails.
    private func handleNetworkReturned() {
        guard let a = active else { return }
        switch link {
        case .failed:
            guard reconnectable, a.mode == .sshTunnel else { return }
            backoffTask?.cancel()
            backoffTask = nil
            backoffAttempt = 0
            pendingNetworkReconnect = false
            lastReconnectAt = Date()
            connect(a, resetBackoff: true)
        case .connecting:
            if reconnectable, a.mode == .sshTunnel {
                pendingNetworkReconnect = true
            }
        case .connected(let base):
            probeActiveLinkAfterWake(base: base)
        case .none:
            break
        }
    }

    private func probeActiveLinkAfterWake(base: String) {
        let gen = generation
        guard let conn = active else { return }
        wakeProbeTask?.cancel()
        wakeProbeTask = Task { [weak self] in
            let alive = await DaemonClient.quickHealthz(baseURL: base, timeout: 2.5)
            guard !Task.isCancelled else { return }
            guard let self, self.generation == gen, case .connected = self.link else { return }
            guard !alive else { return }
            if conn.mode == .sshTunnel && self.reconnectable {
                self.lastReconnectAt = Date()
                self.connect(conn, resetBackoff: true)
            } else if conn.mode == .direct, let tok = self.token {
                // Restart DaemonClient immediately so SSE reconnects without waiting for the 45s read timeout.
                self.startClient(connectionID: conn.id, base: base, token: tok, gen: gen)
            }
        }
    }

    /// Bounded exponential backoff retry for dropped SSH tunnels while the network is up.
    /// Pauses while offline (`!networkSatisfied`) and resumes immediately on `handleNetworkReturned()`.
    private func scheduleBackoffReconnect(for connection: Connection, gen: Int) {
        guard reconnectable, connection.mode == .sshTunnel else { return }
        backoffTask?.cancel()
        guard networkSatisfied else {
            backoffTask = nil
            nextReconnectAt = nil
            waitingForNetwork = true
            return
        }
        let delay = Self.backoffDelay(attempt: backoffAttempt)
        backoffAttempt += 1
        waitingForNetwork = false
        nextReconnectAt = Date().addingTimeInterval(delay)
        backoffTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else { return }
            guard let self, self.generation == gen, self.reconnectable,
                  case .failed = self.link, self.active?.id == connection.id else { return }
            guard self.networkSatisfied else {
                self.nextReconnectAt = nil
                self.waitingForNetwork = true
                return
            }
            self.nextReconnectAt = nil
            self.lastReconnectAt = Date()
            self.connect(connection, resetBackoff: false)
        }
    }

    nonisolated static func backoffDelay(attempt: Int) -> TimeInterval {
        let idx = max(0, min(attempt, backoffDelays.count - 1))
        return backoffDelays[idx]
    }

    // MARK: connections list

    /// Insert or replace, persist, and optionally store or clear a token in the Keychain.
    func upsert(_ c: Connection, token newToken: String?, clearToken: Bool = false) {
        if let i = connections.firstIndex(where: { $0.id == c.id }) { connections[i] = c } else { connections.append(c) }
        if active?.id == c.id { active = c }
        var problems: [String] = []
        if !ConnectionStore.save(connections) { problems.append("could not write connections.json") }
        if let t = newToken, !t.isEmpty {
            let status = ConnectionStore.setTokenDetailed(t, for: c.id)
            tokenPresenceEpoch += 1
            if status != errSecSuccess {
                problems.append(ConnectionStore.keychainFailureMessage(status: status, action: "store the token"))
            }
        } else if clearToken {
            ConnectionStore.clearToken(for: c.id)
            tokenPresenceEpoch += 1
        }
        storageError = problems.isEmpty ? nil : problems.joined(separator: "; ")
    }

    func remove(_ c: Connection) {
        if active?.id == c.id { disconnect(); active = nil }
        connections.removeAll { $0.id == c.id }
        notificationSeeds.removeValue(forKey: c.id)
        ConnectionStore.clearToken(for: c.id)
        tokenPresenceEpoch += 1
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

    /// Bring the window forward; navigate the pane to `session` when given while a link is active/opening,
    /// or kick off an immediate reconnect carrying `session` if the tunnel is currently `.failed` in backoff.
    func openWindow(focus session: String? = nil) {
        openWindowTick += 1
        if let session {
            switch link {
            case .connected, .connecting:
                pendingRoute = .session(session)
                routeTick += 1
            case .failed:
                if let a = active {
                    pendingRoute = .session(session)
                    routeTick += 1
                    backoffTask?.cancel()
                    backoffTask = nil
                    nextReconnectAt = nil
                    waitingForNetwork = false
                    connect(a, resetBackoff: true)
                }
            case .none:
                break
            }
        }
        NSApp.activate(ignoringOtherApps: true)
        for w in NSApp.windows where w.canBecomeMain {
            if w.isMiniaturized { w.deminiaturize(nil) }
            w.makeKeyAndOrderFront(nil)
        }
        if isConnected {
            focusWebPane()
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
        c.title = cut(prefix + (n.title.isEmpty ? "ferret" : n.title), 80)
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

    /// Runs the real DaemonClient against a daemon for a few seconds (token from $FERRET_TOKEN).
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
        if Counts().menuLabel != "ferret" { failures.append("Counts.menuLabel empty") }
        if Counts(running: 2, waiting: 1, active: 3, runningAgents: 4).compactMenuLabel != "!1 2m 4a" { failures.append("Counts.compactMenuLabel urgent first") }
        if Counts().compactMenuLabel != "ferret" { failures.append("Counts.compactMenuLabel empty") }
        if Counts(running: 1, runningAgents: 1).summary != "1 mission running · 1 agent running" { failures.append("Counts.summary singular") }
        if AppState.backoffDelay(attempt: 0) != 2 || AppState.backoffDelay(attempt: 99) != 30 { failures.append("AppState.backoffDelay") }
        if Notifier.cut("a\nb", 10) != "a b" || Notifier.cut(String(repeating: "x", count: 20), 5).count != 5 {
            failures.append("Notifier.cut")
        }
        var navQ = AppState.NavActionQueue()
        navQ.enqueue(.back)
        navQ.enqueue(.focus)
        navQ.enqueue(.resetZoom)
        if navQ.drain() != [.back, .focus, .resetZoom] { failures.append("NavActionQueue FIFO order") }
        if !navQ.drain().isEmpty { failures.append("NavActionQueue not empty after drain") }
        if WindowCloseHider.closeDecision(hasAttachedSheet: true, isFullScreen: false) != .ignoreSheet {
            failures.append("WindowCloseHider attached sheet")
        }
        if WindowCloseHider.closeDecision(hasAttachedSheet: false, isFullScreen: true) != .exitFullScreenThenHide {
            failures.append("WindowCloseHider full screen")
        }
        if WindowCloseHider.closeDecision(hasAttachedSheet: false, isFullScreen: false) != .hideImmediately {
            failures.append("WindowCloseHider normal close")
        }
        for f in failures { print("FAIL \(f)") }
        print(failures.isEmpty ? "self-check: all passed" : "self-check: \(failures.count) failed")
        return failures.isEmpty ? 0 : 1
    }
}
#endif
