import AppKit
import SwiftUI

/// The main window: a unified compact native macOS toolbar, status/find bars when needed, and the web pane filling the rest.
/// See gui/DESIGN.md.
struct RootView: View {
    @EnvironmentObject var state: AppState
    @State private var justCopied = false
    @State private var copyResetTask: Task<Void, Never>?

    var body: some View {
        VStack(spacing: 0) {
            StatusBanner()
            if state.findVisible && state.isConnected {
                FindBar()
                Divider()
            }
            switch state.link {
            case .connected:
                // A new epoch builds a new pane; reports from the one it replaced are dropped.
                let epoch = state.paneEpoch
                ZStack {
                    WebPane.adaptivePageColor
                    WebPane(dataStore: state.webDataStore,
                            pageZoom: state.pageZoom,
                            entryTick: state.entryTick,
                            routeTick: state.routeTick,
                            findTick: state.findTick,
                            navTick: state.navTick,
                            isFindBarOpen: state.findVisible,
                            takeEntry: { state.takeEntryURL() },
                            takeRoute: { state.takeRoute() },
                            takeFindAction: { state.takeFindAction() },
                            takeNavActions: { state.takeNavActions() },
                            isTunnelAlive: { state.isTunnelAlive },
                            onCreated: { state.requestWebEntry(for: epoch) },
                            onState: { s in if state.paneEpoch == epoch { state.webState = s } },
                            onRouteChanged: { frag in if state.paneEpoch == epoch { state.noteRouteFragment(frag) } },
                            onSessionExpired: { if state.paneEpoch == epoch { state.handleWebSessionExpired() } },
                            onProcessTerminated: { if state.paneEpoch == epoch { state.handleWebProcessTerminated() } },
                            onReloadRequested: { if state.paneEpoch == epoch { state.reload() } },
                            onNavCapability: { back, fwd in
                                if state.paneEpoch == epoch {
                                    state.canGoBack = back
                                    state.canGoForward = fwd
                                }
                            },
                            onFindResult: { found in
                                if state.paneEpoch == epoch {
                                    state.findNotFound = !found && !state.findQuery.isEmpty
                                }
                            },
                            onDownloadNotice: { msg, url in
                                if state.paneEpoch == epoch {
                                    state.showDownloadNotice(msg, fileURL: url)
                                }
                            })
                        .id(epoch)
                    overlay
                }
            case .connecting(let phrase):
                ConnectionStageCard(
                    title: state.active?.displayName ?? "ferret",
                    subtitle: targetSubtitle(for: state.active),
                    phrase: phrase,
                    onCancel: { state.disconnect() }
                )
            case .failed(let err):
                failedView(err)
            case .none:
                ConnectionsView()
            }
        }
        .background(WebPane.adaptivePageColor)
        .background(WindowCloseHider())
        // Support Shift+Cmd+= (Cmd+) alongside Cmd= without duplicating the View menu item.
        .background {
            Button("") { if state.isConnected { state.zoomIn() } }
                .keyboardShortcut("+", modifiers: .command)
                .opacity(0)
                .frame(width: 0, height: 0)
                .accessibilityHidden(true)
        }
        .toolbar { toolbarContent }
        .onDisappear { copyResetTask?.cancel() }
        .sheet(isPresented: $state.showingConnectionsSheet) {
            ConnectionsView(inSheet: true, onDismiss: { state.showingConnectionsSheet = false })
                .environmentObject(state)
                .frame(minWidth: 540, minHeight: 380)
        }
        .sheet(item: $state.editingConnection) { c in
            let isNew = !state.connections.contains(where: { $0.id == c.id })
            ConnectionEditor(original: c, isNew: isNew, offerConnect: true) { saved, token, clearToken, connectNow in
                state.upsert(saved, token: token, clearToken: clearToken)
                state.editingConnection = nil
                if connectNow { state.connect(saved) }
            } onCancel: {
                state.editingConnection = nil
            }
            .environmentObject(state)
        }
    }

    // MARK: unified compact native toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        // Keep text/menu labels out of macOS 26+ Liquid Glass icon platters so text never overflows a circular bezel.
        ToolbarItem(placement: .navigation) {
            connectionMenu
        }
        .hideGlassPlatterIfAvailable()

        ToolbarItemGroup(placement: .navigation) {
            if state.isConnected {
                Button { state.goBack() } label: {
                    Image(systemName: "chevron.left")
                }
                .disabled(!state.canGoBack)
                .help("Back (⌘[)")
                .accessibilityLabel("Back")

                Button { state.goForward() } label: {
                    Image(systemName: "chevron.right")
                }
                .disabled(!state.canGoForward)
                .help("Forward (⌘])")
                .accessibilityLabel("Forward")
            }
        }

        // Status text and custom pill badges live in their own platter-free toolbar item (macOS 26+).
        ToolbarItem(placement: .primaryAction) {
            HStack(spacing: 8) {
                toolbarStatusCluster
                if state.isConnected && abs(state.pageZoom - 1.0) > 0.01 {
                    Button {
                        state.zoomReset()
                        state.focusWebPane()
                    } label: {
                        Text("\(Int((state.pageZoom * 100).rounded()))%")
                            .font(.caption.monospacedDigit().weight(.medium))
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(.quaternary.opacity(0.75), in: Capsule())
                    }
                    .buttonStyle(.plain)
                    .help("Reset zoom to 100% (⌘0)")
                    .accessibilityLabel("Zoom \(Int((state.pageZoom * 100).rounded())) percent. Click to reset.")
                }
            }
            .padding(.horizontal, 4)
        }
        .hideGlassPlatterIfAvailable()

        // Pure SF Symbol buttons only inside the native Liquid Glass action group.
        ToolbarItemGroup(placement: .primaryAction) {
            if state.notifStatus == .notDetermined || state.notifStatus == .denied {
                Button {
                    if state.notifStatus == .denied {
                        if let u = URL(string: "x-apple.systempreferences:com.apple.preference.notifications") {
                            NSWorkspace.shared.open(u)
                        }
                    } else {
                        Notifier.requestAuthorization()
                    }
                } label: {
                    Image(systemName: state.notifStatus == .denied ? "bell.slash" : "bell.badge")
                }
                .help(state.notifStatus == .denied
                      ? "Native macOS notifications are off — open System Settings"
                      : "Enable native macOS notifications for pending questions")
                .accessibilityLabel(state.notifStatus == .denied ? "Open notification settings" : "Enable native notifications")
            }
            if state.isConnected {
                Button { state.reload() } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Reload the page (⌘R)")
                .accessibilityLabel("Reload the page")

                Button {
                    state.copyAddress()
                    state.focusWebPane()
                    copyResetTask?.cancel()
                    justCopied = true
                    copyResetTask = Task {
                        try? await Task.sleep(for: .seconds(1.5))
                        guard !Task.isCancelled else { return }
                        justCopied = false
                    }
                } label: {
                    Image(systemName: justCopied ? "checkmark" : "link")
                }
                .help("Copy the daemon's address (no login code, no token) (⇧⌘C)")
                .accessibilityLabel(justCopied ? "Address copied" : "Copy the daemon's address")

                Button { state.openInDefaultBrowser() } label: {
                    Image(systemName: "arrow.up.forward.app")
                }
                .help("Open signed-in page in default browser (⇧⌘O)")
                .accessibilityLabel("Open in default browser")
            }
            if state.link != .none {
                Button { state.disconnect() } label: {
                    Image(systemName: "xmark.circle")
                }
                .help("Disconnect")
                .accessibilityLabel("Disconnect")
            }
        }
    }

    private var connectionMenu: some View {
        let activeName = state.active?.displayName ?? "ferret"
        return Menu {
            ForEach(state.connections) { c in
                let isActive = state.isCurrentlyActive(c)
                Button { if !isActive { state.connect(c) } } label: {
                    Label(c.displayName, systemImage: isActive ? "checkmark" : "")
                }
            }
            if !state.connections.isEmpty { Divider() }
            Button("Add Connection…") {
                state.editingConnection = Connection(name: "")
            }
            Button("Manage Connections…") {
                state.openConnectionsManager()
            }
            if state.link != .none {
                Divider()
                Button("Disconnect") { state.disconnect() }
            }
        } label: {
            HStack(spacing: 6) {
                Circle()
                    .fill(dotColor)
                    .frame(width: 8, height: 8)
                    .accessibilityHidden(true)
                Text(activeName)
                    .font(.headline)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .help("Switch or manage connections (⌘,) — status: \(dotLabel)")
        .accessibilityLabel("\(activeName), \(dotLabel). Switch or manage connections.")
    }

    @ViewBuilder
    private var toolbarStatusCluster: some View {
        let countsStale = state.feedStatus.stale || state.daemonUnreachable
        let showLiveLabel = state.isConnected && !state.daemonUnreachable && !state.feedStatus.stale
        HStack(spacing: 8) {
            if state.feedStatus.lastUpdated != nil {
                ViewThatFits(in: .horizontal) {
                    Text((countsStale ? "Last known: " : "") + state.counts.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .fixedSize()
                    EmptyView()
                }
                if state.counts.waiting > 0 {
                    Button {
                        state.openInbox()
                        state.focusWebPane()
                    } label: {
                        Text("\(state.counts.waiting) needs you")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(countsStale ? Color.secondary : Color.orange)
                            .lineLimit(1)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background((countsStale ? Color.secondary : Color.orange).opacity(0.16), in: Capsule())
                    }
                    .buttonStyle(.plain)
                    .disabled(!state.isConnected)
                    .help("Open inbox in the web UI (⇧⌘I)")
                }
                if state.counts.requests > 0 {
                    ViewThatFits(in: .horizontal) {
                        Button {
                            state.openInbox()
                            state.focusWebPane()
                        } label: {
                            Text("\(state.counts.requests) asking")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 3)
                                .background(.quaternary.opacity(0.6), in: Capsule())
                        }
                        .buttonStyle(.plain)
                        .disabled(!state.isConnected)
                        .help("Open host scope requests in inbox")
                        EmptyView()
                    }
                }
            }
            if showLiveLabel {
                if state.feedStatus.lastUpdated != nil {
                    Text("·")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                }
                TimelineView(.periodic(from: .now, by: 5)) { context in
                    Text(state.feedStatus.label(at: context.date))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .fixedSize()
                }
                .help(state.feedStatus.detail.isEmpty ? state.status : state.feedStatus.detail)
            } else if !state.isConnected && state.link != .none {
                Text(state.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .fixedSize()
                    .help(state.status)
            }
        }
    }

    // MARK: overlays & state cards

    /// Over the web view: a unified loading card until the first load, a clear message when it fails.
    @ViewBuilder private var overlay: some View {
        switch state.webState {
        case .failed(let msg):
            VStack(spacing: 14) {
                Image(systemName: "wifi.exclamationmark")
                    .font(.system(size: 32))
                    .foregroundStyle(.orange)
                // A generic headline: this fires for an auth/login-code failure too, where the daemon
                // is reachable and the fix is just Reconnect. The specific reason and action is the body.
                Text("Can't show the ferret page").font(.headline)
                Text(msg)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
                HStack(spacing: 8) {
                    Button("Retry") { state.reload() }.buttonStyle(.borderedProminent)
                    if let a = state.active {
                        Button("Reconnect") { state.connect(a) }
                        Button("Edit…") { state.editingConnection = a }
                    }
                }
            }
            .padding(28)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(WebPane.adaptivePageColor)
        case .idle, .loading:
            if !pageEverLoaded {
                ConnectionStageCard(
                    title: state.active?.displayName ?? "ferret",
                    subtitle: targetSubtitle(for: state.active),
                    phrase: "loading the web UI…",
                    onCancel: { state.disconnect() }
                )
            }
        case .loaded:
            EmptyView()
        }
    }

    @ViewBuilder
    private func failedView(_ err: String) -> some View {
        VStack(spacing: 14) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 32))
                .foregroundStyle(.orange)
            if let a = state.active {
                Text("Could not connect to \(a.displayName)")
                    .font(.headline)
            }
            Text(err)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 480)
            if state.waitingForNetwork {
                Label("Waiting for network…", systemImage: "wifi.slash")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(.quaternary.opacity(0.6), in: Capsule())
            } else if let nextAt = state.nextReconnectAt {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    let secs = max(1, Int(ceil(nextAt.timeIntervalSince(ctx.date))))
                    Label("Retrying automatically in \(secs)s…", systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(.quaternary.opacity(0.6), in: Capsule())
                }
            }
            HStack(spacing: 8) {
                if let a = state.active {
                    Button("Retry") { state.connect(a) }.buttonStyle(.borderedProminent)
                    Button("Edit…") { state.editingConnection = a }
                }
                Button("Connections") { state.disconnect() }
            }
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(WebPane.adaptivePageColor)
    }

    private func targetSubtitle(for connection: Connection?) -> String? {
        guard let c = connection else { return nil }
        switch c.mode {
        case .sshTunnel: return "ssh \(c.sshHost) → 127.0.0.1:\(c.remotePort)"
        case .direct: return c.baseURL
        }
    }

    // Only a pane's first load is covered (a reload builds a new pane); the page's own later navigations
    // keep it visible.
    private var pageEverLoaded: Bool { state.webLoadedOnce }

    /// A worded version of the status dot, for VoiceOver.
    private var dotLabel: String {
        switch state.link {
        case .connected: return state.daemonUnreachable ? "daemon unreachable" : (state.feedStatus.stale ? "stale" : "connected")
        case .connecting: return "connecting"
        case .failed: return "disconnected"
        case .none: return "not connected"
        }
    }

    private var dotColor: Color {
        switch state.link {
        case .connected:
            if state.daemonUnreachable { return .orange }
            return state.feedStatus.stale || state.feedStatus.mode != .live ? .orange : .green
        case .connecting: return .orange
        case .failed: return .red
        case .none: return .gray
        }
    }
}

/// Cohesive centered card shared by `.connecting` and initial `"loading the web UI…"` so there is no
/// jarring layout shift or button disappearance as the tunnel transitions into the WebView.
struct ConnectionStageCard: View {
    let title: String
    let subtitle: String?
    let phrase: String
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 12) {
            ProgressView()
                .controlSize(.regular)
            VStack(spacing: 4) {
                Text(title)
                    .font(.headline)
                if let subtitle, !subtitle.isEmpty {
                    Text(verbatim: subtitle)
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                }
                Text(phrase)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.top, 2)
            }
            Button("Cancel", action: onCancel)
                .padding(.top, 4)
        }
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(WebPane.adaptivePageColor)
    }
}

/// Slim banner strip below the toolbar for offline/reconnecting errors, Keychain/storage errors,
/// and download feedback (including "Reveal in Finder") so diagnostics are never truncated.
struct StatusBanner: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            if state.isConnected && state.daemonUnreachable {
                bannerRow(color: .orange, icon: "wifi.exclamationmark", text: state.status) {
                    if let a = state.active {
                        Button("Reconnect") { state.connect(a) }
                            .controlSize(.small)
                    }
                }
            } else if state.isConnected && state.feedStatus.stale && state.feedStatus.lastUpdated != nil {
                TimelineView(.periodic(from: .now, by: 5)) { ctx in
                    let detail = state.feedStatus.detail
                    let msg = detail.isEmpty
                        ? state.feedStatus.label(at: ctx.date)
                        : "\(state.feedStatus.label(at: ctx.date)) — \(detail)"
                    bannerRow(color: .orange, icon: "arrow.triangle.2.circlepath", text: msg) {
                        if let a = state.active {
                            Button("Reconnect") { state.connect(a) }
                                .controlSize(.small)
                        }
                    }
                }
            }
            if state.link != .none, let err = state.storageError {
                bannerRow(color: .red, icon: "key.slash", text: err) {
                    Button("Dismiss") { state.storageError = nil }
                        .controlSize(.small)
                }
            }
            if let dl = state.downloadNotice {
                bannerRow(color: .accentColor, icon: "arrow.down.circle", text: dl.text) {
                    HStack(spacing: 6) {
                        if dl.fileURL != nil {
                            Button("Reveal in Finder") { state.revealDownloadInFinder() }
                                .controlSize(.small)
                        }
                        Button("Dismiss") { state.showDownloadNotice(nil) }
                            .controlSize(.small)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func bannerRow<Action: View>(color: Color, icon: String, text: String, @ViewBuilder action: () -> Action) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .accessibilityHidden(true)
            Text(text)
                .font(.caption)
                .foregroundStyle(.primary)
                .lineLimit(2)
                .textSelection(.enabled)
            Spacer(minLength: 8)
            action()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(color.opacity(0.12))
        Divider()
    }
}

/// Native Find-in-Page bar (`⌘F` / `⌘G` / `⇧⌘G`) backed by `WKWebView.find(_:configuration:)`.
/// Debounces live typing (150ms), supports `Shift+Enter` for previous match, and scopes `Esc` to FindBar
/// focus so Web UI `<dialog>`s keep their own `Esc` handling.
struct FindBar: View {
    @EnvironmentObject var state: AppState
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            HStack(spacing: 4) {
                TextField("Find in page", text: $state.findQuery)
                    .textFieldStyle(.plain)
                    .focused($focused)
                    .onKeyPress(keys: [.return]) { press in
                        if press.modifiers.contains(.shift) {
                            state.findPrevious()
                        } else {
                            state.findNext()
                        }
                        return .handled
                    }
                    .onChange(of: state.findQuery) { _, newValue in
                        state.findQueryChanged(newValue)
                    }
                if !state.findQuery.isEmpty {
                    Button {
                        state.findQuery = ""
                        state.clearFindHighlight()
                        focused = true
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("Clear search")
                    .accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 6))
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(state.findNotFound ? Color.orange.opacity(0.75) : Color.primary.opacity(0.12), lineWidth: 1)
            )
            .frame(maxWidth: 280)

            if state.findNotFound {
                Text("Not found")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.orange)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.16), in: Capsule())
            }
            Button { state.findPrevious() } label: {
                Image(systemName: "chevron.up").padding(4).contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .disabled(state.findQuery.isEmpty)
            .help("Previous match (⇧⌘G or ⇧Enter)")
            .accessibilityLabel("Previous match")
            Button { state.findNext() } label: {
                Image(systemName: "chevron.down").padding(4).contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .disabled(state.findQuery.isEmpty)
            .help("Next match (⌘G or Enter)")
            .accessibilityLabel("Next match")
            Spacer()
            Button { state.closeFind() } label: {
                Image(systemName: "xmark").padding(4).contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .help("Close Find (Esc)")
            .accessibilityLabel("Close Find")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
        .onKeyPress(.escape) {
            state.closeFind()
            return .handled
        }
        .onAppear { focused = true }
        .onChange(of: state.findFocusTick) { _, _ in focused = true }
    }
}

/// Intercepts closing the main window (`⌘W` or red traffic-light button) to hide (`orderOut`) instead of
/// tearing down the live `WKWebView` and unsent drafts. App Quit (`⌘Q`) bypasses `windowShouldClose`.
/// Refuses hiding underneath an attached sheet, and exits macOS Full Screen cleanly before hiding.
struct WindowCloseHider: NSViewRepresentable {
    enum CloseDecision: Equatable {
        case ignoreSheet
        case exitFullScreenThenHide
        case hideImmediately
    }

    nonisolated static func closeDecision(hasAttachedSheet: Bool, isFullScreen: Bool) -> CloseDecision {
        if hasAttachedSheet { return .ignoreSheet }
        if isFullScreen { return .exitFullScreenThenHide }
        return .hideImmediately
    }

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async {
            context.coordinator.attach(to: view.window)
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        if let window = nsView.window {
            context.coordinator.attach(to: window)
        }
    }

    static func dismantleNSView(_ nsView: NSView, coordinator: Coordinator) {
        coordinator.detach()
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    @MainActor
    final class Coordinator: NSObject, NSWindowDelegate {
        private weak var attachedWindow: NSWindow?
        private var previousDelegate: (any NSWindowDelegate)?
        private var pendingHideAfterFullScreen = false

        func attach(to window: NSWindow?) {
            guard let window, attachedWindow !== window else { return }
            detach()
            attachedWindow = window
            if window.delegate !== self {
                previousDelegate = window.delegate
                window.delegate = self
            }
        }

        func detach() {
            pendingHideAfterFullScreen = false
            if let window = attachedWindow, window.delegate === self {
                window.delegate = previousDelegate
            }
            attachedWindow = nil
            previousDelegate = nil
        }

        func windowShouldClose(_ sender: NSWindow) -> Bool {
            switch WindowCloseHider.closeDecision(
                hasAttachedSheet: sender.attachedSheet != nil,
                isFullScreen: sender.styleMask.contains(.fullScreen)
            ) {
            case .ignoreSheet:
                return false
            case .exitFullScreenThenHide:
                pendingHideAfterFullScreen = true
                sender.toggleFullScreen(nil)
                return false
            case .hideImmediately:
                sender.orderOut(nil)
                return false
            }
        }

        func windowDidExitFullScreen(_ notification: Notification) {
            previousDelegate?.windowDidExitFullScreen?(notification)
            if pendingHideAfterFullScreen {
                pendingHideAfterFullScreen = false
                if let window = (notification.object as? NSWindow) ?? attachedWindow {
                    window.orderOut(nil)
                }
            }
        }

        func windowDidFailToExitFullScreen(_ window: NSWindow) {
            pendingHideAfterFullScreen = false
            previousDelegate?.windowDidFailToExitFullScreen?(window)
        }

        nonisolated private static func isHandledSelector(_ aSelector: Selector!) -> Bool {
            aSelector == #selector(NSWindowDelegate.windowShouldClose(_:))
                || aSelector == #selector(NSWindowDelegate.windowDidExitFullScreen(_:))
                || aSelector == #selector(NSWindowDelegate.windowDidFailToExitFullScreen(_:))
        }

        nonisolated override func responds(to aSelector: Selector!) -> Bool {
            if Self.isHandledSelector(aSelector) { return true }
            if super.responds(to: aSelector) { return true }
            guard Thread.isMainThread else { return false }
            return MainActor.assumeIsolated { previousDelegate?.responds(to: aSelector) ?? false }
        }

        nonisolated override func forwardingTarget(for aSelector: Selector!) -> Any? {
            if Self.isHandledSelector(aSelector) { return self }
            guard Thread.isMainThread else { return super.forwardingTarget(for: aSelector) }
            if let prev = MainActor.assumeIsolated({ previousDelegate }), prev.responds(to: aSelector) {
                return prev
            }
            return super.forwardingTarget(for: aSelector)
        }
    }
}

private extension ToolbarContent {
    @ToolbarContentBuilder
    func hideGlassPlatterIfAvailable() -> some ToolbarContent {
        #if compiler(>=6.2)
        if #available(macOS 26.0, *) {
            self.sharedBackgroundVisibility(.hidden)
        } else {
            self
        }
        #else
        self
        #endif
    }
}
