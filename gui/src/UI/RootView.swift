import AppKit
import SwiftUI

/// The main window: a connection bar on top, status/find bars when needed, and the web pane filling the rest.
/// See gui/DESIGN.md.
struct RootView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            ConnectionBar()
            Divider()
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
                            takeNavAction: { state.takeNavAction() },
                            isTunnelAlive: { state.isTunnelAlive },
                            onCreated: { state.requestWebEntry(for: epoch) },
                            onState: { s in if state.paneEpoch == epoch { state.webState = s } },
                            onRouteChanged: { frag in if state.paneEpoch == epoch { state.noteRouteFragment(frag) } },
                            onSessionExpired: { if state.paneEpoch == epoch { state.handleWebSessionExpired() } },
                            onProcessTerminated: { if state.paneEpoch == epoch { state.handleWebProcessTerminated() } },
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
                            onDownloadNotice: { msg in
                                if state.paneEpoch == epoch {
                                    state.showDownloadNotice(msg)
                                }
                            })
                        .id(epoch)
                    overlay
                }
            case .connecting(let phrase):
                VStack(spacing: 12) {
                    ProgressView()
                    Text(phrase).foregroundStyle(.secondary)
                    Button("Cancel") { state.disconnect() }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .failed(let err):
                VStack(spacing: 12) {
                    Image(systemName: "exclamationmark.triangle").font(.largeTitle)
                    Text(err)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 460)
                    HStack {
                        if let a = state.active {
                            Button("Retry") { state.connect(a) }.buttonStyle(.borderedProminent)
                            Button("Edit…") { state.editingConnection = a }
                        }
                        Button("Connections") { state.disconnect() }
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .none:
                ConnectionsView()
            }
        }
        .background(WindowCloseHider())
        .sheet(isPresented: $state.showingConnectionsSheet) {
            ConnectionsView(inSheet: true, onDismiss: { state.showingConnectionsSheet = false })
                .environmentObject(state)
                .frame(minWidth: 520, minHeight: 360)
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

    /// Over the web view: a spinner until the first load, a clear message when it fails.
    @ViewBuilder private var overlay: some View {
        switch state.webState {
        case .failed(let msg):
            VStack(spacing: 12) {
                Image(systemName: "wifi.exclamationmark").font(.largeTitle)
                // A generic headline: this fires for an auth/login-code failure too, where the daemon
                // is reachable and the fix is just Reconnect. The specific reason and action is the body.
                Text("Can't show the ferret page").font(.headline)
                Text(msg)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
                HStack {
                    Button("Retry") { state.reload() }.buttonStyle(.borderedProminent)
                    if let a = state.active {
                        Button("Reconnect") { state.connect(a) }
                        Button("Edit…") { state.editingConnection = a }
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(.background)
        case .idle, .loading:
            if !pageEverLoaded {
                VStack(spacing: 12) { ProgressView(); Text("loading the web UI…").foregroundStyle(.secondary) }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(.background)
            }
        case .loaded:
            EmptyView()
        }
    }

    // Only a pane's first load is covered (a reload builds a new pane); the page's own later navigations
    // keep it visible.
    private var pageEverLoaded: Bool { state.webLoadedOnce }
}

/// Slim banner strip below the connection bar for offline/reconnecting errors, Keychain/storage errors,
/// and download feedback so diagnostics are never hidden behind a truncated single-line caption.
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
                bannerRow(color: .accentColor, icon: "arrow.down.circle", text: dl) {
                    Button("Dismiss") { state.showDownloadNotice(nil) }
                        .controlSize(.small)
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
struct FindBar: View {
    @EnvironmentObject var state: AppState
    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField("Find in page", text: $state.findQuery)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 260)
                .focused($focused)
                .onSubmit { state.findNext() }
                .onChange(of: state.findQuery) { _, newValue in
                    if newValue.isEmpty {
                        state.clearFindHighlight()
                    } else {
                        state.findNotFound = false
                        state.findNext()
                    }
                }
            if state.findNotFound {
                Text("Not found")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Button { state.findPrevious() } label: {
                Image(systemName: "chevron.up").padding(4).contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .disabled(state.findQuery.isEmpty)
            .help("Previous match (⇧⌘G)")
            .accessibilityLabel("Previous match")
            Button { state.findNext() } label: {
                Image(systemName: "chevron.down").padding(4).contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .disabled(state.findQuery.isEmpty)
            .help("Next match (⌘G)")
            .accessibilityLabel("Next match")
            Spacer()
            Button { state.closeFind() } label: {
                Image(systemName: "xmark").padding(4).contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .keyboardShortcut(.cancelAction)
            .help("Close Find (Esc)")
            .accessibilityLabel("Close Find")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
        .onAppear { focused = true }
        .onChange(of: state.findFocusTick) { _, _ in focused = true }
    }
}

/// Intercepts closing the main window (`⌘W` or red traffic-light button) to hide (`orderOut`) instead of
/// tearing down the live `WKWebView` and unsent drafts. App Quit (`⌘Q`) bypasses `windowShouldClose`.
struct WindowCloseHider: NSViewRepresentable {
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
            if let window = attachedWindow, window.delegate === self {
                window.delegate = previousDelegate
            }
            attachedWindow = nil
            previousDelegate = nil
        }

        func windowShouldClose(_ sender: NSWindow) -> Bool {
            sender.orderOut(nil)
            return false
        }

        nonisolated override func responds(to aSelector: Selector!) -> Bool {
            if aSelector == #selector(NSWindowDelegate.windowShouldClose(_:)) { return true }
            if super.responds(to: aSelector) { return true }
            guard Thread.isMainThread else { return false }
            return MainActor.assumeIsolated { previousDelegate?.responds(to: aSelector) ?? false }
        }

        nonisolated override func forwardingTarget(for aSelector: Selector!) -> Any? {
            if aSelector == #selector(NSWindowDelegate.windowShouldClose(_:)) { return self }
            guard Thread.isMainThread else { return super.forwardingTarget(for: aSelector) }
            if let prev = MainActor.assumeIsolated({ previousDelegate }), prev.responds(to: aSelector) {
                return prev
            }
            return super.forwardingTarget(for: aSelector)
        }
    }
}

/// The bar above the web pane: active connection name, switcher, back/forward, status, reload, copy address.
struct ConnectionBar: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        let activeName = state.active?.displayName ?? "ferret"
        let countsStale = state.feedStatus.stale || state.daemonUnreachable
        HStack(spacing: 8) {
            Circle().fill(dotColor).frame(width: 8, height: 8)
                .accessibilityLabel("Connection status: \(dotLabel)")
            Text(activeName).font(.headline).lineLimit(1).truncationMode(.tail)
            if state.link != .none {
                Menu {
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
                        state.showingConnectionsSheet = true
                    }
                } label: {
                    Image(systemName: "arrow.left.arrow.right")
                        .padding(4)
                        .contentShape(Rectangle())
                }
                .menuStyle(.borderlessButton).fixedSize()
                .help("Switch or manage connections (⌘,)")
                .accessibilityLabel("Switch or manage connections")
            }
            if case .connected = state.link {
                HStack(spacing: 2) {
                    Button { state.goBack(); state.focusWebPane() } label: {
                        Image(systemName: "chevron.left").padding(4).contentShape(Rectangle())
                    }
                    .disabled(!state.canGoBack)
                    .help("Back (⌘[)")
                    .accessibilityLabel("Back")
                    Button { state.goForward(); state.focusWebPane() } label: {
                        Image(systemName: "chevron.right").padding(4).contentShape(Rectangle())
                    }
                    .disabled(!state.canGoForward)
                    .help("Forward (⌘])")
                    .accessibilityLabel("Forward")
                }
            }
            Spacer(minLength: 4)
            if state.feedStatus.lastUpdated != nil {
                ViewThatFits(in: .horizontal) {
                    Text((countsStale ? "Last known: " : "") + state.counts.summary)
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    EmptyView()
                }
                if state.counts.waiting > 0 {
                    Button { state.openInbox(); state.focusWebPane() } label: {
                        Text("\(state.counts.waiting) needs you")
                            .font(.caption.weight(.medium))
                            .foregroundStyle(countsStale ? Color.secondary : Color.orange)
                            .lineLimit(1)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .contentShape(Rectangle())
                    }
                    .disabled(!state.isConnected)
                    .help("Open inbox in the web UI (⇧⌘I)")
                }
                if state.counts.requests > 0 {
                    ViewThatFits(in: .horizontal) {
                        Button { state.openInbox(); state.focusWebPane() } label: {
                            Text("\(state.counts.requests) asking for hosts")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                .padding(.horizontal, 4).padding(.vertical, 2)
                                .contentShape(Rectangle())
                        }
                        .disabled(!state.isConnected)
                        .help("Open inbox in the web UI")
                        EmptyView()
                    }
                }
            }
            if case .connected = state.link, !state.daemonUnreachable {
                TimelineView(.periodic(from: .now, by: 5)) { context in
                    Text(state.feedStatus.label(at: context.date))
                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                .help(state.feedStatus.detail.isEmpty ? state.status : state.feedStatus.detail)
            } else {
                Text(state.status).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    .help(state.status)
            }
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
                        .padding(4)
                        .contentShape(Rectangle())
                }
                .help(state.notifStatus == .denied
                      ? "Native macOS notifications are off — open System Settings"
                      : "Enable native macOS notifications for pending questions")
                .accessibilityLabel(state.notifStatus == .denied ? "Open notification settings" : "Enable native notifications")
            }
            if case .connected = state.link {
                Button { state.reload() } label: {
                    Image(systemName: "arrow.clockwise").padding(4).contentShape(Rectangle())
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
                    Image(systemName: justCopied ? "checkmark" : "link").padding(4).contentShape(Rectangle())
                }
                .help("Copy the daemon's address (no login code, no token) (⇧⌘C)")
                .accessibilityLabel(justCopied ? "Address copied" : "Copy the daemon's address")
            }
            if state.link != .none {
                Button { state.disconnect() } label: {
                    Image(systemName: "xmark.circle").padding(4).contentShape(Rectangle())
                }
                .help("Disconnect")
                .accessibilityLabel("Disconnect")
            }
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 12).padding(.vertical, 6)
        .onDisappear { copyResetTask?.cancel() }
    }

    @State private var justCopied = false
    @State private var copyResetTask: Task<Void, Never>?

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
