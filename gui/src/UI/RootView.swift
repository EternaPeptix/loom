import SwiftUI

/// The main window: a connection bar on top, the web pane filling the rest. See gui/DESIGN.md.
struct RootView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(spacing: 0) {
            ConnectionBar()
            Divider()
            switch state.link {
            case .connected:
                // A new epoch builds a new pane; reports from the one it replaced are dropped.
                let epoch = state.paneEpoch
                ZStack {
                    WebPane(entryTick: state.entryTick,
                            routeTick: state.routeTick,
                            takeEntry: { state.takeEntryURL() },
                            takeRoute: { state.takeRoute() },
                            isTunnelAlive: { state.isTunnelAlive },
                            onCreated: { state.requestWebEntry(for: epoch) },
                            onState: { s in if state.paneEpoch == epoch { state.webState = s } })
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
    }

    /// Over the web view: a spinner until the first load, a clear message when it fails.
    @ViewBuilder private var overlay: some View {
        switch state.webState {
        case .failed(let msg):
            VStack(spacing: 12) {
                Image(systemName: "wifi.exclamationmark").font(.largeTitle)
                // A generic headline: this fires for an auth/login-code failure too, where the daemon
                // is reachable and the fix is just Reconnect. The specific reason and action is the body.
                Text("Can't show the loom page").font(.headline)
                Text(msg)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 460)
                HStack {
                    Button("Retry") { state.reload() }.buttonStyle(.borderedProminent)
                    if let a = state.active { Button("Reconnect") { state.connect(a) } }
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

/// The bar above the web pane: active connection name, link status, reload, copy address.
struct ConnectionBar: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        let activeName = state.active.map { $0.name.isEmpty ? $0.sshHost : $0.name } ?? "loom"
        let countsStale = state.feedStatus.stale || state.daemonUnreachable
        HStack(spacing: 10) {
            Circle().fill(dotColor).frame(width: 8, height: 8)
                .accessibilityLabel("Connection status: \(dotLabel)")
            Text(activeName).font(.headline).lineLimit(1).truncationMode(.tail)
            if state.link != .none {
                Menu {
                    ForEach(state.connections) { c in
                        let isActive = state.isCurrentlyActive(c)
                        Button { if !isActive { state.connect(c) } } label: {
                            Label(c.name.isEmpty ? c.sshHost : c.name, systemImage: isActive ? "checkmark" : "")
                        }
                    }
                } label: {
                    Image(systemName: "arrow.left.arrow.right")
                        .padding(4)
                        .contentShape(Rectangle())
                }
                .menuStyle(.borderlessButton).fixedSize()
                .help("Switch connection")
                .accessibilityLabel("Switch connection")
            }
            Spacer()
            if state.feedStatus.lastUpdated != nil {
                Text((countsStale ? "Last known: " : "") + state.counts.summary)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                if state.counts.waiting > 0 {
                    Button { state.openInbox() } label: {
                        Text("\(state.counts.waiting) needs you")
                            .font(.caption.weight(.medium))
                            .foregroundStyle(countsStale ? Color.secondary : Color.orange)
                            .lineLimit(1)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .contentShape(Rectangle())
                    }
                    .disabled(!state.isConnected)
                    .help("Open inbox in the web UI")
                }
                if state.counts.requests > 0 {
                    Button { state.openInbox() } label: {
                        Text("\(state.counts.requests) asking for hosts")
                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            .padding(.horizontal, 4).padding(.vertical, 2)
                            .contentShape(Rectangle())
                    }
                    .disabled(!state.isConnected)
                    .help("Open inbox in the web UI")
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
            if case .connected = state.link {
                Button { state.reload() } label: {
                    Image(systemName: "arrow.clockwise").padding(4).contentShape(Rectangle())
                }
                .help("Reload the page (⌘R)")
                .accessibilityLabel("Reload the page")
                Button {
                    state.copyAddress()
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
                .help("Copy the daemon's address (no login code, no token)")
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
