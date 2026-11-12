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
                ZStack {
                    WebPane(url: state.webEntryURL,
                            focusSession: $state.focusSession,
                            onState: { state.webState = $0 })
                        .id(state.connectionEpoch)
                    overlay
                }
            case .connecting(let phrase):
                centered(ProgressView(), phrase)
            case .failed(let err):
                VStack(spacing: 12) {
                    Image(systemName: "exclamationmark.triangle").font(.largeTitle)
                    Text(err).foregroundStyle(.secondary).textSelection(.enabled).multilineTextAlignment(.center)
                    HStack {
                        if let a = state.active { Button("Retry") { state.connect(a) } }
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
                Text("The daemon is unreachable").font(.headline)
                Text(msg).foregroundStyle(.secondary).textSelection(.enabled).multilineTextAlignment(.center)
                HStack {
                    Button("Retry") { state.reload() }
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

    // A reload of an already-shown page keeps the page visible; only the first load blanks it.
    private var pageEverLoaded: Bool { state.webLoadedOnce }

    private func centered(_ icon: some View, _ text: String) -> some View {
        VStack(spacing: 12) { icon; Text(text).foregroundStyle(.secondary) }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// The bar above the web pane: active connection name, link status, reload, copy web URL.
struct ConnectionBar: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(dotColor).frame(width: 8, height: 8)
            Text(state.active?.name ?? "loom").font(.headline)
            if state.link != .none {
                Menu {
                    ForEach(state.connections) { c in
                        Button(c.name.isEmpty ? c.sshHost : c.name) { state.connect(c) }
                    }
                } label: { Image(systemName: "arrow.left.arrow.right") }
                    .menuStyle(.borderlessButton).fixedSize()
                    .help("Switch connection")
            }
            Spacer()
            if state.counts.running > 0 || state.counts.waiting > 0 || state.counts.active > 0 {
                Text("\(state.counts.running) running · \(state.counts.waiting) waiting · \(state.counts.active) active")
                    .font(.caption).foregroundStyle(state.counts.waiting > 0 ? Color.red : Color.secondary)
            }
            Text(state.status).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            if case .connected = state.link {
                Button { state.reload() } label: { Image(systemName: "arrow.clockwise") }
                    .help("Reload the page")
                Button { state.copyWebURL() } label: { Image(systemName: "link") }
                    .help("Copy web URL (includes the token)")
            }
            if state.link != .none {
                Button { state.disconnect() } label: { Image(systemName: "xmark.circle") }
                    .help("Disconnect")
            }
        }
        .buttonStyle(.borderless)
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    private var dotColor: Color {
        switch state.link {
        case .connected: return state.counts.waiting > 0 ? .red : .green
        case .connecting: return .orange
        case .failed: return .red
        case .none: return .gray
        }
    }
}
