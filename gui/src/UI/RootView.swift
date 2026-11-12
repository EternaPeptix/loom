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
                WebPane(url: state.webEntryURL, focusSession: $state.focusSession)
            case .connecting(let phrase):
                centered(ProgressView(), phrase)
            case .failed(let err):
                centered(Image(systemName: "exclamationmark.triangle"), err)
            case .none:
                ConnectionsView()
            }
        }
    }

    private func centered(_ icon: some View, _ text: String) -> some View {
        VStack(spacing: 12) { icon; Text(text).foregroundStyle(.secondary) }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// The bar above the web pane: active connection name, link status, reload.
struct ConnectionBar: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        HStack {
            Text(state.active?.name ?? "loom").font(.headline)
            Spacer()
            Text(state.status).font(.caption).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }
}
