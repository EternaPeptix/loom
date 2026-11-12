import SwiftUI

/// Shown when nothing is connected: the saved connections and a way to add / edit / connect one.
/// See gui/DESIGN.md "Connections". This skeleton lists them and offers Connect; the editor sheet,
/// persistence and token entry are the implementer's to complete.
struct ConnectionsView: View {
    @EnvironmentObject var state: AppState
    @State private var editing: Connection? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Connections").font(.title3)
                Spacer()
                Button {
                    editing = Connection(name: "new connection")
                } label: { Image(systemName: "plus") }
            }
            if state.connections.isEmpty {
                Text("No connections yet. Add one that points at a loom daemon — directly if it is on this machine, or over SSH if it runs on another.")
                    .foregroundStyle(.secondary)
            } else {
                List(state.connections) { c in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(c.name)
                            Text(subtitle(c)).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Connect") { state.connect(c) }
                    }
                }
            }
            Spacer()
        }
        .padding(16)
        .sheet(item: $editing) { c in
            // Editor sheet: see DESIGN.md. Placeholder keeps the build green.
            VStack { Text("Edit \(c.name)"); Button("Done") { editing = nil } }.padding(24).frame(width: 420)
        }
    }

    private func subtitle(_ c: Connection) -> String {
        switch c.mode {
        case .sshTunnel: return "ssh \(c.sshHost) → 127.0.0.1:\(c.remotePort)"
        case .direct: return c.baseURL
        }
    }
}
