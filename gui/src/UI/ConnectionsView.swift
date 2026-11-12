import SwiftUI

/// Shown when nothing is connected: the saved connections, with add / edit / delete / connect.
/// See gui/DESIGN.md "Connections".
struct ConnectionsView: View {
    @EnvironmentObject var state: AppState
    @State private var editing: Connection? = nil
    @State private var deleting: Connection? = nil
    @State private var offeredFirstRun = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Connections").font(.title3)
                Spacer()
                Button {
                    editing = Connection(name: "")
                } label: { Image(systemName: "plus") }
                .help("Add a connection")
            }
            if let err = state.storageError {
                Text(err).font(.caption).foregroundStyle(.red)
            }
            if state.connections.isEmpty {
                Text("No connections yet. Add one that points at a loom daemon — directly if it is on this machine, or over SSH if it runs on another.")
                    .foregroundStyle(.secondary)
            } else {
                List(state.connections) { c in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(c.name.isEmpty ? "(unnamed)" : c.name)
                            Text(subtitle(c)).font(.caption).foregroundStyle(.secondary)
                            if let bad = invalidReason(c) { Text(bad).font(.caption).foregroundStyle(.red) }
                        }
                        Spacer()
                        Button("Edit") { editing = c }
                        Button("Delete", role: .destructive) { deleting = c }
                        Button("Connect") { state.connect(c) }.buttonStyle(.borderedProminent)
                            .disabled(invalidReason(c) != nil)
                    }
                    .padding(.vertical, 2)
                }
            }
            Spacer()
        }
        .padding(16)
        .onAppear {
            // First run: go straight to the add form.
            if state.connections.isEmpty && !offeredFirstRun {
                offeredFirstRun = true
                editing = Connection(name: "")
            }
        }
        .sheet(item: $editing) { c in
            ConnectionEditor(original: c, isNew: !state.connections.contains(where: { $0.id == c.id })) { saved, token in
                state.upsert(saved, token: token)
                editing = nil
            } onCancel: { editing = nil }
            .environmentObject(state)
        }
        .confirmationDialog("Delete this connection?", isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }), presenting: deleting) { c in
            Button("Delete \(c.name)", role: .destructive) { state.remove(c); deleting = nil }
            Button("Cancel", role: .cancel) { deleting = nil }
        } message: { _ in
            Text("This also removes its token from the Keychain.")
        }
    }

    /// A saved Direct connection whose URL breaks the http/https host rule is shown as invalid, not used.
    private func invalidReason(_ c: Connection) -> String? {
        c.mode == .direct ? ConnectionStore.baseURLProblem(c.baseURL) : nil
    }

    private func subtitle(_ c: Connection) -> String {
        switch c.mode {
        case .sshTunnel: return "ssh \(c.sshHost) → 127.0.0.1:\(c.remotePort)"
        case .direct: return c.baseURL
        }
    }
}

/// The add / edit sheet. The token field is write-only: it is never filled from the Keychain.
struct ConnectionEditor: View {
    let original: Connection
    let isNew: Bool
    let onSave: (Connection, String?) -> Void
    let onCancel: () -> Void

    @State private var draft: Connection
    @State private var token = ""
    @State private var portText: String
    @State private var hasStoredToken: Bool

    init(original: Connection, isNew: Bool,
         onSave: @escaping (Connection, String?) -> Void, onCancel: @escaping () -> Void) {
        self.original = original; self.isNew = isNew; self.onSave = onSave; self.onCancel = onCancel
        _draft = State(initialValue: original)
        _portText = State(initialValue: String(original.remotePort))
        _hasStoredToken = State(initialValue: ConnectionStore.token(for: original.id) != nil)
    }

    private var needsToken: Bool { draft.mode == .direct || draft.tokenSource == .manual }
    private var port: Int? { Int(portText).flatMap { (1...65535).contains($0) ? $0 : nil } }

    private var problem: String? {
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give the connection a name." }
        switch draft.mode {
        case .sshTunnel:
            if !ConnectionStore.isValidSSHHost(draft.sshHost.trimmingCharacters(in: .whitespaces)) {
                return "SSH host must be a host alias or user@host (no spaces, not starting with “-”)."
            }
            if port == nil { return "Remote port must be 1–65535." }
        case .direct:
            if let m = ConnectionStore.baseURLProblem(draft.baseURL) { return m }
        }
        if needsToken {
            let t = token.trimmingCharacters(in: .whitespacesAndNewlines)
            if t.isEmpty && !hasStoredToken { return "Paste the daemon token (64 lowercase hex characters)." }
            if !t.isEmpty && !ConnectionStore.isValidToken(t) { return "The token must be exactly 64 lowercase hex characters." }
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(isNew ? "Add connection" : "Edit connection").font(.title3)
            Form {
                TextField("Name", text: $draft.name, prompt: Text("studio"))
                Picker("Reach it", selection: $draft.mode) {
                    Text("Over SSH").tag(Connection.Mode.sshTunnel)
                    Text("Direct URL").tag(Connection.Mode.direct)
                }
                .pickerStyle(.segmented)
                if draft.mode == .sshTunnel {
                    TextField("SSH host", text: $draft.sshHost, prompt: Text("alias or user@host"))
                    TextField("Remote port", text: $portText, prompt: Text("7878"))
                    Picker("Token", selection: $draft.tokenSource) {
                        Text("Fetch over SSH (~/.loom/token)").tag(Connection.TokenSource.fetchOverSsh)
                        Text("Enter manually").tag(Connection.TokenSource.manual)
                    }
                } else {
                    TextField("Base URL", text: $draft.baseURL, prompt: Text("http://127.0.0.1:7878"))
                }
                if needsToken {
                    SecureField("Token", text: $token,
                                prompt: Text(hasStoredToken ? "stored in Keychain — leave blank to keep" : "64 hex characters"))
                }
            }
            if let p = problem {
                Text(p).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction)
                Button("Save") {
                    var c = draft
                    c.name = c.name.trimmingCharacters(in: .whitespaces)
                    c.sshHost = c.sshHost.trimmingCharacters(in: .whitespaces)
                    c.remotePort = port ?? c.remotePort
                    if c.mode == .direct { c.baseURL = ConnectionStore.normalizedBaseURL(c.baseURL) ?? c.baseURL }
                    let t = token.trimmingCharacters(in: .whitespacesAndNewlines)
                    onSave(c, needsToken && !t.isEmpty ? t : nil)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(problem != nil)
            }
        }
        .padding(24)
        .frame(width: 460)
    }
}
