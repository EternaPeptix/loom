import SwiftUI

/// Shown when nothing is connected: the saved connections, with add / edit / delete / connect.
/// See gui/DESIGN.md "Connections".
struct ConnectionsView: View {
    @EnvironmentObject var state: AppState
    @State private var editing: Connection? = nil
    @State private var deleting: Connection? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Connections").font(.title3)
                Spacer()
                Button {
                    editing = Connection(name: "")
                } label: { Image(systemName: "plus") }
                .help("Add a connection")
                .accessibilityLabel("Add a connection")
            }
            if let err = state.storageError {
                Text(err).font(.caption).foregroundStyle(.red)
            }
            if state.connections.isEmpty {
                VStack(alignment: .leading, spacing: 12) {
                    Text("No connections yet. Add one that points at a loom daemon — directly if it is on this machine, or over SSH if it runs on another.")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: 520, alignment: .leading)
                    Button("Add connection") {
                        editing = Connection(name: "")
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(.top, 8)
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
            // First run: open the add form once (persisted on AppState so reopening the window does not re-prompt).
            if state.connections.isEmpty && !state.offeredFirstRun {
                state.offeredFirstRun = true
                editing = Connection(name: "")
            }
        }
        .sheet(item: $editing) { c in
            ConnectionEditor(original: c, isNew: !state.connections.contains(where: { $0.id == c.id })) { saved, token, clearToken in
                state.upsert(saved, token: token, clearToken: clearToken)
                editing = nil
            } onCancel: { editing = nil }
            .environmentObject(state)
        }
        .confirmationDialog("Delete this connection?", isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }), presenting: deleting) { c in
            let label = c.name.trimmingCharacters(in: .whitespaces).isEmpty ? "(unnamed)" : c.name
            Button("Delete \(label)", role: .destructive) { state.remove(c); deleting = nil }
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
    private enum Field: Hashable { case name }

    let original: Connection
    let isNew: Bool
    let onSave: (Connection, String?, Bool) -> Void
    let onCancel: () -> Void

    @State private var draft: Connection
    @State private var token = ""
    @State private var portText: String
    @State private var hasStoredToken: Bool
    @State private var checkedStoredToken: Bool
    @State private var clearStoredToken = false
    @State private var showValidation = false
    @FocusState private var focusedField: Field?

    init(original: Connection, isNew: Bool,
         onSave: @escaping (Connection, String?, Bool) -> Void, onCancel: @escaping () -> Void) {
        self.original = original; self.isNew = isNew; self.onSave = onSave; self.onCancel = onCancel
        _draft = State(initialValue: original)
        _portText = State(initialValue: String(original.remotePort))
        let origNeedsToken = original.mode == .direct || original.tokenSource == .manual
        let checkOnInit = !isNew && origNeedsToken
        _hasStoredToken = State(initialValue: checkOnInit ? ConnectionStore.hasToken(for: original.id) : false)
        _checkedStoredToken = State(initialValue: checkOnInit)
    }

    private var needsToken: Bool { draft.mode == .direct || draft.tokenSource == .manual }
    private var port: Int? {
        Int(portText.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap { (1...65535).contains($0) ? $0 : nil }
    }

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
            if t.isEmpty && !hasStoredToken && !clearStoredToken { return "Paste the daemon token (64 lowercase hex characters)." }
            if !t.isEmpty && !ConnectionStore.isValidToken(t) { return "The token must be exactly 64 lowercase hex characters." }
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(isNew ? "Add connection" : "Edit connection").font(.title3)
            Form {
                TextField("Name", text: $draft.name, prompt: Text("studio"))
                    .focused($focusedField, equals: .name)
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
                    if draft.tokenSource == .fetchOverSsh {
                        Text("Uses non-interactive SSH (`BatchMode=yes`) — key or ssh-agent authentication must succeed without prompts.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    TextField("Base URL", text: $draft.baseURL, prompt: Text("http://127.0.0.1:7878"))
                }
                if needsToken {
                    HStack {
                        SecureField("Token", text: $token,
                                    prompt: Text(hasStoredToken ? "stored in Keychain — leave blank to keep"
                                                 : clearStoredToken ? "saved token will be cleared on Save" : "64 hex characters"))
                        if hasStoredToken {
                            Button("Clear saved token", role: .destructive) {
                                clearStoredToken = true
                                hasStoredToken = false
                                token = ""
                                showValidation = true
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                    Text("The daemon writes its token to ~/.loom/token on its host (`loom` reads it there).")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if (showValidation || !isNew), let p = problem {
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
                    let newTok = needsToken && !t.isEmpty ? t : nil
                    onSave(c, newTok, newTok == nil && clearStoredToken)
                }
                .keyboardShortcut(.defaultAction)
                .disabled(problem != nil)
            }
        }
        .padding(24)
        .frame(width: 460)
        .onAppear { focusedField = .name }
        .onChange(of: draft) { _, _ in showValidation = true }
        .onChange(of: portText) { _, _ in showValidation = true }
        .onChange(of: token) { _, _ in showValidation = true }
        .onChange(of: needsToken) { _, needs in
            if needs && !isNew && !checkedStoredToken && !clearStoredToken {
                checkedStoredToken = true
                hasStoredToken = ConnectionStore.hasToken(for: original.id)
            }
        }
    }
}
