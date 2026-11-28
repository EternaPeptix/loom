import SwiftUI

/// Shown when nothing is connected (and inside the `⌘,` Manage Connections sheet): the saved connections,
/// local daemon auto-detection, and add / edit / delete / connect actions.
/// See gui/DESIGN.md "Connections".
struct ConnectionsView: View {
    @EnvironmentObject var state: AppState
    var inSheet: Bool = false
    var onDismiss: (() -> Void)? = nil

    @State private var editing: Connection? = nil
    @State private var deleting: Connection? = nil
    @State private var localDaemon: ConnectionStore.LocalDaemonInfo? = nil
    @State private var probedLocal = false

    private var localAlreadySaved: Bool {
        guard let local = localDaemon else { return false }
        return state.connections.contains {
            $0.mode == .direct && ConnectionStore.normalizedBaseURL($0.baseURL) == local.baseURL
        }
    }

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
                if inSheet, let onDismiss {
                    Button("Done", action: onDismiss)
                        .keyboardShortcut(.cancelAction)
                }
            }
            if let err = state.storageError {
                Text(err).font(.caption).foregroundStyle(.red)
            }
            if let local = localDaemon, !localAlreadySaved {
                HStack(spacing: 10) {
                    Image(systemName: "desktopcomputer")
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Local daemon detected at \(local.baseURL)")
                            .font(.subheadline.weight(.medium))
                        Text(local.hasToken
                             ? "Reads ~/.ferret/token automatically — no manual copy-paste needed."
                             : "Token file ~/.ferret/token not readable; you can paste the token in the editor.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(local.hasToken ? "Connect locally" : "Configure…") {
                        connectToDetectedLocal(local)
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding(10)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
            }
            if state.connections.isEmpty {
                VStack(alignment: .leading, spacing: 12) {
                    Text("No saved connections yet. Add one that points at a ferret daemon — directly if it is on this machine, or over SSH if it runs on another.")
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
                    let bad = invalidReason(c)
                    let isActive = state.isCurrentlyActive(c)
                    HStack {
                        VStack(alignment: .leading) {
                            HStack(spacing: 6) {
                                Text(c.displayName)
                                if isActive {
                                    Text("Active")
                                        .font(.caption2.weight(.medium))
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 1)
                                        .background(Color.green.opacity(0.18), in: Capsule())
                                }
                            }
                            Text(subtitle(c)).font(.caption).foregroundStyle(.secondary)
                            if let bad { Text(bad).font(.caption).foregroundStyle(.red) }
                        }
                        Spacer()
                        Button("Edit") { editing = c }
                        Button("Delete", role: .destructive) { deleting = c }
                        Button(isActive ? "Reconnect" : "Connect") {
                            state.connect(c)
                            onDismiss?()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(bad != nil)
                    }
                    .padding(.vertical, 2)
                    .contentShape(Rectangle())
                    .onTapGesture(count: 2) {
                        guard bad == nil else { return }
                        state.connect(c)
                        onDismiss?()
                    }
                }
            }
            Spacer()
        }
        .padding(16)
        .task {
            await probeLocalDaemon()
            // First run: only auto-open the blank add sheet if no local daemon was auto-detected.
            if !inSheet && state.connections.isEmpty && !state.offeredFirstRun && localDaemon == nil {
                state.offeredFirstRun = true
                editing = Connection(name: "")
            } else if !inSheet && state.connections.isEmpty && localDaemon != nil {
                state.offeredFirstRun = true
            }
        }
        .sheet(item: $editing) { c in
            let isNew = !state.connections.contains(where: { $0.id == c.id })
            ConnectionEditor(original: c, isNew: isNew, offerConnect: isNew || !state.isCurrentlyActive(c)) { saved, token, clearToken, connectNow in
                state.upsert(saved, token: token, clearToken: clearToken)
                editing = nil
                if connectNow {
                    state.connect(saved)
                    onDismiss?()
                }
            } onCancel: { editing = nil }
            .environmentObject(state)
        }
        .confirmationDialog("Delete this connection?", isPresented: Binding(
            get: { deleting != nil }, set: { if !$0 { deleting = nil } }), presenting: deleting) { c in
            let label = c.displayName
            Button("Delete \(label)", role: .destructive) { state.remove(c); deleting = nil }
            Button("Cancel", role: .cancel) { deleting = nil }
        } message: { _ in
            Text("This also removes its token from the Keychain.")
        }
    }

    private func probeLocalDaemon() async {
        guard !probedLocal else { return }
        probedLocal = true
        if let info = ConnectionStore.localDaemonFromHome() {
            if await DaemonClient.quickHealthz(baseURL: info.baseURL, timeout: 1.5) {
                localDaemon = info
                return
            }
        }
        let defaultBase = "http://127.0.0.1:7878"
        if await DaemonClient.quickHealthz(baseURL: defaultBase, timeout: 1.5) {
            let hasToken = FileManager.default.isReadableFile(atPath: ConnectionStore.ferretHome.appendingPathComponent("token").path)
            localDaemon = ConnectionStore.LocalDaemonInfo(baseURL: defaultBase, hasToken: hasToken, pid: nil)
        }
    }

    private func connectToDetectedLocal(_ local: ConnectionStore.LocalDaemonInfo) {
        if local.hasToken {
            let c = Connection(name: "local", mode: .direct, tokenSource: .localFile, baseURL: local.baseURL)
            state.upsert(c, token: nil, clearToken: false)
            state.connect(c)
            onDismiss?()
        } else {
            editing = Connection(name: "local", mode: .direct, tokenSource: .manual, baseURL: local.baseURL)
        }
    }

    /// Validates saved connections so broken Direct URLs, invalid SSH hosts, or cleared-token profiles
    /// show an actionable reason and disable Connect until edited.
    private func invalidReason(_ c: Connection) -> String? {
        switch c.mode {
        case .direct:
            if let bad = ConnectionStore.baseURLProblem(c.baseURL) { return bad }
            if c.tokenSource == .localFile { return nil }
            if !ConnectionStore.hasToken(for: c.id) {
                return "No token stored — click Edit to paste one or read ~/.ferret/token."
            }
            return nil
        case .sshTunnel:
            if !ConnectionStore.isValidSSHHost(c.sshHost) {
                return "Invalid SSH host — click Edit to fix it."
            }
            if !(1...65535).contains(c.remotePort) {
                return "Remote port must be 1–65535."
            }
            if c.tokenSource == .manual && !ConnectionStore.hasToken(for: c.id) {
                return "No token stored — click Edit to paste one or switch to Fetch over SSH."
            }
            return nil
        }
    }

    private func subtitle(_ c: Connection) -> String {
        switch c.mode {
        case .sshTunnel: return "ssh \(c.sshHost) → 127.0.0.1:\(c.remotePort)"
        case .direct:
            return c.tokenSource == .localFile ? "\(c.baseURL) · ~/.ferret/token" : c.baseURL
        }
    }
}

/// The add / edit sheet. The token field is write-only: it is never filled from the Keychain.
struct ConnectionEditor: View {
    private enum Field: Hashable { case name }

    let original: Connection
    let isNew: Bool
    let offerConnect: Bool
    let onSave: (Connection, String?, Bool, Bool) -> Void
    let onCancel: () -> Void

    @State private var draft: Connection
    @State private var token = ""
    @State private var portText: String
    @State private var hasStoredToken: Bool
    @State private var checkedStoredToken: Bool
    @State private var clearStoredToken = false
    @State private var showValidation = false
    @State private var localTokenNote: String? = nil
    @FocusState private var focusedField: Field?

    init(original: Connection, isNew: Bool, offerConnect: Bool = false,
         onSave: @escaping (Connection, String?, Bool, Bool) -> Void, onCancel: @escaping () -> Void) {
        self.original = original; self.isNew = isNew; self.offerConnect = offerConnect
        self.onSave = onSave; self.onCancel = onCancel
        var normalized = original
        // Backwards compatibility: legacy Direct profiles stored tokenSource = .fetchOverSsh.
        if normalized.mode == .direct && normalized.tokenSource == .fetchOverSsh {
            normalized.tokenSource = .manual
        }
        _draft = State(initialValue: normalized)
        _portText = State(initialValue: String(original.remotePort))
        let origNeedsToken = (normalized.mode == .direct && normalized.tokenSource != .localFile)
            || (normalized.mode == .sshTunnel && normalized.tokenSource == .manual)
        let checkOnInit = !isNew && origNeedsToken
        _hasStoredToken = State(initialValue: checkOnInit ? ConnectionStore.hasToken(for: original.id) : false)
        _checkedStoredToken = State(initialValue: checkOnInit)
    }

    private var needsManualToken: Bool {
        switch draft.mode {
        case .sshTunnel: return draft.tokenSource == .manual
        case .direct: return draft.tokenSource != .localFile
        }
    }

    private var port: Int? {
        Int(portText.trimmingCharacters(in: .whitespacesAndNewlines)).flatMap { (1...65535).contains($0) ? $0 : nil }
    }

    private var canConnectAfterSave: Bool {
        if problem != nil { return false }
        if needsManualToken {
            let t = token.trimmingCharacters(in: .whitespacesAndNewlines)
            if t.isEmpty && (!hasStoredToken || clearStoredToken) { return false }
        }
        return true
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
        if needsManualToken {
            let t = token.trimmingCharacters(in: .whitespacesAndNewlines)
            if t.isEmpty && !hasStoredToken && !clearStoredToken { return "Paste the daemon token (64 lowercase hex characters)." }
            if !t.isEmpty && !ConnectionStore.isValidToken(t) { return "The token must be exactly 64 lowercase hex characters." }
        }
        return nil
    }

    private var localTokenReadable: Bool {
        FileManager.default.isReadableFile(atPath: ConnectionStore.ferretHome.appendingPathComponent("token").path)
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
                        Text("Fetch over SSH (~/.ferret/token)").tag(Connection.TokenSource.fetchOverSsh)
                        Text("Enter manually").tag(Connection.TokenSource.manual)
                    }
                    if draft.tokenSource == .fetchOverSsh {
                        Text("Uses non-interactive SSH (`BatchMode=yes`) — key or ssh-agent authentication must succeed without prompts.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                } else {
                    TextField("Base URL", text: $draft.baseURL, prompt: Text("http://127.0.0.1:7878"))
                    Picker("Token", selection: $draft.tokenSource) {
                        Text("Read local ~/.ferret/token").tag(Connection.TokenSource.localFile)
                        Text("Enter manually").tag(Connection.TokenSource.manual)
                    }
                    if draft.tokenSource == .localFile {
                        Text("Reads \(ConnectionStore.ferretHome.appendingPathComponent("token").path) on connect.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if needsManualToken {
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
                        } else if draft.mode == .direct && localTokenReadable {
                            Button("Read ~/.ferret/token") {
                                if let local = ConnectionStore.readLocalToken() {
                                    token = local
                                    clearStoredToken = false
                                    localTokenNote = "Loaded token from ~/.ferret/token."
                                } else {
                                    localTokenNote = "~/.ferret/token does not contain a valid 64-character hex token."
                                }
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                    if clearStoredToken && token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        Text("Saving without a token will disable Connect until a new token is entered.")
                            .font(.caption).foregroundStyle(.orange)
                    } else if let note = localTokenNote {
                        Text(note).font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("The daemon writes its token to ~/.ferret/token on its host (`ferret` reads it there).")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if (showValidation || !isNew), let p = problem {
                Text(p).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction)
                if offerConnect && canConnectAfterSave {
                    Button("Save") { commit(connectNow: false) }
                        .disabled(problem != nil)
                    Button("Save & Connect") { commit(connectNow: true) }
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.defaultAction)
                        .disabled(!canConnectAfterSave)
                } else {
                    Button("Save") { commit(connectNow: false) }
                        .keyboardShortcut(.defaultAction)
                        .disabled(problem != nil)
                }
            }
        }
        .padding(24)
        .frame(width: 480)
        .onAppear { focusedField = .name }
        .onChange(of: draft.mode) { _, newMode in
            switch newMode {
            case .sshTunnel:
                if draft.tokenSource == .localFile { draft.tokenSource = .fetchOverSsh }
            case .direct:
                if draft.tokenSource == .fetchOverSsh {
                    draft.tokenSource = (isNew && localTokenReadable) ? .localFile : .manual
                }
            }
            showValidation = true
        }
        .onChange(of: draft) { _, _ in showValidation = true }
        .onChange(of: portText) { _, _ in showValidation = true }
        .onChange(of: token) { _, _ in showValidation = true; localTokenNote = nil }
        .onChange(of: needsManualToken) { _, needs in
            if needs && !isNew && !checkedStoredToken && !clearStoredToken {
                checkedStoredToken = true
                hasStoredToken = ConnectionStore.hasToken(for: original.id)
            }
        }
    }

    private func commit(connectNow: Bool) {
        var c = draft
        c.name = c.name.trimmingCharacters(in: .whitespaces)
        c.sshHost = c.sshHost.trimmingCharacters(in: .whitespaces)
        c.remotePort = port ?? c.remotePort
        if c.mode == .direct { c.baseURL = ConnectionStore.normalizedBaseURL(c.baseURL) ?? c.baseURL }
        let t = token.trimmingCharacters(in: .whitespacesAndNewlines)
        let newTok = needsManualToken && !t.isEmpty ? t : nil
        onSave(c, newTok, newTok == nil && clearStoredToken, connectNow)
    }
}
