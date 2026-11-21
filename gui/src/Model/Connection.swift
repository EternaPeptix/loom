import Foundation
import Darwin
import Security

/// A saved way to reach one loom daemon. See gui/DESIGN.md "Connection model".
/// Secrets (the bearer token) are NOT stored here — they live in the Keychain, keyed by `id`.
struct Connection: Codable, Identifiable, Equatable, Sendable {
    enum Mode: String, Codable, Sendable { case sshTunnel, direct }
    enum TokenSource: String, Codable, Sendable { case fetchOverSsh, manual }

    var id: UUID = UUID()
    var name: String = ""

    var mode: Mode = .sshTunnel
    // .sshTunnel
    var sshHost: String = ""
    var remotePort: Int = 7878
    var tokenSource: TokenSource = .fetchOverSsh
    // .direct
    var baseURL: String = "http://127.0.0.1:7878"
}

/// Load/save the connection list and the per-connection token.
///
/// CONTRACT for the implementer:
/// - `load()` reads `~/Library/Application Support/loom-desk/connections.json` (empty list when
///   missing or unreadable — never throws to the UI). `save(_:)` writes it with file mode 0600,
///   creating the directory (0700).
/// - `token(for:)` / `setToken(_:for:)` / `clearToken(for:)` use the login Keychain
///   (`kSecClassGenericPassword`, service `com.loom.desk`, account = connection id string). A token is
///   64 lowercase hex characters; reject anything else in `setToken`.
enum ConnectionStore {
    static let keychainService = "com.loom.desk"

    /// `~/Library/Application Support/loom-desk`
    static var directory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support")
        return base.appendingPathComponent("loom-desk", isDirectory: true)
    }
    static var fileURL: URL { directory.appendingPathComponent("connections.json") }

    private struct Lossy<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: Decoder) throws { value = try? T(from: decoder) }
    }

    /// Empty when the file is missing or unreadable. Never throws.
    static func load() -> [Connection] {
        load(from: fileURL)
    }

    /// Writes the list (never any token) with mode 0600 into a 0700 directory. Returns false on failure.
    @discardableResult
    static func save(_ connections: [Connection]) -> Bool {
        save(connections, to: fileURL)
    }

    static func load(from url: URL) -> [Connection] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        if let exact = try? JSONDecoder().decode([Connection].self, from: data) {
            return exact
        }
        // Preserve corrupt/unparseable JSON before a future save() overwrites the file.
        let dir = url.deletingLastPathComponent()
        let backup = dir.appendingPathComponent(url.lastPathComponent + ".corrupt")
        try? ensurePrivateDirectory(dir)
        try? writeAtomic0600(data, to: backup)
        if let boxes = try? JSONDecoder().decode([Lossy<Connection>].self, from: data) {
            return boxes.compactMap { $0.value }
        }
        return []
    }

    @discardableResult
    static func save(_ connections: [Connection], to url: URL) -> Bool {
        do {
            try ensurePrivateDirectory(url.deletingLastPathComponent())
            let enc = JSONEncoder()
            enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try enc.encode(connections)
            try writeAtomic0600(data, to: url)
            return true
        } catch {
            return false
        }
    }

    private static func ensurePrivateDirectory(_ dir: URL) throws {
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
    }

    private static func writeAtomic0600(_ data: Data, to url: URL) throws {
        let dir = url.deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        var cleanup = true
        defer { if cleanup { try? FileManager.default.removeItem(at: tmp) } }
        guard FileManager.default.createFile(
            atPath: tmp.path, contents: data,
            attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
        if Darwin.rename(tmp.path, url.path) != 0 {
            let e = Int(errno)
            throw NSError(domain: NSPOSIXErrorDomain, code: e)
        }
        cleanup = false
    }

    private static func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: keychainService,
         kSecAttrAccount as String: id.uuidString]
    }

    /// True when a Keychain entry exists for `id` without reading or decrypting the secret payload.
    static func hasToken(for id: UUID) -> Bool {
        var q = query(id)
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecReturnAttributes as String] = true
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess
    }

    static func token(for id: UUID) -> String? {
        var q = query(id)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data,
              let s = String(data: data, encoding: .utf8) else { return nil }
        return s
    }

    /// Stores a valid token (updating in place when present so a failed write never deletes an existing
    /// token). Returns false for an invalid token or a Keychain failure.
    @discardableResult
    static func setToken(_ token: String, for id: UUID) -> Bool {
        guard isValidToken(token) else { return false }
        let q = query(id)
        let data = Data(token.utf8)
        let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecSuccess { return true }
        guard status == errSecItemNotFound else { return false }
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    static func clearToken(for id: UUID) {
        SecItemDelete(query(id) as CFDictionary)
    }

    /// True for exactly 64 lowercase hex characters.
    static func isValidToken(_ s: String) -> Bool {
        s.utf8.count == 64 && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    /// An ssh destination must not look like an option (`-oProxyCommand=...`) or hold whitespace.
    static func isValidSSHHost(_ s: String) -> Bool {
        !s.isEmpty && !s.hasPrefix("-") && !s.contains(where: { $0.isWhitespace || $0.isNewline })
    }

    /// Why a `.direct` base URL cannot be used, or nil when it can. http is allowed only for a loopback
    /// host (127.0.0.1, localhost, [::1]): the token travels in every request, so any other host must
    /// use https.
    static func baseURLProblem(_ s: String) -> String? {
        var t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        while t.hasSuffix("/") { t.removeLast() }
        guard !t.hasSuffix(":"),
              let u = URL(string: t), let c = URLComponents(string: t),
              let scheme = u.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = u.host?.lowercased(), !host.isEmpty,
              u.user == nil, u.password == nil, u.query == nil, u.fragment == nil, u.path.isEmpty,
              c.user == nil, c.password == nil, c.query == nil, c.fragment == nil, c.path.isEmpty else {
            return "Base URL must look like http://127.0.0.1:7878 or https://host:port (no path, credentials, query or fragment)."
        }
        if let port = u.port ?? c.port, !(1...65535).contains(port) {
            return "Base URL port must be 1–65535."
        }
        if scheme == "http" && !["127.0.0.1", "localhost", "::1", "[::1]"].contains(host) {
            return "http is allowed only for 127.0.0.1, localhost or [::1]; any other host must use https (the token would travel in clear text)."
        }
        return nil
    }

    /// The trimmed base URL when `baseURLProblem` has nothing to say, else nil.
    static func normalizedBaseURL(_ s: String) -> String? {
        guard baseURLProblem(s) == nil else { return nil }
        var t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        while t.hasSuffix("/") { t.removeLast() }
        return t
    }

    #if DEBUG
    static func selfCheck() -> [String] {
        var f: [String] = []
        func chk(_ c: Bool, _ m: String) { if !c { f.append("ConnectionStore: " + m) } }
        let good = String(repeating: "ab12", count: 16)
        chk(isValidToken(good), "valid token rejected")
        chk(!isValidToken(String(good.dropLast())), "63 chars accepted")
        chk(!isValidToken(good.uppercased()), "uppercase accepted")
        chk(!isValidToken(String(repeating: "g", count: 64)), "non-hex accepted")
        chk(!isValidToken(good + "\n"), "trailing newline accepted")
        chk(!isValidSSHHost("-oProxyCommand=x"), "option-like host accepted")
        chk(isValidSSHHost("user@studio"), "plain host rejected")
        chk(normalizedBaseURL("http://127.0.0.1:7878/") == "http://127.0.0.1:7878", "base url normalize")
        chk(normalizedBaseURL("file:///etc") == nil, "file url accepted")
        for ok in ["http://127.0.0.1:7878", "http://localhost:7878", "http://[::1]:7878", "https://studio.example.com:7878",
                   "HTTP://LOCALHOST:1"] {
            chk(baseURLProblem(ok) == nil, "rejected \(ok): \(baseURLProblem(ok) ?? "")")
        }
        for bad in ["http://studio.example.com:7878", "http://10.0.0.5:7878", "http://127.0.0.1.evil.com", "http://localhost.evil.com",
                    "http://127.0.0.1@evil.com", "http://@127.0.0.1:7878", "http://127.0.0.1:7878?", "http://127.0.0.1:7878#",
                    "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:99999", "https://studio.example.com:0",
                    "http://127.0.0.1:", "ftp://localhost"] {
            chk(baseURLProblem(bad) != nil, "accepted \(bad)")
        }
        chk(baseURLProblem("http://10.0.0.5:7878")?.contains("https") == true, "message does not name https")

        // Atomic 0600 persistence & corrupt-JSON backup preservation.
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent("loom-conn-check-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }
        let jsonURL = tmpDir.appendingPathComponent("connections.json")
        let sample = Connection(name: "studio", mode: .sshTunnel, sshHost: "studio", remotePort: 7878)
        chk(save([sample], to: jsonURL), "save to temp dir failed")
        let dirMode = (try? FileManager.default.attributesOfItem(atPath: tmpDir.path)[.posixPermissions] as? NSNumber)?.intValue
        let fileMode = (try? FileManager.default.attributesOfItem(atPath: jsonURL.path)[.posixPermissions] as? NSNumber)?.intValue
        chk(dirMode == 0o700, "directory mode not 0700: \(String(describing: dirMode))")
        chk(fileMode == 0o600, "file mode not 0600: \(String(describing: fileMode))")
        chk(load(from: jsonURL) == [sample], "round-trip load failed")
        try? Data("{corrupt".utf8).write(to: jsonURL)
        chk(load(from: jsonURL).isEmpty, "corrupt json returned items")
        let backupURL = tmpDir.appendingPathComponent("connections.json.corrupt")
        chk(FileManager.default.fileExists(atPath: backupURL.path), "corrupt backup not created")
        let backupMode = (try? FileManager.default.attributesOfItem(atPath: backupURL.path)[.posixPermissions] as? NSNumber)?.intValue
        chk(backupMode == 0o600, "corrupt backup mode not 0600: \(String(describing: backupMode))")
        return f
    }
    #endif
}
