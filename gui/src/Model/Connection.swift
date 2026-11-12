import Foundation
import Security

/// A saved way to reach one loom daemon. See gui/DESIGN.md "Connection model".
/// Secrets (the bearer token) are NOT stored here — they live in the Keychain, keyed by `id`.
struct Connection: Codable, Identifiable, Equatable {
    enum Mode: String, Codable { case sshTunnel, direct }
    enum TokenSource: String, Codable { case fetchOverSsh, manual }

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

    /// Empty when the file is missing or unreadable. Never throws.
    static func load() -> [Connection] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        return (try? JSONDecoder().decode([Connection].self, from: data)) ?? []
    }

    /// Writes the list (never any token) with mode 0600 into a 0700 directory. Returns false on failure.
    @discardableResult
    static func save(_ connections: [Connection]) -> Bool {
        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let enc = JSONEncoder()
            enc.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try enc.encode(connections)
            try data.write(to: fileURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
            return true
        } catch {
            return false
        }
    }

    private static func query(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: keychainService,
         kSecAttrAccount as String: id.uuidString]
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

    /// Stores a valid token (replacing any existing one). Returns false for an invalid token or a
    /// Keychain failure.
    @discardableResult
    static func setToken(_ token: String, for id: UUID) -> Bool {
        guard isValidToken(token) else { return false }
        SecItemDelete(query(id) as CFDictionary)
        var add = query(id)
        add[kSecValueData as String] = Data(token.utf8)
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

    /// An http(s) URL with a host, no credentials; used for `.direct` connections.
    static func normalizedBaseURL(_ s: String) -> String? {
        var t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        while t.hasSuffix("/") { t.removeLast() }
        guard let u = URL(string: t), let scheme = u.scheme?.lowercased(),
              scheme == "http" || scheme == "https", let host = u.host, !host.isEmpty,
              u.user == nil, u.password == nil, u.query == nil, u.fragment == nil,
              u.path.isEmpty else { return nil }
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
        chk(isValidSSHHost("user@512S1"), "plain host rejected")
        chk(normalizedBaseURL("http://127.0.0.1:7878/") == "http://127.0.0.1:7878", "base url normalize")
        chk(normalizedBaseURL("file:///etc") == nil, "file url accepted")
        return f
    }
    #endif
}
