import Foundation

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
    static func load() -> [Connection] { [] }
    static func save(_ connections: [Connection]) { }
    static func token(for id: UUID) -> String? { nil }
    static func setToken(_ token: String, for id: UUID) { }
    static func clearToken(for id: UUID) { }

    /// True for exactly 64 lowercase hex characters.
    static func isValidToken(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }
}
