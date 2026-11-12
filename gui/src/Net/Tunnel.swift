import Foundation

/// Manages the SSH port-forward to a daemon that binds loopback on another host, and the token fetch.
/// See gui/DESIGN.md "Tunnel". Exactly one tunnel is alive at a time.
///
/// CONTRACT for the implementer:
/// - `open(_:)` for a `.sshTunnel` connection: pick a free 127.0.0.1 port, spawn
///   `ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15
///    -L 127.0.0.1:<local>:127.0.0.1:<remotePort> <sshHost>`, wait (poll-connect, ~10 s) until the
///   forward answers, then (if `.fetchOverSsh`) `ssh -o BatchMode=yes <sshHost> cat ~/.loom/token`,
///   trim and validate it. Returns `Ready(baseURL: "http://127.0.0.1:<local>", token:)` or throws a
///   `TunnelError` whose message includes ssh stderr.
/// - `close()` SIGTERMs the ssh child, SIGKILLs after a short grace, forgets the port. Idempotent.
/// - A `.direct` connection does not use this type; its baseURL is configured and its token comes
///   from the Keychain or a prompt.
final class Tunnel {
    struct Ready { let baseURL: String; let token: String? }

    enum TunnelError: Error, CustomStringConvertible {
        case spawnFailed(String)
        case forwardTimedOut(String)
        case badToken(String)
        var description: String {
            switch self {
            case .spawnFailed(let s): return "could not start the SSH tunnel: \(s)"
            case .forwardTimedOut(let s): return "the SSH tunnel did not come up: \(s)"
            case .badToken(let s): return "could not read the daemon token: \(s)"
            }
        }
    }

    private var ssh: Process?

    func open(_ connection: Connection) async throws -> Ready {
        throw TunnelError.spawnFailed("not implemented")
    }

    func close() { }

    /// A free TCP port on 127.0.0.1 (bind 0, read it back, release). Helper the implementer uses.
    static func freeLoopbackPort() -> Int? { nil }
}
