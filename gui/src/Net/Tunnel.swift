import Foundation
import Darwin

/// Manages the SSH port-forward to a daemon that binds loopback on another host, and the token fetch.
/// See gui/DESIGN.md "Tunnel". Exactly one tunnel is alive at a time.
///
/// - `open(_:)` for a `.sshTunnel` connection: pick a free 127.0.0.1 port, spawn
///   `ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15
///    -L 127.0.0.1:<local>:127.0.0.1:<remotePort> <sshHost>`, wait (poll-connect, ~10 s) until the
///   forward answers, then (if `.fetchOverSsh`) `ssh -o BatchMode=yes <sshHost> cat ~/.loom/token`,
///   trim and validate it. Returns `Ready(baseURL: "http://127.0.0.1:<local>", token:)` or throws a
///   `TunnelError` whose message includes ssh stderr.
/// - `close()` SIGTERMs the ssh child, SIGKILLs after a short grace, forgets the port. Idempotent.
/// - A `.direct` connection does not use this type.
final class Tunnel: @unchecked Sendable {
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

    /// Thread-safe accumulator for a child's stderr.
    private final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()
        func append(_ d: Data) { lock.lock(); data.append(d); if data.count > 65_536 { data = data.suffix(32_768) }; lock.unlock() }
        var text: String {
            lock.lock(); defer { lock.unlock() }
            // ssh repeats itself (one "open failed" per probe): keep each distinct line once, last few only.
            var seen = Set<String>(), lines: [String] = []
            for l in String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline) {
                let t = l.trimmingCharacters(in: .whitespaces)
                if !t.isEmpty && seen.insert(t).inserted { lines.append(t) }
            }
            return lines.suffix(3).joined(separator: "; ")
        }
    }

    private let lock = NSLock()
    private var ssh: Process?
    private var stderrSink: Sink?
    private var closing = false

    /// Called (on an arbitrary thread) if the ssh child exits without `close()` having been asked.
    var onUnexpectedExit: (@Sendable (String) -> Void)?

    static let forwardDeadline: TimeInterval = 10

    func open(_ connection: Connection) async throws -> Ready {
        guard connection.mode == .sshTunnel else {
            throw TunnelError.spawnFailed("not an SSH connection")
        }
        guard ConnectionStore.isValidSSHHost(connection.sshHost) else {
            throw TunnelError.spawnFailed("the SSH host is empty or malformed")
        }
        guard (1...65535).contains(connection.remotePort) else {
            throw TunnelError.spawnFailed("the remote port is out of range")
        }
        close()
        guard let local = Tunnel.freeLoopbackPort() else {
            throw TunnelError.spawnFailed("no free local port")
        }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        p.arguments = ["-N",
                       "-o", "BatchMode=yes",
                       "-o", "ExitOnForwardFailure=yes",
                       "-o", "ServerAliveInterval=15",
                       "-L", "127.0.0.1:\(local):127.0.0.1:\(connection.remotePort)",
                       "--", connection.sshHost]
        let err = Pipe()
        let sink = Sink()
        err.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil } else { sink.append(d) }
        }
        p.standardError = err
        p.standardOutput = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        p.terminationHandler = { [weak self] proc in
            guard let self else { return }
            self.lock.lock()
            let intentional = self.closing || self.ssh !== proc
            self.lock.unlock()
            if !intentional {
                let msg = sink.text
                self.onUnexpectedExit?(msg.isEmpty ? "ssh exited with status \(proc.terminationStatus)" : msg)
            }
        }
        lock.withLock { closing = false; ssh = p; stderrSink = sink }
        do { try p.run() } catch {
            lock.withLock { ssh = nil; stderrSink = nil }
            throw TunnelError.spawnFailed(error.localizedDescription)
        }

        // Wait for the forward, and for the daemon behind it to answer /healthz.
        let deadline = Date().addingTimeInterval(Tunnel.forwardDeadline)
        var portUp = false
        while true {
            if Task.isCancelled { close(); throw CancellationError() }
            if !p.isRunning {
                // Give the stderr pipe a moment to drain.
                try? await Task.sleep(nanoseconds: 100_000_000)
                let msg = sink.text
                close()
                throw TunnelError.forwardTimedOut(msg.isEmpty ? "ssh exited with status \(p.terminationStatus)" : msg)
            }
            if Tunnel.canConnect(port: local) {
                portUp = true
                if await Tunnel.healthz(port: local) { break }
            }
            if Date() >= deadline {
                let msg = sink.text
                close()
                let why = portUp
                    ? "the forward is up but nothing answered on \(connection.sshHost):\(connection.remotePort) (is the daemon running?)"
                    : "no answer within \(Int(Tunnel.forwardDeadline)) s"
                throw TunnelError.forwardTimedOut(msg.isEmpty ? why : "\(why) — \(msg)")
            }
            try? await Task.sleep(nanoseconds: 150_000_000)
        }

        var token: String? = nil
        if connection.tokenSource == .fetchOverSsh {
            do { token = try await fetchToken(host: connection.sshHost) } catch {
                close()
                throw error
            }
        }
        return Ready(baseURL: "http://127.0.0.1:\(local)", token: token)
    }

    func close() {
        lock.lock()
        closing = true
        let p = ssh
        ssh = nil
        stderrSink = nil
        lock.unlock()
        guard let p else { return }
        if p.isRunning {
            p.terminate()
            let pid = p.processIdentifier
            // Escalate off the caller's thread so quit/teardown never blocks on a stuck ssh.
            DispatchQueue.global().async {
                for _ in 0..<20 {                     // ~2 s grace
                    if !p.isRunning { return }
                    usleep(100_000)
                }
                if p.isRunning { kill(pid, SIGKILL) }
            }
        }
    }

    /// Synchronous variant for app quit: SIGTERM, brief wait, SIGKILL.
    func closeBlocking() {
        lock.lock()
        closing = true
        let p = ssh
        ssh = nil
        lock.unlock()
        guard let p, p.isRunning else { return }
        let pid = p.processIdentifier
        p.terminate()
        for _ in 0..<10 {
            if !p.isRunning { return }
            usleep(100_000)
        }
        if p.isRunning { kill(pid, SIGKILL) }
    }

    // MARK: token

    private func fetchToken(host: String) async throws -> String {
        let r = await Tunnel.runCapture("/usr/bin/ssh",
                                        ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, "cat ~/.loom/token"],
                                        timeout: 20)
        guard r.status == 0 else {
            let m = r.stderr.isEmpty ? "ssh exited with status \(r.status)" : r.stderr
            throw TunnelError.badToken(m)
        }
        let t = r.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ConnectionStore.isValidToken(t) else {
            throw TunnelError.badToken("~/.loom/token on \(host) is not 64 lowercase hex characters")
        }
        return t
    }

    struct Captured { var status: Int32; var stdout: String; var stderr: String }

    /// Run a short-lived child, capture its output, kill it after `timeout` seconds.
    static func runCapture(_ path: String, _ args: [String], timeout: TimeInterval) async -> Captured {
        await withCheckedContinuation { (cont: CheckedContinuation<Captured, Never>) in
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: path)
                p.arguments = args
                let o = Pipe(), e = Pipe()
                p.standardOutput = o
                p.standardError = e
                p.standardInput = FileHandle.nullDevice
                do { try p.run() } catch {
                    cont.resume(returning: Captured(status: -1, stdout: "", stderr: error.localizedDescription))
                    return
                }
                let timer = DispatchSource.makeTimerSource(queue: .global())
                timer.schedule(deadline: .now() + timeout)
                timer.setEventHandler { if p.isRunning { p.terminate() } }
                timer.resume()
                let group = DispatchGroup()
                var outData = Data(), errData = Data()
                group.enter()
                DispatchQueue.global().async { outData = o.fileHandleForReading.readDataToEndOfFile(); group.leave() }
                group.enter()
                DispatchQueue.global().async { errData = e.fileHandleForReading.readDataToEndOfFile(); group.leave() }
                group.wait()
                p.waitUntilExit()
                timer.cancel()
                cont.resume(returning: Captured(
                    status: p.terminationStatus,
                    stdout: String(decoding: outData.prefix(65_536), as: UTF8.self),
                    stderr: String(decoding: errData.prefix(16_384), as: UTF8.self)
                        .trimmingCharacters(in: .whitespacesAndNewlines)))
            }
        }
    }

    // MARK: ports

    /// A free TCP port on 127.0.0.1 (bind 0, read it back, release).
    static func freeLoopbackPort() -> Int? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { Darwin.close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { return nil }
        var out = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let got = withUnsafeMutablePointer(to: &out) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard got == 0 else { return nil }
        let port = Int(UInt16(bigEndian: out.sin_port))
        return port > 0 ? port : nil
    }

    /// One blocking connect attempt to 127.0.0.1:port (loopback: returns immediately).
    static func canConnect(port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { Darwin.close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return r == 0
    }

    /// `GET /healthz` (no token needed) through the forward: true only when the daemon answers 200.
    static func healthz(port: Int) async -> Bool {
        guard let url = URL(string: "http://127.0.0.1:\(port)/healthz") else { return false }
        var req = URLRequest(url: url)
        req.timeoutInterval = 2
        req.cachePolicy = .reloadIgnoringLocalCacheData
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 2
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        guard let (_, resp) = try? await session.data(for: req),
              let http = resp as? HTTPURLResponse else { return false }
        return http.statusCode == 200
    }

    #if DEBUG
    static func selfCheck() -> [String] {
        var f: [String] = []
        if let p = freeLoopbackPort() {
            if canConnect(port: p) { f.append("Tunnel: free port \(p) accepted a connection") }
        } else { f.append("Tunnel: freeLoopbackPort returned nil") }
        return f
    }
    #endif
}
