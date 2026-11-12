import Foundation
import Darwin

/// Manages the SSH port-forward to a daemon that binds loopback on another host, and the token fetch.
/// See gui/DESIGN.md "Tunnel". Exactly one tunnel is alive at a time.
///
/// - `open(_:)` for a `.sshTunnel` connection: wait for the child the last `close()` stopped to exit, then
///   spawn `ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15
///    -o ControlMaster=no -o ControlPath=none -L 127.0.0.1:<port>:127.0.0.1:<port> <sshHost>` (the SAME
///   port number at both ends, because the daemon only accepts its own port in the Host/Origin headers;
///   a busy port is an error, never a different port), wait (poll-connect, ~10 s) until the
///   forward answers, then (if `.fetchOverSsh`) `ssh -o BatchMode=yes <sshHost> cat ~/.loom/token`
///   (multiplexing off too), trim and validate it, and check the child is still running. Returns
///   `Ready(baseURL: "http://127.0.0.1:<port>", token:)` or throws a `TunnelError` whose message
///   includes ssh stderr.
/// - `close()` SIGTERMs the ssh child, SIGKILLs after a short grace. Idempotent.
/// - A `.direct` connection does not use this type.
final class Tunnel: @unchecked Sendable {
    struct Ready { let baseURL: String; let token: String? }

    enum TunnelError: Error, CustomStringConvertible {
        case spawnFailed(String)
        case forwardTimedOut(String)
        case badToken(String)
        case portBusy(Int)
        case exited(String)
        var description: String {
            switch self {
            case .spawnFailed(let s): return "could not start the SSH tunnel: \(s)"
            case .forwardTimedOut(let s): return "the SSH tunnel did not come up: \(s)"
            case .badToken(let s): return "could not read the daemon token: \(s)"
            case .portBusy(let p):
                return "local port \(p) is already in use. loom-desk needs 127.0.0.1:\(p) free for this connection "
                    + "(the tunnel must use the daemon's own port number). Close whatever is using port \(p) "
                    + "(`lsof -nP -iTCP:\(p) -sTCP:LISTEN` names it; a leftover ssh from an earlier loom-desk run "
                    + "can hold it), or use a Direct connection with your own ssh -L."
            case .exited(let s): return "the SSH tunnel closed: \(s)"
            }
        }
    }

    /// Thread-safe accumulator for a child's stderr.
    private final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()
        private var ended = false
        func append(_ d: Data) { lock.lock(); data.append(d); if data.count > 65_536 { data = data.suffix(32_768) }; lock.unlock() }
        /// The pipe reached end-of-file: everything the child printed is in.
        func end() { lock.withLock { ended = true } }
        /// Blocks up to ~0.5 s for end-of-file, so the line ssh prints as it exits is not missed.
        func waitForEnd() {
            for _ in 0..<50 {
                if lock.withLock({ ended }) { return }
                usleep(10_000)
            }
        }
        /// `waitForEnd()` for async callers.
        func awaitEnd() async {
            for _ in 0..<50 {
                if lock.withLock({ ended }) || Task.isCancelled { return }
                try? await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        /// The last non-empty line, for a one-line disconnect reason.
        var lastLine: String {
            lock.lock(); defer { lock.unlock() }
            let lines = String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline)
            return lines.last(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty })
                .map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
        }
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
    /// The child the last `close()` stopped, until `open()` has seen it exit: its listener may hold the
    /// port for a moment, and it must not be taken for someone else's.
    private var exiting: Process?

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
        await waitForExitingChild()
        if Task.isCancelled { throw CancellationError() }
        let local = connection.remotePort
        if Tunnel.canConnect(port: local) { throw TunnelError.portBusy(local) }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        p.arguments = Tunnel.tunnelArguments(host: connection.sshHost, port: local)
        let err = Pipe()
        let sink = Sink()
        err.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil; sink.end() } else { sink.append(d) }
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
                // Off Foundation's queue: let the pipe drain so the line ssh printed as it died is in.
                DispatchQueue.global().async {
                    sink.waitForEnd()
                    let msg = sink.lastLine
                    self.onUnexpectedExit?(msg.isEmpty ? "ssh exited with status \(proc.terminationStatus)" : msg)
                }
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
            if Task.isCancelled { close(only: p); throw CancellationError() }
            if !p.isRunning {
                await sink.awaitEnd()
                let msg = sink.text
                close(only: p)
                if Tunnel.isBindFailure(msg) { throw TunnelError.portBusy(local) }
                throw TunnelError.forwardTimedOut(msg.isEmpty ? "ssh exited with status \(p.terminationStatus)" : msg)
            }
            if Tunnel.canConnect(port: local) {
                portUp = true
                if await Tunnel.healthz(port: local) { break }
            }
            if Date() >= deadline {
                let msg = sink.text
                close(only: p)
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
                close(only: p)
                throw error
            }
        }
        if Task.isCancelled { close(only: p); throw CancellationError() }
        // The forward may have died during the token fetch; the caller only learns of an exit from here.
        if !p.isRunning {
            await sink.awaitEnd()
            let msg = sink.lastLine
            close(only: p)
            throw TunnelError.exited(msg.isEmpty ? "ssh exited with status \(p.terminationStatus)" : msg)
        }
        return Ready(baseURL: "http://127.0.0.1:\(local)", token: token)
    }

    /// True while the ssh child of the current tunnel is still running.
    var isRunning: Bool { lock.withLock { ssh?.isRunning ?? false } }

    /// The last line the current child wrote to stderr ("" when none or no child): why it exited.
    var lastErrorLine: String { lock.withLock { stderrSink?.lastLine ?? "" } }

    func close() { close(only: nil) }

    /// Stops the current child; with `only`, just when that is still the current child, so a superseded
    /// `open()` never stops the tunnel a newer `open()` started.
    private func close(only: Process?) {
        lock.lock()
        if let only, ssh !== only { lock.unlock(); return }
        closing = true
        let p = ssh
        ssh = nil
        stderrSink = nil
        if let p { exiting = p }
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

    /// Waits for the child the last `close()` stopped to exit (bounded: `close()` SIGKILLs it after ~2 s),
    /// so that only a listener that is not loom-desk's own is reported as a busy port.
    private func waitForExitingChild() async {
        guard let p = lock.withLock({ exiting }) else { return }
        for _ in 0..<60 where p.isRunning && !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        lock.withLock { if exiting === p && !p.isRunning { exiting = nil } }
    }

    // MARK: token

    private func fetchToken(host: String) async throws -> String {
        let r = await Tunnel.runCapture("/usr/bin/ssh",
                                        ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"] + Tunnel.noMultiplexing
                                            + ["--", host, "cat ~/.loom/token"],
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

    /// The `-L` argument: the local end uses the daemon's own port number, so the Host and Origin the page
    /// presents are the ones the daemon accepts.
    static func forwardSpec(port: Int) -> String { "127.0.0.1:\(port):127.0.0.1:\(port)" }

    /// No connection sharing: with a ControlMaster/ControlPersist from the operator's ssh config the
    /// forward's listener would live in a master that outlives the child loom-desk tracks and stops.
    static let noMultiplexing = ["-o", "ControlMaster=no", "-o", "ControlPath=none"]

    /// The tunnel child's arguments.
    static func tunnelArguments(host: String, port: Int) -> [String] {
        ["-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15"]
            + noMultiplexing + ["-L", forwardSpec(port: port), "--", host]
    }

    /// True when ssh's stderr says the local end of the forward is taken. Other bind failures (e.g. a
    /// port below 1024: "Permission denied") are not a busy port and are reported with ssh's own words.
    static func isBindFailure(_ stderr: String) -> Bool {
        stderr.lowercased().contains("address already in use")
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
        if forwardSpec(port: 7878) != "127.0.0.1:7878:127.0.0.1:7878" { f.append("Tunnel: forwardSpec \(forwardSpec(port: 7878))") }
        let args = tunnelArguments(host: "studio", port: 7979)
        if let i = args.firstIndex(of: "-L"), i + 1 < args.count {
            if args[i + 1] != "127.0.0.1:7979:127.0.0.1:7979" { f.append("Tunnel: -L \(args[i + 1]) (ports must be equal)") }
        } else { f.append("Tunnel: no -L in the arguments") }
        if Array(args.suffix(2)) != ["--", "studio"] { f.append("Tunnel: host is not last after --") }
        if !args.contains("ControlPath=none") || !args.contains("ControlMaster=no") { f.append("Tunnel: multiplexing not off") }
        if !isBindFailure("bind [127.0.0.1]:7878: Address already in use") { f.append("Tunnel: bind failure not recognised") }
        if isBindFailure("Permission denied (publickey).") { f.append("Tunnel: auth failure taken for bind failure") }
        if isBindFailure("bind [127.0.0.1]:80: Permission denied; channel_setup_fwd_listener_tcpip: cannot listen to port: 80; "
                         + "Could not request local forwarding.") { f.append("Tunnel: privileged port taken for a busy one") }
        if !Tunnel.TunnelError.portBusy(7878).description.contains("port 7878") { f.append("Tunnel: portBusy message lacks the port") }
        return f
    }
    #endif
}
