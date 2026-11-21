import Foundation
import Darwin

/// Manages the SSH port-forward to a daemon that binds loopback on another host, and the token fetch.
/// See gui/DESIGN.md "Tunnel". Exactly one tunnel is alive at a time.
///
/// - `open(_:)` for a `.sshTunnel` connection: derive the browser URL and the ssh forward from ONE validated
///   `Forward` endpoint (same port at both ends), wait for the child the last `close()` stopped to exit, then
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
                return "local port \(p) is already in use. loom-desk needs 127.0.0.1:\(p) free for this connection: "
                    + "the daemon accepts only its own port number, so any forward must use port \(p) on both ends. "
                    + "Stop whatever is listening on port \(p) (`lsof -nP -iTCP:\(p) -sTCP:LISTEN` names it; a leftover "
                    + "ssh from an earlier loom-desk run can hold it), or move one of the daemons to another port with "
                    + "[daemon] bind in its config (if you move the remote one, change this connection's port to match)."
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
    /// All tunnel children stopped by `close()` / `close(only:)` until they have exited: their
    /// listener may hold the port for a moment, and `closeBlocking()` must ensure every one dies on quit.
    private var stopping: [ObjectIdentifier: Process] = [:]
    /// Active one-shot `fetchToken` children so app quit/teardown kills them too.
    private var tokenProcs: [UUID: Process] = [:]
    private var _onUnexpectedExit: (@Sendable (String, @escaping @Sendable () -> Bool) -> Void)?

    /// Called (on an arbitrary thread) with the reason if the ssh child exits without `close()` having been
    /// asked, and a check the receiver runs again when it acts on the report (after any hop to another
    /// thread): true only while that child is still this tunnel's current one.
    var onUnexpectedExit: (@Sendable (String, @escaping @Sendable () -> Bool) -> Void)? {
        get { lock.withLock { _onUnexpectedExit } }
        set { lock.withLock { _onUnexpectedExit = newValue } }
    }

    static let forwardDeadline: TimeInterval = 10

    /// The daemon checks the port in Host and Origin, so the browser-visible and remote ports must
    /// match. Keep the URL and ssh arguments derived from the same validated endpoint.
    struct Forward: Sendable {
        let port: Int

        init?(remotePort: Int) {
            guard (1...65535).contains(remotePort) else { return nil }
            port = remotePort
        }

        var baseURL: String { "http://127.0.0.1:\(port)" }

        func arguments(host: String) -> [String] { Tunnel.tunnelArguments(host: host, port: port) }

        var unavailable: String { TunnelError.portBusy(port).description }

        func failure(_ stderr: String) -> String {
            Tunnel.isBindFailure(stderr) ? stderr + " — " + unavailable : stderr
        }
    }

    func open(_ connection: Connection) async throws -> Ready {
        guard connection.mode == .sshTunnel else {
            throw TunnelError.spawnFailed("not an SSH connection")
        }
        guard ConnectionStore.isValidSSHHost(connection.sshHost) else {
            throw TunnelError.spawnFailed("the SSH host is empty or malformed")
        }
        guard let forward = Forward(remotePort: connection.remotePort) else {
            throw TunnelError.spawnFailed("the remote port is out of range")
        }
        close()
        await waitForExitingChild()
        if Task.isCancelled { throw CancellationError() }
        if Tunnel.canConnect(port: forward.port) { throw TunnelError.portBusy(forward.port) }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        p.arguments = forward.arguments(host: connection.sshHost)
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
                let isCurrent: @Sendable () -> Bool = { [weak self] in self?.isCurrent(proc) ?? false }
                DispatchQueue.global().async {
                    sink.waitForEnd()
                    // A close() or a newer open() during the wait makes this exit someone else's business.
                    guard isCurrent() else { return }
                    let msg = forward.failure(sink.lastLine)
                    self.onUnexpectedExit?(msg.isEmpty ? "ssh exited with status \(proc.terminationStatus)" : msg, isCurrent)
                }
            }
        }
        lock.withLock { closing = false; ssh = p; stderrSink = sink }
        do { try p.run() } catch {
            err.fileHandleForReading.readabilityHandler = nil
            try? err.fileHandleForReading.close()
            try? err.fileHandleForWriting.close()
            sink.end()
            lock.withLock { ssh = nil; stderrSink = nil }
            throw TunnelError.spawnFailed(error.localizedDescription)
        }

        // Wait for the forward, and for the daemon behind it to answer /healthz.
        let deadline = Date().addingTimeInterval(Tunnel.forwardDeadline)
        var portUp = false
        while true {
            try await failIfExited(p, sink: sink, port: forward.port)
            if Tunnel.canConnect(port: forward.port) {
                portUp = true
                if await Tunnel.healthz(port: forward.port) { break }
            }
            try await failIfExited(p, sink: sink, port: forward.port)
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
        return Ready(baseURL: forward.baseURL, token: token)
    }

    private func failIfExited(_ p: Process, sink: Sink, port: Int) async throws {
        if Task.isCancelled { close(only: p); throw CancellationError() }
        if !p.isRunning {
            await sink.awaitEnd()
            let msg = sink.text
            close(only: p)
            if Tunnel.isBindFailure(msg) { throw TunnelError.portBusy(port) }
            throw TunnelError.forwardTimedOut(msg.isEmpty ? "ssh exited with status \(p.terminationStatus)" : msg)
        }
    }

    /// True while the ssh child of the current tunnel is still running.
    var isRunning: Bool { lock.withLock { ssh?.isRunning ?? false } }

    /// The last line the current child wrote to stderr ("" when none or no child): why it exited.
    var lastErrorLine: String { lock.withLock { stderrSink?.lastLine ?? "" } }

    /// True while `p` is the current child and no `close()` has been asked.
    private func isCurrent(_ p: Process) -> Bool { lock.withLock { ssh === p && !closing } }

    func close() { close(only: nil) }

    /// Stops the current child. With `only`, stops exactly that child: when it is still the current one the
    /// tunnel is closed as usual; when it is not (a newer `open()` or a `close()` came first) just that
    /// process is stopped and the current state is left alone, so a superseded `open()` never leaves its own
    /// ssh running and never stops the tunnel a newer `open()` started.
    private func close(only: Process?) {
        lock.lock()
        if let only, ssh !== only {
            if only.isRunning { stopping[ObjectIdentifier(only)] = only }
            lock.unlock()
            stop(only)
            return
        }
        closing = true
        let p = ssh
        ssh = nil
        stderrSink = nil
        if let p { stopping[ObjectIdentifier(p)] = p }
        lock.unlock()
        guard let p else { return }
        stop(p)
    }

    /// SIGTERM, then SIGKILL after a short grace (off the caller's thread).
    private func stop(_ p: Process) {
        let key = ObjectIdentifier(p)
        if p.isRunning {
            lock.withLock { stopping[key] = p }
            p.terminate()
            let pid = p.processIdentifier
            // Escalate off the caller's thread so quit/teardown never blocks on a stuck ssh.
            DispatchQueue.global().async { [weak self] in
                for _ in 0..<20 {                     // ~2 s grace
                    if !p.isRunning {
                        self?.lock.withLock { _ = self?.stopping.removeValue(forKey: key) }
                        return
                    }
                    usleep(100_000)
                }
                if p.isRunning {
                    kill(pid, SIGKILL)
                    for _ in 0..<10 {
                        if !p.isRunning { break }
                        usleep(20_000)
                    }
                }
                self?.lock.withLock {
                    if !p.isRunning { _ = self?.stopping.removeValue(forKey: key) }
                }
            }
        } else {
            lock.withLock { _ = stopping.removeValue(forKey: key) }
        }
    }

    /// Synchronous variant for app quit: SIGTERM, brief wait, SIGKILL on all tracked children.
    func closeBlocking() {
        let tracked: [Process] = lock.withLock {
            closing = true
            var procs: [ObjectIdentifier: Process] = stopping
            if let p = ssh {
                procs[ObjectIdentifier(p)] = p
                stopping[ObjectIdentifier(p)] = p
                ssh = nil
                stderrSink = nil
            }
            for p in tokenProcs.values { procs[ObjectIdentifier(p)] = p }
            return Array(procs.values)
        }
        let alive = tracked.filter { $0.isRunning }
        if alive.isEmpty {
            lock.withLock {
                stopping = stopping.filter { $0.value.isRunning }
                tokenProcs = tokenProcs.filter { $0.value.isRunning }
            }
            return
        }
        let targets = alive.map { ($0, $0.processIdentifier) }
        for (p, _) in targets { p.terminate() }
        for _ in 0..<10 {
            if !targets.contains(where: { $0.0.isRunning }) { break }
            usleep(100_000)
        }
        var killed = false
        for (p, pid) in targets where p.isRunning {
            kill(pid, SIGKILL)
            killed = true
        }
        if killed {
            for _ in 0..<10 {
                if !targets.contains(where: { $0.0.isRunning }) { break }
                usleep(10_000)
            }
        }
        lock.withLock {
            stopping = stopping.filter { $0.value.isRunning }
            tokenProcs = tokenProcs.filter { $0.value.isRunning }
        }
    }

    /// Waits for children stopped by `close()` / `close(only:)` to exit (bounded: `stop()` SIGKILLs
    /// after ~2 s), so that only a listener that is not loom-desk's own is reported as a busy port.
    private func waitForExitingChild() async {
        let pending = lock.withLock { Array(stopping.values) }
        guard !pending.isEmpty else { return }
        for _ in 0..<60 {
            if Task.isCancelled || !pending.contains(where: { $0.isRunning }) { break }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        lock.withLock { stopping = stopping.filter { $0.value.isRunning } }
    }

    // MARK: token

    private func fetchToken(host: String) async throws -> String {
        let tokenID = UUID()
        let r = await Tunnel.runCapture("/usr/bin/ssh",
                                        ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"] + Tunnel.noMultiplexing
                                            + ["--", host, "cat ~/.loom/token"],
                                        timeout: 20) { [weak self] proc in
            guard let self else { return }
            self.lock.withLock {
                if let proc { self.tokenProcs[tokenID] = proc } else { self.tokenProcs.removeValue(forKey: tokenID) }
            }
        }
        if Task.isCancelled { throw CancellationError() }
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

    private static func terminateWithEscalation(_ p: Process, graceSeconds: Double = 1.0) {
        guard p.isRunning else { return }
        let pid = p.processIdentifier
        p.terminate()
        DispatchQueue.global().async {
            let steps = max(1, Int(graceSeconds / 0.1))
            for _ in 0..<steps {
                if !p.isRunning { return }
                usleep(100_000)
            }
            if p.isRunning { kill(pid, SIGKILL) }
        }
    }

    /// Run a short-lived child, capture its output, kill it after `timeout` seconds or on Task cancellation.
    static func runCapture(_ path: String,
                           _ args: [String],
                           timeout: TimeInterval,
                           onProcess: (@Sendable (Process?) -> Void)? = nil) async -> Captured {
        if Task.isCancelled {
            return Captured(status: -1, stdout: "", stderr: "cancelled")
        }
        final class Box: @unchecked Sendable {
            let lock = NSLock()
            var proc: Process?
            var cancelled = false
            var finished = false
        }
        final class DataBox: @unchecked Sendable {
            private let lock = NSLock()
            private var value = Data()
            func set(_ d: Data) { lock.withLock { value = d } }
            func get() -> Data { lock.withLock { value } }
        }
        let box = Box()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (cont: CheckedContinuation<Captured, Never>) in
                DispatchQueue.global().async {
                    let earlyCancel: Bool = box.lock.withLock {
                        if box.cancelled {
                            box.finished = true
                            return true
                        }
                        return false
                    }
                    if earlyCancel {
                        cont.resume(returning: Captured(status: -1, stdout: "", stderr: "cancelled"))
                        return
                    }
                    let p = Process()
                    p.executableURL = URL(fileURLWithPath: path)
                    p.arguments = args
                    let o = Pipe(), e = Pipe()
                    p.standardOutput = o
                    p.standardError = e
                    p.standardInput = FileHandle.nullDevice
                    do { try p.run() } catch {
                        try? o.fileHandleForReading.close(); try? o.fileHandleForWriting.close()
                        try? e.fileHandleForReading.close(); try? e.fileHandleForWriting.close()
                        box.lock.withLock { box.finished = true }
                        cont.resume(returning: Captured(status: -1, stdout: "", stderr: error.localizedDescription))
                        return
                    }
                    let cancelAfterLaunch: Bool = box.lock.withLock {
                        box.proc = p
                        return box.cancelled
                    }
                    onProcess?(p)
                    if cancelAfterLaunch {
                        terminateWithEscalation(p)
                    }
                    let timer = DispatchSource.makeTimerSource(queue: .global())
                    timer.schedule(deadline: .now() + timeout)
                    timer.setEventHandler { terminateWithEscalation(p) }
                    timer.resume()
                    let group = DispatchGroup()
                    let outBox = DataBox(), errBox = DataBox()
                    group.enter()
                    DispatchQueue.global().async { outBox.set(o.fileHandleForReading.readDataToEndOfFile()); group.leave() }
                    group.enter()
                    DispatchQueue.global().async { errBox.set(e.fileHandleForReading.readDataToEndOfFile()); group.leave() }
                    group.wait()
                    p.waitUntilExit()
                    timer.cancel()
                    onProcess?(nil)
                    box.lock.withLock { box.proc = nil; box.finished = true }
                    cont.resume(returning: Captured(
                        status: p.terminationStatus,
                        stdout: String(decoding: outBox.get().prefix(65_536), as: UTF8.self),
                        stderr: String(decoding: errBox.get().prefix(16_384), as: UTF8.self)
                            .trimmingCharacters(in: .whitespacesAndNewlines)))
                }
            }
        } onCancel: {
            let proc: Process? = box.lock.withLock {
                box.cancelled = true
                return box.finished ? nil : box.proc
            }
            if let proc { terminateWithEscalation(proc) }
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

    #if DEBUG
    /// Reserve a loopback address until the caller closes the returned descriptor. Port 0 is used
    /// only by isolated self-checks. ssh makes the final bind with ExitOnForwardFailure, so a race
    /// after the preflight still fails explicitly rather than changing ports.
    private static func bindLoopback(port: Int) -> Int32? {
        guard (0...65535).contains(port) else { return nil }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var reuse: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            Darwin.close(fd)
            return nil
        }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { Darwin.close(fd); return nil }
        return fd
    }

    private static func localPort(_ fd: Int32) -> Int? {
        var out = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let got = withUnsafeMutablePointer(to: &out) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard got == 0 else { return nil }
        let port = Int(UInt16(bigEndian: out.sin_port))
        return port > 0 ? port : nil
    }
    #endif

    /// One blocking connect attempt to 127.0.0.1:port (loopback: returns immediately).
    static func canConnect(port: Int) -> Bool {
        guard (1...65535).contains(port) else { return false }
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
        func check(_ condition: Bool, _ message: String) { if !condition { f.append("Tunnel: " + message) } }
        if let i = args.firstIndex(of: "-L"), i + 1 < args.count {
            if args[i + 1] != "127.0.0.1:7979:127.0.0.1:7979" { f.append("Tunnel: -L \(args[i + 1]) (ports must be equal)") }
        } else { f.append("Tunnel: no -L in the arguments") }
        if Array(args.suffix(2)) != ["--", "studio"] { f.append("Tunnel: host is not last after --") }
        if !args.contains("ControlPath=none") || !args.contains("ControlMaster=no") { f.append("Tunnel: multiplexing not off") }
        if !isBindFailure("bind [127.0.0.1]:7878: Address already in use") { f.append("Tunnel: bind failure not recognised") }
        if isBindFailure("Permission denied (publickey).") { f.append("Tunnel: auth failure taken for bind failure") }
        if isBindFailure("bind [127.0.0.1]:80: Permission denied; channel_setup_fwd_listener_tcpip: cannot listen to port: 80; "
                         + "Could not request local forwarding.") { f.append("Tunnel: privileged port taken for a busy one") }
        let busy = Tunnel.TunnelError.portBusy(7878).description
        if !busy.contains("port 7878") { f.append("Tunnel: portBusy message lacks the port") }
        // A forward on another local port is always refused (the daemon checks the port in Host), so the
        // message must not suggest one, and must say how to free or change the port.
        if busy.contains("ssh -L") || busy.contains("Direct connection") { f.append("Tunnel: portBusy suggests a forward on another port") }
        if !busy.contains("port 7878 on both ends") { f.append("Tunnel: portBusy does not say both ends use the daemon's port") }
        if !busy.contains("[daemon] bind") || !busy.contains("change this connection's port") {
            f.append("Tunnel: portBusy does not say how to move a daemon")
        }
        for port in [1, 7878, 65535] {
            guard let forward = Forward(remotePort: port) else { f.append("Tunnel: valid port refused"); continue }
            check(forward.port == port, "forward changed the daemon port")
            check(forward.baseURL == "http://127.0.0.1:\(port)", "base URL port differs")
            check(forward.arguments(host: "fixture") == tunnelArguments(host: "fixture", port: port), "forward arguments differ from the tunnel's")
            check(forward.arguments(host: "fixture").contains("127.0.0.1:\(port):127.0.0.1:\(port)"), "forward ports differ")
            check(forward.failure("bind: Address already in use").contains(forward.unavailable), "bind race has no actionable conflict message")
        }
        check(Forward(remotePort: 0) == nil && Forward(remotePort: 65536) == nil && Forward(remotePort: -1) == nil, "invalid forward port accepted")
        if let fd = bindLoopback(port: 0) {
            defer { Darwin.close(fd) }
            if let port = localPort(fd) {
                check(listen(fd, 1) == 0, "fixture listener could not start")
                check(canConnect(port: port), "fixture listener was not reachable")
                if let collision = bindLoopback(port: port) {
                    Darwin.close(collision)
                    f.append("Tunnel: occupied port was accepted")
                }
            } else { f.append("Tunnel: fixture listener has no port") }
        } else { f.append("Tunnel: fixture port reservation failed") }
        return f
    }
    #endif
}
