import Foundation
import CryptoKit
import Security

/// Read-only client to the active daemon: derives the menu-bar counts and fires notifications when a
/// mission needs a human. See gui/DESIGN.md "Daemon client". It never writes to the daemon — answering
/// and stopping happen in the web UI.
///
/// Wire facts (checked against the daemon source and a live daemon, they differ from the design text):
/// - `/api/events` frames carry only `data:` lines (no `event:`); the kind is the JSON `type` field:
///   `session` {info: SessionInfo}, `status` {session, status}, `record` {session, record{kind,…}},
///   `settled`, `error`, `lagged`, and (only with `?deltas=true`) `delta`/`net`.
/// - There is NO inbox event. An inbox item opens as a `record` whose `kind` is `inbox_opened` and
///   closes as `inbox_resolved`; a `status` carries `open_inbox`. So an inbox change is a trigger to
///   re-read `GET /api/inbox` (entries: {session, mission, title, opened_ms, item{item_id, item_kind,
///   text, options, blocking, …}}), which is the source of truth for the open set.
final class DaemonClient: @unchecked Sendable {
    // MARK: wire types (tolerant: every field optional, unknown fields ignored)

    struct StatusLite: Decodable, Equatable {
        var phase: String?
        var open_inbox: Int?
    }

    struct SessionLite: Decodable, Equatable {
        var id: String
        var title: String?
        var archived: Bool?
        var status: StatusLite?
        var phase: String? { status?.phase }
    }

    struct ItemLite: Decodable, Equatable {
        var item_id: String
        var item_kind: String?
        var text: String?
        var blocking: Bool?
        /// An explicit `blocking` wins; when absent, the kinds that need a human count as blocking.
        var isBlocking: Bool {
            if let b = blocking { return b }
            switch item_kind ?? "" {
            case "approval", "question", "blocker", "parked": return true
            default: return false
            }
        }
    }

    struct InboxLite: Decodable, Equatable {
        var session: String
        var title: String?
        var item: ItemLite
    }

    struct RecordLite: Decodable { var kind: String? }

    struct BusEvent: Decodable {
        var type: String
        var info: SessionLite?
        var session: String?
        var status: StatusLite?
        var record: RecordLite?
    }

    /// Decode an array, dropping elements that do not parse instead of failing the whole list.
    private struct Lossy<T: Decodable>: Decodable {
        let value: T?
        init(from decoder: Decoder) throws { value = try? T(from: decoder) }
    }

    static func decodeList<T: Decodable>(_ type: T.Type, from data: Data) -> [T]? {
        guard let boxes = try? JSONDecoder().decode([Lossy<T>].self, from: data) else { return nil }
        return boxes.compactMap { $0.value }
    }

    // MARK: web login (one-time code)

    enum LoginOutcome: Equatable {
        case code(String)       // a fresh single-use code
        case failed(String)     // a sentence for the operator
    }

    /// `{"code": "<hex>", "expires_in_s": 60}` -> the code, or nil when it is missing or not hex.
    static func parseLoginCode(_ data: Data) -> String? {
        struct Answer: Decodable { var code: String? }
        guard let a = try? JSONDecoder().decode(Answer.self, from: data), let c = a.code,
              (8...256).contains(c.utf8.count),
              c.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) || ($0 >= 0x41 && $0 <= 0x46) })
        else { return nil }
        return c
    }

    /// `<base>/#code=<code>`: the page exchanges the code itself; no token is in the URL.
    static func codeEntryURL(base: String, code: String) -> URL? {
        guard var c = URLComponents(string: base) else { return nil }
        c.path = "/"; c.query = nil
        c.fragment = "code=" + code
        return c.url
    }

    /// The only text the app puts on the pasteboard: scheme, host and port of the daemon, nothing that
    /// could be a code or a token (path, query, fragment and credentials are dropped).
    static func addressForPasteboard(base: String) -> String {
        guard var c = URLComponents(string: base) else { return "" }
        c.user = nil; c.password = nil; c.path = ""; c.query = nil; c.fragment = nil
        return c.string ?? ""
    }

    /// `POST <base>/api/login-codes` with the bearer token. A fresh code is needed for every page load.
    static func requestLoginCode(baseURL: String, token: String) async -> LoginOutcome {
        guard let url = URL(string: baseURL + "/api/login-codes") else { return .failed("the daemon address is not a valid URL") }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 5
        req.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 5
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else { return .failed("the daemon sent no HTTP answer") }
            switch http.statusCode {
            case 200:
                if let c = parseLoginCode(data) { return .code(c) }
                return .failed("the daemon answered the login request without a usable code. Update loom-desk and the daemon to matching versions.")
            case 404:
                return .failed("the daemon has no login-code route, so it is older than this app. Restart it on the new version.")
            case 401, 403:
                return .failed("the daemon rejected the token (HTTP \(http.statusCode)). Edit the connection and reconnect.")
            default: return .failed("the daemon refused the login request (HTTP \(http.statusCode)). Reconnect to retry.")
            }
        } catch {
            return .failed("could not reach the daemon for a login code: \(error.localizedDescription). Reconnect to retry.")
        }
    }

    // MARK: daemon identity (before the token is sent anywhere)

    enum IdentityOutcome: Equatable {
        case proven
        case mismatch(String)       // answered, but did not prove it is this token's daemon (a sentence for the operator)
        case unreachable(String)    // no usable answer (network error, 5xx, no proof JSON): the error text; retry later

        /// The sentence a one-shot caller (connect, a login-code request) shows when the token must not be
        /// sent, nil when proven. Such a caller does not retry by itself, so the operator is told to.
        var failure: String? {
            switch self {
            case .proven: return nil
            case .mismatch(let m): return m
            case .unreachable(let e):
                return "could not reach the daemon to check its identity: \(e). Reconnect to retry."
            }
        }
    }

    /// `onMode` text prefix for "the identity check could not reach the daemon" (the client's runner only:
    /// it does retry).
    static let unreachableModePrefix = "daemon unreachable, retrying"

    static func unreachableMessage(_ error: String) -> String { "\(unreachableModePrefix) (\(error))" }

    /// Sorts one answer of `/healthz?nonce=`: 5xx, or a non-200 without proof JSON (a restarting daemon behind
    /// a TLS proxy), is unreachable; a 200 whose proof is missing or wrong, or any other non-5xx answer
    /// carrying proof JSON (right or wrong: only a 200 proves), is a mismatch.
    static func classifyIdentity(status: Int, data: Data, token: String, nonce: String, baseURL: String) -> IdentityOutcome {
        let proof = parseIdentityProof(data)
        if status >= 500 || (status != 200 && proof == nil) { return .unreachable("HTTP \(status)") }
        guard status == 200, let proof,
              constantTimeEqual(proof.lowercased(), identityProof(token: token, nonce: nonce))
        else { return .mismatch(identityMismatchMessage(baseURL)) }
        return .proven
    }

    /// 64 random hexadecimal characters (32 bytes from the system generator), or nil if it fails.
    static func randomNonce() -> String? {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// `HMAC-SHA256(key: the token's bytes, message: "loom-healthz-v1:" + nonce)` as lowercase hex.
    static func identityProof(token: String, nonce: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data(("loom-healthz-v1:" + nonce).utf8),
                                                  using: SymmetricKey(data: Data(token.utf8)))
        return mac.map { String(format: "%02x", $0) }.joined()
    }

    /// Equality without an early exit on the first differing byte. Different lengths are unequal at once
    /// (the length of a proof is public).
    static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<x.count { diff |= x[i] ^ y[i] }
        return diff == 0
    }

    /// `{"ok": true, "proof": "<hex>"}` -> the proof, nil when it is missing or `ok` is not true.
    static func parseIdentityProof(_ data: Data) -> String? {
        struct Answer: Decodable { var ok: Bool?; var proof: String? }
        guard let a = try? JSONDecoder().decode(Answer.self, from: data), a.ok == true else { return nil }
        return a.proof
    }

    /// `onMode` text prefix for "the address no longer belongs to this token's daemon".
    static let identityModePrefix = "identity: "

    static func identityMismatchMessage(_ base: String) -> String {
        "something answered on \(base) but did not prove it is the loom daemon for this token, so the token was not sent. "
            + "If the daemon is older than this app, restart it on the new version; otherwise check the address and the token."
    }

    /// `GET <base>/healthz?nonce=<N>` (no token is sent): the daemon must answer with the HMAC proof for
    /// this token. Call before every use of the token.
    static func verifyIdentity(baseURL: String, token: String) async -> IdentityOutcome {
        guard let nonce = randomNonce() else { return .unreachable("could not get random bytes from the system to check the daemon") }
        guard var c = URLComponents(string: baseURL + "/healthz") else { return .mismatch("the daemon address is not a valid URL") }
        c.queryItems = [URLQueryItem(name: "nonce", value: nonce)]
        guard let url = c.url else { return .mismatch("the daemon address is not a valid URL") }
        var req = URLRequest(url: url)
        req.timeoutInterval = 5
        req.cachePolicy = .reloadIgnoringLocalCacheData
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 5
        cfg.httpShouldSetCookies = false
        cfg.httpCookieAcceptPolicy = .never
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else { return .unreachable("no HTTP answer") }
            return classifyIdentity(status: http.statusCode, data: data, token: token, nonce: nonce, baseURL: baseURL)
        } catch {
            return .unreachable(error.localizedDescription)
        }
    }

    // MARK: model (pure)

    struct Model: Equatable {
        var sessions: [String: SessionLite] = [:]
        var inbox: [String: InboxLite] = [:]      // keyed by item_id

        var counts: Counts { DaemonClient.derive(sessions: Array(sessions.values), inbox: Array(inbox.values)) }

        struct Refresh: OptionSet {
            let rawValue: Int
            static let inbox = Refresh(rawValue: 1)
            static let sessions = Refresh(rawValue: 2)
        }

        mutating func replaceSessions(_ list: [SessionLite]) {
            sessions = Dictionary(list.filter { $0.archived != true }.map { ($0.id, $0) },
                                  uniquingKeysWith: { _, b in b })
        }
        mutating func replaceInbox(_ list: [InboxLite]) {
            inbox = Dictionary(list.map { ($0.item.item_id, $0) }, uniquingKeysWith: { _, b in b })
        }

        /// Fold one stream event in; says what must be re-read from the API.
        mutating func apply(_ ev: BusEvent) -> Refresh {
            switch ev.type {
            case "session":
                if let info = ev.info {
                    if info.archived == true { sessions[info.id] = nil } else { sessions[info.id] = info }
                    return (info.status?.open_inbox ?? 0) > 0 ? [.inbox] : []
                }
                return [.sessions]
            case "status":
                guard let id = ev.session, let st = ev.status else { return [] }
                guard var s = sessions[id] else { return [.sessions, .inbox] }
                let before = s.status?.open_inbox ?? 0
                s.status = st
                sessions[id] = s
                return (st.open_inbox ?? 0) != before ? [.inbox] : []
            case "record":
                if let k = ev.record?.kind, k.hasPrefix("inbox") { return [.inbox] }
                return []
            case "settled", "lagged":
                return [.sessions, .inbox]
            default:
                return []
            }
        }
    }

    /// Derive counts from the current sessions and open inbox items. Pure helper.
    /// running = phase running; active = not ended / archived; waiting = open blocking inbox items.
    static func derive(sessions: [SessionLite], inbox: [InboxLite]) -> Counts {
        let live = sessions.filter { $0.archived != true }
        return Counts(running: live.filter { $0.phase == "running" }.count,
                      waiting: inbox.filter { $0.item.isBlocking }.count,
                      active: live.filter { $0.phase != "ended" }.count)
    }

    // MARK: SSE parsing (pure)

    /// The `data:` payload of one frame (the lines between blank lines), or nil when it has none
    /// (comments such as `: keep-alive`, `id:`/`retry:` only). Multiple `data:` lines join with "\n".
    static func parseFrame(_ frame: String) -> String? {
        var parts: [String] = []
        for raw in frame.split(separator: "\n", omittingEmptySubsequences: true) {
            var line = Substring(raw)
            if line.hasSuffix("\r") { line = line.dropLast() }
            if line.hasPrefix(":") { continue }
            if line == "data" { parts.append(""); continue }
            if line.hasPrefix("data:") {
                var v = line.dropFirst(5)
                if v.hasPrefix(" ") { v = v.dropFirst() }
                parts.append(String(v))
            }
        }
        return parts.isEmpty ? nil : parts.joined(separator: "\n")
    }

    /// Append a chunk to `buffer` and return the `data:` payloads of every frame it completes; the
    /// incomplete tail stays in `buffer`. CRLF is accepted. Pure helper.
    static func sseEvents(appending chunk: String, to buffer: inout String) -> [String] {
        buffer += chunk.replacingOccurrences(of: "\r\n", with: "\n")
        var out: [String] = []
        while let r = buffer.range(of: "\n\n") {
            let frame = String(buffer[buffer.startIndex..<r.lowerBound])
            buffer.removeSubrange(buffer.startIndex..<r.upperBound)
            if let d = parseFrame(frame) { out.append(d) }
        }
        return out
    }

    // MARK: lifecycle

    private let lock = NSLock()
    private var task: Task<Void, Never>?

    /// `onMode` says how the data is arriving: "live" or "polling (reason)".
    func start(baseURL: String,
               token: String?,
               onCounts: @escaping @Sendable (Counts) -> Void,
               onBlockingInbox: @escaping @Sendable (_ sessionId: String, _ title: String, _ text: String) -> Void,
               onMode: @escaping @Sendable (String) -> Void = { _ in }) {
        stop()
        let runner = Runner(baseURL: baseURL, token: token,
                            onCounts: onCounts, onBlocking: onBlockingInbox, onMode: onMode)
        let t = Task.detached { await runner.run() }
        lock.lock(); task = t; lock.unlock()
    }

    func stop() {
        lock.lock(); let t = task; task = nil; lock.unlock()
        t?.cancel()
    }

    // MARK: runner

    private final class Runner: @unchecked Sendable {
        let baseURL: String
        let token: String?
        let onCounts: @Sendable (Counts) -> Void
        let onBlocking: @Sendable (String, String, String) -> Void
        let onMode: @Sendable (String) -> Void
        let session: URLSession

        private let lock = NSLock()
        private var model = Model()
        private var seen = Set<String>()
        private var seeded = false
        private var lastCounts: Counts?

        init(baseURL: String, token: String?,
             onCounts: @escaping @Sendable (Counts) -> Void,
             onBlocking: @escaping @Sendable (String, String, String) -> Void,
             onMode: @escaping @Sendable (String) -> Void) {
            self.baseURL = baseURL; self.token = token
            self.onCounts = onCounts; self.onBlocking = onBlocking; self.onMode = onMode
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 45      // the stream sends a keep-alive every 15 s
            cfg.httpShouldSetCookies = false
            cfg.httpCookieAcceptPolicy = .never
            session = URLSession(configuration: cfg)
        }

        func request(_ path: String) -> URLRequest? {
            guard let url = URL(string: baseURL + path) else { return nil }
            var r = URLRequest(url: url)
            r.httpMethod = "GET"                    // read-only, always
            r.cachePolicy = .reloadIgnoringLocalCacheData
            if let token { r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
            return r
        }

        func get(_ path: String) async throws -> Data {
            guard let r = request(path) else { throw URLError(.badURL) }
            let (data, resp) = try await session.data(for: r)
            if let h = resp as? HTTPURLResponse, h.statusCode != 200 { throw HTTPError(status: h.statusCode) }
            return data
        }

        struct HTTPError: Error, CustomStringConvertible {
            var status: Int
            var description: String { status == 401 ? "the daemon rejected the token (401)" : "HTTP \(status)" }
        }

        /// The token goes out only to a daemon that has just proven it holds it. On failure reports it
        /// (a wrong answer with `identityModePrefix`, so the app can mark the link; no usable answer as
        /// `unreachableMessage`, since this loop does try again), waits, and says false.
        private func proven() async -> Bool {
            guard let token else { return true }
            let outcome = await DaemonClient.verifyIdentity(baseURL: baseURL, token: token)
            if case .proven = outcome { return true }
            if Task.isCancelled { return false }
            switch outcome {
            case .mismatch(let why): onMode(DaemonClient.identityModePrefix + why)
            case .unreachable(let e): onMode(DaemonClient.unreachableMessage(e))
            case .proven: break
            }
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            return false
        }

        func run() async {
            while !Task.isCancelled {
                var reason = "stream ended"
                if !(await proven()) { continue }
                do {
                    try await stream()
                } catch is CancellationError {
                    break
                } catch {
                    reason = (error as? HTTPError)?.description ?? error.localizedDescription
                }
                if Task.isCancelled { break }
                // Whatever ended the stream may have freed the port for another listener: prove the daemon
                // again before the snapshot below sends the token.
                if !(await proven()) { continue }
                onMode("polling (\(reason))")
                await refresh(sessions: true, inbox: true)
                try? await Task.sleep(nanoseconds: 4_000_000_000)
            }
            session.invalidateAndCancel()
        }

        func stream() async throws {
            guard let r = request("/api/events") else { throw URLError(.badURL) }
            // URLSession hands back the response only once the first body bytes arrive, and an idle
            // daemon sends none for up to 15 s (the keep-alive). Take a snapshot meanwhile so the
            // counts are right at once; a second one below closes the gap before the stream opened.
            async let early: Void = refresh(sessions: true, inbox: true)
            let (bytes, resp) = try await session.bytes(for: r)
            await early
            if let h = resp as? HTTPURLResponse, h.statusCode != 200 { throw HTTPError(status: h.statusCode) }
            // Subscribed, then snapshot again: nothing between the first snapshot and now is lost.
            await refresh(sessions: true, inbox: true)
            onMode("live")
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask { [self] in
                    // Belt and braces: the inbox set is re-read now and then even if no event says so.
                    while !Task.isCancelled {
                        try await Task.sleep(nanoseconds: 20_000_000_000)
                        await refresh(sessions: false, inbox: true)
                    }
                }
                group.addTask { [self] in
                    var pending = [UInt8]()
                    for try await b in bytes {
                        if b == 0x0D { continue }
                        pending.append(b)
                        if pending.count >= 2, pending[pending.count - 1] == 0x0A, pending[pending.count - 2] == 0x0A {
                            let frame = String(decoding: pending, as: UTF8.self)
                            pending.removeAll(keepingCapacity: true)
                            if let payload = DaemonClient.parseFrame(frame) { await handle(payload) }
                        } else if pending.count > 4_000_000 {
                            pending.removeAll()     // a runaway frame: drop it rather than grow
                        }
                    }
                    throw URLError(.networkConnectionLost)
                }
                _ = try await group.next()
                group.cancelAll()
            }
        }

        func handle(_ payload: String) async {
            guard let ev = try? JSONDecoder().decode(BusEvent.self, from: Data(payload.utf8)) else { return }
            let need = lock.withLock { model.apply(ev) }
            publish()
            if !need.isEmpty { await refresh(sessions: need.contains(.sessions), inbox: need.contains(.inbox)) }
        }

        func refresh(sessions: Bool, inbox: Bool) async {
            if sessions, let d = try? await get("/api/sessions"),
               let list = DaemonClient.decodeList(SessionLite.self, from: d) {
                lock.withLock { model.replaceSessions(list) }
            }
            if inbox, let d = try? await get("/api/inbox"),
               let list = DaemonClient.decodeList(InboxLite.self, from: d) {
                let fresh: [InboxLite] = lock.withLock {
                    model.replaceInbox(list)
                    let f = seeded ? list.filter { $0.item.isBlocking && !seen.contains($0.item.item_id) } : []
                    for e in list { seen.insert(e.item.item_id) }   // the first snapshot seeds silently
                    seeded = true
                    return f
                }
                for e in fresh {
                    onBlocking(e.session, e.title ?? e.session, e.item.text ?? "")
                }
            }
            publish()
        }

        func publish() {
            let (c, changed): (Counts, Bool) = lock.withLock {
                let c = model.counts
                let ch = c != lastCounts
                if ch { lastCounts = c }
                return (c, ch)
            }
            if changed { onCounts(c) }
        }
    }

    // MARK: self-checks

    #if DEBUG
    static func selfCheck() -> [String] {
        var f: [String] = []
        func chk(_ c: Bool, _ m: String) { if !c { f.append("DaemonClient: " + m) } }

        // SSE framing, including a frame split across chunks, comments and CRLF.
        var buf = ""
        var out = sseEvents(appending: ": keep-alive\n\ndata: {\"a\":1}\n\nda", to: &buf)
        chk(out == ["{\"a\":1}"], "frame + comment: \(out)")
        out = sseEvents(appending: "ta: x\r\ndata: y\r\n\r\n", to: &buf)
        chk(out == ["x\ny"], "split chunk / multi data / CRLF: \(out)")
        chk(buf.isEmpty, "buffer not drained: \(buf)")
        chk(parseFrame("id: 4\ndata:no-space") == "no-space", "data without space")
        chk(parseFrame(": only a comment") == nil, "comment frame yielded data")

        // Counts derivation from real-shaped JSON.
        let sessions = Data("""
        [{"id":"s1","title":"a","archived":false,"active":true,"extra":1,"status":{"phase":"running","open_inbox":1}},
         {"id":"s2","archived":false,"status":{"phase":"idle","open_inbox":0}},
         {"id":"s3","archived":false,"status":{"phase":"ended"}},
         {"nope":true}]
        """.utf8)
        let inbox = Data("""
        [{"session":"s1","mission":"m","title":"t","opened_ms":1,"item":{"item_id":"i1","item_kind":"question","text":"q?","blocking":true}},
         {"session":"s3","title":"t","item":{"item_id":"i2","item_kind":"finished","text":"done","blocking":false}}]
        """.utf8)
        let ss = decodeList(SessionLite.self, from: sessions) ?? []
        let ii = decodeList(InboxLite.self, from: inbox) ?? []
        chk(ss.count == 3, "lossy session decode kept \(ss.count)")
        chk(ii.count == 2, "inbox decode kept \(ii.count)")
        let c = derive(sessions: ss, inbox: ii)
        chk(c == Counts(running: 1, waiting: 1, active: 2), "derive: \(c)")

        // Event folding.
        var m = Model()
        m.replaceSessions(ss); m.replaceInbox(ii)
        let st = try? JSONDecoder().decode(BusEvent.self, from: Data(
            "{\"type\":\"status\",\"session\":\"s1\",\"status\":{\"phase\":\"idle\",\"open_inbox\":0}}".utf8))
        if let st {
            let need = m.apply(st)
            chk(need.contains(.inbox), "status with open_inbox change must refresh inbox")
            chk(m.counts.running == 0, "status event did not update phase")
        } else { f.append("DaemonClient: status event did not decode") }
        let rec = try? JSONDecoder().decode(BusEvent.self, from: Data(
            "{\"type\":\"record\",\"session\":\"s1\",\"record\":{\"seq\":3,\"kind\":\"inbox_opened\",\"x\":1}}".utf8))
        if let rec { var m2 = m; chk(m2.apply(rec).contains(.inbox), "inbox_opened must refresh inbox") }
        else { f.append("DaemonClient: record event did not decode") }

        // Login entry URL: it carries a code and never the token.
        chk(codeEntryURL(base: "http://127.0.0.1:7878", code: "0a1b2c")?.absoluteString == "http://127.0.0.1:7878/#code=0a1b2c",
            "code url: \(codeEntryURL(base: "http://127.0.0.1:7878", code: "0a1b2c")?.absoluteString ?? "nil")")
        chk(!(codeEntryURL(base: "http://127.0.0.1:7878", code: "0a1b2c")?.absoluteString.contains("token") ?? true), "code url mentions token")
        chk(parseLoginCode(Data("{\"code\":\"00ff00ff00ff00ff\",\"expires_in_s\":60}".utf8)) == "00ff00ff00ff00ff", "login code parse")
        chk(parseLoginCode(Data("{\"code\":\"zz\",\"expires_in_s\":60}".utf8)) == nil, "short login code accepted")
        chk(parseLoginCode(Data("{\"code\":\"00ff00ff00ff00zz\",\"expires_in_s\":60}".utf8)) == nil, "non-hex login code accepted")
        chk(parseLoginCode(Data("{\"expires_in_s\":60}".utf8)) == nil, "missing login code accepted")

        chk(addressForPasteboard(base: "http://127.0.0.1:7878") == "http://127.0.0.1:7878", "copied address")
        chk(addressForPasteboard(base: "https://u:p@h.example:1/x?token=t#code=c") == "https://h.example:1", "copied address keeps a secret")

        // Daemon identity proof: a known token and nonce, constant-time comparison, answer parsing.
        let ptok = String(repeating: "ab12", count: 16)
        let pnonce = String(repeating: "0123456789abcdef", count: 4)
        let want = "1fc539b8ca1872003953db475a0df90e51af1a8b13dbdc634a84b28a63c46fcb"
        chk(identityProof(token: ptok, nonce: pnonce) == want, "identity proof: \(identityProof(token: ptok, nonce: pnonce))")
        chk(identityProof(token: ptok, nonce: pnonce + "0") != want, "proof ignores the nonce")
        chk(constantTimeEqual(want, want), "equal proofs differ")
        chk(!constantTimeEqual(want, String(want.dropLast()) + "c"), "near miss accepted")
        chk(!constantTimeEqual(want, String(want.dropLast())), "shorter proof accepted")
        chk(!constantTimeEqual(want, ""), "empty proof accepted")
        chk(parseIdentityProof(Data("{\"ok\":true,\"proof\":\"\(want)\"}".utf8)) == want, "proof parse")
        chk(parseIdentityProof(Data("{\"ok\":true}".utf8)) == nil, "missing proof accepted")
        let okBody = Data("{\"ok\":true,\"proof\":\"\(want)\"}".utf8), noProof = Data("{\"ok\":true}".utf8)
        func cls(_ st: Int, _ d: Data, _ n: String = pnonce) -> IdentityOutcome {
            classifyIdentity(status: st, data: d, token: ptok, nonce: n, baseURL: "http://h")
        }
        chk(cls(200, okBody) == .proven, "identity 200 proof")
        chk(cls(200, noProof) == .mismatch(identityMismatchMessage("http://h")), "identity 200 without proof")
        chk(cls(200, okBody, pnonce + "0") == .mismatch(identityMismatchMessage("http://h")), "identity 200 wrong proof")
        chk(cls(502, Data()) == .unreachable("HTTP 502"), "identity 502")
        chk(cls(503, okBody) == .unreachable("HTTP 503"), "identity 503 with body")
        chk(cls(404, Data("nope".utf8)) == .unreachable("HTTP 404"), "identity 404 no proof")
        chk(cls(404, okBody) == .mismatch(identityMismatchMessage("http://h")), "identity 404 with a right proof")
        chk(IdentityOutcome.unreachable("x").failure == "could not reach the daemon to check its identity: x. Reconnect to retry.",
            "unreachable one-shot text")
        chk(unreachableMessage("x") == "daemon unreachable, retrying (x)", "unreachable runner text")
        chk(unreachableMessage("x").hasPrefix(unreachableModePrefix), "runner text carries its prefix")
        chk(IdentityOutcome.mismatch("m").failure == "m", "mismatch text")
        chk(IdentityOutcome.proven.failure == nil, "proven has no failure")
        chk(parseIdentityProof(Data("{\"ok\":false,\"proof\":\"\(want)\"}".utf8)) == nil, "ok=false accepted")
        let n1 = randomNonce(), n2 = randomNonce()
        chk(n1?.count == 64 && n1 != n2 && n1?.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) == true,
            "nonce: \(n1 ?? "nil")")
        chk(identityMismatchMessage("http://127.0.0.1:7878").contains("restart it on the new version"), "mismatch message")
        return f
    }
    #endif
}
