import Foundation

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

        func run() async {
            while !Task.isCancelled {
                var reason = "stream ended"
                do {
                    try await stream()
                } catch is CancellationError {
                    break
                } catch {
                    reason = (error as? HTTPError)?.description ?? error.localizedDescription
                }
                if Task.isCancelled { break }
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
        return f
    }
    #endif
}
