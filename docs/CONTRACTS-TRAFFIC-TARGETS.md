# Contract: captured traffic, findings tied to it, and targets shared across missions

Normative for the work merged with it. Each part names the files it owns. When a part is done its
rules move into `docs/DESIGN.md` (§11 network for C and I, the ledger section for F, a new section
"Targets" for T), `docs/RUN.md` and `docs/UI.md`, and this file shrinks to a pointer.

Decided by the operator (2026-11-24): HTTPS interception is **opt-in** (packs and missions turn it
on); security packs **refuse** a finding about a host without captured traffic with that host; the
shared asset graph is keyed by a **named target**.

Why: the proxy enforces scope and logs each decision, but keeps no request or response. HTTPS from a
command is a CONNECT tunnel it cannot read. `http_send` sees whole exchanges but keeps them in memory
(1024 at most) and loses them at a restart. A finding therefore cannot point at the traffic that shows
it, and nothing a mission learns about a target outlives the mission.

## C. Captured exchanges (`loom-core` event, `loom-net` sink, `loom-tools` http/web/mcp, runtime)

C1. **Record.** New event `Event::Exchange(Exchange)`, written to the session log:
```
Exchange { id: "ex-" + 12 base32 chars (random, like call ids),
           call_id: Option<CallId>,      // the call it was made in, when known
           ts_ms, source: "tool" | "proxy",
           tool: Option<String>,         // http_send, web_fetch, mcp__…, for source tool
           scheme: "http" | "https", tls: "plain" | "intercepted" | "tool",
           method, host, port, target,   // target = path and query as sent
           status: Option<u16>,          // None when no response (refused, reset, timeout)
           error: Option<String>,
           request: BlobRef, response: Option<BlobRef>,   // whole HTTP/1.1 messages, head and body
           request_bytes: u64, response_bytes: u64,        // true sizes
           truncated: bool,              // a body passed capture_max_bytes and was cut there
           duration_ms: u64 }
```
The blobs are ordinary stored outputs: `read` with `out:<key>` reads them, `grep` with an `out:` path
searches them, and `evidence` can quote them. An exchange's request and response blobs are listed in
the compaction key table (K5) as `ex-… · METHOD host/target · status` rows, under "Traffic".

C2. **Bounds.** `[network] capture_max_bytes` (default 1 MiB) per body; longer bodies are stored up to
it with `truncated: true` and the true size. Per session at most `capture_max_exchanges` (default
100 000) are recorded; past it the proxy still relays and decides, records no more, and the session
gets one harness note saying capture stopped and why.

C3. **What is captured.**
- **In-process tools** (`http_send`, `web_fetch`, MCP over HTTP): every exchange they make, with
  `source: "tool"`, `tls: "tool"`, and their `call_id`. They hand the exchanges back through a
  reserved meta key of their `ToolOutput` (like images, `META_EXCHANGES`); `finalize` removes it and
  the session records one `Exchange` per entry right after the call's `tool_result`. `http_send`'s
  result names the `ex-` id of each exchange beside its request id.
- **Plain HTTP through the proxy** from a sandboxed command: every request and response it forwards,
  `source: "proxy"`, `tls: "plain"`.
- **HTTPS through the proxy:** only when interception is on for the session (part I), `tls:
  "intercepted"`. Otherwise the tunnel stays opaque and no exchange is recorded (the `net.jsonl`
  decision is, as today).
- Proxy exchanges carry no `call_id` from the proxy; the session attributes one to the call that was
  running when it started (between that call's `exec_started` and its `tool_result`, the same window
  N1 uses for denials), else to none (a background job's traffic). The attribution is written into
  the record at append.

C4. **Restart.** Exchanges are in the log and the blob store, so they survive a restart. `http_send`'s
`request_id` for replay accepts an `ex-` id as well; replaying one recorded before a restart works from
its stored request (its cookie jar and captures are still not restored, and the result says so).

C5. **Secrets.** Bodies and headers are stored as sent: they are evidence. The UI and the API mark
`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization` and `X-Api-Key` values as sensitive and
show them masked until revealed (part U). Proxy credentials (`Proxy-Authorization` to loom's own proxy)
are never stored.

## I. HTTPS interception, opt-in (`loom-net` new module `tls.rs`, `proxy.rs`, config, packs, sandbox env)

I1. **Switch.** `[network] intercept = "pack"` (default) | `"always"` | `"never"`. With `"pack"`, a
mission intercepts when its pack says `intercept = true` (set for `ctf`, `redteam`, `vr`), unless the
mission was started with `intercept: false` (API body, `loom run --no-intercept`, a checkbox in the new
mission form); a mission of another pack can be started with `intercept: true`. The choice is recorded
in `session_start` (`intercept: bool`) and is fixed for the mission; its children inherit it.

I2. **The CA.** On first need the daemon creates `~/.loom/ca/loom-ca.pem` and `loom-ca.key` (ECDSA
P-256, 10 years, CN "loom interception CA (this machine)", key file `0600`). `~/.loom` is never
readable in the sandbox (already the rule), so no command can read the key. `loom ca show` prints the
certificate and its SHA-256 fingerprint; `loom ca rotate` makes a new one (sessions started after it
use it).

I3. **The sandbox trusts it** only for intercepting sessions: the session's tmp dir gets
`ca-bundle.pem` = the system roots (the first of `/etc/ssl/cert.pem`, `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt` that exists, else the bundled webpki roots in PEM) followed by the
loom CA, and the command environment gets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
`NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `PIP_CERT` and `AWS_CA_BUNDLE` pointing at it. Nothing is added
to a system or user trust store.

I4. **Per connection.** For an allowed `CONNECT host:port` of an intercepting session, unless the host
matches `[network] intercept_passthrough` (globs, default empty) or the target's (T1):
- The proxy answers `200`, does the TLS handshake with the command using a leaf certificate for `host`
  (SAN = the host name or IP, valid 24 h, signed by the CA, cached per host for the daemon's life),
  offering ALPN `http/1.1` only.
- It connects upstream with rustls, verifying the server's certificate against the webpki roots plus
  `[network] upstream_roots` (PEM files), with SNI = host. A host the target lists in
  `upstream_insecure` (T1) is not verified (labs and CTFs use self-signed certificates); every
  exchange with it is marked `upstream_unverified: true`. A verification failure ends the client
  connection with a TLS alert and records the decision `upstream certificate not valid for {host}:
  {reason}` in `net.jsonl` and as an `Exchange` with `error`.
- Requests on the decrypted stream are parsed as HTTP/1.1 (the proxy's existing head parser), relayed
  one by one (keep-alive allowed), and each request/response pair is captured (C1). If the first bytes
  are not an HTTP/1.1 request, the stream is relayed as bytes and one `Exchange` with `method:
  "TLS"`, no status and `error: "not HTTP/1.1: {n} bytes each way, not stored"` is recorded.
- A client that refuses the loom certificate (pinning, its own trust store) fails its handshake; the
  decision `client refused the interception certificate for {host}` is recorded, and the next
  `bash` result's facts say: `HTTPS to {host} was refused by the client under interception; add it to
  intercept_passthrough or use http_send`.
- Policy decisions, scope, private-address rules and `net.jsonl` are unchanged; interception happens
  only after a connection is allowed.

I5. **New dependencies:** `rcgen` (with the `ring` backend, already in the lockfile), `rustls` and
`tokio-rustls` (already in the lockfile through reqwest) as direct dependencies of `loom-net`.

## F. Findings tied to traffic (`loom-agent` gate and ledger tools, packs)

F1. A role with `require_traffic = true` (set on the finishing roles of `ctf`, `redteam`, `vr`) cannot
`finish`, or `conclude` with `status: met`, while a claim the answer relies on names a network host
that none of the claim's attested supporting evidence reached.
- **Claims the answer relies on:** the supported claims the `finish` evidence cites, or all supported
  claims of the mission when `finish` cites none.
- **The hosts a claim names:** those of its `assets` (new optional field on `claim`: asset ids or
  locators of the security state; `Host`, `Service`, `Endpoint` assets count, `File` and `Identity`
  do not), plus the host of every `http(s)://` URL and every host name or IP in the claim's text that
  is inside the mission target's scope (T1). Without a target, only `assets` and URLs count.
- **Reached:** some evidence of the claim that is attested, supports it, and cites a call during which
  an `Exchange` with that host (any port) was recorded with a status (a response arrived), or that
  quotes an `ex-` blob of such an exchange.
F2. The refusal names each claim, host and what to do, for example:
`finish cannot be accepted yet: c3 names api.acme.test, but none of its supporting evidence reached
it. Cite the evidence of a call that did (http_send, web_fetch, or a command while interception is on
for this mission; interception is off), or take the host out of the claim.` The text names only
tools the role is shown (T1 of the steering contract).
F3. Every claim in the ledger view and the verifier's brief shows its hosts as `reached` (with the
`ex-` ids) or `not reached`, whatever the role, so the verifier and the operator see it too.

## T. Targets shared across missions (`loom-core` new module `target.rs`, runtime, daemon, CLI)

T1. **A target** lives in `~/.loom/targets/{name}/` (name: `[a-z0-9][a-z0-9_-]{0,63}`):
`target.toml` with `scope = ["acme.test", "*.acme.test", "10.20.0.0/24"]`, `exclude = [...]`,
`upstream_insecure = [...]`, `intercept_passthrough = [...]`, `notes = "..."`; and `graph.jsonl`,
append-only and hash-chained like `net.jsonl`. Created and edited with `loom target add|show|scope|list`
and the API. A scope entry is a host, `*.` glob, IP or CIDR; `exclude` wins.

T2. **A mission** may name one target at start (`target` in the API body, `loom run --target acme`, a
select in the new-mission form). Recorded in `session_start` with the scope as it was then; children
inherit it. The target's scope is added to the mission's network allowlist (in every mode but `open`,
where it changes nothing), and `exclude` is denied even when another rule would allow it; the start
note says so. A mission without a target keeps its private security state, as today.

T3. **The graph.** Nodes `domain` (registrable), `host` (a name), `ip`, `service` (`host-or-ip:port/proto`),
`endpoint` (`METHOD scheme://host:port/path-template`); edges `parent` (host→domain), `resolves`
(host→ip), `runs` (host or ip→service), `serves` (service→endpoint). Node ids hash kind and canonical
locator as the security state's asset ids do, so a mission's asset and the target's node of the same
locator share an id. Each line of `graph.jsonl` is one of `node_seen`, `edge`, `coverage`, `finding`,
with `mission`, `session`, `ts_ms`, evidence keys, and `prev`.

T4. **Written by missions bound to the target**, as they go:
- every allowed proxy connection or exchange with an in-scope host → `node_seen` for the host, its
  IP (the decision's `resolved`), the service, and for exchanges the endpoint (path template:
  numeric and UUID-like segments become `{id}`);
- the security state's `asset_upsert` of a `Host`/`Service`/`Endpoint` → `node_seen` and edges;
  `coverage_set` → `coverage` (`tested` with evidence keys, or `deferred` with the reason);
- a claim that becomes supported and names hosts (F1) → `finding` on those nodes with the claim text,
  id and evidence keys; withdrawn or refuted later → a `finding` line with `status`.
Out-of-scope hosts are never written. Writes are synchronous with the record that caused them.

T5. **Read by missions:** the lead's system prompt gets, under "# Target {name}", the scope and a
summary (counts by kind; untested services and endpoints, most recently seen first, at most 40;
findings, at most 20, each `{node} · {claim text} · mission {id}`), cut at 8 KiB with a pointer to
`security_query` `view: "target"` (new; filters `kind`, `status` = untested|tested|deferred|finding,
`under` = a node id or locator, `max`). The summary is computed once at the lead's start and recorded
in `session_start`, so the request prefix is stable.

T6. **Status of a node** (for the UI and queries): `finding` if any open finding, else `tested` if any
mission tested it, else `deferred` if deferred, else `untested` when seen, and `in scope, not seen`
for scope entries with no node yet. Each status keeps which missions set it.

T7. **API and CLI:** `GET /api/targets` (name, scope, counts by status), `POST /api/targets`,
`PUT /api/targets/{name}` (scope, exclude, upstream_insecure, intercept_passthrough, notes),
`GET /api/targets/{name}/graph?status=&kind=&under=` (nodes with status, missions and evidence keys;
edges), `GET /api/exchanges/{session}?host=&after=&limit=` (a session's exchanges, newest last),
`GET /api/targets/{name}/exchanges?node=` (exchanges of every mission of the target with that node).
`loom target list|add|show|scope`, `loom ca show|rotate`. The SSE stream sends `{type:"target", name}`
when a target's graph changes (at most once a second per target).

## U. UI (`ui/`, fixture)

U1. **Exchanges.** A tool row with exchanges (or a `bash` row during which the proxy captured some)
shows `N requests` in its head; its body lists them (`METHOD host/target · status · size · time`),
each opening an exchange viewer: request and response side by side (stacked on a phone), headers as a
table with sensitive values masked and a Reveal toggle, body with Copy and Open as output (the
ordinary viewer with its `out:` key). Interception and `upstream_unverified` are shown as small marks.

U2. **Session's traffic.** The inspector's Network tab lists the session's exchanges under its
decisions, filterable by host and status, with the same viewer.

U3. **Claims.** Each claim shows its hosts as `reached · ex-…` (link) or `not reached` (amber), in the
Evidence tab, the ledger and the verifier card.

U4. **Targets.** The sidebar gets a Targets entry (`#/targets`, `#/t/{name}`). A target page has: the
scope (editable), counts by status, a tree domain → host → ip → service → endpoint with a status dot
per node (finding red, tested green, deferred grey, untested amber ring, in scope not seen hollow),
filters (status, kind, text), and a node panel: status with the missions that set it, findings with
links to their claims, evidence keys (open the viewer), and the exchanges with that node (U1 viewer).
The tree is virtualized past 2 000 rows. A mission's header shows a `target acme` chip linking to its
page; the new-mission form has a Target select.

## Tests

- **C:** a plain-HTTP request from `bash` through the proxy is recorded with both bodies, attributed to
  the running call; a body over the cap is truncated with the true size; `http_send`'s exchanges are
  recorded with its call id and survive a reopen of the session; replay by `ex-` id after a restart;
  a background job's exchange has no call id; the compaction key table lists exchanges; proxy
  credentials are never in a stored request.
- **I:** with interception on, `curl` with the bundle in its env gets a response from a local TLS test
  server (self-signed, listed in `upstream_insecure`) and both messages are recorded; with it off,
  the same request is a tunnel and nothing is recorded; a passthrough host is tunneled; an upstream
  with an invalid certificate and no `upstream_insecure` is refused and recorded; a non-HTTP TLS
  stream is relayed and recorded as `TLS`; the CA key is not readable from the sandbox (mirror the
  existing `~/.loom` read test); keep-alive with two requests gives two exchanges.
- **F:** finish refused when a supported claim names a host no evidence reached, accepted when an
  `http_send` evidence reached it, accepted for a claim naming only a `File` asset, not gated for a
  role without `require_traffic`; the refusal text names only shown tools.
- **T:** scope parsing (globs, CIDR, exclude wins); a mission with a target can reach scope hosts in
  `deny_all` mode and cannot reach excluded ones; graph writes from an exchange, an `asset_upsert`, a
  `coverage_set` and a supported claim; out-of-scope never written; status derivation (T6) and the
  `view: "target"` query; two missions of a target see each other's coverage at start; the summary
  is recorded and stable across a reopen; the hash chain of `graph.jsonl`.
- **U:** pure models (exchange list, header masking, target tree with statuses, filters) in
  `ui/core.test.js`; fixture routes for all of T7 and exchanges.
