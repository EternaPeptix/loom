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

## C. Captured exchanges (`ferret-core` event, `ferret-net` sink, `ferret-tools` http/web/mcp, runtime)

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
show them masked until revealed (part U). Proxy credentials (`Proxy-Authorization` to ferret's own proxy)
are never stored.

## I. HTTPS interception, opt-in (`ferret-net` new module `tls.rs`, `proxy.rs`, config, packs, sandbox env)

I1. **Switch.** `[network] intercept = "pack"` (default) | `"always"` | `"never"`. With `"pack"`, a
mission intercepts when its pack says `intercept = true` (set for `ctf`, `redteam`, `vr`), unless the
mission was started with `intercept: false` (API body, `ferret run --no-intercept`, a checkbox in the new
mission form); a mission of another pack can be started with `intercept: true`. The choice is recorded
in `session_start` (`intercept: bool`) and is fixed for the mission; its children inherit it.

I2. **The CA.** On first need the daemon creates `~/.ferret/ca/ferret-ca.pem` and `ferret-ca.key` (ECDSA
P-256, 10 years, CN "ferret interception CA (this machine)", key file `0600`). `~/.ferret` is never
readable in the sandbox (already the rule), so no command can read the key. `ferret ca show` prints the
certificate and its SHA-256 fingerprint; `ferret ca rotate` makes a new one (sessions started after it
use it).

I3. **The sandbox trusts it** only for intercepting sessions: the session's tmp dir gets
`ca-bundle.pem` = the system roots (the first of `/etc/ssl/cert.pem`, `/etc/ssl/certs/ca-certificates.crt`,
`/etc/pki/tls/certs/ca-bundle.crt` that exists, else the bundled webpki roots in PEM) followed by the
ferret CA, and the command environment gets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
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
- A client that refuses the ferret certificate (pinning, its own trust store) fails its handshake; the
  decision `client refused the interception certificate for {host}` is recorded, and the next
  `bash` result's facts say: `HTTPS to {host} was refused by the client under interception; add it to
  intercept_passthrough or use http_send`.
- Policy decisions, scope, private-address rules and `net.jsonl` are unchanged; interception happens
  only after a connection is allowed.

I5. **New dependencies:** `rcgen` (with the `ring` backend, already in the lockfile), `rustls` and
`tokio-rustls` (already in the lockfile through reqwest) as direct dependencies of `ferret-net`.

## F. Findings tied to traffic (`ferret-agent` gate and ledger tools, packs)

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

## T. Targets shared across missions (`ferret-core` new module `target.rs`, runtime, daemon, CLI)

T1. **A target** lives in `~/.ferret/targets/{name}/` (name: `[a-z0-9][a-z0-9_-]{0,63}`):
`target.toml` with `scope = ["acme.test", "*.acme.test", "10.20.0.0/24"]`, `exclude = [...]`,
`upstream_insecure = [...]`, `intercept_passthrough = [...]`, `notes = "..."`; and `graph.jsonl`,
append-only and hash-chained like `net.jsonl`. Created and edited with `ferret target add|show|scope|list`
and the API. A scope entry is a host, `*.` glob, IP or CIDR; `exclude` wins.

T2. **A mission** may name one target at start (`target` in the API body, `ferret run --target acme`, a
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
`ferret target list|add|show|scope`, `ferret ca show|rotate`. The SSE stream sends `{type:"target", name}`
when a target's graph changes (at most once a second per target).

## S. Stored authenticated sessions (credential profiles) (`ferret-core` `creds.rs`, `ferret-net` proxy injection, `ferret-daemon` CLI/API)

A credential profile lets the operator hand ferret a session it is already logged into — including behind
2FA — once, so missions bound to a target carry that session into their in-scope requests without the
agent ever seeing the secret. It builds on the interception+capture path (I, C) and the target scope (T).

S1. **A profile** belongs to a target: `~/.ferret/targets/{name}/creds/{profile}.enc` (profile name
`[a-z0-9][a-z0-9_-]{0,63}`; `default` when unnamed). Decrypted (S4) it is a list of items, each
`{ kind: "cookie" | "header", name, value, host }` where `host` is a single in-scope host (never a
glob). A `cookie` item is one `name=value` pair of a host's jar; a `header` item is a whole header
value (e.g. `Authorization`). The item values are secrets (S5); nothing else in the file is.

S2. **Recording a login through the proxy** (the operator, never the agent). `ferret creds record
--target acme [--profile default]` opens a short-lived intercepting capture session scoped to the
target and prints one line: the proxy address and the ferret CA to trust (the same CA as I2 — already
trusted inside a mission, trusted once by the operator's browser here). The operator points a browser
at it and logs in. For every **in-scope** exchange it collects, from the request, each `Cookie` pair
and any `Authorization` / `X-Api-Key` value, and from the response each `Set-Cookie`; it streams what
it is collecting as `host · cookie <name>` / `host · header <name>` lines, **names only, never
values**. On `--stop` (or Ctrl-C) it writes the profile: per in-scope host, the latest value of each
cookie and header seen (response `Set-Cookie` overrides an earlier request `Cookie` of the same name),
one item each, `host` = the host it was seen on. Out-of-scope traffic is dropped, not written.
  - Scripted path (no browser): `ferret creds set --target acme [--profile default] --host api.acme.test
    --cookie 'session=…'` / `--header 'Authorization: Bearer …'` (repeatable). `--host` must be in the
    target scope. Same storage, same secret handling.

  - Collection rules: request `Cookie` pairs and response `Set-Cookie` (name and value only; attributes
    ignored) give `cookie` items; request `Authorization` and `X-Api-Key` (names case-insensitive, stored as
    first seen) give `header` items. Within one exchange the request is read before the response. A
    `Set-Cookie` with an empty value or `Max-Age` of 0 or less removes that cookie item. Cookie names are
    case-sensitive.
  - The recording session (daemon side): a proxy grant for a pseudo-session `creds-rec-{random}` with the
    daemon's `[network]` policy in `open` mode plus the target scope (T2), so the operator's browser reaches
    the target and any login provider; interception only for hosts the target scope contains
    (`CaptureGrant::intercept_scope`), every other CONNECT stays an opaque tunnel and nothing of it is read.
    It prints the proxy address with its user and password (browsers ask for them), the CA path and its
    SHA-256 fingerprint. It ends on `--stop`, Ctrl-C, or after 30 minutes, and writes the profile in each
    case; a recording that collected nothing writes nothing and says so. API: `POST
    /api/targets/{name}/creds` with `{"record":{"profile":"default"}}` → `{handle, proxy, user, password,
    ca_path, ca_sha256}`; `GET /api/targets/{name}/creds/record/{handle}?after={n}` → `{lines, next, done}`
    (name lines only); `POST /api/targets/{name}/creds` with `{"stop": handle}` → the profile summary.

S3. **Injection.** A mission bound to a target may name one profile at start (`creds` in the API body,
`ferret run --creds default`, a select in the new-mission form; default none). Recorded in
`session_start` as the profile name and a redaction-safe summary (`default · 3 cookies, 1 header ·
*.acme.test`), never values; children inherit it. The session grant carries the decrypted items. For
**every forwarded request** — plain or intercepted — whose destination host equals an item's `host`
**and** is allowed by the mission's network policy **and** in the target scope, the proxy, after the
connection is allowed and before forwarding upstream:
- merges each matching `cookie` item into the request's `Cookie` header **without overwriting a cookie
  the request already sets** by that name (the request wins);
- sets each matching `header` item **only if the request does not already send that header** (the
  request wins).
A request to any other host is forwarded untouched. An opaque CONNECT tunnel (a mission without interception,
or a host on a passthrough list) carries nothing: the proxy never sees its requests, so a command's HTTPS
reaches the target with profile items only in an intercepting mission (the in-process tools inject themselves
either way, S8). The agent names the profile; it never reads the values, and no tool, record, prompt or UI
shows them (S5).

S4. **Encryption at rest, unattended.** A daemon key at `~/.ferret/keys/creds.key` (32 random bytes,
file `0600`, created on first need exactly like the access token and journal key; dir `0700`). Each
profile file is `v1 || 12-byte nonce || ciphertext || tag` under `ring::aead` `CHACHA20_POLY1305`,
with AAD = `"{target}/{profile}"` so a file cannot be moved or renamed between profiles or targets
without failing to open. The key lives under `~/.ferret` (never readable in the sandbox, like the CA key
and token), so the daemon decrypts profiles at start with no passphrase and an unattended run keeps
working. This protects a reader of the targets directory, not someone who already holds `~/.ferret`
(the same trust boundary the access token and CA key already sit behind). No new dependency: `ring` is
in the lockfile (I5); it becomes a direct dependency of the crate that owns `creds.rs`.

S5. **Secrets.** On a mission start with a profile, the session's secret set
(`ferret_core::creds::Secrets`, held in `SessionTools::secrets`) gets every injected item value of at least
`Secrets::MIN_LEN` (8) bytes, and for a header value of the form `<scheme> <token>` the token as well. The set
replaces each with `[redacted]` in every tool result's text and in every output a tool stores
(`ferret_tools::finalize`), and in the request and response blobs of every exchange the session records
(`Traffic::ingest`, and the exchanges in-process tools hand back). Independently of length, the request a
capture stores is the **redacted copy**: the proxy (S3) and in-process tools (S8) record the request with each
value ferret itself added replaced by `[redacted]`, and send the real one. `net.jsonl` records no header or body,
so it never holds a value. A `Set-Cookie` the mission observes on its own is still stored as evidence and
masked-until-revealed per C5; only values ferret injected are redacted outright. The proxy-credential rule (C5)
is unchanged. The prompt is built from tool results, so it never holds a value either.

S6. **Scope safety (the invariant).** The effective attach set is computed at load as, per item, its
single `host` kept only if that host is inside the mission target's current scope (T1) and not in
`exclude`; items failing this are dropped with a start-note count, never injected. The proxy decides
injection on the **destination host of each forwarded request**, re-checked for every request on a
kept-alive connection and for every request a client makes after following a 3xx, so a redirect or a
link to an out-of-scope host carries nothing. A captured `acme.test` login is therefore only ever
attached to in-scope `acme.test` hosts and never to an attacker-controlled host, even one reached in
the same session. If a target's scope is later narrowed so a profile host falls outside it, that
item stops being injected (checked at each mission start, not cached).

S7. **CLI/API.** `ferret creds list --target acme` (profiles with item counts and when recorded),
`ferret creds show --target acme --profile default` (item kinds, names and hosts, recorded-at — never
values), `ferret creds record|set|rm`. `POST /api/targets/{name}/creds` (record session handle / set
items), `GET /api/targets/{name}/creds` (`[ProfileSummary]`, no values), `GET
/api/targets/{name}/creds/{profile}` (`{summary: ProfileSummary, items: [ItemView]}`), `DELETE
/api/targets/{name}/creds/{profile}` (`204`; `404` when there was none). Setting items over the API:
`POST /api/targets/{name}/creds` with `{"set":{"profile":"default","items":[{kind,name,value,host}]}}` →
`ProfileSummary`; a host outside the scope is a `409` with the sentence. Every creds route is the
operator's (the access token), never reachable from a session's proxy credential. The new-mission form's Target select gains a Credentials select
listing the chosen target's profiles.

S8. **In-process tools.** `http_send` and `web_fetch` (except requests on the reference path) apply S3 to
each request they send themselves, with the session's items (`SessionTools::creds`), the same host equality
and the same request-wins merging (`ferret_net::inject::apply`), and record the redacted copy as the exchange's
request. A cookie the tool's own jar holds for that host counts as one the request already sends. MCP servers
over HTTP are never given profile items (they carry their own configured auth).

S9. **The in-process proxy credential.** Every session grant also carries a second credential for in-process
clients (`SessionGrant::tool_url`), with the same session, listener and policy. A request made with it is never
intercepted, captured or injected by the proxy: the in-process tools record their own exchanges (`tls:
"tool"`) and inject themselves (S8). So in an intercepting mission `http_send`, `web_fetch` and MCP over HTTPS
keep verifying the real server certificate with their own roots instead of meeting the ferret CA, which their
client does not trust. Commands never get it (it is not in `env()`). `ferret_tools::web::session_proxy` returns
`SessionTools::tool_proxy` when the runtime set it, else the command proxy from `ToolCtx::env` (tests and
callers without a runtime).

S12. **In-process TLS to the target** (found in the live test: a self-signed in-scope host was reachable by
`curl` through the intercepting proxy but never by `http_send`). The runtime sets `SessionTools::upstream_insecure`
to the mission target's `upstream_insecure` (T1; the lead's `TargetRef`, so every agent of the mission has it)
for every session with a target; MCP sessions never get it. `http_send`, `http_repeat`, `web_fetch` and the
oracle decide per request, on the request URL's host and port (`port_or_known_default`), with the same matcher
the proxy uses (`ferret_net::host_listed`, the former `intercept::listed`): a listed `https` request is sent by a
client that does not verify the server certificate, and its recorded exchange has `upstream_unverified: true`;
every other request (another host, a redirect hop to another host, the reference path, `cve`/`dep_scan` lookups,
MCP) keeps full verification. A redirect is decided again on each hop's own URL.

S13. **Transport errors name their cause.** When an in-process client fails before a response (connect, TLS, a
proxy refusal, a timeout), the error text the tool returns and records is reqwest's message followed by each
`std::error::Error::source()` in the chain, `: `-joined, skipping a source whose text the line already holds
(so a certificate failure reads `error sending request for url (https://h:p/x): … invalid peer certificate:
UnknownIssuer`, not the top line alone). For a certificate failure on a host that is in the mission target's
scope but not on its `upstream_insecure` list it adds one sentence: `The server's certificate did not verify;
the operator can list {host} in the target's upstream_insecure if it is a lab host with a self-signed
certificate.`

S10. **Summary line** (`creds::summary_line`): `{profile} · {n} cookie(s), {m} header(s) · {hosts}`, the
counts of the effective set, a count of 0 left out (`default · 2 cookies · acme.test`), hosts sorted and
comma-separated, at most 3 then `and {k} more`; when S6 dropped items it ends with ` · {d} out of scope, not
attached`.


S11. **Runtime.** `NewSession::creds` names the profile; it is refused (one sentence, nothing created) without
`target`, for an invalid or unknown profile name, or for a profile that does not open. The lead's
`SessionMeta::creds` and its `session_start` carry `CredsRef { profile, summary, dropped }` (S10 line, S6
count); every agent of the mission inherits the same `CredsRef`. The items live only in memory: a per-mission
entry of the runtime holds `Arc<Inject>` and `Arc<Secrets>`, filled on first need by reading the profile
through `CredsStore` and applying S6 with the scope recorded in the lead's `TargetRef` (T2), and shared by
every session of the mission (lead, agents, the finish gate's verifier); it is dropped when the mission's
last session closes. Each session with `creds` gets, right after its grant: `Proxy::set_inject`, and
`SessionTools::creds`, `SessionTools::secrets`, `Traffic::secrets`; every session gets
`SessionTools::tool_proxy` = `SessionGrant::tool_url()` (S9). A session restored after a restart fills the
entry the same way; a profile that is gone or no longer opens leaves the mission without items (a
`tracing::warn`, the restore goes on). The lead's network section of the system prompt (`network_with_target`)
gains one line when `creds` is set. In an intercepting mission: `Credential profile {summary line} is attached
to your requests to those hosts (commands through the proxy, http_send, web_fetch); you never see its values,
and a cookie or header your request sends itself overrides it.` Without interception the parenthesis is
`(http_send, web_fetch, and plain-HTTP requests from commands; a command's HTTPS goes through an opaque tunnel
and carries nothing)`. A secret value never reaches `meta.json`, a record, the prompt or an API
answer.

S11a. **Several profiles (main's Wave B, with the monitor in ef34aa4).** `NewSession::creds_profiles` mounts more
profiles than the default one; `SessionMeta::creds_profiles` and `session_start.creds_profiles` carry their `CredsRef`s
(names and S10 lines only), every agent inherits them, and one union redactor (`Secrets::union`) covers every mounted
profile's values. The monitor reads the lead's start record and lists the profiles in its AUTHORIZATION block
(`docs/MONITOR.md` §2.4, `Authorization::credentials`, `{profile} ({summary})`): acting as each one is the operator's
choice; a profile authorizes no host, and its values never reach the monitor either.
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

U5. **Credential profiles.** The target page gets a Credentials panel: one row per profile from `GET
/api/targets/{name}/creds` (`{profile} · {n} cookies, {m} headers · {hosts} · recorded {age}`), a Show that
lists item kind, name and host (never a value: the API sends none), a Delete with a confirm, and the two ways
to add one as copyable commands (`ferret creds record --target {name}`, `ferret creds set --target {name} --host …
--cookie '…'`); the UI never takes a secret value itself. The new-mission form shows a Credentials select
under Target once a target with profiles is chosen (default "none"), sent as `creds`. A mission whose
`session_start` has `creds` shows a `creds default` chip beside the target chip with the summary as its
title, and the Session tab shows the summary line.

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
  existing `~/.ferret` read test); keep-alive with two requests gives two exchanges.
- **F:** finish refused when a supported claim names a host no evidence reached, accepted when an
  `http_send` evidence reached it, accepted for a claim naming only a `File` asset, not gated for a
  role without `require_traffic`; the refusal text names only shown tools.
- **T:** scope parsing (globs, CIDR, exclude wins); a mission with a target can reach scope hosts in
  `deny_all` mode and cannot reach excluded ones; graph writes from an exchange, an `asset_upsert`, a
  `coverage_set` and a supported claim; out-of-scope never written; status derivation (T6) and the
  `view: "target"` query; two missions of a target see each other's coverage at start; the summary
  is recorded and stable across a reopen; the hash chain of `graph.jsonl`.
- **S:** recording keeps only in-scope items (an out-of-scope host seen during record is dropped, and its
  tunnel is not intercepted); `Set-Cookie` overrides an earlier request cookie and `Max-Age=0` removes it; an
  in-scope `cookie` item is merged into a forwarded request (plain and intercepted) and the same session's
  request to an out-of-scope host is untouched; an item never overrides a cookie or header the request already
  sends; the captured request holds `[redacted]` where ferret injected and the upstream received the real value;
  a response echoing an injected value is `[redacted]` in the stored exchange and in the tool result; a
  profile file round-trips through seal/open, fails to open with the wrong AAD (swapped between profiles or
  targets) or another key; the key file is 0600 in a 0700 dir; narrowing the target scope drops the
  now-out-of-scope item at the next mission start and the summary says so; `ferret creds show` and every API
  answer never hold a value (`Item`'s `Debug` neither); a mission started with `creds` records `CredsRef` (no value anywhere in its session directory) and an agent it starts attaches the same items; `creds` without `target` is refused; the tool credential is never intercepted (an
  `http_send` to an https test server works in an intercepting session) and never in a command's env;
  `http_send` injects for a matching host and records the redacted copy; with the target listing `127.0.0.1`
  in `upstream_insecure`, `http_send` and `web_fetch` reach a self-signed https test server, record
  `upstream_unverified: true` and still inject the profile, a self-signed server not listed fails with the
  certificate cause in the error text (S13), and a redirect from a listed host to an unlisted self-signed one
  fails verification on the second hop.
- **U:** pure models (exchange list, header masking, target tree with statuses, filters) in
  `ui/core.test.js`; fixture routes for all of T7 and exchanges.
