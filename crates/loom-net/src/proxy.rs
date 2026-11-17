//! The proxy server.
//!
//! CONTRACT.
//!
//! `Proxy::start(port, sink)` binds the shared listener `127.0.0.1:{port}` (0 = any free port; `port()`
//! is the port bound) and serves until `shutdown` or drop; each session's grant adds a listener of its
//! own (see *Sessions*). Every listener speaks HTTP/1.1 proxying only:
//! - `CONNECT host:port` → on success `HTTP/1.1 200 Connection established\r\n\r\n`, then bytes are
//!   copied both ways until either side closes;
//! - a request with an absolute `http://` URI → the proxy connects to that host (port 80 by
//!   default), sends the request with an origin-form target, drops `Proxy-Authorization` and
//!   `Proxy-Connection`, adds `Connection: close`, and copies the request body and the response
//!   through, one request and one response per client connection (see *Forwarded requests*);
//! - a check, method [`CHECK_METHOD`] with the destination as `host:port` or as an absolute
//!   `http://host:port/` URI (see *Checks*);
//! - anything else (origin-form target, `https://` absolute URI, unparseable head, a head larger than
//!   64 KiB, no head within the head timeout of [`Limits`]) → `400` with a sentence.
//!
//! ## Checks
//! A check asks for the policy's verdict on a destination without using it: the proxy applies the
//! policy to the name, resolves it and checks the addresses as for a connection, but connects to
//! nothing. It answers `200` (allowed), `403` (refused, with the refusal text) or `502` (the name does
//! not resolve), with the rule in header [`RULE_HEADER`], and records the decision with method
//! `LOOM-CHECK` and the rule suffixed ` (check only)`. Tools ask it before an https request, because an
//! HTTP client does not show what the proxy answered to its CONNECT.
//!
//! ## Sessions
//! `grant(session, policy) -> Result<SessionGrant, ProxyError>` returns fresh random credentials (user =
//! the session id, password = 32 hex chars) and the port of the session's own listener. The first grant
//! of a session binds that listener on `127.0.0.1:0` (a failure is `ProxyError::Bind`, and nothing is
//! granted); a later grant of the same session keeps its listener and port and replaces the password, so
//! the old one gets `407`. It must be called inside a Tokio runtime. A command's environment names only
//! its own session's port, and the sandbox lets the command connect to that port and no other of the
//! proxy's, so credentials a command reads from another process (another session's command, through
//! the environment it was started with) are of no use to it, and the proxy will not open a tunnel to
//! one of its own listeners for it either (below): **command credentials are accepted only on
//! their session's listener, and reference credentials only on the shared listener.** Credentials that
//! arrive on another listener are refused as unknown ones are (`407`), with the decision rule
//! `proxy authentication failed: credentials of session {owner} on the port of session {listener}`
//! (or `… on the shared port`, `reference credentials on the port of session {listener}`), recorded for
//! the listener's session (the session whose sandbox may connect there) or, on the shared listener,
//! unattributed. The check is by the listener a connection was accepted on, before anything else of the
//! request is acted on. The client authenticates with `Proxy-Authorization: Basic`.
//! Missing or unknown credentials → `407` with `Proxy-Authenticate: Basic realm="loom"`.
//! `grant_reference(session, cfg)` returns a separate `ReferenceGrant` (URL and host matcher, no env) on the
//! shared listener. Its random credential is kept only in trusted in-process tools, with GET/check/CONNECT permitted.
//! Plain HTTP strips Authorization, Cookie and Referer. HTTPS CONNECT is opaque: the trusted client
//! enforces GET, no URL user-info, no credential headers and redirect policy at every hop. Neither a
//! host reservation nor GET-only access prevents exfiltration in URL paths/queries.
//! `session_port(session) -> Option<u16>`: the port of the session's own listener while it holds a
//! command grant.
//! `revoke(session)` drops both command and reference grants; connections already open are left to finish.
//! The session's listener is closed, and `session_port` gives `None`; its port is **retired**: kept, as a
//! number only, among the proxy's own ports for the proxy's life. A listener for a session is opened with
//! `tokio::net::TcpSocket`: bind `127.0.0.1:0`, read the port, and if it is retired (or otherwise one of
//! the proxy's own ports) keep that socket aside and bind again, up to 64 times, else
//! `ProxyError::Bind` saying that no fresh loopback port was found and that a daemon restart frees the
//! retired ones; the sockets set aside are dropped once a fresh port is found. So no later session of this
//! proxy's life is given a port that an earlier session's sandbox allows (a process that left its
//! command's process group outlives its session and keeps its profile), and a revoked session holds no
//! descriptor. The fresh port is added to the own ports **before** `listen`. A later grant of a session
//! whose listener was closed opens a new one (on a fresh port; its new sandbox names it).
//!
//! **The proxy never connects to itself.** A destination address that is loopback (`127.0.0.0/8`, `::1`,
//! and IPv6 forms carrying a `127.x` address) or unspecified (`0.0.0.0/8`, `::`, and such forms) with a
//! port of one of the proxy's listeners (the shared one and every session's, open or retired) is refused
//! whatever the policy says, before `check_addr`, for a tunnel, a forwarded request and a check alike,
//! with rule `deny the egress proxy's own port {port}`. A connection that succeeds is checked again
//! against the own ports before anything is recorded as allowed or sent (a listener opened between the
//! first check and the connect is in the set by then, since its port is added before it listens); a hit
//! closes it and refuses it the same way. Otherwise a session whose policy reaches
//! loopback (`allow_private`, a granted `127.0.0.1:{port}`) could open a tunnel to another session's
//! listener and present that session's credentials there, through the proxy, which would accept them.
//! `set_policy(session, policy)` replaces the policy of a session that holds a grant and keeps its
//! credentials, so commands already running pick the change up on their next connection. It does not touch the
//! session's reference grant, which has a policy of its own. `hold(session, policy)` is the replacement for a hold:
//! it sets the policy of **both** the command grant and the reference grant (so that an in-process GET that follows
//! redirects cannot open a new reference connection after the cut), and the reference entry keeps it until
//! `grant_reference` mints it again or the session is revoked.
//! `cut_hosts(session, pattern) -> usize` ends the session's open tunnels and forwarded requests whose
//! destination the grant pattern covers (`policy::pattern_covers`; a port in the pattern must match), and
//! a connection accepted but not yet connected is refused when it would open (it is registered before the
//! destination is opened, and the policy it is judged by is read after it is registered, from the
//! session's current entry, not from the one taken when it authenticated: a `set_policy` that ran in
//! between is seen; a forwarded request whose destination was cut while its name resolved or its connection
//! opened is not written to it, the client gets `502` and the record says why). Each ended connection that was on record as allowed gets the second decision
//! with the reason "the operator revoked the destination". It is what the operator's `loom scope revoke`
//! calls after `set_policy`; the other sessions' connections to the same destination are not touched.
//! `cut(session) -> usize` and `cut_sessions(sessions) -> usize` (E4a, `docs/MONITOR.md` §2.2) end every open
//! tunnel and forwarded request of the session or sessions whatever the destination, **reference grants'
//! connections included** (they are the session's: a connection is registered under the session id of its
//! credentials, command or reference). The proxy does not know missions: the runtime's `cut_mission` lists the
//! sessions of a mission. The bytes of an open tunnel stop within milliseconds (the relay is dropped, so both
//! sockets close); each ended connection that was on record as allowed gets the second decision with the fixed
//! reason "the session's connections were closed by loom" (never anything the monitor decided or wrote). A
//! connection that authenticated before the call and is registered after it is ended when it registers (each
//! cut bumps a counter and marks its sessions with it; a connection remembers the counter at its
//! authentication), and one that is only resolving or connecting is ended when it has opened its destination,
//! before the `200` and before any byte upstream (a connect that hangs is bounded by its 10 s timeout and
//! carries no bytes). It does not touch the policy, the credentials or the listener: the caller sets a hold
//! with `set_policy` first so that nothing new opens. It returns how many were ended; `0` for a session with
//! nothing open.
//!
//! ## Veto (E4b)
//! `set_veto(Some(f))` installs a synchronous, in-process veto, `f(session, &Dest) -> Option<rule>`, with
//! `Dest { host, port, method, resolved, sni }`. It is asked for every connection the name policy allowed, for a
//! `CONNECT`, a forwarded request and a check alike: (1) at the name stage, before any lookup (`resolved` and
//! `sni` are `None`), so a canary host is never resolved; (2) for each address the policy allowed, before the
//! connect (`resolved` is the address), so nothing is opened toward a vetoed address (a check asks it for the
//! address it would use, the first the policy allows, and answers and records a veto of it as for a connect); (3) for the server name of a
//! tunnel's ClientHello when it differs from the destination (`sni`, see *Server names*). `Some(rule)` ends the
//! request: `502` with `X-Loom-Proxy: 1` and a fixed sentence that says the destination is closed to the mission
//! by loom's own rules, that nothing was opened or sent, that it must not be retried and that `report_blocker`
//! with class `needs_approval` is the way out; the rule is **not** in the body. The decision is recorded as
//! refused (`allowed: false`) with the rule `vetoed: {rule}` (cut to 200 characters; ` (check only)` is added for
//! a check) and the resolved address when there is one. The rule is a class word chosen by the hook and is
//! readable by the agent (it is in the net record): the monitor's veto uses fixed class words and never a
//! reviewer's or a tripwire's text. The hook runs on the proxy's tasks and must not block; the decision that
//! a refusal is recorded is the proxy's, the hook's own events are its own. This is the design's "synchronous
//! veto in the audit hook", as a separate hook because the monitor is built after the proxy and the audit hook
//! is fixed at start; it also runs before the connect, not only before the `200`. `set_veto(None)` removes it.
//!
//! ## Observing refusals
//! `set_refusal_observer(Some(f))` installs `f(session, &Dest)`, told of each request whose destination name the
//! session's policy refused (`CONNECT`, forwarded request and check alike; `resolved` and `sni` are `None`) and of a
//! tunnel whose ClientHello server name the policy refused or whose encrypted-ClientHello extension names another
//! host (`sni` is that name). It only observes: the answer, the record and the refusal are the policy's own. The
//! veto is asked only of what the policy allowed, and the default modes (`deny_all`, an allowlist) refuse most
//! names before it, so this is how the daemon sees a decoy host named in a mission whose policy does not allow it
//! (CN-4). It runs on the proxy's own tasks and must not block. `set_refusal_observer(None)` removes it.
//!
//! ## Server names (E4c)
//! After the `200` of a `CONNECT` and before one byte goes upstream, the proxy reads the client's first flight
//! (the bytes that came with the head, then more) and looks at it with `clienthello::parse`:
//! - not TLS (the stream does not start like a TLS record: a first byte outside `0x14..=0x17`, or a second byte of
//!   `0x10` or more, which a Go `crypto/tls` server also treats as not TLS): passed unchanged, nothing to bind
//!   (an SSH or SMTP banner, plain HTTP, STARTTLS before its upgrade); a server that speaks before the client
//!   does ends the wait the same way. A stream that **does** start like a TLS record but whose first record is not a
//!   handshake record of version `3.x` (a warning alert, a change-cipher-spec, application data, a record header
//!   with version `0.0` or `1.0`) is refused as a hello that cannot be read: servers (Go, BoringSSL, rustls) skip a
//!   leading alert or accept such a version and read the hello behind it, so passing it would let the name be
//!   hidden;
//! - a ClientHello whose server name is the destination (compared in the policy's normal form) passes, with
//!   no extra record; an IP-literal destination with no name passes;
//! - another name passes only when the session's current policy allows it (`check_name`, which applies deny
//!   rules in every mode and the allowlist in allowlist mode) and the veto lets it through; the decision
//!   that follows the allow is recorded as allowed with `sni` set and the rule `{rule} (sni {name}, another
//!   name the policy allows)`;
//! - a ClientHello with an encrypted-ClientHello extension whose outer server name **is** the destination passes as
//!   an ordinary one: Chromium (Playwright, Puppeteer, curl-impersonate and the like) sends a placeholder (GREASE)
//!   extension, type `0xfe0d`, with the real name in the clear on every hello, and the proxy cannot tell it from a
//!   real one. The residual is a real ECH hello to an ECH-capable granted front whose public name is the
//!   destination: its inner name is hidden (`docs/MONITOR.md` X4);
//! - refused (nothing sent upstream, the tunnel closed, one more decision recorded as refused with the rule and
//!   `sni` when there was one): an encrypted-ClientHello extension with another outer name or none (`deny an
//!   encrypted ClientHello whose outer server name is not the destination: the server name is hidden from the
//!   proxy (browsers send a placeholder extension with the destination's own name, which passes)`), a ClientHello that cannot be read or is larger than 64 KiB, one that does not
//!   arrive in full within the head timeout, no server name to a destination that is a name, a name the policy
//!   denies, a name the veto closes.
//!
//! Only the first flight is judged: a second ClientHello later in the stream (a renegotiation, a hello retry) and
//! a tunnel that upgrades to TLS after a plaintext start are not (`docs/MONITOR.md` X4); Host-header fronting
//! inside a session whose name matches is not stopped either. A tunnel that sends nothing and hears nothing is
//! closed at the idle limit, as before, with the same record.
//!
//! ## Canary users (E4d)
//! `add_canary_user(user, label)` registers a decoy user in the session table; `remove_canary_user(user)` takes it
//! out; `set_canary_hook(Some(f))` installs `f(&CanaryHit)`. A request that presents a registered user as its
//! Basic user, with any password, on any listener, is a canary event: the hook runs (on a blocking thread, and
//! has returned before the answer is written, so the event exists before any byte flows), then the attempt is
//! recorded **uncapped** (the limit on unattributed answers does not apply) and attributed to the session whose
//! listener received it (`CanaryHit::listener`; unattributed on the shared listener), with the rule and the
//! answer of any unknown user (`proxy authentication failed: unknown user`, `407`, the same bytes): nothing a
//! client can read says the user was a decoy. A decoy user never authenticates, whatever its password, and no
//! connection is opened. `add_canary_user` refuses (with a sentence) an empty name, one over 128 bytes and the
//! user of a session's grant; reference grants have random `reference-…` names no canary should take.
//!
//! ## Listeners (E4e)
//! `set_listener_check(Some(f))` installs `f(session, addr, client) -> Option<rule>`, run on a blocking thread for
//! each connection that reached an address of this machine (a loopback or unspecified address, or one of its own
//! interface addresses given by `set_local_addrs`; never one of the proxy's own ports) **after** the connect and
//! before anything is recorded or sent. `addr` is the address connected to (with the destination port) and `client`
//! the local end of the connection the proxy opened: the process that holds the other end is the one the bytes
//! reach, which the check finds by the accepted socket (so a squatter that closes its listening socket as it
//! accepts is still found) and, failing that, by the listeners that cover `addr`. `Some(rule)` refuses the
//! connection like any policy refusal (`403`, the rule in the body and the record, the connection closed, the next
//! address tried) so a lab port squatted by a sandboxed process of another mission is never used. The runtime's
//! check is `loom_tools::sandbox::census::listener_of` (TW-05): a holder attributed to a loom sandbox is refused
//! unless it belongs to the connector's own mission; the operator's own services, a connection nobody holds and an
//! unreadable table pass. The scans of the process table that run at once are bounded (4): the others wait their
//! turn, so a swarm of loopback connections cannot starve the proxy's other work.
//! `SessionGrant::env()` gives the variables to place in a command's environment so that ordinary
//! clients use the proxy: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lower-case forms, all
//! `http://{user}:{password}@127.0.0.1:{port}` with the session's own port, plus `NO_PROXY`/`no_proxy` = ``
//! (empty, so loopback labs also pass policy unless the sandbox opens their ports directly).
//! `shutdown` and `stop` close every listener. The limits below are of the proxy as a whole, across
//! listeners, as before.
//!
//! ## Deciding and connecting
//! For each request: `policy.check_name` → if allowed, resolve the name (`tokio::net::lookup_host`;
//! an IP literal resolves to itself), then walk the resolved addresses in order and connect to the
//! first one that `policy.check_addr` allows (10 s connect timeout each). The connection is made to
//! that checked address, never by name, so a second lookup cannot change the destination. If every
//! address is refused the decision is the first refusal.
//! Every request produces exactly one `NetDecision` (and a second one when it fails after an allow,
//! see below, or, for a tunnel, when its ClientHello names another allowed name or is refused, see *Server
//! names*) sent to `sink` together with the session id:
//! `host`, `port`, `method` (`CONNECT` or the request method), `allowed`, `rule`, `resolved` (the
//! address connected to, or the refused address, when there is one). Resolution or connect failures
//! after an allow are reported as allowed with the rule suffixed ` (unreachable: {why})`.
//! A connection on record as allowed that then fails gets a second decision: the same destination,
//! address and rule, allowed, with the rule suffixed ` (failed after the allow: {why})`. For a tunnel
//! that is when its client is gone before the `200`, the bytes it sent ahead cannot be written, it
//! ends (closed, failed on either side, or idle) before the destination sent a byte, or the proxy shuts
//! down while it is open (reason "the egress proxy shut down"); once bytes have come from the
//! destination the proxy cannot tell a cut-off encrypted stream from a routine close, so the tunnel is
//! not judged further otherwise. For a forwarded request it is when the request cannot be written,
//! the destination answers nothing usable or stalls, the relay fails on either side, or the proxy shuts
//! down during the relay.
//! Refusals answer `403` with header `X-Loom-Proxy: 1` and a plain-text body that states the
//! destination, the rule, and that the network policy is set by the operator in the loom config
//! (`[network]`) — a command cannot change it. Unreachable destinations answer `502` with
//! `X-Loom-Proxy: 1` and the reason. Proxy-generated responses always carry `X-Loom-Proxy: 1` and
//! `Connection: close`.
//!
//! The proxy never logs or stores request or response bodies. It must not panic on any input; a
//! failing connection affects only itself. `Proxy` is cheap to clone (shared state inside).
//!
//! Tests required (all on loopback with local listeners; grant policies with
//! `allow_private = ["127.0.0.1"]` where a test needs to reach its own listener): CONNECT tunnel
//! echoes bytes both ways; plain HTTP forward rewrites the target, strips proxy headers, relays the
//! body and the response; 407 without / with wrong credentials; credentials of a revoked session;
//! deny rule → 403 + header + one refused decision; open mode to loopback without allow_private →
//! refused as private-address with `resolved` set; allowlist miss; unreachable port → 502 and an
//! allowed decision with the suffix; exactly one decision per request and the right session id on
//! each when two sessions use the proxy at once; malformed heads → 400 and the server keeps serving;
//! oversized head; `env()` contents; shutdown stops accepting. Listeners: two sessions' grants have
//! different ports, neither the shared one; session B's valid credentials on A's port → `407`, nothing
//! connected, one refused decision recorded for A naming B; A's credentials on the shared port → `407`
//! (unattributed); a reference grant works on the shared port and is refused on a session's port; a second
//! grant of A keeps the port and the first password gets `407`; after `revoke(A)` a connect to A's port
//! fails, `session_port(A)` is `None`, the grants of 20 new sessions never get A's port, a grant of A again
//! gets a port that is not the old one, and a proxy test with the retired check forced to hit every time
//! gets `ProxyError::Bind` with the sentence and leaves no socket bound; `shutdown` closes the session
//! listeners too. A connect to a retired port through the proxy is refused with the own-port rule. The foreign-credentials test asserts
//! that the destination listener accepted nothing. Own ports: with a policy that allows `127.0.0.1`
//! (`allow_private`) in open mode, a `CONNECT`, a forwarded `GET http://127.0.0.1:{port}/` and a check to
//! another session's port, to the session's own port and to the shared port are each refused (`403`, rule
//! `deny the egress proxy's own port {port}`), also written as `[::ffff:127.0.0.1]:{port}` and
//! `0.0.0.0:{port}`, while another loopback port is still allowed. `cut_hosts`: a pattern that covers
//! nothing, or only another port, cuts nothing; one that covers a tunnel closes it (bytes stop) and leaves
//! the same session's tunnel to another destination and another session's tunnel to the same one; the
//! second decision names the reason. `cut`: every connection of the session ends within a second and the bytes
//! stop, a reference grant's tunnel with them, another session's tunnel stays, each ended one is on record
//! with the fixed reason, `cut_sessions` ends several sessions' connections, a connection that authenticated
//! before a cut and registers after it is ended while one that authenticated after is not, a hold followed by a
//! cut leaves nothing open and nothing new, the proxy still serves the session afterwards. Veto: a vetoed name is
//! not looked up and nothing connects to it (`502`, marker, fixed body without the rule, one refused record with
//! `vetoed: …`), a check of it is answered the same way, a vetoed address stops the connect, the hook is asked at
//! the name stage and again with the address, removing it opens the name. Server names: the destination's own
//! name passes and the hello arrives whole, another allowed name passes and is recorded with `sni`, a denied name
//! is refused with nothing received upstream, an encrypted hello, an unreadable one and a missing name are
//! refused, an IP destination takes no name but not a denied one, a hello sent in pieces is read whole, plain
//! HTTP and a server's banner pass, a stalled hello is refused after the head timeout. Canaries: the hook has
//! run when the answer arrives, the answer equals an unknown user's byte for byte, the record is attributed to
//! the listener's session and says nothing of a decoy, a run of them on the shared listener is never capped, a
//! removed decoy is an unknown user. Listeners: a refusal names the rule in the `403` and the record, another
//! loopback port passes, a forwarded request is checked too, the check is given the local end of the connection, and
//! this machine's own addresses are told apart from others. Hold: a hold sets the reference grant's policy too, so
//! after a cut a reference connection is refused. Observer: a canary name refused by an allowlist, as a `CONNECT`, a
//! check and a tunnel's server name, is seen by the observer. Veto: a check asks it for the resolved address. Server
//! names: a placeholder encrypted hello naming the destination passes and one naming another host does not, an alert
//! or a record of version `0.0` in front of a hello naming a denied name is refused with nothing sent upstream.
//! `clienthello` has its own list.
//!
//! ## Audit
//! `start_with` takes an audit hook ([`AuditFn`]), called on a blocking thread with the session (or
//! `None`) and the decision. For an allowed connection it runs after the name lookup and the TCP
//! connect to the checked address, and before any byte is sent either way: the `200` of a CONNECT and
//! the forwarded request wait for it. When it fails the client gets `502` (with the marker) saying
//! that the egress audit log could not be written, and the connection is closed. So the DNS query and
//! the TCP handshake to an allowed destination leave the host before the record exists, and a lookup
//! that fails is recorded best effort only.
//! Refusals, unreachable destinations and the answers the proxy gives itself (`400`, `407`, `429`,
//! `503`) are recorded best effort: a failure is logged. Answers that cannot be tied to a granted
//! session by its credentials (no or wrong credentials, a head that cannot be read or does not arrive,
//! the limit of all sessions) go to the hook with `None`, at most 10 a minute; the next one recorded
//! says how many were left out. The records of these answers carry the destination only when the
//! request names a valid one (else host `-`, port 0); their texts are cut, with `…` marking the cut.
//! With a hook, `sink` receives only the decisions of requests that reached the policy and that the
//! hook failed to record, so a consumer that shows what the hook recorded and what the sink sends sees
//! each decision once.
//!
//! ## Limits ([`Limits`], defaults)
//! - 256 connections in all. A connection that has not sent a complete head within 10 s gets `400`.
//!   At the limit a new connection takes the slot of the oldest connection that is only being
//!   answered by the proxy itself and drained, or, when there is none, of the oldest connection that
//!   has not sent a complete head yet (that one is closed); when there is neither it is answered `503`
//!   with `Retry-After: 5`.
//! - 64 connections per session; over it `429` with `Retry-After: 5`.
//! - 16 name lookups at once, at most 4 of them for one session; a lookup waits up to 10 s for a turn.
//! - The two directions of a tunnel or forwarded request are relayed independently. With no byte
//!   moving in either direction for 10 minutes the connection is closed; a forwarded request that has
//!   sent nothing back yet gets `504` first. A tunnel passes a half close on to the other side.
//! - A forwarded request whose client ends its side (closes, or only shuts down its writing half) is
//!   not read any more but still gets the response while the destination keeps sending: it ends when
//!   the destination is silent for 30 s, or at once when a write to the client fails.
//!
//! ## Forwarded requests
//! The request body is forwarded up to its end as its head frames it: `Content-Length` bytes, or a
//! `chunked` body up to its last chunk and trailers (a body with another transfer coding, or a chunked
//! body the proxy cannot follow, runs until the client stops sending). What the client sends after it
//! is not forwarded.
//! A plain-HTTP response head from the destination is parsed as an HTTP client parses it (a bare LF
//! ends a line too) and written to the client again with CRLF line ends and without any
//! `X-Loom-Proxy` header; only responses the proxy generates carry that marker. The final (non-1xx)
//! head also loses the destination's `Connection`, `Keep-Alive` and `Proxy-Connection` headers, and its
//! `Content-Length` when it has a `Transfer-Encoding`, and ends in `Connection: close`. A head that does
//! not parse, or whose `Content-Length` values are not numbers or differ, gets `502`.
//! The response ends where its head says, read as hyper reads it: at the head for a `HEAD` request and
//! for `204` and `304`; after the last chunk and the trailers when the last coding of the last
//! `Transfer-Encoding` is `chunked`; after `Content-Length` bytes; otherwise (and for `101`) when the
//! destination closes. At that end the proxy closes the connection and relays nothing more, so bytes
//! a destination sends after its response never reach the client. A chunked body that breaks the
//! chunked format ends the relay where it breaks.
//! When the client sends anything after its request other than empty lines, a response that runs
//! until the destination closes is cut: the relay ends with the bytes that carried its head, or at once
//! when they have already been relayed.

use crate::clienthello::{self, Hello};
use crate::policy::{is_local_literal, normalize_host, Policy, Verdict};
use base64::Engine as _;
use loom_core::event::NetDecision;
use loom_core::SessionId;
use rand::RngExt;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

const MAX_HEAD: usize = 64 * 1024;
const MAX_HEADERS: usize = 100;
/// Headers of a destination's response head that are read; a head with more gets `502`.
const MAX_RESPONSE_HEADERS: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Addresses of one name that are examined; a name with more is cut here.
const MAX_ADDRS: usize = 32;
/// Lab-listener scans (of the process table) that run at once; the others wait for a turn.
const MAX_SCANS: usize = 4;
/// Tasks that answer connections over the limit of all sessions with a `503` the client can read.
const REFUSALS: usize = 16;
/// Records a minute of answers that name no granted session.
const UNATTRIBUTED_PER_MINUTE: u32 = 10;
/// Bytes past its body that the client of a forwarded request may send before the request is dropped.
const MAX_DISCARD: usize = 1024 * 1024;
/// The header that marks a response the proxy generated itself.
const MARKER: &str = "x-loom-proxy";
/// The method of a check (see *Checks*).
pub const CHECK_METHOD: &str = "LOOM-CHECK";
/// The header of a check's answer that carries the rule.
pub const RULE_HEADER: &str = "X-Loom-Rule";

/// The audit hook: called with the session (`None` for an answer that names no granted session) and
/// the decision, it must have recorded the decision durably when it returns `Ok`. It may block (it
/// runs on a blocking thread). For an allowed connection the proxy calls it before the upstream socket
/// is used and refuses the connection (502) when it fails.
pub type AuditFn = Arc<dyn Fn(Option<&SessionId>, &NetDecision) -> std::io::Result<()> + Send + Sync>;

/// A destination as the veto and the listener check see it.
#[derive(Clone, Copy, Debug)]
pub struct Dest<'a> {
    pub host: &'a str,
    pub port: u16,
    /// `CONNECT`, `LOOM-CHECK` or the HTTP method of a plain request.
    pub method: &'a str,
    /// The address about to be connected to; `None` at the name stage, before any lookup.
    pub resolved: Option<IpAddr>,
    /// The server name of the TLS ClientHello of a tunnel, when it is not the destination's own name.
    pub sni: Option<&'a str>,
}

/// The synchronous veto (E4b, see *Veto*): the session and the destination in, a refusal rule out. It runs on the
/// proxy's own tasks and must not block.
pub type VetoFn = Arc<dyn Fn(&SessionId, &Dest<'_>) -> Option<String> + Send + Sync>;

/// The lab-listener identity check (E4e, see *Listeners*): the session, the address about to be used (on this
/// machine) and the local end of the connection the proxy opened to it in, a refusal rule out when the process
/// that holds the other end is not one the session may reach. It runs on a blocking thread.
pub type ListenerFn = Arc<dyn Fn(&SessionId, SocketAddr, Option<SocketAddr>) -> Option<String> + Send + Sync>;

/// Told of each request whose destination name the session's policy refused (see *Observing refusals*): the session
/// and the destination (`resolved` is `None`; `sni` is the server name of a tunnel's hello when that is the name
/// refused). It only observes: the answer is the policy's. It runs on the proxy's own tasks and must not block.
pub type RefusalFn = Arc<dyn Fn(&SessionId, &Dest<'_>) + Send + Sync>;

/// An authentication with a canary user (E4d, see *Canary users*).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryHit {
    /// The decoy user name the client presented.
    pub user: String,
    /// What the registrant called the canary.
    pub label: String,
    /// The session whose listener received the attempt (the session whose sandbox may connect there); `None` on
    /// the shared listener.
    pub listener: Option<SessionId>,
    pub method: String,
    pub host: String,
    pub port: u16,
}

/// Called with each [`CanaryHit`] before the answer is written, on a blocking thread.
pub type CanaryFn = Arc<dyn Fn(&CanaryHit) + Send + Sync>;

/// Test hook: name to addresses, instead of a system lookup.
type Resolver = Arc<dyn Fn(&str) -> Vec<IpAddr> + Send + Sync>;

/// Resource limits of one proxy.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Concurrent client connections, all sessions together. Default 256.
    pub max_connections: usize,
    /// Concurrent client connections of one session. Default 64.
    pub max_per_session: usize,
    /// A connection that has not sent a complete request head within this gets `400`. Default 10 s.
    pub head_timeout: Duration,
    /// A tunnel or forwarded request with no bytes in either direction for this long is closed.
    /// Default 10 minutes.
    pub idle_timeout: Duration,
    /// After the client of a forwarded request has ended its side, the request ends once the
    /// destination is silent for this long (or `idle_timeout`, when shorter). Default 30 s.
    pub forward_grace: Duration,
    /// Concurrent name lookups. Default 16.
    pub max_lookups: usize,
    /// Concurrent name lookups of one session. Default 4.
    pub max_lookups_per_session: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_connections: 256,
            max_per_session: 64,
            head_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(600),
            forward_grace: Duration::from_secs(30),
            max_lookups: 16,
            max_lookups_per_session: 4,
        }
    }
}

fn semaphore(permits: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(permits.min(Semaphore::MAX_PERMITS)))
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("could not bind the egress proxy on 127.0.0.1:{port}: {source}")]
    Bind { port: u16, source: std::io::Error },
}

/// Credentials and address for one session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGrant {
    pub port: u16,
    pub user: String,
    pub password: String,
}

impl SessionGrant {
    /// `http://{user}:{password}@127.0.0.1:{port}`
    pub fn url(&self) -> String {
        format!("http://{}:{}@127.0.0.1:{}", self.user, self.password, self.port)
    }

    /// Proxy variables for a command's environment (see module contract).
    pub fn env(&self) -> BTreeMap<String, String> {
        let url = self.url();
        let mut m = BTreeMap::new();
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            m.insert(k.to_string(), url.clone());
        }
        m.insert("NO_PROXY".to_string(), String::new());
        m.insert("no_proxy".to_string(), String::new());
        m
    }
}

/// A separate capability held only by trusted in-process reference clients, never command env.
/// CONNECT is opaque: the client must enforce GET, strip credentials and validate each redirect.
#[derive(Clone, Debug)]
pub struct ReferenceGrant {
    grant: SessionGrant,
    raw_policy: Policy,
}

impl ReferenceGrant {
    pub fn url(&self) -> String {
        self.grant.url()
    }

    /// Pattern routing only; the proxy still checks deny rules and resolved addresses.
    pub fn matches_host(&self, host: &str, port: u16) -> bool {
        self.raw_policy.matches_reference(host, port)
    }
}

struct Entry {
    reference: bool,
    session: SessionId,
    password: String,
    policy: Arc<Policy>,
    /// One permit per open client connection of the session.
    permits: Arc<Semaphore>,
    /// One permit per name lookup of the session in progress.
    lookups: Arc<Semaphore>,
}

/// A pending connection: its id, the token that closes it and its connection permit.
type PendingEntry = (u64, CancellationToken, OwnedSemaphorePermit);

/// The connections whose slot a new one may take at the limit, each queue oldest first: those only
/// being drained after an answer of the proxy itself, and those that have not sent a complete request
/// head yet.
#[derive(Default)]
struct Pending {
    next: u64,
    draining: VecDeque<PendingEntry>,
    heads: VecDeque<PendingEntry>,
}

/// Records of answers that name no granted session: how many were written in the current minute,
/// and how many were left out since the last one written.
struct Budget {
    since: std::time::Instant,
    used: u32,
    left_out: u64,
}

/// State shared with every connection task (tasks never hold `Inner`, so dropping the last `Proxy`
/// handle stops the server).
struct Shared {
    sessions: Mutex<HashMap<String, Entry>>,
    sink: UnboundedSender<(SessionId, NetDecision)>,
    audit: Option<AuditFn>,
    limits: Limits,
    connections: Arc<Semaphore>,
    lookups: Arc<Semaphore>,
    resolver: Option<Resolver>,
    pending: Mutex<Pending>,
    refusals: Arc<Semaphore>,
    unattributed: Mutex<Budget>,
    /// The tasks that serve or refuse a connection.
    tasks: TaskTracker,
    /// The ports of the proxy's own listeners: the shared one, every session's open one and every retired
    /// one. A connection to one of them is refused whatever the policy says.
    own_ports: Mutex<HashSet<u16>>,
    /// The ports of session listeners that were closed by a revoke, as numbers only. Always also in
    /// `own_ports`.
    retired: Mutex<HashSet<u16>>,
    /// The tunnels and forwarded requests being served, by connection id, so that [`Proxy::cut_hosts`] can
    /// end the ones to a destination the operator withdrew.
    live: Mutex<HashMap<u64, Live>>,
    next_live: AtomicU64,
    /// Bumped by every cut; `cut_marks` holds the value of the last cut of each session, so that a connection
    /// that authenticated before a cut and registers after it is ended at once.
    cut_seq: AtomicU64,
    cut_marks: Mutex<HashMap<String, u64>>,
    hooks: Mutex<Hooks>,
    /// Canary users (decoys in the session table) by user name, with their labels.
    canaries: Mutex<HashMap<String, String>>,
    /// This machine's own interface addresses besides loopback (`Proxy::set_local_addrs`): a connection to one
    /// is checked by the listener check as a loopback one is.
    local_addrs: Mutex<Vec<IpAddr>>,
    /// Lab-listener scans in flight (a scan reads the process table).
    scans: Arc<Semaphore>,
}

#[derive(Default)]
struct Hooks {
    veto: Option<VetoFn>,
    listener: Option<ListenerFn>,
    canary: Option<CanaryFn>,
    refused: Option<RefusalFn>,
}

/// One connection being served, as `cut_hosts` and `cut` see it.
struct Live {
    session: SessionId,
    host: String,
    port: u16,
    cut: Cut,
}

/// The way a connection is ended from outside: a token, and the reason the second decision gives. The first cut
/// wins.
#[derive(Clone)]
struct Cut {
    token: CancellationToken,
    why: Arc<Mutex<&'static str>>,
}

impl Cut {
    fn new() -> Cut {
        Cut { token: CancellationToken::new(), why: Arc::new(Mutex::new("")) }
    }

    /// Ends the connection with `why`; false when it was already ended.
    fn fire(&self, why: &'static str) -> bool {
        let mut w = lock(&self.why);
        if self.token.is_cancelled() {
            return false;
        }
        *w = why;
        self.token.cancel();
        true
    }

    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    async fn cancelled(&self) {
        self.token.cancelled().await;
    }

    fn why(&self) -> &'static str {
        *lock(&self.why)
    }
}

/// Registers a connection in [`Shared::live`] and takes it out again when dropped.
struct LiveGuard<'a> {
    shared: &'a Shared,
    id: u64,
    cut: Cut,
}

impl<'a> LiveGuard<'a> {
    /// `seen` is the value of `Shared::cut_seq` when the connection authenticated: a cut of its session after
    /// that ends it as soon as it is registered.
    fn register(shared: &'a Shared, session: &SessionId, host: &str, port: u16, seen: u64) -> LiveGuard<'a> {
        let id = shared.next_live.fetch_add(1, Ordering::Relaxed);
        let cut = Cut::new();
        let live = Live { session: session.clone(), host: host.to_string(), port, cut: cut.clone() };
        lock(&shared.live).insert(id, live);
        if lock(&shared.cut_marks).get(session.as_str()).is_some_and(|mark| *mark > seen) {
            cut.fire(CUT_REVIEW);
        }
        LiveGuard { shared, id, cut }
    }
}

/// The policy of the session's current entry (the one `set_policy` last gave it), `fallback` when the
/// session holds no entry any more.
fn current_policy(shared: &Shared, session: &SessionId, reference: bool, fallback: Arc<Policy>) -> Arc<Policy> {
    lock(&shared.sessions)
        .values()
        .find(|e| &e.session == session && e.reference == reference)
        .map_or(fallback, |e| e.policy.clone())
}

impl Drop for LiveGuard<'_> {
    fn drop(&mut self) {
        lock(&self.shared.live).remove(&self.id);
    }
}

impl Shared {
    /// The verdict on one resolved address: refused when it reaches one of the proxy's own listeners
    /// (a loopback or unspecified address with an own port), else the policy's.
    fn check_addr(&self, policy: &Policy, host: &str, port: u16, ip: IpAddr, name_rule: &str) -> Verdict {
        if let Some(refused) = self.own_port_verdict(ip, port) {
            return refused;
        }
        policy.check_addr(host, port, ip, name_rule)
    }

    /// Whether a connection to `ip` reaches this machine: a loopback or unspecified address, or one of its own
    /// interface addresses (`Proxy::set_local_addrs`).
    fn reaches_this_machine(&self, ip: IpAddr) -> bool {
        is_local_literal(ip) || {
            let ip = crate::policy::canonical_ip(ip);
            lock(&self.local_addrs).iter().any(|a| crate::policy::canonical_ip(*a) == ip)
        }
    }

    /// The refusal for an address that reaches one of the proxy's own ports, else `None`.
    fn own_port_verdict(&self, ip: IpAddr, port: u16) -> Option<Verdict> {
        if is_local_literal(ip) && lock(&self.own_ports).contains(&port) {
            return Some(Verdict { allowed: false, rule: format!("deny the egress proxy's own port {port}") });
        }
        None
    }

    /// Registers a new connection, which has not sent its head yet, as pending; returns its id and the
    /// token that closes it.
    fn add_pending(&self, permit: OwnedSemaphorePermit) -> (u64, CancellationToken) {
        self.enqueue(permit, false)
    }

    /// Registers a connection that is only being drained after an answer of the proxy itself as
    /// pending. It has nothing left to serve, so eviction closes it before any connection still sending
    /// its head; among those drained, the oldest goes first, as its client has had the longest to read
    /// the answer.
    fn add_draining(&self, permit: OwnedSemaphorePermit) -> (u64, CancellationToken) {
        self.enqueue(permit, true)
    }

    fn enqueue(&self, permit: OwnedSemaphorePermit, draining: bool) -> (u64, CancellationToken) {
        let mut guard = lock(&self.pending);
        let p = &mut *guard;
        let id = p.next;
        p.next = p.next.wrapping_add(1);
        let token = CancellationToken::new();
        let queue = if draining { &mut p.draining } else { &mut p.heads };
        queue.push_back((id, token.clone(), permit));
        (id, token)
    }

    /// Closes the oldest connection being drained, or else the oldest one still sending its head, and
    /// returns its permit.
    fn evict_pending(&self) -> Option<OwnedSemaphorePermit> {
        let (_, token, permit) = {
            let mut guard = lock(&self.pending);
            let p = &mut *guard;
            p.draining.pop_front().or_else(|| p.heads.pop_front())?
        };
        token.cancel();
        Some(permit)
    }

    /// Takes a pending connection's permit back; `None` when a newer connection was given it.
    fn claim_pending(&self, id: u64) -> Option<OwnedSemaphorePermit> {
        let mut guard = lock(&self.pending);
        let p = &mut *guard;
        for queue in [&mut p.draining, &mut p.heads] {
            if let Some(i) = queue.iter().position(|(x, _, _)| *x == id) {
                return queue.remove(i).map(|(_, _, permit)| permit);
            }
        }
        None
    }

    /// Whether a record of an answer that names no session may be written now; if so, how many such
    /// records were left out before it.
    fn unattributed_turn(&self) -> Option<u64> {
        let mut b = lock(&self.unattributed);
        if b.since.elapsed() >= Duration::from_secs(60) {
            b.since = std::time::Instant::now();
            b.used = 0;
        }
        if b.used >= UNATTRIBUTED_PER_MINUTE {
            if b.left_out == 0 {
                tracing::warn!(
                    "the egress proxy is answering many requests that name no session; recording at most {UNATTRIBUTED_PER_MINUTE} a minute"
                );
            }
            b.left_out = b.left_out.saturating_add(1);
            return None;
        }
        b.used = b.used.saturating_add(1);
        Some(std::mem::take(&mut b.left_out))
    }

    fn leave_out(&self) {
        let mut b = lock(&self.unattributed);
        b.left_out = b.left_out.saturating_add(1);
    }
}

/// A pending connection's place in [`Pending`]; dropped before it is claimed, it gives the permit back.
struct PendingGuard<'a> {
    shared: &'a Shared,
    id: u64,
}

impl PendingGuard<'_> {
    fn claim(self) -> Option<OwnedSemaphorePermit> {
        self.shared.claim_pending(self.id)
    }
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        drop(self.shared.claim_pending(self.id));
    }
}

/// Why a connection on record as allowed ended when the proxy was cancelled.
const SHUTDOWN: &str = "the egress proxy shut down";

/// Why a connection on record as allowed ended when the operator withdrew its destination.
const CUT: &str = "the operator revoked the destination";
/// Why a connection on record as allowed ended when [`Proxy::cut`] ended the session's connections. A fixed
/// sentence: nothing the monitor decided or wrote reaches a record the agent can read.
const CUT_REVIEW: &str = "the session's connections were closed by loom";

/// The listener a connection was accepted on.
#[derive(Clone)]
enum Origin {
    /// The shared listener, for the reference clients.
    Shared,
    /// The listener of one session's command grant.
    Session(SessionId),
}

struct Inner {
    port: u16,
    shared: Arc<Shared>,
    cancel: CancellationToken,
    /// The session listeners: session id to its port and its token (a child of `cancel`). A revoke closes
    /// the session's listener and removes it from here.
    listeners: Mutex<HashMap<String, (u16, CancellationToken)>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

impl Proxy {
    /// A proxy without an audit hook and with the default limits.
    pub async fn start(port: u16, sink: UnboundedSender<(SessionId, NetDecision)>) -> Result<Proxy, ProxyError> {
        Proxy::start_with(port, sink, None, Limits::default()).await
    }

    /// `audit` records every decision before it takes effect (see [`AuditFn`] and *Audit* above); `sink`
    /// then receives only the decisions it failed to record. Without `audit`, `sink` receives every
    /// decision of a request that reached the policy.
    pub async fn start_with(
        port: u16,
        sink: UnboundedSender<(SessionId, NetDecision)>,
        audit: Option<AuditFn>,
        limits: Limits,
    ) -> Result<Proxy, ProxyError> {
        Proxy::start_inner(port, sink, audit, limits, None).await
    }

    async fn start_inner(
        port: u16,
        sink: UnboundedSender<(SessionId, NetDecision)>,
        audit: Option<AuditFn>,
        limits: Limits,
        resolver: Option<Resolver>,
    ) -> Result<Proxy, ProxyError> {
        let listener =
            TcpListener::bind(("127.0.0.1", port)).await.map_err(|source| ProxyError::Bind { port, source })?;
        let bound = listener.local_addr().map_err(|source| ProxyError::Bind { port, source })?.port();
        let shared = Arc::new(Shared {
            sessions: Mutex::new(HashMap::new()),
            sink,
            audit,
            connections: semaphore(limits.max_connections),
            lookups: semaphore(limits.max_lookups),
            limits,
            resolver,
            pending: Mutex::new(Pending::default()),
            refusals: semaphore(REFUSALS),
            unattributed: Mutex::new(Budget { since: std::time::Instant::now(), used: 0, left_out: 0 }),
            tasks: TaskTracker::new(),
            own_ports: Mutex::new(HashSet::from([bound])),
            retired: Mutex::new(HashSet::new()),
            live: Mutex::new(HashMap::new()),
            next_live: AtomicU64::new(0),
            cut_seq: AtomicU64::new(0),
            cut_marks: Mutex::new(HashMap::new()),
            hooks: Mutex::new(Hooks::default()),
            canaries: Mutex::new(HashMap::new()),
            local_addrs: Mutex::new(Vec::new()),
            scans: semaphore(MAX_SCANS),
        });
        let cancel = CancellationToken::new();
        tokio::spawn(accept_loop(listener, shared.clone(), cancel.clone(), cancel.clone(), Origin::Shared));
        Ok(Proxy { inner: Arc::new(Inner { port: bound, shared, cancel, listeners: Mutex::new(HashMap::new()) }) })
    }

    /// The port actually bound.
    pub fn port(&self) -> u16 {
        self.inner.port
    }

    /// The port of the session's own listener while it holds a command grant.
    pub fn session_port(&self, session: &SessionId) -> Option<u16> {
        let held = lock(&self.inner.shared.sessions).get(session.as_str()).is_some_and(|e| !e.reference);
        if !held {
            return None;
        }
        lock(&self.inner.listeners).get(session.as_str()).filter(|(_, t)| !t.is_cancelled()).map(|(p, _)| *p)
    }

    /// The port of the session's listener, opened (inside a Tokio runtime) on the first call.
    fn session_listener(&self, session: &SessionId) -> Result<u16, ProxyError> {
        let mut listeners = lock(&self.inner.listeners);
        if let Some((port, token)) = listeners.get(session.as_str()) {
            if !token.is_cancelled() {
                return Ok(*port);
            }
        }
        let shared = &self.inner.shared;
        let listener = open_fresh_listener(shared, &|port| lock(&shared.retired).contains(&port))?;
        let port = listener.local_addr().map_err(|source| ProxyError::Bind { port: 0, source })?.port();
        let token = self.inner.cancel.child_token();
        tokio::spawn(accept_loop(
            listener,
            shared.clone(),
            self.inner.cancel.clone(),
            token.clone(),
            Origin::Session(session.clone()),
        ));
        listeners.insert(session.as_str().to_string(), (port, token));
        Ok(port)
    }

    pub fn grant(&self, session: &SessionId, policy: Policy) -> Result<SessionGrant, ProxyError> {
        let port = self.session_listener(session)?;
        let password = format!("{:032x}", rand::rng().random::<u128>());
        let limits = &self.inner.shared.limits;
        let entry = Entry {
            reference: false,
            session: session.clone(),
            password: password.clone(),
            policy: Arc::new(policy),
            permits: semaphore(limits.max_per_session),
            lookups: semaphore(limits.max_lookups_per_session),
        };
        lock(&self.inner.shared.sessions).insert(session.as_str().to_string(), entry);
        Ok(SessionGrant { port, user: session.as_str().to_string(), password })
    }

    /// Mint a credential for in-process reference GET clients. It is not added to command env.
    pub fn grant_reference(
        &self,
        session: &SessionId,
        cfg: &loom_core::config::NetworkCfg,
    ) -> Result<ReferenceGrant, String> {
        let raw_policy = Policy::new(cfg)?;
        let policy = Policy::reference(cfg)?;
        let user = format!("reference-{:032x}", rand::rng().random::<u128>());
        let password = format!("{:032x}", rand::rng().random::<u128>());
        let limits = &self.inner.shared.limits;
        let entry = Entry {
            reference: true,
            session: session.clone(),
            password: password.clone(),
            policy: Arc::new(policy),
            permits: semaphore(limits.max_per_session),
            lookups: semaphore(limits.max_lookups_per_session),
        };
        let mut sessions = lock(&self.inner.shared.sessions);
        sessions.retain(|_, entry| !(entry.reference && &entry.session == session));
        sessions.insert(user.clone(), entry);
        Ok(ReferenceGrant { grant: SessionGrant { port: self.inner.port, user, password }, raw_policy })
    }

    /// Replaces the policy of **both** entries of a session, the command grant and its reference grant, with
    /// `policy` (a hold: nothing new opens for the session, whichever credentials it presents), so that a cut
    /// after it leaves nothing open and nothing new, in-process tools that follow redirects included. The
    /// credentials stay. The reference entry keeps the hold until `grant_reference` mints it again or the session
    /// is revoked. False when the session holds no grant.
    pub fn hold(&self, session: &SessionId, policy: Policy) -> bool {
        let policy = Arc::new(policy);
        let mut any = false;
        for entry in lock(&self.inner.shared.sessions).values_mut().filter(|e| &e.session == session) {
            entry.policy = policy.clone();
            any = true;
        }
        any
    }

    /// Replace the policy of a session that holds a grant. Its credentials stay as they are. False
    /// when the session holds no grant.
    pub fn set_policy(&self, session: &SessionId, policy: Policy) -> bool {
        match lock(&self.inner.shared.sessions).get_mut(session.as_str()) {
            Some(entry) => {
                entry.policy = Arc::new(policy);
                true
            }
            None => false,
        }
    }

    /// Ends the tunnels and forwarded requests of `session` whose destination `pattern` covers (a grant's
    /// host pattern, with or without a port; see [`crate::policy::pattern_covers`]), including a
    /// connection that has been accepted but has not opened its destination yet (it is refused when it
    /// would). Each ended connection is recorded as failed after the allow, reason "the operator revoked
    /// the destination". Returns how many were ended. The caller sets the narrowed policy first, so a
    /// connection that starts afterwards is refused by it.
    pub fn cut_hosts(&self, session: &SessionId, pattern: &str) -> usize {
        let live = lock(&self.inner.shared.live);
        let mut cut = 0usize;
        for l in live.values().filter(|l| &l.session == session) {
            if !l.cut.is_cancelled() && crate::policy::pattern_covers(pattern, &l.host, Some(l.port)) && l.cut.fire(CUT)
            {
                cut = cut.saturating_add(1);
            }
        }
        cut
    }

    /// Ends every open tunnel and forwarded request of `session`, reference grants' included, whatever the
    /// destination (E4a). Returns how many were ended. Each ended connection that was on record as allowed gets
    /// the second decision, with the fixed reason "the session's connections were closed by loom". A
    /// connection the session authenticated before this call and has not registered yet is ended when it
    /// registers; one that is only resolving or connecting its destination is ended when that finishes, before
    /// the `200` or any byte upstream. The bytes of an open tunnel stop within a few milliseconds. It does not
    /// change the policy: the caller sets a hold with `set_policy` first, so a connection that starts afterwards
    /// is refused by it.
    pub fn cut(&self, session: &SessionId) -> usize {
        self.cut_sessions(std::iter::once(session))
    }

    /// [`Proxy::cut`] for each of `sessions`: the sessions of one mission (the proxy does not know missions;
    /// the runtime's `cut_mission` lists them).
    pub fn cut_sessions<'a>(&self, sessions: impl IntoIterator<Item = &'a SessionId>) -> usize {
        let shared = &self.inner.shared;
        let sessions: HashSet<&SessionId> = sessions.into_iter().collect();
        let mark = shared.cut_seq.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        {
            let mut marks = lock(&shared.cut_marks);
            for s in &sessions {
                marks.insert(s.as_str().to_string(), mark);
            }
        }
        let live = lock(&shared.live);
        let mut cut = 0usize;
        for l in live.values().filter(|l| sessions.contains(&l.session)) {
            if l.cut.fire(CUT_REVIEW) {
                cut = cut.saturating_add(1);
            }
        }
        cut
    }

    /// Installs the synchronous veto (E4b, see *Veto*), replacing the one before; `None` removes it.
    pub fn set_veto(&self, veto: Option<VetoFn>) {
        lock(&self.inner.shared.hooks).veto = veto;
    }

    /// Installs the lab-listener identity check (E4e, see *Listeners*); `None` removes it.
    pub fn set_listener_check(&self, check: Option<ListenerFn>) {
        lock(&self.inner.shared.hooks).listener = check;
    }

    /// Installs the observer of refused names (see *Observing refusals*); `None` removes it.
    pub fn set_refusal_observer(&self, observer: Option<RefusalFn>) {
        lock(&self.inner.shared.hooks).refused = observer;
    }

    /// Tells the proxy this machine's own interface addresses (LAN, tailnet, global IPv6), which the listener check
    /// treats as loopback; the daemon refreshes them with its infrastructure.
    pub fn set_local_addrs(&self, addrs: Vec<IpAddr>) {
        *lock(&self.inner.shared.local_addrs) = addrs;
    }

    /// Installs the canary hook (E4d, see *Canary users*); `None` removes it.
    pub fn set_canary_hook(&self, hook: Option<CanaryFn>) {
        lock(&self.inner.shared.hooks).canary = hook;
    }

    /// Registers a decoy user (CN-1) in the session table: any request that presents `user` as its Basic user,
    /// with any password, on any listener, fires the canary hook and gets the answer of an unknown user. Refused
    /// (with a sentence) when `user` is empty, longer than 128 bytes, or already the user of a session or a
    /// reference grant. Registering a user again replaces its label.
    pub fn add_canary_user(&self, user: &str, label: &str) -> Result<(), String> {
        if user.is_empty() || user.len() > 128 {
            return Err("A canary user must be 1 to 128 bytes long. Give it a longer or shorter name.".to_string());
        }
        if lock(&self.inner.shared.sessions).contains_key(user) {
            return Err(format!(
                "{user:?} is the user of a session's proxy grant, so it cannot be a canary. Choose a name no session can have."
            ));
        }
        lock(&self.inner.shared.canaries).insert(user.to_string(), label.to_string());
        Ok(())
    }

    /// Takes a decoy user out of the table; false when it was not there.
    pub fn remove_canary_user(&self, user: &str) -> bool {
        lock(&self.inner.shared.canaries).remove(user).is_some()
    }

    /// What the name check of the session's current policy says about `host:port`; `None` when the
    /// session holds no grant.
    pub fn check_name(&self, session: &SessionId, host: &str, port: u16) -> Option<crate::policy::Verdict> {
        lock(&self.inner.shared.sessions).get(session.as_str()).map(|e| e.policy.check_name(host, port))
    }

    /// Drops the session's credentials and closes its listener; its port is retired (see the module
    /// contract).
    pub fn revoke(&self, session: &SessionId) {
        lock(&self.inner.shared.sessions).retain(|_, entry| &entry.session != session);
        if let Some((port, token)) = lock(&self.inner.listeners).remove(session.as_str()) {
            lock(&self.inner.shared.retired).insert(port);
            token.cancel();
        }
    }

    /// Stop accepting connections. Open tunnels are closed.
    pub fn shutdown(&self) {
        self.inner.cancel.cancel();
    }

    /// Like [`Proxy::shutdown`], then waits up to `within` for the connections to end, so that the records
    /// they write on the way out (the second decision of one on record as allowed) are written before the
    /// caller goes on, e.g. to exit the process.
    pub async fn stop(&self, within: Duration) {
        self.shutdown();
        let tasks = &self.inner.shared.tasks;
        tasks.close();
        let _ = tokio::time::timeout(within, tasks.wait()).await;
    }
}

/// How many sockets are bound in a row to find a loopback port that is not one of the proxy's own.
const LISTENER_ATTEMPTS: usize = 64;

/// Opens a listener on a loopback port that is neither retired (`is_retired`) nor one of the proxy's own
/// ports. The port is added to the own ports before `listen`. Sockets bound to unusable ports are held
/// until a fresh one is found, so the system hands out another each time, and dropped on return.
fn open_fresh_listener(shared: &Shared, is_retired: &dyn Fn(u16) -> bool) -> Result<TcpListener, ProxyError> {
    let bind = |source: std::io::Error| ProxyError::Bind { port: 0, source };
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(bind(std::io::Error::other("a session's listener can only be opened inside a Tokio runtime")));
    }
    let mut aside = Vec::new();
    for _ in 0..LISTENER_ATTEMPTS {
        let socket = tokio::net::TcpSocket::new_v4().map_err(bind)?;
        socket.bind(SocketAddr::from(([127, 0, 0, 1], 0))).map_err(bind)?;
        let port = socket.local_addr().map_err(bind)?.port();
        if is_retired(port) || !lock(&shared.own_ports).insert(port) {
            aside.push(socket);
            continue;
        }
        return match socket.listen(1024) {
            Ok(listener) => Ok(listener),
            Err(e) => {
                lock(&shared.own_ports).remove(&port);
                Err(bind(e))
            }
        };
    }
    Err(ProxyError::Bind {
        port: 0,
        source: std::io::Error::other(format!(
            "No fresh loopback port was found in {LISTENER_ATTEMPTS} attempts, because the ports the system offered \
             were all in use by the proxy or retired by a revoked session; restarting the daemon frees the retired ports."
        )),
    })
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Accepts on one listener until `stop`; connections are served until `cancel` (the proxy's own token),
/// so closing a session's listener leaves its open connections to finish.
async fn accept_loop(
    listener: TcpListener,
    shared: Arc<Shared>,
    cancel: CancellationToken,
    stop: CancellationToken,
    origin: Origin,
) {
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            r = listener.accept() => match r {
                Ok((stream, _)) => {
                    // At the limit, the slot of a connection being drained, or else of the oldest one still
                    // without a head, is taken over.
                    let slot = shared.connections.clone().try_acquire_owned().ok().or_else(|| shared.evict_pending());
                    match slot {
                        Some(permit) => {
                            let (id, evicted) = shared.add_pending(permit);
                            shared.tasks.spawn(handle(stream, shared.clone(), cancel.clone(), id, evicted, origin.clone()));
                        }
                        None => refuse(stream, &shared),
                    }
                }
                // Out of descriptors or a connection reset before accept: keep serving.
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
        }
    }
}

/// Answers a connection over the limit of all sessions with `503`: from one of a few tasks that let
/// the client read it, or, when those are busy too, with one non-blocking write and close.
fn refuse(stream: TcpStream, shared: &Arc<Shared>) {
    let body = format!(
        "loom proxy: too many open proxy connections (limit {}). Wait for running commands to finish, or retry shortly.\n",
        shared.limits.max_connections
    );
    let (status, extra) = ("503 Service Unavailable", "Retry-After: 5\r\n");
    match shared.refusals.clone().try_acquire_owned() {
        Ok(permit) => {
            let owner = shared.clone();
            shared.tasks.spawn(async move {
                let mut stream = stream;
                audit_local(&owner, None, local_decision(None, "connection limit (all sessions)")).await;
                respond(&mut stream, status, extra, &body).await;
                drop(permit);
            });
        }
        Err(_) => {
            let _ = stream.try_write(response_bytes(status, extra, &body).as_bytes());
            shared.leave_out();
        }
    }
}

struct Head {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice())
    }
}

enum HeadError {
    Closed,
    Bad(String),
}

fn try_parse(buf: &[u8]) -> Result<Option<(Head, usize)>, String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => {
            if !matches!(req.version, Some(0 | 1)) {
                return Err("only HTTP/1.0 and HTTP/1.1 requests are supported".into());
            }
            let method = req.method.ok_or("the request has no method")?.to_string();
            let target = req.path.ok_or("the request has no target")?.to_string();
            let headers = req.headers.iter().map(|h| (h.name.to_string(), h.value.to_vec())).collect();
            Ok(Some((Head { method, target, headers }, n)))
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(e) => Err(format!("the request head could not be parsed ({e})")),
    }
}

/// Reads up to the end of the request head; returns it with any bytes read past it.
async fn read_head(client: &mut TcpStream) -> Result<(Head, Vec<u8>), HeadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    loop {
        match try_parse(&buf) {
            Ok(Some((head, n))) => {
                if n > MAX_HEAD {
                    return Err(HeadError::Bad(too_large()));
                }
                return Ok((head, buf.split_off(n)));
            }
            Ok(None) => {}
            Err(m) => return Err(HeadError::Bad(m)),
        }
        if buf.len() >= MAX_HEAD {
            return Err(HeadError::Bad(too_large()));
        }
        match client.read_buf(&mut buf).await {
            Ok(0) if buf.is_empty() => return Err(HeadError::Closed),
            Ok(0) => return Err(HeadError::Bad("the connection closed in the middle of the request head".into())),
            Ok(_) => {}
            Err(_) => return Err(HeadError::Closed),
        }
    }
}

fn too_large() -> String {
    format!("the request head is larger than {} KiB; send a smaller head", MAX_HEAD / 1024)
}

/// `d` in words: whole minutes, whole seconds, or milliseconds.
fn human(d: Duration) -> String {
    let s = d.as_secs();
    let (minutes, seconds) = (s / 60, s % 60);
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    if d.subsec_nanos() != 0 || s == 0 {
        format!("{} ms", d.as_millis())
    } else if minutes > 0 && seconds == 0 {
        plural(minutes, "minute")
    } else {
        plural(s, "second")
    }
}

/// `s` cut to `max` characters, with `…` when something was cut.
fn cut(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", s.get(..i).unwrap_or("")),
        None => s.to_string(),
    }
}

/// A proxy-generated response. These, and only these, carry `X-Loom-Proxy: 1`.
fn response_bytes(status: &str, extra: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nX-Loom-Proxy: 1\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Writes a proxy-generated response and closes. Unread input is drained briefly so that closing
/// does not reset the connection before the client has read the response.
async fn respond(client: &mut TcpStream, status: &str, extra: &str, body: &str) {
    if send(client, status, extra, body).await {
        drain(client).await;
    }
}

/// Like [`respond`], for a connection that holds the global `slot`: before the drain the slot is
/// pending again, so at the limit a new connection takes it over (and this one is closed) rather than
/// wait for a connection that has nothing left to serve; it is taken before the slot of any
/// connection still sending its head (see [`Shared::add_draining`]).
async fn answer(
    client: &mut TcpStream,
    shared: &Shared,
    slot: OwnedSemaphorePermit,
    status: &str,
    extra: &str,
    body: &str,
) {
    if !send(client, status, extra, body).await {
        return;
    }
    let (id, evicted) = shared.add_draining(slot);
    let _pending = PendingGuard { shared, id };
    tokio::select! {
        _ = drain(client) => {}
        _ = evicted.cancelled() => {}
    }
}

/// Writes a proxy-generated response and ends the writing side; false when the client is gone.
async fn send(client: &mut TcpStream, status: &str, extra: &str, body: &str) -> bool {
    let msg = response_bytes(status, extra, body);
    if client.write_all(msg.as_bytes()).await.is_err() {
        return false;
    }
    let _ = client.shutdown().await;
    true
}

/// Reads and drops what the client still sends, for up to 500 ms.
async fn drain(client: &mut TcpStream) {
    let drain = async {
        let mut sink = [0u8; 4096];
        let mut total = 0usize;
        while total < 256 * 1024 {
            match client.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => total = total.saturating_add(n),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(500), drain).await;
}

async fn bad_request(client: &mut TcpStream, shared: &Shared, slot: OwnedSemaphorePermit, why: &str) {
    let body = format!(
        "loom proxy: {why}. This proxy accepts `CONNECT host:port` and `GET http://host/path`-style requests with an absolute http:// URI; use CONNECT for https.\n"
    );
    answer(client, shared, slot, "400 Bad Request", "", &body).await;
}

/// Records a decision: the audit hook first (on a blocking thread, so file I/O never stalls a worker).
/// The sink gets the decision when `to_sink` and the hook did not record it: always without a hook,
/// and as a refusal when the hook failed. A failing hook is returned.
async fn audit_decision(
    shared: &Shared,
    session: Option<&SessionId>,
    d: NetDecision,
    to_sink: bool,
) -> std::io::Result<()> {
    let result = match &shared.audit {
        None => Err(None),
        Some(f) => {
            let (f, s, dd) = (f.clone(), session.cloned(), d.clone());
            match tokio::task::spawn_blocking(move || f(s.as_ref(), &dd)).await {
                Ok(r) => r.map_err(Some),
                Err(e) => Err(Some(std::io::Error::other(format!("the audit task failed: {e}")))),
            }
        }
    };
    if let (Err(failure), true, Some(s)) = (&result, to_sink, session) {
        let shown = match failure {
            None => d,
            Some(_) if d.allowed => {
                NetDecision { allowed: false, rule: format!("{} (refused: egress audit log not written)", d.rule), ..d }
            }
            Some(_) => NetDecision { rule: format!("{} (egress audit log not written)", d.rule), ..d },
        };
        let _ = shared.sink.send((s.clone(), shown));
    }
    match result {
        Ok(()) | Err(None) => Ok(()),
        Err(Some(e)) => Err(e),
    }
}

/// Records an answer the proxy gives itself, best effort: a failure is logged. Answers that name no
/// session are recorded at most [`UNATTRIBUTED_PER_MINUTE`] a minute.
async fn audit_local(shared: &Shared, session: Option<&SessionId>, mut d: NetDecision) {
    if shared.audit.is_none() {
        return;
    }
    if session.is_none() {
        match shared.unattributed_turn() {
            None => return,
            Some(0) => {}
            Some(n) => d.rule = format!("{} ({n} similar answers before this one were not recorded)", d.rule),
        }
    }
    if let Err(e) = audit_decision(shared, session, d, false).await {
        let whose = session.map_or("a request without a session", |s| s.as_str());
        tracing::warn!("cannot write the egress audit record of {whose}: {e}");
    }
}

/// The record of an answer the proxy gives itself to `head` (when it was read).
fn local_decision(head: Option<&Head>, rule: &str) -> NetDecision {
    let (host, port) = head.and_then(destination).unwrap_or_else(|| ("-".to_string(), 0));
    NetDecision {
        host: cut(&host, 255),
        port,
        method: head.map_or_else(|| "-".to_string(), |h| cut(&h.method, 32)),
        allowed: false,
        rule: cut(rule, 300),
        resolved: None,
        sni: None,
    }
}

/// The destination a request names, when its target parses as one.
fn destination(head: &Head) -> Option<(String, u16)> {
    let t = head.target.as_str();
    let http = t.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("http://"));
    if head.method == "CONNECT" || (head.method == CHECK_METHOD && !http) {
        return parse_authority(t, None).ok();
    }
    if http {
        return plain_target(t).ok().map(|(host, port, _, _)| (host, port));
    }
    let rest = t.get(..8).filter(|p| p.eq_ignore_ascii_case("https://")).and_then(|_| t.get(8..))?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    parse_authority(rest.get(..end)?, Some(443)).ok()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct Authed {
    reference: bool,
    session: SessionId,
    policy: Arc<Policy>,
    permits: Arc<Semaphore>,
    lookups: Arc<Semaphore>,
}

/// Why a request carries no usable credentials.
enum AuthError {
    /// The reason, as it is recorded.
    Failed(String),
    /// The request presented a decoy user (E4d): its label. It is recorded and answered as an unknown user.
    Canary { user: String, label: String },
}

/// The session whose Basic credentials the request carries, or why there is none.
fn authenticate(shared: &Shared, head: &Head) -> Result<Authed, AuthError> {
    let failed = |why: &str| AuthError::Failed(why.to_string());
    let Some(value) = head.header("proxy-authorization") else { return Err(failed("no credentials")) };
    let decoded = (|| {
        let value = std::str::from_utf8(value).ok()?;
        let (scheme, encoded) = value.trim().split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("basic") {
            return None;
        }
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded.trim()).ok()?;
        String::from_utf8(decoded).ok()
    })();
    // Passwords are hex, so the last colon separates the two.
    let Some((user, password)) = decoded.as_deref().and_then(|d| d.rsplit_once(':')) else {
        return Err(failed("the credentials are not Basic user:password"));
    };
    // A decoy user is looked for first, whatever the password: presenting it is the event.
    if let Some(label) = lock(&shared.canaries).get(user) {
        return Err(AuthError::Canary { user: user.to_string(), label: label.clone() });
    }
    let sessions = lock(&shared.sessions);
    let Some(e) = sessions.get(user) else { return Err(failed("unknown user")) };
    if constant_time_eq(e.password.as_bytes(), password.as_bytes()) {
        let (session, policy) = (e.session.clone(), e.policy.clone());
        Ok(Authed { reference: e.reference, session, policy, permits: e.permits.clone(), lookups: e.lookups.clone() })
    } else {
        Err(AuthError::Failed(format!("wrong password for session {}", e.session.as_str())))
    }
}

/// `host[:port]` or `[v6][:port]`, without credentials. The host is returned normalized.
fn parse_authority(s: &str, default_port: Option<u16>) -> Result<(String, u16), String> {
    if s.is_empty() {
        return Err("the destination is empty".into());
    }
    if s.contains('@') {
        return Err("credentials inside the destination are not supported".into());
    }
    let port_of = |p: Option<&str>| -> Result<u16, String> {
        match p {
            Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| format!("`{p}` is not a valid port")),
            None => default_port.ok_or_else(|| "the destination has no port; write host:port".to_string()),
        }
    };
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']').ok_or("the `[` has no closing `]`")?;
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return Err("the text in brackets is not an IPv6 address".into());
        }
        let port = match after {
            "" => port_of(None)?,
            _ => port_of(Some(after.strip_prefix(':').ok_or("only `:port` may follow `]`")?))?,
        };
        (inner, port)
    } else {
        match s.split_once(':') {
            None => (s, port_of(None)?),
            Some((h, p)) => (h, port_of(Some(p))?),
        }
    };
    let host = normalize_host(host);
    let name_ok = !host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'));
    if !name_ok && host.parse::<IpAddr>().is_err() {
        return Err(format!("`{host}` is not a usable host name (use ASCII names or punycode)"));
    }
    Ok((host, port))
}

/// Everything needed to attribute and report one request's decision.
struct Ctx<'a> {
    shared: &'a Shared,
    session: &'a SessionId,
    /// The session's name lookup turns.
    lookups: &'a Arc<Semaphore>,
    method: &'a str,
    host: &'a str,
    port: u16,
}

impl Ctx<'_> {
    /// Audits and publishes this request's decision.
    async fn record(&self, allowed: bool, rule: String, resolved: Option<IpAddr>) -> std::io::Result<()> {
        self.record_sni(allowed, rule, resolved, None).await
    }

    /// `record` for a decision that names the TLS server name of the tunnel.
    async fn record_sni(
        &self,
        allowed: bool,
        rule: String,
        resolved: Option<IpAddr>,
        sni: Option<String>,
    ) -> std::io::Result<()> {
        let d = NetDecision {
            host: self.host.to_string(),
            port: self.port,
            method: self.method.to_string(),
            allowed,
            rule,
            resolved: resolved.map(|a| a.to_string()),
            sni,
        };
        audit_decision(self.shared, Some(self.session), d, true).await
    }

    /// The refusal rule of the synchronous veto for this destination, `None` when there is no veto or it lets the
    /// destination through (see *Veto*).
    fn veto(&self, resolved: Option<IpAddr>, sni: Option<&str>) -> Option<String> {
        let hook = lock(&self.shared.hooks).veto.clone()?;
        let dest = Dest { host: self.host, port: self.port, method: self.method, resolved, sni };
        hook(self.session, &dest).map(|rule| cut(&rule, 200))
    }

    /// Records a veto and returns the answer: `502` with the marker and a fixed sentence.
    async fn vetoed(&self, rule: &str, resolved: Option<IpAddr>, sni: Option<String>) -> (&'static str, String) {
        let rule = if self.method == CHECK_METHOD {
            format!("vetoed: {rule} (check only)")
        } else {
            format!("vetoed: {rule}")
        };
        if let Err(e) = self.record_sni(false, rule, resolved, sni).await {
            tracing::warn!("cannot write the egress audit record of {}: {e}", self.session.as_str());
        }
        (
            "502 Bad Gateway",
            format!(
                "loom proxy: {} is closed to this mission by loom's own rules, so the connection was not opened and nothing was sent. Do not retry it. If the goal cannot be reached without it, report_blocker with class needs_approval.\n",
                self.dest()
            ),
        )
    }

    /// The refusal rule of the lab-listener identity check for a connection to the loopback address `ip`
    /// (see *Listeners*), `None` when there is no check or it finds nothing.
    async fn listener_refusal(&self, ip: IpAddr, client: Option<SocketAddr>) -> Option<String> {
        let hook = lock(&self.shared.hooks).listener.clone()?;
        let (session, addr) = (self.session.clone(), SocketAddr::new(ip, self.port));
        // At most `MAX_SCANS` scans of the process table run at once; a swarm of loopback connections waits here.
        let _turn = self.shared.scans.clone().acquire_owned().await.ok()?;
        tokio::task::spawn_blocking(move || hook(&session, addr, client)).await.ok().flatten().map(|r| cut(&r, 200))
    }

    /// Tells the refusal observer that the policy refused the name `host`, or the server name `sni` of a tunnel.
    fn observe_refusal(&self, sni: Option<&str>) {
        let Some(hook) = lock(&self.shared.hooks).refused.clone() else { return };
        hook(self.session, &Dest { host: self.host, port: self.port, method: self.method, resolved: None, sni });
    }

    /// Like `record`, for decisions that need no audit to succeed: a failure is only logged.
    async fn record_best_effort(&self, allowed: bool, rule: String, resolved: Option<IpAddr>) {
        self.record_best_effort_sni(allowed, rule, resolved, None).await;
    }

    async fn record_best_effort_sni(&self, allowed: bool, rule: String, resolved: Option<IpAddr>, sni: Option<String>) {
        if let Err(e) = self.record_sni(allowed, rule, resolved, sni).await {
            tracing::warn!("cannot write the egress audit record of {}: {e}", self.session.as_str());
        }
    }

    /// Records that a connection on record as allowed failed before or while its request was relayed:
    /// the allow's rule and address again, with the failure, so the trail never ends at a bare allow
    /// for traffic that did not flow. Best effort.
    async fn failed_after_allow(&self, allowed: &Allowed, why: &str) {
        let rule = format!("{} (failed after the allow: {why})", allowed.rule);
        self.record_best_effort(true, rule, Some(allowed.ip)).await;
    }

    fn dest(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn refused(&self, rule: &str) -> (&'static str, String) {
        (
            "403 Forbidden",
            format!(
                "loom network policy: {} to {} was refused by rule `{rule}`. The network policy is set by the operator in the loom config ([network]); a command cannot change it. Use a destination the policy allows, or ask the operator to change the config.\n",
                if self.method == CHECK_METHOD { "a connection" } else { self.method },
                self.dest()
            ),
        )
    }

    fn unreachable(&self, why: &str) -> (&'static str, String) {
        (
            "502 Bad Gateway",
            format!(
                "loom proxy: {} was allowed by the network policy but could not be reached: {why}. Check the host name and port, or try again later.\n",
                self.dest()
            ),
        )
    }

    fn silent(&self, after: Duration) -> (&'static str, String) {
        (
            "504 Gateway Timeout",
            format!(
                "loom proxy: {} sent no response for {}, so the request was closed. Retry it, or check that the host is up and answering.\n",
                self.dest(),
                human(after)
            ),
        )
    }

    fn audit_failed(&self, e: &std::io::Error) -> (&'static str, String) {
        (
            "502 Bad Gateway",
            format!(
                "loom proxy: the egress audit log could not be written ({e}), so the connection to {} was refused. Tell the operator to check the session directory and the disk, then retry.\n",
                self.dest()
            ),
        )
    }
}

/// Name to addresses, on a task of its own: the test hook, or a system lookup. A lookup holds a turn
/// of its session and one of the proxy until it ends, even when the caller has given up waiting.
async fn resolve(cx: &Ctx<'_>) -> Result<Vec<IpAddr>, String> {
    let turn = |s: &Arc<Semaphore>| tokio::time::timeout(RESOLVE_TIMEOUT, s.clone().acquire_owned());
    let Ok(Ok(mine)) = turn(cx.lookups).await else {
        return Err(format!(
            "this session already has {} name lookups in progress",
            cx.shared.limits.max_lookups_per_session
        ));
    };
    let Ok(Ok(all)) = turn(&cx.shared.lookups).await else {
        return Err("too many name lookups are in progress".to_string());
    };
    let (name, port, resolver) = (cx.host.to_string(), cx.port, cx.shared.resolver.clone());
    let task = tokio::spawn(async move {
        let found = match resolver {
            Some(r) => tokio::task::spawn_blocking(move || r(&name)).await.map_err(std::io::Error::other),
            None => tokio::net::lookup_host((name.as_str(), port)).await.map(|it| it.map(|a| a.ip()).collect()),
        };
        drop((mine, all));
        found.map(|v: Vec<IpAddr>| v.into_iter().take(MAX_ADDRS).collect::<Vec<_>>())
    });
    match tokio::time::timeout(RESOLVE_TIMEOUT, task).await {
        Ok(Ok(Ok(v))) => Ok(v),
        Ok(Ok(Err(e))) => Err(format!("name lookup failed: {e}")),
        Ok(Err(_)) => Err("name lookup failed".to_string()),
        Err(_) => Err("name lookup timed out".to_string()),
    }
}

/// The rule and the address of a connection that is on record as allowed.
struct Allowed {
    rule: String,
    ip: IpAddr,
}

/// Applies the policy to the name, resolves it, and connects to the first address the policy allows.
/// Reports exactly one decision; for the connection it returns, the audit hook has succeeded first, and
/// the rule and address it was recorded with come along. On failure returns the status line and body
/// to send.
async fn open_upstream(cx: &Ctx<'_>, policy: &Policy) -> Result<(TcpStream, Allowed), (&'static str, String)> {
    let v = policy.check_name(cx.host, cx.port);
    if !v.allowed {
        cx.observe_refusal(None);
        cx.record_best_effort(false, v.rule.clone(), None).await;
        return Err(cx.refused(&v.rule));
    }
    let name_rule = v.rule;
    // Before any lookup: a vetoed name is never resolved.
    if let Some(rule) = cx.veto(None, None) {
        return Err(cx.vetoed(&rule, None, None).await);
    }

    let addrs: Vec<IpAddr> = match cx.host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => match resolve(cx).await {
            Ok(a) => a,
            Err(why) => return Err(unreachable_decision(cx, &name_rule, None, &why).await),
        },
    };
    if addrs.is_empty() {
        return Err(unreachable_decision(cx, &name_rule, None, "the name has no addresses").await);
    }

    let mut first_refusal: Option<(String, IpAddr)> = None;
    let mut first_failure: Option<(String, IpAddr, String)> = None;
    for ip in addrs {
        let cv = cx.shared.check_addr(policy, cx.host, cx.port, ip, &name_rule);
        if !cv.allowed {
            first_refusal.get_or_insert((cv.rule, ip));
            continue;
        }
        // Before the connect: nothing is opened toward an address the veto closes.
        if let Some(rule) = cx.veto(Some(ip), None) {
            return Err(cx.vetoed(&rule, Some(ip), None).await);
        }
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(ip, cx.port))).await {
            Ok(Ok(s)) => {
                // A listener opened between the first check and the connect is in the set by now.
                if let Some(refused) = cx.shared.own_port_verdict(ip, cx.port) {
                    drop(s);
                    first_refusal.get_or_insert((refused.rule, ip));
                    continue;
                }
                // The process that holds the other end of a connection to this machine is not another session's
                // sandbox process.
                if cx.shared.reaches_this_machine(ip) {
                    if let Some(rule) = cx.listener_refusal(ip, s.local_addr().ok()).await {
                        drop(s);
                        first_refusal.get_or_insert((rule, ip));
                        continue;
                    }
                }
                let _ = s.set_nodelay(true);
                // Nothing has been sent upstream yet; the connection is used only once it is on record.
                return match cx.record(true, cv.rule.clone(), Some(ip)).await {
                    Ok(()) => Ok((s, Allowed { rule: cv.rule, ip })),
                    Err(e) => {
                        tracing::warn!("cannot write the egress audit record of {}: {e}", cx.session.as_str());
                        Err(cx.audit_failed(&e))
                    }
                };
            }
            Ok(Err(e)) => {
                first_failure.get_or_insert((cv.rule, ip, e.to_string()));
            }
            Err(_) => {
                first_failure.get_or_insert((cv.rule, ip, "connection timed out".to_string()));
            }
        }
    }
    if let Some((rule, ip, why)) = first_failure {
        return Err(unreachable_decision(cx, &rule, Some(ip), &why).await);
    }
    match first_refusal {
        Some((rule, ip)) => {
            cx.record_best_effort(false, rule.clone(), Some(ip)).await;
            Err(cx.refused(&rule))
        }
        None => Err(unreachable_decision(cx, &name_rule, None, "the name has no addresses").await),
    }
}

async fn unreachable_decision(cx: &Ctx<'_>, rule: &str, ip: Option<IpAddr>, why: &str) -> (&'static str, String) {
    cx.record_best_effort(true, format!("{rule} (unreachable: {why})"), ip).await;
    cx.unreachable(why)
}

/// Answers a check (see *Checks*): the decision `open_upstream` would make, without connecting.
async fn check(client: &mut TcpStream, cx: &Ctx<'_>, policy: &Policy, slot: OwnedSemaphorePermit) {
    let name = policy.check_name(cx.host, cx.port);
    if !name.allowed {
        cx.observe_refusal(None);
    }
    // A vetoed destination is answered as `open_upstream` answers it, without a lookup.
    if name.allowed {
        if let Some(rule) = cx.veto(None, None) {
            let (status, body) = cx.vetoed(&rule, None, None).await;
            return answer(client, cx.shared, slot, status, "", &body).await;
        }
    }
    let found = if name.allowed {
        let addrs = match cx.host.parse::<IpAddr>() {
            Ok(ip) => Ok(vec![ip]),
            Err(_) => resolve(cx).await,
        };
        // The first address the policy allows, else the first refusal.
        addrs.and_then(|addrs| {
            let mut checked =
                addrs.into_iter().map(|ip| (cx.shared.check_addr(policy, cx.host, cx.port, ip, &name.rule), Some(ip)));
            let first = checked.next().ok_or("the name has no addresses")?;
            Ok(if first.0.allowed { first } else { checked.find(|(v, _)| v.allowed).unwrap_or(first) })
        })
    } else {
        Ok((name.clone(), None))
    };
    // The address the connect would use is asked of the veto too, as `open_upstream` asks it.
    if let Ok((v, Some(ip))) = &found {
        if v.allowed {
            if let Some(rule) = cx.veto(Some(*ip), None) {
                let (status, body) = cx.vetoed(&rule, Some(*ip), None).await;
                return answer(client, cx.shared, slot, status, "", &body).await;
            }
        }
    }
    let (allowed, rule, resolved, (status, body)) = match found {
        Ok((v, ip)) if v.allowed => {
            let body = format!("loom network policy: a connection to {} is allowed by rule `{}`.\n", cx.dest(), v.rule);
            (true, v.rule, ip, ("200 OK", body))
        }
        Ok((v, ip)) => (false, v.rule.clone(), ip, cx.refused(&v.rule)),
        Err(why) => (true, format!("{} (unreachable: {why})", name.rule), None, cx.unreachable(&why)),
    };
    let header: String = rule.chars().map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '?' }).collect();
    cx.record_best_effort(allowed, format!("{rule} (check only)"), resolved).await;
    answer(client, cx.shared, slot, status, &format!("{RULE_HEADER}: {header}\r\n"), &body).await;
}

/// Answers a request of a session that the proxy rejects itself with 400, after auditing it.
async fn reject(
    client: &mut TcpStream,
    shared: &Shared,
    slot: OwnedSemaphorePermit,
    session: &SessionId,
    head: &Head,
    why: &str,
) {
    audit_local(shared, Some(session), local_decision(Some(head), &format!("bad request: {why}"))).await;
    bad_request(client, shared, slot, why).await;
}

/// Answers `407` to a request whose credentials are missing, unknown, or of no use on this listener.
async fn unauthorized(client: &mut TcpStream, shared: &Shared, slot: OwnedSemaphorePermit) {
    let body = "loom proxy: missing or unknown proxy credentials. Use the proxy settings from the command's environment (HTTP_PROXY / HTTPS_PROXY), which carry this session's credentials.\n";
    let challenge = "Proxy-Authenticate: Basic realm=\"loom\"\r\n";
    answer(client, shared, slot, "407 Proxy Authentication Required", challenge, body).await;
}

/// A decoy user was presented (E4d): the hook runs first (so the event exists before any answer is written), then
/// the attempt is recorded, attributed to the session whose listener received it and never counted against the
/// limit of unattributed answers, as an unknown user's: nothing on the record or in the answer tells a client
/// that the user was a decoy.
async fn canary_used(shared: &Arc<Shared>, origin: &Origin, head: &Head, user: String, label: String) {
    let listener = match origin {
        Origin::Shared => None,
        Origin::Session(l) => Some(l.clone()),
    };
    let (host, port) = destination(head).unwrap_or_else(|| ("-".to_string(), 0));
    let hit = CanaryHit { user, label, listener: listener.clone(), method: cut(&head.method, 32), host, port };
    let hook = lock(&shared.hooks).canary.clone();
    if let Some(hook) = hook {
        let _ = tokio::task::spawn_blocking(move || hook(&hit)).await;
    }
    let d = local_decision(Some(head), "proxy authentication failed: unknown user");
    if let Err(e) = audit_decision(shared, listener.as_ref(), d, false).await {
        tracing::warn!("cannot write the egress audit record of a rejected request: {e}");
    }
}

/// Serves one connection. It is pending (`id`, closed through `evicted`) until its head is complete.
async fn handle(
    mut client: TcpStream,
    shared: Arc<Shared>,
    cancel: CancellationToken,
    id: u64,
    evicted: CancellationToken,
    origin: Origin,
) {
    let _ = client.set_nodelay(true);
    let pending = PendingGuard { shared: &shared, id };
    let wait = shared.limits.head_timeout;
    let read = tokio::select! {
        r = tokio::time::timeout(wait, read_head(&mut client)) => r,
        _ = evicted.cancelled() => return,
        _ = cancel.cancelled() => return,
    };
    // From here the connection holds its slot itself; when a newer one was given it meanwhile, it ends.
    let Some(slot) = pending.claim() else { return };
    let (head, extra) = match read {
        Err(_) => {
            let why = format!("no complete request head arrived within {}", human(wait));
            audit_local(&shared, None, local_decision(None, &format!("bad request: {why}"))).await;
            return bad_request(&mut client, &shared, slot, &why).await;
        }
        Ok(Err(HeadError::Closed)) => return,
        Ok(Err(HeadError::Bad(m))) => {
            audit_local(&shared, None, local_decision(None, &format!("bad request: {m}"))).await;
            return bad_request(&mut client, &shared, slot, &m).await;
        }
        Ok(Ok(x)) => x,
    };
    let auth = match authenticate(&shared, &head) {
        Ok(a) => a,
        Err(AuthError::Failed(why)) => {
            let rule = format!("proxy authentication failed: {why}");
            audit_local(&shared, None, local_decision(Some(&head), &rule)).await;
            return unauthorized(&mut client, &shared, slot).await;
        }
        Err(AuthError::Canary { user, label }) => {
            canary_used(&shared, &origin, &head, user, label).await;
            return unauthorized(&mut client, &shared, slot).await;
        }
    };
    // Cuts made from here on end the connection once it is registered (see `Proxy::cut`).
    let seen = shared.cut_seq.load(Ordering::SeqCst);
    let Authed { reference, session, policy, permits, lookups } = auth;
    // Command credentials count only on their own session's listener, reference ones only on the shared
    // one; nothing else of the request is acted on before this.
    let wrong_port = match (&origin, reference) {
        (Origin::Shared, true) => None,
        (Origin::Session(l), false) if *l == session => None,
        (Origin::Shared, false) => Some(format!("credentials of session {} on the shared port", session.as_str())),
        (Origin::Session(l), true) => Some(format!("reference credentials on the port of session {}", l.as_str())),
        (Origin::Session(l), false) => {
            Some(format!("credentials of session {} on the port of session {}", session.as_str(), l.as_str()))
        }
    };
    if let Some(why) = wrong_port {
        let rule = format!("proxy authentication failed: {why}");
        let listener_session = match &origin {
            Origin::Shared => None,
            Origin::Session(l) => Some(l),
        };
        audit_local(&shared, listener_session, local_decision(Some(&head), &rule)).await;
        return unauthorized(&mut client, &shared, slot).await;
    }
    if reference && !matches!(head.method.as_str(), "GET" | "CONNECT" | CHECK_METHOD) {
        return reject(
            &mut client,
            &shared,
            slot,
            &session,
            &head,
            "reference credentials allow GET only; use an active scope grant for other methods",
        )
        .await;
    }
    let Ok(_session_slot) = permits.try_acquire_owned() else {
        let body = format!(
            "loom proxy: this session already has {} open proxy connections, the limit. Let running requests finish before starting more.\n",
            shared.limits.max_per_session
        );
        audit_local(&shared, Some(&session), local_decision(Some(&head), "connection limit (per session)")).await;
        return answer(&mut client, &shared, slot, "429 Too Many Requests", "Retry-After: 5\r\n", &body).await;
    };
    let connect = head.method == "CONNECT";
    if connect || head.method == CHECK_METHOD {
        // A check may name its destination as an absolute http:// URI, which HTTP clients send as is.
        let dest = match head.target.get(..7) {
            Some(s) if !connect && s.eq_ignore_ascii_case("http://") => {
                plain_target(&head.target).map(|(host, port, _, _)| (host, port))
            }
            _ => parse_authority(&head.target, None),
        };
        match dest {
            Ok((host, port)) => {
                let (shared, session, lookups) = (&*shared, &session, &lookups);
                let method = if connect { "CONNECT" } else { CHECK_METHOD };
                let cx = Ctx { shared, session, lookups, method, host: &host, port };
                if connect {
                    let live = LiveGuard::register(shared, session, &host, port, seen);
                    let policy = current_policy(shared, session, reference, policy);
                    tunnel(client, extra, &cx, &policy, slot, cancel, live.cut.clone()).await;
                } else {
                    check(&mut client, &cx, &policy, slot).await;
                }
            }
            Err(m) => reject(&mut client, &shared, slot, &session, &head, &m).await,
        }
        return;
    }
    let lower = head.target.get(..8).map(str::to_ascii_lowercase);
    if lower.as_deref() == Some("https://") {
        let why = "https:// absolute URIs are not proxied; use CONNECT host:443 for https";
        return reject(&mut client, &shared, slot, &session, &head, why).await;
    }
    if !matches!(head.target.get(..7), Some(p) if p.eq_ignore_ascii_case("http://")) {
        let why = "the request target is not an absolute http:// URI or a CONNECT destination";
        return reject(&mut client, &shared, slot, &session, &head, why).await;
    }
    match plain_target(&head.target) {
        Ok((host, port, authority, path)) => {
            let (shared, session, lookups) = (&*shared, &session, &lookups);
            let cx = Ctx { shared, session, lookups, method: &head.method, host: &host, port };
            let live = LiveGuard::register(shared, session, &host, port, seen);
            let cut = live.cut.clone();
            let policy = current_policy(shared, session, reference, policy);
            forward(client, extra, &head, &cx, &policy, &authority, &path, reference, slot, cancel, cut).await;
        }
        Err(m) => reject(&mut client, &shared, slot, &session, &head, &m).await,
    }
}

/// Splits `http://authority/path` into (host, port, authority as written, origin-form path).
fn plain_target(target: &str) -> Result<(String, u16, String, String), String> {
    let rest = target.get(7..).ok_or("the request target is too short")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (host, port) = parse_authority(authority, Some(80))?;
    let tail = tail.split('#').next().unwrap_or("");
    let path = if tail.is_empty() {
        "/".to_string()
    } else if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };
    Ok((host, port, authority.to_string(), path))
}

/// What the first flight of a tunnel's client came to (see `bind_sni`).
enum Bound {
    /// Relay it: the bytes read so far, and the server name when it was not the destination's own name.
    Pass(Vec<u8>, Option<String>),
    /// Refuse the tunnel: the rule and the server name read, if any.
    Refused(String, Option<String>),
    /// Nothing came for the idle period.
    Idle(Duration),
}

/// Binds a tunnel to the name it was opened for (E4c): the proxy reads the client's first flight before one byte
/// goes upstream. A flight that is not TLS passes as it is (there is no name to bind); a TLS ClientHello passes
/// when its server name is the destination or another name the policy allows and the veto lets through, and is
/// refused when it carries an encrypted-ClientHello extension, cannot be read, or has no name for a destination
/// that is a name. A server that speaks first (an SSH banner) ends the wait.
async fn bind_sni(client: &mut TcpStream, up: &TcpStream, mut first: Vec<u8>, cx: &Ctx<'_>, policy: &Policy) -> Bound {
    let limits = &cx.shared.limits;
    let mut buf = vec![0u8; 4096];
    loop {
        match clienthello::parse(&first) {
            Hello::NotTls => return Bound::Pass(first, None),
            Hello::Malformed(why) => {
                return Bound::Refused(format!("deny a TLS ClientHello that cannot be read ({why})"), None)
            }
            Hello::Tls { sni, ech } => return judge_sni(first, sni, ech, cx, policy),
            Hello::Empty | Hello::Incomplete => {}
        }
        if first.len() >= clienthello::MAX_HELLO {
            return Bound::Refused("deny a TLS ClientHello larger than a ClientHello can be".to_string(), None);
        }
        let waiting = first.is_empty();
        let wait = if waiting { limits.idle_timeout } else { limits.head_timeout };
        let read = tokio::select! {
            r = tokio::time::timeout(wait, client.read(&mut buf)) => r,
            // A server that speaks first is not a TLS server: nothing to bind.
            _ = up.readable(), if waiting => return Bound::Pass(first, None),
        };
        match read {
            Err(_) if waiting => return Bound::Idle(wait),
            Err(_) => {
                let rule = format!("deny a TLS ClientHello that did not arrive in full within {}", human(wait));
                return Bound::Refused(rule, None);
            }
            // Nothing was said: the relay sees the client's end as it always has.
            Ok(Ok(0)) if waiting => return Bound::Pass(first, None),
            // The client ended in the middle of its hello: what it sent is not relayed as a name-bound flight.
            Ok(Ok(0)) => {
                return Bound::Refused("deny a TLS ClientHello that ended before it was complete".to_string(), None)
            }
            Ok(Ok(n)) => first.extend_from_slice(buf.get(..n).unwrap_or(&[])),
            Ok(Err(_)) => return Bound::Pass(first, None),
        }
    }
}

/// The verdict on a complete ClientHello of a tunnel to `cx.host`.
fn judge_sni(first: Vec<u8>, sni: Option<String>, ech: bool, cx: &Ctx<'_>, policy: &Policy) -> Bound {
    // Chromium sends a placeholder encrypted-ClientHello extension (GREASE) on every hello, with the real name in the
    // clear: that one names the destination and passes. Any other hello that carries the extension is refused,
    // because the proxy cannot tell a placeholder from a real one whose inner name is hidden.
    let names_the_destination = sni.as_deref().is_some_and(|n| normalize_host(n) == normalize_host(cx.host));
    if ech && !names_the_destination {
        cx.observe_refusal(sni.as_deref());
        let rule = "deny an encrypted ClientHello whose outer server name is not the destination: the server name is hidden from the proxy (browsers send a placeholder extension with the destination's own name, which passes)".to_string();
        return Bound::Refused(rule, sni);
    }
    let literal = cx.host.parse::<IpAddr>().is_ok();
    let Some(name) = sni else {
        return if literal {
            Bound::Pass(first, None)
        } else {
            Bound::Refused(format!("deny a TLS connection without a server name to the name {}", cx.host), None)
        };
    };
    let name = normalize_host(&name);
    if name == normalize_host(cx.host) {
        return Bound::Pass(first, None);
    }
    let verdict = policy.check_name(&name, cx.port);
    if !verdict.allowed {
        cx.observe_refusal(Some(&name));
        let rule = format!("deny the server name {name}, which is not the destination {}: {}", cx.host, verdict.rule);
        return Bound::Refused(rule, Some(name));
    }
    if let Some(rule) = cx.veto(None, Some(&name)) {
        return Bound::Refused(format!("vetoed: {rule}"), Some(name));
    }
    Bound::Pass(first, Some(name))
}

/// How a tunnel's relay phase ended.
enum Phase {
    Relayed(RelayEnd),
    Refused(String, Option<String>),
    Idle(Duration),
    UpstreamWrite,
}

async fn tunnel(
    mut client: TcpStream,
    extra: Vec<u8>,
    cx: &Ctx<'_>,
    policy: &Policy,
    slot: OwnedSemaphorePermit,
    cancel: CancellationToken,
    cut: Cut,
) {
    let idle = cx.shared.limits.idle_timeout;
    let (mut up, allowed) = match open_upstream(cx, policy).await {
        Ok(s) => s,
        Err((status, body)) => return answer(&mut client, cx.shared, slot, status, "", &body).await,
    };
    let _slot = slot;
    if cut.is_cancelled() {
        return cx.failed_after_allow(&allowed, cut.why()).await;
    }
    if client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return cx.failed_after_allow(&allowed, "the client closed the connection before the tunnel was open").await;
    }
    let phase = tokio::select! {
        phase = async {
            let first = match bind_sni(&mut client, &up, extra, cx, policy).await {
                Bound::Pass(first, sni) => {
                    if let Some(name) = sni {
                        let rule = format!("{} (sni {name}, another name the policy allows)", allowed.rule);
                        cx.record_best_effort_sni(true, rule, Some(allowed.ip), Some(name)).await;
                    }
                    first
                }
                Bound::Refused(rule, sni) => return Phase::Refused(rule, sni),
                Bound::Idle(after) => return Phase::Idle(after),
            };
            if !first.is_empty() && !write_within(&mut up, &first, idle).await {
                return Phase::UpstreamWrite;
            }
            Phase::Relayed(relay(&mut client, &mut up, idle, None).await)
        } => phase,
        _ = cancel.cancelled() => return cx.failed_after_allow(&allowed, SHUTDOWN).await,
        _ = cut.cancelled() => return cx.failed_after_allow(&allowed, cut.why()).await,
    };
    let end = match phase {
        Phase::Relayed(end) => end,
        Phase::Refused(rule, sni) => {
            // Nothing was sent upstream. The refusal follows the allow, so the trail never ends at a bare allow.
            cx.record_best_effort_sni(false, rule, Some(allowed.ip), sni).await;
            return;
        }
        Phase::Idle(after) => {
            let why = format!("the tunnel was idle for {} before the destination sent a byte", human(after));
            return cx.failed_after_allow(&allowed, &why).await;
        }
        Phase::UpstreamWrite => {
            let why = "the bytes the client sent ahead could not be written to the destination";
            return cx.failed_after_allow(&allowed, why).await;
        }
    };
    // Once bytes have come from the destination, a failure cannot be told from a routine close.
    let why = match end {
        RelayEnd::Done(false) => "the tunnel closed".to_string(),
        RelayEnd::Failed(why, false) => why.to_string(),
        RelayEnd::Idle(false, after) => format!("the tunnel was idle for {}", human(after)),
        RelayEnd::Done(true) | RelayEnd::Failed(_, true) | RelayEnd::Idle(true, _) | RelayEnd::BadUpstream(..) => {
            return
        }
    };
    cx.failed_after_allow(&allowed, &format!("{why} before the destination sent a byte")).await;
}

/// Writes all of `bytes` within `idle`; false when the peer is gone or too slow.
async fn write_within<W: AsyncWriteExt + Unpin>(w: &mut W, bytes: &[u8], idle: Duration) -> bool {
    matches!(tokio::time::timeout(idle, w.write_all(bytes)).await, Ok(Ok(())))
}

/// How the request body of a forwarded request is framed.
enum Body {
    None,
    Length(u64),
    /// Chunked: relay up to the last chunk and its trailers.
    Chunked,
    /// Another transfer coding, unframed by length: relay until the client stops sending.
    Stream,
}

fn body_kind(head: &Head) -> Result<Body, String> {
    let mut length: Option<u64> = None;
    let mut coding: Option<&[u8]> = None;
    for (n, v) in &head.headers {
        if n.eq_ignore_ascii_case("content-length") {
            let parsed = std::str::from_utf8(v)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or("the Content-Length header is not a number")?;
            if length.is_some_and(|l| l != parsed) {
                return Err("the request has conflicting Content-Length headers".into());
            }
            length = Some(parsed);
        } else if n.eq_ignore_ascii_case("transfer-encoding") {
            coding = Some(v);
        }
    }
    match (length, coding) {
        (Some(_), Some(_)) => Err("the request has both Content-Length and Transfer-Encoding".into()),
        (Some(n), None) => Ok(Body::Length(n)),
        (None, Some(v)) if ends_chunked(v) => Ok(Body::Chunked),
        (None, Some(_)) => Ok(Body::Stream),
        (None, None) => Ok(Body::None),
    }
}

/// Whether the value of the last `Transfer-Encoding` header makes the body chunked: its last coding is
/// `chunked` (as hyper reads it).
fn ends_chunked(value: &[u8]) -> bool {
    value.rsplit(|b| *b == b',').next().is_some_and(|c| c.trim_ascii().eq_ignore_ascii_case(b"chunked"))
}

/// Whether bytes a client sent after its request are more than the empty lines some clients add after
/// a body.
fn further_request(past: &[u8]) -> bool {
    past.iter().any(|b| !matches!(b, b'\r' | b'\n'))
}

/// Follows the framing of a chunked body to find where it ends, as leniently as common HTTP clients
/// read it; the bytes themselves are passed on unchanged.
#[derive(Clone, Copy)]
enum Chunked {
    /// In a chunk-size line, before or in the size: the size so far, and whether a digit was read.
    Size(u64, bool),
    /// In a chunk-size line after the size (extensions, spaces) up to the line end: the size.
    Line(u64),
    /// In the data of a chunk: the bytes still to come.
    Data(u64),
    /// After the data of a chunk, before its line end.
    DataEnd,
    /// In the trailer section after the last chunk; whether the current line is still empty.
    Trailer(bool),
    /// The body has ended.
    Done,
}

impl Chunked {
    fn new() -> Self {
        Chunked::Size(0, false)
    }

    fn done(&self) -> bool {
        matches!(self, Chunked::Done)
    }

    /// Takes the next bytes; returns how many of them belong to the body (all of them until it ends).
    fn feed(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        let mut used = 0usize;
        loop {
            let rest = data.get(used..).unwrap_or(&[]);
            let Some(&b) = rest.first() else { return Ok(used) };
            let n = match *self {
                Chunked::Done => return Ok(used),
                Chunked::Data(left) => {
                    let k = usize::try_from(left).map_or(rest.len(), |l| l.min(rest.len()));
                    let left = left.saturating_sub(k as u64);
                    *self = if left == 0 { Chunked::DataEnd } else { Chunked::Data(left) };
                    k
                }
                state => {
                    *self = state.step(b)?;
                    1
                }
            };
            used = used.saturating_add(n);
        }
    }

    /// The state after one byte outside chunk data.
    fn step(self, b: u8) -> Result<Chunked, &'static str> {
        if let (Chunked::Size(size, _), Some(d)) = (self, char::from(b).to_digit(16)) {
            let size = size.checked_mul(16).and_then(|s| s.checked_add(u64::from(d)));
            return Ok(Chunked::Size(size.ok_or("a chunk size is too large")?, true));
        }
        Ok(match (self, b) {
            (Chunked::Size(_, false), b' ' | b'\t') => self,
            (Chunked::Size(_, false), _) => return Err("a chunk does not start with its size"),
            (Chunked::Size(0, true) | Chunked::Line(0), b'\n') => Chunked::Trailer(true),
            (Chunked::Size(size, true) | Chunked::Line(size), b'\n') => Chunked::Data(size),
            (Chunked::Size(size, true) | Chunked::Line(size), _) => Chunked::Line(size),
            (Chunked::DataEnd, b'\r') => self,
            (Chunked::DataEnd, b'\n') => Chunked::new(),
            (Chunked::DataEnd, _) => return Err("the data of a chunk is not followed by a line end"),
            (Chunked::Trailer(true), b'\n') => Chunked::Done,
            (Chunked::Trailer(_), b'\n') => Chunked::Trailer(true),
            (Chunked::Trailer(empty), b'\r') => Chunked::Trailer(empty),
            (Chunked::Trailer(_), _) => Chunked::Trailer(false),
            (Chunked::Data(_) | Chunked::Done, _) => self,
        })
    }
}

/// What is still to come of the request body of a forwarded request.
enum Owed {
    /// This many bytes.
    Bytes(u64),
    /// The rest of a chunked body.
    Chunked(Chunked),
    /// Everything until the client stops sending.
    Stream,
}

impl Owed {
    /// How many of `data`, the client's next bytes, belong to the body; the rest come after it.
    fn take(&mut self, data: &[u8]) -> usize {
        match self {
            Owed::Bytes(left) => {
                let k = usize::try_from(*left).map_or(data.len(), |l| l.min(data.len()));
                *left = left.saturating_sub(k as u64);
                k
            }
            Owed::Chunked(c) => match c.feed(data) {
                Ok(k) => k,
                // A body the proxy cannot follow is passed on whole, for the destination to judge.
                Err(_) => {
                    *self = Owed::Stream;
                    data.len()
                }
            },
            Owed::Stream => data.len(),
        }
    }
}

/// Response heads from the destination, written again without any `X-Loom-Proxy` header (see
/// [`response_head`]). Interim (1xx) heads are treated the same way. The body after the final head is
/// passed on up to the end that head gives it; bytes after that end are dropped.
struct HeadFilter {
    buf: Vec<u8>,
    /// The request was `HEAD`: the response has no body whatever its headers say.
    head_request: bool,
    /// How the body after the final head is framed; `None` until that head has been read.
    body: Option<Framing>,
}

/// How the body of a response is framed.
enum Framing {
    /// Bytes still to come (none for a response without a body).
    Length(u64),
    Chunked(Chunked),
    /// Everything until the destination closes.
    UntilClose,
}

impl HeadFilter {
    fn new(head_request: bool) -> Self {
        Self { buf: Vec::new(), head_request, body: None }
    }

    /// The final head has been read.
    fn head_done(&self) -> bool {
        self.body.is_some()
    }

    /// The response is complete; nothing further from the destination is relayed.
    fn finished(&self) -> bool {
        match &self.body {
            Some(Framing::Length(left)) => *left == 0,
            Some(Framing::Chunked(c)) => c.done(),
            Some(Framing::UntilClose) | None => false,
        }
    }

    /// The final head has been read and the body runs until the destination closes.
    fn until_close(&self) -> bool {
        matches!(self.body, Some(Framing::UntilClose))
    }

    /// Takes the next bytes from the destination; returns what may be sent to the client now.
    fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        if self.body.is_some() {
            return self.pass(data);
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        while let Some(h) = response_head(&self.buf, self.head_request)? {
            out.extend_from_slice(&h.head);
            self.buf.drain(..h.len.min(self.buf.len()));
            if let Some(framing) = h.body {
                self.body = Some(framing);
                let rest = std::mem::take(&mut self.buf);
                out.append(&mut self.pass(&rest)?);
                return Ok(out);
            }
        }
        if self.buf.len() > MAX_HEAD {
            return Err(format!("the destination sent a response head larger than {} KiB", MAX_HEAD / 1024));
        }
        Ok(out)
    }

    /// The bytes of `data`, which follow the final head, that belong to the body.
    fn pass(&mut self, data: &[u8]) -> Result<Vec<u8>, String> {
        let k = match &mut self.body {
            Some(Framing::Length(left)) => {
                let k = usize::try_from(*left).map_or(data.len(), |l| l.min(data.len()));
                *left = left.saturating_sub(k as u64);
                k
            }
            Some(Framing::Chunked(c)) => {
                c.feed(data).map_err(|m| format!("the destination's chunked response is malformed ({m})"))?
            }
            Some(Framing::UntilClose) | None => data.len(),
        };
        Ok(data.get(..k).unwrap_or(&[]).to_vec())
    }
}

/// A response head read from the destination.
struct RespHead {
    /// The head written again with CRLF line ends and without `X-Loom-Proxy` headers. A final head
    /// has no `Connection`, `Keep-Alive` or `Proxy-Connection` header of the destination, no
    /// `Content-Length` when it has a `Transfer-Encoding`, and ends in `Connection: close`.
    head: Vec<u8>,
    /// Its length in the buffer it was read from.
    len: usize,
    /// For a final head, how the body after it is framed; `None` for an interim (1xx) head.
    body: Option<Framing>,
}

/// The body length that the `Content-Length` headers give, read as hyper reads them: `None` when
/// there is none, an error when a value is not a number or two differ.
fn content_length(headers: &[httparse::Header<'_>]) -> Result<Option<u64>, String> {
    let mut length = None;
    for h in headers.iter().filter(|h| h.name.eq_ignore_ascii_case("content-length")) {
        for v in h.value.split(|b| *b == b',').map(<[u8]>::trim_ascii) {
            let n = std::str::from_utf8(v).ok().filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()));
            match (n.and_then(|n| n.parse::<u64>().ok()), length) {
                (Some(n), None) => length = Some(n),
                (Some(n), Some(l)) if n == l => {}
                _ => return Err("the destination's response has an invalid or conflicting Content-Length".into()),
            }
        }
    }
    Ok(length)
}

/// The response head at the start of `buf`, parsed as an HTTP client parses it, for a request that
/// was `HEAD` or not. `None` while it is incomplete.
fn response_head(buf: &[u8], head_request: bool) -> Result<Option<RespHead>, String> {
    let mut headers = vec![httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let parsed = httparse::ParserConfig::default()
        .allow_obsolete_multiline_headers_in_responses(true)
        .allow_spaces_after_header_name_in_responses(true)
        .allow_multiple_spaces_in_response_status_delimiters(true)
        .parse_response(&mut resp, buf);
    let n = match parsed {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(format!("the destination did not answer with a valid HTTP response ({e})")),
    };
    let (Some(version), Some(code)) = (resp.version, resp.code) else {
        return Err("the destination did not answer with a valid HTTP response".into());
    };
    let is_final = !(100..200).contains(&code) || code == 101;
    let coding = resp.headers.iter().rev().find(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));
    let body = if !is_final {
        None
    } else if head_request || matches!(code, 204 | 304) {
        Some(Framing::Length(0))
    } else if code == 101 {
        Some(Framing::UntilClose)
    } else if let Some(c) = coding {
        Some(if ends_chunked(c.value) { Framing::Chunked(Chunked::new()) } else { Framing::UntilClose })
    } else {
        Some(content_length(resp.headers)?.map_or(Framing::UntilClose, Framing::Length))
    };
    let dropped = |name: &str| {
        let connection = ["connection", "keep-alive", "proxy-connection"].iter().any(|d| name.eq_ignore_ascii_case(d));
        is_final && (connection || (coding.is_some() && name.eq_ignore_ascii_case("content-length")))
    };
    let mut head = format!("HTTP/1.{version} {code} {}\r\n", resp.reason.unwrap_or("")).into_bytes();
    for h in resp.headers.iter().filter(|h| !h.name.eq_ignore_ascii_case(MARKER) && !dropped(h.name)) {
        head.extend_from_slice(h.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(h.value);
        head.extend_from_slice(b"\r\n");
    }
    if is_final {
        head.extend_from_slice(b"Connection: close\r\n");
    }
    head.extend_from_slice(b"\r\n");
    Ok(Some(RespHead { head, len: n, body }))
}

/// What the relay of a forwarded request needs.
struct Fwd {
    /// What the client still owes of the request body.
    owed: Owed,
    /// The client sent more than its request together with it (see [`further_request`]).
    further: bool,
    /// After the client has ended its side, how long a silent destination is waited for.
    grace: Duration,
    /// The request method is `HEAD`.
    head_request: bool,
}

/// How a relay ended. The flag says whether anything from the destination had been sent to the client.
enum RelayEnd {
    /// Both sides are done (a forwarded request: the response ended).
    Done(bool),
    /// A peer failed, or the client sent too much: why.
    Failed(&'static str, bool),
    /// No byte moved for the period given; whether anything had been sent to the client.
    Idle(bool, Duration),
    /// The destination's response was unusable; whether anything had been sent to the client.
    BadUpstream(String, bool),
}

/// What the two directions of a relay share.
struct Flow {
    start: tokio::time::Instant,
    /// When a byte last moved in either direction, in milliseconds after `start`.
    last_ms: AtomicU64,
    /// The client of a forwarded request has ended its side.
    client_done: AtomicBool,
    /// The client of a forwarded request sent more than its request (see [`further_request`]).
    extra_request: AtomicBool,
    /// The head of a forwarded response whose body runs until the destination closes has been relayed.
    until_close: AtomicBool,
    /// Something has been sent to the client.
    wrote: AtomicBool,
}

impl Flow {
    /// Notes that the client sent more than its request; true when the response runs until the
    /// destination closes and its head has been relayed, so the relay ends now. The two sides note
    /// their part and read the other's in the opposite order, so at least one of them sees both.
    fn client_sent_more(&self) -> bool {
        self.extra_request.store(true, Ordering::SeqCst);
        self.until_close.load(Ordering::SeqCst)
    }

    /// Notes that the head of a response that runs until the destination closes has been relayed; true
    /// when the client has sent more than its request, so the relay ends now.
    fn response_until_close(&self) -> bool {
        self.until_close.store(true, Ordering::SeqCst);
        self.extra_request.load(Ordering::SeqCst)
    }

    fn touch(&self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.fetch_max(ms, Ordering::Relaxed);
    }

    fn last(&self) -> tokio::time::Instant {
        let ms = Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        self.start.checked_add(ms).unwrap_or(self.start)
    }
}

/// How one direction of a relay ended.
enum Pump {
    /// Its source ended cleanly.
    Ended,
    /// The relay must stop: a peer failed, or the client sent too much; why.
    Stop(&'static str),
    /// The destination's response was unusable.
    Bad(String),
    /// The client of a forwarded request sent more than its request while the response runs until the
    /// destination closes: nothing more is relayed.
    Cut,
}

/// Writes all of `bytes`, counting each partial write as activity.
async fn write_counted(w: &mut WriteHalf<'_>, mut bytes: &[u8], flow: &Flow) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let n = w.write(bytes).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        flow.touch();
        bytes = bytes.get(n..).unwrap_or(&[]);
    }
    Ok(())
}

/// Client to destination. A tunnel passes the client's end on. With `forward` (what the client of a
/// forwarded request still owes of its body) bytes past the body are discarded and noted in `flow`,
/// the client's end is noted in `flow`, and a destination that stops reading does not end the relay.
async fn upload(r: &mut ReadHalf<'_>, w: &mut WriteHalf<'_>, flow: &Flow, mut forward: Option<Owed>) -> Pump {
    let mut buf = vec![0u8; 16 * 1024];
    let mut sending = true;
    let mut discarded = 0usize;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            Err(_) => return Pump::Stop("the client's connection failed"),
        };
        flow.touch();
        if n == 0 {
            if forward.is_some() {
                flow.client_done.store(true, Ordering::Relaxed);
            } else {
                let _ = w.shutdown().await;
            }
            return Pump::Ended;
        }
        let data = buf.get(..n).unwrap_or(&[]);
        let body = forward.as_mut().map_or(n, |owed| owed.take(data));
        let more = further_request(data.get(body..).unwrap_or(&[]));
        let take = if sending { body } else { 0 };
        discarded = discarded.saturating_add(n.saturating_sub(take));
        if discarded > MAX_DISCARD {
            return Pump::Stop("the client sent more than 1 MiB past the request body");
        }
        if take > 0 && write_counted(w, data.get(..take).unwrap_or(&[]), flow).await.is_err() {
            if forward.is_none() {
                return Pump::Stop("writing to the destination failed");
            }
            // The destination stopped reading; its answer may still come.
            sending = false;
        }
        // A further request on a connection that carries one: no later destination bytes may be read as
        // its answer.
        if more && flow.client_sent_more() {
            return Pump::Cut;
        }
    }
}

/// Destination to client. A tunnel passes the destination's end on. With `filter` (a forwarded
/// request) the response head is filtered, an end before the head is complete is `Bad`, and the
/// relay ends at the end of the response, or after its head when the response runs until the
/// destination closes and the client has sent more than its request.
async fn download(r: &mut ReadHalf<'_>, w: &mut WriteHalf<'_>, flow: &Flow, mut filter: Option<HeadFilter>) -> Pump {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let read = r.read(&mut buf).await;
        let head_pending = filter.as_ref().is_some_and(|f| !f.head_done());
        let n = match read {
            Ok(0) | Err(_) if head_pending => {
                return Pump::Bad("the destination closed the connection before it answered".to_string())
            }
            Ok(0) => {
                let _ = w.shutdown().await;
                return Pump::Ended;
            }
            Ok(n) => n,
            Err(_) => return Pump::Stop("the connection to the destination failed"),
        };
        flow.touch();
        let chunk = buf.get(..n).unwrap_or(&[]);
        let out = match filter.as_mut() {
            Some(f) => match f.push(chunk) {
                Ok(v) => Cow::Owned(v),
                Err(m) => return Pump::Bad(m),
            },
            None => Cow::Borrowed(chunk),
        };
        if !out.is_empty() {
            flow.wrote.store(true, Ordering::Relaxed);
            if write_counted(w, &out, flow).await.is_err() {
                return Pump::Stop("writing to the client failed");
            }
        }
        // One request, one response: what follows its end is not relayed.
        let over = filter.as_ref().is_some_and(|f| f.finished() || (f.until_close() && flow.response_until_close()));
        if over {
            let _ = w.shutdown().await;
            return Pump::Ended;
        }
    }
}

/// Ends when no byte has moved for `idle`, or for `grace` once the client of a forwarded request has
/// ended its side; returns the period that passed.
async fn watchdog(flow: &Flow, idle: Duration, grace: Option<Duration>) -> Duration {
    let step = grace.unwrap_or(idle);
    loop {
        let limit = match grace {
            Some(g) if flow.client_done.load(Ordering::Relaxed) => g,
            _ => idle,
        };
        let now = tokio::time::Instant::now();
        let deadline = flow.last().checked_add(limit).unwrap_or(now);
        if now >= deadline {
            return limit;
        }
        let wake = now.checked_add(step).map_or(deadline, |w| w.min(deadline));
        tokio::time::sleep_until(wake).await;
    }
}

/// Copies bytes both ways, each direction on its own, until both sides are done or no byte has moved
/// in either direction for `idle`. A failing peer ends both.
///
/// With `forward` (a forwarded plain request) the destination's response head is filtered, bytes of
/// the client past the body are discarded, and the relay ends when the response ends (see
/// *Forwarded requests*); after the client has ended its side it also ends when the destination is
/// silent for the grace period.
async fn relay(client: &mut TcpStream, up: &mut TcpStream, idle: Duration, forward: Option<Fwd>) -> RelayEnd {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = up.split();
    let flow = Flow {
        start: tokio::time::Instant::now(),
        last_ms: AtomicU64::new(0),
        client_done: AtomicBool::new(false),
        extra_request: AtomicBool::new(forward.as_ref().is_some_and(|f| f.further)),
        until_close: AtomicBool::new(false),
        wrote: AtomicBool::new(false),
    };
    let is_forward = forward.is_some();
    let (owed, filter, grace) = match forward {
        Some(f) => (Some(f.owed), Some(HeadFilter::new(f.head_request)), Some(f.grace.min(idle))),
        None => (None, None, None),
    };
    let to_up = upload(&mut cr, &mut uw, &flow, owed);
    let to_client = download(&mut ur, &mut cw, &flow, filter);
    let quiet = watchdog(&flow, idle, grace);
    tokio::pin!(to_up, to_client, quiet);
    let wrote = || flow.wrote.load(Ordering::Relaxed);
    let (mut up_open, mut down_open) = (true, true);
    while up_open || down_open {
        tokio::select! {
            r = &mut to_up, if up_open => match r {
                Pump::Ended => up_open = false,
                Pump::Stop(why) => return RelayEnd::Failed(why, wrote()),
                Pump::Bad(_) | Pump::Cut => return RelayEnd::Done(wrote()),
            },
            r = &mut to_client, if down_open => match r {
                Pump::Ended | Pump::Cut if is_forward => return RelayEnd::Done(wrote()),
                Pump::Ended | Pump::Cut => down_open = false,
                Pump::Stop(why) => return RelayEnd::Failed(why, wrote()),
                Pump::Bad(why) => return RelayEnd::BadUpstream(why, wrote()),
            },
            after = &mut quiet => return RelayEnd::Idle(wrote(), after),
        }
    }
    RelayEnd::Done(wrote())
}

#[allow(clippy::too_many_arguments)]
async fn forward(
    mut client: TcpStream,
    extra: Vec<u8>,
    head: &Head,
    cx: &Ctx<'_>,
    policy: &Policy,
    authority: &str,
    path: &str,
    reference: bool,
    slot: OwnedSemaphorePermit,
    cancel: CancellationToken,
    cut: Cut,
) {
    let idle = cx.shared.limits.idle_timeout;
    let body = match body_kind(head) {
        Ok(b) => b,
        Err(m) => return reject(&mut client, cx.shared, slot, cx.session, head, &m).await,
    };
    let (mut up, allowed) = match open_upstream(cx, policy).await {
        Ok(s) => s,
        Err((status, text)) => return answer(&mut client, cx.shared, slot, status, "", &text).await,
    };
    // Cut while the name resolved or the connection opened: nothing is written to the destination.
    if cut.is_cancelled() {
        cx.failed_after_allow(&allowed, cut.why()).await;
        let (status, text) = cx.unreachable(cut.why());
        return answer(&mut client, cx.shared, slot, status, "", &text).await;
    }

    let mut out: Vec<u8> = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", head.method, path, authority).into_bytes();
    for (n, v) in &head.headers {
        let drop = ["proxy-authorization", "proxy-connection", "connection", "keep-alive", "upgrade", "host"]
            .iter()
            .any(|d| n.eq_ignore_ascii_case(d));
        let secret = reference && ["authorization", "cookie", "referer"].iter().any(|x| n.eq_ignore_ascii_case(x));
        if drop || secret {
            continue;
        }
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    // The bytes of the body that arrived with the head, what the client still owes, and what it sent
    // after its request.
    let mut owed = match body {
        Body::None => Owed::Bytes(0),
        Body::Length(n) => Owed::Bytes(n),
        Body::Chunked => Owed::Chunked(Chunked::new()),
        Body::Stream => Owed::Stream,
    };
    let (already, past) = extra.split_at(owed.take(&extra).min(extra.len()));
    out.extend_from_slice(already);
    if !write_within(&mut up, &out, idle).await {
        let why = "sending the request to the destination failed";
        cx.failed_after_allow(&allowed, why).await;
        let (status, text) = cx.unreachable(why);
        return answer(&mut client, cx.shared, slot, status, "", &text).await;
    }

    let fwd = Fwd {
        owed,
        further: further_request(past),
        grace: cx.shared.limits.forward_grace,
        head_request: head.method.eq_ignore_ascii_case("HEAD"),
    };
    let end = tokio::select! {
        r = relay(&mut client, &mut up, idle, Some(fwd)) => r,
        _ = cancel.cancelled() => return cx.failed_after_allow(&allowed, SHUTDOWN).await,
        _ = cut.cancelled() => return cx.failed_after_allow(&allowed, cut.why()).await,
    };
    let (why, reply) = match end {
        RelayEnd::Done(_) => return,
        RelayEnd::Failed(why, wrote) => {
            let when = if wrote { "while the response was relayed" } else { "before the destination answered" };
            (format!("{why} {when}"), None)
        }
        RelayEnd::BadUpstream(why, wrote) => (why.clone(), (!wrote).then(|| cx.unreachable(&why))),
        RelayEnd::Idle(false, after) => {
            (format!("the destination sent no response for {}", human(after)), Some(cx.silent(after)))
        }
        RelayEnd::Idle(true, after) => (format!("the destination's response stalled for {}", human(after)), None),
    };
    cx.failed_after_allow(&allowed, &why).await;
    if let Some((status, text)) = reply {
        answer(&mut client, cx.shared, slot, status, "", &text).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::config::{NetworkCfg, NetworkMode};
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
    use tokio::time::timeout;

    type Rx = UnboundedReceiver<(SessionId, NetDecision)>;
    const T: Duration = Duration::from_secs(5);

    async fn start() -> (Proxy, Rx) {
        let (tx, rx) = unbounded_channel();
        (Proxy::start(0, tx).await.unwrap(), rx)
    }

    type Seen = Arc<Mutex<Vec<(Option<SessionId>, NetDecision)>>>;

    /// A proxy whose audit hook records into the returned list (and fails when `fail` is set).
    async fn start_audited(fail: bool, limits: Limits, resolver: Option<Resolver>) -> (Proxy, Rx, Seen) {
        let (tx, rx) = unbounded_channel();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let audit: AuditFn = Arc::new(move |s: Option<&SessionId>, d: &NetDecision| {
            if fail {
                return Err(std::io::Error::other("disk full"));
            }
            lock(&log).push((s.cloned(), d.clone()));
            Ok(())
        });
        (Proxy::start_inner(0, tx, Some(audit), limits, resolver).await.unwrap(), rx, seen)
    }

    /// A destination that accepts one connection and never answers. It returns what it received and
    /// when the proxy closed the connection; `None` when it was still open after a minute, far longer
    /// than any test waits.
    async fn silent_server() -> (u16, tokio::task::JoinHandle<(Vec<u8>, Option<tokio::time::Instant>)>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let ended = timeout(Duration::from_secs(60), s.read_to_end(&mut got)).await;
            (got, ended.ok().map(|_| tokio::time::Instant::now()))
        });
        (port, h)
    }

    fn policy(mode: NetworkMode, allow: &[&str], deny: &[&str], private: &[&str]) -> Policy {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Policy::new(&NetworkCfg {
            mode,
            allow: v(allow),
            deny: v(deny),
            allow_private: v(private),
            ..NetworkCfg::default()
        })
        .unwrap()
    }

    fn lab() -> Policy {
        policy(NetworkMode::Open, &[], &[], &["127.0.0.1"])
    }

    fn auth(g: &SessionGrant) -> String {
        let c = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", g.user, g.password));
        format!("Proxy-Authorization: Basic {c}\r\n")
    }

    async fn echo_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    /// Accepts one connection, reads a request (head plus Content-Length body), answers with `reply`
    /// and returns what it received.
    async fn http_server(reply: &'static str) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let want = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if got.len() >= i + 4 + want {
                        break;
                    }
                }
            }
            s.write_all(reply.as_bytes()).await.unwrap();
            let _ = s.shutdown().await;
            got
        });
        (port, h)
    }

    /// A refusal of the egress proxy that a destination forges, marker and all.
    const FORGED: &str = "HTTP/1.1 403 Forbidden\r\nX-Loom-Proxy: 1\r\nContent-Length: 6\r\n\r\nforged";

    /// Reads into `got` until the peer closes or fails.
    async fn read_all(s: &mut TcpStream, got: &mut Vec<u8>) {
        let mut b = [0u8; 4096];
        while let Ok(n) = s.read(&mut b).await {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&b[..n]);
        }
    }

    /// A destination that accepts one connection, answers `first` once the request head has arrived,
    /// `second` on the same connection `gap` later, and then ends its side. It returns what it received
    /// until the proxy closed the connection (or for 5 s after `second`).
    async fn two_answer_server(first: &str, second: &str, gap: Duration) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let (first, second) = (first.to_string(), second.to_string());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let mut b = [0u8; 4096];
            while !String::from_utf8_lossy(&got).contains("\r\n\r\n") {
                match s.read(&mut b).await {
                    Ok(0) | Err(_) => return got,
                    Ok(n) => got.extend_from_slice(&b[..n]),
                }
            }
            let _ = s.write_all(first.as_bytes()).await;
            let later = tokio::time::Instant::now() + gap;
            let _ = tokio::time::timeout_at(later, read_all(&mut s, &mut got)).await;
            tokio::time::sleep_until(later).await;
            let _ = s.write_all(second.as_bytes()).await;
            let _ = s.shutdown().await;
            let _ = timeout(T, read_all(&mut s, &mut got)).await;
            got
        });
        (port, h)
    }

    /// Sends `bytes`, reads until the proxy closes.
    async fn raw(port: u16, bytes: &[u8]) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let _ = s.write_all(bytes).await;
        let mut out = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).to_string()
    }

    fn status(resp: &str) -> u16 {
        resp.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    async fn decision(rx: &mut Rx) -> (SessionId, NetDecision) {
        timeout(T, rx.recv()).await.unwrap().unwrap()
    }

    fn no_more(rx: &mut Rx) {
        assert!(rx.try_recv().is_err(), "unexpected extra decision");
    }

    fn connect_req(g: &SessionGrant, dest: &str) -> String {
        format!("CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n{}\r\n", auth(g))
    }

    /// Asks the proxy on `port` for its verdict on `dest`; returns the status and the decision sent.
    async fn check_on(port: u16, g: &SessionGrant, dest: &str, rx: &mut Rx) -> (u16, NetDecision) {
        let r = raw(port, format!("{CHECK_METHOD} {dest} HTTP/1.1\r\n{}\r\n", auth(g)).as_bytes()).await;
        (status(&r), decision(rx).await.1)
    }

    async fn read_until(s: &mut TcpStream, end: &str) -> String {
        let mut got = Vec::new();
        let mut b = [0u8; 1];
        while !String::from_utf8_lossy(&got).ends_with(end) {
            timeout(T, s.read_exact(&mut b)).await.unwrap().unwrap();
            got.push(b[0]);
        }
        String::from_utf8_lossy(&got).to_string()
    }

    #[tokio::test]
    async fn reference_grants_are_separate_strip_headers_and_revoke_with_the_session() {
        let (p, _, seen) = start_audited(false, Limits::default(), None).await;
        let (port, got) = http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let sid = SessionId::from("s-reference");
        let cfg = NetworkCfg {
            mode: NetworkMode::Open,
            reference_hosts: vec![format!("127.0.0.1:{port}")],
            allow_private: vec!["127.0.0.1".into()],
            ..NetworkCfg::default()
        };
        let raw_grant = p.grant(&sid, Policy::new(&cfg).unwrap()).unwrap();
        let reference = p.grant_reference(&sid, &cfg).unwrap();
        assert_ne!(reference.url(), raw_grant.url());
        assert!(reference.matches_host("127.0.0.1", port));
        assert!(!raw_grant.env().values().any(|value| value == &reference.url()));
        let url = format!("http://127.0.0.1:{port}/reference?q=public");
        let denied = raw(raw_grant.port, format!("GET {url} HTTP/1.1\r\n{}\r\n", auth(&raw_grant)).as_bytes()).await;
        assert_eq!(status(&denied), 403);
        assert!(!lock(&seen).last().unwrap().1.allowed);
        let post = raw(
            p.port(),
            format!("POST {url} HTTP/1.1\r\n{}Content-Length: 0\r\n\r\n", auth(&reference.grant)).as_bytes(),
        )
        .await;
        assert_eq!(status(&post), 400);
        assert!(!lock(&seen).last().unwrap().1.allowed);
        let response = raw(
            p.port(),
            format!(
                "GET {url} HTTP/1.1\r\n{}Authorization: secret\r\nCookie: secret\r\nReferer: secret\r\n\r\n",
                auth(&reference.grant)
            )
            .as_bytes(),
        )
        .await;
        assert_eq!(status(&response), 200);
        let (who, decision) = lock(&seen).last().unwrap().clone();
        assert_eq!(who, Some(sid.clone()));
        assert!(decision.allowed);
        let request = String::from_utf8(got.await.unwrap()).unwrap().to_lowercase();
        assert!(!request.contains("authorization:") && !request.contains("cookie:") && !request.contains("referer:"));
        p.revoke(&sid);
        let revoked = raw(p.port(), format!("GET {url} HTTP/1.1\r\n{}\r\n", auth(&reference.grant)).as_bytes()).await;
        assert_eq!(status(&revoked), 407);
    }

    #[tokio::test]
    async fn connect_tunnel_echoes_both_ways() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let sid = SessionId::from("s-one");
        let g = p.grant(&sid, lab()).unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        let head = read_until(&mut s, "\r\n\r\n").await;
        assert_eq!(head, "HTTP/1.1 200 Connection established\r\n\r\n");
        for msg in [&b"hello"[..], b"second round"] {
            s.write_all(msg).await.unwrap();
            let mut back = vec![0u8; msg.len()];
            timeout(T, s.read_exact(&mut back)).await.unwrap().unwrap();
            assert_eq!(back, msg);
        }
        let (who, d) = decision(&mut rx).await;
        assert_eq!(who, sid);
        assert_eq!((d.host.as_str(), d.port, d.method.as_str(), d.allowed), ("127.0.0.1", echo, "CONNECT", true));
        assert_eq!(d.rule, "allow_private 127.0.0.1");
        assert_eq!(d.resolved.as_deref(), Some("127.0.0.1"));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn localhost_name_reaches_allowed_loopback_address() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let g = p.grant(&SessionId::from("s-lh"), lab()).unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("localhost:{echo}")).as_bytes()).await.unwrap();
        let head = read_until(&mut s, "\r\n\r\n").await;
        assert_eq!(status(&head), 200);
        let (_, d) = decision(&mut rx).await;
        assert!(d.allowed);
        assert_eq!(d.resolved.as_deref(), Some("127.0.0.1"), "{d:?}");
    }

    #[tokio::test]
    async fn plain_forward_rewrites_target_and_relays() {
        let (p, mut rx) = start().await;
        let (port, server) = http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
        let sid = SessionId::from("s-fwd");
        let g = p.grant(&sid, lab()).unwrap();
        let req = format!(
            "GET http://127.0.0.1:{port}/a/b?x=1#frag HTTP/1.1\r\nHost: wrong.test\r\n{}Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\nX-Test: 1\r\n\r\n",
            auth(&g)
        );
        let resp = raw(g.port, req.as_bytes()).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
        assert!(resp.ends_with("\r\n\r\nok"), "{resp}");
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.starts_with("GET /a/b?x=1 HTTP/1.1\r\n"), "{got}");
        assert!(got.contains(&format!("Host: 127.0.0.1:{port}\r\n")), "{got}");
        assert!(got.contains("X-Test: 1\r\n"), "{got}");
        assert!(got.contains("Connection: close\r\n"), "{got}");
        let lower = got.to_ascii_lowercase();
        assert!(!lower.contains("proxy-"), "{got}");
        assert!(!lower.contains("keep-alive"), "{got}");
        assert!(!lower.contains("wrong.test"), "{got}");
        let (who, d) = decision(&mut rx).await;
        assert_eq!(who, sid);
        assert_eq!((d.method.as_str(), d.port, d.allowed), ("GET", port, true));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn plain_forward_relays_request_body() {
        let (p, _rx) = start().await;
        let (port, server) = http_server("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n").await;
        let g = p.grant(&SessionId::from("s-post"), lab()).unwrap();
        let req = format!("POST http://127.0.0.1:{port} HTTP/1.1\r\n{}Content-Length: 11\r\n\r\nhello world", auth(&g));
        let resp = raw(g.port, req.as_bytes()).await;
        assert_eq!(status(&resp), 201, "{resp}");
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.starts_with("POST / HTTP/1.1\r\n"), "{got}");
        assert!(got.ends_with("\r\n\r\nhello world"), "{got}");
    }

    #[tokio::test]
    async fn a_chunked_request_body_is_forwarded_to_its_last_chunk_and_no_further() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-chunked-post"), lab()).unwrap();
        let (port, server) = two_answer_server("HTTP/1.0 200 OK\r\n\r\nfirst", FORGED, Duration::from_secs(2)).await;
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        let head = format!("POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Transfer-Encoding: chunked\r\n\r\n", auth(&g));
        s.write_all(format!("{head}4\r\nbo").as_bytes()).await.unwrap();
        let begun = read_until(&mut s, "first").await;
        // The rest of the body, then a further request in the same write.
        let more = format!("dy\r\n0\r\n\r\nGET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        s.write_all(more.as_bytes()).await.unwrap();
        let started = tokio::time::Instant::now();
        let mut rest = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut rest)).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the proxy waited for the destination: {:?}",
            started.elapsed()
        );
        assert!(begun.ends_with("\r\n\r\nfirst") && rest.is_empty(), "{begun:?} {:?}", String::from_utf8_lossy(&rest));
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.ends_with("\r\n\r\n4\r\nbody\r\n0\r\n\r\n") && !got.contains("GET "), "{got}");
    }

    #[tokio::test]
    async fn failing_audit_refuses_the_connection_and_nothing_reaches_the_upstream() {
        let (p, mut rx, seen) = start_audited(true, Limits::default(), None).await;
        let (port, server) = silent_server().await;
        let g = p.grant(&SessionId::from("s-af"), lab()).unwrap();
        let req = format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(g.port, req.as_bytes()).await;
        assert_eq!(status(&resp), 502, "{resp}");
        assert!(
            resp.contains("X-Loom-Proxy: 1\r\n") && resp.contains("egress audit log could not be written"),
            "{resp}"
        );
        let (got, closed) = server.await.unwrap();
        assert!(got.is_empty() && closed.is_some(), "the upstream must not receive bytes: {got:?}");
        assert!(lock(&seen).is_empty());
        let (_, d) = decision(&mut rx).await;
        assert!(!d.allowed && d.rule.contains("audit log not written"), "{d:?}");
        // CONNECT is refused before the 200 as well.
        let (port, server) = silent_server().await;
        let r = raw(g.port, connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        assert!(server.await.unwrap().0.is_empty());
    }

    #[tokio::test]
    async fn audit_is_written_before_the_upstream_sees_the_request() {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, _rx) = unbounded_channel();
        let f2 = flag.clone();
        let audit: AuditFn = Arc::new(move |_: Option<&SessionId>, d: &NetDecision| {
            assert!(d.allowed);
            std::thread::sleep(Duration::from_millis(150));
            f2.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });
        let p = Proxy::start_inner(0, tx, Some(audit), Limits::default(), None).await.unwrap();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let f3 = flag.clone();
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 1];
            let n = timeout(T, s.read(&mut b)).await.unwrap().unwrap();
            let audited = f3.load(std::sync::atomic::Ordering::SeqCst);
            let _ = s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
            (n, audited)
        });
        let g = p.grant(&SessionId::from("s-ord"), lab()).unwrap();
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(g.port, req.as_bytes()).await;
        assert_eq!(status(&resp), 204, "{resp}");
        assert_eq!(server.await.unwrap(), (1, true), "the upstream saw bytes before the audit record was written");
    }

    #[tokio::test]
    async fn bad_requests_and_failed_authentication_are_audited() {
        let limits = Limits { head_timeout: Duration::from_millis(300), ..Limits::default() };
        let (p, mut rx, seen) = start_audited(false, limits, None).await;
        let sid = SessionId::from("s-aud");
        let g = p.grant(&sid, lab()).unwrap();
        // Requests of a session: under that session, with the destination when the target names one.
        let r = raw(g.port, format!("GET https://example.test/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 400);
        let r = raw(g.port, connect_req(&g, "nohostport").as_bytes()).await;
        assert_eq!(status(&r), 400);
        // Requests that name no granted session: under no session, whatever user they claim.
        let none = raw(g.port, b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n").await;
        assert_eq!(status(&none), 407);
        let unknown = SessionGrant { user: "s-nobody".into(), ..g.clone() };
        assert_eq!(status(&raw(g.port, connect_req(&unknown, "127.0.0.1:9").as_bytes()).await), 407);
        let wrong = SessionGrant { password: "0".repeat(32), ..g.clone() };
        assert_eq!(status(&raw(g.port, connect_req(&wrong, "127.0.0.1:9").as_bytes()).await), 407);
        assert_eq!(status(&raw(g.port, b"garbage\r\n\r\n").await), 400);
        let mut slow = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        slow.write_all(b"CONNECT 127.0.0.1:9 HT").await.unwrap();
        let mut out = Vec::new();
        timeout(T, slow.read_to_end(&mut out)).await.unwrap().unwrap();
        assert_eq!(status(&String::from_utf8_lossy(&out)), 400);
        let check = format!("{CHECK_METHOD} 127.0.0.1:9 HTTP/1.1\r\n\r\n");
        assert_eq!(status(&raw(g.port, check.as_bytes()).await), 407);
        let seen = lock(&seen).clone();
        assert_eq!(seen.len(), 8, "{seen:?}");
        assert!(seen.iter().all(|(_, d)| !d.allowed));
        let rule = |i: usize| seen[i].1.rule.as_str();
        assert_eq!(row(&seen[0]), (Some("s-aud"), "GET", "example.test", 443));
        assert!(rule(0).starts_with("bad request: https://"), "{seen:?}");
        assert_eq!(row(&seen[1]), (Some("s-aud"), "CONNECT", "-", 0));
        assert_eq!(row(&seen[2]), (None, "CONNECT", "127.0.0.1", 9));
        assert_eq!(rule(2), "proxy authentication failed: no credentials");
        assert_eq!(row(&seen[3]), (None, "CONNECT", "127.0.0.1", 9));
        assert_eq!(rule(3), "proxy authentication failed: unknown user");
        assert_eq!(row(&seen[4]), (None, "CONNECT", "127.0.0.1", 9));
        assert_eq!(rule(4), "proxy authentication failed: wrong password for session s-aud");
        assert_eq!(row(&seen[5]), (None, "-", "-", 0));
        assert!(rule(5).starts_with("bad request: the request head could not be parsed"), "{seen:?}");
        assert_eq!(row(&seen[6]), (None, "-", "-", 0));
        assert_eq!(rule(6), "bad request: no complete request head arrived within 300 ms");
        // A check names its destination as `host:port`, like a CONNECT.
        assert_eq!(row(&seen[7]), (None, CHECK_METHOD, "127.0.0.1", 9));
        // None of these reached the policy, so the sink gets none of them.
        no_more(&mut rx);
    }

    fn row(e: &(Option<SessionId>, NetDecision)) -> (Option<&str>, &str, &str, u16) {
        (e.0.as_ref().map(SessionId::as_str), e.1.method.as_str(), e.1.host.as_str(), e.1.port)
    }

    #[tokio::test]
    async fn unattributed_records_are_capped_and_count_what_they_left_out() {
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        for _ in 0..13 {
            assert_eq!(status(&raw(p.port(), b"garbage\r\n\r\n").await), 400);
        }
        assert_eq!(lock(&seen).len(), 10);
        // A minute later the next one is recorded, with the number left out before it.
        let earlier = std::time::Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
        lock(&p.inner.shared.unattributed).since = earlier;
        assert_eq!(status(&raw(p.port(), b"garbage\r\n\r\n").await), 400);
        let last = lock(&seen).last().unwrap().1.rule.clone();
        assert_eq!(lock(&seen).len(), 11);
        assert!(last.ends_with("(3 similar answers before this one were not recorded)"), "{last}");
        // Long texts from the request are cut, and the cut is marked.
        let g = p.grant(&SessionId::from("s-cut"), lab()).unwrap();
        let r = raw(g.port, format!("CONNECT {}!:1 HTTP/1.1\r\n{}\r\n", "b".repeat(500), auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 400);
        let r = raw(g.port, format!("CONNECT {}:1 HTTP/1.1\r\n\r\n", "a".repeat(500)).as_bytes()).await;
        assert_eq!(status(&r), 407);
        let all = lock(&seen).clone();
        let (_, bad) = all.iter().find(|(s, _)| s.as_ref().is_some_and(|s| s.as_str() == "s-cut")).unwrap();
        assert!(bad.rule.chars().count() == 301 && bad.rule.ends_with('…'), "{}", bad.rule);
        let (who, failed) = all.last().unwrap();
        assert!(who.is_none() && failed.host.chars().count() == 256 && failed.host.ends_with('…'), "{}", failed.host);
    }

    #[tokio::test]
    async fn missing_wrong_and_revoked_credentials_get_407() {
        let (p, mut rx) = start().await;
        let sid = SessionId::from("s-auth");
        let g = p.grant(&sid, lab()).unwrap();
        let none = raw(g.port, b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n").await;
        assert_eq!(status(&none), 407, "{none}");
        assert!(none.contains("Proxy-Authenticate: Basic realm=\"loom\"\r\n"), "{none}");
        assert!(none.contains("X-Loom-Proxy: 1\r\n"));
        let wrong = SessionGrant { password: "0".repeat(32), ..g.clone() };
        let r = raw(g.port, connect_req(&wrong, "127.0.0.1:9").as_bytes()).await;
        assert_eq!(status(&r), 407);
        let unknown = SessionGrant { user: "s-nobody".into(), ..g.clone() };
        assert_eq!(status(&raw(g.port, connect_req(&unknown, "127.0.0.1:9").as_bytes()).await), 407);
        let garbage = raw(g.port, b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nProxy-Authorization: Basic !!!\r\n\r\n").await;
        assert_eq!(status(&garbage), 407);
        p.revoke(&sid);
        // The session's listener is closed; the old credentials are unknown on the shared port.
        assert_eq!(status(&raw(p.port(), connect_req(&g, "127.0.0.1:9").as_bytes()).await), 407);
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn deny_rule_answers_403_with_one_decision() {
        let (p, mut rx) = start().await;
        let sid = SessionId::from("s-deny");
        let g = p.grant(&sid, policy(NetworkMode::Open, &[], &["blocked.test"], &[])).unwrap();
        let r = raw(g.port, connect_req(&g, "Blocked.test.:443").as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n"));
        assert!(r.contains("Connection: close\r\n"));
        assert!(r.contains("blocked.test:443") && r.contains("deny blocked.test") && r.contains("[network]"), "{r}");
        let (who, d) = decision(&mut rx).await;
        assert_eq!(who, sid);
        assert_eq!((d.allowed, d.rule.as_str(), d.resolved.clone()), (false, "deny blocked.test", None));
        assert_eq!(d.host, "blocked.test");
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn open_mode_loopback_is_refused_as_private() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let g = p.grant(&SessionId::from("s-priv"), policy(NetworkMode::Open, &[], &[], &[])).unwrap();
        let r = raw(g.port, connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert!(!d.allowed);
        assert_eq!(d.rule, "deny private-address 127.0.0.1");
        assert_eq!(d.resolved.as_deref(), Some("127.0.0.1"));
        // The same through a name that resolves to loopback, and through a mapped IPv6 literal.
        let r = raw(g.port, connect_req(&g, &format!("localhost:{echo}")).as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert!(!d.allowed && d.resolved.is_some(), "{d:?}");
        let r = raw(g.port, connect_req(&g, &format!("[::ffff:127.0.0.1]:{echo}")).as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert_eq!(d.rule, "deny private-address ::ffff:127.0.0.1");
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn deny_list_applies_to_resolved_addresses() {
        let resolver: Resolver = Arc::new(|name: &str| {
            let ip = match name {
                "lab.test" => "10.0.0.5",
                "mapped.test" => "::ffff:10.0.0.5",
                "cidr.test" => "10.1.2.3",
                "pub.test" => "203.0.113.7",
                _ => return Vec::new(),
            };
            vec![ip.parse().unwrap()]
        });
        let (tx, mut rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, None, Limits::default(), Some(resolver)).await.unwrap();
        let deny = ["10.0.0.5", "10.1.0.0/16", "203.0.113.7"];
        let g = p.grant(&SessionId::from("s-dr"), policy(NetworkMode::Open, &[], &deny, &["10.0.0.0/8"])).unwrap();
        for (dest, rule) in [
            ("lab.test:80", "deny 10.0.0.5"),
            ("mapped.test:80", "deny 10.0.0.5"),
            ("[::ffff:10.0.0.5]:80", "deny 10.0.0.5"),
            ("cidr.test:80", "deny 10.1.0.0/16"),
            ("pub.test:443", "deny 203.0.113.7"),
        ] {
            let r = raw(g.port, connect_req(&g, dest).as_bytes()).await;
            assert_eq!(status(&r), 403, "{dest}: {r}");
            let (_, d) = decision(&mut rx).await;
            assert!(!d.allowed, "{dest}: {d:?}");
            assert_eq!(d.rule, rule, "{dest}");
        }
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn ipv6_forms_that_carry_a_private_ipv4_address_are_refused_by_name_and_as_literals() {
        // NAT64 (both prefixes) and 6to4 forms of each address, each reachable through a name of its own.
        let carried = |v4: &str| {
            let n = u32::from(v4.parse::<std::net::Ipv4Addr>().unwrap());
            [format!("64:ff9b::{v4}"), format!("64:ff9b:1::{v4}"), format!("2002:{:x}:{:x}::1", n >> 16, n & 0xffff)]
        };
        let teredo = "2001:0:4136:e378:8000:63bf:3fff:fdd2";
        let mut table: Vec<(String, String)> = vec![("teredo.test".into(), teredo.into())];
        for v4 in ["10.0.0.5", "127.0.0.1", "192.168.1.5", "8.8.8.8"] {
            for (i, a) in carried(v4).into_iter().enumerate() {
                table.push((format!("f{i}-{v4}.test"), a));
            }
        }
        let names = table.clone();
        let resolver: Resolver = Arc::new(move |name: &str| {
            names.iter().filter(|(n, _)| n == name).map(|(_, a)| a.parse().unwrap()).collect()
        });
        let (tx, mut rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, None, Limits::default(), Some(resolver)).await.unwrap();
        let open = p.grant(&SessionId::from("s-c-open"), policy(NetworkMode::Open, &[], &[], &[])).unwrap();
        let al = p.grant(&SessionId::from("s-c-al"), policy(NetworkMode::Allowlist, &["*"], &[], &[])).unwrap();
        let listed =
            p.grant(&SessionId::from("s-c-ls"), policy(NetworkMode::Open, &[], &[], &["10.0.0.5", "8.8.8.8"])).unwrap();
        let deny = ["10.0.0.5", "8.8.8.0/24"];
        let denied =
            p.grant(&SessionId::from("s-c-dn"), policy(NetworkMode::Open, &[], &deny, &["10.0.0.0/8"])).unwrap();
        for (name, addr) in &table {
            let v4 = name.split_once('-').map_or("", |(_, rest)| rest.trim_end_matches(".test"));
            let shown = addr.parse::<IpAddr>().unwrap().to_string();
            for dest in [format!("{name}:443"), format!("[{addr}]:443")] {
                for g in [&open, &al] {
                    let (code, d) = check_on(g.port, g, &dest, &mut rx).await;
                    if v4 == "8.8.8.8" {
                        assert_eq!(code, 200, "{dest}: {d:?}");
                    } else {
                        assert_eq!(
                            (code, d.rule),
                            (403, format!("deny private-address {shown} (check only)")),
                            "{dest}"
                        );
                        assert_eq!(d.resolved.as_deref(), Some(shown.as_str()), "{dest}");
                    }
                }
                let (code, d) = check_on(listed.port, &listed, &dest, &mut rx).await;
                assert_eq!(code == 200, matches!(v4, "10.0.0.5" | "8.8.8.8"), "{dest}: {d:?}");
                if v4 == "10.0.0.5" {
                    assert_eq!(d.rule, "allow_private 10.0.0.5 (check only)", "{dest}");
                }
                let (code, d) = check_on(denied.port, &denied, &dest, &mut rx).await;
                match v4 {
                    "10.0.0.5" => assert_eq!((code, d.rule.as_str()), (403, "deny 10.0.0.5 (check only)"), "{dest}"),
                    "8.8.8.8" => assert_eq!((code, d.rule.as_str()), (403, "deny 8.8.8.0/24 (check only)"), "{dest}"),
                    _ => assert_eq!(code, 403, "{dest}: {d:?}"),
                }
            }
        }
        // A real connection through a name to such an address is refused before connecting.
        let r = raw(open.port, connect_req(&open, "f2-127.0.0.1.test:443").as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        assert_eq!(decision(&mut rx).await.1.rule, "deny private-address 2002:7f00:1::1");
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn name_lookups_are_bounded_per_session_and_in_all() {
        use std::sync::atomic::AtomicUsize;
        let calls = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicBool::new(false));
        let (c, o) = (calls.clone(), open.clone());
        let resolver: Resolver = Arc::new(move |_: &str| {
            c.fetch_add(1, Ordering::SeqCst);
            while !o.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
            vec!["10.9.9.9".parse().unwrap()]
        });
        let limits = Limits { max_lookups: 3, max_lookups_per_session: 2, ..Limits::default() };
        let (tx, _rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, None, limits, Some(resolver)).await.unwrap();
        let ga = p.grant(&SessionId::from("s-la"), policy(NetworkMode::Open, &[], &[], &[])).unwrap();
        let gb = p.grant(&SessionId::from("s-lb"), policy(NetworkMode::Open, &[], &[], &[])).unwrap();
        let ask = |g: &SessionGrant| {
            let (port, req) = (g.port, connect_req(g, "slow.test:80"));
            tokio::spawn(async move { status(&raw(port, req.as_bytes()).await) })
        };
        let settled = |n: usize| {
            let calls = calls.clone();
            async move {
                let deadline = tokio::time::Instant::now() + T;
                while calls.load(Ordering::SeqCst) < n {
                    assert!(tokio::time::Instant::now() < deadline, "only {calls:?} lookups started");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
                calls.load(Ordering::SeqCst)
            }
        };
        // One session gets two lookups at once; its third waits.
        let mut asked: Vec<_> = (0..3).map(|_| ask(&ga)).collect();
        assert_eq!(settled(2).await, 2);
        // Another session still gets a turn, which fills the proxy's three.
        asked.push(ask(&gb));
        assert_eq!(settled(3).await, 3);
        asked.push(ask(&gb));
        assert_eq!(settled(3).await, 3);
        open.store(true, Ordering::SeqCst);
        for a in asked {
            assert_eq!(timeout(T, a).await.unwrap().unwrap(), 403);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn allowlist_miss_is_refused_without_resolving() {
        let (p, mut rx) = start().await;
        let g = p.grant(&SessionId::from("s-al"), policy(NetworkMode::Allowlist, &["only.test"], &[], &[])).unwrap();
        let r = raw(g.port, connect_req(&g, "other.test:443").as_bytes()).await;
        assert_eq!(status(&r), 403);
        let (_, d) = decision(&mut rx).await;
        assert_eq!((d.rule.as_str(), d.resolved), ("not in allow list", None));
        let g = p.grant(&SessionId::from("s-da"), policy(NetworkMode::DenyAll, &[], &[], &[])).unwrap();
        let r = raw(g.port, format!("GET http://x.test/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 403);
        let (_, d) = decision(&mut rx).await;
        assert_eq!((d.rule.as_str(), d.method.as_str()), ("mode deny_all", "GET"));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn a_check_answers_the_verdict_and_the_rule_without_connecting() {
        let resolver: Resolver = Arc::new(|name: &str| match name {
            "lab.test" => vec!["127.0.0.1".parse().unwrap()],
            _ => Vec::new(),
        });
        let (tx, mut rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, None, Limits::default(), Some(resolver)).await.unwrap();
        let sid = SessionId::from("s-check");
        let g = p.grant(&sid, policy(NetworkMode::Open, &[], &["blocked.test"], &["127.0.0.1"])).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let ask = |target: String| format!("{CHECK_METHOD} {target} HTTP/1.1\r\n{}\r\n", auth(&g));
        let rule = |r: &str| r.lines().find_map(|l| l.strip_prefix("X-Loom-Rule: ")).map(str::to_string);
        // Allowed, as host:port and as the absolute URI an HTTP client sends; nothing connects.
        for target in [format!("lab.test:{port}"), format!("http://lab.test:{port}/")] {
            let r = raw(g.port, ask(target).as_bytes()).await;
            assert_eq!(status(&r), 200, "{r}");
            assert!(r.contains("X-Loom-Proxy: 1\r\n"), "{r}");
            assert_eq!(rule(&r).as_deref(), Some("allow_private 127.0.0.1"), "{r}");
            let (who, d) = decision(&mut rx).await;
            assert_eq!((who, d.method.as_str(), d.allowed), (sid.clone(), CHECK_METHOD, true));
            assert_eq!(
                (d.rule.as_str(), d.resolved.as_deref()),
                ("allow_private 127.0.0.1 (check only)", Some("127.0.0.1"))
            );
        }
        assert!(timeout(Duration::from_millis(200), l.accept()).await.is_err(), "a check connected to the destination");
        // Refused, with the refusal text and the rule.
        let r = raw(g.port, ask("blocked.test:443".into()).as_bytes()).await;
        assert_eq!(status(&r), 403, "{r}");
        assert_eq!(rule(&r).as_deref(), Some("deny blocked.test"), "{r}");
        assert!(r.contains("refused by rule `deny blocked.test`"), "{r}");
        assert_eq!(decision(&mut rx).await.1.rule, "deny blocked.test (check only)");
        // A name that does not resolve.
        let r = raw(g.port, ask("nowhere.test:443".into()).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert!(
            d.allowed && d.rule.starts_with("mode open (unreachable: ") && d.rule.ends_with("(check only)"),
            "{d:?}"
        );
        // A check needs the session's credentials like any request.
        let r = raw(g.port, format!("{CHECK_METHOD} blocked.test:443 HTTP/1.1\r\n\r\n").as_bytes()).await;
        assert_eq!(status(&r), 407, "{r}");
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn set_policy_changes_what_the_same_credentials_may_reach() {
        let (p, mut rx) = start().await;
        let sid = SessionId::from("s-sp");
        let g = p.grant(&sid, policy(NetworkMode::Allowlist, &["only.test"], &[], &[])).unwrap();
        let r = raw(g.port, connect_req(&g, "other.test:443").as_bytes()).await;
        assert_eq!(status(&r), 403);
        let (_, d) = decision(&mut rx).await;
        assert_eq!(d.rule.as_str(), "not in allow list");
        // The new policy lists the host; the same credentials now pass the name check.
        assert!(p.set_policy(&sid, policy(NetworkMode::Allowlist, &["only.test", "other.test"], &[], &[])));
        let r = raw(g.port, connect_req(&g, "other.test:443").as_bytes()).await;
        assert_ne!(status(&r), 407, "{r}");
        let (_, d) = decision(&mut rx).await;
        assert_ne!(d.rule.as_str(), "not in allow list", "{d:?}");
        // And back.
        assert!(p.set_policy(&sid, policy(NetworkMode::DenyAll, &[], &[], &[])));
        let r = raw(g.port, connect_req(&g, "other.test:443").as_bytes()).await;
        assert_eq!(status(&r), 403);
        let (_, d) = decision(&mut rx).await;
        assert_eq!(d.rule.as_str(), "mode deny_all");
        assert!(!p.set_policy(&SessionId::from("s-none"), policy(NetworkMode::Open, &[], &[], &[])));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn unreachable_port_is_502_and_allowed_decision() {
        let (p, mut rx) = start().await;
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let g = p.grant(&SessionId::from("s-502"), lab()).unwrap();
        let r = raw(g.port, connect_req(&g, &format!("127.0.0.1:{dead}")).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n"));
        let (_, d) = decision(&mut rx).await;
        assert!(d.allowed);
        assert!(d.rule.starts_with("allow_private 127.0.0.1 (unreachable: "), "{}", d.rule);
        assert_eq!(d.resolved.as_deref(), Some("127.0.0.1"));
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn a_failure_after_an_allow_is_recorded_after_it_in_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.jsonl");
        let (writer, file) = (Arc::new(crate::netlog::NetLogWriter::new()), path.clone());
        // A destination that resets each connection it accepts once the proxy, connected to it, is
        // recording its allow: a reset any earlier could fail the proxy's connect instead.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (reset, mut resets) = unbounded_channel::<()>();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let _ = resets.recv().await;
                s.set_zero_linger().unwrap();
            }
        });
        // Allows announce themselves and are slow to record, so that what a peer does meanwhile has
        // happened when the proxy goes on.
        let (allowing, mut allows) = unbounded_channel::<String>();
        let audit: AuditFn = Arc::new(move |_: Option<&SessionId>, d: &NetDecision| {
            if d.allowed && !d.rule.contains("(failed after the allow: ") {
                let _ = allowing.send(d.method.clone());
                if d.port == port {
                    let _ = reset.send(());
                }
                std::thread::sleep(Duration::from_millis(300));
            }
            writer.append(&file, d)
        });
        let (tx, _rx) = unbounded_channel();
        let p = Proxy::start_inner(0, tx, Some(audit), Limits::default(), None).await.unwrap();
        let g = p.grant(&SessionId::from("s-after"), lab()).unwrap();
        let lines = |n: usize| {
            let path = path.clone();
            async move {
                let deadline = tokio::time::Instant::now() + T;
                loop {
                    let text = std::fs::read_to_string(&path).unwrap_or_default();
                    if text.lines().count() >= n {
                        return text;
                    }
                    assert!(tokio::time::Instant::now() < deadline, "not recorded: {text}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        };
        // A forwarded request: the destination is gone before the request head can be written to it.
        let r = raw(g.port, format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        assert_eq!(status(&r), 502, "{r}");
        assert_eq!(timeout(T, allows.recv()).await.unwrap().as_deref(), Some("GET"));
        // A tunnel whose client resets while its allow is being recorded, before the proxy can answer.
        let echo = echo_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(timeout(T, allows.recv()).await.unwrap().as_deref(), Some("CONNECT"));
        s.set_zero_linger().unwrap();
        drop(s);
        lines(4).await;
        // A tunnel whose destination resets before it sends a byte, while the client stays.
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let mut rest = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut rest)).await.unwrap();
        assert!(rest.is_empty(), "{rest:?}");
        lines(6).await;
        // A tunnel both sides close before the destination sent a byte.
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        s.shutdown().await.unwrap();
        let _ = timeout(T, s.read_to_end(&mut rest)).await.unwrap();
        let text = lines(8).await;
        assert_eq!(crate::netlog::verify(&text), Ok(()));
        let rows: Vec<NetDecision> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let rules: Vec<(&str, bool, &str)> =
            rows.iter().map(|d| (d.method.as_str(), d.allowed, d.rule.as_str())).collect();
        assert_eq!(rules.len(), 8, "{rules:?}");
        let failures = [
            ("GET", "sending the request to the destination failed"),
            ("CONNECT", "the client closed the connection before the tunnel was open"),
            ("CONNECT", "the connection to the destination failed before the destination sent a byte"),
            ("CONNECT", "the tunnel closed before the destination sent a byte"),
        ];
        for (i, (method, why)) in failures.into_iter().enumerate() {
            assert_eq!(rules[2 * i], (method, true, "allow_private 127.0.0.1"), "{rules:?}");
            let failed = format!("allow_private 127.0.0.1 (failed after the allow: {why})");
            assert_eq!(rules[2 * i + 1], (method, true, failed.as_str()), "{rules:?}");
            assert_eq!(rows[2 * i + 1].resolved.as_deref(), Some("127.0.0.1"));
        }
    }

    #[tokio::test]
    async fn two_sessions_are_attributed_separately() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let (a, b) = (SessionId::from("s-aaa"), SessionId::from("s-bbb"));
        let ga = p.grant(&a, lab()).unwrap();
        let gb = p.grant(&b, policy(NetworkMode::Open, &[], &[], &[])).unwrap();
        let dest = format!("127.0.0.1:{echo}");
        let ra = connect_req(&ga, &dest);
        let rb = connect_req(&gb, &dest);
        let one = async {
            let mut s = TcpStream::connect(("127.0.0.1", ga.port)).await.unwrap();
            s.write_all(ra.as_bytes()).await.unwrap();
            let h = read_until(&mut s, "\r\n\r\n").await;
            status(&h)
        };
        let two = async { status(&raw(gb.port, rb.as_bytes()).await) };
        let (sa, sb) = tokio::join!(one, two);
        assert_eq!((sa, sb), (200, 403));
        let mut seen = [decision(&mut rx).await, decision(&mut rx).await];
        seen.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(seen[0].0, a);
        assert!(seen[0].1.allowed);
        assert_eq!(seen[1].0, b);
        assert!(!seen[1].1.allowed);
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn malformed_requests_get_400_and_server_keeps_serving() {
        let (p, mut rx) = start().await;
        let echo = echo_server().await;
        let g = p.grant(&SessionId::from("s-bad"), lab()).unwrap();
        let a = auth(&g);
        let cases: Vec<String> = vec![
            "garbage\r\n\r\n".into(),
            "\x00\x01\x02\r\n\r\n".into(),
            "GET / HTTP/9.9\r\n\r\n".into(),
            format!("GET /origin HTTP/1.1\r\n{a}\r\n"),
            format!("GET https://example.test/ HTTP/1.1\r\n{a}\r\n"),
            format!("CONNECT nohostport HTTP/1.1\r\n{a}\r\n"),
            format!("CONNECT a b:443 HTTP/1.1\r\n{a}\r\n"),
            format!("CONNECT host:0 HTTP/1.1\r\n{a}\r\n"),
            format!("CONNECT [::1:443 HTTP/1.1\r\n{a}\r\n"),
            format!("GET http://user@host.test/ HTTP/1.1\r\n{a}\r\n"),
            format!("GET http://h.test/ HTTP/1.1\r\n{a}Content-Length: 1\r\nContent-Length: 2\r\n\r\n"),
            format!("POST http://h.test/ HTTP/1.1\r\n{a}Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            format!("GET http://h\u{e9}.test/ HTTP/1.1\r\n{a}\r\n"),
        ];
        for c in cases {
            let r = raw(g.port, c.as_bytes()).await;

            assert_eq!(status(&r), 400, "request {c:?} got {r}");
            assert!(r.contains("X-Loom-Proxy: 1\r\n"), "{r}");
        }
        // A client that connects and leaves, or sends half a head, does not disturb anything.
        drop(TcpStream::connect(("127.0.0.1", g.port)).await.unwrap());
        let mut half = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        half.write_all(b"CONNECT 127.0.0.1:1 HT").await.unwrap();
        drop(half);
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let (_, d) = decision(&mut rx).await;
        assert!(d.allowed);
        no_more(&mut rx);
    }

    #[tokio::test]
    async fn oversized_head_gets_400() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-big"), lab()).unwrap();
        let req = format!("CONNECT 127.0.0.1:1 HTTP/1.1\r\n{}X-Pad: {}\r\n\r\n", auth(&g), "a".repeat(70 * 1024));
        let r = raw(g.port, req.as_bytes()).await;
        assert_eq!(status(&r), 400, "{}", &r[..r.len().min(200)]);
        assert!(r.contains("64 KiB"));
        // Still serving.
        assert_eq!(status(&raw(g.port, b"x\r\n\r\n").await), 400);
    }

    #[tokio::test]
    async fn connection_caps_apply_globally_and_per_session() {
        let echo = echo_server().await;
        let dest = format!("127.0.0.1:{echo}");
        let tunnel = |_p: &Proxy, g: &SessionGrant| {
            let (port, req) = (g.port, connect_req(g, &dest));
            async move {
                let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                s.write_all(req.as_bytes()).await.unwrap();
                let head = read_until(&mut s, "\r\n\r\n").await;
                (s, status(&head))
            }
        };
        // Per session: the second tunnel of a session at its cap gets 429; another session is unaffected.
        let limits = Limits { max_per_session: 1, ..Limits::default() };
        let (p, _rx, seen) = start_audited(false, limits, None).await;
        let (ga, gb) =
            (p.grant(&SessionId::from("s-ca"), lab()).unwrap(), p.grant(&SessionId::from("s-cb"), lab()).unwrap());
        let (held, st) = tunnel(&p, &ga).await;
        assert_eq!(st, 200);
        let r = raw(ga.port, connect_req(&ga, &dest).as_bytes()).await;
        assert_eq!(status(&r), 429, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n"));
        assert!(lock(&seen).iter().any(|(_, d)| d.rule == "connection limit (per session)"));
        let (_other, st) = tunnel(&p, &gb).await;
        assert_eq!(st, 200);
        // The permit comes back when the tunnel closes.
        drop(held);
        let deadline = tokio::time::Instant::now() + T;
        loop {
            let (_s, st) = tunnel(&p, &ga).await;
            if st == 200 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "the session cap was never released");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Globally: with every slot held by a connection that has sent its head, the next one gets 503,
        // recorded under no session.
        let limits = Limits { max_connections: 2, ..Limits::default() };
        let (p, _rx, seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-cg"), lab()).unwrap();
        let (_a, st) = tunnel(&p, &g).await;
        assert_eq!(st, 200);
        let (_b, st) = tunnel(&p, &g).await;
        assert_eq!(st, 200);
        let r = raw(g.port, connect_req(&g, &dest).as_bytes()).await;
        assert_eq!(status(&r), 503, "{r}");
        assert!(r.contains("X-Loom-Proxy: 1\r\n") && r.contains("limit 2") && r.contains("Retry-After: 5\r\n"), "{r}");
        let last = lock(&seen).last().cloned().unwrap();
        assert_eq!((last.0, last.1.rule.as_str()), (None, "connection limit (all sessions)"));
    }

    #[tokio::test]
    async fn at_the_limit_a_new_connection_takes_the_slot_of_the_oldest_silent_one() {
        let echo = echo_server().await;
        let limits = Limits { max_connections: 2, ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-ev"), lab()).unwrap();
        // Two connections that never send a head hold both slots.
        let mut oldest = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut newer = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        // A real request still gets through, and the oldest silent connection is closed for it.
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let mut out = Vec::new();
        timeout(T, oldest.read_to_end(&mut out)).await.expect("the oldest silent connection was kept").unwrap();
        assert!(out.is_empty());
        let mut b = [0u8; 1];
        assert!(timeout(Duration::from_millis(200), newer.read(&mut b)).await.is_err(), "the newer one was closed too");
    }

    #[tokio::test]
    async fn connections_the_proxy_has_answered_itself_do_not_hold_their_slot() {
        let echo = echo_server().await;
        let limits = Limits { max_connections: 2, ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-drain"), lab()).unwrap();
        // Each client reads its answer (407, 400, 403) and keeps the connection open, so the proxy is
        // left waiting for it to close.
        let mut held = Vec::new();
        let requests = [
            "CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n".to_string(),
            "garbage\r\n\r\n".to_string(),
            connect_req(&g, "127.0.0.1:1"),
            connect_req(
                &p.grant(&SessionId::from("s-drain-2"), policy(NetworkMode::DenyAll, &[], &[], &[])).unwrap(),
                "x.test:1",
            ),
        ];
        for req in requests.iter().cycle().take(12) {
            let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
            s.write_all(req.as_bytes()).await.unwrap();
            let head = read_until(&mut s, "\r\n\r\n").await;
            assert!(matches!(status(&head), 400 | 403 | 407 | 502), "{head}");
            held.push(s);
        }
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
    }

    #[tokio::test]
    async fn eviction_closes_the_oldest_draining_connection_before_any_still_sending_a_head() {
        let (p, _rx) = start().await;
        let shared = &p.inner.shared;
        let permit = || shared.connections.clone().try_acquire_owned().unwrap();
        let (_, waiting) = shared.add_pending(permit());
        let (_, older) = shared.add_draining(permit());
        let (_, newer) = shared.add_draining(permit());
        let (_, later) = shared.add_pending(permit());
        let order = [&older, &newer, &waiting, &later];
        for (i, closed) in order.iter().enumerate() {
            assert!(shared.evict_pending().is_some());
            assert!(closed.is_cancelled(), "{i}");
            assert!(order.iter().skip(i + 1).all(|t| !t.is_cancelled()), "{i}");
        }
        assert!(shared.evict_pending().is_none());
    }

    #[tokio::test]
    async fn at_the_limit_a_new_connection_takes_the_slot_of_a_drained_one_before_a_silent_one() {
        let echo = echo_server().await;
        let limits = Limits { max_connections: 3, ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-order"), lab()).unwrap();
        let shared = p.inner.shared.clone();
        // The ids of the connections being drained, or of those still sending a head, oldest first.
        let queued = move |draining: bool| -> Vec<u64> {
            let p = lock(&shared.pending);
            let queue = if draining { &p.draining } else { &p.heads };
            queue.iter().map(|(id, _, _)| *id).collect()
        };
        async fn until(what: &str, done: impl Fn() -> bool) {
            let deadline = tokio::time::Instant::now() + T;
            while !done() {
                assert!(tokio::time::Instant::now() < deadline, "{what}");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        // The oldest connection has not sent its head.
        let mut silent = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        until("the silent connection was never accepted", || queued(false).len() == 1).await;
        // Two newer ones are answered 407 and stay open, so the proxy drains them.
        let mut answered = Vec::new();
        let mut drained: Vec<u64> = Vec::new();
        for _ in 0..2 {
            let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
            s.write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\n\r\n").await.unwrap();
            assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 407);
            let new = || queued(true).into_iter().filter(|id| !drained.contains(id)).collect::<Vec<u64>>();
            until("the answered connection was never drained", || !new().is_empty()).await;
            let new = new();
            drained.extend(new);
            answered.push(s);
        }
        // Every slot is taken; a new connection gets the one of the older drained connection. A drain
        // lasts 500 ms, so that one may also have ended by itself; either way it is gone.
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        assert!(!queued(true).contains(&drained[0]), "the newer drained connection was closed first: {drained:?}");
        let mut b = [0u8; 1];
        assert!(
            timeout(Duration::from_millis(200), silent.read(&mut b)).await.is_err(),
            "the silent connection was closed"
        );
    }

    #[tokio::test]
    async fn idle_tunnels_and_idle_forwards_are_closed() {
        let idle = Duration::from_secs(1);
        let limits = Limits { idle_timeout: idle, ..Limits::default() };
        let (p, _rx, seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-idle"), lab()).unwrap();
        // A tunnel to a peer that never speaks (and would hold its side open for a minute).
        let (port, server) = silent_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let started = tokio::time::Instant::now();
        let mut rest = Vec::new();
        let n = timeout(T, s.read_to_end(&mut rest)).await.expect("the idle tunnel was not closed").unwrap();
        let waited = started.elapsed();
        assert_eq!(n, 0);
        assert!(waited >= idle - Duration::from_millis(100) && waited < Duration::from_secs(3), "{waited:?}");
        let (_, closed) = timeout(T, server).await.unwrap().unwrap();
        assert!(closed.is_some_and(|at| at.duration_since(started) < Duration::from_secs(3)));
        // Nothing came from the destination, so the allow is followed by a record that says so.
        let rules: Vec<String> = lock(&seen).iter().map(|(_, d)| d.rule.clone()).collect();
        let idled = "(failed after the allow: the tunnel was idle for 1 second before the destination sent a byte)";
        assert_eq!(rules, ["allow_private 127.0.0.1".to_string(), format!("allow_private 127.0.0.1 {idled}")]);
        // A forwarded request whose upstream never answers gets a 504 that says so.
        let (port, server) = silent_server().await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let started = tokio::time::Instant::now();
        let resp = raw(g.port, req.as_bytes()).await;
        let waited = started.elapsed();
        assert_eq!(status(&resp), 504, "{resp}");
        assert!(resp.contains("X-Loom-Proxy: 1\r\n") && resp.contains("sent no response for 1 second"), "{resp}");
        assert!(waited >= idle - Duration::from_millis(100) && waited < Duration::from_secs(3), "{waited:?}");
        assert!(timeout(T, server).await.unwrap().unwrap().1.is_some());
        // Traffic keeps a tunnel alive past the idle period.
        let echo = echo_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            s.write_all(b"x").await.unwrap();
            let mut b = [0u8; 1];
            timeout(T, s.read_exact(&mut b)).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn forward_ends_when_the_client_goes_away() {
        let limits = Limits { forward_grace: Duration::from_millis(300), ..Limits::default() };
        let (p, _rx, _seen) = start_audited(false, limits, None).await;
        let g = p.grant(&SessionId::from("s-gone"), lab()).unwrap();
        let (port, server) = silent_server().await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let gone = tokio::time::Instant::now();
        drop(s);
        // The upstream sees the request and then its connection closing, long before the 10-minute idle
        // timeout and long before the helper would give up on its own.
        let (got, closed) = timeout(T, server).await.expect("the upstream connection stayed open").unwrap();
        assert!(String::from_utf8_lossy(&got).starts_with("GET / HTTP/1.1\r\n"));
        let closed = closed.expect("the upstream connection stayed open");
        assert!(closed.duration_since(gone) < Duration::from_secs(2), "{:?}", closed.duration_since(gone));
    }

    #[tokio::test]
    async fn forward_still_answers_a_client_that_half_closes() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-half"), lab()).unwrap();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let mut b = [0u8; 1024];
            while !String::from_utf8_lossy(&got).contains("\r\n\r\n") {
                let n = s.read(&mut b).await.unwrap();
                assert!(n > 0, "the request was cut off");
                got.extend_from_slice(&b[..n]);
            }
            // Answer only after the client has ended its side.
            tokio::time::sleep(Duration::from_millis(300)).await;
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
            let _ = s.shutdown().await;
        });
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await.unwrap();
        s.shutdown().await.unwrap();
        let mut out = Vec::new();
        timeout(T, s.read_to_end(&mut out)).await.unwrap().unwrap();
        let resp = String::from_utf8_lossy(&out).to_string();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n") && resp.ends_with("\r\n\r\nok"), "{resp}");
    }

    #[tokio::test]
    async fn tunnel_relays_both_directions_at_once() {
        // Each side writes everything before it reads anything back: both directions must move at once.
        const N: usize = 32 * 1024 * 1024;
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let (mut r, mut w) = s.into_split();
            let writer = tokio::spawn(async move {
                w.write_all(&vec![b'd'; N]).await.unwrap();
                w.shutdown().await.unwrap();
            });
            let mut got = Vec::new();
            r.read_to_end(&mut got).await.unwrap();
            writer.await.unwrap();
            got.len()
        });
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-duplex"), lab()).unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let both = async {
            s.write_all(&vec![b'u'; N]).await.unwrap();
            s.shutdown().await.unwrap();
            let mut back = Vec::new();
            s.read_to_end(&mut back).await.unwrap();
            back
        };
        let back = timeout(Duration::from_secs(30), both).await.expect("the tunnel stalled");
        assert!(back.len() == N && back.iter().all(|b| *b == b'd'));
        assert_eq!(timeout(T, server).await.unwrap().unwrap(), N);
    }

    #[tokio::test]
    async fn cut_hosts_ends_the_tunnels_of_a_withdrawn_destination_and_only_those() {
        let echo = echo_server().await;
        let other_echo = echo_server().await;
        let (p, mut rx) = start().await;
        let (a, b) = (SessionId::from("s-cut-a"), SessionId::from("s-cut-b"));
        let (ga, gb) = (p.grant(&a, lab()).unwrap(), p.grant(&b, lab()).unwrap());
        let open = |g: &SessionGrant, port: u16| {
            let req = connect_req(g, &format!("127.0.0.1:{port}"));
            let port = g.port;
            async move {
                let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                s.write_all(req.as_bytes()).await.unwrap();
                assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
                s
            }
        };
        let mut a_cut = open(&ga, echo).await;
        let mut a_kept = open(&ga, other_echo).await;
        let mut b_same = open(&gb, echo).await;
        async fn echoes(s: &mut TcpStream) -> Option<[u8; 4]> {
            s.write_all(b"ping").await.unwrap();
            let mut got = [0u8; 4];
            timeout(T, s.read_exact(&mut got)).await.ok().and_then(|r| r.ok()).map(|_| got)
        }
        assert_eq!(echoes(&mut a_cut).await, Some(*b"ping"));
        // A pattern that covers nothing of the session cuts nothing.
        assert_eq!(p.cut_hosts(&a, "example.test"), 0);
        // (Not `echo + 1`: the system hands out ports in sequence, so that can be `other_echo`'s.)
        let unused = (1..u16::MAX).map(|d| echo.wrapping_add(d)).find(|p| *p != other_echo && *p != echo).unwrap();
        assert_eq!(p.cut_hosts(&a, &format!("127.0.0.1:{unused}")), 0, "another port");
        // The destination of one tunnel of A: only that tunnel ends, and the other session's tunnel to the
        // same destination stays.
        assert_eq!(p.cut_hosts(&a, &format!("127.0.0.1:{echo}")), 1);
        let mut gone = Vec::new();
        let ended = timeout(T, a_cut.read_to_end(&mut gone)).await;
        assert!(ended.is_ok(), "the cut tunnel must close");
        assert_eq!(echoes(&mut a_kept).await, Some(*b"ping"));
        assert_eq!(echoes(&mut b_same).await, Some(*b"ping"));
        // The cut is on record as a failure after the allow, with its reason.
        let mut reasons = Vec::new();
        while let Ok(Some((sid, d))) = timeout(Duration::from_millis(500), rx.recv()).await {
            if sid == a && d.rule.contains("failed after the allow") {
                reasons.push(d.rule);
            }
        }
        assert!(reasons.iter().any(|r| r.contains("the operator revoked the destination")), "{reasons:?}");
        // A wildcard without a port covers every port of its hosts; the host form `127.0.0.1` covers both.
        assert_eq!(p.cut_hosts(&a, "127.0.0.1"), 1);
        assert_eq!(p.cut_hosts(&a, "127.0.0.1"), 0, "nothing left to cut");
    }

    /// A forwarded request whose destination is cut while its name still resolves is not delivered.
    #[tokio::test]
    async fn a_forward_cut_while_its_name_resolves_is_not_delivered() {
        let (port, server) = http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let resolver: Resolver = Arc::new(|_: &str| {
            std::thread::sleep(Duration::from_millis(800));
            vec!["127.0.0.1".parse().unwrap()]
        });
        let (p, _rx, _seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let s = SessionId::from("s-cut-forward");
        let g = p.grant(&s, lab()).unwrap();
        let req = format!("POST http://slow.test:{port}/x HTTP/1.1\r\n{}Content-Length: 5\r\n\r\nhello", auth(&g));
        let gp = g.port;
        let client = tokio::spawn(async move { raw(gp, req.as_bytes()).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(p.cut_hosts(&s, "slow.test"), 1);
        let resp = timeout(T, client).await.unwrap().unwrap();
        assert_eq!(status(&resp), 502, "{resp}");
        let got = timeout(T, server).await.unwrap().unwrap();
        assert!(got.is_empty(), "the destination received {:?}", String::from_utf8_lossy(&got));
    }

    /// A tunnel through `g` to `dest`, answered `200`.
    async fn tunnel_to(g: &SessionGrant, dest: &str) -> TcpStream {
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(g, dest).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        s
    }

    /// A resolver that maps every name to 127.0.0.1 and counts its calls.
    fn loopback_resolver() -> (Resolver, Arc<AtomicU64>) {
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let r: Resolver = Arc::new(move |_: &str| {
            c.fetch_add(1, Ordering::SeqCst);
            vec!["127.0.0.1".parse().unwrap()]
        });
        (r, calls)
    }

    async fn echoes(s: &mut TcpStream) -> bool {
        s.write_all(b"ping").await.is_ok() && {
            let mut got = [0u8; 4];
            timeout(Duration::from_millis(800), s.read_exact(&mut got)).await.is_ok_and(|r| r.is_ok())
        }
    }

    #[tokio::test]
    async fn cut_ends_every_connection_of_the_session_within_a_second_and_no_other() {
        let echo = echo_server().await;
        let (p, mut rx) = start().await;
        let (a, b) = (SessionId::from("s-cut-all-a"), SessionId::from("s-cut-all-b"));
        let (ga, gb) = (p.grant(&a, lab()).unwrap(), p.grant(&b, lab()).unwrap());
        // Two tunnels of A to different ports, a forwarded request of A, and a reference grant of A.
        let other = echo_server().await;
        let mut a1 = tunnel_to(&ga, &format!("127.0.0.1:{echo}")).await;
        let mut a2 = tunnel_to(&ga, &format!("127.0.0.1:{other}")).await;
        let cfg = NetworkCfg {
            mode: NetworkMode::Open,
            reference_hosts: vec![format!("127.0.0.1:{echo}")],
            allow_private: vec!["127.0.0.1".into()],
            ..NetworkCfg::default()
        };
        let reference = p.grant_reference(&a, &cfg).unwrap();
        let mut a3 = TcpStream::connect(("127.0.0.1", reference.grant.port)).await.unwrap();
        let ref_auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", reference.grant.user, reference.grant.password));
        a3.write_all(
            format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nProxy-Authorization: Basic {ref_auth}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(status(&read_until(&mut a3, "\r\n\r\n").await), 200);
        let mut b1 = tunnel_to(&gb, &format!("127.0.0.1:{echo}")).await;
        for s in [&mut a1, &mut a2, &mut a3, &mut b1] {
            assert!(echoes(s).await);
        }
        let started = tokio::time::Instant::now();
        assert_eq!(p.cut(&a), 3, "two tunnels and the reference tunnel");
        for s in [&mut a1, &mut a2, &mut a3] {
            let mut gone = Vec::new();
            let ended = timeout(Duration::from_secs(1), s.read_to_end(&mut gone)).await;
            assert!(ended.is_ok(), "a cut tunnel must close within a second");
        }
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        assert!(echoes(&mut b1).await, "another session's tunnel is not touched");
        assert_eq!(p.cut(&a), 0, "nothing is left to cut");
        // Each ended connection is on record after its allow, with the fixed reason.
        let mut reasons = Vec::new();
        while let Ok(Some((sid, d))) = timeout(Duration::from_millis(500), rx.recv()).await {
            if sid == a && d.rule.contains("failed after the allow") {
                reasons.push(d.rule);
            }
        }
        let closed = reasons.iter().filter(|r| r.contains("the session's connections were closed by loom")).count();
        assert_eq!(closed, 3, "{reasons:?}");
        // The proxy still serves the session afterwards: a cut is not a revoke.
        let mut again = tunnel_to(&ga, &format!("127.0.0.1:{echo}")).await;
        assert!(echoes(&mut again).await);
    }

    #[tokio::test]
    async fn cut_sessions_ends_the_connections_of_every_session_named() {
        let echo = echo_server().await;
        let (p, _rx) = start().await;
        let ids: Vec<SessionId> = ["s-m-1", "s-m-2", "s-m-3"].iter().map(|s| SessionId::from(*s)).collect();
        let grants: Vec<SessionGrant> = ids.iter().map(|i| p.grant(i, lab()).unwrap()).collect();
        let mut conns = Vec::new();
        for g in &grants {
            conns.push(tunnel_to(g, &format!("127.0.0.1:{echo}")).await);
        }
        assert_eq!(p.cut_sessions(ids.iter().take(2)), 2);
        for c in conns.iter_mut().take(2) {
            let mut gone = Vec::new();
            assert!(timeout(Duration::from_secs(1), c.read_to_end(&mut gone)).await.is_ok());
        }
        assert!(echoes(&mut conns[2]).await);
    }

    #[tokio::test]
    async fn a_connection_that_authenticated_before_a_cut_is_ended_when_it_registers() {
        let (p, _rx) = start().await;
        let s = SessionId::from("s-cut-race");
        let _g = p.grant(&s, lab()).unwrap();
        let shared = &p.inner.shared;
        let before = shared.cut_seq.load(Ordering::SeqCst);
        assert_eq!(p.cut(&s), 0, "no connection is open yet");
        let late = LiveGuard::register(shared, &s, "h.test", 443, before);
        assert!(late.cut.is_cancelled(), "authenticated before the cut, registered after it");
        assert_eq!(late.cut.why(), CUT_REVIEW);
        let after = shared.cut_seq.load(Ordering::SeqCst);
        let fresh = LiveGuard::register(shared, &s, "h.test", 443, after);
        assert!(!fresh.cut.is_cancelled(), "authenticated after the cut");
        let other = LiveGuard::register(shared, &SessionId::from("s-other"), "h.test", 443, before);
        assert!(!other.cut.is_cancelled(), "another session is not cut");
    }

    #[tokio::test]
    async fn a_hold_then_a_cut_leaves_the_session_nothing_open_and_nothing_new() {
        let echo = echo_server().await;
        let (p, _rx) = start().await;
        let s = SessionId::from("s-hold");
        let g = p.grant(&s, lab()).unwrap();
        let mut open = tunnel_to(&g, &format!("127.0.0.1:{echo}")).await;
        assert!(echoes(&mut open).await);
        assert!(p.set_policy(&s, policy(NetworkMode::DenyAll, &[], &[], &[])));
        assert_eq!(p.cut(&s), 1);
        let mut gone = Vec::new();
        assert!(timeout(Duration::from_secs(1), open.read_to_end(&mut gone)).await.is_ok());
        let mut fresh = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        fresh.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        let mut resp = String::new();
        let _ = timeout(T, fresh.read_to_string(&mut resp)).await;
        assert_eq!(status(&resp), 403, "{resp}");
    }

    #[tokio::test]
    async fn a_hold_also_holds_the_reference_grant_so_no_new_reference_connection_opens() {
        let echo = echo_server().await;
        let (p, _rx) = start().await;
        let s = SessionId::from("s-hold-ref");
        let g = p.grant(&s, lab()).unwrap();
        let cfg = NetworkCfg {
            mode: NetworkMode::Open,
            reference_hosts: vec![format!("127.0.0.1:{echo}")],
            allow_private: vec!["127.0.0.1".into()],
            ..NetworkCfg::default()
        };
        let reference = p.grant_reference(&s, &cfg).unwrap();
        let ref_connect = |port: u16| {
            let auth = base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", reference.grant.user, reference.grant.password));
            async move {
                let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                let req = format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n");
                c.write_all(req.as_bytes()).await.unwrap();
                let mut resp = String::new();
                let _ = timeout(T, c.read_to_string(&mut resp)).await;
                status(&resp)
            }
        };
        // A hop of an in-process GET that follows redirects opens a reference tunnel while nothing is held.
        let mut open = TcpStream::connect(("127.0.0.1", reference.grant.port)).await.unwrap();
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", reference.grant.user, reference.grant.password));
        open.write_all(
            format!("CONNECT 127.0.0.1:{echo} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(status(&read_until(&mut open, "\r\n\r\n").await), 200);
        // The hold, then the cut: the next hop is refused, not let through by a stale reference policy.
        assert!(p.hold(&s, policy(NetworkMode::DenyAll, &[], &[], &[])));
        assert_eq!(p.cut(&s), 1);
        assert_eq!(ref_connect(reference.grant.port).await, 403);
        let mut fresh = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        fresh.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        let mut resp = String::new();
        let _ = timeout(T, fresh.read_to_string(&mut resp)).await;
        assert_eq!(status(&resp), 403, "{resp}");
        assert!(!p.hold(&SessionId::from("nobody"), lab()));
    }

    #[tokio::test]
    async fn a_refused_canary_name_is_observed_in_every_path_whatever_the_policy_says() {
        let (resolver, _) = loopback_resolver();
        let (p, _rx, _seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let s = SessionId::from("s-observe");
        // Deny-all but one granted name: every canary name is refused by the policy, never reaching the veto.
        let g = p.grant(&s, policy(NetworkMode::Allowlist, &["granted.test"], &[], &["127.0.0.1"])).unwrap();
        type Seen = Arc<Mutex<Vec<(String, String, Option<String>)>>>;
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        p.set_refusal_observer(Some(Arc::new(move |_: &SessionId, d: &Dest<'_>| {
            lock(&log).push((d.host.to_string(), d.method.to_string(), d.sni.map(str::to_string)));
        })));
        p.set_veto(Some(Arc::new(|_: &SessionId, _: &Dest<'_>| None)));
        // A CONNECT and a check of a name the allowlist refuses.
        let mut c = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        c.write_all(connect_req(&g, "decoy.test:443").as_bytes()).await.unwrap();
        let mut resp = String::new();
        timeout(T, c.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert_eq!(status(&resp), 403, "{resp}");
        let mut c = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        c.write_all(format!("LOOM-CHECK decoy2.test:443 HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await.unwrap();
        let mut resp = String::new();
        timeout(T, c.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert_eq!(status(&resp), 403, "{resp}");
        // The server name of a tunnel to the granted name that the allowlist refuses.
        let echo = echo_server().await;
        let mut c = tunnel_to(&g, &format!("granted.test:{echo}")).await;
        c.write_all(&hello_for(Some("decoy3.test"), &[])).await.unwrap();
        assert!(drained(&mut c, T).await.is_empty());
        let seen = lock(&seen).clone();
        assert!(seen.contains(&("decoy.test".into(), "CONNECT".into(), None)), "{seen:?}");
        assert!(seen.contains(&("decoy2.test".into(), CHECK_METHOD.into(), None)), "{seen:?}");
        assert!(seen.contains(&("granted.test".into(), "CONNECT".into(), Some("decoy3.test".into()))), "{seen:?}");
    }

    #[tokio::test]
    async fn this_machines_own_addresses_are_told_to_the_listener_check() {
        let (p, _rx) = start().await;
        let lan: IpAddr = "192.0.2.7".parse().unwrap();
        let shared = &p.inner.shared;
        assert!(shared.reaches_this_machine("127.0.0.1".parse().unwrap()));
        assert!(shared.reaches_this_machine("::".parse().unwrap()));
        assert!(!shared.reaches_this_machine(lan));
        p.set_local_addrs(vec![lan, "::ffff:198.51.100.9".parse().unwrap()]);
        assert!(shared.reaches_this_machine(lan));
        assert!(shared.reaches_this_machine("198.51.100.9".parse().unwrap()));
        assert!(!shared.reaches_this_machine("192.0.2.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn the_veto_closes_a_destination_before_any_lookup_connect_or_byte() {
        let (server, got) = silent_server().await;
        let (resolver, lookups) = loopback_resolver();
        let (p, _rx, seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let s = SessionId::from("s-veto");
        let g = p.grant(&s, lab()).unwrap();
        type Asked = Arc<Mutex<Vec<(String, u16, String, Option<IpAddr>)>>>;
        let asked: Asked = Arc::new(Mutex::new(Vec::new()));
        let log = asked.clone();
        p.set_veto(Some(Arc::new(move |who: &SessionId, d: &Dest<'_>| {
            assert_eq!(who.as_str(), "s-veto");
            lock(&log).push((d.host.to_string(), d.port, d.method.to_string(), d.resolved));
            d.host.ends_with(".canary.test").then(|| "closed by loom".to_string())
        })));
        // A vetoed name: 502 with the marker and a fixed sentence, no lookup, nothing connected.
        let mut c = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        c.write_all(connect_req(&g, &format!("bait.canary.test:{server}")).as_bytes()).await.unwrap();
        let mut resp = String::new();
        timeout(T, c.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert_eq!(status(&resp), 502, "{resp}");
        assert!(
            resp.contains("X-Loom-Proxy: 1\r\n") && resp.contains("closed to this mission by loom's own rules"),
            "{resp}"
        );
        assert!(!resp.contains("closed by loom\n"), "the hook's own words are not in the body");
        assert_eq!(lookups.load(Ordering::SeqCst), 0, "a vetoed name is not looked up");
        {
            let seen = lock(&seen);
            let rows: Vec<&NetDecision> =
                seen.iter().map(|(_, d)| d).filter(|d| d.host == "bait.canary.test").collect();
            assert_eq!(rows.len(), 1, "{rows:?}");
            assert!(
                !rows[0].allowed && rows[0].rule == "vetoed: closed by loom" && rows[0].resolved.is_none(),
                "{rows:?}"
            );
        }
        // A check of the name is answered the same way and recorded as a check.
        let (status_of_check, d) = {
            let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
            let req = format!("LOOM-CHECK x.canary.test:443 HTTP/1.1\r\n{}\r\n", auth(&g));
            s.write_all(req.as_bytes()).await.unwrap();
            let mut resp = String::new();
            timeout(T, s.read_to_string(&mut resp)).await.unwrap().unwrap();
            let d = lock(&seen).iter().map(|(_, d)| d.clone()).find(|d| d.host == "x.canary.test").unwrap();
            (status(&resp), d)
        };
        assert_eq!(status_of_check, 502);
        assert!(d.rule.ends_with("(check only)") && !d.allowed, "{d:?}");
        // A name the veto lets through is looked up, and the hook then saw the address too.
        let mut ok = tunnel_to(&g, &format!("fine.test:{server}")).await;
        ok.write_all(b"x").await.unwrap();
        drop(ok);
        let _ = timeout(T, got).await;
        let queries = lock(&asked).clone();
        assert!(queries.iter().any(|(h, _, m, r)| h == "fine.test" && m == "CONNECT" && r.is_none()), "{queries:?}");
        assert!(
            queries.iter().any(|(h, _, _, r)| h == "fine.test" && *r == Some("127.0.0.1".parse().unwrap())),
            "{queries:?}"
        );
        // Removing the veto opens the name again.
        p.set_veto(None);
        let (server2, _got2) = silent_server().await;
        let _open = tunnel_to(&g, &format!("bait.canary.test:{server2}")).await;
    }

    #[tokio::test]
    async fn a_veto_of_the_resolved_address_stops_the_connect() {
        let (server, got) = silent_server().await;
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        let s = SessionId::from("s-veto-ip");
        let g = p.grant(&s, lab()).unwrap();
        p.set_veto(Some(Arc::new(move |_: &SessionId, d: &Dest<'_>| {
            (d.resolved == Some("127.0.0.1".parse().unwrap()) && d.port == server).then(|| "closed by loom".to_string())
        })));
        let mut c = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        c.write_all(connect_req(&g, &format!("127.0.0.1:{server}")).as_bytes()).await.unwrap();
        let mut resp = String::new();
        timeout(T, c.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert_eq!(status(&resp), 502, "{resp}");
        let rows: Vec<NetDecision> = lock(&seen).iter().map(|(_, d)| d.clone()).collect();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(!rows[0].allowed && rows[0].resolved.as_deref() == Some("127.0.0.1"), "{rows:?}");
        // The destination was never connected to: its accept is still pending.
        assert!(timeout(Duration::from_millis(300), got).await.is_err());
        // A check of the same destination is answered the same way, as the real connect would be.
        let mut c = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        let req = format!("LOOM-CHECK 127.0.0.1:{server} HTTP/1.1\r\n{}\r\n", auth(&g));
        c.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        timeout(T, c.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert_eq!(status(&resp), 502, "{resp}");
        let last = lock(&seen).last().map(|(_, d)| d.clone()).unwrap();
        assert!(!last.allowed && last.rule.starts_with("vetoed:") && last.rule.ends_with("(check only)"), "{last:?}");
    }

    /// The ClientHello bytes a client sends for `name` (`None`: no server name), with `extra` extensions.
    fn hello_for(name: Option<&str>, extra: &[(u16, Vec<u8>)]) -> Vec<u8> {
        use crate::clienthello::fixtures::{message, record, sni_ext};
        let mut ext: Vec<(u16, Vec<u8>)> = vec![(10, vec![0, 2, 0, 29])];
        if let Some(n) = name {
            ext.push(sni_ext(&[n]));
        }
        ext.extend(extra.iter().cloned());
        record(&message(&ext, true))
    }

    /// Reads until the peer ends or `wait` passes.
    async fn drained(s: &mut TcpStream, wait: Duration) -> Vec<u8> {
        let mut got = Vec::new();
        let _ = timeout(wait, s.read_to_end(&mut got)).await;
        got
    }

    #[tokio::test]
    async fn a_tls_tunnel_must_name_its_destination_or_another_name_the_policy_allows() {
        let echo = echo_server().await;
        let (resolver, _) = loopback_resolver();
        let (p, _rx, seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let s = SessionId::from("s-sni");
        let denying = policy(NetworkMode::Open, &[], &["evil.test"], &["127.0.0.1"]);
        let g = p.grant(&s, denying).unwrap();
        let dest = format!("bound.test:{echo}");
        // The destination's own name passes, and the hello reaches the destination whole (the echo returns it).
        let hello = hello_for(Some("Bound.Test"), &[]);
        let mut c = tunnel_to(&g, &dest).await;
        c.write_all(&hello).await.unwrap();
        let mut back = vec![0u8; hello.len()];
        timeout(T, c.read_exact(&mut back)).await.unwrap().unwrap();
        assert_eq!(back, hello);
        assert!(echoes(&mut c).await, "the tunnel carries on after the hello");
        let own: Vec<NetDecision> = lock(&seen).iter().map(|(_, d)| d.clone()).filter(|d| d.sni.is_some()).collect();
        assert!(own.is_empty(), "the destination's own name adds no record: {own:?}");
        // Another name the policy allows passes and is recorded with the name.
        let other = hello_for(Some("cdn.test"), &[]);
        let mut c = tunnel_to(&g, &dest).await;
        c.write_all(&other).await.unwrap();
        let mut back = vec![0u8; other.len()];
        timeout(T, c.read_exact(&mut back)).await.unwrap().unwrap();
        let rows: Vec<NetDecision> = lock(&seen).iter().map(|(_, d)| d.clone()).filter(|d| d.sni.is_some()).collect();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!(rows[0].allowed && rows[0].sni.as_deref() == Some("cdn.test"), "{rows:?}");
        assert_eq!(rows[0].host, "bound.test");
        // A name the policy denies is refused: nothing reaches the destination, the tunnel closes.
        let (server, got) = silent_server().await;
        let mut c = tunnel_to(&g, &format!("bound.test:{server}")).await;
        c.write_all(&hello_for(Some("evil.test"), &[])).await.unwrap();
        assert!(drained(&mut c, T).await.is_empty());
        let (received, _) = timeout(T, got).await.unwrap().unwrap();
        assert!(received.is_empty(), "the destination received {received:?}");
        let refused: Vec<NetDecision> = lock(&seen).iter().map(|(_, d)| d.clone()).filter(|d| !d.allowed).collect();
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(refused[0].sni.as_deref() == Some("evil.test") && refused[0].rule.contains("evil.test"), "{refused:?}");
        assert_eq!(refused[0].host, "bound.test");
    }

    #[tokio::test]
    async fn an_encrypted_hello_an_unreadable_one_and_a_missing_name_are_refused() {
        let (resolver, _) = loopback_resolver();
        let (p, _rx, seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let s = SessionId::from("s-sni-bad");
        let g = p.grant(&s, lab()).unwrap();
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("ech", hello_for(Some("other.test"), &[(0xfe0d, vec![0, 1])]), "encrypted ClientHello"),
            ("ech without a name", hello_for(None, &[(0xfe0d, vec![0, 1])]), "encrypted ClientHello"),
            ("no name", hello_for(None, &[]), "without a server name"),
            (
                "two names",
                {
                    use crate::clienthello::fixtures::{message, record, sni_ext};
                    record(&message(&[sni_ext(&["bound.test"]), sni_ext(&["bound.test"])], true))
                },
                "cannot be read",
            ),
        ];
        for (what, hello, rule) in cases {
            let (server, got) = silent_server().await;
            let mut c = tunnel_to(&g, &format!("bound.test:{server}")).await;
            c.write_all(&hello).await.unwrap();
            assert!(drained(&mut c, T).await.is_empty(), "{what}");
            let (received, _) = timeout(T, got).await.unwrap().unwrap();
            assert!(received.is_empty(), "{what}: the destination received {received:?}");
            let last = lock(&seen).last().map(|(_, d)| d.clone()).unwrap();
            assert!(!last.allowed && last.rule.contains(rule), "{what}: {last:?}");
        }
    }

    /// The placeholder (GREASE) encrypted-ClientHello extension a Chromium hello carries: outer type, one KDF and
    /// AEAD, a config id, a 32-byte encapsulated key and a payload of the usual padded size.
    fn grease_ech() -> (u16, Vec<u8>) {
        let mut d = vec![0u8, 0, 1, 0, 1, 0x5a, 0, 32];
        d.extend([0xa5; 32]);
        d.extend(144u16.to_be_bytes());
        d.extend([0x3c; 144]);
        (0xfe0d, d)
    }

    #[tokio::test]
    async fn a_browsers_placeholder_encrypted_hello_naming_the_destination_passes() {
        let echo = echo_server().await;
        let (resolver, _) = loopback_resolver();
        let (p, _rx, seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let g = p.grant(&SessionId::from("s-grease"), lab()).unwrap();
        let hello = hello_for(Some("bound.test"), &[grease_ech()]);
        let mut c = tunnel_to(&g, &format!("bound.test:{echo}")).await;
        c.write_all(&hello).await.unwrap();
        let mut back = vec![0u8; hello.len()];
        timeout(T, c.read_exact(&mut back)).await.unwrap().unwrap();
        assert_eq!(back, hello);
        assert!(lock(&seen).iter().all(|(_, d)| d.allowed), "{:?}", lock(&seen));
        // The same extension in front of a name that is not the destination is refused, nothing sent upstream.
        let (server, got) = silent_server().await;
        let mut c = tunnel_to(&g, &format!("bound.test:{server}")).await;
        c.write_all(&hello_for(Some("front.test"), &[grease_ech()])).await.unwrap();
        assert!(drained(&mut c, T).await.is_empty());
        let (received, _) = timeout(T, got).await.unwrap().unwrap();
        assert!(received.is_empty(), "{received:?}");
    }

    #[tokio::test]
    async fn a_record_in_front_of_the_hello_does_not_hide_a_fronted_name() {
        use crate::clienthello::fixtures::{message, record, sni_ext};
        let (resolver, _) = loopback_resolver();
        let (p, _rx, seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let g = p
            .grant(&SessionId::from("s-alert"), policy(NetworkMode::Open, &[], &["evil.test"], &["127.0.0.1"]))
            .unwrap();
        let hello = record(&message(&[sni_ext(&["evil.test"])], true));
        let mut skewed = hello.clone();
        skewed[1] = 0;
        skewed[2] = 0;
        let mut alerted = vec![0x15, 3, 1, 0, 2, 1, 0x5a];
        alerted.extend(&hello);
        for (what, flight) in [("alert first", alerted), ("record version 0.0", skewed)] {
            let (server, got) = silent_server().await;
            let mut c = tunnel_to(&g, &format!("bound.test:{server}")).await;
            c.write_all(&flight).await.unwrap();
            assert!(drained(&mut c, T).await.is_empty(), "{what}");
            let (received, _) = timeout(T, got).await.unwrap().unwrap();
            assert!(received.is_empty(), "{what}: the destination received {received:?}");
            let last = lock(&seen).last().map(|(_, d)| d.clone()).unwrap();
            assert!(!last.allowed && last.rule.contains("cannot be read"), "{what}: {last:?}");
        }
    }

    #[tokio::test]
    async fn a_tunnel_to_an_address_may_send_no_name_but_not_a_foreign_denied_one() {
        let echo = echo_server().await;
        let (p, _rx, _seen) = start_audited(false, Limits::default(), None).await;
        let s = SessionId::from("s-sni-ip");
        let g = p.grant(&s, policy(NetworkMode::Open, &[], &["evil.test"], &["127.0.0.1"])).unwrap();
        let hello = hello_for(None, &[]);
        let mut c = tunnel_to(&g, &format!("127.0.0.1:{echo}")).await;
        c.write_all(&hello).await.unwrap();
        let mut back = vec![0u8; hello.len()];
        timeout(T, c.read_exact(&mut back)).await.unwrap().unwrap();
        assert_eq!(back, hello);
        let mut c = tunnel_to(&g, &format!("127.0.0.1:{echo}")).await;
        c.write_all(&hello_for(Some("evil.test"), &[])).await.unwrap();
        assert!(drained(&mut c, T).await.is_empty());
    }

    /// A destination that accepts connections, records the first bytes of each and closes.
    async fn recording_server() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let log = got.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n =
                        timeout(Duration::from_secs(3), s.read(&mut buf)).await.ok().and_then(|r| r.ok()).unwrap_or(0);
                    buf.truncate(n);
                    lock(&log).push(buf);
                });
            }
        });
        (port, got)
    }

    /// A real TLS client (the system `curl`) through the proxy: its own ClientHello, whatever extensions its
    /// library sends, is read; a hello for the destination passes, one for another allowed name passes, one for a
    /// denied name never reaches the destination. Skipped where `curl` is missing.
    #[tokio::test]
    async fn a_real_tls_clients_hello_is_read_and_a_fronted_one_is_refused() {
        let Some(curl) = ["/usr/bin/curl", "/usr/local/bin/curl", "/opt/homebrew/bin/curl"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
        else {
            return;
        };
        let (port, got) = recording_server().await;
        let (resolver, _) = loopback_resolver();
        let (p, _rx, seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let s = SessionId::from("s-curl");
        let g = p.grant(&s, policy(NetworkMode::Open, &[], &["evil.test"], &["127.0.0.1"])).unwrap();
        let proxy_url = format!("http://{}:{}@127.0.0.1:{}", g.user, g.password, g.port);
        let run = |url: String, connect_to: Option<String>| {
            let (curl, proxy_url) = (curl.to_string(), proxy_url.clone());
            async move {
                tokio::task::spawn_blocking(move || {
                    let mut cmd = std::process::Command::new(curl);
                    cmd.args(["-sk", "--max-time", "4", "--proxytunnel", "--proxy", &proxy_url]);
                    if let Some(c) = connect_to {
                        cmd.args(["--connect-to", &c]);
                    }
                    cmd.arg(url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
                    let _ = cmd.status();
                })
                .await
                .unwrap();
            }
        };
        // The destination's connections that carried bytes (a refused tunnel's connection carried none).
        let hellos =
            || -> Vec<Hello> { lock(&got).iter().filter(|b| !b.is_empty()).map(|b| clienthello::parse(b)).collect() };
        let seen_hello = |at: usize| -> Option<Hello> { hellos().into_iter().nth(at) };
        // The destination's own name.
        run(format!("https://bound.test:{port}/"), None).await;
        let own = timeout(T, async {
            loop {
                if let Some(h) = seen_hello(0) {
                    return h;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the hello of a real client reached the destination");
        assert!(matches!(&own, Hello::Tls { sni: Some(n), ech: false } if n == "bound.test"), "{own:?}");
        // Fronting through the same destination with a denied name: curl connects (by CONNECT) to bound.test but
        // its hello names evil.test.
        run(format!("https://evil.test:{port}/"), Some(format!("evil.test:{port}:bound.test:{port}"))).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(hellos().len(), 1, "the fronted hello must not reach the destination: {:?}", lock(&seen));
        let refused: Vec<NetDecision> = lock(&seen).iter().map(|(_, d)| d.clone()).filter(|d| !d.allowed).collect();
        assert!(refused.iter().any(|d| d.sni.as_deref() == Some("evil.test") && d.host == "bound.test"), "{refused:?}");
        // Another name the policy allows passes.
        run(format!("https://cdn.test:{port}/"), Some(format!("cdn.test:{port}:bound.test:{port}"))).await;
        let deadline = tokio::time::Instant::now() + T;
        while hellos().len() < 2 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            matches!(seen_hello(1), Some(Hello::Tls { sni: Some(n), .. }) if n == "cdn.test"),
            "{:?}",
            seen_hello(1)
        );
    }

    #[tokio::test]
    async fn a_hello_sent_in_pieces_is_read_whole_and_other_traffic_is_not_held_up() {
        let echo = echo_server().await;
        let (resolver, _) = loopback_resolver();
        let (p, _rx, _seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let s = SessionId::from("s-sni-pieces");
        let g = p.grant(&s, lab()).unwrap();
        let hello = hello_for(Some("bound.test"), &[]);
        let mut c = tunnel_to(&g, &format!("bound.test:{echo}")).await;
        for piece in hello.chunks(7) {
            c.write_all(piece).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut back = vec![0u8; hello.len()];
        timeout(T, c.read_exact(&mut back)).await.unwrap().unwrap();
        assert_eq!(back, hello);
        // Not TLS: an HTTP request passes at once, whatever the destination is called.
        let mut c = tunnel_to(&g, &format!("bound.test:{echo}")).await;
        c.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut back = [0u8; 18];
        timeout(T, c.read_exact(&mut back)).await.unwrap().unwrap();
        assert_eq!(&back, b"GET / HTTP/1.1\r\n\r\n");
        // A server that speaks first needs nothing from the client.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let banner_port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let _ = s.write_all(b"SSH-2.0-test\r\n").await;
                let _ = timeout(T, s.read_to_end(&mut Vec::new())).await;
            }
        });
        let mut c = tunnel_to(&g, &format!("127.0.0.1:{banner_port}")).await;
        let mut banner = [0u8; 14];
        timeout(Duration::from_secs(2), c.read_exact(&mut banner)).await.unwrap().unwrap();
        assert_eq!(&banner, b"SSH-2.0-test\r\n");
        // A hello that stops half way is refused after the head timeout, not held for ever.
        let (server, got) = silent_server().await;
        let limits = Limits { head_timeout: Duration::from_millis(400), ..Limits::default() };
        let (p2, _rx2, seen2) = start_audited(false, limits, None).await;
        let g2 = p2.grant(&SessionId::from("s-sni-stall"), lab()).unwrap();
        let mut c = tunnel_to(&g2, &format!("127.0.0.1:{server}")).await;
        c.write_all(&hello[..10]).await.unwrap();
        assert!(drained(&mut c, T).await.is_empty());
        assert!(timeout(T, got).await.unwrap().unwrap().0.is_empty());
        let last = lock(&seen2).last().map(|(_, d)| d.clone()).unwrap();
        assert!(!last.allowed && last.rule.contains("did not arrive in full"), "{last:?}");
    }

    #[tokio::test]
    async fn a_canary_user_fires_the_hook_before_the_answer_and_is_answered_as_an_unknown_user() {
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        let s = SessionId::from("s-canary");
        let g = p.grant(&s, lab()).unwrap();
        let hits: Arc<Mutex<Vec<CanaryHit>>> = Arc::new(Mutex::new(Vec::new()));
        let log = hits.clone();
        p.set_canary_hook(Some(Arc::new(move |h: &CanaryHit| lock(&log).push(h.clone()))));
        assert!(p.add_canary_user("loom-helper-7f3a", "CN-1 mission m1").is_ok());
        assert!(p.add_canary_user("", "x").is_err());
        let err = p.add_canary_user(s.as_str(), "x").err().unwrap_or_default();
        assert!(err.contains("cannot be a canary"), "{err}");
        let creds = base64::engine::general_purpose::STANDARD.encode("loom-helper-7f3a:0123456789abcdef");
        let req = format!("CONNECT 169.254.169.254:80 HTTP/1.1\r\nProxy-Authorization: Basic {creds}\r\n\r\n");
        // On the session's listener: attributed to the session, answered 407 as an unknown user is.
        let mut c = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        c.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        timeout(T, c.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert_eq!(status(&resp), 407, "{resp}");
        assert!(resp.contains("Proxy-Authenticate"), "{resp}");
        let unknown = base64::engine::general_purpose::STANDARD.encode("nobody:0123456789abcdef");
        let plain = raw(
            g.port,
            format!("CONNECT 169.254.169.254:80 HTTP/1.1\r\nProxy-Authorization: Basic {unknown}\r\n\r\n").as_bytes(),
        )
        .await;
        assert_eq!(resp, plain, "a decoy's answer is an unknown user's, byte for byte");
        // The hook had run when the answer arrived.
        {
            let hits = lock(&hits);
            assert_eq!(hits.len(), 1, "{hits:?}");
            assert_eq!(hits[0].user, "loom-helper-7f3a");
            assert_eq!(hits[0].label, "CN-1 mission m1");
            assert_eq!(hits[0].listener.as_ref(), Some(&s));
            assert_eq!(
                (hits[0].host.as_str(), hits[0].port, hits[0].method.as_str()),
                ("169.254.169.254", 80, "CONNECT")
            );
        }
        // The record is attributed to the listener's session and says only what an unknown user's says.
        let rules: Vec<(Option<String>, String)> =
            lock(&seen).iter().map(|(s, d)| (s.as_ref().map(|s| s.as_str().to_string()), d.rule.clone())).collect();
        assert!(rules.iter().all(|(_, r)| !r.to_lowercase().contains("canary") && !r.contains("CN-1")), "{rules:?}");
        assert!(
            rules.contains(&(Some("s-canary".to_string()), "proxy authentication failed: unknown user".to_string())),
            "{rules:?}"
        );
        // On the shared listener the attempt is unattributed, and a run of them is never capped.
        for _ in 0..(UNATTRIBUTED_PER_MINUTE + 15) {
            let resp = raw(p.port(), req.as_bytes()).await;
            assert_eq!(status(&resp), 407);
        }
        assert_eq!(lock(&hits).len(), 1 + (UNATTRIBUTED_PER_MINUTE as usize) + 15);
        assert!(lock(&hits).iter().skip(1).all(|h| h.listener.is_none()));
        let unattributed = lock(&seen)
            .iter()
            .filter(|(s, d)| s.is_none() && d.rule == "proxy authentication failed: unknown user")
            .count();
        // (One more: the unknown user of the comparison above.)
        assert_eq!(unattributed, (UNATTRIBUTED_PER_MINUTE as usize) + 15 + 1, "none of them was left out");
        // A removed decoy is an unknown user again, and no hook fires.
        assert!(p.remove_canary_user("loom-helper-7f3a"));
        let _ = raw(g.port, req.as_bytes()).await;
        assert_eq!(lock(&hits).len(), 1 + (UNATTRIBUTED_PER_MINUTE as usize) + 15);
    }

    #[tokio::test]
    async fn the_listener_check_refuses_a_loopback_destination_whose_listener_it_names() {
        let (allowed_port, _) = silent_server().await;
        let echo = echo_server().await;
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        let s = SessionId::from("s-listener");
        let g = p.grant(&s, lab()).unwrap();
        let asked: Arc<Mutex<Vec<(String, SocketAddr)>>> = Arc::new(Mutex::new(Vec::new()));
        let log = asked.clone();
        p.set_listener_check(Some(Arc::new(move |who: &SessionId, to: SocketAddr, client: Option<SocketAddr>| {
            // The local end of the connection the proxy opened is what names the process that holds the other end.
            assert!(client.is_some_and(|c| c.ip().is_loopback() && c.port() != 0), "{client:?}");
            lock(&log).push((who.as_str().to_string(), to));
            (to.port() == echo).then(|| "deny a listener started inside a loom sandbox".to_string())
        })));
        let mut c = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        c.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        let mut resp = String::new();
        timeout(T, c.read_to_string(&mut resp)).await.unwrap().unwrap();
        assert_eq!(status(&resp), 403, "{resp}");
        assert!(resp.contains("deny a listener started inside a loom sandbox"), "{resp}");
        let last = lock(&seen).last().map(|(_, d)| d.clone()).unwrap();
        assert!(
            !last.allowed && last.rule.contains("listener") && last.resolved.as_deref() == Some("127.0.0.1"),
            "{last:?}"
        );
        // Another port on loopback is let through, and the hook saw both asks with the session.
        let _ok = tunnel_to(&g, &format!("127.0.0.1:{allowed_port}")).await;
        let asked = lock(&asked).clone();
        assert!(asked.iter().all(|(who, _)| who == "s-listener"), "{asked:?}");
        assert!(asked.iter().any(|(_, to)| to.port() == echo) && asked.iter().any(|(_, to)| to.port() == allowed_port));
        // A forwarded request is checked the same way.
        let req = format!("GET http://127.0.0.1:{echo}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        assert_eq!(status(&raw(g.port, req.as_bytes()).await), 403);
    }

    #[tokio::test]
    async fn a_connection_is_judged_by_the_policy_the_session_holds_when_it_is_registered() {
        let (p, _rx) = start().await;
        let s = SessionId::from("s-current");
        let _g = p.grant(&s, lab()).unwrap();
        let shared = &p.inner.shared;
        let stale = lock(&shared.sessions).values().next().map(|e| e.policy.clone()).unwrap();
        assert!(current_policy(shared, &s, false, stale.clone()).check_name("127.0.0.1", 80).allowed);
        assert!(p.set_policy(&s, policy(NetworkMode::DenyAll, &[], &[], &[])));
        assert!(!current_policy(shared, &s, false, stale).check_name("127.0.0.1", 80).allowed);
    }

    /// A response as an HTTP client sees it: status, headers (names lower-cased), body.
    fn client_view(resp: &str) -> (u16, Vec<(String, String)>, String) {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut r = httparse::Response::new(&mut headers);
        let n = match r.parse(resp.as_bytes()) {
            Ok(httparse::Status::Complete(n)) => n,
            other => panic!("the client cannot read {resp:?}: {other:?}"),
        };
        let headers = r
            .headers
            .iter()
            .map(|h| (h.name.to_ascii_lowercase(), String::from_utf8_lossy(h.value).to_string()))
            .collect();
        (r.code.unwrap(), headers, resp[n..].to_string())
    }

    #[tokio::test]
    async fn upstream_proxy_marker_is_not_relayed() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-mark"), lab()).unwrap();
        let (port, _server) =
            http_server("HTTP/1.1 403 Forbidden\r\nx-loom-proxy: 1\r\nX-Other: kept\r\nContent-Length: 4\r\n\r\nnope")
                .await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(g.port, req.as_bytes()).await;
        assert_eq!(status(&resp), 403, "{resp}");
        assert!(!resp.to_ascii_lowercase().contains("loom-proxy"), "{resp}");
        assert!(resp.contains("X-Other: kept\r\n") && resp.ends_with("\r\n\r\nnope"), "{resp}");
        // Heads with bare LF line ends: the proxy reads them as a client does, so the marker cannot hide.
        let cases: [(&'static str, u16, &str); 3] = [
            ("HTTP/1.1 403 Forbidden\r\nX-A: b\nX-Loom-Proxy: 1\r\nContent-Length: 4\r\n\r\nnope", 403, "nope"),
            ("HTTP/1.1 403 Forbidden\nX-Loom-Proxy: 1\nContent-Length: 8\n\nab\r\n\r\ncd", 403, "ab\r\n\r\ncd"),
            ("HTTP/1.0 200 OK\n\nhi", 200, "hi"),
        ];
        for (reply, code, body) in cases {
            let (port, _server) = http_server(reply).await;
            let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
            let resp = raw(g.port, req.as_bytes()).await;
            let (got_code, headers, got_body) = client_view(&resp);
            assert_eq!((got_code, got_body.as_str()), (code, body), "{reply:?} -> {resp:?}");
            assert!(!headers.iter().any(|(n, _)| n == "x-loom-proxy"), "{reply:?} -> {resp:?}");
        }
        // A destination that does not speak HTTP gets a proxy-generated 502, which does carry the marker.
        let (port, _server) = http_server("not http at all\r\n\r\n").await;
        let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        let resp = raw(g.port, req.as_bytes()).await;
        assert_eq!(status(&resp), 502, "{resp}");
        assert!(resp.contains("X-Loom-Proxy: 1\r\n"));
    }

    #[tokio::test]
    async fn a_forwarded_response_says_connection_close_and_ends_the_connection() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-close"), lab()).unwrap();
        let first = "HTTP/1.1 302 Found\r\nLocation: /b\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\
                     Proxy-Connection: keep-alive\r\nContent-Length: 0\r\n\r\n";
        let (port, _server) = two_answer_server(first, FORGED, Duration::from_secs(2)).await;
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await.unwrap();
        let head = read_until(&mut s, "\r\n\r\n").await;
        let started = tokio::time::Instant::now();
        // A client that ignores the head sends the next hop on the same connection.
        let _ = s.write_all(format!("GET http://127.0.0.1:{port}/b HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await;
        let mut rest = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut rest)).await;
        assert!(head.starts_with("HTTP/1.1 302 Found\r\nLocation: /b\r\n"), "{head}");
        assert_eq!(head.matches("Connection: close\r\n").count(), 1, "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(!lower.contains("keep-alive") && !lower.contains("proxy-connection"), "{head}");
        assert!(rest.is_empty(), "{:?}", String::from_utf8_lossy(&rest));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the proxy waited for the destination: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn chunked_bodies_are_followed_to_their_end_across_any_split() {
        let bodies = [
            "0\r\n\r\n",
            "2\r\nok\r\n0\r\n\r\n",
            "A;name=value\r\n0123456789\r\n0\r\nX-Trailer: t\r\nY: u\r\n\r\n",
            " 3 \nabc\n0\n\n",
            "00002\r\nok\r\r\n0\r\n\r\n",
        ];
        for body in bodies {
            let all = format!("{body}{FORGED}");
            for split in 0..=all.len() {
                let (a, b) = all.as_bytes().split_at(split);
                let mut c = Chunked::new();
                let used = c.feed(a).unwrap() + c.feed(b).unwrap();
                assert_eq!(used, body.len(), "{body:?} split at {split}");
                assert!(c.done(), "{body:?} split at {split}");
            }
        }
        let mut c = Chunked::new();
        assert_eq!(c.feed(b"5\r\nab"), Ok(5));
        assert!(!c.done());
        for bad in ["x\r\n", "\r\n", "2\r\nokX", "1FFFFFFFFFFFFFFFF\r\n"] {
            assert!(Chunked::new().feed(bad.as_bytes()).is_err(), "{bad:?}");
        }
        // A request body the proxy cannot follow is passed on whole.
        let mut owed = Owed::Chunked(Chunked::new());
        assert_eq!(owed.take(b"zz\r\nmore"), 8);
        assert!(matches!(owed, Owed::Stream));
    }

    #[tokio::test]
    async fn a_chunked_response_ends_after_its_last_chunk_and_trailers() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-chunked"), lab()).unwrap();
        let body = "2\r\nok\r\n3;note=x\r\nabc\r\n0\r\nX-Trailer: t\r\n\r\n";
        // The forged answer comes in the same segment as the last chunk, or later on the same connection.
        let together =
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n{body}{FORGED}");
        let apart = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n{body}");
        for (first, second) in [(together.as_str(), ""), (apart.as_str(), FORGED)] {
            for pipelined in [false, true] {
                let (port, _server) = two_answer_server(first, second, Duration::from_secs(2)).await;
                let one = format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\n{}\r\n", auth(&g));
                let req = if pipelined { one.repeat(2) } else { one };
                let started = tokio::time::Instant::now();
                let resp = raw(g.port, req.as_bytes()).await;
                assert!(started.elapsed() < Duration::from_secs(1), "{first:?}: {:?}", started.elapsed());
                let (code, headers, got) = client_view(&resp);
                assert_eq!((code, got.as_str()), (200, body), "{resp:?}");
                // A length beside the transfer coding is dropped, so no client reads the body by it.
                assert!(!headers.iter().any(|(n, _)| n == "content-length"), "{resp:?}");
                assert_eq!(headers.last().map(|(n, v)| (n.as_str(), v.as_str())), Some(("connection", "close")));
            }
        }
    }

    #[tokio::test]
    async fn a_response_ends_at_its_head_or_after_its_length() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-length"), lab()).unwrap();
        let cases: [(&str, &str, u16, &str); 5] = [
            // No body for HEAD, 204 and 304, whatever the length says.
            ("HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", 200, ""),
            ("GET", "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello", 204, ""),
            ("GET", "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nhello", 304, ""),
            // Bytes past the length are not relayed; repeated equal values are one length.
            ("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokay", 200, "ok"),
            ("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nokay", 200, "ok"),
        ];
        for (method, first, code, body) in cases {
            let (port, _server) = two_answer_server(first, FORGED, Duration::from_secs(2)).await;
            let req = format!("{method} http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
            let started = tokio::time::Instant::now();
            let resp = raw(g.port, req.as_bytes()).await;
            assert!(started.elapsed() < Duration::from_secs(1), "{first:?}: {:?}", started.elapsed());
            let (got_code, _, got_body) = client_view(&resp);
            assert_eq!((got_code, got_body.as_str()), (code, body), "{first:?} -> {resp:?}");
        }
        // A length that clients would read differently gets a 502 from the proxy.
        let unclear = [
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nokay",
            "HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok",
        ];
        for first in unclear {
            let (port, _server) = two_answer_server(first, "", Duration::from_secs(2)).await;
            let req = format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
            let resp = raw(g.port, req.as_bytes()).await;
            assert_eq!(status(&resp), 502, "{first:?} -> {resp:?}");
            assert!(
                resp.contains("X-Loom-Proxy: 1\r\n") && resp.contains("invalid or conflicting Content-Length"),
                "{resp}"
            );
        }
    }

    #[tokio::test]
    async fn a_client_that_sends_more_than_its_request_cuts_a_response_that_runs_until_close() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-more"), lab()).unwrap();
        let gap = Duration::from_secs(2);
        let get = |port: u16| format!("GET http://127.0.0.1:{port}/ HTTP/1.1\r\n{}\r\n", auth(&g));
        // Two requests in one write: only the first is forwarded, and its answer ends the connection.
        let (port, server) = two_answer_server("HTTP/1.0 200 OK\r\n\r\nfirst", FORGED, gap).await;
        let started = tokio::time::Instant::now();
        let resp = raw(g.port, get(port).repeat(2).as_bytes()).await;
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        assert_eq!(client_view(&resp).2, "first", "{resp:?}");
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert_eq!(got.matches("GET ").count(), 1, "{got}");
        // The end of a body and a further request in one read, while the destination is silent.
        let (port, server) = two_answer_server("HTTP/1.0 200 OK\r\n\r\nfirst", FORGED, gap).await;
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        let post = format!("POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Content-Length: 4\r\n\r\nbo", auth(&g));
        s.write_all(post.as_bytes()).await.unwrap();
        let begun = read_until(&mut s, "first").await;
        let started = tokio::time::Instant::now();
        s.write_all(format!("dy{}", get(port)).as_bytes()).await.unwrap();
        let mut rest = Vec::new();
        let _ = timeout(T, s.read_to_end(&mut rest)).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the proxy waited for the destination: {:?}",
            started.elapsed()
        );
        assert!(begun.ends_with("\r\n\r\nfirst") && rest.is_empty(), "{begun:?} {:?}", String::from_utf8_lossy(&rest));
        let got = String::from_utf8(server.await.unwrap()).unwrap();
        assert!(got.ends_with("\r\n\r\nbody") && !got.contains("GET "), "{got}");
        // Empty lines after a body are not a further request.
        let (port, _server) = two_answer_server("HTTP/1.0 200 OK\r\n\r\none", "two", Duration::from_millis(300)).await;
        let req = format!("POST http://127.0.0.1:{port}/ HTTP/1.1\r\n{}Content-Length: 4\r\n\r\nbody\r\n", auth(&g));
        assert_eq!(client_view(&raw(g.port, req.as_bytes()).await).2, "onetwo");
    }

    #[tokio::test]
    async fn env_and_grant_contents() {
        let (p, _rx) = start().await;
        let g = p.grant(&SessionId::from("s-env"), lab()).unwrap();
        assert_ne!(g.port, p.port());
        assert_eq!(Some(g.port), p.session_port(&SessionId::from("s-env")));
        assert_eq!(g.user, "s-env");
        assert_eq!(g.password.len(), 32);
        assert!(g.password.chars().all(|c| c.is_ascii_hexdigit()));
        let url = format!("http://s-env:{}@127.0.0.1:{}", g.password, g.port);
        assert_eq!(g.url(), url);
        let env = g.env();
        assert_eq!(env.len(), 8);
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
            assert_eq!(env.get(k), Some(&url), "{k}");
        }
        assert_eq!(env.get("NO_PROXY").map(String::as_str), Some(""));
        assert_eq!(env.get("no_proxy").map(String::as_str), Some(""));
        let g2 = p.grant(&SessionId::from("s-env2"), lab()).unwrap();
        assert_ne!(g.password, g2.password);
        assert_ne!(g.port, g2.port);
    }

    /// The decisions of the audit hook, as (session, rule).
    fn audited(seen: &Seen) -> Vec<(Option<String>, String)> {
        lock(seen).iter().map(|(s, d)| (s.as_ref().map(|s| s.as_str().to_string()), d.rule.clone())).collect()
    }

    /// A destination that counts the connections it accepts.
    async fn counting_server() -> (u16, Arc<AtomicU64>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let count = Arc::new(AtomicU64::new(0));
        let seen = count.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                seen.fetch_add(1, Ordering::SeqCst);
                drop(s);
            }
        });
        (port, count)
    }

    #[tokio::test]
    async fn each_session_has_its_own_listener_and_foreign_credentials_get_407() {
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        let echo = echo_server().await;
        let (a, b) = (SessionId::from("s-la-a"), SessionId::from("s-la-b"));
        let (ga, gb) = (p.grant(&a, lab()).unwrap(), p.grant(&b, lab()).unwrap());
        assert_ne!(ga.port, gb.port);
        assert!(ga.port != p.port() && gb.port != p.port());
        assert_eq!((p.session_port(&a), p.session_port(&b)), (Some(ga.port), Some(gb.port)));
        assert_eq!(p.session_port(&SessionId::from("s-none")), None);
        let dest = format!("127.0.0.1:{echo}");
        // Each works on its own port.
        assert_eq!(status(&raw(ga.port, connect_req(&ga, &dest).as_bytes()).await), 200);
        assert_eq!(status(&raw(gb.port, connect_req(&gb, &dest).as_bytes()).await), 200);
        // B's valid credentials on A's port: 407, nothing connected, one refusal recorded for A naming B.
        let (counted, accepted) = counting_server().await;
        let r = raw(ga.port, connect_req(&gb, &format!("127.0.0.1:{counted}")).as_bytes()).await;
        assert_eq!(status(&r), 407, "{r}");
        assert!(r.contains("Proxy-Authenticate: Basic"), "{r}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(accepted.load(Ordering::SeqCst), 0, "the destination listener accepted a connection");
        let refusals = |seen: &Seen| -> Vec<(Option<String>, String)> {
            audited(seen).into_iter().filter(|(_, rule)| rule.starts_with("proxy authentication failed")).collect()
        };
        assert_eq!(
            refusals(&seen),
            [(
                Some("s-la-a".to_string()),
                "proxy authentication failed: credentials of session s-la-b on the port of session s-la-a".to_string()
            )]
        );
        assert!(lock(&seen)
            .iter()
            .filter(|(_, d)| d.rule.starts_with("proxy authentication"))
            .all(|(_, d)| !d.allowed));
        // A's credentials on the shared port: 407, unattributed.
        let r = raw(p.port(), connect_req(&ga, &dest).as_bytes()).await;
        assert_eq!(status(&r), 407, "{r}");
        assert_eq!(
            refusals(&seen).last().unwrap(),
            &(None, "proxy authentication failed: credentials of session s-la-a on the shared port".to_string())
        );
    }

    #[tokio::test]
    async fn reference_grants_work_on_the_shared_port_only() {
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        let (port, _server) = http_server("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
        let sid = SessionId::from("s-ref-port");
        let cfg = NetworkCfg {
            mode: NetworkMode::Open,
            reference_hosts: vec![format!("127.0.0.1:{port}")],
            allow_private: vec!["127.0.0.1".into()],
            ..NetworkCfg::default()
        };
        let g = p.grant(&sid, lab()).unwrap();
        let reference = p.grant_reference(&sid, &cfg).unwrap();
        assert_eq!(reference.grant.port, p.port());
        let req = format!("GET http://127.0.0.1:{port}/x HTTP/1.1\r\n{}\r\n", auth(&reference.grant));
        let refused = raw(g.port, req.as_bytes()).await;
        assert_eq!(status(&refused), 407, "{refused}");
        assert_eq!(
            audited(&seen).last().unwrap(),
            &(
                Some("s-ref-port".to_string()),
                "proxy authentication failed: reference credentials on the port of session s-ref-port".to_string()
            )
        );
        let ok = raw(p.port(), req.as_bytes()).await;
        assert_eq!(status(&ok), 200, "{ok}");
    }

    #[tokio::test]
    async fn a_second_grant_keeps_the_port_and_replaces_the_password() {
        let (p, _rx) = start().await;
        let echo = echo_server().await;
        let sid = SessionId::from("s-again");
        let first = p.grant(&sid, lab()).unwrap();
        let second = p.grant(&sid, lab()).unwrap();
        assert_eq!(first.port, second.port);
        assert_ne!(first.password, second.password);
        let dest = format!("127.0.0.1:{echo}");
        assert_eq!(status(&raw(first.port, connect_req(&first, &dest).as_bytes()).await), 407);
        assert_eq!(status(&raw(second.port, connect_req(&second, &dest).as_bytes()).await), 200);
    }

    #[tokio::test]
    async fn revoke_closes_the_listener_and_retires_its_port() {
        let (p, _rx) = start().await;
        let echo = echo_server().await;
        let (a, b) = (SessionId::from("s-rv-a"), SessionId::from("s-rv-b"));
        let (ga, gb) = (p.grant(&a, lab()).unwrap(), p.grant(&b, lab()).unwrap());
        let gone = async |port: u16| {
            let deadline = tokio::time::Instant::now() + T;
            loop {
                if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                    return true;
                }
                if tokio::time::Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        assert!(TcpStream::connect(("127.0.0.1", ga.port)).await.is_ok());
        p.revoke(&a);
        assert!(gone(ga.port).await, "a revoked session's listener still accepts");
        assert_eq!(p.session_port(&a), None);
        assert!(lock(&p.inner.listeners).get("s-rv-a").is_none());
        // 20 new sessions never get A's port.
        for i in 0..20 {
            let g = p.grant(&SessionId::from(format!("s-rv-new-{i}").as_str()), lab()).unwrap();
            assert_ne!(g.port, ga.port);
        }
        // A later grant of A opens a new listener on another port; the old credentials do not work there.
        let again = p.grant(&a, lab()).unwrap();
        assert_ne!(again.port, ga.port);
        assert_eq!(p.session_port(&a), Some(again.port));
        let dest = format!("127.0.0.1:{echo}");
        assert_eq!(status(&raw(again.port, connect_req(&ga, &dest).as_bytes()).await), 407);
        assert_eq!(status(&raw(again.port, connect_req(&again, &dest).as_bytes()).await), 200);
        assert!(TcpStream::connect(("127.0.0.1", gb.port)).await.is_ok());
        assert!(TcpStream::connect(("127.0.0.1", p.port())).await.is_ok());
        p.shutdown();
        assert!(gone(ga.port).await, "a session listener still accepts after shutdown");
        assert!(gone(gb.port).await, "a session listener still accepts after shutdown");
        assert!(gone(p.port()).await, "the shared listener still accepts after shutdown");
    }

    #[tokio::test]
    async fn no_fresh_port_gives_a_bind_error_and_leaves_nothing_bound() {
        let (p, _rx) = start().await;
        let tried = Mutex::new(Vec::new());
        let e = open_fresh_listener(&p.inner.shared, &|port| {
            lock(&tried).push(port);
            true
        })
        .expect_err("every port is retired, so no listener opens");
        let text = e.to_string();
        assert!(text.contains("No fresh loopback port was found") && text.contains("restarting the daemon"), "{text}");
        let tried = lock(&tried).clone();
        assert_eq!(tried.len(), LISTENER_ATTEMPTS);
        // The sockets set aside are closed: each of those ports can be bound again.
        for port in tried {
            assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok(), "port {port} is still bound");
        }
        assert!(lock(&p.inner.shared.own_ports).len() == 1);
    }

    #[tokio::test]
    async fn the_proxy_never_connects_to_its_own_ports() {
        let resolver: Resolver =
            Arc::new(|name: &str| if name == "localhost" { vec![IpAddr::from([127, 0, 0, 1])] } else { Vec::new() });
        let (p, mut rx, _seen) = start_audited(false, Limits::default(), Some(resolver)).await;
        let echo = echo_server().await;
        let (a, b) = (SessionId::from("s-own-a"), SessionId::from("s-own-b"));
        let (ga, gb) = (p.grant(&a, lab()).unwrap(), p.grant(&b, lab()).unwrap());
        // A revoked session's port is still the proxy's own.
        let c = SessionId::from("s-own-c");
        let gc = p.grant(&c, lab()).unwrap();
        p.revoke(&c);
        while rx.try_recv().is_ok() {}
        for port in [gb.port, ga.port, p.port(), gc.port] {
            let rule = format!("deny the egress proxy's own port {port}");
            for host in ["127.0.0.1", "[::ffff:127.0.0.1]", "0.0.0.0", "localhost", "[::1]", "127.1.2.3"] {
                let dest = format!("{host}:{port}");
                let connect = raw(ga.port, connect_req(&ga, &dest).as_bytes()).await;
                let forwarded =
                    raw(ga.port, format!("GET http://{dest}/ HTTP/1.1\r\n{}\r\n", auth(&ga)).as_bytes()).await;
                let checked =
                    raw(ga.port, format!("{CHECK_METHOD} {dest} HTTP/1.1\r\n{}\r\n", auth(&ga)).as_bytes()).await;
                for (what, r) in [("CONNECT", connect), ("GET", forwarded), ("check", checked)] {
                    assert_eq!(status(&r), 403, "{what} {dest}: {r}");
                    assert!(r.contains(&rule), "{what} {dest}: {r}");
                }
            }
        }
        // Another loopback port is still allowed, by tunnel and by check.
        let dest = format!("127.0.0.1:{echo}");
        assert_eq!(status(&raw(ga.port, connect_req(&ga, &dest).as_bytes()).await), 200);
        let r = raw(ga.port, format!("{CHECK_METHOD} {dest} HTTP/1.1\r\n{}\r\n", auth(&ga)).as_bytes()).await;
        assert_eq!(status(&r), 200, "{r}");
    }

    #[tokio::test]
    async fn an_open_connection_survives_the_revoke_of_its_session() {
        let (p, _rx) = start().await;
        let echo = echo_server().await;
        let sid = SessionId::from("s-rv-open");
        let g = p.grant(&sid, lab()).unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{echo}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        p.revoke(&sid);
        s.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        timeout(T, s.read_exact(&mut got)).await.unwrap().unwrap();
        assert_eq!(&got, b"ping");
    }

    #[test]
    fn grant_outside_a_runtime_is_an_error_not_a_panic() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let (p, _rx) = rt.block_on(start());
        let e = p.grant(&SessionId::from("s-no-rt"), lab()).unwrap_err();
        assert!(e.to_string().contains("Tokio runtime"), "{e}");
    }

    #[tokio::test]
    async fn shutdown_during_a_tunnel_or_forward_is_recorded_after_the_allow() {
        let (p, _rx, seen) = start_audited(false, Limits::default(), None).await;
        let g = p.grant(&SessionId::from("s-down"), lab()).unwrap();
        let (port, _server) = silent_server().await;
        let mut s = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        s.write_all(connect_req(&g, &format!("127.0.0.1:{port}")).as_bytes()).await.unwrap();
        assert_eq!(status(&read_until(&mut s, "\r\n\r\n").await), 200);
        let (port2, _server2) = silent_server().await;
        let mut f = TcpStream::connect(("127.0.0.1", g.port)).await.unwrap();
        f.write_all(format!("GET http://127.0.0.1:{port2}/ HTTP/1.1\r\n{}\r\n", auth(&g)).as_bytes()).await.unwrap();
        // The methods of the allowed requests recorded with `rule`, sorted.
        let methods = |rule: &str| -> Vec<String> {
            let seen = lock(&seen);
            let mut m: Vec<String> =
                seen.iter().filter(|(_, d)| d.allowed && d.rule == rule).map(|(_, d)| d.method.clone()).collect();
            m.sort();
            m
        };
        // Both are on record as allowed before the proxy shuts down; from there nothing is checked before
        // the relay, which sees the shutdown even when it starts after it.
        let deadline = tokio::time::Instant::now() + T;
        while methods("allow_private 127.0.0.1") != ["CONNECT", "GET"] {
            assert!(tokio::time::Instant::now() < deadline, "{:?}", lock(&seen));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // `stop` returns once the connections have ended, their records written.
        timeout(T, p.stop(T)).await.unwrap();
        let shut = "allow_private 127.0.0.1 (failed after the allow: the egress proxy shut down)";
        assert_eq!(methods(shut), ["CONNECT", "GET"], "{:?}", lock(&seen));
    }

    #[tokio::test]
    async fn bind_error_and_shutdown() {
        let (p, _rx) = start().await;
        let (tx, _r2) = unbounded_channel();
        let e = Proxy::start(p.port(), tx).await.err().unwrap();
        assert!(e.to_string().contains(&p.port().to_string()));
        let port = p.port();
        p.shutdown();
        let deadline = tokio::time::Instant::now() + T;
        loop {
            if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "still accepting after shutdown");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn dropping_the_last_handle_stops_the_server() {
        let (p, _rx) = start().await;
        let port = p.port();
        let q = p.clone();
        drop(p);
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_ok());
        drop(q);
        let deadline = tokio::time::Instant::now() + T;
        while TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            assert!(tokio::time::Instant::now() < deadline, "still accepting after drop");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(parse_authority("Example.TEST.:443", None), Ok(("example.test".into(), 443)));
        assert_eq!(parse_authority("example.test", Some(80)), Ok(("example.test".into(), 80)));
        assert_eq!(parse_authority("[::1]:8080", None), Ok(("::1".into(), 8080)));
        assert_eq!(parse_authority("[::1]", Some(80)), Ok(("::1".into(), 80)));
        for bad in ["", "host", "host:", "host:99999", "a@b:1", "::1:80", "[::1", "[x]:1", "h st:1", ":80"] {
            assert!(parse_authority(bad, None).is_err(), "{bad:?}");
        }
    }
}
