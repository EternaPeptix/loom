//! The proxy server.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! `Proxy::start(port, sink)` binds `127.0.0.1:{port}` (0 = any free port) and serves until
//! `shutdown` or drop. It speaks HTTP/1.1 proxying only:
//! - `CONNECT host:port` → on success `HTTP/1.1 200 Connection established\r\n\r\n`, then bytes are
//!   copied both ways until either side closes;
//! - a request with an absolute `http://` URI → the proxy connects to that host (port 80 by
//!   default), sends the request with an origin-form target, drops `Proxy-Authorization` and
//!   `Proxy-Connection`, adds `Connection: close`, and copies the request body and the response
//!   through unchanged. One request per client connection.
//! - anything else (origin-form target, `https://` absolute URI, unparseable head, a head larger than
//!   64 KiB, no head within 30 s) → `400` with a sentence.
//!
//! ## Sessions
//! `grant(session, policy)` returns a [`SessionGrant`] with fresh random credentials (user = the
//! session id, password = 32 hex chars). The client authenticates with `Proxy-Authorization: Basic`.
//! Missing or unknown credentials → `407` with `Proxy-Authenticate: Basic realm="loom"`.
//! `revoke(session)` drops them; connections already open are left to finish.
//! `SessionGrant::env()` gives the variables to place in a command's environment so that ordinary
//! clients use the proxy: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lower-case forms, all
//! `http://{user}:{password}@127.0.0.1:{port}`, plus `NO_PROXY`/`no_proxy` = `` (empty, so loopback
//! labs also pass policy unless the sandbox opens their ports directly).
//!
//! ## Deciding and connecting
//! For each request: `policy.check_name` → if allowed, resolve the name (`tokio::net::lookup_host`;
//! an IP literal resolves to itself), then walk the resolved addresses in order and connect to the
//! first one that `policy.check_addr` allows (10 s connect timeout each). The connection is made to
//! that checked address, never by name, so a second lookup cannot change the destination. If every
//! address is refused the decision is the first refusal.
//! Every request produces exactly one `NetDecision` sent to `sink` together with the session id:
//! `host`, `port`, `method` (`CONNECT` or the request method), `allowed`, `rule`, `resolved` (the
//! address connected to, or the refused address, when there is one). Resolution or connect failures
//! after an allow are reported as allowed with the rule suffixed ` (unreachable: {why})`.
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
//! oversized head; `env()` contents; shutdown stops accepting.

use crate::policy::Policy;
use loom_core::event::NetDecision;
use loom_core::SessionId;
use std::collections::BTreeMap;
use tokio::sync::mpsc::UnboundedSender;

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
        todo!("implement per module contract")
    }

    /// Proxy variables for a command's environment (see module contract).
    pub fn env(&self) -> BTreeMap<String, String> {
        todo!("implement per module contract")
    }
}

#[derive(Clone)]
pub struct Proxy {
    #[allow(dead_code)]
    inner: std::sync::Arc<Inner>,
}

#[allow(dead_code)]
struct Inner {
    port: u16,
}

impl Proxy {
    pub async fn start(port: u16, sink: UnboundedSender<(SessionId, NetDecision)>) -> Result<Proxy, ProxyError> {
        let _ = (port, sink);
        todo!("implement per module contract")
    }

    /// The port actually bound.
    pub fn port(&self) -> u16 {
        todo!("implement per module contract")
    }

    pub fn grant(&self, session: &SessionId, policy: Policy) -> SessionGrant {
        let _ = (session, policy);
        todo!("implement per module contract")
    }

    pub fn revoke(&self, session: &SessionId) {
        let _ = session;
        todo!("implement per module contract")
    }

    /// Stop accepting connections. Open tunnels are closed.
    pub fn shutdown(&self) {
        todo!("implement per module contract")
    }
}
