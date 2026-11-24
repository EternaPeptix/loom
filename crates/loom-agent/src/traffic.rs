//! Captured exchanges in the session log (CONTRACTS-TRAFFIC-TARGETS C and F).
//!
//! The proxy hands each captured request/response to the runtime's sink; [`Traffic::ingest`] stores the two
//! messages as blobs, attributes the exchange to the call that was running when it started (between the
//! call's `exec_started` and its `tool_result`, else to none) and queues it. The session appends the queue
//! to its log at its next flush. [`MissionTraffic`] is the mission's index of every exchange recorded by any
//! of its sessions: the replay by `ex-` id and the finding gate read it.

use loom_core::blob::BlobStore;
use loom_core::event::Exchange;
use loom_core::ids::{new_exchange_id, CallId};
use loom_net::capture::{Captured, Transport};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Every exchange the sessions of one mission recorded, oldest first.
#[derive(Default)]
pub struct MissionTraffic {
    list: Mutex<Vec<Exchange>>,
}

impl MissionTraffic {
    /// Index an exchange (once per id).
    pub fn add(&self, x: &Exchange) {
        let mut list = lock(&self.list);
        if !list.iter().any(|e| e.id == x.id) {
            list.push(x.clone());
        }
    }

    pub fn find(&self, id: &str) -> Option<Exchange> {
        lock(&self.list).iter().find(|e| e.id == id).cloned()
    }

    pub fn all(&self) -> Vec<Exchange> {
        lock(&self.list).clone()
    }
}

struct Window {
    call: CallId,
    start_ms: u64,
    end_ms: Option<u64>,
}

/// One session's capture state.
pub struct Traffic {
    pub mission: Arc<MissionTraffic>,
    /// Interception is on for the mission (I1), recorded in `session_start`.
    pub intercept: bool,
    max_exchanges: u64,
    count: AtomicU64,
    stopped: AtomicBool,
    note_due: AtomicBool,
    pending: Mutex<Vec<Exchange>>,
    windows: Mutex<VecDeque<Window>>,
    /// The session secret set (CONTRACTS-TRAFFIC-TARGETS S5): `ingest` stores the request and response of a
    /// captured exchange with these values replaced. Set by the runtime with the grant; unset = none.
    pub secrets: std::sync::OnceLock<Arc<loom_core::creds::Secrets>>,
}

const WINDOWS_KEPT: usize = 8;

impl Traffic {
    pub fn new(mission: Arc<MissionTraffic>, intercept: bool, max_exchanges: u64) -> Traffic {
        Traffic {
            mission,
            intercept,
            max_exchanges,
            count: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
            note_due: AtomicBool::new(false),
            pending: Mutex::new(Vec::new()),
            windows: Mutex::new(VecDeque::new()),
            secrets: std::sync::OnceLock::new(),
        }
    }

    /// A session with nothing captured and no mission index (tests, sessions without a mission).
    pub fn none() -> Traffic {
        Traffic::new(Arc::new(MissionTraffic::default()), false, u64::MAX)
    }

    /// An `exec_started` was appended for `call`.
    pub fn call_started(&self, call: &CallId, now_ms: u64) {
        let mut w = lock(&self.windows);
        w.push_back(Window { call: call.clone(), start_ms: now_ms, end_ms: None });
        while w.len() > WINDOWS_KEPT {
            w.pop_front();
        }
    }

    /// The call's `tool_result` was appended.
    pub fn call_ended(&self, call: &CallId, now_ms: u64) {
        if let Some(w) = lock(&self.windows).iter_mut().rev().find(|w| &w.call == call) {
            w.end_ms = Some(now_ms);
        }
    }

    fn attribute(&self, ts_ms: u64) -> Option<CallId> {
        lock(&self.windows)
            .iter()
            .rev()
            .find(|w| w.start_ms <= ts_ms && w.end_ms.is_none_or(|e| ts_ms <= e))
            .map(|w| w.call.clone())
    }

    /// Count an exchange a tool made; false once the session's cap is reached.
    pub fn count_one(&self) -> bool {
        if self.count.fetch_add(1, Ordering::SeqCst) >= self.max_exchanges {
            self.count.fetch_sub(1, Ordering::SeqCst);
            self.stop();
            return false;
        }
        true
    }

    fn stop(&self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
            self.note_due.store(true, Ordering::SeqCst);
        }
    }

    /// Store a captured exchange and queue it for the session's log. Returns false when it was dropped (the
    /// session's cap, or the blobs could not be written).
    pub fn ingest(&self, blobs: &BlobStore, cap: Captured) -> bool {
        if !self.count_one() {
            return false;
        }
        // S5: values loom injected for the mission never reach a blob, whichever side echoes them.
        let secrets = self.secrets.get().filter(|s| !s.is_empty());
        let clean = |b: &[u8]| -> Vec<u8> {
            match secrets {
                Some(s) => s.redact_bytes(b).into_owned(),
                None => b.to_vec(),
            }
        };
        let Ok(request) = blobs.put_bytes(&clean(&cap.request)) else { return false };
        let response = match &cap.response {
            Some(r) => match blobs.put_bytes(&clean(r)) {
                Ok(b) => Some(b),
                Err(_) => return false,
            },
            None => None,
        };
        let (scheme, tls) = match cap.transport {
            Transport::Plain => ("http", "plain"),
            Transport::Intercepted => ("https", "intercepted"),
        };
        let call_id = self.attribute(cap.ts_ms);
        let x = Exchange {
            id: new_exchange_id(),
            call_id,
            source: "proxy".into(),
            tool: None,
            scheme: scheme.into(),
            tls: tls.into(),
            method: cap.method,
            host: cap.host,
            port: cap.port,
            target: cap.target,
            status: cap.status,
            error: cap.error,
            request,
            response,
            request_bytes: cap.request_bytes,
            response_bytes: cap.response_bytes,
            truncated: cap.truncated,
            upstream_unverified: cap.upstream_unverified,
            duration_ms: cap.duration_ms,
        };
        lock(&self.pending).push(x);
        true
    }

    /// The queued exchanges, and the one-time note that capture stopped at the session's cap.
    pub fn take_pending(&self) -> (Vec<Exchange>, Option<String>) {
        let list = std::mem::take(&mut *lock(&self.pending));
        let note = self.note_due.swap(false, Ordering::SeqCst).then(|| {
            format!(
                "Traffic capture stopped: this session recorded {} exchanges, the limit of [network] capture_max_exchanges. The proxy still relays and decides; nothing more is recorded.",
                self.max_exchanges
            )
        });
        (list, note)
    }

    pub fn has_pending(&self) -> bool {
        !lock(&self.pending).is_empty() || self.note_due.load(Ordering::SeqCst)
    }
}

/// How the finding gate and the views see a host: the lower-case name without a trailing dot.
pub fn norm(host: &str) -> String {
    host.trim().trim_end_matches('.').trim_matches(['[', ']']).to_ascii_lowercase()
}

/// The exchanges of the mission with `host` (any port) that got a response.
pub fn answered(mission: &MissionTraffic, host: &str) -> Vec<Exchange> {
    let host = norm(host);
    mission.all().into_iter().filter(|x| x.status.is_some() && norm(&x.host) == host).collect()
}

/// The host a security asset's locator names: the authority of a URL, or `host[:port][/path]`.
fn locator_host(locator: &str) -> String {
    let rest = locator.split_once("://").map_or(locator, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split_once(']').map_or(v6, |(h, _)| h)
    } else {
        hostport.split_once(':').map_or(hostport, |(h, _)| h)
    };
    norm(host)
}

/// One host a claim names, and the exchanges that show it was reached (empty: not reached).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostReach {
    pub host: String,
    pub exchanges: Vec<String>,
}

/// The hosts `claim` names (CONTRACTS-TRAFFIC-TARGETS F1) and whether its attested supporting evidence reached
/// each: evidence that cites a call during which an exchange with the host got a response, or that quotes the
/// blob of such an exchange.
///
/// `scope` is the mission target's scope; targets are wired by part T, until then callers pass `None` and only
/// the claim's assets and URLs count.
pub fn claim_reach(
    state: &loom_core::ledger::LedgerState,
    claim: &loom_core::ledger::Claim,
    mission: &MissionTraffic,
    scope: Option<&loom_core::target::Scope>,
) -> Vec<HostReach> {
    use loom_core::security_state::AssetKind;
    let asset_hosts: Vec<String> = claim
        .assets
        .iter()
        .filter_map(|a| state.security.assets.values().find(|x| &x.id == a || &x.locator == a))
        .filter(|a| matches!(a.kind, AssetKind::Host | AssetKind::Service | AssetKind::Endpoint))
        .map(|a| locator_host(&a.locator))
        .collect();
    let hosts = loom_core::target::claim_hosts(&claim.text, &asset_hosts, scope);
    let all = mission.all();
    let support: Vec<_> =
        state.evidence.iter().filter(|e| e.input.claim == claim.id && e.input.attested && e.input.supports).collect();
    hosts
        .into_iter()
        .map(|host| {
            let host = norm(&host);
            let exchanges =
                all.iter()
                    .filter(|x| x.status.is_some() && norm(&x.host) == host)
                    .filter(|x| {
                        support.iter().any(|e| {
                            x.call_id.as_ref() == Some(&e.input.call_id)
                                || e.input.blob.as_ref().is_some_and(|b| {
                                    *b == x.request.id || x.response.as_ref().is_some_and(|r| *b == r.id)
                                })
                        })
                    })
                    .map(|x| x.id.clone())
                    .collect();
            HostReach { host, exchanges }
        })
        .collect()
}

/// The finding gate (F1): `Err(refusal)` when a claim the answer relies on names a host that none of the claim's
/// attested supporting evidence reached. `cited` are the evidence ids `finish` cites; with none, every supported
/// claim of the mission is relied on. `tool` is the refused tool (`finish` or `conclude`). The text names only
/// tools the role is shown.
pub fn check_traffic(
    role: &crate::pack::RoleDef,
    tool: &str,
    state: &loom_core::ledger::LedgerState,
    cited: &[String],
    traffic: &Traffic,
) -> Result<(), String> {
    use loom_core::ledger::ClaimStatus;
    if !role.require_traffic {
        return Ok(());
    }
    let by_cited: Vec<&str> =
        state.evidence.iter().filter(|e| cited.contains(&e.id)).map(|e| e.input.claim.as_str()).collect();
    for claim in state
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Supported && (by_cited.is_empty() || by_cited.contains(&c.id.as_str())))
    {
        // T: `None` until the mission's target scope is wired.
        let missed: Vec<String> = claim_reach(state, claim, &traffic.mission, None)
            .into_iter()
            .filter(|h| h.exchanges.is_empty())
            .map(|h| h.host)
            .collect();
        if missed.is_empty() {
            continue;
        }
        let shown = |t: &str| role.tools.iter().any(|x| x == t) && !role.hidden_tools.iter().any(|x| x == t);
        let mut ways: Vec<String> =
            ["http_send", "web_fetch"].into_iter().filter(|t| shown(t)).map(str::to_string).collect();
        if ["bash", "exec", "job"].iter().any(|t| shown(t)) {
            let state_of = if traffic.intercept { "on" } else { "off" };
            ways.push(format!("a command while interception is on for this mission; interception is {state_of}"));
        }
        let cite = if ways.is_empty() {
            "Cite the evidence of a call that did".to_string()
        } else {
            // The interception clause follows the list, after a semicolon, as the contract words it.
            match ways.len() {
                1 => format!("Cite the evidence of a call that did ({})", ways[0]),
                n => format!("Cite the evidence of a call that did ({}, or {})", ways[..n - 1].join(", "), ways[n - 1]),
            }
        };
        return Err(format!(
            "{tool} cannot be accepted yet: {} names {}, but none of its supporting evidence reached {}. {cite}, or take the host out of the claim.",
            claim.id,
            missed.join(", "),
            if missed.len() == 1 { "it" } else { "them" }
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(ts: u64) -> Captured {
        Captured {
            ts_ms: ts,
            transport: Transport::Plain,
            method: "GET".into(),
            host: "t.test".into(),
            port: 80,
            target: "/a".into(),
            status: Some(200),
            error: None,
            request: b"GET /a HTTP/1.1\r\nHost: t.test\r\n\r\n".to_vec(),
            response: Some(b"HTTP/1.1 200 OK\r\n\r\nhi".to_vec()),
            request_bytes: 35,
            response_bytes: 21,
            truncated: false,
            upstream_unverified: false,
            duration_ms: 3,
        }
    }

    #[test]
    fn a_proxy_exchange_is_attributed_to_the_call_running_when_it_started() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        let t = Traffic::none();
        let call = CallId::from("c1");
        t.call_started(&call, 100);
        assert!(t.ingest(&blobs, cap(150)));
        t.call_ended(&call, 200);
        assert!(t.ingest(&blobs, cap(250)), "after the call: a background job's traffic");
        assert!(t.ingest(&blobs, cap(50)), "before any call");
        let (xs, note) = t.take_pending();
        assert!(note.is_none());
        assert_eq!(xs[0].call_id.as_ref(), Some(&call));
        assert_eq!(xs[1].call_id, None);
        assert_eq!(xs[2].call_id, None);
        assert!(xs[0].id.starts_with("ex-") && xs[0].id.len() == 15, "{}", xs[0].id);
        assert_eq!((xs[0].source.as_str(), xs[0].tls.as_str(), xs[0].scheme.as_str()), ("proxy", "plain", "http"));
        assert_eq!(blobs.read_all(&xs[0].request.id).unwrap(), cap(0).request);
        assert_eq!(blobs.read_all(&xs[0].response.as_ref().unwrap().id).unwrap(), cap(0).response.unwrap());
    }

    #[test]
    fn the_cap_stops_recording_and_notes_it_once() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        let t = Traffic::new(Arc::new(MissionTraffic::default()), false, 2);
        assert!(t.ingest(&blobs, cap(1)));
        assert!(t.ingest(&blobs, cap(2)));
        assert!(!t.ingest(&blobs, cap(3)));
        assert!(!t.ingest(&blobs, cap(4)));
        let (xs, note) = t.take_pending();
        assert_eq!(xs.len(), 2);
        assert!(note.unwrap().contains("capture_max_exchanges"));
        assert!(t.take_pending().1.is_none(), "the note comes once");
    }

    #[test]
    fn an_intercepted_exchange_is_https() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        let t = Traffic::none();
        let mut c = cap(1);
        c.transport = Transport::Intercepted;
        c.port = 443;
        assert!(t.ingest(&blobs, c));
        let (xs, _) = t.take_pending();
        assert_eq!((xs[0].scheme.as_str(), xs[0].tls.as_str()), ("https", "intercepted"));
    }

    #[test]
    fn ingest_redacts_the_mission_secrets_in_both_directions() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        let t = Traffic::none();
        let item = loom_core::creds::Item {
            kind: loom_core::creds::ItemKind::Cookie,
            name: "session".into(),
            value: "s3cr3t-session-value-9f2".into(),
            host: "t.test".into(),
        };
        let _ = t.secrets.set(Arc::new(loom_core::creds::Secrets::for_items(&[item])));
        let mut c = cap(1);
        c.request = b"GET /a HTTP/1.1\r\nCookie: session=s3cr3t-session-value-9f2\r\n\r\n".to_vec();
        c.response = Some(b"HTTP/1.1 200 OK\r\n\r\necho s3cr3t-session-value-9f2".to_vec());
        let counted = (c.request_bytes, c.response_bytes);
        assert!(t.ingest(&blobs, c));
        let (xs, _) = t.take_pending();
        let req = String::from_utf8(blobs.read_all(&xs[0].request.id).unwrap()).unwrap();
        let resp = String::from_utf8(blobs.read_all(&xs[0].response.as_ref().unwrap().id).unwrap()).unwrap();
        assert!(req.contains("[redacted]") && !req.contains("s3cr3t"), "{req}");
        assert!(resp.contains("[redacted]") && !resp.contains("s3cr3t"), "{resp}");
        assert_eq!((xs[0].request_bytes, xs[0].response_bytes), counted);
    }
}
