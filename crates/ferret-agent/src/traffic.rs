//! Captured exchanges in the session log (CONTRACTS-TRAFFIC-TARGETS C and F).
//!
//! The proxy hands each captured request/response to the runtime's sink; [`Traffic::ingest`] stores the two
//! messages as blobs, attributes the exchange to the call that was running when it started (between the
//! call's `exec_started` and its `tool_result`, else to none) and queues it. The session appends the queue
//! to its log at its next flush. [`MissionTraffic`] is the mission's index of every exchange recorded by any
//! of its sessions: the replay by `ex-` id and the finding gate read it.

use ferret_core::blob::BlobStore;
use ferret_core::event::Exchange;
use ferret_core::ids::{new_exchange_id, CallId};
use ferret_net::capture::{Captured, Transport};
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
    pub secrets: std::sync::OnceLock<Arc<ferret_core::creds::Secrets>>,
    /// The mission target's parsed scope (CONTRACTS-TRAFFIC-TARGETS T2/F1), set by the runtime when
    /// the mission has a target. Used by [`check_traffic`] to extract bare in-scope hostnames.
    pub target_scope: std::sync::OnceLock<ferret_core::target::Scope>,
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
            target_scope: std::sync::OnceLock::new(),
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
        // S5: values ferret injected for the mission never reach a blob, whichever side echoes them.
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
        let passive_signals = cap
            .passive_signals
            .into_iter()
            .map(|mut s| {
                if let Some(sec) = secrets {
                    s.summary = sec.redact(&s.summary).into_owned();
                    s.detail = sec.redact(&s.detail).into_owned();
                }
                s
            })
            .collect();
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
            passive_signals,
            principal: None,
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

    /// Queue an operator-imported exchange (e.g. from HAR 1.2) onto an active session's flush queue.
    pub fn push_imported(&self, x: Exchange) {
        self.mission.add(&x);
        lock(&self.pending).push(x);
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

/// True when the trailing words of `prefix` (within the current clause) explicitly negate the
/// immediately following host mention — e.g. `not auth.idp.test`, `instead of auth.idp.test`,
/// `does not use auth.idp.test`, `doesn't use auth.idp.test`, `not hitting auth.idp.test`,
/// `not calling auth.idp.test`, `not on auth.idp.test`, `no longer auth.idp.test`, `never auth.idp.test`.
///
/// Narrow by design so security claims like `"CSRF is not enforced on api.acme.test"` or
/// `"api.acme.test does not check auth"` still require traffic to `api.acme.test`.
fn is_preceded_by_negation(prefix: &str) -> bool {
    let trimmed = prefix.trim_end_matches(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | '[' | '<' | ':')
    });
    if trimmed.is_empty() {
        return false;
    }
    let clause = trimmed
        .rsplit_once(['\n', '\r', '.', '!', '?', ';', ',', '(', ')', '[', ']'])
        .map_or(trimmed, |(_, rest)| rest);
    let words: Vec<String> = clause
        .split_whitespace()
        .map(|w| {
            w.replace('\u{2019}', "'")
                .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '\'')
                .to_ascii_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect();
    if words.is_empty() {
        return false;
    }
    const PREPS: &[&str] = &["on", "at", "to", "from", "via", "by", "for", "in", "through", "over"];
    const VERBS: &[&str] = &[
        "use", "uses", "used", "using",
        "hit", "hits", "hitting",
        "call", "calls", "calling",
        "reach", "reaches", "reached", "reaching",
        "contact", "contacts", "contacted", "contacting",
        "query", "queries", "queried", "querying",
        "request", "requests", "requested", "requesting",
        "target", "targets", "targeted", "targeting",
        "connect", "connects", "connected", "connecting",
        "talk", "talks", "talked", "talking",
        "send", "sends", "sent", "sending",
        "route", "routes", "routed", "routing",
        "point", "points", "pointed", "pointing",
        "hosted", "served", "proxied", "forwarded",
        "redirect", "redirects", "redirected", "redirecting",
        "going",
    ];
    let mut end = words.len();
    let has_prep = end > 0 && PREPS.contains(&words[end - 1].as_str());
    if has_prep {
        end -= 1;
    }
    let has_verb = end > 0 && VERBS.contains(&words[end - 1].as_str());
    if has_verb {
        end -= 1;
    }
    if end == 0 {
        return false;
    }
    let tail = &words[..end];
    let last = tail[tail.len() - 1].as_str();
    let prev = tail.len().checked_sub(2).map(|i| tail[i].as_str());
    let prev2 = tail.len().checked_sub(3).map(|i| tail[i].as_str());

    if matches!(last, "not" | "never" | "neither" | "nor") {
        return true;
    }
    if matches!((prev, last), (Some("instead"), "of") | (Some("rather"), "than") | (Some("no"), "longer")) {
        return true;
    }
    if matches!((prev2, prev, last), (Some("as"), Some("opposed"), "to")) {
        return true;
    }
    if has_verb && matches!(last, "doesn't" | "don't" | "didn't" | "cannot" | "can't" | "won't" | "without") {
        return true;
    }
    if (has_verb || has_prep) && matches!(last, "isn't" | "aren't" | "wasn't" | "weren't") {
        return true;
    }
    false
}

/// True when `token` looks like an HTTP(S) URL, IP address, or bare dotted hostname (optionally with
/// `:port` or `/path`).
fn looks_like_host_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return true;
    }
    let head = token.split(['/', '?', '#']).next().unwrap_or(token).trim_end_matches(['.', ':', ',']);
    let host = head
        .split_once(':')
        .filter(|(h, p)| !h.contains(':') && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .map_or(head, |(h, _)| h)
        .trim_matches(['[', ']']);
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if !host.contains('.') || host.len() > 253 {
        return false;
    }
    let mut labels = host.split('.');
    let mut count = 0usize;
    let mut last_label = "";
    for label in &mut labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
        count += 1;
        last_label = label;
    }
    count >= 2 && last_label.len() >= 2 && last_label.bytes().any(|b| b.is_ascii_alphabetic())
}

/// Return a copy of `text` with explicitly negated host mentions (e.g. `"NOT auth.idp.test"`,
/// `"instead of https://auth.idp.test"`, `"does not use auth.idp.test"`) blanked out so
/// [`ferret_core::target::claim_hosts`] does not require mission traffic to hosts the claim
/// explicitly states were NOT used. Any non-negated mention of the same host elsewhere in `text`
/// stays intact.
fn strip_negated_hosts(text: &str) -> String {
    let is_delim = |c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '(' | ')' | '<' | '>' | ',' | ';' | '[' | ']')
    };
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let mut iter = text.char_indices().peekable();
    while let Some((i, c)) = iter.next() {
        if is_delim(c) {
            continue;
        }
        let start = i;
        let mut end = start + c.len_utf8();
        while let Some(&(j, nc)) = iter.peek() {
            if is_delim(nc) {
                break;
            }
            end = j + nc.len_utf8();
            iter.next();
        }
        let token = &text[start..end];
        if looks_like_host_token(token) && is_preceded_by_negation(&text[..start]) {
            out.push_str(&text[cursor..start]);
            out.push(' ');
            cursor = end;
        }
    }
    out.push_str(&text[cursor..]);
    out
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
    state: &ferret_core::ledger::LedgerState,
    claim: &ferret_core::ledger::Claim,
    mission: &MissionTraffic,
    scope: Option<&ferret_core::target::Scope>,
) -> Vec<HostReach> {
    use ferret_core::security_state::AssetKind;
    let asset_hosts: Vec<String> = claim
        .assets
        .iter()
        .filter_map(|a| state.security.assets.values().find(|x| &x.id == a || &x.locator == a))
        .filter(|a| matches!(a.kind, AssetKind::Host | AssetKind::Service | AssetKind::Endpoint))
        .map(|a| locator_host(&a.locator))
        .collect();
    let filtered = strip_negated_hosts(&claim.text);
    let hosts = ferret_core::target::claim_hosts(&filtered, &asset_hosts, scope);
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

/// The hosts an active structured finding names and whether its attested supporting evidence or
/// cited `http_exchanges` reached each with a response (empty: not reached).
pub fn finding_reach(
    state: &ferret_core::ledger::LedgerState,
    finding: &ferret_core::security_state::Finding,
    mission: &MissionTraffic,
    scope: Option<&ferret_core::target::Scope>,
) -> Vec<HostReach> {
    use ferret_core::security_state::AssetKind;
    let mut asset_hosts: Vec<String> = Vec::new();
    if let Some(asset_ref) = finding.asset.as_deref() {
        if let Some(a) = state.security.assets.values().find(|x| x.id == asset_ref || x.locator == asset_ref) {
            if matches!(a.kind, AssetKind::Host | AssetKind::Service | AssetKind::Endpoint) {
                asset_hosts.push(locator_host(&a.locator));
            }
        }
    }
    let mut combined = String::new();
    for piece in [
        Some(finding.target.as_str()),
        finding.endpoint.as_deref(),
        Some(finding.title.as_str()),
        Some(finding.description.as_str()),
        finding.poc_description.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !piece.is_empty() {
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(piece);
        }
    }
    let filtered = strip_negated_hosts(&combined);
    let hosts = ferret_core::target::claim_hosts(&filtered, &asset_hosts, scope);
    let all = mission.all();
    let support: Vec<_> = state
        .evidence
        .iter()
        .filter(|e| {
            e.input.attested
                && e.input.supports
                && (finding.evidence.iter().any(|id| id == &e.id)
                    || finding.claim.as_deref().is_some_and(|cid| e.input.claim == cid))
        })
        .collect();
    hosts
        .into_iter()
        .map(|host| {
            let host = norm(&host);
            let exchanges = all
                .iter()
                .filter(|x| x.status.is_some() && norm(&x.host) == host)
                .filter(|x| {
                    finding.http_exchanges.iter().any(|id| id == &x.id)
                        || support.iter().any(|e| {
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

fn format_cite_ways(role: &crate::pack::RoleDef, intercept: bool) -> String {
    let shown = |t: &str| role.tools.iter().any(|x| x == t) && !role.hidden_tools.iter().any(|x| x == t);
    let mut ways: Vec<String> =
        ["http_send", "web_fetch"].into_iter().filter(|t| shown(t)).map(str::to_string).collect();
    if ["bash", "exec", "job"].iter().any(|t| shown(t)) {
        let state_of = if intercept { "on" } else { "off" };
        ways.push(format!("a command while interception is on for this mission; interception is {state_of}"));
    }
    if ways.is_empty() {
        "Cite the evidence of a call that did".to_string()
    } else {
        // The interception clause follows the list, after a semicolon, as the contract words it.
        match ways.len() {
            1 => format!("Cite the evidence of a call that did ({})", ways[0]),
            n => format!("Cite the evidence of a call that did ({}, or {})", ways[..n - 1].join(", "), ways[n - 1]),
        }
    }
}

/// The finding gate (F1): `Err(refusal)` when a claim or high-confidence structured finding relies
/// on a host that none of its attested supporting evidence (or cited `http_exchanges`) reached, or
/// when any active structured finding cites `http_exchanges` IDs that do not exist in the mission's
/// traffic log. `cited` are the evidence ids `finish` cites; with none, every supported claim of
/// the mission is relied on. `tool` is the refused tool (`finish` or `conclude`). The text names
/// only tools the role is shown.
pub fn check_traffic(
    role: &crate::pack::RoleDef,
    tool: &str,
    state: &ferret_core::ledger::LedgerState,
    cited: &[String],
    traffic: &Traffic,
) -> Result<(), String> {
    use ferret_core::ledger::ClaimStatus;
    use ferret_core::security_state::FindingConfidence;

    let active_findings = state.security.active_findings();
    // Every active finding citing `http_exchanges` must reference real exchange IDs in this mission.
    for finding in &active_findings {
        let missing: Vec<&str> = finding
            .http_exchanges
            .iter()
            .map(String::as_str)
            .filter(|id| traffic.mission.find(id).is_none())
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "{tool} cannot be accepted yet: finding {} cites http_exchanges ({}) that do not exist in this mission's traffic log. Cite real captured exchange IDs from this mission or update the finding with `security_record`.",
                finding.id,
                missing.join(", ")
            ));
        }
    }

    if !role.require_traffic {
        return Ok(());
    }
    let scope = traffic.target_scope.get();
    let cite = format_cite_ways(role, traffic.intercept);

    let by_cited: Vec<&str> =
        state.evidence.iter().filter(|e| cited.contains(&e.id)).map(|e| e.input.claim.as_str()).collect();
    for claim in state
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Supported && (by_cited.is_empty() || by_cited.contains(&c.id.as_str())))
    {
        let missed: Vec<String> = claim_reach(state, claim, &traffic.mission, scope)
            .into_iter()
            .filter(|h| h.exchanges.is_empty())
            .map(|h| h.host)
            .collect();
        if missed.is_empty() {
            continue;
        }
        let has_claim_update = role.tools.iter().any(|x| x == "claim_update");
        let has_claim = role.tools.iter().any(|x| x == "claim");
        let target_noun = if missed.len() == 1 { "that host" } else { "those hosts" };
        let amend = if has_claim_update {
            format!(
                " You can withdraw or amend {} with `claim_update` (for example status `withdrawn`), or cite evidence from a call that reached {target_noun}.",
                claim.id
            )
        } else if has_claim {
            format!(
                " You can withdraw or amend {} with `claim` (passing `id` and status `withdrawn`), or cite evidence from a call that reached {target_noun}.",
                claim.id
            )
        } else {
            String::new()
        };
        return Err(format!(
            "{tool} cannot be accepted yet: {} names {}, but none of its supporting evidence reached {}. {cite}, or take the host out of the claim.{amend}",
            claim.id,
            missed.join(", "),
            if missed.len() == 1 { "it" } else { "them" }
        ));
    }

    // Active high-confidence findings naming hosts must be corroborated by answered mission traffic.
    for finding in active_findings.into_iter().filter(|f| f.confidence == FindingConfidence::High) {
        let missed: Vec<String> = finding_reach(state, finding, &traffic.mission, scope)
            .into_iter()
            .filter(|h| h.exchanges.is_empty())
            .map(|h| h.host)
            .collect();
        if !missed.is_empty() {
            return Err(format!(
                "{tool} cannot be accepted yet: high-confidence finding {} ({}) names {}, but none of its supporting evidence or cited http_exchanges reached {}. {cite}, or downgrade/withdraw the finding with `security_record`.",
                finding.id,
                finding.title,
                missed.join(", "),
                if missed.len() == 1 { "it" } else { "them" }
            ));
        }
        if !finding.http_exchanges.is_empty()
            && finding
                .http_exchanges
                .iter()
                .all(|id| traffic.mission.find(id).is_none_or(|x| x.status.is_none()))
        {
            return Err(format!(
                "{tool} cannot be accepted yet: high-confidence finding {} ({}) cites http_exchanges ({}) that never received a response. Capture an answered exchange or downgrade/withdraw the finding with `security_record`.",
                finding.id,
                finding.title,
                finding.http_exchanges.join(", ")
            ));
        }
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
            passive_signals: Vec::new(),
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
        let item = ferret_core::creds::Item {
            kind: ferret_core::creds::ItemKind::Cookie,
            name: "session".into(),
            value: "s3cr3t-session-value-9f2".into(),
            host: "t.test".into(),
        };
        let _ = t.secrets.set(Arc::new(ferret_core::creds::Secrets::for_items(&[item])));
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

    #[test]
    fn ingest_copies_and_redacts_passive_signals_from_proxy_captures() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        let t = Traffic::none();
        let secret = "s3cr3t-passive-val-991";
        let item = ferret_core::creds::Item {
            kind: ferret_core::creds::ItemKind::Header,
            name: "X-Api-Key".into(),
            value: secret.into(),
            host: "t.test".into(),
        };
        let _ = t.secrets.set(Arc::new(ferret_core::creds::Secrets::for_items(&[item])));
        let mut c = cap(1);
        c.passive_signals.push(ferret_core::event::PassiveSignal {
            kind: "cors_misconfig".into(),
            severity: "high".into(),
            summary: format!("ACAO reflects origin with {secret}"),
            detail: format!("detail containing {secret}"),
        });
        assert!(t.ingest(&blobs, c));
        let (xs, _) = t.take_pending();
        assert_eq!(xs[0].passive_signals.len(), 1);
        let sig = &xs[0].passive_signals[0];
        assert_eq!(sig.kind, "cors_misconfig");
        assert_eq!(sig.severity, "high");
        assert!(!sig.summary.contains(secret) && sig.summary.contains("[redacted]"), "{}", sig.summary);
        assert!(!sig.detail.contains(secret) && sig.detail.contains("[redacted]"), "{}", sig.detail);
    }

    fn make_role(require_traffic: bool) -> crate::pack::RoleDef {
        let mut r = crate::pack::Packs::builtin().unwrap().role(None, Some("lead")).unwrap().clone();
        r.require_traffic = require_traffic;
        if !r.tools.iter().any(|t| t == "http_send") {
            r.tools.push("http_send".into());
        }
        r
    }

    fn make_exchange(blobs: &BlobStore, id: &str, host: &str, call_id: Option<&str>, status: Option<u16>) -> Exchange {
        let blob = blobs.put_bytes(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        Exchange {
            id: id.into(),
            call_id: call_id.map(CallId::from),
            source: "tool".into(),
            tool: Some("http_send".into()),
            scheme: "https".into(),
            tls: "tool".into(),
            method: "GET".into(),
            host: host.into(),
            port: 443,
            target: "/".into(),
            status,
            error: status.is_none().then(|| "connection refused".into()),
            request: blob.clone(),
            response: status.map(|_| blob),
            request_bytes: 18,
            response_bytes: 18,
            truncated: false,
            upstream_unverified: false,
            duration_ms: 2,
            passive_signals: Vec::new(),
            principal: None,
        }
    }

    #[test]
    fn check_traffic_uses_target_scope_for_bare_in_scope_hosts() {
        use ferret_core::ledger::{ClaimStatus, Entry, EvidenceInput, EvidenceKind, LedgerOp, LedgerState};
        use ferret_core::ids::SessionId;

        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        let traffic = Traffic::none();
        let scope = ferret_core::target::Scope::parse(&["*.acme.test".into()], &[]).unwrap();
        let _ = traffic.target_scope.set(scope);

        let mut state = LedgerState::default();
        let mut n = 0u64;
        let mut apply = |op: LedgerOp| {
            n += 1;
            state.apply(&Entry {
                n,
                ts_ms: n,
                session: SessionId::from("s-1"),
                from_user: false,
                op,
                mac: String::new(),
            });
        };
        // Bare hostname (no http:// scheme) matched ONLY when real target Scope is wired.
        apply(LedgerOp::ClaimAdd { text: "api.acme.test leaks admin tokens".into(), assets: vec![] });
        apply(LedgerOp::EvidenceAdd(EvidenceInput {
            claim: "c1".into(),
            kind: EvidenceKind::Execution,
            supports: true,
            session: SessionId::from("s-1"),
            call_id: CallId::from("call-1"),
            blob: None,
            lines: None,
            quote: None,
            note: "ran check".into(),
            attested: true,
            tool: Some("http_send".into()),
            grade: Some(ferret_core::event::EvidenceGrade::Run),
        }));
        apply(LedgerOp::ClaimUpdate { id: "c1".into(), status: ClaimStatus::Supported, note: "done".into() });

        let role = make_role(true);
        let err = check_traffic(&role, "finish", &state, &["e1".into()], &traffic).unwrap_err();
        assert!(err.contains("api.acme.test"), "{err}");

        traffic.mission.add(&make_exchange(&blobs, "ex-111111111111", "api.acme.test", Some("call-1"), Some(200)));
        check_traffic(&role, "finish", &state, &["e1".into()], &traffic).unwrap();
    }

    #[test]
    fn check_traffic_verifies_active_findings_exchanges_and_high_confidence_corroboration() {
        use ferret_core::ledger::{Entry, EvidenceInput, EvidenceKind, LedgerOp, LedgerState};
        use ferret_core::security_state::{FindingConfidence, FindingInput, SecurityOp};
        use ferret_core::ids::SessionId;

        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        let traffic = Traffic::none();
        let scope = ferret_core::target::Scope::parse(&["app.acme.test".into()], &[]).unwrap();
        let _ = traffic.target_scope.set(scope);

        let mut state = LedgerState::default();
        let mut n = 0u64;
        let mut apply = |op: LedgerOp| {
            n += 1;
            state.apply(&Entry {
                n,
                ts_ms: n,
                session: SessionId::from("s-1"),
                from_user: false,
                op,
                mac: String::new(),
            });
        };
        apply(LedgerOp::ClaimAdd { text: "finding evidence holder".into(), assets: vec![] });
        apply(LedgerOp::EvidenceAdd(EvidenceInput {
            claim: "c1".into(),
            kind: EvidenceKind::Execution,
            supports: true,
            session: SessionId::from("s-1"),
            call_id: CallId::from("call-1"),
            blob: None,
            lines: None,
            quote: None,
            note: "observed".into(),
            attested: true,
            tool: Some("bash".into()),
            grade: Some(ferret_core::event::EvidenceGrade::Run),
        }));
        let mut finding = FindingInput {
            title: "IDOR on user export".into(),
            description: "Endpoint on app.acme.test exposes other users' records.".into(),
            impact: "PII exposure".into(),
            target: "app.acme.test".into(),
            severity: Some(ferret_core::security_state::FindingSeverity::High),
            cvss_breakdown: None,
            evidence: vec!["e1".into()],
            counterevidence: "Checked authorization header handling.".into(),
            confidence: FindingConfidence::High,
            confidence_rationale: None,
            severity_change_conditions: "Scoped to authenticated users.".into(),
            technical_analysis: None,
            remediation_steps: None,
            assumptions: None,
            poc_description: None,
            poc_handle: None,
            fix_effort: None,
            endpoint: Some("https://app.acme.test/api/export".into()),
            method: Some("GET".into()),
            cve: None,
            cwe: Some("CWE-639".into()),
            code_locations: vec![],
            fix_verification: None,
            http_exchanges: vec!["ex-missing12345".into()],
            asset: None,
            claim: None,
        };
        apply(LedgerOp::Security(SecurityOp::FindingRecord { finding: Box::new(finding.clone()) }));

        // 1. Missing `ex-*` ID is rejected even when `require_traffic` is false.
        let err = check_traffic(&make_role(false), "finish", &state, &[], &traffic).unwrap_err();
        assert!(err.contains("ex-missing12345") && err.contains("do not exist"), "{err}");

        // 2. Replace with real unanswered exchange -> rejected for high-confidence finding.
        traffic.mission.add(&make_exchange(&blobs, "ex-missing12345", "app.acme.test", Some("call-1"), None));
        let err = check_traffic(&make_role(true), "finish", &state, &[], &traffic).unwrap_err();
        assert!(err.contains("app.acme.test"), "{err}");

        // 3. Record an answered exchange for the finding's host and update `http_exchanges` -> passes.
        let answered_id = "ex-real20000001";
        traffic.mission.add(&make_exchange(&blobs, answered_id, "app.acme.test", Some("call-99"), Some(200)));
        finding.http_exchanges = vec![answered_id.into()];
        let mut state2 = LedgerState::default();
        state2.apply(&Entry {
            n: 1,
            ts_ms: 1,
            session: SessionId::from("s-1"),
            from_user: false,
            op: LedgerOp::ClaimAdd { text: "holder".into(), assets: vec![] },
            mac: String::new(),
        });
        state2.apply(&Entry {
            n: 2,
            ts_ms: 2,
            session: SessionId::from("s-1"),
            from_user: false,
            op: LedgerOp::EvidenceAdd(EvidenceInput {
                claim: "c1".into(),
                kind: EvidenceKind::Execution,
                supports: true,
                session: SessionId::from("s-1"),
                call_id: CallId::from("call-1"),
                blob: None,
                lines: None,
                quote: None,
                note: "observed".into(),
                attested: true,
                tool: Some("http_send".into()),
                grade: Some(ferret_core::event::EvidenceGrade::Run),
            }),
            mac: String::new(),
        });
        state2.apply(&Entry {
            n: 3,
            ts_ms: 3,
            session: SessionId::from("s-1"),
            from_user: false,
            op: LedgerOp::Security(SecurityOp::FindingRecord { finding: Box::new(finding) }),
            mac: String::new(),
        });
        check_traffic(&make_role(true), "finish", &state2, &[], &traffic).unwrap();
    }

    #[test]
    fn check_traffic_ignores_explicitly_negated_host_mentions_and_hints_claim_update() {
        use ferret_core::ids::SessionId;
        use ferret_core::ledger::{ClaimStatus, Entry, EvidenceInput, EvidenceKind, LedgerOp, LedgerState};

        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        let traffic = Traffic::none();
        let scope = ferret_core::target::Scope::parse(&["*.acme.test".into(), "*.idp.test".into()], &[]).unwrap();
        let _ = traffic.target_scope.set(scope);
        traffic.mission.add(&make_exchange(
            &blobs,
            "ex-222222222222",
            "wallet.acme.test",
            Some("call-1"),
            Some(200),
        ));

        let build_state = |text: &str| {
            let mut state = LedgerState::default();
            let mut n = 0u64;
            let mut apply = |op: LedgerOp| {
                n += 1;
                state.apply(&Entry {
                    n,
                    ts_ms: n,
                    session: SessionId::from("s-1"),
                    from_user: false,
                    op,
                    mac: String::new(),
                });
            };
            apply(LedgerOp::ClaimAdd { text: text.into(), assets: vec![] });
            apply(LedgerOp::EvidenceAdd(EvidenceInput {
                claim: "c1".into(),
                kind: EvidenceKind::Execution,
                supports: true,
                session: SessionId::from("s-1"),
                call_id: CallId::from("call-1"),
                blob: None,
                lines: None,
                quote: None,
                note: "ran check".into(),
                attested: true,
                tool: Some("http_send".into()),
                grade: Some(ferret_core::event::EvidenceGrade::Run),
            }));
            apply(LedgerOp::ClaimUpdate { id: "c1".into(), status: ClaimStatus::Supported, note: "done".into() });
            state
        };

        let role = make_role(true);
        for comparative in [
            "App uses wallet.acme.test, NOT auth.idp.test",
            "Routes to wallet.acme.test, not https://auth.idp.test/api/v1",
            "Uses wallet.acme.test instead of auth.idp.test",
            "Uses wallet.acme.test rather than `auth.idp.test`",
            "wallet.acme.test does not use auth.idp.test",
            "wallet.acme.test doesn't use auth.idp.test",
            "wallet.acme.test never auth.idp.test and no longer login.idp.test",
            "wallet.acme.test is not hitting auth.idp.test, not calling login.idp.test, and not on cdn.idp.test",
        ] {
            let state = build_state(comparative);
            check_traffic(&role, "finish", &state, &["e1".into()], &traffic)
                .unwrap_or_else(|e| panic!("negated host should not block `{comparative}`: {e}"));
        }

        // Security claims where "not" describes missing protection on a host must still require traffic!
        let missing_protection = build_state("CSRF is not enforced on auth.idp.test");
        let err = check_traffic(&role, "finish", &missing_protection, &["e1".into()], &traffic).unwrap_err();
        assert!(err.contains("auth.idp.test"), "{err}");
        assert!(err.contains("claim_update"), "error must suggest claim_update: {err}");

        // A host negated once AND asserted affirmatively elsewhere still requires traffic!
        let mixed = build_state("Uses wallet.acme.test, NOT auth.idp.test. Later auth.idp.test returned 200.");
        let err = check_traffic(&role, "finish", &mixed, &["e1".into()], &traffic).unwrap_err();
        assert!(err.contains("auth.idp.test"), "{err}");
    }
}
