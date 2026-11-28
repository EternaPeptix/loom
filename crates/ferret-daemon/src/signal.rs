//! Native two-way Signal bridge (`[signal]`) over a local `signal-cli daemon --http` instance.
//!
//! CONTRACT.
//!
//! - Outbound: drains [`Runtime::subscribe`] and [`Runtime::subscribe_notices`] on a dedicated
//!   collector loop into a bounded `mpsc` queue (never blocking bus reads on Signal HTTP RPCs),
//!   coalesces rapid error bursts, retries transient send failures with backoff, reconciles open
//!   inbox items on startup and bus lag, and forwards configured event kinds (`blocker`, `question`,
//!   `approval`, `parked`, `finished`, `error`, `disk`) plus repeat/restart reminders to
//!   `signal.recipient` via `POST {http_url}/api/v1/rpc` (`method = "send"`). Records each sent
//!   Signal `timestamp` → [`OutboundRef`] in a bounded, atomically persisted `0600` map
//!   (`<home>/signal_sent.json`) so quote-replies survive daemon restarts, and pre-records pending
//!   outbound body hashes plus timestamps to suppress Note-to-Self sync echo-backs without races.
//! - Inbound: streams `GET {http_url}/api/v1/events?account=<account>` (SSE) with UTF-8-safe
//!   frame buffering, TCP keepalive, contact warming on every connect, live [`SignalHealth`]
//!   updates, and exponential reconnect backoff. Every inbound envelope MUST pass the strict
//!   `signal.allow_from` sender check (and normalized `signal.allow_groups` when in a group);
//!   unauthorized senders are logged at `warn` (redacted) and ignored.
//! - Routing authorized replies:
//!   - Slash commands: `/inbox`, `/status`, `/stop [id|#n]`, `/resume [id|#n]`, `/scope`,
//!     `/dismiss [id|#n]`, `/tail [id|#n]`, `/mute [dur]`, `/unmute`, `/release`, `/approve`,
//!     `/rule`, `/help`.
//!   - Quote-reply (`dataMessage.quote.id` matching a sent alert, with `quote.text` fallback):
//!     grants/denies `request_scope` approvals via `Runtime::grant_scope`, answers open inbox items
//!     with strict `1..=N` option expansion and confirmation echo, or sends a follow-up to the
//!     mission's lead session when resolved or an error alert. Unmatched quotes NEVER fall through
//!     to unquoted routing.
//!   - Explicit `@<id|#n> <text>`: answers a matching open inbox item or messages a matching root
//!     session (exact, prefix, unique suffix, `#n` alias, or unique title substring). Bare `@<id>`
//!     returns a usage hint instead of falling through.
//!   - Plain unquoted DM reply: answers ONLY a sole open blocking item; groups ignore unquoted
//!     chatter; attachments/reactions in DMs return a concise text-only hint.

use crate::wire::SignalHealth;
use ferret_agent::runtime::{BusEvent, InboxEntry, NoticeEvent, NoticeSource, Runtime, SessionInfo, LOW_DISK_NOTICE};
use ferret_agent::session::Phase;
use ferret_core::config::{valid_signal_uuid, SignalCfg};
use ferret_core::event::{Event, InboxItem, InboxKind, Record, ToolStatus, TurnEndReason};
use ferret_core::SessionId;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_SENT_REFS: usize = 500;
const ECHO_TTL: Duration = Duration::from_secs(300);
const PENDING_ECHO_TTL: Duration = Duration::from_secs(60);
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE: Duration = Duration::from_secs(30);
const SSE_BACKOFF_MIN: Duration = Duration::from_secs(2);
const SSE_BACKOFF_MAX: Duration = Duration::from_secs(60);
const OUTBOUND_QUEUE_CAP: usize = 128;
const BURST_COALESCE_WINDOW: Duration = Duration::from_millis(1_500);
const RETRY_DELAYS: [Duration; 3] = [Duration::from_secs(2), Duration::from_secs(5), Duration::from_secs(15)];
const DEFAULT_MUTE_SECS: u64 = 30 * 60;
const MAX_MUTE_SECS: u64 = 24 * 60 * 60;
const MAX_TAIL_ITEMS: usize = 15;
const DEFAULT_TAIL_ITEMS: usize = 6;
const TAIL_FETCH_LIMIT: usize = 50;

/// Metadata retained per outbound Signal message timestamp so phone quote-replies route precisely.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundRef {
    pub timestamp: u64,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    pub session: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    /// True when this alert represents a `request_scope` (`Approval` + non-blocking + host list).
    #[serde(default)]
    pub is_scope_request: bool,
    /// Owning lead session when `session` was a child (so follow-ups reach the mission lead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead_session: Option<String>,
}

/// Persisted bounded ring of outbound Signal timestamps (`<home>/signal_sent.json`, mode `0600`),
/// plus in-memory echo suppression, PNP identity cache, mute deadline, and `#N` phone shortcuts.
#[derive(Clone)]
struct SentStore {
    path: PathBuf,
    inner: Arc<Mutex<SentInner>>,
}

#[derive(Default)]
struct SentInner {
    order: VecDeque<u64>,
    by_ts: HashMap<u64, OutboundRef>,
    /// Recent outbound timestamps (all messages, including acks) for Note-to-Self echo filtering.
    recent_echo: VecDeque<(u64, Instant)>,
    /// Pre-send `(normalized_target, sha256(trimmed_body), recorded_at)` entries recorded BEFORE
    /// awaiting RPC `send`, closing the SSE-before-HTTP-response Note-to-Self echo race.
    pending_echo: VecDeque<(String, [u8; 32], Instant)>,
    /// Best-effort normalized UUID → E.164 mapping learned from envelopes & `listContacts`.
    uuid_to_number: HashMap<String, String>,
    /// Reverse E.164 → normalized UUID mapping (for Note-to-Self `destinationUuid` envelopes).
    number_to_uuid: HashMap<String, String>,
    /// `#1..#N` inbox item shortcuts populated by `/inbox` and multi-blocker ambiguity prompts.
    inbox_aliases: Vec<String>,
    /// `#1..#N` root session shortcuts populated by `/status` and multi-session `/resume`/`/stop`.
    session_aliases: Vec<String>,
    /// Epoch milliseconds until which outbound alerts are muted (`/mute`).
    muted_until_ms: Option<u64>,
    /// Inbox item IDs already enqueued/reconciled during this bridge lifetime (prevents lag dupes).
    seen_items: HashSet<String>,
}

impl SentStore {
    fn open(path: PathBuf) -> Self {
        let mut inner = SentInner::default();
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Vec<OutboundRef>>(&bytes) {
                Ok(list) => {
                    for r in list {
                        inner.order.push_back(r.timestamp);
                        inner.by_ts.insert(r.timestamp, r);
                    }
                    while inner.order.len() > MAX_SENT_REFS {
                        if let Some(old) = inner.order.pop_front() {
                            inner.by_ts.remove(&old);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "signal: could not parse {} ({e}); starting with empty quote-reply store",
                        path.display()
                    );
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    "signal: could not read {} ({e}); starting with empty quote-reply store",
                    path.display()
                );
            }
        }
        Self { path, inner: Arc::new(Mutex::new(inner)) }
    }

    fn note_pending_echo(&self, target: &str, body: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        prune_pending_echo(&mut g.pending_echo, now);
        g.pending_echo.push_back((normalize_echo_target(target), body_hash(body), now));
        while g.pending_echo.len() > MAX_SENT_REFS {
            g.pending_echo.pop_front();
        }
    }

    fn note_echo(&self, ts: u64) {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        prune_recent_echo(&mut g.recent_echo, now);
        g.recent_echo.push_back((ts, now));
        while g.recent_echo.len() > MAX_SENT_REFS {
            g.recent_echo.pop_front();
        }
    }

    fn consume_echo(&self, ts: Option<u64>, target: &str, body: &str) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        prune_recent_echo(&mut g.recent_echo, now);
        prune_pending_echo(&mut g.pending_echo, now);

        let norm_target = normalize_echo_target(target);
        let hash = body_hash(body);
        let mut matched = false;

        if let Some(t) = ts {
            if let Some(pos) = g.recent_echo.iter().position(|(recorded, _)| *recorded == t) {
                g.recent_echo.remove(pos);
                matched = true;
            }
            if g.by_ts.contains_key(&t) {
                matched = true;
            }
        }
        if let Some(pos) =
            g.pending_echo.iter().position(|(tgt, h, _)| *h == hash && echo_targets_match(&g, tgt, &norm_target))
        {
            g.pending_echo.remove(pos);
            matched = true;
        }
        matched
    }

    fn record_outbound(&self, info: OutboundRef) {
        let snapshot: Vec<OutboundRef> = {
            let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let ts = info.timestamp;
            g.order.retain(|t| *t != ts);
            g.order.push_back(ts);
            g.by_ts.insert(ts, info);
            while g.order.len() > MAX_SENT_REFS {
                if let Some(old) = g.order.pop_front() {
                    g.by_ts.remove(&old);
                }
            }
            g.order.iter().filter_map(|t| g.by_ts.get(t).cloned()).collect()
        };
        if let Err(e) = save_private_json(&self.path, &snapshot) {
            tracing::warn!("signal: could not persist {}: {e}", self.path.display());
        }
    }

    fn lookup(&self, ts: u64) -> Option<OutboundRef> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).by_ts.get(&ts).cloned()
    }

    fn has_recorded_item(&self, item_id: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .by_ts
            .values()
            .any(|r| r.item_id.as_deref() == Some(item_id))
    }

    fn mark_item_seen(&self, item_id: &str) -> bool {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).seen_items.insert(item_id.to_string())
    }

    fn is_item_seen(&self, item_id: &str) -> bool {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).seen_items.contains(item_id)
    }

    fn remember_identity(&self, number: Option<&str>, uuid: Option<&str>) {
        let Some(n) = number.map(str::trim).filter(|s| !s.is_empty()) else {
            return;
        };
        let Some(u_raw) = uuid.map(str::trim).filter(|s| !s.is_empty()) else {
            return;
        };
        let u = SignalCfg::normalize_signal_id(u_raw).to_ascii_lowercase();
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        g.uuid_to_number.insert(u.clone(), n.to_string());
        g.number_to_uuid.insert(n.to_ascii_lowercase(), u);
    }

    fn number_for_uuid(&self, uuid: &str) -> Option<String> {
        let key = SignalCfg::normalize_signal_id(uuid).to_ascii_lowercase();
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).uuid_to_number.get(&key).cloned()
    }

    fn uuid_for_number(&self, number: &str) -> Option<String> {
        let key = number.trim().to_ascii_lowercase();
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).number_to_uuid.get(&key).cloned()
    }

    fn set_inbox_aliases(&self, ids: Vec<String>) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).inbox_aliases = ids;
    }

    fn inbox_alias(&self, one_based: usize) -> Option<String> {
        one_based
            .checked_sub(1)
            .and_then(|idx| self.inner.lock().unwrap_or_else(|p| p.into_inner()).inbox_aliases.get(idx).cloned())
    }

    fn set_session_aliases(&self, ids: Vec<String>) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).session_aliases = ids;
    }

    fn session_alias(&self, one_based: usize) -> Option<String> {
        one_based
            .checked_sub(1)
            .and_then(|idx| self.inner.lock().unwrap_or_else(|p| p.into_inner()).session_aliases.get(idx).cloned())
    }

    fn set_muted_until(&self, until_ms: Option<u64>, health: &SignalHealth) {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).muted_until_ms = until_ms;
        health.set_muted_until(until_ms);
    }

    fn muted_until(&self, now_ms: u64, health: &SignalHealth) -> Option<u64> {
        let mut g = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match g.muted_until_ms {
            Some(until) if until > now_ms => Some(until),
            Some(_) => {
                g.muted_until_ms = None;
                drop(g);
                health.set_muted_until(None);
                None
            }
            None => None,
        }
    }
}

fn prune_recent_echo(q: &mut VecDeque<(u64, Instant)>, now: Instant) {
    while q.front().is_some_and(|(_, t)| now.saturating_duration_since(*t) > ECHO_TTL) {
        q.pop_front();
    }
}

fn prune_pending_echo(q: &mut VecDeque<(String, [u8; 32], Instant)>, now: Instant) {
    while q.front().is_some_and(|(_, _, t)| now.saturating_duration_since(*t) > PENDING_ECHO_TTL) {
        q.pop_front();
    }
}

fn normalize_echo_target(target: &str) -> String {
    let t = target.trim();
    if let Some(gid) = t.strip_prefix("group:") {
        format!("group:{}", gid.trim())
    } else {
        SignalCfg::normalize_signal_id(t).to_ascii_lowercase()
    }
}

/// Match normalized echo targets directly or across learned E.164 ↔ UUID identity mappings so a
/// Note-to-Self `destinationUuid`-only sync envelope suppresses a pending E.164 send (and vice versa).
fn echo_targets_match(inner: &SentInner, stored: &str, incoming: &str) -> bool {
    if stored == incoming || stored.is_empty() || incoming.is_empty() {
        return true;
    }
    if stored.starts_with("group:") || incoming.starts_with("group:") {
        return false;
    }
    inner.uuid_to_number.get(incoming).is_some_and(|n| n.eq_ignore_ascii_case(stored))
        || inner.number_to_uuid.get(incoming).is_some_and(|u| u.eq_ignore_ascii_case(stored))
        || inner.uuid_to_number.get(stored).is_some_and(|n| n.eq_ignore_ascii_case(incoming))
        || inner.number_to_uuid.get(stored).is_some_and(|u| u.eq_ignore_ascii_case(incoming))
}

fn body_hash(body: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body.trim().as_bytes());
    hasher.finalize().into()
}

fn save_private_json<T: Serialize>(path: &Path, val: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(val).map_err(std::io::Error::other)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("signal_sent.json");
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// JSON-RPC / SSE client over `signal-cli daemon --http`.
#[derive(Clone)]
pub struct SignalClient {
    cfg: SignalCfg,
    http: reqwest::Client,
    base: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalCheckReport {
    pub http_url: String,
    pub account: String,
    pub recipient: String,
    pub allow_from: Vec<String>,
    pub events: Vec<String>,
    pub reachable: bool,
    /// `Some(true)` when `listAccounts` confirmed `account` is loaded; `None` if unsupported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_registered: Option<bool>,
    /// Non-fatal setup warnings (e.g., `recipient` absent from `allow_from`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl SignalClient {
    pub fn new(cfg: SignalCfg) -> Result<Self, String> {
        cfg.check()?;
        let base = cfg.http_url.trim().trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(CONNECT_TIMEOUT)
            .tcp_keepalive(TCP_KEEPALIVE)
            .build()
            .map_err(|e| format!("Could not build Signal HTTP client: {e}"))?;
        Ok(Self { cfg, http, base })
    }

    pub fn config(&self) -> &SignalCfg {
        &self.cfg
    }

    /// Ping `{http_url}/api/v1/check`, verify `account` via `listAccounts` when supported, and
    /// return configuration sanity warnings.
    pub async fn check(&self) -> Result<SignalCheckReport, String> {
        let url = format!("{}/api/v1/check", self.base);
        let resp = self.http.get(&url).timeout(CHECK_TIMEOUT).send().await.map_err(|e| {
            let bind = http_bind_hint(&self.base);
            let acct = self.cfg.account.trim();
            format!(
                "Cannot reach signal-cli daemon at {} ({e}). Start it with `signal-cli -a {acct} daemon --http {bind}` (or `signal-cli daemon --http {bind}` for multi-account).",
                self.base
            )
        })?;
        if !resp.status().is_success() {
            return Err(format!("signal-cli health check at {url} returned HTTP {}", resp.status().as_u16()));
        }

        let account_registered = self.check_registered_account().await?;
        let warnings = config_sanity_warnings(&self.cfg);

        Ok(SignalCheckReport {
            http_url: self.base.clone(),
            account: self.cfg.account.clone(),
            recipient: self.cfg.recipient.clone(),
            allow_from: self.cfg.allow_from.clone(),
            events: self.cfg.events.clone(),
            reachable: true,
            account_registered,
            warnings,
        })
    }

    /// Best-effort `listAccounts` verification: returns `Ok(Some(true))` when the configured
    /// account is loaded, `Err(...)` when `listAccounts` succeeds and omits it, or `Ok(None)` when
    /// the daemon does not expose `listAccounts`.
    async fn check_registered_account(&self) -> Result<Option<bool>, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "listAccounts",
            "id": "ferret_check_accounts",
        });
        let Ok(resp) =
            self.http.post(format!("{}/api/v1/rpc", self.base)).timeout(CHECK_TIMEOUT).json(&body).send().await
        else {
            return Ok(None);
        };
        if !resp.status().is_success() {
            return Ok(None);
        }
        let Ok(val) = resp.json::<Value>().await else {
            return Ok(None);
        };
        let Some(list) = val.get("result").and_then(Value::as_array) else {
            return Ok(None);
        };
        let accounts: Vec<String> = list
            .iter()
            .filter_map(|entry| {
                entry
                    .as_str()
                    .or_else(|| entry.get("number").and_then(Value::as_str))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .collect();
        let wanted = self.cfg.account.trim();
        if accounts.iter().any(|a| a.eq_ignore_ascii_case(wanted)) {
            return Ok(Some(true));
        }
        let loaded = if accounts.is_empty() { "none".to_string() } else { accounts.join(", ") };
        Err(format!(
            "signal-cli daemon at {} is reachable, but account {wanted} is not loaded (loaded accounts: {loaded}). Register/link {wanted} or restart signal-cli with `-a {wanted}`.",
            self.base
        ))
    }

    /// Send a plain text message to `target` (E.164, Signal UUID/PNI, or `group:<id>`) and return
    /// the Signal timestamp.
    pub async fn send_message(&self, target: &str, message: &str) -> Result<Option<u64>, String> {
        let mut params = serde_json::Map::new();
        params.insert("account".into(), json!(self.cfg.account.trim()));
        params.insert("message".into(), json!(message));
        let t = target.trim();
        if t.starts_with("group:") {
            params.insert("groupId".into(), json!(SignalCfg::normalize_group_id(t)));
        } else {
            params.insert("recipient".into(), json!([normalize_rpc_recipient(t)]));
        }
        let body = json!({
            "jsonrpc": "2.0",
            "method": "send",
            "params": Value::Object(params),
            "id": format!("ferret_{}", ferret_core::now_ms()),
        });
        let resp = self
            .http
            .post(format!("{}/api/v1/rpc", self.base))
            .timeout(RPC_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("Signal RPC send failed (could not reach {}): {e}", self.base))?;
        if !resp.status().is_success() {
            return Err(format!("Signal RPC send returned HTTP {}", resp.status().as_u16()));
        }
        let val: Value = resp.json().await.map_err(|e| format!("Invalid JSON from signal-cli RPC: {e}"))?;
        if let Some(err) = val.get("error") {
            return Err(translate_rpc_error(err, self.cfg.account.trim()));
        }
        let result = val.get("result");
        if let Some(results) = result.and_then(|r| r.get("results")).and_then(Value::as_array) {
            for r in results {
                if let Some(rtype) = r.get("type").and_then(Value::as_str) {
                    if rtype != "SUCCESS" {
                        return Err(translate_delivery_error(r, rtype, self.cfg.account.trim(), t));
                    }
                }
            }
        }
        Ok(result.and_then(|r| r.get("timestamp")).and_then(Value::as_u64))
    }

    /// Send a message to the configured `signal.recipient`.
    pub async fn send_default(&self, message: &str) -> Result<Option<u64>, String> {
        self.send_message(&self.cfg.recipient, message).await
    }

    /// Best-effort fetch of contacts so UUID-only inbound messages still match E.164 `allow_from`.
    async fn warm_contacts(&self, store: &SentStore) {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "listContacts",
            "params": { "account": self.cfg.account.trim(), "allRecipients": true },
            "id": "ferret_contacts",
        });
        let Ok(resp) =
            self.http.post(format!("{}/api/v1/rpc", self.base)).timeout(CHECK_TIMEOUT).json(&body).send().await
        else {
            return;
        };
        let Ok(val) = resp.json::<Value>().await else { return };
        let Some(list) = val.get("result").and_then(Value::as_array) else { return };
        for c in list {
            let num = c.get("number").and_then(Value::as_str);
            for field in ["uuid", "serviceId", "aci", "pni"] {
                if let Some(uuid) = c.get(field).and_then(Value::as_str) {
                    store.remember_identity(num, Some(uuid));
                }
            }
        }
    }
}

fn http_bind_hint(base: &str) -> String {
    if let Ok(u) = reqwest::Url::parse(base) {
        if let Some(host) = u.host_str() {
            return match u.port() {
                Some(p) => format!("{host}:{p}"),
                None => host.to_string(),
            };
        }
    }
    "127.0.0.1:1337".to_string()
}

/// Normalize a non-group recipient for `signal-cli`: keep `PNI:<uuid>` uppercase, strip `u:`/`U:`
/// when wrapping a UUID (signal-cli takes bare ACI UUIDs, not `u:<uuid>`), and preserve E.164.
fn normalize_rpc_recipient(raw: &str) -> String {
    let t = raw.trim();
    if let Some(rest) = t.strip_prefix("pni:").or_else(|| t.strip_prefix("PNI:")) {
        return format!("PNI:{}", rest.trim());
    }
    if let Some(rest) = t.strip_prefix("u:").or_else(|| t.strip_prefix("U:")) {
        let trimmed = rest.trim();
        if valid_signal_uuid(trimmed) {
            return trimmed.to_string();
        }
    }
    t.to_string()
}

fn config_sanity_warnings(cfg: &SignalCfg) -> Vec<String> {
    let mut warnings = Vec::new();
    let rec = cfg.recipient.trim();
    if !rec.starts_with("group:") {
        let norm_rec = SignalCfg::normalize_signal_id(rec);
        let in_allow = cfg.allow_from.iter().any(|a| SignalCfg::normalize_signal_id(a).eq_ignore_ascii_case(norm_rec));
        if !in_allow {
            warnings.push(format!(
                "signal.recipient ({rec}) is not in signal.allow_from; outbound alerts will send, but replies from that recipient will be ignored."
            ));
        }
    }
    warnings
}

fn translate_rpc_error(err: &Value, account: &str) -> String {
    let code = err.get("code").and_then(Value::as_i64);
    let msg = err.get("message").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
    let Some(msg) = msg else {
        return format!("Signal RPC error: {err}");
    };
    let lower = msg.to_ascii_lowercase();
    if lower.contains("not registered") || lower.contains("unknown account") || lower.contains("account not found") {
        return format!(
            "Signal RPC error: {msg}. Verify account {account} is registered/linked (`signal-cli listAccounts`) or start signal-cli with `-a {account}`."
        );
    }
    if lower.contains("untrusted") || lower.contains("identity") {
        return format!(
            "Signal RPC error: {msg}. Trust the recipient's safety number with `signal-cli -a {account} trust -a <recipient>`."
        );
    }
    match code {
        Some(c) => format!("Signal RPC error ({c}): {msg}"),
        None => format!("Signal RPC error: {msg}"),
    }
}

fn translate_delivery_error(result_obj: &Value, rtype: &str, account: &str, target: &str) -> String {
    let who = result_obj
        .get("recipientAddress")
        .and_then(|a| a.get("number").or_else(|| a.get("uuid")).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .unwrap_or(target);
    let extra = result_obj.get("message").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());

    match rtype {
        "UNTRUSTED_IDENTITY" | "IDENTITY_FAILURE" => format!(
            "Signal delivery failed ({rtype}) for {who}: safety number changed or is not yet trusted. Verify the safety number in Signal, then run `signal-cli -a {account} trust -a {who}` (or `signal-cli -a {account} trust -v <SAFETY_NUMBER> {who}`)."
        ),
        "UNREGISTERED_FAILURE" => format!(
            "Signal delivery failed (UNREGISTERED_FAILURE) for {who}: recipient is not registered on Signal or hides their phone number under Phone Number Privacy (configure their Signal ACI UUID instead of E.164)."
        ),
        "NETWORK_FAILURE" => {
            "Signal delivery failed (NETWORK_FAILURE): signal-cli could not reach Signal servers (transient — check network and signal-cli logs).".to_string()
        }
        "PROOF_REQUIRED_FAILURE" => format!(
            "Signal delivery failed (PROOF_REQUIRED_FAILURE): Signal rate-limited or requires a captcha challenge on account {account}."
        ),
        _ => match extra {
            Some(detail) => format!("Signal delivery failed ({rtype}) for {who}: {detail}"),
            None => format!("Signal delivery failed: {rtype} (for {who})"),
        },
    }
}

fn is_permanent_send_error(err: &str) -> bool {
    [
        "UNTRUSTED_IDENTITY",
        "IDENTITY_FAILURE",
        "UNREGISTERED_FAILURE",
        "PROOF_REQUIRED_FAILURE",
        "HTTP 400",
        "HTTP 401",
        "HTTP 403",
        "HTTP 404",
        "not registered",
        "Unknown account",
        "Account not found",
    ]
    .iter()
    .any(|needle| err.contains(needle))
}

#[derive(Clone, Debug)]
enum OutboundJob {
    Inbox { session: SessionId, item: InboxItem, kind: String, is_reminder: bool },
    Error { session: Option<SessionId>, message: String },
    Notice { kind: String, title: String, text: String },
}

#[derive(Clone, Copy, Debug)]
struct SenderTiming {
    coalesce_window: Duration,
    retry_delays: [Duration; 3],
}

impl Default for SenderTiming {
    fn default() -> Self {
        Self { coalesce_window: BURST_COALESCE_WINDOW, retry_delays: RETRY_DELAYS }
    }
}

/// Spawn the two-way Signal bridge (decoupled outbound collector + sender + inbound SSE listener)
/// until `shutdown`.
pub fn spawn_bridge(
    cfg: SignalCfg,
    runtime: Runtime,
    sent_store_path: PathBuf,
    health: Arc<SignalHealth>,
    shutdown: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    let client = match SignalClient::new(cfg) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("signal bridge disabled due to invalid config: {e}");
            health.record_error(format!("invalid config: {e}"));
            return None;
        }
    };
    let store = SentStore::open(sent_store_path);
    Some(tokio::spawn(async move {
        tracing::info!(
            "signal bridge active: {} -> {} (events: {})",
            client.config().http_url,
            client.config().recipient,
            client.config().events.join(", ")
        );
        client.warm_contacts(&store).await;
        let (tx, rx) = mpsc::channel::<OutboundJob>(OUTBOUND_QUEUE_CAP);
        let pending = Arc::new(AtomicUsize::new(0));
        let collect_task = outbound_collector_loop(
            client.config().clone(),
            runtime.clone(),
            store.clone(),
            health.clone(),
            tx,
            pending.clone(),
            shutdown.clone(),
        );
        let send_task = outbound_sender_loop(
            client.clone(),
            runtime.clone(),
            store.clone(),
            health.clone(),
            rx,
            pending,
            SenderTiming::default(),
            shutdown.clone(),
        );
        let in_task = inbound_sse_loop(client, runtime, store, health, shutdown);
        tokio::join!(collect_task, send_task, in_task);
        tracing::info!("signal bridge stopped");
    }))
}

fn try_enqueue_job(
    tx: &mpsc::Sender<OutboundJob>,
    pending: &AtomicUsize,
    health: &SignalHealth,
    job: OutboundJob,
) -> bool {
    match tx.try_send(job) {
        Ok(()) => {
            let count = pending.fetch_add(1, Ordering::SeqCst) + 1;
            health.set_pending_sends(count);
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::warn!("signal outbound queue full ({OUTBOUND_QUEUE_CAP}); dropping alert");
            health.add_dropped_events(1);
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn dec_pending(pending: &AtomicUsize, health: &SignalHealth) {
    let prev = pending.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_sub(1))).unwrap_or(0);
    health.set_pending_sends(prev.saturating_sub(1));
}

fn reconcile_open_inbox(
    cfg: &SignalCfg,
    runtime: &Runtime,
    store: &SentStore,
    health: &SignalHealth,
    tx: &mpsc::Sender<OutboundJob>,
    pending: &AtomicUsize,
    blocking_only: bool,
) {
    for entry in runtime.inbox() {
        if blocking_only && !entry.item.blocking {
            continue;
        }
        let kind = inbox_kind_str(entry.item.kind);
        if !cfg.wants_event(kind) {
            continue;
        }
        if store.is_item_seen(&entry.item.item_id) {
            continue;
        }
        let is_reminder = blocking_only && store.has_recorded_item(&entry.item.item_id);
        store.mark_item_seen(&entry.item.item_id);
        let _ = try_enqueue_job(
            tx,
            pending,
            health,
            OutboundJob::Inbox { session: entry.session, item: entry.item, kind: kind.to_string(), is_reminder },
        );
    }
}

async fn outbound_collector_loop(
    cfg: SignalCfg,
    runtime: Runtime,
    store: SentStore,
    health: Arc<SignalHealth>,
    tx: mpsc::Sender<OutboundJob>,
    pending: Arc<AtomicUsize>,
    shutdown: CancellationToken,
) {
    let mut rx_bus = runtime.subscribe();
    let mut rx_notices = runtime.subscribe_notices();

    // Catch up anything already open before `spawn_bridge` subscribed (post-restart reminders and
    // low-disk state).
    if runtime.disk_low() && cfg.wants_event("disk") {
        let _ = try_enqueue_job(
            &tx,
            &pending,
            &health,
            OutboundJob::Notice {
                kind: "disk".to_string(),
                title: "Low disk space".to_string(),
                text: LOW_DISK_NOTICE.to_string(),
            },
        );
    }
    reconcile_open_inbox(&cfg, &runtime, &store, &health, &tx, &pending, true);

    let mut notices_open = true;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            r = rx_bus.recv() => match r {
                Ok(BusEvent::Record { session, record }) => {
                    if let Event::InboxOpened(item) = record.event {
                        let kind = inbox_kind_str(item.kind);
                        if !cfg.wants_event(kind) {
                            continue;
                        }
                        store.mark_item_seen(&item.item_id);
                        let _ = try_enqueue_job(
                            &tx,
                            &pending,
                            &health,
                            OutboundJob::Inbox {
                                session,
                                item,
                                kind: kind.to_string(),
                                is_reminder: false,
                            },
                        );
                    }
                }
                Ok(BusEvent::Error { session, message }) => {
                    if cfg.wants_event("error") {
                        let _ = try_enqueue_job(&tx, &pending, &health, OutboundJob::Error { session, message });
                    }
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("signal bridge lagged {n} bus events; reconciling open inbox");
                    health.add_dropped_events(n);
                    reconcile_open_inbox(&cfg, &runtime, &store, &health, &tx, &pending, false);
                }
                Err(RecvError::Closed) => return,
            },
            n = rx_notices.recv(), if notices_open => match n {
                Ok(notice) => enqueue_notice(&cfg, &store, &health, &tx, &pending, notice),
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("signal bridge lagged {n} notice events");
                    health.add_dropped_events(n);
                }
                Err(RecvError::Closed) => {
                    notices_open = false;
                }
            },
        }
    }
}

fn enqueue_notice(
    cfg: &SignalCfg,
    store: &SentStore,
    health: &SignalHealth,
    tx: &mpsc::Sender<OutboundJob>,
    pending: &AtomicUsize,
    notice: NoticeEvent,
) {
    if !cfg.wants_event(&notice.kind) {
        return;
    }
    match notice.source {
        NoticeSource::Disk => {
            let _ = try_enqueue_job(
                tx,
                pending,
                health,
                OutboundJob::Notice { kind: notice.kind, title: notice.title, text: notice.text },
            );
        }
        NoticeSource::Repeat | NoticeSource::Restart => {
            if let (Some(session), Some(item)) = (notice.session, notice.item) {
                store.mark_item_seen(&item.item_id);
                let _ = try_enqueue_job(
                    tx,
                    pending,
                    health,
                    OutboundJob::Inbox { session, item, kind: notice.kind, is_reminder: true },
                );
            } else {
                let _ = try_enqueue_job(
                    tx,
                    pending,
                    health,
                    OutboundJob::Notice { kind: notice.kind, title: notice.title, text: notice.text },
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn outbound_sender_loop(
    client: SignalClient,
    runtime: Runtime,
    store: SentStore,
    health: Arc<SignalHealth>,
    mut rx: mpsc::Receiver<OutboundJob>,
    pending: Arc<AtomicUsize>,
    timing: SenderTiming,
    shutdown: CancellationToken,
) {
    let mut deferred: Option<OutboundJob> = None;

    loop {
        let job = match deferred.take() {
            Some(j) => j,
            None => {
                let next = tokio::select! {
                    _ = shutdown.cancelled() => return,
                    j = rx.recv() => j,
                };
                match next {
                    Some(j) => {
                        dec_pending(&pending, &health);
                        j
                    }
                    None => return,
                }
            }
        };

        // Honor active `/mute` deadline (and auto-clear when expired).
        if store.muted_until(ferret_core::now_ms(), &health).is_some() {
            tracing::debug!("signal outbound suppressed while muted");
            continue;
        }

        match job {
            OutboundJob::Inbox { session, item, kind, is_reminder } => {
                let (title, is_child, lead) = session_meta_summary(&runtime, &session);
                let display_title = if is_child { format!("unverified: {title}") } else { title.clone() };
                let text =
                    format_inbox_alert(&kind, &session, &display_title, &item, client.config().max_chars, is_reminder);
                let scope_req = is_scope_request(&item);
                let res = send_with_retry(&client, &store, &text, timing.retry_delays, &shutdown).await;
                match res {
                    Ok(ts_opt) => {
                        health.record_send_ok(ferret_core::now_ms());
                        if let Some(ts) = ts_opt {
                            store.note_echo(ts);
                            store.record_outbound(OutboundRef {
                                timestamp: ts,
                                kind,
                                item_id: Some(item.item_id),
                                session: session.as_str().to_string(),
                                title,
                                options: item.options,
                                is_scope_request: scope_req,
                                lead_session: lead.map(|s| s.as_str().to_string()),
                            });
                        }
                    }
                    Err(e) => {
                        tracing::warn!("signal outbound ({kind}) failed: {e}");
                        health.record_error(format!("outbound ({kind}): {e}"));
                        health.add_dropped_events(1);
                    }
                }
            }
            OutboundJob::Error { session, message } => {
                let mut batch = vec![(session, message)];
                // Briefly coalesce rapid error bursts into one notification without delaying
                // non-error inbox items.
                if !timing.coalesce_window.is_zero() {
                    let deadline = tokio::time::Instant::now() + timing.coalesce_window;
                    loop {
                        let next = tokio::select! {
                            _ = shutdown.cancelled() => return,
                            _ = tokio::time::sleep_until(deadline) => None,
                            j = rx.recv() => j,
                        };
                        match next {
                            Some(OutboundJob::Error { session, message }) => {
                                dec_pending(&pending, &health);
                                batch.push((session, message));
                                if batch.len() >= 10 {
                                    break;
                                }
                            }
                            Some(other) => {
                                dec_pending(&pending, &health);
                                deferred = Some(other);
                                break;
                            }
                            None => break,
                        }
                    }
                }
                let (text, single_ref) = if batch.len() == 1 {
                    let (sess, msg) = batch.remove(0);
                    let (sid, display_title, raw_title, lead) = match &sess {
                        Some(s) => {
                            let (t, is_child, lead) = session_meta_summary(&runtime, s);
                            let dt = if is_child { format!("unverified: {t}") } else { t.clone() };
                            (s.as_str().to_string(), dt, t, lead)
                        }
                        None => ("daemon".to_string(), "Ferret daemon".to_string(), "Ferret daemon".to_string(), None),
                    };
                    let text = format_error_alert(&sid, &display_title, &msg, client.config().max_chars);
                    let r = sess.map(|s| (s, raw_title, lead));
                    (text, r)
                } else {
                    let entries: Vec<(String, String, String)> = batch
                        .into_iter()
                        .map(|(sess, msg)| match sess {
                            Some(s) => {
                                let (t, is_child, _) = session_meta_summary(&runtime, &s);
                                let dt = if is_child { format!("unverified: {t}") } else { t };
                                (s.as_str().to_string(), dt, msg)
                            }
                            None => ("daemon".to_string(), "Ferret daemon".to_string(), msg),
                        })
                        .collect();
                    (format_error_burst(&entries, client.config().max_chars), None)
                };
                match send_with_retry(&client, &store, &text, timing.retry_delays, &shutdown).await {
                    Ok(ts_opt) => {
                        health.record_send_ok(ferret_core::now_ms());
                        if let Some(ts) = ts_opt {
                            store.note_echo(ts);
                            if let Some((s, title, lead)) = single_ref {
                                store.record_outbound(OutboundRef {
                                    timestamp: ts,
                                    kind: "error".to_string(),
                                    item_id: None,
                                    session: s.as_str().to_string(),
                                    title,
                                    options: Vec::new(),
                                    is_scope_request: false,
                                    lead_session: lead.map(|l| l.as_str().to_string()),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("signal outbound (error) failed: {e}");
                        health.record_error(format!("outbound (error): {e}"));
                        health.add_dropped_events(1);
                    }
                }
            }
            OutboundJob::Notice { kind, title, text } => {
                let msg = format_notice_alert(&kind, &title, &text, client.config().max_chars);
                match send_with_retry(&client, &store, &msg, timing.retry_delays, &shutdown).await {
                    Ok(ts_opt) => {
                        health.record_send_ok(ferret_core::now_ms());
                        if let Some(ts) = ts_opt {
                            store.note_echo(ts);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("signal outbound ({kind}) failed: {e}");
                        health.record_error(format!("outbound ({kind}): {e}"));
                        health.add_dropped_events(1);
                    }
                }
            }
        }
    }
}

async fn send_with_retry(
    client: &SignalClient,
    store: &SentStore,
    text: &str,
    retry_delays: [Duration; 3],
    shutdown: &CancellationToken,
) -> Result<Option<u64>, String> {
    let target = &client.config().recipient;
    let mut attempt = 0usize;
    loop {
        store.note_pending_echo(target, text);
        match client.send_default(text).await {
            Ok(ts) => return Ok(ts),
            Err(e) => {
                if is_permanent_send_error(&e) || attempt >= retry_delays.len() {
                    return Err(e);
                }
                let delay = retry_delays[attempt];
                attempt += 1;
                tracing::warn!(
                    "signal outbound transient error (retry {attempt}/{} in {delay:?}): {e}",
                    retry_delays.len()
                );
                tokio::select! {
                    _ = shutdown.cancelled() => return Err(e),
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }
    }
}

/// Incremental UTF-8-safe Server-Sent Events frame decoder.
///
/// Buffers raw bytes until `\n` boundaries so multi-byte UTF-8 characters (emoji, smart quotes,
/// non-ASCII text) split across TCP chunks are never corrupted, and reassembles multi-line `data:`
/// blocks terminated by blank lines (`\n\n` / `\r\n\r\n`).
#[derive(Default)]
struct SseDecoder {
    buf: Vec<u8>,
    data_lines: Vec<String>,
}

impl SseDecoder {
    fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
            let mut line_bytes: Vec<u8> = self.buf.drain(..=nl).collect();
            if line_bytes.last() == Some(&b'\n') {
                line_bytes.pop();
            }
            if line_bytes.last() == Some(&b'\r') {
                line_bytes.pop();
            }
            let line = match String::from_utf8(line_bytes) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("signal SSE: non-UTF-8 bytes in line; replacing lossily");
                    String::from_utf8_lossy(e.as_bytes()).into_owned()
                }
            };
            if line.is_empty() {
                if !self.data_lines.is_empty() {
                    events.push(self.data_lines.join("\n"));
                    self.data_lines.clear();
                }
                continue;
            }
            if line.starts_with(':') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("data:") {
                let val = rest.strip_prefix(' ').unwrap_or(rest);
                self.data_lines.push(val.to_string());
            }
        }
        events
    }

    fn flush(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let mut leftover = std::mem::take(&mut self.buf);
            if leftover.last() == Some(&b'\r') {
                leftover.pop();
            }
            if let Ok(line) = String::from_utf8(leftover) {
                if let Some(rest) = line.strip_prefix("data:") {
                    let val = rest.strip_prefix(' ').unwrap_or(rest);
                    self.data_lines.push(val.to_string());
                }
            }
        }
        if !self.data_lines.is_empty() {
            out.push(self.data_lines.join("\n"));
            self.data_lines.clear();
        }
        out
    }
}

async fn inbound_sse_loop(
    client: SignalClient,
    runtime: Runtime,
    store: SentStore,
    health: Arc<SignalHealth>,
    shutdown: CancellationToken,
) {
    let mut backoff = SSE_BACKOFF_MIN;
    let events_url = format!("{}/api/v1/events", client.base);
    let account = client.config().account.trim().to_string();

    while !shutdown.is_cancelled() {
        let req = client
            .http
            .get(&events_url)
            .query(&[("account", account.as_str())])
            .header("Accept", "text/event-stream")
            .send();

        let resp = tokio::select! {
            _ = shutdown.cancelled() => {
                health.set_connected(false);
                return;
            }
            r = req => r,
        };
        match resp {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("signal SSE connected to {}", client.base);
                health.set_connected(true);
                health.clear_error();
                backoff = SSE_BACKOFF_MIN;
                // Re-warm contacts on every connect so daemon-before-signal-cli boot ordering still
                // learns UUID ↔ E.164 identities for Phone Number Privacy users.
                client.warm_contacts(&store).await;
                let mut stream = resp.bytes_stream();
                let mut decoder = SseDecoder::default();
                loop {
                    let chunk = tokio::select! {
                        _ = shutdown.cancelled() => {
                            health.set_connected(false);
                            return;
                        }
                        next = stream.next() => next,
                    };
                    let Some(item) = chunk else {
                        for payload in decoder.flush() {
                            process_sse_payload(&client, &runtime, &store, &health, &payload).await;
                        }
                        health.set_connected(false);
                        tracing::warn!("signal SSE stream closed by server (retrying in {backoff:?})");
                        break;
                    };
                    match item {
                        Ok(bytes) => {
                            for payload in decoder.push(&bytes) {
                                process_sse_payload(&client, &runtime, &store, &health, &payload).await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("signal SSE stream error: {e}");
                            health.set_connected(false);
                            health.record_error(format!("SSE stream error: {e}"));
                            break;
                        }
                    }
                }
            }
            Ok(resp) => {
                let code = resp.status().as_u16();
                tracing::warn!("signal SSE HTTP {code} (retrying in {backoff:?})");
                health.set_connected(false);
                health.record_error(format!("SSE HTTP {code}"));
            }
            Err(e) => {
                tracing::warn!("signal SSE connect error: {e} (retrying in {backoff:?})");
                health.set_connected(false);
                health.record_error(format!("SSE connect error: {e}"));
            }
        }
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(SSE_BACKOFF_MAX);
    }
}

async fn process_sse_payload(
    client: &SignalClient,
    runtime: &Runtime,
    store: &SentStore,
    health: &SignalHealth,
    payload: &str,
) {
    let trimmed = payload.trim();
    if trimmed.is_empty() {
        return;
    }
    health.record_event(ferret_core::now_ms());
    match serde_json::from_str::<Value>(trimmed) {
        Ok(val) => handle_envelope(client, runtime, store, health, &val).await,
        Err(e) => tracing::warn!("signal SSE: ignoring malformed JSON event: {e}"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum InboundContent {
    Text { text: String, quote_ts: Option<u64>, quote_text: Option<String> },
    AttachmentOnly,
    Reaction { emoji: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedInbound {
    sender: String,
    sender_uuid: Option<String>,
    reply_target: String,
    group_id: Option<String>,
    content: InboundContent,
    is_note_to_self: bool,
}

fn is_ferret_bot_message(text: &str) -> bool {
    let t = text.trim();
    t.starts_with("[Ferret · ")
        || t.starts_with("✓ ")
        || t.starts_with("✗ ")
        || t.starts_with("Ferret Signal commands:")
        || t.starts_with("Ferret status:")
        || t.starts_with("Open inbox items (")
        || t.starts_with("Inbox is empty.")
        || t.starts_with("Multiple items are waiting")
        || t.starts_with("Multiple sessions are running")
        || t.starts_with("Multiple stopped/parked sessions")
        || t.starts_with("Multiple dismissible items")
        || t.starts_with("No blocking inbox item is waiting")
        || t.starts_with("No running session")
        || t.starts_with("No stopped or parked session")
        || t.starts_with("No missions yet.")
        || t.starts_with("Specify a session id")
        || t.starts_with("Unknown command ")
        || t.starts_with("Usage: ")
        || t.starts_with("Attachments and voice notes aren't supported")
        || t.starts_with("Reactions aren't acted on")
        || t.starts_with("Recent activity for ")
}

fn parse_envelope(cfg: &SignalCfg, store: &SentStore, raw: &Value) -> Option<ParsedInbound> {
    let env = raw.get("envelope").unwrap_or(raw);
    let account = cfg.account.trim();

    let source_num = env.get("sourceNumber").and_then(Value::as_str);
    let source_uuid = env.get("sourceUuid").and_then(Value::as_str);
    store.remember_identity(source_num, source_uuid);

    let (is_note_to_self, data_msg) = if let Some(sync) = env.get("syncMessage") {
        let sent = sync.get("sentMessage")?;
        let dest_num = sent
            .get("destinationNumber")
            .and_then(Value::as_str)
            .or_else(|| sent.get("destination").and_then(Value::as_str));
        let dest_uuid = sent.get("destinationUuid").and_then(Value::as_str);
        let group_opt =
            sent.get("groupInfo").and_then(|g| g.get("groupId")).and_then(Value::as_str).filter(|s| !s.is_empty());
        let is_self_dest = dest_num.is_some_and(|d| d.eq_ignore_ascii_case(account))
            || dest_uuid.is_some_and(|du| {
                let norm_du = SignalCfg::normalize_signal_id(du);
                store.number_for_uuid(norm_du).is_some_and(|n| n.eq_ignore_ascii_case(account))
                    || store.uuid_for_number(account).is_some_and(|au| au.eq_ignore_ascii_case(norm_du))
                    || source_uuid.is_some_and(|su| SignalCfg::normalize_signal_id(su).eq_ignore_ascii_case(norm_du))
            });
        if !is_self_dest && group_opt.is_none() {
            return None;
        }
        let sent_ts = sent.get("timestamp").and_then(Value::as_u64);
        let sent_text = sent.get("message").and_then(Value::as_str).unwrap_or("").trim();
        let echo_target = match group_opt {
            Some(gid) => format!("group:{gid}"),
            None => dest_num.or(dest_uuid).unwrap_or(account).to_string(),
        };
        if store.consume_echo(sent_ts, &echo_target, sent_text)
            || (is_self_dest && group_opt.is_none() && store.consume_echo(sent_ts, account, sent_text))
        {
            return None;
        }
        // Suppress Note-to-Self sync echoes carrying Ferret's own outbound alert/ack/test prefixes
        // (covers `ferret signal test` sent from a separate CLI process and daemon restarts).
        if is_ferret_bot_message(sent_text) {
            return None;
        }
        (true, sent)
    } else {
        let dm = env.get("dataMessage").or_else(|| env.get("editMessage").and_then(|e| e.get("dataMessage")))?;
        (false, dm)
    };

    let source_any = source_num.or(source_uuid).or_else(|| env.get("source").and_then(Value::as_str))?;

    if source_num.is_some_and(|n| n.eq_ignore_ascii_case(account)) && !is_note_to_self {
        return None;
    }

    let group_id = data_msg
        .get("groupInfo")
        .and_then(|g| g.get("groupId"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| SignalCfg::normalize_group_id(s).to_string());
    let reply_target = match &group_id {
        Some(gid) => format!("group:{gid}"),
        None => source_num.unwrap_or(source_any).to_string(),
    };

    let text = data_msg.get("message").and_then(Value::as_str).unwrap_or("").trim().to_string();
    let content = if !text.is_empty() {
        let quote_ts = data_msg.get("quote").and_then(|q| q.get("id")).and_then(Value::as_u64);
        let quote_text = data_msg.get("quote").and_then(|q| q.get("text")).and_then(Value::as_str).map(str::to_string);
        InboundContent::Text { text, quote_ts, quote_text }
    } else if let Some(reaction) = data_msg.get("reaction") {
        let is_remove = reaction.get("isRemove").and_then(Value::as_bool).unwrap_or(false);
        if is_remove {
            return None;
        }
        let emoji = reaction.get("emoji").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if emoji.is_empty() {
            return None;
        }
        InboundContent::Reaction { emoji }
    } else if data_msg.get("attachments").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
        InboundContent::AttachmentOnly
    } else {
        return None;
    };

    Some(ParsedInbound {
        sender: source_num.unwrap_or(source_any).to_string(),
        sender_uuid: source_uuid.map(str::to_string),
        reply_target,
        group_id,
        content,
        is_note_to_self,
    })
}

fn sender_authorized(cfg: &SignalCfg, store: &SentStore, msg: &ParsedInbound) -> bool {
    // Group gate when message arrived in a group (handles normalized raw & `group:` IDs).
    if let Some(gid) = &msg.group_id {
        let norm_gid = SignalCfg::normalize_group_id(gid);
        let allowed_groups = cfg.normalized_allow_groups();
        if !allowed_groups.iter().any(|g| g == norm_gid) {
            return false;
        }
    }

    let mut candidates: Vec<String> = vec![SignalCfg::normalize_signal_id(&msg.sender).to_string()];
    if let Some(u) = &msg.sender_uuid {
        let norm_u = SignalCfg::normalize_signal_id(u).to_string();
        candidates.push(norm_u.clone());
        if let Some(mapped) = store.number_for_uuid(&norm_u) {
            candidates.push(SignalCfg::normalize_signal_id(&mapped).to_string());
        }
    }
    cfg.allow_from.iter().any(|allowed| {
        let a = SignalCfg::normalize_signal_id(allowed);
        !a.is_empty() && a != "*" && candidates.iter().any(|c| c.eq_ignore_ascii_case(a))
    })
}

fn redact_sender(raw: &str) -> String {
    let t = raw.trim();
    let chars: Vec<char> = t.chars().collect();
    if chars.len() <= 6 {
        return "***".to_string();
    }
    if t.starts_with('+') {
        let tail: String = chars[chars.len() - 4..].iter().collect();
        return format!("+…{tail}");
    }
    let head: String = chars[..8.min(chars.len() - 4)].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

async fn handle_envelope(
    client: &SignalClient,
    runtime: &Runtime,
    store: &SentStore,
    health: &SignalHealth,
    raw: &Value,
) {
    let Some(msg) = parse_envelope(client.config(), store, raw) else {
        return;
    };
    if !sender_authorized(client.config(), store, &msg) {
        tracing::warn!(
            sender = %redact_sender(&msg.sender),
            uuid = ?msg.sender_uuid.as_deref().map(redact_sender),
            group = ?msg.group_id,
            "signal: ignoring message from unauthorized sender (check signal.allow_from / signal.allow_groups)"
        );
        return;
    }
    let reply = dispatch_inbound(runtime, store, health, client.config(), &msg).await;
    if let Some(ack_raw) = reply {
        let ack = truncate_chars(&ack_raw, client.config().max_chars);
        store.note_pending_echo(&msg.reply_target, &ack);
        match client.send_message(&msg.reply_target, &ack).await {
            Ok(ts_opt) => {
                health.record_send_ok(ferret_core::now_ms());
                if let Some(ts) = ts_opt {
                    store.note_echo(ts);
                }
            }
            Err(e) => {
                tracing::warn!("signal ack send failed: {e}");
                health.record_error(format!("ack send failed: {e}"));
            }
        }
    }
}

async fn dispatch_inbound(
    runtime: &Runtime,
    store: &SentStore,
    health: &SignalHealth,
    cfg: &SignalCfg,
    msg: &ParsedInbound,
) -> Option<String> {
    let in_group = msg.group_id.is_some();
    let (raw_text, quote_ts, quote_text) = match &msg.content {
        InboundContent::AttachmentOnly => {
            return (!in_group).then(|| {
                "Attachments and voice notes aren't supported over Signal yet — please reply with text.".to_string()
            });
        }
        InboundContent::Reaction { emoji: _ } => {
            return (!in_group).then(|| {
                "Reactions aren't acted on — quote-reply with text (or an option number / \"approve\" / \"deny\")."
                    .to_string()
            });
        }
        InboundContent::Text { text, quote_ts, quote_text } => (text.as_str(), *quote_ts, quote_text.as_deref()),
    };

    let text = raw_text.trim();
    if text.is_empty() {
        return None;
    }

    // 1. Built-in operator slash commands.
    if text.starts_with('/') {
        return Some(handle_slash_command(runtime, store, health, cfg, text).await);
    }

    // 2. Quote-reply to a specific Ferret outbound alert (NEVER fall through to Step 4 on miss).
    if let Some(qts) = quote_ts {
        if let Some(target) = store.lookup(qts).or_else(|| fallback_ref_from_quote_text(quote_text, runtime)) {
            return Some(handle_quoted_reply(runtime, &target, text).await);
        }
        return Some(
            "✗ That quoted message is no longer tracked (expired or not a Ferret alert). Send /inbox or reply `@<id> <text>`."
                .to_string(),
        );
    }

    // 3. Explicit `@<id|#n> <message>` addressing an open inbox item or session.
    if let Some(rest) = text.strip_prefix('@') {
        let mut split = rest.splitn(2, char::is_whitespace);
        let id_token = split.next().unwrap_or("").trim();
        let body = split.next().unwrap_or("").trim();
        if id_token.is_empty() || body.is_empty() {
            return Some(
                "Usage: `@<item_or_session_id> <message>` (or `@#1 <message>` after /inbox or /status).".to_string(),
            );
        }
        return Some(handle_addressed_reply(runtime, store, id_token, body).await);
    }

    // 4. Plain unquoted reply: ignored in groups so casual chatter never hijacks blockers; in DMs
    // routes ONLY when there is a sole open blocking item.
    if in_group {
        return None;
    }
    let inbox = runtime.inbox();
    let blocking: Vec<&InboxEntry> = inbox.iter().filter(|e| e.item.blocking).collect();
    if blocking.len() == 1 {
        let entry = blocking[0];
        return Some(answer_with_options(runtime, entry, text).await);
    }
    if blocking.is_empty() {
        return Some(
            "No blocking inbox item is waiting. Quote-reply to a mission alert, use `@<id> <text>`, or send /inbox or /status."
                .to_string(),
        );
    }

    let alias_ids: Vec<String> = blocking.iter().take(8).map(|e| e.item.item_id.clone()).collect();
    store.set_inbox_aliases(alias_ids);
    let mut out = String::from("Multiple items are waiting — quote-reply to one, or reply `@#1 <answer>`:\n");
    for (idx, e) in blocking.iter().take(8).enumerate() {
        out.push_str(&format!(
            "• #{} ({}) [{}] {} — {}\n",
            idx + 1,
            tail_id(&e.item.item_id),
            inbox_kind_str(e.item.kind),
            e.title,
            truncate_chars(&first_line(&e.item.text), 80)
        ));
    }
    if blocking.len() > 8 {
        out.push_str(&format!("… +{} more (send /inbox)", blocking.len() - 8));
    }
    Some(out.trim_end().to_string())
}

fn fallback_ref_from_quote_text(quote_text: Option<&str>, runtime: &Runtime) -> Option<OutboundRef> {
    let text = quote_text?;
    let item_tok = extract_footer_token(text, "item:");
    let sess_tok = extract_footer_token(text, "session:");

    if let Some(tok) = item_tok {
        let inbox = runtime.inbox();
        let matches: Vec<&InboxEntry> = inbox.iter().filter(|e| id_matches(&e.item.item_id, tok)).collect();
        if matches.len() == 1 {
            let e = matches[0];
            let (_, _, lead) = session_meta_summary(runtime, &e.session);
            return Some(OutboundRef {
                timestamp: 0,
                kind: inbox_kind_str(e.item.kind).to_string(),
                item_id: Some(e.item.item_id.clone()),
                session: e.session.as_str().to_string(),
                title: e.title.clone(),
                options: e.item.options.clone(),
                is_scope_request: is_scope_request(&e.item),
                lead_session: lead.map(|l| l.as_str().to_string()),
            });
        }
    }

    if let Some(tok) = sess_tok {
        let sessions = runtime.sessions(false);
        let matches: Vec<&SessionInfo> = sessions.iter().filter(|s| id_matches(s.meta.id.as_str(), tok)).collect();
        if matches.len() == 1 {
            let s = matches[0];
            let lead = walk_to_root_lead(runtime, &s.meta.id);
            let title = runtime.session(&lead).map(|l| l.meta.title).unwrap_or_else(|| s.meta.title.clone());
            return Some(OutboundRef {
                timestamp: 0,
                kind: "followup".to_string(),
                item_id: None,
                session: s.meta.id.as_str().to_string(),
                title,
                options: Vec::new(),
                is_scope_request: false,
                lead_session: Some(lead.as_str().to_string()),
            });
        }
    }
    None
}

fn extract_footer_token<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    let idx = text.rfind(label)?;
    let rest = text[idx + label.len()..].trim_start();
    let tok =
        rest.split(|c: char| c.is_whitespace() || matches!(c, '·' | ',' | ';' | ')' | ']')).next().unwrap_or("").trim();
    if tok.len() >= 4 {
        Some(tok)
    } else {
        None
    }
}

async fn handle_quoted_reply(runtime: &Runtime, target: &OutboundRef, text: &str) -> String {
    if let Some(item_id) = &target.item_id {
        let inbox = runtime.inbox();
        if let Some(entry) = inbox.iter().find(|e| e.item.item_id == *item_id) {
            if is_scope_request(&entry.item) {
                return handle_scope_reply(runtime, entry, text).await;
            }
            return answer_with_options(runtime, entry, text).await;
        }
    }
    let follow_sid = resolve_lead_session(runtime, target.lead_session.as_deref().unwrap_or(&target.session));
    match runtime.send_message(&follow_sid, text).await {
        Ok(()) => format!("✓ Sent follow-up to {} ({})", target.title, tail_id(follow_sid.as_str())),
        Err(e) => format!("✗ Could not message {} ({}): {e}", target.title, tail_id(follow_sid.as_str())),
    }
}

async fn handle_scope_reply(runtime: &Runtime, entry: &InboxEntry, raw_reply: &str) -> String {
    let reply = raw_reply.trim();
    let lower = reply.to_ascii_lowercase();
    let hosts = &entry.item.options;

    if matches!(lower.as_str(), "deny" | "reject" | "no" | "n" | "dismiss" | "cancel") {
        return match runtime.answer(&entry.item.item_id, "").await {
            Ok(()) => {
                format!("✓ Denied & dismissed scope request [{}] on {}.", tail_id(&entry.item.item_id), entry.title)
            }
            Err(e) => format!("✗ Could not dismiss scope request [{}]: {e}", tail_id(&entry.item.item_id)),
        };
    }

    let selected: Vec<String> = if matches!(lower.as_str(), "approve" | "yes" | "y" | "allow" | "grant" | "all") {
        hosts.clone()
    } else if let Some(chosen) = parse_host_indices(reply, hosts) {
        match chosen {
            Ok(list) => list,
            Err(msg) => return msg,
        }
    } else {
        return format!(
            "✗ Scope request expects \"approve\", host numbers (1..={}), or \"deny\". Requested: {}",
            hosts.len(),
            hosts.join(", ")
        );
    };

    match runtime.grant_scope(&entry.session, &selected, Some("approved via Signal")).await {
        Ok(receipt) => {
            let _ = runtime.answer(&entry.item.item_id, "").await;
            format!("✓ Granted scope on {}: {}", entry.title, receipt.hosts.join(", "))
        }
        Err(e) => format!("✗ Could not grant scope on {}: {e}", entry.title),
    }
}

/// Parse space/comma-separated 1-based host indices like `"1"`, `"1 2"`, `"1, 3"`, or `"#2"`.
/// Returns `None` when the text is not a list of integers (so caller shows usage help).
fn parse_host_indices(reply: &str, hosts: &[String]) -> Option<Result<Vec<String>, String>> {
    let tokens: Vec<&str> = reply
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|t| t.trim().trim_start_matches('#').trim_end_matches(['.', ')']))
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.is_empty() {
        return None;
    }
    let mut parsed = Vec::with_capacity(tokens.len());
    for tok in tokens {
        let Ok(n) = tok.parse::<usize>() else {
            return None;
        };
        parsed.push(n);
    }
    let mut selected = Vec::new();
    for n in parsed {
        if n == 0 || n > hosts.len() {
            return Some(Err(format!(
                "✗ Host number {n} is out of range (1..={}). Requested: {}",
                hosts.len(),
                hosts.join(", ")
            )));
        }
        let h = &hosts[n - 1];
        if !selected.contains(h) {
            selected.push(h.clone());
        }
    }
    Some(Ok(selected))
}

async fn handle_addressed_reply(runtime: &Runtime, store: &SentStore, token: &str, body: &str) -> String {
    let inbox = runtime.inbox();

    // 1. `#N` or numeric alias from `/inbox` or multi-blocker prompt.
    if let Some(n) = parse_alias_index(token) {
        if let Some(item_id) = store.inbox_alias(n) {
            if let Some(entry) = inbox.iter().find(|e| e.item.item_id == item_id) {
                return if is_scope_request(&entry.item) {
                    handle_scope_reply(runtime, entry, body).await
                } else {
                    answer_with_options(runtime, entry, body).await
                };
            }
        }
        if let Some(sess_id) = store.session_alias(n) {
            let sid = SessionId::from(sess_id.as_str());
            if let Some(info) = runtime.session(&sid) {
                return send_session_message(runtime, &info, body).await;
            }
        }
        return format!("✗ Shortcut `{token}` is stale or not set. Send /inbox or /status first.");
    }

    // 2. Open inbox item by exact ID, prefix >= 4, or unique suffix >= 4.
    let item_matches: Vec<&InboxEntry> = inbox.iter().filter(|e| id_matches(&e.item.item_id, token)).collect();
    if item_matches.len() == 1 {
        let entry = item_matches[0];
        return if is_scope_request(&entry.item) {
            handle_scope_reply(runtime, entry, body).await
        } else {
            answer_with_options(runtime, entry, body).await
        };
    }
    if item_matches.len() > 1 {
        return format!("✗ `{token}` matches multiple open inbox items; use `@#N` from /inbox or a longer suffix.");
    }

    // 3. Root session by exact ID, prefix >= 4, unique suffix >= 4, or unique title substring.
    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    match match_root_session(&roots, token) {
        SessionMatch::One(s) => send_session_message(runtime, s, body).await,
        SessionMatch::Many => format!("✗ `{token}` matches multiple sessions; use `@#N` from /status or a longer ID."),
        SessionMatch::None => {
            format!("✗ No open inbox item or session matches `{token}`. Send /inbox or /status.")
        }
    }
}

async fn send_session_message(runtime: &Runtime, info: &SessionInfo, body: &str) -> String {
    match runtime.send_message(&info.meta.id, body).await {
        Ok(()) => format!("✓ Sent message to {} ({})", info.meta.title, tail_id(info.meta.id.as_str())),
        Err(e) => format!("✗ Could not message {}: {e}", tail_id(info.meta.id.as_str())),
    }
}

async fn answer_with_options(runtime: &Runtime, entry: &InboxEntry, raw_reply: &str) -> String {
    match expand_option_strict(raw_reply, &entry.item.options) {
        Ok(expanded) => answer_entry(runtime, entry, &expanded).await,
        Err(err) => err,
    }
}

async fn answer_entry(runtime: &Runtime, entry: &InboxEntry, answer: &str) -> String {
    match runtime.answer(&entry.item.item_id, answer).await {
        Ok(()) => {
            let preview = truncate_chars(&first_line(answer), 60);
            format!(
                "✓ Answered {} [{}] on {} → \"{preview}\"",
                inbox_kind_str(entry.item.kind),
                tail_id(&entry.item.item_id),
                entry.title,
            )
        }
        Err(e) => format!("✗ Could not answer {}: {e}", tail_id(&entry.item.item_id)),
    }
}

async fn handle_slash_command(
    runtime: &Runtime,
    store: &SentStore,
    health: &SignalHealth,
    cfg: &SignalCfg,
    text: &str,
) -> String {
    let mut parts = text.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("").to_ascii_lowercase();
    let arg = parts.next().unwrap_or("").trim();

    match cmd.as_str() {
        "/help" | "/start" => concat!(
            "Ferret Signal commands:\n",
            "• Quote-reply an alert → answers it (or approves/denies scope requests)\n",
            "• Quote-reply a finished/error alert → sends a follow-up to the mission\n",
            "• Plain DM reply (when 1 blocker is open) → answers it directly\n",
            "• @<id|#n> <text> → answer inbox item or message mission\n",
            "• /inbox — list open inbox items (#1..#N)\n",
            "• /status — show running, waiting & stopped missions (#1..#N)\n",
            "• /tail [id|#n] [count] — recent activity for a mission\n",
            "• /scope <id|#n> [host...] — grant requested or named network hosts\n",
            "• /dismiss [id|#n] — dismiss a non-blocking or finished inbox item\n",
            "• /stop [id|#n] — stop a running session\n",
            "• /resume [id|#n] — resume a stopped or parked session\n",
            "• /approve <id|#n> <text> — record an approval on a mission\n",
            "• /rule <id|#n> <text> — add a standing rule to a mission\n",
            "• /release <id|#n> <reason> — close a blocked mission\n",
            "• /mute [15m|2h|off] · /unmute — silence/resume outbound alerts"
        )
        .to_string(),
        "/inbox" => cmd_inbox(runtime, store, cfg.max_chars),
        "/status" => cmd_status(runtime, store, health, cfg.max_chars),
        "/stop" => cmd_stop(runtime, store, arg).await,
        "/resume" => cmd_resume(runtime, store, arg).await,
        "/dismiss" => cmd_dismiss(runtime, store, arg).await,
        "/scope" => cmd_scope(runtime, store, arg).await,
        "/tail" => cmd_tail(runtime, store, arg, cfg.max_chars),
        "/mute" => cmd_mute(store, health, arg),
        "/unmute" => {
            store.set_muted_until(None, health);
            "✓ Signal alerts unmuted.".to_string()
        }
        "/release" => cmd_release(runtime, store, arg).await,
        "/approve" => cmd_approve(runtime, store, arg).await,
        "/rule" => cmd_rule(runtime, store, arg).await,
        _ => format!("Unknown command `{cmd}`. Send /help for options."),
    }
}

fn cmd_inbox(runtime: &Runtime, store: &SentStore, max_chars: usize) -> String {
    let items = runtime.inbox();
    if items.is_empty() {
        store.set_inbox_aliases(Vec::new());
        return "Inbox is empty.".to_string();
    }
    let shown = items.len().min(12);
    store.set_inbox_aliases(items.iter().take(shown).map(|e| e.item.item_id.clone()).collect());
    let mut out = format!("Open inbox items ({}):\n", items.len());
    for (idx, e) in items.iter().take(shown).enumerate() {
        let label = if is_scope_request(&e.item) {
            format!("SCOPE · {} host(s)", e.item.options.len())
        } else {
            let tag = if e.item.blocking { "BLOCKING" } else { "info" };
            let opts =
                if e.item.options.is_empty() { String::new() } else { format!(" · {} opts", e.item.options.len()) };
            format!("{} · {tag}{opts}", inbox_kind_str(e.item.kind))
        };
        let line = format!(
            "• #{} ({}) [{}] {}\n  {}\n",
            idx + 1,
            tail_id(&e.item.item_id),
            label,
            e.title,
            truncate_chars(&first_line(&e.item.text), 110)
        );
        if out.chars().count() + line.chars().count() + 40 > max_chars && idx > 0 {
            out.push_str(&format!("… +{} more", items.len() - idx));
            return out.trim_end().to_string();
        }
        out.push_str(&line);
    }
    if items.len() > shown {
        out.push_str(&format!("… +{} more", items.len() - shown));
    }
    out.trim_end().to_string()
}

fn cmd_status(runtime: &Runtime, store: &SentStore, health: &SignalHealth, max_chars: usize) -> String {
    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    let running_count = roots.iter().filter(|s| s.status.phase == Phase::Running).count();
    let waiting_count = roots.iter().filter(|s| is_waiting_session(s)).count();
    let stopped_count = roots.iter().filter(|s| is_resumable_session(s)).count();
    let open_inbox = runtime.inbox().len();

    let mute_suffix = store.muted_until(ferret_core::now_ms(), health).map(|until| {
        let mins = until.saturating_sub(ferret_core::now_ms()).div_ceil(60_000).max(1);
        format!(" · muted ({mins}m left)")
    });
    let mut out = format!(
        "Ferret status: {running_count} running · {waiting_count} waiting · {stopped_count} stopped · {open_inbox} open inbox · {} total{}",
        roots.len(),
        mute_suffix.unwrap_or_default()
    );

    // Order for operator triage: running first, then waiting/blocked, then stopped/resumable, then
    // recent idle/finished missions.
    let mut ordered: Vec<&SessionInfo> = Vec::with_capacity(roots.len());
    ordered.extend(roots.iter().copied().filter(|s| s.status.phase == Phase::Running));
    ordered.extend(roots.iter().copied().filter(|s| s.status.phase != Phase::Running && is_waiting_session(s)));
    ordered.extend(
        roots
            .iter()
            .copied()
            .filter(|s| s.status.phase != Phase::Running && !is_waiting_session(s) && is_resumable_session(s)),
    );
    ordered.extend(
        roots
            .iter()
            .copied()
            .filter(|s| s.status.phase != Phase::Running && !is_waiting_session(s) && !is_resumable_session(s)),
    );

    let shown = ordered.len().min(12);
    store.set_session_aliases(ordered.iter().take(shown).map(|s| s.meta.id.as_str().to_string()).collect());
    for (idx, s) in ordered.iter().take(shown).enumerate() {
        let state = session_state_badge(s);
        let line = format!("\n• #{} ({}) [{state}] {}", idx + 1, tail_id(s.meta.id.as_str()), s.meta.title);
        if out.chars().count() + line.chars().count() + 24 > max_chars && idx > 0 {
            out.push_str(&format!("\n… +{} more", ordered.len() - idx));
            return out;
        }
        out.push_str(&line);
    }
    if ordered.len() > shown {
        out.push_str(&format!("\n… +{} more", ordered.len() - shown));
    }
    out
}

async fn cmd_stop(runtime: &Runtime, store: &SentStore, arg: &str) -> String {
    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    let sid = if arg.is_empty() {
        let running: Vec<&SessionInfo> = roots.iter().copied().filter(|s| s.status.phase == Phase::Running).collect();
        match running.as_slice() {
            [only] => only.meta.id.clone(),
            [] => return "No running session to stop.".to_string(),
            many => {
                store.set_session_aliases(many.iter().take(8).map(|s| s.meta.id.as_str().to_string()).collect());
                let mut msg = String::from("Multiple sessions are running — send `/stop #1` (or `/stop <id>`):");
                for (i, s) in many.iter().take(8).enumerate() {
                    msg.push_str(&format!("\n• #{} ({}) {}", i + 1, tail_id(s.meta.id.as_str()), s.meta.title));
                }
                return msg;
            }
        }
    } else {
        match resolve_session_token(&roots, store, arg) {
            Ok(s) => s.meta.id.clone(),
            Err(e) => return e,
        }
    };
    match runtime.stop(&sid).await {
        Ok(()) => format!("✓ Stopped {}", tail_id(sid.as_str())),
        Err(e) => format!("✗ Could not stop {}: {e}", tail_id(sid.as_str())),
    }
}

async fn cmd_resume(runtime: &Runtime, store: &SentStore, arg: &str) -> String {
    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    let sid = if arg.is_empty() {
        let resumable: Vec<&SessionInfo> = roots.iter().copied().filter(|s| is_resumable_session(s)).collect();
        match resumable.as_slice() {
            [only] => only.meta.id.clone(),
            [] => return "No stopped or parked session to resume. Send /status to list missions.".to_string(),
            many => {
                store.set_session_aliases(many.iter().take(8).map(|s| s.meta.id.as_str().to_string()).collect());
                let mut msg = String::from("Multiple stopped/parked sessions — send `/resume #1` (or `/resume <id>`):");
                for (i, s) in many.iter().take(8).enumerate() {
                    msg.push_str(&format!(
                        "\n• #{} ({}) [{}] {}",
                        i + 1,
                        tail_id(s.meta.id.as_str()),
                        session_state_badge(s),
                        s.meta.title
                    ));
                }
                return msg;
            }
        }
    } else {
        match resolve_session_token(&roots, store, arg) {
            Ok(s) => s.meta.id.clone(),
            Err(e) => return e,
        }
    };
    match runtime.resume(&sid).await {
        Ok(()) => format!("✓ Resumed {}", tail_id(sid.as_str())),
        Err(e) => format!("✗ Could not resume {}: {e}", tail_id(sid.as_str())),
    }
}

async fn cmd_dismiss(runtime: &Runtime, store: &SentStore, arg: &str) -> String {
    let inbox = runtime.inbox();
    let target = if arg.is_empty() {
        let non_blocking: Vec<&InboxEntry> = inbox.iter().filter(|e| !e.item.blocking).collect();
        match non_blocking.as_slice() {
            [only] => *only,
            [] => {
                return if inbox.is_empty() {
                    "Inbox is empty.".to_string()
                } else {
                    "✗ Only blocking inbox items are open; reply to answer them instead of /dismiss.".to_string()
                };
            }
            many => {
                store.set_inbox_aliases(many.iter().take(8).map(|e| e.item.item_id.clone()).collect());
                let mut msg = String::from("Multiple dismissible items — send `/dismiss #1` (or `/dismiss <id>`):");
                for (i, e) in many.iter().take(8).enumerate() {
                    msg.push_str(&format!(
                        "\n• #{} ({}) [{}] {}",
                        i + 1,
                        tail_id(&e.item.item_id),
                        inbox_kind_str(e.item.kind),
                        e.title
                    ));
                }
                return msg;
            }
        }
    } else {
        match resolve_inbox_token(&inbox, store, arg) {
            Ok(e) => e,
            Err(err) => return err,
        }
    };

    if target.item.blocking {
        return format!(
            "✗ Item [{}] ({}) is blocking and requires an answer, not /dismiss.",
            tail_id(&target.item.item_id),
            target.title
        );
    }
    match runtime.answer(&target.item.item_id, "").await {
        Ok(()) => format!(
            "✓ Dismissed {} [{}] on {}",
            inbox_kind_str(target.item.kind),
            tail_id(&target.item.item_id),
            target.title
        ),
        Err(e) => format!("✗ Could not dismiss {}: {e}", tail_id(&target.item.item_id)),
    }
}

async fn cmd_scope(runtime: &Runtime, store: &SentStore, arg: &str) -> String {
    let tokens: Vec<&str> = arg.split_whitespace().collect();
    if tokens.is_empty() {
        // Convenience: if exactly 1 scope request is open, show how to approve it.
        let scopes: Vec<InboxEntry> = runtime.inbox().into_iter().filter(|e| is_scope_request(&e.item)).collect();
        if let [only] = scopes.as_slice() {
            return format!(
                "Usage: `/scope <session|#n> <host>...`, or `/scope {}` to approve [{}]: {}",
                tail_id(&only.item.item_id),
                only.title,
                only.item.options.join(", ")
            );
        }
        return "Usage: `/scope <session|#n> <host>...` (or `/scope <scope_item_id|#n>`).".to_string();
    }

    // Single token: allow `/scope <item_id|#n>` to grant all hosts of an open scope request.
    if tokens.len() == 1 {
        let inbox = runtime.inbox();
        if let Ok(entry) = resolve_inbox_token(&inbox, store, tokens[0]) {
            if is_scope_request(&entry.item) {
                return handle_scope_reply(runtime, entry, "approve").await;
            }
            return format!(
                "✗ Item [{}] is not a network scope request. Use `/scope <session|#n> <host>...`.",
                tail_id(&entry.item.item_id)
            );
        }
        return "Usage: `/scope <session|#n> <host>...` (provide at least one host, or a scope-request item id)."
            .to_string();
    }

    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    let target = match resolve_session_token(&roots, store, tokens[0]) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let hosts: Vec<String> = tokens[1..].iter().map(|h| h.to_string()).collect();
    match runtime.grant_scope(&target.meta.id, &hosts, Some("granted via Signal")).await {
        Ok(receipt) => format!("✓ Granted scope on {}: {}", target.meta.title, receipt.hosts.join(", ")),
        Err(e) => format!("✗ Could not grant scope on {}: {e}", target.meta.title),
    }
}

fn cmd_tail(runtime: &Runtime, store: &SentStore, arg: &str, max_chars: usize) -> String {
    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    if roots.is_empty() {
        return "No missions yet.".to_string();
    }

    let tokens: Vec<&str> = arg.split_whitespace().collect();
    let (target, count) = match tokens.as_slice() {
        [] => {
            let running: Vec<&SessionInfo> =
                roots.iter().copied().filter(|s| s.status.phase == Phase::Running).collect();
            let chosen = if running.len() == 1 { running[0] } else { roots[0] };
            (chosen, DEFAULT_TAIL_ITEMS)
        }
        [one] => match resolve_session_token(&roots, store, one) {
            Ok(s) => (s, DEFAULT_TAIL_ITEMS),
            Err(e) => return e,
        },
        [one, two, ..] => {
            let s = match resolve_session_token(&roots, store, one) {
                Ok(s) => s,
                Err(e) => return e,
            };
            let n = two.parse::<usize>().ok().unwrap_or(DEFAULT_TAIL_ITEMS).clamp(1, MAX_TAIL_ITEMS);
            (s, n)
        }
    };

    let stored = match runtime.stored_records_before(&target.meta.id, u64::MAX, TAIL_FETCH_LIMIT) {
        Ok(v) => v,
        Err(e) => return format!("✗ Could not read activity for {}: {e}", tail_id(target.meta.id.as_str())),
    };
    let lines: Vec<String> = stored.iter().filter_map(|sr| summarize_record(&sr.record)).collect();
    let mut out = format!(
        "Recent activity for {} ({}) [{}]:",
        target.meta.title,
        tail_id(target.meta.id.as_str()),
        session_state_badge(target)
    );
    if lines.is_empty() {
        out.push_str("\n(no activity recorded yet)");
        return out;
    }
    let start = lines.len().saturating_sub(count);
    for line in &lines[start..] {
        let entry = format!("\n• {line}");
        if out.chars().count() + entry.chars().count() > max_chars {
            break;
        }
        out.push_str(&entry);
    }
    out
}

fn summarize_record(record: &Record) -> Option<String> {
    match &record.event {
        Event::UserMessage { text, .. } => {
            let s = first_line(text);
            (!s.is_empty()).then(|| format!("user: {}", truncate_chars(&s, 100)))
        }
        Event::ModelResponse(r) => {
            let s = first_line(&r.text);
            if !s.is_empty() {
                Some(format!("model: {}", truncate_chars(&s, 110)))
            } else if !r.tool_calls.is_empty() {
                let names: Vec<&str> = r.tool_calls.iter().map(|c| c.name.as_str()).take(3).collect();
                Some(format!("model → tools: {}", names.join(", ")))
            } else {
                None
            }
        }
        Event::ToolResult(r) => {
            let status = match r.status {
                ToolStatus::Ok => "ok",
                ToolStatus::Error => "error",
                ToolStatus::Invalid => "invalid",
                ToolStatus::Denied => "denied",
                ToolStatus::Timeout => "timeout",
                ToolStatus::Interrupted => "interrupted",
            };
            let line = first_line(&r.text);
            if line.is_empty() {
                Some(format!("tool {} [{status}]", r.name))
            } else {
                Some(format!("tool {} [{status}]: {}", r.name, truncate_chars(&line, 90)))
            }
        }
        Event::InboxOpened(item) => {
            Some(format!("inbox [{}]: {}", inbox_kind_str(item.kind), truncate_chars(&first_line(&item.text), 90)))
        }
        Event::InboxResolved { item_id, answer } => {
            if answer.trim().is_empty() {
                Some(format!("inbox dismissed [{}]", tail_id(item_id)))
            } else {
                Some(format!("inbox answered [{}]: {}", tail_id(item_id), truncate_chars(&first_line(answer), 80)))
            }
        }
        Event::Interrupted { reason } => Some(format!("interrupted: {}", truncate_chars(&first_line(reason), 90))),
        Event::TurnEnd { reason } => Some(format!("turn ended: {}", turn_end_word(*reason))),
        Event::SessionEnd { detail, .. } => Some(format!("session ended: {}", truncate_chars(&first_line(detail), 90))),
        _ => None,
    }
}

fn cmd_mute(store: &SentStore, health: &SignalHealth, arg: &str) -> String {
    let trimmed = arg.trim();
    if trimmed.eq_ignore_ascii_case("off") || trimmed == "0" {
        store.set_muted_until(None, health);
        return "✓ Signal alerts unmuted.".to_string();
    }
    let secs = if trimmed.is_empty() {
        DEFAULT_MUTE_SECS
    } else {
        match parse_duration_secs(trimmed) {
            Some(s) => s.clamp(60, MAX_MUTE_SECS),
            None => {
                return format!("✗ Invalid mute duration `{trimmed}`. Examples: `/mute 30m`, `/mute 2h`, `/mute off`.");
            }
        }
    };
    let until = ferret_core::now_ms().saturating_add(secs.saturating_mul(1_000));
    store.set_muted_until(Some(until), health);
    format!("✓ Muted Signal alerts for {}. Send /unmute to resume early.", format_duration_short(secs))
}

fn parse_duration_secs(raw: &str) -> Option<u64> {
    let t = raw.trim().to_ascii_lowercase();
    if t.is_empty() {
        return None;
    }
    if let Some(h) = t.strip_suffix('h') {
        let n = h.trim().parse::<u64>().ok()?;
        return (n > 0).then(|| n.saturating_mul(3600));
    }
    if let Some(m) = t.strip_suffix('m') {
        let n = m.trim().parse::<u64>().ok()?;
        return (n > 0).then(|| n.saturating_mul(60));
    }
    if let Some(s) = t.strip_suffix('s') {
        let n = s.trim().parse::<u64>().ok()?;
        return (n > 0).then_some(n);
    }
    let mins = t.parse::<u64>().ok()?;
    (mins > 0).then(|| mins.saturating_mul(60))
}

fn format_duration_short(secs: u64) -> String {
    if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

async fn cmd_release(runtime: &Runtime, store: &SentStore, arg: &str) -> String {
    let mut split = arg.splitn(2, char::is_whitespace);
    let token = split.next().unwrap_or("").trim();
    let reason = split.next().unwrap_or("").trim();
    if token.is_empty() || reason.is_empty() {
        return "Usage: `/release <session|#n> <reason>`.".to_string();
    }
    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    let target = match resolve_session_token(&roots, store, token) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match runtime.release(&target.meta.id, reason).await {
        Ok(r) => {
            let verb = if r.queued { "queued for" } else { "sent to" };
            format!("✓ Release {verb} {} ({})", target.meta.title, tail_id(target.meta.id.as_str()))
        }
        Err(e) => format!("✗ Could not release {}: {e}", tail_id(target.meta.id.as_str())),
    }
}

async fn cmd_approve(runtime: &Runtime, store: &SentStore, arg: &str) -> String {
    let mut split = arg.splitn(2, char::is_whitespace);
    let token = split.next().unwrap_or("").trim();
    let text = split.next().unwrap_or("").trim();
    if token.is_empty() {
        return "Usage: `/approve <session|#n> <what is approved>` (or `/approve <scope_item|#n>`).".to_string();
    }
    // Convenience: `/approve #1` with no extra text approves an open scope-request item.
    if text.is_empty() {
        let inbox = runtime.inbox();
        if let Ok(entry) = resolve_inbox_token(&inbox, store, token) {
            if is_scope_request(&entry.item) {
                return handle_scope_reply(runtime, entry, "approve").await;
            }
        }
        return "Usage: `/approve <session|#n> <what is approved>`.".to_string();
    }
    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    let target = match resolve_session_token(&roots, store, token) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match runtime.approve(&target.meta.id, text, "").await {
        Ok(r) => {
            let verb = if r.queued { "queued for" } else { "recorded on" };
            format!("✓ Approval {verb} {} ({})", target.meta.title, tail_id(target.meta.id.as_str()))
        }
        Err(e) => format!("✗ Could not approve on {}: {e}", tail_id(target.meta.id.as_str())),
    }
}

async fn cmd_rule(runtime: &Runtime, store: &SentStore, arg: &str) -> String {
    let mut split = arg.splitn(2, char::is_whitespace);
    let token = split.next().unwrap_or("").trim();
    let text = split.next().unwrap_or("").trim();
    if token.is_empty() || text.is_empty() {
        return "Usage: `/rule <session|#n> <standing rule>`.".to_string();
    }
    let sessions = runtime.sessions(false);
    let roots: Vec<&SessionInfo> = sessions.iter().filter(|s| s.meta.parent.is_none()).collect();
    let target = match resolve_session_token(&roots, store, token) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match runtime.add_rule(&target.meta.id, text).await {
        Ok(r) => {
            let verb = if r.queued { "queued for" } else { "recorded on" };
            format!("✓ Rule {verb} {} ({})", target.meta.title, tail_id(target.meta.id.as_str()))
        }
        Err(e) => format!("✗ Could not add rule on {}: {e}", tail_id(target.meta.id.as_str())),
    }
}

enum SessionMatch<'a> {
    One(&'a SessionInfo),
    Many,
    None,
}

fn match_root_session<'a>(roots: &[&'a SessionInfo], token: &str) -> SessionMatch<'a> {
    if token.eq_ignore_ascii_case("last") {
        return roots.first().copied().map_or(SessionMatch::None, SessionMatch::One);
    }
    let id_hits: Vec<&SessionInfo> = roots.iter().copied().filter(|s| id_matches(s.meta.id.as_str(), token)).collect();
    if id_hits.len() == 1 {
        return SessionMatch::One(id_hits[0]);
    }
    if id_hits.len() > 1 {
        return SessionMatch::Many;
    }
    // Fallback: unique case-insensitive mission title substring (at least 3 chars).
    if token.chars().count() >= 3 {
        let needle = token.to_ascii_lowercase();
        let title_hits: Vec<&SessionInfo> =
            roots.iter().copied().filter(|s| s.meta.title.to_ascii_lowercase().contains(&needle)).collect();
        if title_hits.len() == 1 {
            return SessionMatch::One(title_hits[0]);
        }
        if title_hits.len() > 1 {
            return SessionMatch::Many;
        }
    }
    SessionMatch::None
}

fn resolve_session_token<'a>(
    roots: &[&'a SessionInfo],
    store: &SentStore,
    token: &str,
) -> Result<&'a SessionInfo, String> {
    if let Some(n) = parse_alias_index(token) {
        if let Some(id) = store.session_alias(n) {
            if let Some(found) = roots.iter().copied().find(|s| s.meta.id.as_str() == id) {
                return Ok(found);
            }
        }
        return Err(format!("✗ Session shortcut `{token}` is stale or out of range. Send /status first."));
    }
    match match_root_session(roots, token) {
        SessionMatch::One(s) => Ok(s),
        SessionMatch::Many => {
            Err(format!("✗ `{token}` matches multiple sessions; use `#N` from /status or a longer ID."))
        }
        SessionMatch::None => Err(format!("✗ No session matches `{token}`. Send /status to list missions.")),
    }
}

fn resolve_inbox_token<'a>(inbox: &'a [InboxEntry], store: &SentStore, token: &str) -> Result<&'a InboxEntry, String> {
    if let Some(n) = parse_alias_index(token) {
        if let Some(id) = store.inbox_alias(n) {
            if let Some(found) = inbox.iter().find(|e| e.item.item_id == id) {
                return Ok(found);
            }
        }
        return Err(format!("✗ Inbox shortcut `{token}` is stale or out of range. Send /inbox first."));
    }
    let matches: Vec<&InboxEntry> = inbox.iter().filter(|e| id_matches(&e.item.item_id, token)).collect();
    match matches.as_slice() {
        [only] => Ok(*only),
        [] => Err(format!("✗ No open inbox item matches `{token}`. Send /inbox.")),
        _ => Err(format!("✗ `{token}` matches multiple inbox items; use `#N` from /inbox or a longer suffix.")),
    }
}

/// Match an ID by exact equality, prefix (len >= 4), or unique suffix (len >= 4), case-insensitively
/// (tolerating phone auto-capitalization and leading `…` copied from short display).
fn id_matches(full: &str, raw_token: &str) -> bool {
    let tok = raw_token.trim().trim_start_matches('…').trim_start_matches("...");
    if tok.is_empty() {
        return false;
    }
    let full_l = full.to_ascii_lowercase();
    let tok_l = tok.to_ascii_lowercase();
    full_l == tok_l || (tok_l.len() >= 4 && (full_l.starts_with(&tok_l) || full_l.ends_with(&tok_l)))
}

fn parse_alias_index(token: &str) -> Option<usize> {
    let stripped = token.trim().strip_prefix('#').unwrap_or(token.trim());
    let n = stripped.parse::<usize>().ok()?;
    (1..=32).contains(&n).then_some(n)
}

fn is_scope_request(item: &InboxItem) -> bool {
    item.kind == InboxKind::Approval && !item.blocking && !item.options.is_empty()
}

fn is_waiting_session(s: &SessionInfo) -> bool {
    s.status.open_inbox > 0
        || matches!(s.status.last_end, Some(TurnEndReason::Asked | TurnEndReason::Blocked | TurnEndReason::Waiting))
}

fn is_resumable_session(s: &SessionInfo) -> bool {
    s.status.phase == Phase::Idle
        && matches!(
            s.status.last_end,
            Some(
                TurnEndReason::Stopped | TurnEndReason::Parked | TurnEndReason::Error | TurnEndReason::BudgetExhausted
            )
        )
}

fn session_state_badge(s: &SessionInfo) -> String {
    match s.status.phase {
        Phase::Running => format!("running · step {}", s.status.step),
        Phase::Ended => "ended".to_string(),
        Phase::Idle => match s.status.last_end {
            Some(r) => turn_end_word(r).to_string(),
            None => "idle".to_string(),
        },
    }
}

fn turn_end_word(r: TurnEndReason) -> &'static str {
    match r {
        TurnEndReason::Yielded => "yielded",
        TurnEndReason::Finished => "finished",
        TurnEndReason::Asked => "asked",
        TurnEndReason::Blocked => "blocked",
        TurnEndReason::Waiting => "waiting",
        TurnEndReason::Stopped => "stopped",
        TurnEndReason::Parked => "parked",
        TurnEndReason::BudgetExhausted => "budget exhausted",
        TurnEndReason::Error => "error",
    }
}

/// Strict option expansion: accepts `"2"`, `"2."`, `"2)"`, `"#2"`, rejects out-of-range bare
/// integers (e.g. `"0"` or `"9"` when only 2 options exist), and passes custom free-text through.
fn expand_option_strict(reply: &str, options: &[String]) -> Result<String, String> {
    if options.is_empty() {
        return Ok(reply.to_string());
    }
    let candidate = reply.trim().trim_start_matches('#').trim_end_matches(['.', ')']);
    if !candidate.is_empty() && candidate.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(idx) = candidate.parse::<usize>() {
            if idx >= 1 && idx <= options.len() {
                return Ok(options[idx - 1].clone());
            }
            return Err(format!(
                "✗ Option {idx} is out of range (choose 1..={}, or write a custom answer).",
                options.len()
            ));
        }
    }
    Ok(reply.to_string())
}

fn inbox_kind_str(kind: InboxKind) -> &'static str {
    match kind {
        InboxKind::Approval => "approval",
        InboxKind::Question => "question",
        InboxKind::Blocker => "blocker",
        InboxKind::Parked => "parked",
        InboxKind::Finished => "finished",
    }
}

/// Walk `meta.parent` pointers up to the mission root lead (bounded for cycle safety).
fn resolve_root_id(start: &SessionId, parent_of: impl Fn(&SessionId) -> Option<SessionId>) -> SessionId {
    let mut cur = start.clone();
    for _ in 0..8 {
        let Some(parent) = parent_of(&cur) else { break };
        if parent == cur {
            break;
        }
        cur = parent;
    }
    cur
}

fn walk_to_root_lead(runtime: &Runtime, start: &SessionId) -> SessionId {
    resolve_root_id(start, |id| runtime.session(id).and_then(|i| i.meta.parent))
}

/// Returns `(title, is_child, root_lead_session_when_child)`.
fn session_meta_summary(runtime: &Runtime, session: &SessionId) -> (String, bool, Option<SessionId>) {
    match runtime.session(session) {
        Some(info) => {
            let is_child = info.meta.parent.is_some();
            let lead = is_child.then(|| walk_to_root_lead(runtime, session));
            (info.meta.title, is_child, lead)
        }
        None => (session.as_str().to_string(), false, None),
    }
}

fn resolve_lead_session(runtime: &Runtime, raw_session: &str) -> SessionId {
    walk_to_root_lead(runtime, &SessionId::from(raw_session))
}

fn format_inbox_alert(
    kind: &str,
    session: &SessionId,
    title: &str,
    item: &InboxItem,
    max_chars: usize,
    is_reminder: bool,
) -> String {
    let scope_req = is_scope_request(item);
    let kind_badge = if scope_req { "SCOPE APPROVAL".to_string() } else { kind.to_ascii_uppercase() };
    let prefix = if is_reminder { "Ferret · REMINDER · " } else { "Ferret · " };
    let header = format!("[{prefix}{kind_badge}] {title}");
    let footer = format!("item: {} · session: {}", item.item_id, short_id(session.as_str()));

    let hint = if scope_req {
        "Quote-reply \"approve\" (all), host numbers (e.g. \"1 2\"), or \"deny\"."
    } else if item.kind == InboxKind::Finished {
        "Quote-reply to send a follow-up, or /dismiss to clear."
    } else if !item.options.is_empty() {
        "Quote-reply with an option number (1-N) or your answer."
    } else if item.blocking {
        "Quote-reply to answer (or reply directly if sole blocker)."
    } else {
        "Quote-reply to answer, or /dismiss to clear."
    };

    let untrusted = item.call_id.is_some();
    let body_raw = if untrusted {
        format!("[From the agent, unverified] {}", item.text.trim())
    } else {
        item.text.trim().to_string()
    };

    // Build options/hosts block, capping per-option length if `max_chars` is tight.
    let options_block = if item.options.is_empty() {
        String::new()
    } else {
        let heading = if scope_req { "Requested hosts:" } else { "Options:" };
        let max_opt_block = max_chars / 2;
        let mut block = String::from(heading);
        let per_opt_cap = (max_opt_block / item.options.len().max(1)).clamp(24, 180);
        for (i, opt) in item.options.iter().enumerate() {
            let line = format!("\n  {}. {}", i + 1, truncate_chars(opt.trim(), per_opt_block_line(per_opt_cap)));
            if block.chars().count() + line.chars().count() > max_opt_block && i > 0 {
                block.push_str(&format!("\n  … +{} more", item.options.len() - i));
                break;
            }
            block.push_str(&line);
        }
        block
    };

    // Lock-screen friendly layout: header + body first, then options/hint, then metadata footer.
    let sep_options = if options_block.is_empty() { 0 } else { 2 };
    let overhead = header.chars().count()
        + 1 // \n after header
        + sep_options
        + options_block.chars().count()
        + 2 // \n\n before hint
        + hint.chars().count()
        + 1 // \n before footer
        + footer.chars().count();

    let body_budget = max_chars.saturating_sub(overhead);
    let mut out = String::new();
    out.push_str(&header);
    if body_budget >= 20 {
        out.push('\n');
        out.push_str(&truncate_chars(&body_raw, body_budget));
    }
    if !options_block.is_empty() {
        out.push_str("\n\n");
        out.push_str(&options_block);
    }
    out.push_str("\n\n");
    out.push_str(hint);
    out.push('\n');
    out.push_str(&footer);

    if out.chars().count() <= max_chars {
        out
    } else {
        truncate_chars(&out, max_chars)
    }
}

fn per_opt_block_line(cap: usize) -> usize {
    cap.saturating_sub(6).max(16)
}

fn format_error_alert(session: &str, title: &str, message: &str, max_chars: usize) -> String {
    let header = format!("[Ferret · ERROR] {title}");
    let footer = format!("session: {}", short_id(session));
    let overhead = header.chars().count() + 1 + 2 + footer.chars().count();
    let budget = max_chars.saturating_sub(overhead);
    let mut out = header;
    if budget >= 16 {
        out.push('\n');
        out.push_str(&truncate_chars(message.trim(), budget));
    }
    out.push_str("\n\n");
    out.push_str(&footer);
    if out.chars().count() <= max_chars {
        out
    } else {
        truncate_chars(&out, max_chars)
    }
}

fn format_error_burst(entries: &[(String, String, String)], max_chars: usize) -> String {
    let mut out = format!("[Ferret · ERROR ({} alerts)]", entries.len());
    for (idx, (sid, title, msg)) in entries.iter().enumerate() {
        let line = format!("\n• {} ({}): {}", title, tail_id(sid), truncate_chars(&first_line(msg), 120));
        if out.chars().count() + line.chars().count() + 20 > max_chars && idx > 0 {
            out.push_str(&format!("\n… +{} more", entries.len() - idx));
            break;
        }
        out.push_str(&line);
    }
    truncate_chars(&out, max_chars)
}

fn format_notice_alert(kind: &str, title: &str, text: &str, max_chars: usize) -> String {
    let header = format!("[Ferret · {}] {title}", kind.to_ascii_uppercase());
    let overhead = header.chars().count() + 1;
    let budget = max_chars.saturating_sub(overhead);
    if budget >= 16 {
        let body = truncate_chars(text.trim(), budget);
        truncate_chars(&format!("{header}\n{body}"), max_chars)
    } else {
        truncate_chars(&header, max_chars)
    }
}

fn short_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

/// Compact mobile-friendly ID suffix: the last 6 random Crockford characters (preceded by `…`) so
/// concurrent time-prefixed IDs stay visually distinct on phones.
fn tail_id(id: &str) -> String {
    if id.len() <= 10 || !id.is_ascii() {
        return id.to_string();
    }
    format!("…{}", &id[id.len() - 6..])
}

fn first_line(s: &str) -> String {
    s.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").to_string()
}

fn truncate_chars(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::Router;
    use ferret_agent::runtime::NewSession;
    use ferret_core::config::{Config, ModelProfile, NetworkMode, Paths, SandboxMode};
    use ferret_core::event::Budget;
    use ferret_model::mock::{MockServer, Reply, Script};
    use std::collections::BTreeMap;

    fn sample_cfg(url: &str) -> SignalCfg {
        SignalCfg {
            enabled: true,
            http_url: url.to_string(),
            account: "+15550100".to_string(),
            recipient: "+15550199".to_string(),
            allow_from: vec!["+15550199".to_string()],
            allow_groups: Vec::new(),
            events: SignalCfg::default().events,
            max_chars: 3500,
        }
    }

    fn text_inbound(text: &str, quote_ts: Option<u64>, quote_text: Option<&str>, group: Option<&str>) -> ParsedInbound {
        ParsedInbound {
            sender: "+15550199".to_string(),
            sender_uuid: None,
            reply_target: group.map_or_else(|| "+15550199".to_string(), |g| format!("group:{g}")),
            group_id: group.map(str::to_string),
            content: InboundContent::Text {
                text: text.to_string(),
                quote_ts,
                quote_text: quote_text.map(str::to_string),
            },
            is_note_to_self: false,
        }
    }

    struct TestRuntime {
        _dir: tempfile::TempDir,
        _server: MockServer,
        ws: PathBuf,
        rt: Runtime,
    }

    async fn start_test_runtime(script: Script) -> TestRuntime {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let server = MockServer::start(script).await.unwrap();
        let mut config = Config::default();
        config.models.clear();
        config.models.insert(
            "mock".into(),
            ModelProfile {
                base_url: server.base_url(),
                model: "mock".into(),
                context_window: Some(1_000_000),
                retry_window_s: 1,
                retry_max_delay_s: 1,
                stall_timeout_s: 30,
                ..ModelProfile::default()
            },
        );
        config.default_model = "mock".into();
        config.sandbox.mode = SandboxMode::None;
        config.network.mode = NetworkMode::DenyAll;
        config.network.capture_max_exchanges = 0;
        config.agents.verify_finish = false;
        config.tools.kill_grace_s = 1;
        let paths = Paths::at(dir.path().join("home"));
        let rt = Runtime::start(config, paths).await.unwrap();
        TestRuntime { _dir: dir, _server: server, ws, rt }
    }

    fn new_session(ws: &Path, role: &str, title: &str, message: &str) -> NewSession {
        NewSession {
            workspace: ws.to_path_buf(),
            pack: None,
            role: Some(role.to_string()),
            model: None,
            title: Some(title.to_string()),
            unattended: Some(false),
            budget: Budget::default(),
            message: Some(message.to_string()),
            prior: Vec::new(),
            role_models: BTreeMap::new(),
            create_workspace: false,
            attachments: Vec::new(),
            target: None,
            creds: None,
            intercept: None,
        }
    }

    async fn wait_for<F: Fn() -> bool>(cond: F) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        panic!("condition did not become true within timeout");
    }

    #[test]
    fn envelope_parsing_pnp_authorization_pre_send_echo_and_attachments() {
        let dir = tempfile::tempdir().unwrap();
        let store = SentStore::open(dir.path().join("signal_sent.json"));
        let mut cfg = sample_cfg("http://127.0.0.1:1337");
        cfg.allow_from = vec![
            "+15550199".to_string(),
            "u:00000000-0000-4000-8000-000000000001".to_string(),
            "PNI:11111111-2222-3333-4444-555555555555".to_string(),
        ];
        cfg.allow_groups = vec!["group:grpABC==".to_string()];

        // Authorized DM with quote-reply (including quote.text capture)
        let dm = json!({
            "envelope": {
                "sourceNumber": "+15550199",
                "sourceUuid": "uuid-owner-1",
                "dataMessage": {
                    "message": "2.",
                    "quote": { "id": 1700000000123u64, "text": "[Ferret · QUESTION] Audit\nitem: i-abc · session: s-123" }
                }
            }
        });
        let parsed = parse_envelope(&cfg, &store, &dm).unwrap();
        assert_eq!(parsed.sender, "+15550199");
        assert!(matches!(
            &parsed.content,
            InboundContent::Text { text, quote_ts: Some(1700000000123), quote_text: Some(_) } if text == "2."
        ));
        assert!(sender_authorized(&cfg, &store, &parsed));

        // UUID-only PNP message matching remembered number AND normalized `u:` / `PNI:` entries
        for uuid in ["uuid-owner-1", "00000000-0000-4000-8000-000000000001", "11111111-2222-3333-4444-555555555555"] {
            let uuid_only = json!({
                "envelope": {
                    "sourceUuid": uuid,
                    "dataMessage": { "message": "/status" }
                }
            });
            let parsed_uuid = parse_envelope(&cfg, &store, &uuid_only).unwrap();
            assert!(sender_authorized(&cfg, &store, &parsed_uuid), "failed for uuid {uuid}");
        }

        // Group allowlist accepts normalized `group:` prefix
        let grp_msg = json!({
            "envelope": {
                "sourceNumber": "+15550199",
                "dataMessage": {
                    "message": "/inbox",
                    "groupInfo": { "groupId": "grpABC==" }
                }
            }
        });
        let parsed_grp = parse_envelope(&cfg, &store, &grp_msg).unwrap();
        assert!(sender_authorized(&cfg, &store, &parsed_grp));

        // Stranger DM is rejected
        let stranger = json!({
            "envelope": {
                "sourceNumber": "+15550188",
                "dataMessage": { "message": "rm -rf /" }
            }
        });
        let parsed_stranger = parse_envelope(&cfg, &store, &stranger).unwrap();
        assert!(!sender_authorized(&cfg, &store, &parsed_stranger));

        // Pre-send Note-to-Self echo suppression BEFORE `note_echo(ts)` is called (SSE-wins race!)
        store.note_pending_echo("+15550100", "Custom outbound text without prefix");
        let early_echo = json!({
            "envelope": {
                "sourceNumber": "+15550100",
                "syncMessage": {
                    "sentMessage": {
                        "destinationNumber": "+15550100",
                        "timestamp": 1700000000888u64,
                        "message": "Custom outbound text without prefix"
                    }
                }
            }
        });
        assert!(parse_envelope(&cfg, &store, &early_echo).is_none());

        // CLI `ferret signal test` Note-to-Self echo suppression (even though daemon never sent it)
        let cli_test_echo = json!({
            "envelope": {
                "sourceNumber": "+15550100",
                "syncMessage": {
                    "sentMessage": {
                        "destinationNumber": "+15550100",
                        "timestamp": 1700000000777u64,
                        "message": "[Ferret · TEST] Signal bridge connected."
                    }
                }
            }
        });
        assert!(parse_envelope(&cfg, &store, &cli_test_echo).is_none());

        // Persisted OutboundRef also suppresses Note-to-Self echo after restart
        store.record_outbound(OutboundRef {
            timestamp: 1700000000123,
            kind: "question".into(),
            item_id: Some("i-abc".into()),
            session: "s-123".into(),
            title: "Audit".into(),
            options: vec!["staging".into(), "prod".into()],
            is_scope_request: false,
            lead_session: None,
        });
        let reloaded = SentStore::open(dir.path().join("signal_sent.json"));
        let post_restart_echo = json!({
            "envelope": {
                "sourceNumber": "+15550100",
                "syncMessage": {
                    "sentMessage": {
                        "destinationNumber": "+15550100",
                        "timestamp": 1700000000123u64,
                        "message": "replayed body"
                    }
                }
            }
        });
        assert!(parse_envelope(&cfg, &reloaded, &post_restart_echo).is_none());

        // Attachment-only and reaction envelopes parse into distinct kinds instead of vanishing
        let att = json!({
            "envelope": {
                "sourceNumber": "+15550199",
                "dataMessage": { "attachments": [{ "contentType": "image/png" }] }
            }
        });
        assert_eq!(parse_envelope(&cfg, &store, &att).unwrap().content, InboundContent::AttachmentOnly);

        let react = json!({
            "envelope": {
                "sourceNumber": "+15550199",
                "dataMessage": { "reaction": { "emoji": "👍", "isRemove": false } }
            }
        });
        assert_eq!(
            parse_envelope(&cfg, &store, &react).unwrap().content,
            InboundContent::Reaction { emoji: "👍".into() }
        );
    }

    #[test]
    fn option_expansion_and_alert_formatting_respect_bounds_and_footer_layout() {
        let opts = vec!["staging".to_string(), "prod".to_string()];
        assert_eq!(expand_option_strict("2", &opts).unwrap(), "prod");
        assert_eq!(expand_option_strict("2.", &opts).unwrap(), "prod");
        assert_eq!(expand_option_strict("2)", &opts).unwrap(), "prod");
        assert_eq!(expand_option_strict("#1", &opts).unwrap(), "staging");
        assert_eq!(expand_option_strict("custom answer", &opts).unwrap(), "custom answer");
        assert!(expand_option_strict("0", &opts).unwrap_err().contains("out of range"));
        assert!(expand_option_strict("9", &opts).unwrap_err().contains("out of range"));

        // Lock-screen layout: body appears on line 2 BEFORE item/session metadata footer
        let item = InboxItem {
            item_id: "i-019a2b3c4d5e6f7g".into(),
            kind: InboxKind::Question,
            text: "Deploy to staging now?".into(),
            options: opts.clone(),
            blocking: true,
            call_id: None,
            reference: None,
        };
        let rendered =
            format_inbox_alert("question", &SessionId::from("s-019a2b3c4d5e6f7g"), "Release", &item, 220, false);
        assert!(rendered.chars().count() <= 220, "exceeded max_chars: {}", rendered.chars().count());
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], "[Ferret · QUESTION] Release");
        assert!(lines[1].contains("Deploy to staging now?"), "body should be on line 2: {rendered}");
        assert!(lines.last().unwrap().starts_with("item: i-019a2b3c4d5e6f7g"), "footer should be last: {rendered}");

        // Scope request renders Requested hosts instead of Options
        let scope_item = InboxItem {
            item_id: "i-scope1234567890".into(),
            kind: InboxKind::Approval,
            text: "Scope request: need api.example.test".into(),
            options: vec!["api.example.test".into(), "cdn.example.test".into()],
            blocking: false,
            call_id: Some(ferret_core::CallId::from("c1")),
            reference: None,
        };
        let scope_rendered =
            format_inbox_alert("approval", &SessionId::from("s-019a2b3c4d5e6f7g"), "Audit", &scope_item, 600, false);
        assert!(scope_rendered.contains("[Ferret · SCOPE APPROVAL] Audit"), "{scope_rendered}");
        assert!(scope_rendered.contains("Requested hosts:"), "{scope_rendered}");
        assert!(!scope_rendered.contains("Options:"), "{scope_rendered}");
        assert!(scope_rendered.contains("\"approve\""), "{scope_rendered}");
    }

    #[test]
    fn sse_decoder_preserves_multibyte_utf8_across_single_byte_splits_and_multiline_data() {
        let mut dec = SseDecoder::default();
        let payload = "event: receive\ndata: {\"msg\":\"🚀 café — ‘ok’\"}\n\ndata: line1\ndata: line2\n\n";
        let mut out = Vec::new();
        for b in payload.as_bytes() {
            out.extend(dec.push(&[*b]));
        }
        out.extend(dec.flush());
        assert_eq!(out, vec!["{\"msg\":\"🚀 café — ‘ok’\"}", "line1\nline2"]);
    }

    #[tokio::test]
    async fn signal_client_check_list_accounts_and_untrusted_identity_remediation() {
        let received = Arc::new(Mutex::new(Vec::<Value>::new()));
        let rec_clone = received.clone();
        let app = Router::new().route("/api/v1/check", get(|| async { axum::http::StatusCode::OK })).route(
            "/api/v1/rpc",
            post(move |axum::Json(body): axum::Json<Value>| {
                let rec = rec_clone.clone();
                async move {
                    rec.lock().unwrap().push(body.clone());
                    match body["method"].as_str() {
                        Some("listAccounts") => axum::Json(json!({
                            "jsonrpc": "2.0",
                            "result": [{ "number": "+15550100" }],
                            "id": "1"
                        })),
                        Some("send") if body["params"]["message"] == "trigger-untrusted" => axum::Json(json!({
                            "jsonrpc": "2.0",
                            "result": {
                                "timestamp": 1764280000112u64,
                                "results": [{
                                    "type": "UNTRUSTED_IDENTITY",
                                    "recipientAddress": { "number": "+15550199" }
                                }]
                            },
                            "id": "2"
                        })),
                        _ => axum::Json(json!({
                            "jsonrpc": "2.0",
                            "result": { "timestamp": 1764280000111u64, "results": [{ "type": "SUCCESS" }] },
                            "id": "3"
                        })),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = SignalClient::new(sample_cfg(&format!("http://{addr}"))).unwrap();
        let report = client.check().await.unwrap();
        assert!(report.reachable);
        assert_eq!(report.account_registered, Some(true));
        assert!(report.warnings.is_empty());

        let ts = client.send_default("hello from ferret").await.unwrap();
        assert_eq!(ts, Some(1764280000111));

        // UNTRUSTED_IDENTITY gives actionable `signal-cli trust` command
        let err = client.send_default("trigger-untrusted").await.unwrap_err();
        assert!(err.contains("UNTRUSTED_IDENTITY"), "{err}");
        assert!(err.contains("signal-cli -a +15550100 trust -a +15550199"), "{err}");

        // Wrong account fails `check()` loudly when `listAccounts` omits it
        let mut wrong_acct = sample_cfg(&format!("http://{addr}"));
        wrong_acct.account = "+15550177".into();
        let bad_client = SignalClient::new(wrong_acct).unwrap();
        let err = bad_client.check().await.unwrap_err();
        assert!(err.contains("+15550177") && err.contains("not loaded"), "{err}");

        // `u:<uuid>` recipient is normalized to bare UUID for signal-cli RPC
        let mut uuid_cfg = sample_cfg(&format!("http://{addr}"));
        uuid_cfg.recipient = "u:00000000-0000-4000-8000-000000000001".into();
        uuid_cfg.allow_from = vec!["+15550199".into()];
        let uuid_client = SignalClient::new(uuid_cfg).unwrap();
        let warn_report = uuid_client.check().await.unwrap();
        assert!(!warn_report.warnings.is_empty(), "expected allow_from mismatch warning");
        uuid_client.send_default("ping").await.unwrap();
        let last = received.lock().unwrap().last().cloned().unwrap();
        assert_eq!(last["params"]["recipient"][0], "00000000-0000-4000-8000-000000000001");
    }

    #[tokio::test]
    async fn scope_approval_unmatched_quote_guard_shortcuts_and_slash_commands() {
        let script = Script::new(|_, step| match step {
            // Turn 0 (session 1): request_scope
            0 => {
                Reply::tool("request_scope", r#"{"hosts":["api.example.test","cdn.example.test"],"why":"Fetch docs"}"#)
                    .into()
            }
            // Turn 1 (session 1): ask blocking question with options
            1 => Reply::tool(
                "ask_user",
                r#"{"question":"Pick environment","options":["staging","prod"],"blocking":true}"#,
            )
            .into(),
            _ => Reply::text("done").into(),
        });
        let env = start_test_runtime(script).await;
        let dir = tempfile::tempdir().unwrap();
        let store = SentStore::open(dir.path().join("signal_sent.json"));
        let cfg = sample_cfg("http://127.0.0.1:1337");
        let health = SignalHealth::from_config(&cfg);

        let info = env.rt.create_session(new_session(&env.ws, "lead", "Alpha Mission", "start")).await.unwrap();
        // Wait for both scope approval item and blocking question to open
        wait_for(|| env.rt.inbox().len() >= 2).await;

        let inbox = env.rt.inbox();
        let scope_entry = inbox.iter().find(|e| is_scope_request(&e.item)).expect("scope request").clone();
        let q_entry = inbox.iter().find(|e| e.item.blocking).expect("blocking question").clone();

        // Record only the scope alert in SentStore
        store.record_outbound(OutboundRef {
            timestamp: 1001,
            kind: "approval".into(),
            item_id: Some(scope_entry.item.item_id.clone()),
            session: info.meta.id.as_str().into(),
            title: info.meta.title.clone(),
            options: scope_entry.item.options.clone(),
            is_scope_request: true,
            lead_session: None,
        });

        // 1. Unmatched quote-reply MUST NOT fall through and answer the blocking question!
        let bad_quote = text_inbound("yes", Some(999999), Some("unrelated old chat"), None);
        let reply = dispatch_inbound(&env.rt, &store, &health, &cfg, &bad_quote).await.unwrap();
        assert!(reply.contains("no longer tracked"), "{reply}");
        assert!(env.rt.inbox().iter().any(|e| e.item.item_id == q_entry.item.item_id), "blocker must stay open!");

        // 2. Fallback quote-reply via `quote.text` footer resolves even when ts isn't in SentStore
        let fallback_text =
            format!("[Ferret · SCOPE APPROVAL] Alpha\nitem: {} · session: {}", scope_entry.item.item_id, info.meta.id);
        let partial_grant = text_inbound("1", Some(888888), Some(&fallback_text), None);
        let reply = dispatch_inbound(&env.rt, &store, &health, &cfg, &partial_grant).await.unwrap();
        assert!(reply.contains("✓ Granted scope on Alpha Mission: api.example.test"), "{reply}");
        wait_for(|| !env.rt.inbox().iter().any(|e| e.item.item_id == scope_entry.item.item_id)).await;

        // 3. Bare `@<id>` returns usage hint instead of answering the sole open blocker
        let bare_at = text_inbound("@s-1234", None, None, None);
        let reply = dispatch_inbound(&env.rt, &store, &health, &cfg, &bare_at).await.unwrap();
        assert!(reply.starts_with("Usage: `@"), "{reply}");
        assert!(env.rt.inbox().iter().any(|e| e.item.item_id == q_entry.item.item_id));

        // 4. Group unquoted chatter is ignored silently (does NOT answer blocker or spam)
        let grp_chat = text_inbound("hey team what's for lunch", None, None, Some("grp1"));
        assert!(dispatch_inbound(&env.rt, &store, &health, &cfg, &grp_chat).await.is_none());
        assert!(env.rt.inbox().iter().any(|e| e.item.item_id == q_entry.item.item_id));

        // 5. `/inbox` assigns `#1`, and `@#1 2.` expands option #2 and echoes resolved text
        let inbox_out =
            dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("/inbox", None, None, None)).await.unwrap();
        assert!(inbox_out.contains("#1"), "{inbox_out}");
        let ans_out =
            dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("@#1 2.", None, None, None)).await.unwrap();
        assert!(ans_out.contains("✓ Answered question") && ans_out.contains("→ \"prod\""), "{ans_out}");
        wait_for(|| !env.rt.inbox().iter().any(|e| e.item.item_id == q_entry.item.item_id)).await;

        // 6. `/status` lists non-running sessions with `#1`; `/tail #1` returns recent activity;
        // `/mute 15m` updates SignalHealth; `/unmute` clears it; `/approve`, `/rule`, `/release` work
        let status_out =
            dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("/status", None, None, None)).await.unwrap();
        assert!(status_out.contains("#1") && status_out.contains("Alpha Mission"), "{status_out}");

        let tail_out = dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("/tail #1", None, None, None))
            .await
            .unwrap();
        assert!(tail_out.contains("Recent activity for Alpha Mission"), "{tail_out}");

        let mute_out = dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("/mute 15m", None, None, None))
            .await
            .unwrap();
        assert!(mute_out.contains("Muted Signal alerts for 15m"), "{mute_out}");
        assert!(health.snapshot().muted_until_ms.is_some());

        let unmute_out =
            dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("/unmute", None, None, None)).await.unwrap();
        assert!(unmute_out.contains("unmuted"), "{unmute_out}");
        assert!(health.snapshot().muted_until_ms.is_none());

        // Suffix matching on `/rule`, `/approve`, and `/release`
        let suffix = &info.meta.id.as_str()[info.meta.id.as_str().len() - 6..];
        let rule_out = dispatch_inbound(
            &env.rt,
            &store,
            &health,
            &cfg,
            &text_inbound(&format!("/rule {suffix} stay read-only"), None, None, None),
        )
        .await
        .unwrap();
        assert!(rule_out.contains("✓ Rule"), "{rule_out}");

        let approve_out = dispatch_inbound(
            &env.rt,
            &store,
            &health,
            &cfg,
            &text_inbound("/approve #1 deploy staging", None, None, None),
        )
        .await
        .unwrap();
        assert!(approve_out.contains("✓ Approval"), "{approve_out}");

        let release_out = dispatch_inbound(
            &env.rt,
            &store,
            &health,
            &cfg,
            &text_inbound("/release #1 target unavailable", None, None, None),
        )
        .await
        .unwrap();
        assert!(release_out.contains("✓ Release"), "{release_out}");

        // Bare `/resume` does NOT blindly resume a non-stopped mission
        let resume_none =
            dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("/resume", None, None, None)).await.unwrap();
        assert!(resume_none.contains("No stopped or parked session"), "{resume_none}");

        // `/scope <session> <host>` grants explicit hosts directly
        let explicit_scope = dispatch_inbound(
            &env.rt,
            &store,
            &health,
            &cfg,
            &text_inbound("/scope #1 docs.example.test", None, None, None),
        )
        .await
        .unwrap();
        assert!(explicit_scope.contains("✓ Granted scope on Alpha Mission: docs.example.test"), "{explicit_scope}");

        // Corrupt `signal_sent.json` recovers cleanly without panicking
        let corrupt_path = dir.path().join("corrupt_sent.json");
        std::fs::write(&corrupt_path, b"{not valid json").unwrap();
        let recovered = SentStore::open(corrupt_path);
        assert!(recovered.lookup(1).is_none());

        env.rt.shutdown().await;
    }

    #[tokio::test]
    async fn scope_deny_dismiss_and_safe_stop_resume_flows() {
        let script = Script::new(|_, step| match step {
            0 => Reply::tool("request_scope", r#"{"hosts":["blocked.example.test"],"why":"Test deny"}"#).into(),
            _ => Reply::text("finished reply").into(),
        });
        let env = start_test_runtime(script).await;
        let dir = tempfile::tempdir().unwrap();
        let store = SentStore::open(dir.path().join("signal_sent.json"));
        let cfg = sample_cfg("http://127.0.0.1:1337");
        let health = SignalHealth::from_config(&cfg);

        let info = env.rt.create_session(new_session(&env.ws, "lead", "Beta Mission", "go")).await.unwrap();
        wait_for(|| env.rt.inbox().iter().any(|e| is_scope_request(&e.item))).await;
        let scope_entry = env.rt.inbox().into_iter().find(|e| is_scope_request(&e.item)).unwrap();

        // Quote-reply `"deny"` dismisses scope request without granting scope
        store.record_outbound(OutboundRef {
            timestamp: 2002,
            kind: "approval".into(),
            item_id: Some(scope_entry.item.item_id.clone()),
            session: info.meta.id.as_str().into(),
            title: info.meta.title.clone(),
            options: scope_entry.item.options.clone(),
            is_scope_request: true,
            lead_session: None,
        });
        let deny_out = dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("deny", Some(2002), None, None))
            .await
            .unwrap();
        assert!(deny_out.contains("✓ Denied & dismissed scope request"), "{deny_out}");
        wait_for(|| !env.rt.inbox().iter().any(|e| e.item.item_id == scope_entry.item.item_id)).await;

        // Wait for turn to settle, then `/dismiss` clears any remaining non-blocking item cleanly
        let dismiss_out = dispatch_inbound(&env.rt, &store, &health, &cfg, &text_inbound("/dismiss", None, None, None))
            .await
            .unwrap();
        assert!(dismiss_out.contains("✓ Dismissed") || dismiss_out.contains("Inbox is empty."), "{dismiss_out}");

        // Attachment and reaction DMs get helpful hints (while groups stay silent)
        let att_dm = ParsedInbound {
            sender: "+15550199".into(),
            sender_uuid: None,
            reply_target: "+15550199".into(),
            group_id: None,
            content: InboundContent::AttachmentOnly,
            is_note_to_self: false,
        };
        let att_reply = dispatch_inbound(&env.rt, &store, &health, &cfg, &att_dm).await.unwrap();
        assert!(att_reply.contains("Attachments and voice notes"), "{att_reply}");

        let att_grp = ParsedInbound { group_id: Some("grp1".into()), ..att_dm };
        assert!(dispatch_inbound(&env.rt, &store, &health, &cfg, &att_grp).await.is_none());

        env.rt.shutdown().await;
    }

    #[tokio::test]
    async fn spawn_bridge_updates_sse_health_and_retries_transient_sends() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_clone = attempts.clone();
        let sent_msgs = Arc::new(Mutex::new(Vec::<String>::new()));
        let sent_clone = sent_msgs.clone();

        let app = Router::new()
            .route(
                "/api/v1/events",
                get(|| async {
                    let body = concat!(
                        "event: receive\n",
                        "data: {\"envelope\":{\"sourceNumber\":\"+15550199\",\"dataMessage\":{\"message\":\"/status\"}}}\n\n"
                    );
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                        body,
                    )
                }),
            )
            .route(
                "/api/v1/rpc",
                post(move |axum::Json(body): axum::Json<Value>| {
                    let attempts = attempts_clone.clone();
                    let sent = sent_clone.clone();
                    async move {
                        match body["method"].as_str() {
                            Some("listContacts") => axum::Json(json!({ "jsonrpc": "2.0", "result": [], "id": "c" })),
                            Some("send") => {
                                let n = attempts.fetch_add(1, Ordering::SeqCst);
                                if let Some(m) = body["params"]["message"].as_str() {
                                    sent.lock().unwrap().push(m.to_string());
                                }
                                // Fail first send with transient NETWORK_FAILURE? No, ack sends don't retry;
                                // keep mock returning SUCCESS here for the SSE `/status` ack.
                                let _ = n;
                                axum::Json(json!({
                                    "jsonrpc": "2.0",
                                    "result": { "timestamp": 1764280000900u64, "results": [{ "type": "SUCCESS" }] },
                                    "id": "s"
                                }))
                            }
                            _ => axum::Json(json!({ "jsonrpc": "2.0", "result": {}, "id": "x" })),
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let env = start_test_runtime(Script::new(|_, _| Reply::text("ok").into())).await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = sample_cfg(&format!("http://{addr}"));
        let health = Arc::new(SignalHealth::from_config(&cfg));
        let shutdown = CancellationToken::new();

        let handle = spawn_bridge(
            cfg.clone(),
            env.rt.clone(),
            dir.path().join("signal_sent.json"),
            health.clone(),
            shutdown.clone(),
        )
        .expect("bridge spawned");

        wait_for(|| !sent_msgs.lock().unwrap().is_empty()).await;
        let snap = health.snapshot();
        assert!(snap.last_event_ms.is_some(), "expected SSE event timestamp in health: {snap:?}");
        assert!(snap.last_send_ms.is_some(), "expected send timestamp in health: {snap:?}");
        assert!(
            sent_msgs.lock().unwrap().iter().any(|m| m.starts_with("Ferret status:")),
            "expected /status ack: {:?}",
            sent_msgs.lock().unwrap()
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(3), handle).await;

        // Verify transient retry recovers on attempt 2 while permanent UNTRUSTED_IDENTITY fails fast
        let retry_calls = Arc::new(AtomicUsize::new(0));
        let rc = retry_calls.clone();
        let retry_app = Router::new().route(
            "/api/v1/rpc",
            post(move |axum::Json(body): axum::Json<Value>| {
                let rc = rc.clone();
                async move {
                    let msg = body["params"]["message"].as_str().unwrap_or("");
                    let n = rc.fetch_add(1, Ordering::SeqCst);
                    if msg == "permanent" {
                        return axum::Json(json!({
                            "jsonrpc": "2.0",
                            "result": { "timestamp": 1, "results": [{ "type": "UNTRUSTED_IDENTITY" }] },
                            "id": "p"
                        }));
                    }
                    if n == 0 {
                        return axum::Json(json!({
                            "jsonrpc": "2.0",
                            "result": { "timestamp": 1, "results": [{ "type": "NETWORK_FAILURE" }] },
                            "id": "t0"
                        }));
                    }
                    axum::Json(json!({
                        "jsonrpc": "2.0",
                        "result": { "timestamp": 1764280000999u64, "results": [{ "type": "SUCCESS" }] },
                        "id": "t1"
                    }))
                }
            }),
        );
        let rlistener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let raddr = rlistener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(rlistener, retry_app).await.unwrap() });

        let rclient = SignalClient::new(sample_cfg(&format!("http://{raddr}"))).unwrap();
        let rstore = SentStore::open(dir.path().join("retry_sent.json"));
        let fast = [Duration::from_millis(5); 3];
        let ts = send_with_retry(&rclient, &rstore, "transient", fast, &CancellationToken::new()).await.unwrap();
        assert_eq!(ts, Some(1764280000999));
        assert_eq!(retry_calls.load(Ordering::SeqCst), 2, "transient failure should retry once and succeed");

        let before = retry_calls.load(Ordering::SeqCst);
        let perm_err =
            send_with_retry(&rclient, &rstore, "permanent", fast, &CancellationToken::new()).await.unwrap_err();
        assert!(perm_err.contains("UNTRUSTED_IDENTITY"));
        assert_eq!(retry_calls.load(Ordering::SeqCst), before + 1, "permanent error must not retry");

        env.rt.shutdown().await;
    }

    #[tokio::test]
    async fn outbound_sender_coalesces_error_bursts_and_updates_signal_health() {
        let sent_msgs = Arc::new(Mutex::new(Vec::<String>::new()));
        let sent_clone = sent_msgs.clone();
        let app = Router::new().route(
            "/api/v1/rpc",
            post(move |axum::Json(body): axum::Json<Value>| {
                let s = sent_clone.clone();
                async move {
                    if body["method"] == "send" {
                        if let Some(m) = body["params"]["message"].as_str() {
                            s.lock().unwrap().push(m.to_string());
                        }
                    }
                    axum::Json(json!({
                        "jsonrpc": "2.0",
                        "result": { "timestamp": 1764280000555u64, "results": [{ "type": "SUCCESS" }] },
                        "id": "1"
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let env = start_test_runtime(Script::new(|_, _| Reply::text("ok").into())).await;
        let dir = tempfile::tempdir().unwrap();
        let store = SentStore::open(dir.path().join("signal_sent.json"));
        let mut cfg = sample_cfg(&format!("http://{addr}"));
        cfg.events.push("disk".into());
        let client = SignalClient::new(cfg.clone()).unwrap();
        let health = Arc::new(SignalHealth::from_config(&cfg));
        let shutdown = CancellationToken::new();
        let (tx, rx) = mpsc::channel(16);
        let pending = Arc::new(AtomicUsize::new(0));

        let timing =
            SenderTiming { coalesce_window: Duration::from_millis(80), retry_delays: [Duration::from_millis(10); 3] };
        let sender = tokio::spawn(outbound_sender_loop(
            client,
            env.rt.clone(),
            store.clone(),
            health.clone(),
            rx,
            pending.clone(),
            timing,
            shutdown.clone(),
        ));

        // Enqueue 3 rapid error alerts + 1 disk notice
        for msg in ["err-1", "err-2", "err-3"] {
            try_enqueue_job(&tx, &pending, &health, OutboundJob::Error { session: None, message: msg.into() });
        }
        enqueue_notice(
            &cfg,
            &store,
            &health,
            &tx,
            &pending,
            NoticeEvent {
                source: NoticeSource::Disk,
                kind: "disk".into(),
                session: None,
                title: "Low disk space".into(),
                text: LOW_DISK_NOTICE.into(),
                item: None,
            },
        );

        wait_for(|| sent_msgs.lock().unwrap().len() >= 2).await;
        shutdown.cancel();
        let _ = sender.await;

        let msgs = sent_msgs.lock().unwrap().clone();
        assert_eq!(msgs.len(), 2, "expected 1 coalesced error burst + 1 disk alert: {msgs:?}");
        assert!(
            msgs[0].contains("[Ferret · ERROR (3 alerts)]") && msgs[0].contains("err-1") && msgs[0].contains("err-3")
        );
        assert!(msgs[1].contains("[Ferret · DISK] Low disk space"));
        let snap = health.snapshot();
        assert!(snap.last_send_ms.is_some());
        assert_eq!(snap.pending_sends, 0);
        assert_eq!(snap.dropped_events, 0);

        env.rt.shutdown().await;
    }

    #[test]
    fn note_to_self_uuid_only_echo_and_multihop_grandchild_lead_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let store = SentStore::open(dir.path().join("signal_sent.json"));
        let mut cfg = sample_cfg("http://127.0.0.1:1337");
        cfg.recipient = "+15550100".into();
        cfg.allow_from = vec!["+15550100".into(), "00000000-0000-4000-8000-000000000001".into()];

        // 1a. Pending echo recorded under E.164, sync envelope arrives with destinationUuid only
        // after learning identity mapping (e.g. via listContacts or an earlier envelope).
        store.remember_identity(Some("+15550100"), Some("00000000-0000-4000-8000-000000000001"));
        store.note_pending_echo("+15550100", "unprefixed custom reply");
        let uuid_sync_echo = json!({
            "envelope": {
                "sourceUuid": "00000000-0000-4000-8000-000000000001",
                "syncMessage": {
                    "sentMessage": {
                        "destinationUuid": "00000000-0000-4000-8000-000000000001",
                        "timestamp": 1764280001111u64,
                        "message": "unprefixed custom reply"
                    }
                }
            }
        });
        assert!(
            parse_envelope(&cfg, &store, &uuid_sync_echo).is_none(),
            "UUID-only Note-to-Self sync must match E.164 pending echo"
        );

        // 1b. Even BEFORE any identity mapping is warmed, Note-to-Self sourceUuid == destinationUuid
        // matches an E.164 pending echo for `account`.
        let cold_store = SentStore::open(dir.path().join("signal_sent_cold.json"));
        cold_store.note_pending_echo("+15550100", "cold custom reply");
        let cold_sync_echo = json!({
            "envelope": {
                "sourceUuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "syncMessage": {
                    "sentMessage": {
                        "destinationUuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                        "timestamp": 1764280001112u64,
                        "message": "cold custom reply"
                    }
                }
            }
        });
        assert!(
            parse_envelope(&cfg, &cold_store, &cold_sync_echo).is_none(),
            "cold UUID-only Note-to-Self sync must still match account pending echo"
        );

        // 1c. All slash-command bot responses are suppressed on Note-to-Self sync even without pending_echo
        for bot_reply in [
            "Usage: `/scope <session|#n> <host>...`",
            "Usage: `/release <session|#n> <reason>`.",
            "No running session to stop.",
            "No missions yet.",
            "Multiple sessions are running — send `/stop #1` (or `/stop <id>`):",
            "Multiple stopped/parked sessions — send `/resume #1` (or `/resume <id>`):",
            "Multiple dismissible items — send `/dismiss #1` (or `/dismiss <id>`):",
        ] {
            let sync_msg = json!({
                "envelope": {
                    "sourceUuid": "00000000-0000-4000-8000-000000000001",
                    "syncMessage": {
                        "sentMessage": {
                            "destinationUuid": "00000000-0000-4000-8000-000000000001",
                            "timestamp": 1764280001113u64,
                            "message": bot_reply
                        }
                    }
                }
            });
            assert!(parse_envelope(&cfg, &store, &sync_msg).is_none(), "bot reply leaked: {bot_reply}");
        }

        // Real operator Note-to-Self message with destinationUuid STILL passes through
        let real_user = json!({
            "envelope": {
                "sourceUuid": "00000000-0000-4000-8000-000000000001",
                "syncMessage": {
                    "sentMessage": {
                        "destinationUuid": "00000000-0000-4000-8000-000000000001",
                        "timestamp": 1764280001114u64,
                        "message": "proceed with staging"
                    }
                }
            }
        });
        let parsed = parse_envelope(&cfg, &store, &real_user).expect("real user note-to-self must pass");
        assert!(sender_authorized(&cfg, &store, &parsed));

        // 2. Multi-hop grandchild parent walk (lead -> dispatcher -> solver -> leaf) & cycle guard
        let parents: HashMap<SessionId, SessionId> = HashMap::from([
            (SessionId::from("s-dispatcher"), SessionId::from("s-lead")),
            (SessionId::from("s-solver"), SessionId::from("s-dispatcher")),
            (SessionId::from("s-leaf"), SessionId::from("s-solver")),
            (SessionId::from("s-cyc-a"), SessionId::from("s-cyc-b")),
            (SessionId::from("s-cyc-b"), SessionId::from("s-cyc-a")),
        ]);
        let lookup = |id: &SessionId| parents.get(id).cloned();
        assert_eq!(resolve_root_id(&SessionId::from("s-lead"), lookup), SessionId::from("s-lead"));
        assert_eq!(resolve_root_id(&SessionId::from("s-dispatcher"), lookup), SessionId::from("s-lead"));
        assert_eq!(resolve_root_id(&SessionId::from("s-solver"), lookup), SessionId::from("s-lead"));
        assert_eq!(resolve_root_id(&SessionId::from("s-leaf"), lookup), SessionId::from("s-lead"));
        // Bounded loop terminates cleanly on pathological cycle
        let _ = resolve_root_id(&SessionId::from("s-cyc-a"), lookup);
    }
}
