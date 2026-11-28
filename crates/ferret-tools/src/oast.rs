//! Out-of-Band Application Security Testing (OAST) callback broker and tools (`oast_mint`, `oast_poll`).
//!
//! CONTRACT.
//!
//! - Disabled by default (`[oast] enabled = false`). When not mounted on `SessionTools::oast`, both
//!   `oast_mint` and `oast_poll` refuse with an explicit message telling the operator to configure `[oast]`.
//! - Supports two modes:
//!   - `OastMode::Local`: binds a lightweight async Tokio HTTP listener (`cfg.bind`, default `127.0.0.1:0`)
//!     that replies `200 OK` and records source IP, method, path, headers, first 64 KiB of body, and
//!     timestamp for tokens matched via `/oast/<token>` or `Host: <token>.*`; plus an optional UDP DNS
//!     listener (`cfg.dns_bind`) that parses minimal RFC 1035 queries, matches `<token>.*`, records
//!     qname/qtype/src_ip, and replies with a synthetic `127.0.0.1` `A` record.
//!   - `OastMode::External`: polls an operator-configured OAST polling endpoint (`external_poll_url`,
//!     requiring `https://` or loopback `http://`) with an optional bearer token read from
//!     `external_token_file` (`O_NOFOLLOW`, `0600`, owner UID match, 4 KiB cap) and a strict 4 MiB
//!     response cap.
//! - Strict mission isolation: tokens minted by mission A are recorded and returned ONLY for mission A;
//!   a session in mission B can never see mission A's interactions, even if it guesses a token.
//! - Bounded storage: at most [`MAX_INTERACTIONS_PER_MISSION`] (1,024) interactions retained per mission
//!   and at most [`MAX_BODY_BYTES`] (64 KiB) per HTTP callback body.
//! - `oast_poll` stores raw redacted interaction payloads in the `BlobStore` and carries
//!   `META_EVIDENCE_GRADE = "run"` (with `ToolClass::Exec`) when `>= 1` callback interaction is observed,
//!   or `"read"` when no callback has arrived yet.

use crate::{
    params::{opt, spec},
    Body, Tool, ToolCtx, ToolOutput,
};
use async_trait::async_trait;
use ferret_core::config::{OastCfg, OastMode};
use ferret_core::event::{ToolClass, ToolSpec, META_ALSO_STORED, META_EVIDENCE_GRADE};
use futures_util::StreamExt;
use rand::RngExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Maximum captured HTTP callback body size (64 KiB).
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Maximum HTTP callback header bytes read before rejecting/truncating (16 KiB).
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Maximum interactions retained per mission (oldest dropped when exceeded).
pub const MAX_INTERACTIONS_PER_MISSION: usize = 1024;
/// Maximum tokens minted per mission (oldest evicted from active map past this cap).
const MAX_TOKENS_PER_MISSION: usize = 4096;
/// Maximum external deduplication keys retained per mission.
const MAX_SEEN_EXTERNAL_PER_MISSION: usize = 4 * MAX_INTERACTIONS_PER_MISSION;
/// Maximum response bytes accepted from an external OAST poll endpoint (4 MiB).
pub const MAX_EXTERNAL_POLL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum size of `external_token_file` (4 KiB).
pub const MAX_EXTERNAL_TOKEN_FILE_BYTES: usize = 4 * 1024;
/// Maximum concurrent incoming local HTTP callback connections.
const MAX_LOCAL_CONNS: usize = 64;
/// Timeout for reading a single incoming local HTTP callback request.
const LOCAL_CONN_TIMEOUT: Duration = Duration::from_secs(5);
/// Length of each minted OAST token (lowercase alphanumeric).
const TOKEN_LEN: usize = 16;

/// Result returned by [`OastBroker::mint`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OastMintResult {
    pub token: String,
    pub http_url: String,
    pub dns_host: String,
    pub mode: String,
}

/// One captured out-of-band callback interaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OastInteraction {
    pub seq: u64,
    /// `"http"` or `"dns"` (or external protocol string).
    pub protocol: String,
    pub token: String,
    pub mission: String,
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_exchange: Option<String>,
    pub timestamp_ms: u64,
    pub remote_addr: String,
    pub summary: String,
    pub raw: String,
}

#[derive(Clone, Debug)]
struct TokenMeta {
    mission: String,
    session: String,
    label: Option<String>,
    trigger_exchange: Option<String>,
}

#[derive(Default)]
struct MissionBucket {
    next_seq: u64,
    interactions: VecDeque<OastInteraction>,
    token_order: VecDeque<String>,
    seen_external: HashSet<String>,
    seen_external_order: VecDeque<String>,
}

#[derive(Default)]
struct BrokerState {
    tokens: HashMap<String, TokenMeta>,
    missions: HashMap<String, MissionBucket>,
}

struct ExternalCfg {
    poll_url: String,
    token: Option<String>,
    client: Client,
}

/// Process-wide or mission-shared OAST callback broker.
pub struct OastBroker {
    mode: OastMode,
    public_host: Option<String>,
    http_addr: Option<SocketAddr>,
    dns_addr: Option<SocketAddr>,
    external: Option<ExternalCfg>,
    state: Arc<Mutex<BrokerState>>,
    notify: Arc<Notify>,
    cancel: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for OastBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OastBroker")
            .field("mode", &self.mode)
            .field("http_addr", &self.http_addr)
            .field("dns_addr", &self.dns_addr)
            .field("public_host", &self.public_host)
            .finish()
    }
}

impl Drop for OastBroker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn generate_token() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(TOKEN_LEN);
    let mut rng = rand::rng();
    let mut buf = [0u8; 32];
    // Rejection-sample so every character in ALPHABET (36) is strictly uniform (252 = 7 * 36).
    while out.len() < TOKEN_LEN {
        rng.fill(&mut buf[..]);
        for &b in &buf {
            if b < 252 {
                out.push(ALPHABET[(b % 36) as usize] as char);
                if out.len() == TOKEN_LEN {
                    break;
                }
            }
        }
    }
    out
}

fn validate_external_poll_url(raw: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(raw.trim()).map_err(|e| format!("oast.external_poll_url is not a valid URL: {e}."))?;
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "oast.external_poll_url must include a host.".to_string())?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err("oast.external_poll_url must not contain embedded credentials; use external_token_file.".into());
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" => {
            let is_loopback = host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
            if !is_loopback {
                return Err(format!(
                    "oast.external_poll_url `{raw}` uses plaintext http:// for non-loopback host `{host}`; use https:// or a loopback address."
                ));
            }
            Ok(url)
        }
        other => Err(format!("oast.external_poll_url must use https:// or loopback http:// (got `{other}`).")),
    }
}

impl OastBroker {
    /// Start an OAST callback broker from `cfg`.
    pub async fn start(cfg: &OastCfg) -> Result<Arc<Self>, String> {
        if !cfg.enabled {
            return Err("OAST is disabled ([oast] enabled = false).".into());
        }
        cfg.check()?;
        let state = Arc::new(Mutex::new(BrokerState::default()));
        let notify = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let mut tasks = Vec::new();
        let public_host = cfg.public_host.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);

        match cfg.mode {
            OastMode::Local => {
                let bind = if cfg.bind.trim().is_empty() { "127.0.0.1:0" } else { cfg.bind.trim() };
                let listener = TcpListener::bind(bind)
                    .await
                    .map_err(|e| format!("OAST HTTP listener could not bind `{bind}`: {e}."))?;
                let http_addr = listener
                    .local_addr()
                    .map_err(|e| format!("OAST HTTP listener address could not be read: {e}."))?;
                let http_task = tokio::spawn(run_http_listener(
                    listener,
                    state.clone(),
                    notify.clone(),
                    cancel.clone(),
                ));
                tasks.push(http_task);

                let dns_addr = if let Some(dns_bind) = cfg.dns_bind.as_deref().map(str::trim).filter(|s| !s.is_empty())
                {
                    let socket = UdpSocket::bind(dns_bind)
                        .await
                        .map_err(|e| format!("OAST DNS listener could not bind `{dns_bind}`: {e}."))?;
                    let addr = socket
                        .local_addr()
                        .map_err(|e| format!("OAST DNS listener address could not be read: {e}."))?;
                    let dns_task =
                        tokio::spawn(run_dns_listener(socket, state.clone(), notify.clone(), cancel.clone()));
                    tasks.push(dns_task);
                    Some(addr)
                } else {
                    None
                };

                Ok(Arc::new(Self {
                    mode: OastMode::Local,
                    public_host,
                    http_addr: Some(http_addr),
                    dns_addr,
                    external: None,
                    state,
                    notify,
                    cancel,
                    tasks: Mutex::new(tasks),
                }))
            }
            OastMode::External => {
                let raw_url = cfg
                    .external_poll_url
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or("oast.external_poll_url is required when oast.mode = \"external\".")?;
                let parsed = validate_external_poll_url(raw_url)?;
                let token = match cfg.external_token_file.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    Some(path) => {
                        let raw = crate::mcp::read_private_secret_file(
                            Path::new(path),
                            "oast.external_token_file",
                            MAX_EXTERNAL_TOKEN_FILE_BYTES,
                        )?;
                        let trimmed = raw.trim().to_string();
                        if trimmed.is_empty() {
                            return Err("oast.external_token_file is empty.".into());
                        }
                        Some(trimmed)
                    }
                    None => None,
                };
                let client = Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(15))
                    .build()
                    .map_err(|e| format!("OAST external HTTP client could not be built: {e}."))?;
                Ok(Arc::new(Self {
                    mode: OastMode::External,
                    public_host,
                    http_addr: None,
                    dns_addr: None,
                    external: Some(ExternalCfg { poll_url: parsed.to_string(), token, client }),
                    state,
                    notify,
                    cancel,
                    tasks: Mutex::new(tasks),
                }))
            }
        }
    }

    pub fn mode(&self) -> OastMode {
        self.mode
    }

    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    pub fn dns_addr(&self) -> Option<SocketAddr> {
        self.dns_addr
    }

    /// Mint a new cryptographically random 16-char lowercase alphanumeric OAST callback token bound
    /// strictly to `mission`.
    pub fn mint(
        &self,
        mission: &str,
        session: &str,
        label: Option<&str>,
        trigger_exchange: Option<&str>,
    ) -> OastMintResult {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let token = loop {
            let candidate = generate_token();
            if !st.tokens.contains_key(&candidate) {
                break candidate;
            }
        };
        let bucket = st.missions.entry(mission.to_string()).or_default();
        let evicted = if bucket.token_order.len() >= MAX_TOKENS_PER_MISSION {
            bucket.token_order.pop_front()
        } else {
            None
        };
        bucket.token_order.push_back(token.clone());
        if let Some(old_token) = evicted {
            st.tokens.remove(&old_token);
        }
        st.tokens.insert(
            token.clone(),
            TokenMeta {
                mission: mission.to_string(),
                session: session.to_string(),
                label: label.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string),
                trigger_exchange: trigger_exchange.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string),
            },
        );
        drop(st);

        let (http_url, dns_host, mode) = match self.mode {
            OastMode::Local => {
                let http_authority = self
                    .public_host
                    .clone()
                    .or_else(|| self.http_addr.map(|a| a.to_string()))
                    .unwrap_or_else(|| "127.0.0.1".into());
                let dns_domain = self
                    .public_host
                    .as_deref()
                    .map(|h| h.split(':').next().unwrap_or(h))
                    .filter(|h| !h.is_empty())
                    .unwrap_or("oast.local");
                (format!("http://{http_authority}/oast/{token}"), format!("{token}.{dns_domain}"), "local".into())
            }
            OastMode::External => {
                let host = self
                    .public_host
                    .clone()
                    .or_else(|| {
                        self.external
                            .as_ref()
                            .and_then(|e| url::Url::parse(&e.poll_url).ok())
                            .and_then(|u| u.host_str().map(str::to_string))
                    })
                    .unwrap_or_else(|| "oast.invalid".into());
                let scheme = self
                    .external
                    .as_ref()
                    .and_then(|e| url::Url::parse(&e.poll_url).ok())
                    .map(|u| u.scheme().to_string())
                    .unwrap_or_else(|| "https".into());
                let dns_domain = host.split(':').next().unwrap_or(&host);
                (format!("{scheme}://{host}/oast/{token}"), format!("{token}.{dns_domain}"), "external".into())
            }
        };

        OastMintResult { token, http_url, dns_host, mode }
    }

    /// Poll captured interactions belonging strictly to `mission`.
    pub async fn poll(
        &self,
        mission: &str,
        token: Option<&str>,
        since_seq: Option<u64>,
    ) -> Result<Vec<OastInteraction>, String> {
        if self.mode == OastMode::External {
            self.poll_external().await?;
        }
        Ok(self.read_local(mission, token, since_seq))
    }

    /// Poll for interactions belonging to `mission`, optionally waiting up to `wait` for at least one
    /// matching callback to arrive.
    pub async fn poll_wait(
        &self,
        mission: &str,
        token: Option<&str>,
        since_seq: Option<u64>,
        wait: Duration,
        cancel: &CancellationToken,
    ) -> Result<Vec<OastInteraction>, String> {
        let initial = self.poll(mission, token, since_seq).await?;
        if !initial.is_empty() || wait.is_zero() {
            return Ok(initial);
        }
        let deadline = Instant::now() + wait;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return self.poll(mission, token, since_seq).await;
            }
            let remaining = deadline.saturating_duration_since(now);
            let step = if self.mode == OastMode::External {
                remaining.min(Duration::from_millis(500))
            } else {
                remaining
            };
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err("OAST poll was cancelled.".into()),
                _ = self.cancel.cancelled() => return Ok(self.read_local(mission, token, since_seq)),
                _ = self.notify.notified(), if self.mode == OastMode::Local => {}
                _ = tokio::time::sleep(step) => {}
            }
            let found = self.poll(mission, token, since_seq).await?;
            if !found.is_empty() {
                return Ok(found);
            }
        }
    }

    fn read_local(&self, mission: &str, token: Option<&str>, since_seq: Option<u64>) -> Vec<OastInteraction> {
        let filter_tok = token.map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty());
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(tok) = &filter_tok {
            // Strict mission isolation: if the requested token belongs to another mission (or does not
            // exist), return empty rather than leaking anything across missions.
            match st.tokens.get(tok) {
                Some(meta) if meta.mission == mission => {}
                _ => return Vec::new(),
            }
        }
        let Some(bucket) = st.missions.get(mission) else {
            return Vec::new();
        };
        let min_seq = since_seq.unwrap_or(0);
        bucket
            .interactions
            .iter()
            .filter(|i| i.seq > min_seq)
            .filter(|i| filter_tok.as_deref().is_none_or(|t| i.token == t))
            .cloned()
            .collect()
    }

    async fn poll_external(&self) -> Result<(), String> {
        let Some(ext) = &self.external else {
            return Ok(());
        };
        let mut req = ext.client.get(&ext.poll_url);
        if let Some(tok) = &ext.token {
            req = req.bearer_auth(tok);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("OAST external poll failed: {e}."))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("OAST external poll returned HTTP {}.", status.as_u16()));
        }
        let mut stream = resp.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| format!("OAST external poll body read failed: {e}."))?;
            if body.len().saturating_add(chunk.len()) > MAX_EXTERNAL_POLL_BYTES {
                return Err(format!(
                    "OAST external poll response exceeded the {MAX_EXTERNAL_POLL_BYTES}-byte cap."
                ));
            }
            body.extend_from_slice(&chunk);
        }
        if body.is_empty() {
            return Ok(());
        }
        let parsed: Value = serde_json::from_slice(&body)
            .map_err(|e| format!("OAST external poll returned invalid JSON: {e}."))?;
        let items: Vec<&Value> = match &parsed {
            Value::Array(arr) => arr.iter().collect(),
            Value::Object(map) => map
                .get("interactions")
                .or_else(|| map.get("data"))
                .and_then(Value::as_array)
                .map(|arr| arr.iter().collect())
                .unwrap_or_default(),
            _ => return Err("OAST external poll JSON must be an array or an object with `interactions`/`data`.".into()),
        };

        // Route every matched callback in the response to its owning `meta.mission` bucket so
        // destructive-pop external servers (e.g. Interactsh) never lose sibling missions' events.
        // `read_local(mission, ...)` remains strictly isolated to the caller's mission.
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.tokens.is_empty() {
            return Ok(());
        }
        let all_tokens: HashMap<String, TokenMeta> = st.tokens.clone();
        let mut routed_any = false;
        for item in items {
            let Some(obj) = item.as_object() else { continue };
            let Some(tok) = extract_external_token(obj, &all_tokens) else { continue };
            let Some(meta) = all_tokens.get(&tok) else { continue };
            let dedup_key = obj
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| ferret_core::sha256_hex(item.to_string().as_bytes()));
            let bucket = st.missions.entry(meta.mission.clone()).or_default();
            if !remember_external(bucket, dedup_key) {
                continue;
            }
            let protocol = obj
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("http")
                .to_ascii_lowercase();
            let remote_addr = obj
                .get("remote-address")
                .or_else(|| obj.get("remote_addr"))
                .or_else(|| obj.get("remote_address"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let summary = obj
                .get("summary")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    let qname = obj.get("qname").or_else(|| obj.get("full-id")).and_then(Value::as_str).unwrap_or("");
                    let method = obj.get("method").and_then(Value::as_str).unwrap_or("");
                    let path = obj.get("path").and_then(Value::as_str).unwrap_or("");
                    if !method.is_empty() || !path.is_empty() {
                        format!("{protocol} {method} {path}").trim().to_string()
                    } else if !qname.is_empty() {
                        format!("{protocol} {qname}")
                    } else {
                        format!("{protocol} interaction for {tok}")
                    }
                });
            let raw = obj
                .get("raw-request")
                .or_else(|| obj.get("raw"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| item.to_string());
            let raw = truncate_utf8(&raw, MAX_BODY_BYTES);
            let timestamp_ms = obj.get("timestamp_ms").and_then(Value::as_u64).unwrap_or_else(now_ms);
            push_interaction_locked(
                bucket,
                meta,
                &tok,
                protocol,
                remote_addr,
                summary,
                raw,
                timestamp_ms,
            );
            routed_any = true;
        }
        drop(st);
        if routed_any {
            self.notify.notify_waiters();
        }
        Ok(())
    }

    /// Stop background HTTP/DNS listener tasks cleanly.
    pub fn shutdown(&self) {
        self.cancel.cancel();
        if let Ok(mut guard) = self.tasks.lock() {
            for h in guard.drain(..) {
                h.abort();
            }
        }
    }
}

fn truncate_utf8(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn extract_external_token(obj: &Map<String, Value>, mission_tokens: &HashMap<String, TokenMeta>) -> Option<String> {
    for key in ["token", "unique-id", "unique_id", "full-id", "full_id", "path", "host", "qname", "raw-request", "raw"] {
        if let Some(val) = obj.get(key).and_then(Value::as_str) {
            let low = val.to_ascii_lowercase();
            if mission_tokens.contains_key(low.trim()) {
                return Some(low.trim().to_string());
            }
            if let Some(t) = extract_token_from_path(&low) {
                if mission_tokens.contains_key(&t) {
                    return Some(t);
                }
            }
            if let Some(t) = extract_token_from_host(&low) {
                if mission_tokens.contains_key(&t) {
                    return Some(t);
                }
            }
            for known in mission_tokens.keys() {
                if low.contains(known.as_str()) {
                    return Some(known.clone());
                }
            }
        }
    }
    None
}

fn remember_external(bucket: &mut MissionBucket, key: String) -> bool {
    if !bucket.seen_external.insert(key.clone()) {
        return false;
    }
    bucket.seen_external_order.push_back(key);
    while bucket.seen_external_order.len() > MAX_SEEN_EXTERNAL_PER_MISSION {
        if let Some(old) = bucket.seen_external_order.pop_front() {
            bucket.seen_external.remove(&old);
        }
    }
    true
}

#[allow(clippy::too_many_arguments)]
fn push_interaction_locked(
    bucket: &mut MissionBucket,
    meta: &TokenMeta,
    token: &str,
    protocol: String,
    remote_addr: String,
    summary: String,
    raw: String,
    timestamp_ms: u64,
) {
    bucket.next_seq = bucket.next_seq.saturating_add(1);
    let seq = bucket.next_seq;
    if bucket.interactions.len() >= MAX_INTERACTIONS_PER_MISSION {
        bucket.interactions.pop_front();
    }
    bucket.interactions.push_back(OastInteraction {
        seq,
        protocol,
        token: token.to_string(),
        mission: meta.mission.clone(),
        session: meta.session.clone(),
        label: meta.label.clone(),
        trigger_exchange: meta.trigger_exchange.clone(),
        timestamp_ms,
        remote_addr,
        summary,
        raw,
    });
}

fn record_local_interaction(
    state: &Arc<Mutex<BrokerState>>,
    notify: &Arc<Notify>,
    token: &str,
    protocol: &str,
    remote_addr: String,
    summary: String,
    raw: String,
) -> bool {
    let tok = token.to_ascii_lowercase();
    let mut st = state.lock().unwrap_or_else(|p| p.into_inner());
    let Some(meta) = st.tokens.get(&tok).cloned() else {
        return false;
    };
    let bucket = st.missions.entry(meta.mission.clone()).or_default();
    push_interaction_locked(
        bucket,
        &meta,
        &tok,
        protocol.to_string(),
        remote_addr,
        summary,
        raw,
        now_ms(),
    );
    drop(st);
    notify.notify_waiters();
    true
}

fn extract_token_from_path(path: &str) -> Option<String> {
    let clean = path.split('?').next().unwrap_or(path);
    let rest = clean.strip_prefix("/oast/")?;
    let seg = rest.split('/').next().unwrap_or("").trim().to_ascii_lowercase();
    (!seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(seg)
}

fn extract_token_from_host(host: &str) -> Option<String> {
    let without_port = host.trim().split(':').next().unwrap_or("").trim_end_matches('.');
    let first = without_port.split('.').next()?.trim().to_ascii_lowercase();
    (!first.is_empty() && first.bytes().all(|b| b.is_ascii_alphanumeric())).then_some(first)
}

async fn run_http_listener(
    listener: TcpListener,
    state: Arc<Mutex<BrokerState>>,
    notify: Arc<Notify>,
    cancel: CancellationToken,
) {
    let sem = Arc::new(Semaphore::new(MAX_LOCAL_CONNS));
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            res = listener.accept() => res,
        };
        let Ok((stream, peer)) = accepted else {
            continue;
        };
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let state = state.clone();
        let notify = notify.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(LOCAL_CONN_TIMEOUT, handle_http_conn(stream, peer, state, notify)).await;
        });
    }
}

async fn handle_http_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    state: Arc<Mutex<BrokerState>>,
    notify: Arc<Notify>,
) {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let mut head_end: Option<usize> = None;
    let mut content_length: Option<usize> = None;

    while buf.len() < MAX_HEAD_BYTES + MAX_BODY_BYTES {
        let read_res = if head_end.is_some() {
            match tokio::time::timeout(Duration::from_millis(250), stream.read(&mut tmp)).await {
                Ok(r) => r,
                Err(_) => break,
            }
        } else {
            stream.read(&mut tmp).await
        };
        let n = match read_res {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let cap = (MAX_HEAD_BYTES + MAX_BODY_BYTES).saturating_sub(buf.len());
        buf.extend_from_slice(&tmp[..n.min(cap)]);
        if head_end.is_none() {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                head_end = Some(pos + 4);
                let head_str = String::from_utf8_lossy(&buf[..pos]);
                for line in head_str.lines().skip(1) {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_length = v.trim().parse::<usize>().ok();
                        }
                    }
                }
                if content_length == Some(0) || content_length.is_none() {
                    break;
                }
            } else if buf.len() >= MAX_HEAD_BYTES {
                break;
            }
        }
        if let (Some(he), Some(cl)) = (head_end, content_length) {
            let want = cl.min(MAX_BODY_BYTES);
            if buf.len().saturating_sub(he) >= want {
                break;
            }
        }
    }

    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    let _ = stream.write_all(response).await;
    let _ = stream.shutdown().await;

    if buf.is_empty() {
        return;
    }
    let split = head_end.map_or(buf.len(), |p| p.saturating_sub(4));
    let head_text = String::from_utf8_lossy(&buf[..split]);
    let mut lines = head_text.split("\r\n");
    let first_line = lines.next().unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("UNKNOWN");
    let path = parts.next().unwrap_or("/");

    let mut host_hdr = String::new();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k_t = k.trim();
            let v_t = v.trim();
            if k_t.eq_ignore_ascii_case("host") {
                host_hdr = v_t.to_string();
            }
            headers.push((k_t.to_string(), v_t.to_string()));
        }
    }

    let body_slice = head_end.map_or(&[][..], |he| {
        let slice = buf.get(he..).unwrap_or_default();
        &slice[..slice.len().min(MAX_BODY_BYTES)]
    });

    let matched_token = {
        let st = state.lock().unwrap_or_else(|p| p.into_inner());
        let from_path = extract_token_from_path(path).filter(|t| st.tokens.contains_key(t));
        from_path.or_else(|| extract_token_from_host(&host_hdr).filter(|t| st.tokens.contains_key(t)))
    };

    let Some(token) = matched_token else {
        return;
    };

    let mut raw = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in &headers {
        raw.push_str(&format!("{k}: {v}\r\n"));
    }
    raw.push_str("\r\n");
    if !body_slice.is_empty() {
        raw.push_str(&String::from_utf8_lossy(body_slice));
    }
    let summary = format!(
        "HTTP {method} {path} (host={}, body={} bytes)",
        if host_hdr.is_empty() { "-" } else { host_hdr.as_str() },
        body_slice.len()
    );
    record_local_interaction(&state, &notify, &token, "http", peer.to_string(), summary, raw);
}

/// Parse a minimal RFC 1035 DNS query packet: returns `(txid, flags, qname, qtype, qclass, question_end_offset)`.
fn parse_dns_query(pkt: &[u8]) -> Option<(u16, u16, String, u16, u16, usize)> {
    if pkt.len() < 12 {
        return None;
    }
    let txid = u16::from_be_bytes([pkt[0], pkt[1]]);
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    // Must be a query (QR bit == 0) with at least 1 question.
    if (flags & 0x8000) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12usize;
    let mut labels = Vec::new();
    let mut total_name_len = 0usize;
    loop {
        let len = *pkt.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // Reject compression pointers (top 2 bits set) or oversized labels in queries.
        if (len & 0xC0) != 0 || len > 63 || labels.len() >= 128 {
            return None;
        }
        let end = pos.checked_add(len)?;
        let label_bytes = pkt.get(pos..end)?;
        total_name_len = total_name_len.saturating_add(len + 1);
        if total_name_len > 255 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label_bytes).to_ascii_lowercase());
        pos = end;
    }
    if labels.is_empty() {
        return None;
    }
    let qtype = u16::from_be_bytes([*pkt.get(pos)?, *pkt.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*pkt.get(pos + 2)?, *pkt.get(pos + 3)?]);
    let question_end = pos + 4;
    Some((txid, flags, labels.join("."), qtype, qclass, question_end))
}

fn dns_qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

/// Build a synthetic RFC 1035 DNS response replying `127.0.0.1` for `A`/`ANY` queries.
fn build_dns_reply(pkt: &[u8], txid: u16, req_flags: u16, qtype: u16, question_end: usize) -> Vec<u8> {
    let rd = req_flags & 0x0100;
    let resp_flags: u16 = 0x8000 | 0x0400 | rd; // QR=1, AA=1, RD copied, RCODE=0
    let include_a = matches!(qtype, 1 | 255);
    let ancount: u16 = if include_a { 1 } else { 0 };
    let mut out = Vec::with_capacity(question_end + if include_a { 16 } else { 0 });
    out.extend_from_slice(&txid.to_be_bytes());
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    if let Some(q) = pkt.get(12..question_end) {
        out.extend_from_slice(q);
    }
    if include_a {
        // Name pointer to offset 12 (the question QNAME).
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        out.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH 4
        out.extend_from_slice(&[127, 0, 0, 1]); // 127.0.0.1
    }
    out
}

async fn run_dns_listener(
    socket: UdpSocket,
    state: Arc<Mutex<BrokerState>>,
    notify: Arc<Notify>,
    cancel: CancellationToken,
) {
    let mut buf = [0u8; 1500];
    loop {
        let received = tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            res = socket.recv_from(&mut buf) => res,
        };
        let Ok((n, peer)) = received else {
            continue;
        };
        let pkt = &buf[..n];
        let Some((txid, flags, qname, qtype, qclass, qend)) = parse_dns_query(pkt) else {
            continue;
        };
        let reply = build_dns_reply(pkt, txid, flags, qtype, qend);
        let _ = socket.send_to(&reply, peer).await;

        let matched_token = {
            let st = state.lock().unwrap_or_else(|p| p.into_inner());
            qname
                .split('.')
                .find(|label| st.tokens.contains_key(*label))
                .map(str::to_string)
        };
        let Some(token) = matched_token else {
            continue;
        };
        let qtype_str = dns_qtype_name(qtype);
        let summary = format!("DNS {qtype_str} {qname}");
        let raw = format!(
            "DNS query\nqname: {qname}\nqtype: {qtype_str} ({qtype})\nqclass: {qclass}\nremote_addr: {peer}\n"
        );
        record_local_interaction(&state, &notify, &token, "dns", peer.to_string(), summary, raw);
    }
}

// ---- tools: oast_mint & oast_poll ----------------------------------------------------------------

pub struct OastMint;
pub struct OastPoll;

fn mission_key(ctx: &ToolCtx) -> &str {
    ctx.capabilities.mission_id.get().map(String::as_str).filter(|s| !s.is_empty()).unwrap_or(ctx.session.as_str())
}

#[async_trait]
impl Tool for OastMint {
    fn spec(&self) -> ToolSpec {
        spec(
            "oast_mint",
            "Mint a unique, mission-isolated out-of-band (OAST) callback token and URL/DNS host for blind SSRF, XXE, XSS, SSTI, or OOB command-execution testing. Requires [oast] enabled = true.",
            ToolClass::Read,
            &[
                opt("label", "string", "Optional short label describing what payload uses this callback token."),
                opt(
                    "trigger_exchange",
                    "string",
                    "Optional ex-* exchange ID that will carry or triggered this callback payload.",
                ),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(broker) = ctx.capabilities.oast.get() else {
            return ToolOutput::error(
                "OAST is not enabled in this session. Ask the operator to configure `[oast] enabled = true` in config.toml.",
            );
        };
        let label = args.get("label").and_then(Value::as_str);
        let trigger_exchange = args.get("trigger_exchange").and_then(Value::as_str);
        let minted = broker.mint(mission_key(ctx), ctx.session.as_str(), label, trigger_exchange);
        ToolOutput::ok(
            format!("minted {}", minted.token),
            Body::Message(
                serde_json::to_string_pretty(&json!({
                    "token": minted.token,
                    "http_url": minted.http_url,
                    "dns_host": minted.dns_host,
                    "mode": minted.mode,
                    "label": label,
                    "trigger_exchange": trigger_exchange,
                }))
                .unwrap_or_default(),
            ),
        )
        .with_more(format!("mode: {}", minted.mode))
    }
}

#[async_trait]
impl Tool for OastPoll {
    fn spec(&self) -> ToolSpec {
        spec(
            "oast_poll",
            "Poll for out-of-band (OAST) HTTP/DNS callbacks received for tokens minted in this mission. Stores raw redacted interaction details in the blob store and returns execution-graded evidence when at least one callback is observed.",
            ToolClass::Exec,
            &[
                opt("token", "string", "Optional OAST token from oast_mint to filter callbacks."),
                opt("since_seq", "integer", "Return only callbacks with seq greater than this value.").min(0),
                opt("wait_s", "integer", "Seconds to wait for a callback to arrive (0..=15, default 0).").min(0).max(15),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(broker) = ctx.capabilities.oast.get() else {
            return ToolOutput::error(
                "OAST is not enabled in this session. Ask the operator to configure `[oast] enabled = true` in config.toml.",
            )
            .with_meta(META_EVIDENCE_GRADE, json!("read"));
        };
        let token = args.get("token").and_then(Value::as_str);
        let since_seq = args.get("since_seq").and_then(Value::as_u64);
        let wait_s = args.get("wait_s").and_then(Value::as_u64).unwrap_or(0).min(15);
        let interactions = match broker
            .poll_wait(mission_key(ctx), token, since_seq, Duration::from_secs(wait_s), &ctx.cancel)
            .await
        {
            Ok(v) => v,
            Err(e) => return ToolOutput::error(e).with_meta(META_EVIDENCE_GRADE, json!("read")),
        };

        let secrets = ctx.capabilities.secrets.get().filter(|s| !s.is_empty());
        let mut stored_ids = Vec::new();
        let mut entries = Vec::with_capacity(interactions.len());
        for it in &interactions {
            let clean_raw = match secrets {
                Some(s) => s.redact(&it.raw).into_owned(),
                None => it.raw.clone(),
            };
            let clean_summary = match secrets {
                Some(s) => s.redact(&it.summary).into_owned(),
                None => it.summary.clone(),
            };
            let (blob_id, handle) = match ctx.blobs.put_bytes(clean_raw.as_bytes()) {
                Ok(b) => {
                    stored_ids.push(json!(b.id.as_str()));
                    (Some(b.id.to_string()), Some(b.handle()))
                }
                Err(_) => (None, None),
            };
            entries.push(json!({
                "seq": it.seq,
                "protocol": it.protocol,
                "token": it.token,
                "label": it.label,
                "trigger_exchange": it.trigger_exchange,
                "timestamp_ms": it.timestamp_ms,
                "remote_addr": it.remote_addr,
                "summary": clean_summary,
                "blob_id": blob_id,
                "handle": handle,
            }));
        }

        let payload = json!({
            "count": entries.len(),
            "interactions": entries,
        });
        let grade = if interactions.is_empty() { "read" } else { "run" };
        let mut out = ToolOutput::ok(
            format!("{} OAST interaction(s)", interactions.len()),
            Body::Raw(serde_json::to_vec_pretty(&payload).unwrap_or_default()),
        )
        .with_meta(META_EVIDENCE_GRADE, json!(grade));
        if !stored_ids.is_empty() {
            out = out.with_meta(META_ALSO_STORED, Value::Array(stored_ids));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::HeaderMap, routing::get, Router};
    use ferret_core::creds::{Item, ItemKind, Secrets};
    use ferret_core::event::{EvidenceGrade, ToolStatus};

    fn local_cfg(with_dns: bool) -> OastCfg {
        OastCfg {
            enabled: true,
            mode: OastMode::Local,
            bind: "127.0.0.1:0".into(),
            public_host: None,
            dns_bind: with_dns.then(|| "127.0.0.1:0".into()),
            external_poll_url: None,
            external_token_file: None,
        }
    }

    fn build_dns_query(txid: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&txid.to_be_bytes());
        pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD=1
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes()); // IN
        pkt
    }

    #[tokio::test]
    async fn local_http_and_dns_mint_poll_and_mission_isolation() {
        let broker = OastBroker::start(&local_cfg(true)).await.unwrap();
        let http_addr = broker.http_addr().expect("http addr");
        let dns_addr = broker.dns_addr().expect("dns addr");

        let mint_a = broker.mint("mission-a", "sess-1", Some("ssrf"), Some("ex-101"));
        let mint_b = broker.mint("mission-b", "sess-2", Some("xxe"), Some("ex-202"));
        assert_eq!(mint_a.token.len(), 16);
        assert!(mint_a.token.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
        assert_eq!(mint_a.http_url, format!("http://{http_addr}/oast/{}", mint_a.token));
        assert_eq!(mint_a.dns_host, format!("{}.oast.local", mint_a.token));
        assert_ne!(mint_a.token, mint_b.token);

        // 1. Trigger HTTP callback via path `/oast/<token>` for mission-a.
        let client = Client::builder().no_proxy().build().unwrap();
        let resp = client
            .post(&mint_a.http_url)
            .header("X-Callback", "hit-path")
            .body("blind-body-payload")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.text().await.unwrap(), "ok");

        // 2. Trigger HTTP callback via Host subdomain `<token>.oast.local` for mission-b.
        let resp_b = client
            .get(format!("http://{http_addr}/any/path"))
            .header("Host", format!("{}.oast.local", mint_b.token))
            .send()
            .await
            .unwrap();
        assert_eq!(resp_b.status().as_u16(), 200);

        // 3. Trigger UDP DNS A query for mission-a and verify synthetic 127.0.0.1 reply.
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_dns_query(0x4242, &mint_a.dns_host, 1);
        udp.send_to(&query, dns_addr).await.unwrap();
        let mut rbuf = [0u8; 512];
        let (rn, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut rbuf)).await.unwrap().unwrap();
        assert!(rn >= query.len() + 16, "expected A answer record, got {rn} bytes");
        assert_eq!(&rbuf[0..2], &0x4242u16.to_be_bytes());
        assert_eq!(&rbuf[rn - 4..rn], &[127, 0, 0, 1]);

        // Poll mission-a: sees ONLY mission-a's HTTP + DNS callbacks (2 interactions).
        let a_hits = broker
            .poll_wait("mission-a", None, None, Duration::from_secs(2), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(a_hits.len(), 2, "{a_hits:?}");
        let http_hit = a_hits.iter().find(|i| i.protocol == "http").expect("http hit");
        assert_eq!(http_hit.token, mint_a.token);
        assert_eq!(http_hit.trigger_exchange.as_deref(), Some("ex-101"));
        assert_eq!(http_hit.label.as_deref(), Some("ssrf"));
        assert!(http_hit.raw.contains("blind-body-payload"), "{}", http_hit.raw);
        let dns_hit = a_hits.iter().find(|i| i.protocol == "dns").expect("dns hit");
        assert_eq!(dns_hit.token, mint_a.token);
        assert!(dns_hit.summary.contains("DNS A") && dns_hit.summary.contains(&mint_a.dns_host));

        // Strict mission isolation: mission-b CANNOT see mission-a's callbacks even when asking by mission-a's token!
        let cross = broker.poll("mission-b", Some(&mint_a.token), None).await.unwrap();
        assert!(cross.is_empty(), "mission-b must never see mission-a callbacks: {cross:?}");
        let b_hits = broker.poll("mission-b", None, None).await.unwrap();
        assert_eq!(b_hits.len(), 1);
        assert_eq!(b_hits[0].token, mint_b.token);

        // since_seq filters older events.
        let since = broker.poll("mission-a", None, Some(a_hits[0].seq)).await.unwrap();
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].seq, a_hits[1].seq);

        broker.shutdown();
    }

    #[tokio::test]
    async fn oast_tools_grade_evidence_redact_secrets_and_fail_closed_when_disabled() {
        let e_off = crate::testutil::env();
        let off_mint = e_off.call("oast_mint", json!({})).await;
        assert_eq!(off_mint.status, ToolStatus::Error);
        assert!(off_mint.text.contains("not enabled"), "{}", off_mint.text);
        let off_poll = e_off.call("oast_poll", json!({})).await;
        assert_eq!(off_poll.status, ToolStatus::Error);
        assert_eq!(EvidenceGrade::of(ToolClass::Exec, &off_poll.meta), EvidenceGrade::Read);

        // Mounted OAST + secrets redaction + execution-grade evidence on arrival.
        let e = crate::testutil::env();
        let broker = OastBroker::start(&local_cfg(false)).await.unwrap();
        e.ctx.capabilities.oast.set(broker.clone()).unwrap();
        e.ctx.capabilities.mission_id.set("m-oast".into()).unwrap();
        let secret = "super-secret-oast-token-999";
        let secrets = Secrets::for_items(&[Item {
            kind: ItemKind::Header,
            name: "Authorization".into(),
            value: secret.into(),
            host: "127.0.0.1".into(),
        }]);
        e.ctx.capabilities.secrets.set(Arc::new(secrets)).unwrap();

        let minted = e.call("oast_mint", json!({"label": "blind-ssrf", "trigger_exchange": "ex-77"})).await;
        assert_eq!(minted.status, ToolStatus::Ok, "{}", minted.text);
        let body_start = minted.text.find('{').unwrap();
        let body_end = minted.text.rfind('}').unwrap();
        let minted_json: Value = serde_json::from_str(&minted.text[body_start..=body_end]).unwrap();
        let http_url = minted_json["http_url"].as_str().unwrap().to_string();
        let token = minted_json["token"].as_str().unwrap().to_string();

        // Poll before callback -> 0 interactions, graded Read (NOT Run).
        let empty = e.call("oast_poll", json!({"token": token})).await;
        assert_eq!(empty.status, ToolStatus::Ok);
        assert_eq!(EvidenceGrade::of(empty.class, &empty.meta), EvidenceGrade::Read);

        // Trigger callback carrying a session secret -> poll returns 1 interaction, graded Run, secret redacted!
        let client = Client::builder().no_proxy().build().unwrap();
        let _ = client.post(&http_url).body(format!("leaked={secret}")).send().await.unwrap();

        let got = e.call("oast_poll", json!({"token": token, "wait_s": 2})).await;
        assert_eq!(got.status, ToolStatus::Ok, "{}", got.text);
        assert_eq!(EvidenceGrade::of(got.class, &got.meta), EvidenceGrade::Run);
        assert!(!got.text.contains(secret), "secret must be redacted from tool output: {}", got.text);
        let stored = e.stored(&got);
        let parsed: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(parsed["count"], 1);
        assert_eq!(parsed["interactions"][0]["trigger_exchange"], "ex-77");
        let blob_id = parsed["interactions"][0]["blob_id"].as_str().unwrap();
        let raw_blob = String::from_utf8(e.ctx.blobs.read_all(&ferret_core::BlobId::from(blob_id)).unwrap()).unwrap();
        assert!(!raw_blob.contains(secret), "secret must be redacted from interaction blob: {raw_blob}");
        assert!(raw_blob.contains("[redacted]"), "{raw_blob}");

        broker.shutdown();
    }

    #[tokio::test]
    async fn external_mode_auth_polling_mission_isolation_and_4mib_cap() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tok_file = dir.path().join("oast.tok");
        std::fs::write(&tok_file, "ext-bearer-xyz\n").unwrap();
        std::fs::set_permissions(&tok_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        let shared_token = Arc::new(Mutex::new(String::new()));
        let shared_for_srv = shared_token.clone();
        let app = Router::new()
            .route(
                "/poll",
                get(move |h: HeaderMap| {
                    let st = shared_for_srv.clone();
                    async move {
                        if h.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer ext-bearer-xyz") {
                            return (axum::http::StatusCode::UNAUTHORIZED, "unauthorized".to_string());
                        }
                        let tok = st.lock().unwrap().clone();
                        let body = json!({
                            "data": [
                                {
                                    "id": "ext-1",
                                    "protocol": "http",
                                    "unique-id": tok,
                                    "remote-address": "198.51.100.42",
                                    "method": "GET",
                                    "path": format!("/oast/{tok}"),
                                    "raw-request": "GET /oast/hit HTTP/1.1\r\nHost: ext.test\r\n\r\n"
                                },
                                {
                                    "id": "ext-foreign",
                                    "protocol": "dns",
                                    "unique-id": "othertoken000000",
                                    "remote-address": "203.0.113.9"
                                }
                            ]
                        })
                        .to_string();
                        (axum::http::StatusCode::OK, body)
                    }
                }),
            )
            .route(
                "/huge",
                get(|| async { "a".repeat(MAX_EXTERNAL_POLL_BYTES + 1024) }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = OastCfg {
            enabled: true,
            mode: OastMode::External,
            bind: "127.0.0.1:0".into(),
            public_host: Some("oast.example.test".into()),
            dns_bind: None,
            external_poll_url: Some(format!("http://{addr}/poll")),
            external_token_file: Some(tok_file.display().to_string()),
        };
        let broker = OastBroker::start(&cfg).await.unwrap();
        let m = broker.mint("mission-ext", "s1", None, Some("ex-9"));
        *shared_token.lock().unwrap() = m.token.clone();

        let hits = broker.poll("mission-ext", None, None).await.unwrap();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].token, m.token);
        assert_eq!(hits[0].remote_addr, "198.51.100.42");
        assert_eq!(hits[0].trigger_exchange.as_deref(), Some("ex-9"));

        // Polling again deduplicates already-ingested external IDs.
        let hits2 = broker.poll("mission-ext", None, Some(hits[0].seq)).await.unwrap();
        assert!(hits2.is_empty());

        // Oversized >4 MiB external poll response is refused cleanly.
        let huge_cfg = OastCfg {
            external_poll_url: Some(format!("http://{addr}/huge")),
            external_token_file: None,
            ..cfg
        };
        let huge_broker = OastBroker::start(&huge_cfg).await.unwrap();
        let err = huge_broker.poll("mission-ext", None, None).await.unwrap_err();
        assert!(err.contains("cap"), "{err}");

        srv.abort();
    }

    #[tokio::test]
    async fn token_and_seen_external_caps_evict_oldest_entries() {
        let broker = OastBroker::start(&local_cfg(false)).await.unwrap();
        let mut minted = Vec::with_capacity(MAX_TOKENS_PER_MISSION + 10);
        for _ in 0..(MAX_TOKENS_PER_MISSION + 10) {
            minted.push(broker.mint("mission-cap", "s1", None, None).token);
        }
        {
            let st = broker.state.lock().unwrap();
            assert_eq!(st.tokens.len(), MAX_TOKENS_PER_MISSION);
            for old in &minted[..10] {
                assert!(!st.tokens.contains_key(old), "oldest token {old} should have been evicted");
            }
            for recent in &minted[10..] {
                assert!(st.tokens.contains_key(recent), "recent token {recent} should still be active");
            }
        }

        // Verify `seen_external` is strictly bounded to `MAX_SEEN_EXTERNAL_PER_MISSION`.
        let mut bucket = MissionBucket::default();
        for i in 0..(MAX_SEEN_EXTERNAL_PER_MISSION + 25) {
            assert!(remember_external(&mut bucket, format!("ext-{i}")));
        }
        assert_eq!(bucket.seen_external.len(), MAX_SEEN_EXTERNAL_PER_MISSION);
        assert_eq!(bucket.seen_external_order.len(), MAX_SEEN_EXTERNAL_PER_MISSION);
        assert!(!bucket.seen_external.contains("ext-0"));
        assert!(bucket.seen_external.contains(&format!("ext-{}", MAX_SEEN_EXTERNAL_PER_MISSION + 24)));
        // Duplicate of a still-tracked key returns false.
        assert!(!remember_external(&mut bucket, format!("ext-{}", MAX_SEEN_EXTERNAL_PER_MISSION + 24)));
        broker.shutdown();
    }

    #[tokio::test]
    async fn external_poll_routes_sibling_missions_without_dropping_on_destructive_pop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let popped = Arc::new(AtomicBool::new(false));
        let tokens_shared = Arc::new(Mutex::new((String::new(), String::new())));
        let popped_srv = popped.clone();
        let tokens_srv = tokens_shared.clone();

        // Destructive-pop external OAST endpoint: returns BOTH mission A and mission B callbacks on first poll,
        // then returns empty `[]` on every subsequent poll (matching Interactsh server semantics).
        let app = Router::new().route(
            "/poll",
            get(move || {
                let popped = popped_srv.clone();
                let tokens = tokens_srv.clone();
                async move {
                    if popped.swap(true, Ordering::SeqCst) {
                        return json!({"data": []}).to_string();
                    }
                    let (tok_a, tok_b) = tokens.lock().unwrap().clone();
                    json!({
                        "data": [
                            {
                                "id": "pop-a-1",
                                "protocol": "http",
                                "unique-id": tok_a,
                                "remote-address": "198.51.100.1",
                                "method": "GET",
                                "path": format!("/oast/{tok_a}")
                            },
                            {
                                "id": "pop-b-1",
                                "protocol": "dns",
                                "unique-id": tok_b,
                                "remote-address": "198.51.100.2",
                                "qname": format!("{tok_b}.oast.example.test")
                            }
                        ]
                    })
                    .to_string()
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cfg = OastCfg {
            enabled: true,
            mode: OastMode::External,
            bind: "127.0.0.1:0".into(),
            public_host: Some("oast.example.test".into()),
            dns_bind: None,
            external_poll_url: Some(format!("http://{addr}/poll")),
            external_token_file: None,
        };
        let broker = OastBroker::start(&cfg).await.unwrap();
        let mint_a = broker.mint("mission-a", "sa", Some("a"), None);
        let mint_b = broker.mint("mission-b", "sb", Some("b"), None);
        *tokens_shared.lock().unwrap() = (mint_a.token.clone(), mint_b.token.clone());

        // Mission A polls FIRST and drains the destructive external endpoint -> sees ONLY mission A's hit.
        let hits_a = broker.poll("mission-a", None, None).await.unwrap();
        assert_eq!(hits_a.len(), 1, "{hits_a:?}");
        assert_eq!(hits_a[0].token, mint_a.token);
        assert_eq!(hits_a[0].mission, "mission-a");
        // Mission A still CANNOT see mission B's callback even by guessing B's token.
        assert!(broker.poll("mission-a", Some(&mint_b.token), None).await.unwrap().is_empty());

        // Mission B polls SECOND (external endpoint now returns `[]`) -> STILL receives its routed callback!
        let hits_b = broker.poll("mission-b", None, None).await.unwrap();
        assert_eq!(hits_b.len(), 1, "{hits_b:?}");
        assert_eq!(hits_b[0].token, mint_b.token);
        assert_eq!(hits_b[0].mission, "mission-b");
        assert_eq!(hits_b[0].protocol, "dns");

        srv.abort();
    }
}
