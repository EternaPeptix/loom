//! Operator-scoped, strictly read-only email inbox (`[mail]`).
//!
//! CONTRACT.
//!
//! - Disabled by default (`MailCfg::enabled == false`). When enabled, [`MailCfg::allow_senders`]
//!   MUST be non-empty and never wildcard all senders (`*`, `*@*`).
//! - Every message is gated BEFORE its body is fetched or returned:
//!   1. `From:` addr-spec (extracted after stripping RFC 5322 quoted display names and comments so
//!      `"security@hackerone.com" <phisher@evil.test>` is rejected) — ALL parsed `From` addresses
//!      must match [`MailCfg::allow_senders`].
//!   2. When [`MailCfg::allow_recipients`] is non-empty, at least one address in `To` /
//!      `Delivered-To` / `X-Original-To` must match (supports plus-addressing such as
//!      `me+bb-*@gmail.com`).
//!   3. When [`MailCfg::require_auth_pass`] is true, an `Authentication-Results` header must
//!      report `dkim=pass` or `spf=pass`.
//!   4. When [`MailCfg::max_age_minutes`] > 0, messages older than the cutoff (or with no usable
//!      timestamp) are excluded.
//! - IMAPS connections use TLS (Mozilla roots via `webpki-root-certs`), open the folder strictly
//!   read-only with IMAP `EXAMINE` (never `SELECT`, `STORE`, `EXPUNGE`), and fetch headers and
//!   bodies with `BODY.PEEK[...]` so message flags (`\Seen`) are never mutated.
//! - Non-matching emails are never counted, named, or distinguishable from nonexistent IDs.

use base64::Engine as _;
use ferret_core::config::{MailAuth, MailBackend, MailCfg};
use regex::Regex;
use rustls::crypto::ring;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SCAN_UIDS: usize = 120;
const MAX_BODY_CHARS: usize = 16 * 1024;
const MAX_RAW_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_LINKS: usize = 25;
const MAX_CODES: usize = 10;

/// Compact summary of one permitted message returned by [`MailClient::list`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailSummary {
    pub id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub ts_secs: Option<i64>,
    pub auth_pass: bool,
}

/// Decoded permitted message returned by [`MailClient::read`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub date: String,
    pub auth_pass: bool,
    pub links: Vec<String>,
    pub codes: Vec<String>,
    pub body: String,
    pub body_truncated: bool,
}

/// Result of [`MailClient::check`] (`ferret mail check`). Never discloses credentials or non-matching mail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailCheckReport {
    pub backend: String,
    pub folder: String,
    pub matching_recent: usize,
    pub allow_senders: Vec<String>,
    pub allow_recipients: Vec<String>,
    pub require_auth_pass: bool,
    pub max_age_minutes: u64,
}

/// Read-only scoped email client bound to one [`MailCfg`].
#[derive(Clone, Debug)]
pub struct MailClient {
    cfg: MailCfg,
}

impl MailClient {
    pub fn new(cfg: MailCfg) -> Self {
        Self { cfg }
    }

    pub fn config(&self) -> &MailCfg {
        &self.cfg
    }

    /// List recent messages permitted by policy, newest first.
    pub async fn list(&self, query: Option<&str>, limit: Option<usize>) -> Result<Vec<MailSummary>, String> {
        self.ensure_enabled()?;
        let cap = limit.unwrap_or(self.cfg.max_messages).clamp(1, self.cfg.max_messages.min(50));
        let now = now_unix_secs();
        let mut items = match self.cfg.backend {
            MailBackend::Imaps => self.imaps_list(now).await?,
            MailBackend::Maildir => self.maildir_list(now)?,
        };
        if let Some(q) = query.map(str::trim).filter(|s| !s.is_empty()) {
            let ql = q.to_ascii_lowercase();
            items.retain(|m| {
                m.subject.to_ascii_lowercase().contains(&ql) || m.from.to_ascii_lowercase().contains(&ql)
            });
        }
        items.sort_by(|a, b| b.ts_secs.cmp(&a.ts_secs).then_with(|| b.id.cmp(&a.id)));
        items.truncate(cap);
        Ok(items)
    }

    /// Read one permitted message by id, decoding MIME/HTML and extracting activation links and OTP codes.
    pub async fn read(&self, id: &str) -> Result<MailMessage, String> {
        self.ensure_enabled()?;
        let id = id.trim();
        if id.is_empty() {
            return Err("Provide a message `id` from an `inbox_read` listing.".into());
        }
        let now = now_unix_secs();
        match self.cfg.backend {
            MailBackend::Imaps => self.imaps_read(id, now).await,
            MailBackend::Maildir => self.maildir_read(id, now),
        }
    }

    /// Verify config, credentials, read-only mailbox access, and report how many recent messages pass policy.
    pub async fn check(&self) -> Result<MailCheckReport, String> {
        self.ensure_enabled()?;
        let now = now_unix_secs();
        let items = match self.cfg.backend {
            MailBackend::Imaps => self.imaps_list(now).await?,
            MailBackend::Maildir => self.maildir_list(now)?,
        };
        Ok(MailCheckReport {
            backend: match self.cfg.backend {
                MailBackend::Imaps => format!("imaps ({}:{})", self.cfg.host, self.cfg.port),
                MailBackend::Maildir => {
                    format!("maildir ({})", self.cfg.maildir_path.as_deref().unwrap_or(""))
                }
            },
            folder: match self.cfg.backend {
                MailBackend::Imaps => self.cfg.folder.clone(),
                MailBackend::Maildir => self.cfg.maildir_path.clone().unwrap_or_default(),
            },
            matching_recent: items.len(),
            allow_senders: self.cfg.allow_senders.clone(),
            allow_recipients: self.cfg.allow_recipients.clone(),
            require_auth_pass: self.cfg.require_auth_pass,
            max_age_minutes: self.cfg.max_age_minutes,
        })
    }

    fn ensure_enabled(&self) -> Result<(), String> {
        if !self.cfg.enabled {
            return Err("Scoped email inbox is disabled (`[mail] enabled = false`).".into());
        }
        self.cfg.check()
    }

    // -------------------------------------------------------------------------
    // Maildir backend (local lab / test / offline sync)
    // -------------------------------------------------------------------------

    fn maildir_files(&self) -> Result<Vec<(String, PathBuf)>, String> {
        let raw_dir = self
            .cfg
            .maildir_path
            .as_deref()
            .ok_or_else(|| "mail.maildir_path is not configured.".to_string())?;
        let root = expand_tilde(raw_dir);
        if !root.is_dir() {
            return Err(format!("Configured maildir `{}` does not exist or is not a directory.", root.display()));
        }
        let mut out = Vec::new();
        let subdirs = [root.join("new"), root.join("cur"), root.clone()];
        let mut seen = BTreeSet::new();
        for dir in subdirs {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for entry in rd.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let Some(name) = path.file_name().and_then(|s| s.to_str()) else { continue };
                if name.starts_with('.') {
                    continue;
                }
                let prefix = if dir == root.join("new") {
                    "new/"
                } else if dir == root.join("cur") {
                    "cur/"
                } else {
                    ""
                };
                let id = format!("md:{prefix}{name}");
                if seen.insert(id.clone()) {
                    out.push((id, path));
                }
            }
        }
        Ok(out)
    }

    fn maildir_list(&self, now_secs: i64) -> Result<Vec<MailSummary>, String> {
        let files = self.maildir_files()?;
        let mut out = Vec::new();
        for (id, path) in files {
            let Ok(bytes) = read_bounded_file(&path, MAX_RAW_MESSAGE_BYTES) else { continue };
            let mtime = file_mtime_secs(&path);
            let (head, _) = split_head_body(&bytes);
            let headers = parse_headers(head);
            if let Some(summary) = evaluate_policy(&self.cfg, &id, &headers, mtime, now_secs) {
                out.push(summary);
            }
        }
        Ok(out)
    }

    fn maildir_read(&self, id: &str, now_secs: i64) -> Result<MailMessage, String> {
        let rel = id
            .strip_prefix("md:")
            .ok_or_else(|| format!("No permitted email with id `{id}` was found."))?;
        if rel.is_empty() || rel.contains("..") || rel.contains('\\') || rel.starts_with('/') {
            return Err(format!("No permitted email with id `{id}` was found."));
        }
        let files = self.maildir_files()?;
        let (_, path) = files
            .into_iter()
            .find(|(fid, _)| fid == id)
            .ok_or_else(|| format!("No permitted email with id `{id}` was found."))?;
        let bytes = read_bounded_file(&path, MAX_RAW_MESSAGE_BYTES)
            .map_err(|_| format!("No permitted email with id `{id}` was found."))?;
        let mtime = file_mtime_secs(&path);
        let (head, _) = split_head_body(&bytes);
        let headers = parse_headers(head);
        let summary = evaluate_policy(&self.cfg, id, &headers, mtime, now_secs)
            .ok_or_else(|| format!("No permitted email with id `{id}` was found."))?;
        Ok(decode_message(summary, &bytes))
    }

    // -------------------------------------------------------------------------
    // IMAPS backend (strictly read-only: EXAMINE + BODY.PEEK)
    // -------------------------------------------------------------------------

    async fn imaps_connect(&self) -> Result<ImapConn<tokio_rustls::client::TlsStream<TcpStream>>, String> {
        let secret = read_password_file(
            self.cfg
                .password_file
                .as_deref()
                .ok_or_else(|| "mail.password_file is not configured.".to_string())?,
        )?;
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((self.cfg.host.as_str(), self.cfg.port)))
            .await
            .map_err(|_| format!("Timed out connecting to IMAPS server {}:{}.", self.cfg.host, self.cfg.port))?
            .map_err(|e| format!("Could not connect to IMAPS server {}:{}: {e}", self.cfg.host, self.cfg.port))?;

        let tls_cfg = imaps_tls_config()?;
        let server_name = ServerName::try_from(self.cfg.host.clone())
            .map_err(|_| format!("Invalid IMAPS server name `{}`.", self.cfg.host))?;
        let tls = tokio::time::timeout(CONNECT_TIMEOUT, TlsConnector::from(tls_cfg).connect(server_name, tcp))
            .await
            .map_err(|_| format!("TLS handshake timed out with IMAPS server {}.", self.cfg.host))?
            .map_err(|e| format!("TLS handshake failed with IMAPS server {}: {e}", self.cfg.host))?;

        let mut conn = ImapConn::new(tls);
        conn.read_greeting().await?;
        match self.cfg.auth {
            MailAuth::Login => conn.login(&self.cfg.username, &secret).await?,
            MailAuth::Xoauth2 => conn.authenticate_xoauth2(&self.cfg.username, &secret).await?,
        }
        conn.examine(&self.cfg.folder).await?;
        Ok(conn)
    }

    async fn imaps_list(&self, now_secs: i64) -> Result<Vec<MailSummary>, String> {
        let mut conn = self.imaps_connect().await?;
        let mut uids = if self.cfg.max_age_minutes > 0 {
            // Subtract 1 day to absorb server-timezone rounding; exact cutoff is enforced in Rust.
            let since_secs = now_secs.saturating_sub((self.cfg.max_age_minutes as i64) * 60 + 86_400);
            let since = format_imap_date(since_secs);
            match conn.uid_search(&format!("SINCE {since}")).await {
                Ok(v) => v,
                Err(_) => conn.uid_search("ALL").await?,
            }
        } else {
            conn.uid_search("ALL").await?
        };
        uids.sort_unstable();
        if uids.len() > MAX_SCAN_UIDS {
            let cut = uids.len() - MAX_SCAN_UIDS;
            uids.drain(..cut);
        }
        let mut out = Vec::new();
        if !uids.is_empty() {
            let fetched = conn.uid_fetch_headers(&uids).await?;
            for item in fetched {
                let id = format!("uid:{}", item.uid);
                let headers = parse_headers(&item.header_bytes);
                let fallback_ts = item.internal_date.as_deref().and_then(parse_imap_internaldate);
                if let Some(summary) = evaluate_policy(&self.cfg, &id, &headers, fallback_ts, now_secs) {
                    out.push(summary);
                }
            }
        }
        let _ = conn.logout().await;
        Ok(out)
    }

    async fn imaps_read(&self, id: &str, now_secs: i64) -> Result<MailMessage, String> {
        let uid: u32 = id
            .strip_prefix("uid:")
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("No permitted email with id `{id}` was found."))?;

        let mut conn = self.imaps_connect().await?;
        let fetched = conn.uid_fetch_headers(&[uid]).await?;
        let Some(item) = fetched.into_iter().find(|f| f.uid == uid) else {
            let _ = conn.logout().await;
            return Err(format!("No permitted email with id `{id}` was found."));
        };
        let headers = parse_headers(&item.header_bytes);
        let fallback_ts = item.internal_date.as_deref().and_then(parse_imap_internaldate);
        let Some(summary) = evaluate_policy(&self.cfg, id, &headers, fallback_ts, now_secs) else {
            // Identical error for disallowed vs missing UIDs so personal inbox UIDs cannot be probed.
            let _ = conn.logout().await;
            return Err(format!("No permitted email with id `{id}` was found."));
        };
        let raw = conn.uid_fetch_raw_body(uid).await?;
        let _ = conn.logout().await;
        let Some(raw) = raw else {
            return Err(format!("No permitted email with id `{id}` was found."));
        };
        Ok(decode_message(summary, &raw))
    }
}

// =============================================================================
// Policy, Spoofing Defense & Address Matching
// =============================================================================

/// Evaluate whether a message's headers satisfy `[mail]` policy and return its summary if permitted.
pub fn evaluate_policy(
    cfg: &MailCfg,
    id: &str,
    headers: &[(String, String)],
    fallback_ts: Option<i64>,
    now_secs: i64,
) -> Option<MailSummary> {
    let from_vals = header_values(headers, "from");
    if from_vals.is_empty() {
        return None;
    }
    let mut from_addrs = Vec::new();
    for v in &from_vals {
        let extracted = extract_email_addresses(v);
        if extracted.is_empty() {
            return None;
        }
        from_addrs.extend(extracted);
    }
    // Every address in every From header must match allow_senders (prevents multi-From smuggling).
    if from_addrs.is_empty() || !from_addrs.iter().all(|a| sender_allowed(a, &cfg.allow_senders)) {
        return None;
    }

    let mut recip_addrs = Vec::new();
    for h in ["to", "delivered-to", "x-original-to"] {
        for v in header_values(headers, h) {
            recip_addrs.extend(extract_email_addresses(&v));
        }
    }
    if !recipient_allowed(&recip_addrs, &cfg.allow_recipients) {
        return None;
    }

    let auth_pass = auth_results_pass(headers);
    if cfg.require_auth_pass && !auth_pass {
        return None;
    }

    let date_raw = header_first(headers, "date").unwrap_or_default();
    let ts_secs = parse_rfc2822_timestamp(&date_raw).or(fallback_ts);
    if cfg.max_age_minutes > 0 {
        let msg_ts = ts_secs?;
        let cutoff = now_secs.saturating_sub((cfg.max_age_minutes as i64) * 60);
        if msg_ts < cutoff {
            return None;
        }
    }

    let subject = decode_rfc2047(&header_first(headers, "subject").unwrap_or_default());
    let to_display = if recip_addrs.is_empty() {
        header_first(headers, "to").map(|s| decode_rfc2047(&s)).unwrap_or_default()
    } else {
        recip_addrs.join(", ")
    };

    Some(MailSummary {
        id: id.to_string(),
        from: from_addrs.join(", "),
        to: to_display,
        subject,
        date: date_raw,
        ts_secs,
        auth_pass,
    })
}

/// Extract RFC 5322 addr-spec addresses from a header value, stripping quoted display names and comments
/// so display-name spoofing like `"security@hackerone.com" <attacker@evil.test>` yields only `attacker@evil.test`.
pub fn extract_email_addresses(raw: &str) -> Vec<String> {
    let cleaned = strip_rfc5322_quotes_and_comments(raw);
    let mut out = Vec::new();
    for part in cleaned.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let candidate = if let Some(lt) = p.find('<') {
            if let Some(gt) = p[lt + 1..].find('>') {
                p[lt + 1..lt + 1 + gt].trim()
            } else {
                continue;
            }
        } else {
            p
        };
        if let Some(norm) = normalize_addr_spec(candidate) {
            if !out.contains(&norm) {
                out.push(norm);
            }
        }
    }
    out
}

fn strip_rfc5322_quotes_and_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_quote = false;
    let mut comment_depth = 0usize;
    while let Some(c) = chars.next() {
        if in_quote {
            if c == '\\' {
                let _ = chars.next();
            } else if c == '"' {
                in_quote = false;
                out.push(' ');
            }
            continue;
        }
        if comment_depth > 0 {
            if c == '\\' {
                let _ = chars.next();
            } else if c == '(' {
                comment_depth += 1;
            } else if c == ')' {
                comment_depth -= 1;
                if comment_depth == 0 {
                    out.push(' ');
                }
            }
            continue;
        }
        match c {
            '"' => in_quote = true,
            '(' => comment_depth = 1,
            _ => out.push(c),
        }
    }
    out
}

fn normalize_addr_spec(raw: &str) -> Option<String> {
    // Strip optional RFC 5322 source route `@host1,@host2:user@domain`
    let s = raw.rsplit(':').next().unwrap_or(raw).trim();
    let (local, domain) = s.split_once('@')?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return None;
    }
    if local.chars().any(char::is_whitespace) || domain.chars().any(char::is_whitespace) {
        return None;
    }
    let dom = domain.trim_end_matches('.').to_ascii_lowercase();
    if dom.is_empty() || !dom.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.')) {
        return None;
    }
    Some(format!("{}@{}", local.to_ascii_lowercase(), dom))
}

/// Match a normalized `local@domain` against an allowlist of patterns (`exact@dom`, `*@dom`,
/// `*@*.dom`, `prefix-*@dom`, `me+bb-*@gmail.com`).
pub fn addr_matches_pattern(addr: &str, pattern: &str) -> bool {
    let pat = pattern.trim().to_ascii_lowercase();
    let Some((pat_local, pat_dom_raw)) = pat.split_once('@') else {
        return false;
    };
    let pat_dom = pat_dom_raw.trim_end_matches('.');
    if pat_local.is_empty() || pat_dom.is_empty() || pat_dom == "*" {
        return false;
    }
    let Some((addr_local, addr_dom)) = addr.split_once('@') else {
        return false;
    };
    let domain_ok = if let Some(suffix) = pat_dom.strip_prefix("*.") {
        !suffix.is_empty()
            && !suffix.contains('*')
            && addr_dom.len() > suffix.len() + 1
            && addr_dom.ends_with(suffix)
            && addr_dom.as_bytes()[addr_dom.len() - suffix.len() - 1] == b'.'
    } else {
        !pat_dom.contains('*') && addr_dom == pat_dom
    };
    if !domain_ok {
        return false;
    }
    wildcard_match(pat_local, addr_local)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (None, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

pub fn sender_allowed(addr: &str, patterns: &[String]) -> bool {
    let Some(norm) = normalize_addr_spec(addr) else { return false };
    patterns.iter().any(|p| addr_matches_pattern(&norm, p))
}

pub fn recipient_allowed(addrs: &[String], patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    addrs.iter().any(|a| patterns.iter().any(|p| addr_matches_pattern(a, p)))
}

/// True when any `Authentication-Results` header reports `dkim=pass` or `spf=pass` as a standalone token.
pub fn auth_results_pass(headers: &[(String, String)]) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)(?:^|[\s;(])(?:dkim|spf)=pass(?:$|[\s;)])").unwrap());
    header_values(headers, "authentication-results").iter().any(|v| re.is_match(v))
}

// =============================================================================
// MIME, Header & Link/OTP Decoding
// =============================================================================

fn split_head_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return (&raw[..pos], &raw[pos + 4..]);
    }
    if let Some(pos) = raw.windows(2).position(|w| w == b"\n\n") {
        return (&raw[..pos], &raw[pos + 2..]);
    }
    (raw, &[])
}

fn parse_headers(head: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(head);
    let mut out: Vec<(String, String)> = Vec::new();
    for raw_line in text.split('\n') {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, val)) = out.last_mut() {
                val.push(' ');
                val.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, val)) = line.split_once(':') {
            out.push((name.trim().to_string(), val.trim().to_string()));
        }
    }
    out
}

fn header_values(headers: &[(String, String)], name: &str) -> Vec<String> {
    headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone()).collect()
}

fn header_first(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

/// Decode RFC 2047 encoded words (`=?UTF-8?B?...?=` and `=?UTF-8?Q?...?=`).
pub fn decode_rfc2047(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)=\?([^?]+)\?([BQ])\?([^?]*)\?=").unwrap());
    let mut out = String::with_capacity(input.len());
    let mut last = 0usize;
    for caps in re.captures_iter(input) {
        let m = caps.get(0).unwrap();
        let between = &input[last..m.start()];
        // RFC 2047 §6.2: whitespace solely between adjacent encoded-words is ignored.
        if last == 0 || !between.chars().all(char::is_whitespace) {
            out.push_str(between);
        }
        let enc = caps.get(2).map(|x| x.as_str()).unwrap_or("");
        let payload = caps.get(3).map(|x| x.as_str()).unwrap_or("");
        let decoded = if enc.eq_ignore_ascii_case("B") {
            base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .ok()
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            Some(decode_q_header(payload))
        };
        out.push_str(decoded.as_deref().unwrap_or(m.as_str()));
        last = m.end();
    }
    out.push_str(&input[last..]);
    out
}

fn decode_q_header(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'_' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'=' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_quoted_printable(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'=' {
            if i + 2 < input.len() && input[i + 1] == b'\r' && input[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if i + 1 < input.len() && input[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            if i + 2 < input.len() {
                if let Ok(h) = std::str::from_utf8(&input[i + 1..i + 3]) {
                    if let Ok(v) = u8::from_str_radix(h, 16) {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                }
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn decode_transfer_encoding(encoding: Option<&str>, body: &[u8]) -> Vec<u8> {
    let enc = encoding.unwrap_or("").trim().to_ascii_lowercase();
    if enc == "base64" {
        let compact: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(&compact).unwrap_or_else(|_| body.to_vec())
    } else if enc == "quoted-printable" {
        decode_quoted_printable(body)
    } else {
        body.to_vec()
    }
}

fn extract_boundary(content_type: &str) -> Option<String> {
    for part in content_type.split(';').skip(1) {
        let p = part.trim();
        if let Some((k, v)) = p.split_once('=') {
            if k.trim().eq_ignore_ascii_case("boundary") {
                let b = v.trim().trim_matches('"').trim_matches('\'');
                if !b.is_empty() {
                    return Some(b.to_string());
                }
            }
        }
    }
    None
}

struct ExtractedParts {
    plain: Vec<String>,
    html: Vec<String>,
}

fn collect_mime_parts(headers: &[(String, String)], body: &[u8], depth: usize, out: &mut ExtractedParts) {
    if depth > 4 {
        return;
    }
    let ct = header_first(headers, "content-type").unwrap_or_else(|| "text/plain".to_string());
    let ct_lower = ct.to_ascii_lowercase();
    let media = ct_lower.split(';').next().unwrap_or("text/plain").trim();

    if media.starts_with("multipart/") {
        let Some(boundary) = extract_boundary(&ct) else { return };
        let marker = format!("--{boundary}");
        let text = String::from_utf8_lossy(body);
        for chunk in text.split(&marker).skip(1) {
            if chunk.starts_with("--") {
                break;
            }
            let chunk = chunk.strip_prefix("\r\n").or_else(|| chunk.strip_prefix('\n')).unwrap_or(chunk);
            let (phead, pbody) = split_head_body(chunk.as_bytes());
            let pheaders = parse_headers(phead);
            collect_mime_parts(&pheaders, pbody, depth + 1, out);
        }
        return;
    }

    let cte = header_first(headers, "content-transfer-encoding");
    let decoded = decode_transfer_encoding(cte.as_deref(), body);
    let text = String::from_utf8_lossy(&decoded).into_owned();
    if media == "text/html" {
        out.html.push(text);
    } else if media.starts_with("text/") || media.is_empty() {
        out.plain.push(text);
    }
}

fn decode_message(summary: MailSummary, raw: &[u8]) -> MailMessage {
    let (head, body) = split_head_body(raw);
    let headers = parse_headers(head);
    let mut parts = ExtractedParts { plain: Vec::new(), html: Vec::new() };
    collect_mime_parts(&headers, body, 0, &mut parts);

    let html_joined = (!parts.html.is_empty()).then(|| parts.html.join("\n"));
    let plain_text = if !parts.plain.is_empty() {
        parts.plain.join("\n\n")
    } else if let Some(html) = &html_joined {
        html2text::from_read(html.as_bytes(), 100).unwrap_or_else(|_| html.clone())
    } else {
        String::new()
    };

    let links = extract_links(&plain_text, html_joined.as_deref());
    let codes = extract_codes(&summary.subject, &plain_text);

    let mut body_out = plain_text.trim().to_string();
    let mut body_truncated = false;
    if body_out.chars().count() > MAX_BODY_CHARS {
        body_out = body_out.chars().take(MAX_BODY_CHARS).collect();
        body_truncated = true;
    }

    MailMessage {
        id: summary.id,
        from: summary.from,
        to: summary.to,
        subject: summary.subject,
        date: summary.date,
        auth_pass: summary.auth_pass,
        links,
        codes,
        body: body_out,
        body_truncated,
    }
}

/// Extract deduplicated `http(s)://` URLs from plain text and raw HTML `href="..."` attributes.
pub fn extract_links(plain: &str, html: Option<&str>) -> Vec<String> {
    static URL_RE: OnceLock<Regex> = OnceLock::new();
    static HREF_RE: OnceLock<Regex> = OnceLock::new();
    let url_re = URL_RE.get_or_init(|| Regex::new(r#"https?://[^\s<>"'`]+"#).unwrap());
    let href_re = HREF_RE.get_or_init(|| Regex::new(r#"(?i)href\s*=\s*["'](https?://[^"']+)["']"#).unwrap());

    let mut out = Vec::new();
    let mut push = |raw: &str| {
        if out.len() >= MAX_LINKS {
            return;
        }
        let unescaped = raw.replace("&amp;", "&").replace("&#38;", "&");
        let trimmed = unescaped.trim_end_matches(['.', ',', ';', ':', ')', ']', '>', '"', '\'']);
        if !trimmed.is_empty() && !out.iter().any(|x| x == trimmed) {
            out.push(trimmed.to_string());
        }
    };

    if let Some(h) = html {
        for caps in href_re.captures_iter(h) {
            if let Some(m) = caps.get(1) {
                push(m.as_str());
            }
        }
    }
    for m in url_re.find_iter(plain) {
        push(m.as_str());
    }
    out
}

/// Extract likely 4–8 digit OTP / verification codes occurring near verification context words.
pub fn extract_codes(subject: &str, text: &str) -> Vec<String> {
    static CTX_RE: OnceLock<Regex> = OnceLock::new();
    static DIGITS_RE: OnceLock<Regex> = OnceLock::new();
    let ctx_re = CTX_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:code|otp|verif(?:y|ication)|pin|passcode|token|confirm(?:ation)?|one[- ]time|2fa|mfa|login|sign[- ]?in)\b")
            .unwrap()
    });
    let digits_re = DIGITS_RE.get_or_init(|| Regex::new(r"\b(\d{4,8}|\d{3}-\d{3})\b").unwrap());

    let mut out = Vec::new();
    let combined = format!("{subject}\n{text}");
    for line in combined.lines() {
        if !ctx_re.is_match(line) {
            continue;
        }
        for caps in digits_re.captures_iter(line) {
            if out.len() >= MAX_CODES {
                return out;
            }
            let code = caps.get(1).unwrap().as_str().to_string();
            // Skip plain years like 2025/2026 when 4 digits.
            if code.len() == 4 && (code.starts_with("19") || code.starts_with("20")) {
                continue;
            }
            if !out.contains(&code) {
                out.push(code);
            }
        }
    }
    out
}

// =============================================================================
// Dates & Credential File Helpers
// =============================================================================

fn now_unix_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

fn file_mtime_secs(path: &Path) -> Option<i64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

fn read_bounded_file(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    f.by_ref().take(max_bytes as u64).read_to_end(&mut buf)?;
    Ok(buf)
}

fn expand_tilde(path: &str) -> PathBuf {
    let trimmed = path.trim();
    if let Some(rest) = trimmed.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(trimmed)
}

/// Read an IMAP password or OAuth2 bearer token from a private (`0600`) file.
pub fn read_password_file(path: &str) -> Result<String, String> {
    let p = expand_tilde(path);
    let meta = std::fs::metadata(&p)
        .map_err(|e| format!("Could not read mail.password_file `{}`: {e}", p.display()))?;
    if !meta.is_file() {
        return Err(format!("mail.password_file `{}` must be a regular file.", p.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "mail.password_file `{}` has permissions {:04o}; make it owner-only first (`chmod 600 {}`).",
                p.display(),
                mode,
                p.display()
            ));
        }
    }
    let raw = std::fs::read_to_string(&p)
        .map_err(|e| format!("Could not read mail.password_file `{}`: {e}", p.display()))?;
    let secret = raw.trim_end_matches(&['\r', '\n'][..]).to_string();
    if secret.is_empty() {
        return Err(format!("mail.password_file `{}` is empty.", p.display()));
    }
    Ok(secret)
}

fn month_num(mon: &str) -> Option<u32> {
    match mon.to_ascii_lowercase().as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let m = u64::from(m);
    let d = u64::from(d);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m as u32, d as u32)
}

fn format_imap_date(unix_secs: i64) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let days = unix_secs.div_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let mon = MONTHS.get((m.saturating_sub(1)) as usize).copied().unwrap_or("Jan");
    format!("{d:02}-{mon}-{y:04}")
}

fn parse_tz_offset(tok: &str) -> i64 {
    let t = tok.trim();
    if (t.starts_with('+') || t.starts_with('-')) && t.len() == 5 {
        if let (Ok(hh), Ok(mm)) = (t[1..3].parse::<i64>(), t[3..5].parse::<i64>()) {
            let sign = if t.starts_with('-') { -1 } else { 1 };
            return sign * (hh * 3600 + mm * 60);
        }
    }
    match t.to_ascii_uppercase().as_str() {
        "UTC" | "GMT" | "UT" | "Z" => 0,
        "EDT" => -4 * 3600,
        "EST" | "CDT" => -5 * 3600,
        "CST" | "MDT" => -6 * 3600,
        "MST" | "PDT" => -7 * 3600,
        "PST" => -8 * 3600,
        _ => 0,
    }
}

/// Parse an RFC 2822 / RFC 5322 `Date:` header into UTC Unix seconds.
pub fn parse_rfc2822_timestamp(raw: &str) -> Option<i64> {
    let cleaned = strip_rfc5322_quotes_and_comments(raw);
    let s = match cleaned.split_once(',') {
        Some((_, rest)) => rest.trim(),
        None => cleaned.trim(),
    };
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 4 {
        return None;
    }
    let day: u32 = parts[0].parse().ok()?;
    let mon = month_num(parts[1])?;
    let mut year: i64 = parts[2].parse().ok()?;
    if year < 100 {
        year += if year >= 50 { 1900 } else { 2000 };
    }
    let hms: Vec<&str> = parts[3].split(':').collect();
    if hms.len() < 2 {
        return None;
    }
    let hh: i64 = hms[0].parse().ok()?;
    let mm: i64 = hms[1].parse().ok()?;
    let ss: i64 = hms.get(2).and_then(|v| v.parse().ok()).unwrap_or(0);
    if !(1..=31).contains(&day) || !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    let tz = parts.get(4).map(|t| parse_tz_offset(t)).unwrap_or(0);
    let days = days_from_civil(year, mon, day);
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss - tz)
}

/// Parse IMAP `INTERNALDATE` (`"27-Nov-2026 14:05:10 +0000"`) into UTC Unix seconds.
pub fn parse_imap_internaldate(raw: &str) -> Option<i64> {
    let s = raw.trim().trim_matches('"');
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let dmy: Vec<&str> = parts[0].split('-').collect();
    if dmy.len() != 3 {
        return None;
    }
    let reassembled = format!("{} {} {} {} {}", dmy[0], dmy[1], dmy[2], parts[1], parts.get(2).copied().unwrap_or("+0000"));
    parse_rfc2822_timestamp(&reassembled)
}

// =============================================================================
// Minimal Read-Only Async IMAP4rev1 Protocol Client
// =============================================================================

fn imaps_tls_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("IMAPS TLS config: {e}"))?;
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
    Ok(Arc::new(builder.with_root_certificates(roots).with_no_client_auth()))
}

fn imap_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[derive(Debug)]
struct ImapUntagged {
    line: String,
    literals: Vec<Vec<u8>>,
}

struct FetchedHeader {
    uid: u32,
    internal_date: Option<String>,
    header_bytes: Vec<u8>,
}

struct ImapConn<S> {
    reader: BufReader<S>,
    tag_seq: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ImapConn<S> {
    fn new(stream: S) -> Self {
        Self { reader: BufReader::new(stream), tag_seq: 0 }
    }

    fn next_tag(&mut self) -> String {
        self.tag_seq += 1;
        format!("A{:04}", self.tag_seq)
    }

    async fn read_line_raw(&mut self) -> Result<String, String> {
        let mut buf = Vec::new();
        let n = tokio::time::timeout(IO_TIMEOUT, self.reader.read_until(b'\n', &mut buf))
            .await
            .map_err(|_| "Timed out reading from IMAPS server.".to_string())?
            .map_err(|e| format!("IMAPS read error: {e}"))?;
        if n == 0 {
            return Err("IMAPS server closed the connection unexpectedly.".into());
        }
        Ok(String::from_utf8_lossy(&buf).trim_end_matches(&['\r', '\n'][..]).to_string())
    }

    async fn read_exact_literal(&mut self, len: usize) -> Result<Vec<u8>, String> {
        if len > MAX_RAW_MESSAGE_BYTES {
            return Err(format!("IMAPS literal exceeds {MAX_RAW_MESSAGE_BYTES} byte cap."));
        }
        let mut buf = vec![0u8; len];
        tokio::time::timeout(IO_TIMEOUT, self.reader.read_exact(&mut buf))
            .await
            .map_err(|_| "Timed out reading IMAPS literal.".to_string())?
            .map_err(|e| format!("IMAPS literal read error: {e}"))?;
        Ok(buf)
    }

    async fn read_greeting(&mut self) -> Result<(), String> {
        let line = self.read_line_raw().await?;
        if !line.starts_with("* OK") && !line.starts_with("* PREAUTH") {
            return Err(format!("Unexpected IMAPS server greeting: {line}"));
        }
        Ok(())
    }

    async fn command(&mut self, cmd: &str) -> Result<Vec<ImapUntagged>, String> {
        let tag = self.next_tag();
        let wire = format!("{tag} {cmd}\r\n");
        tokio::time::timeout(IO_TIMEOUT, self.reader.get_mut().write_all(wire.as_bytes()))
            .await
            .map_err(|_| "Timed out writing to IMAPS server.".to_string())?
            .map_err(|e| format!("IMAPS write error: {e}"))?;
        tokio::time::timeout(IO_TIMEOUT, self.reader.get_mut().flush())
            .await
            .map_err(|_| "Timed out flushing IMAPS command.".to_string())?
            .map_err(|e| format!("IMAPS flush error: {e}"))?;

        let mut untagged = Vec::new();
        loop {
            let mut full_line = self.read_line_raw().await?;
            let mut literals = Vec::new();
            while let Some(lit_len) = trailing_literal_len(&full_line) {
                let data = self.read_exact_literal(lit_len).await?;
                literals.push(data);
                let cont = self.read_line_raw().await?;
                full_line.push(' ');
                full_line.push_str(&cont);
            }
            if let Some(rest) = full_line.strip_prefix(&format!("{tag} ")) {
                if rest.starts_with("OK") {
                    return Ok(untagged);
                }
                return Err(format!("IMAPS command rejected: {rest}"));
            }
            if full_line.starts_with('*') {
                untagged.push(ImapUntagged { line: full_line, literals });
            }
        }
    }

    async fn login(&mut self, user: &str, pass: &str) -> Result<(), String> {
        // Never include credentials in returned errors.
        let cmd = format!("LOGIN {} {}", imap_quote(user), imap_quote(pass));
        self.command(&cmd)
            .await
            .map(|_| ())
            .map_err(|_| "IMAPS authentication failed (check mail.username and mail.password_file).".into())
    }

    async fn authenticate_xoauth2(&mut self, user: &str, token: &str) -> Result<(), String> {
        let sasl = format!("user={user}\x01auth=Bearer {token}\x01\x01");
        let b64 = base64::engine::general_purpose::STANDARD.encode(sasl.as_bytes());
        let cmd = format!("AUTHENTICATE XOAUTH2 {b64}");
        self.command(&cmd)
            .await
            .map(|_| ())
            .map_err(|_| "IMAPS XOAUTH2 authentication failed (check mail.username and OAuth2 bearer token).".into())
    }

    async fn examine(&mut self, folder: &str) -> Result<(), String> {
        // Strictly read-only EXAMINE (never SELECT).
        self.command(&format!("EXAMINE {}", imap_quote(folder)))
            .await
            .map(|_| ())
            .map_err(|e| format!("Could not open IMAPS folder `{folder}` read-only: {e}"))
    }

    async fn uid_search(&mut self, criteria: &str) -> Result<Vec<u32>, String> {
        let lines = self.command(&format!("UID SEARCH {criteria}")).await?;
        let mut uids = Vec::new();
        for item in lines {
            if let Some(rest) = item.line.strip_prefix("* SEARCH") {
                for tok in rest.split_whitespace() {
                    if let Ok(u) = tok.parse::<u32>() {
                        uids.push(u);
                    }
                }
            }
        }
        Ok(uids)
    }

    async fn uid_fetch_headers(&mut self, uids: &[u32]) -> Result<Vec<FetchedHeader>, String> {
        let seq: String = uids.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        let cmd = format!(
            "UID FETCH {seq} (UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM TO DELIVERED-TO X-ORIGINAL-TO SUBJECT DATE MESSAGE-ID AUTHENTICATION-RESULTS)])"
        );
        let lines = self.command(&cmd).await?;
        let mut out = Vec::new();
        for item in lines {
            if !item.line.contains("FETCH") {
                continue;
            }
            let Some(uid) = extract_imap_uid(&item.line) else { continue };
            let internal_date = extract_imap_internaldate(&item.line);
            let header_bytes = item.literals.into_iter().next().unwrap_or_default();
            out.push(FetchedHeader { uid, internal_date, header_bytes });
        }
        Ok(out)
    }

    async fn uid_fetch_raw_body(&mut self, uid: u32) -> Result<Option<Vec<u8>>, String> {
        let lines = self.command(&format!("UID FETCH {uid} (BODY.PEEK[])")).await?;
        for item in lines {
            if item.line.contains("FETCH") {
                if let Some(lit) = item.literals.into_iter().next() {
                    return Ok(Some(lit));
                }
            }
        }
        Ok(None)
    }

    async fn logout(&mut self) -> Result<(), String> {
        let _ = self.command("LOGOUT").await;
        Ok(())
    }
}

fn trailing_literal_len(line: &str) -> Option<usize> {
    let trimmed = line.trim_end();
    if !trimmed.ends_with('}') {
        return None;
    }
    let open = trimmed.rfind('{')?;
    trimmed[open + 1..trimmed.len() - 1].parse::<usize>().ok()
}

fn extract_imap_uid(line: &str) -> Option<u32> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)\bUID\s+(\d+)").unwrap());
    re.captures(line)?.get(1)?.as_str().parse().ok()
}

fn extract_imap_internaldate(line: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"(?i)\bINTERNALDATE\s+"([^"]+)""#).unwrap());
    Some(re.captures(line)?.get(1)?.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(dir: &Path) -> MailCfg {
        MailCfg {
            enabled: true,
            backend: MailBackend::Maildir,
            maildir_path: Some(dir.display().to_string()),
            allow_senders: vec![
                "*@hackerone.com".into(),
                "*@bugcrowd.com".into(),
                "*@*.target.example".into(),
            ],
            allow_recipients: vec!["me+bb-*@gmail.com".into()],
            require_auth_pass: true,
            max_age_minutes: 0,
            max_messages: 20,
            ..MailCfg::default()
        }
    }

    #[test]
    fn spoofing_display_name_and_wildcard_guards() {
        assert_eq!(
            extract_email_addresses(r#""security@hackerone.com" <phisher@evil.test>"#),
            vec!["phisher@evil.test".to_string()]
        );
        assert_eq!(
            extract_email_addresses("HackerOne (noreply@hackerone.com) <real@evil.test>"),
            vec!["real@evil.test".to_string()]
        );
        assert!(sender_allowed("noreply@hackerone.com", &["*@hackerone.com".into()]));
        assert!(!sender_allowed("noreply@evil-hackerone.com", &["*@hackerone.com".into()]));
        assert!(sender_allowed("auth@mail.target.example", &["*@*.target.example".into()]));
        assert!(!sender_allowed("auth@target.example", &["*@*.target.example".into()]));
        assert!(!sender_allowed("anyone@any.com", &["*@*".into()]));
        assert!(recipient_allowed(&["me+bb-h1@gmail.com".into()], &["me+bb-*@gmail.com".into()]));
        assert!(!recipient_allowed(&["me@gmail.com".into()], &["me+bb-*@gmail.com".into()]));
    }

    #[test]
    fn auth_results_and_dates_and_rfc2047() {
        let ok = vec![("Authentication-Results".into(), "mx.google.com; dkim=pass header.i=@hackerone.com; spf=pass".into())];
        let fail = vec![("Authentication-Results".into(), "mx.google.com; dkim=fail; spf=softfail".into())];
        assert!(auth_results_pass(&ok));
        assert!(!auth_results_pass(&fail));

        let ts = parse_rfc2822_timestamp("Fri, 27 Nov 2026 14:00:00 +0000").unwrap();
        let ts2 = parse_imap_internaldate("27-Nov-2026 14:00:00 +0000").unwrap();
        assert_eq!(ts, ts2);
        assert_eq!(format_imap_date(ts), "27-Nov-2026");

        assert_eq!(decode_rfc2047("=?UTF-8?B?QWN0aXZhdGUgeW91ciBhY2NvdW50?="), "Activate your account");
        assert_eq!(decode_rfc2047("=?UTF-8?Q?Verify_your_email=3A_123456?="), "Verify your email: 123456");
    }

    #[tokio::test]
    async fn maildir_enforces_policy_hides_personal_mail_and_extracts_links_and_otp() {
        let dir = tempfile::tempdir().unwrap();
        let new_dir = dir.path().join("new");
        std::fs::create_dir_all(&new_dir).unwrap();

        // 1. Permitted HackerOne activation email (multipart/alternative with HTML link + OTP)
        let allowed_eml = concat!(
            "From: \"HackerOne\" <no-reply@hackerone.com>\r\n",
            "To: me+bb-h1@gmail.com\r\n",
            "Subject: Confirm your HackerOne account\r\n",
            "Date: Fri, 27 Nov 2026 14:00:00 +0000\r\n",
            "Authentication-Results: mx.google.com; dkim=pass header.i=@hackerone.com\r\n",
            "Content-Type: multipart/alternative; boundary=\"b1\"\r\n",
            "\r\n",
            "--b1\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Your verification code is 849201.\r\n",
            "Activate here: https://hackerone.com/users/confirmation?token=abc123&next=1.\r\n",
            "--b1\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<p><a href=\"https://hackerone.com/users/confirmation?token=abc123&amp;next=1\">Activate</a></p>\r\n",
            "--b1--\r\n"
        );
        std::fs::write(new_dir.join("001.eml"), allowed_eml).unwrap();

        // 2. Personal bank email (MUST NOT appear and MUST NOT be readable by ID!)
        let personal_eml = concat!(
            "From: alerts@mybank.example\r\n",
            "To: me+bb-h1@gmail.com\r\n",
            "Subject: Bank statement\r\n",
            "Date: Fri, 27 Nov 2026 14:05:00 +0000\r\n",
            "Authentication-Results: mx.google.com; dkim=pass\r\n",
            "\r\n",
            "Secret personal balance.\r\n"
        );
        std::fs::write(new_dir.join("002.eml"), personal_eml).unwrap();

        // 3. Spoofed display name from evil sender (MUST be rejected)
        let spoofed_eml = concat!(
            "From: \"no-reply@hackerone.com\" <phish@evil.test>\r\n",
            "To: me+bb-h1@gmail.com\r\n",
            "Subject: Click me\r\n",
            "Date: Fri, 27 Nov 2026 14:06:00 +0000\r\n",
            "Authentication-Results: mx.google.com; dkim=pass\r\n",
            "\r\n",
            "https://evil.test/steal\r\n"
        );
        std::fs::write(new_dir.join("003.eml"), spoofed_eml).unwrap();

        // 4. Right sender but failed DKIM/SPF when require_auth_pass = true
        let unauth_eml = concat!(
            "From: no-reply@bugcrowd.com\r\n",
            "To: me+bb-h1@gmail.com\r\n",
            "Subject: Unauthenticated\r\n",
            "Date: Fri, 27 Nov 2026 14:07:00 +0000\r\n",
            "Authentication-Results: mx.google.com; dkim=fail; spf=fail\r\n",
            "\r\n",
            "Code: 999999\r\n"
        );
        std::fs::write(new_dir.join("004.eml"), unauth_eml).unwrap();

        let client = MailClient::new(test_cfg(dir.path()));
        let listed = client.list(None, None).await.unwrap();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0].id, "md:new/001.eml");
        assert_eq!(listed[0].from, "no-reply@hackerone.com");

        let msg = client.read("md:new/001.eml").await.unwrap();
        assert_eq!(msg.codes, vec!["849201"]);
        assert_eq!(msg.links, vec!["https://hackerone.com/users/confirmation?token=abc123&next=1"]);

        // Personal & spoofed messages return the exact same error as a nonexistent ID.
        let e_personal = client.read("md:new/002.eml").await.unwrap_err();
        let e_spoofed = client.read("md:new/003.eml").await.unwrap_err();
        let e_missing = client.read("md:new/999.eml").await.unwrap_err();
        assert!(e_personal.contains("No permitted email"));
        assert!(e_spoofed.contains("No permitted email"));
        assert!(e_missing.contains("No permitted email"));

        let report = client.check().await.unwrap();
        assert_eq!(report.matching_recent, 1);
    }

    #[tokio::test]
    async fn imap_client_parses_literals_and_uses_examine_read_only() {
        let (client_io, mut server_io) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            server_io.write_all(b"* OK [CAPABILITY IMAP4rev1] test ready\r\n").await.unwrap();
            let mut r = BufReader::new(server_io);
            let mut line = String::new();
            let mut saw_examine = false;
            loop {
                line.clear();
                if r.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let mut parts = line.trim().splitn(2, ' ');
                let tag = parts.next().unwrap().to_string();
                let rest = parts.next().unwrap_or("");
                if rest.starts_with("LOGIN ") {
                    r.get_mut().write_all(format!("{tag} OK LOGIN ok\r\n").as_bytes()).await.unwrap();
                } else if rest.starts_with("EXAMINE ") {
                    saw_examine = true;
                    r.get_mut().write_all(format!("* 1 EXISTS\r\n{tag} OK [READ-ONLY] EXAMINE ok\r\n").as_bytes()).await.unwrap();
                } else if rest.starts_with("UID SEARCH ") {
                    r.get_mut().write_all(format!("* SEARCH 7\r\n{tag} OK SEARCH ok\r\n").as_bytes()).await.unwrap();
                } else if rest.starts_with("UID FETCH 7 (UID INTERNALDATE") {
                    let hdr = b"From: noreply@bugcrowd.com\r\nTo: me+bb-bc@gmail.com\r\nSubject: Verify\r\nDate: Fri, 27 Nov 2026 14:00:00 +0000\r\n\r\n";
                    let resp = format!(
                        "* 1 FETCH (UID 7 INTERNALDATE \"27-Nov-2026 14:00:00 +0000\" BODY[HEADER.FIELDS (FROM TO DELIVERED-TO X-ORIGINAL-TO SUBJECT DATE MESSAGE-ID AUTHENTICATION-RESULTS)] {{{}}}\r\n",
                        hdr.len()
                    );
                    r.get_mut().write_all(resp.as_bytes()).await.unwrap();
                    r.get_mut().write_all(hdr).await.unwrap();
                    r.get_mut().write_all(format!(")\r\n{tag} OK FETCH ok\r\n").as_bytes()).await.unwrap();
                } else if rest.starts_with("LOGOUT") {
                    r.get_mut().write_all(format!("* BYE\r\n{tag} OK LOGOUT\r\n").as_bytes()).await.unwrap();
                    break;
                }
            }
            saw_examine
        });

        let mut conn = ImapConn::new(client_io);
        conn.read_greeting().await.unwrap();
        conn.login("alice", "secret").await.unwrap();
        conn.examine("INBOX").await.unwrap();
        let uids = conn.uid_search("ALL").await.unwrap();
        assert_eq!(uids, vec![7]);
        let hdrs = conn.uid_fetch_headers(&uids).await.unwrap();
        assert_eq!(hdrs.len(), 1);
        assert_eq!(hdrs[0].uid, 7);
        assert!(String::from_utf8_lossy(&hdrs[0].header_bytes).contains("noreply@bugcrowd.com"));
        conn.logout().await.unwrap();
        assert!(server.await.unwrap());
    }
}
