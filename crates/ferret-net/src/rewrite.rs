//! Origin-scoped assessment `User-Agent` and declarative operator-only HTTP proxy rewrite rules.
//!
//! CONTRACT.
//!
//! - [`AssessmentUa`] attaches `Ferret-Assessment/1.0` (or `Ferret-Assessment/1.0 (engagement=<ref>)`)
//!   ONLY on exact approved `(scheme, normalized_host, effective_port)` origins when a request has
//!   no explicit `User-Agent` header. Cross-origin redirects naturally drop the label because each
//!   hop is checked against its own destination origin.
//! - Declarative [`RewriteRule`]s are operator-only configuration (never exposed as an agent tool).
//!   Rules are created disabled (`enabled = false`), bounded (`MAX_RULES = 100`, `MAX_ENABLED = 50`,
//!   regex `<= 1 KiB`, values `<= 1 MiB`), forbid mutating framing/hop/Host/`Proxy-*` headers or
//!   setting method `CONNECT` or CR/LF/NUL bytes, run in `(priority ASC, id ASC)` order, and fail
//!   open atomically per rule.
//! - Actions marked `sensitive: true` never appear with plaintext `value` in API reads
//!   ([`RewriteRule::redacted_view`]) or `Debug` output, are AEAD-encrypted at rest in
//!   [`RewriteStore`] (`ring::aead::CHACHA20_POLY1305` using a `0600` key in `keys/rewrite.key`,
//!   with transparent migration of legacy plaintext values on load), are redacted before traffic
//!   capture, and retain stored values on update only when the rule's `host` matcher stays
//!   unchanged (preventing accidental secret redirection to a new host).

use base64::Engine as _;
use ferret_core::config::AssessmentUaCfg;
use ferret_core::creds::{Secrets, REDACTED};
use hmac::{Hmac, KeyInit, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const ENC_PREFIX: &str = "enc:v1:";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub const MAX_RULES: usize = 100;
pub const MAX_ENABLED_RULES: usize = 50;
pub const MAX_REGEX_BYTES: usize = 1024;
pub const MAX_VALUE_BYTES: usize = 1024 * 1024;
pub const MAX_REWRITE_BODY_BYTES: usize = 1024 * 1024;

const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "expect",
    "upgrade",
];

fn effective_port(scheme: &str, port: u16) -> u16 {
    if port != 0 {
        return port;
    }
    if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 }
}

/// Origin-scoped assessment identification header (`Ferret-Assessment/1.0 ...`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssessmentUa {
    origins: HashSet<(String, String, u16)>,
    value: String,
}

impl AssessmentUa {
    pub fn from_cfg(cfg: &AssessmentUaCfg) -> Result<Self, String> {
        cfg.check()?;
        let mut origins = HashSet::new();
        for raw in &cfg.origins {
            let u = url::Url::parse(raw.trim()).map_err(|e| format!("invalid origin `{raw}`: {e}"))?;
            let scheme = u.scheme().to_ascii_lowercase();
            let host = crate::inject::norm_host(u.host_str().unwrap_or(""));
            let port = u.port_or_known_default().unwrap_or_else(|| effective_port(&scheme, 0));
            origins.insert((scheme, host, port));
        }
        let value = match cfg.reference.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(r) => format!("Ferret-Assessment/1.0 (engagement={r})"),
            None => "Ferret-Assessment/1.0".to_string(),
        };
        Ok(Self { origins, value })
    }

    pub fn header_value(&self) -> &str {
        &self.value
    }

    pub fn matches(&self, scheme: &str, host: &str, port: u16) -> bool {
        let s = scheme.to_ascii_lowercase();
        let h = crate::inject::norm_host(host);
        let p = effective_port(&s, port);
        self.origins.contains(&(s, h, p))
    }

    /// Attach `User-Agent` when `(scheme, host, port)` is listed and the request carries no explicit
    /// `User-Agent` header. Returns `true` when added.
    pub fn apply_headers(&self, scheme: &str, host: &str, port: u16, headers: &mut Vec<(String, Vec<u8>)>) -> bool {
        if !self.matches(scheme, host, port) {
            return false;
        }
        if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("user-agent")) {
            return false;
        }
        headers.push(("User-Agent".to_string(), self.value.as_bytes().to_vec()));
        true
    }

    /// Attach `User-Agent` directly to a raw HTTP/1.1 request head when `(scheme, host, port)` matches
    /// and no explicit `User-Agent` header is present.
    pub fn apply_raw_request_head(&self, scheme: &str, host: &str, port: u16, raw_head: &[u8]) -> Option<Vec<u8>> {
        if !self.matches(scheme, host, port) {
            return None;
        }
        apply_default_ua_raw(raw_head, &self.value)
    }
}

/// Insert `User-Agent: <ua>` into a raw HTTP/1.1 request head when it has no explicit `User-Agent` header.
pub fn apply_default_ua_raw(raw_head: &[u8], ua: &str) -> Option<Vec<u8>> {
    if ua.trim().is_empty() || !no_crlf_nul(ua) {
        return None;
    }
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut slots);
    let n = match req.parse(raw_head) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return None,
    };
    if req.headers.iter().any(|h| h.name.eq_ignore_ascii_case("user-agent")) {
        return None;
    }
    let end = raw_head[..n]
        .windows(4)
        .rposition(|w| w == b"\r\n\r\n")
        .map(|i| i + 2)
        .or_else(|| raw_head[..n].windows(2).rposition(|w| w == b"\n\n").map(|i| i + 1))?;
    let mut out = Vec::with_capacity(raw_head.len() + ua.len() + 16);
    out.extend_from_slice(&raw_head[..end]);
    out.extend_from_slice(b"User-Agent: ");
    out.extend_from_slice(ua.trim().as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&raw_head[end..]);
    Some(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewritePhase {
    Request,
    Response,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    pub name: String,
    #[serde(default)]
    pub value_regex: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RewriteMatcher {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resp_headers: Vec<HeaderMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resp_body_regex: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RewriteAction {
    SetMethod {
        value: String,
    },
    SetPathQuery {
        value: String,
    },
    ReplaceUrl {
        regex: String,
        value: String,
    },
    DeleteHeader {
        name: String,
    },
    SetHeader {
        name: String,
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        sensitive: bool,
    },
    ReplaceHeader {
        name: String,
        regex: String,
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        sensitive: bool,
    },
    SetBody {
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        sensitive: bool,
    },
    ReplaceBody {
        regex: String,
        #[serde(default)]
        value: Option<String>,
        #[serde(default)]
        sensitive: bool,
    },
    SetStatus {
        value: u16,
    },
}

impl std::fmt::Debug for RewriteAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn shown(value: &Option<String>, sensitive: bool) -> Option<&str> {
            match (value.as_deref(), sensitive) {
                (Some(_), true) => Some(REDACTED),
                (v, false) => v,
                (None, true) => None,
            }
        }
        match self {
            RewriteAction::SetMethod { value } => f.debug_struct("SetMethod").field("value", value).finish(),
            RewriteAction::SetPathQuery { value } => f.debug_struct("SetPathQuery").field("value", value).finish(),
            RewriteAction::ReplaceUrl { regex, value } => {
                f.debug_struct("ReplaceUrl").field("regex", regex).field("value", value).finish()
            }
            RewriteAction::DeleteHeader { name } => f.debug_struct("DeleteHeader").field("name", name).finish(),
            RewriteAction::SetHeader { name, value, sensitive } => f
                .debug_struct("SetHeader")
                .field("name", name)
                .field("value", &shown(value, *sensitive))
                .field("sensitive", sensitive)
                .finish(),
            RewriteAction::ReplaceHeader { name, regex, value, sensitive } => f
                .debug_struct("ReplaceHeader")
                .field("name", name)
                .field("regex", regex)
                .field("value", &shown(value, *sensitive))
                .field("sensitive", sensitive)
                .finish(),
            RewriteAction::SetBody { value, sensitive } => f
                .debug_struct("SetBody")
                .field("value", &shown(value, *sensitive))
                .field("sensitive", sensitive)
                .finish(),
            RewriteAction::ReplaceBody { regex, value, sensitive } => f
                .debug_struct("ReplaceBody")
                .field("regex", regex)
                .field("value", &shown(value, *sensitive))
                .field("sensitive", sensitive)
                .finish(),
            RewriteAction::SetStatus { value } => f.debug_struct("SetStatus").field("value", value).finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewriteRule {
    #[serde(default)]
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    pub phase: RewritePhase,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub matchers: RewriteMatcher,
    pub actions: Vec<RewriteAction>,
    #[serde(default)]
    pub note: String,
}

fn forbidden_header(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    lower.is_empty()
        || lower.starts_with("proxy-")
        || FORBIDDEN_HEADERS.contains(&lower.as_str())
        || name.bytes().any(|b| b <= 0x20 || b == b':' || b >= 0x7f)
}

fn no_crlf_nul(s: &str) -> bool {
    !s.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

fn compile_re(pat: &str, field: &str) -> Result<Regex, String> {
    if pat.len() > MAX_REGEX_BYTES {
        return Err(format!("{field} regex exceeds {MAX_REGEX_BYTES} bytes."));
    }
    Regex::new(pat).map_err(|e| format!("invalid {field} regex: {e}"))
}

fn check_value_size(v: &str, field: &str) -> Result<(), String> {
    if v.len() > MAX_VALUE_BYTES {
        return Err(format!("{field} exceeds {MAX_VALUE_BYTES} bytes."));
    }
    Ok(())
}

fn valid_host_matcher(host: &str) -> Result<String, String> {
    let h = crate::inject::norm_host(host);
    if h.is_empty() || h.contains(':') || h.contains('/') || h.chars().any(char::is_whitespace) {
        return Err(format!("invalid host matcher `{host}`: give an exact host name or `*.suffix` without a port."));
    }
    if let Some(rest) = h.strip_prefix("*.") {
        if rest.is_empty() || rest.contains('*') {
            return Err(format!("invalid host matcher `{host}`: only a leading `*.` wildcard is allowed."));
        }
    } else if h.contains('*') {
        return Err(format!("invalid host matcher `{host}`: only a leading `*.` wildcard is allowed."));
    }
    Ok(h)
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let h = crate::inject::norm_host(host);
    if let Some(suffix) = pattern.strip_prefix("*.") {
        h.len() > suffix.len() + 1 && h.ends_with(suffix) && h.as_bytes()[h.len() - suffix.len() - 1] == b'.'
    } else {
        h == pattern
    }
}

fn status_matches(specs: &[String], status: u16) -> bool {
    if specs.is_empty() {
        return true;
    }
    specs.iter().any(|s| {
        let t = s.trim().to_ascii_lowercase();
        if let Some(digit) = t.strip_suffix("xx").filter(|d| d.len() == 1) {
            digit.parse::<u16>().ok().is_some_and(|c| status / 100 == c)
        } else {
            t.parse::<u16>().ok() == Some(status)
        }
    })
}

impl RewriteRule {
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() || self.name.len() > 200 || self.name.chars().any(char::is_control) {
            return Err("Rewrite rule `name` must be nonblank and at most 200 bytes without control characters.".into());
        }
        if self.actions.is_empty() || self.actions.len() > 32 {
            return Err("Rewrite rule must have between 1 and 32 actions.".into());
        }
        if let Some(h) = self.matchers.host.as_deref().filter(|s| !s.trim().is_empty()) {
            valid_host_matcher(h)?;
        }
        if let Some(re) = self.matchers.url_regex.as_deref().filter(|s| !s.is_empty()) {
            compile_re(re, "matchers.url_regex")?;
        }
        if let Some(re) = self.matchers.body_regex.as_deref().filter(|s| !s.is_empty()) {
            compile_re(re, "matchers.body_regex")?;
        }
        if let Some(re) = self.matchers.resp_body_regex.as_deref().filter(|s| !s.is_empty()) {
            if self.phase != RewritePhase::Response {
                return Err("matchers.resp_body_regex is only valid in the response phase.".into());
            }
            compile_re(re, "matchers.resp_body_regex")?;
        }
        if !self.matchers.status.is_empty() || !self.matchers.resp_headers.is_empty() {
            if self.phase != RewritePhase::Response {
                return Err("matchers.status and matchers.resp_headers are only valid in the response phase.".into());
            }
            for s in &self.matchers.status {
                let t = s.trim().to_ascii_lowercase();
                let ok_class = t.len() == 3 && t.ends_with("xx") && matches!(t.as_bytes()[0], b'1'..=b'5');
                let ok_code = t.parse::<u16>().is_ok_and(|c| (100..=599).contains(&c));
                if !ok_class && !ok_code {
                    return Err(format!("invalid status matcher `{s}` (use a code like `404` or class like `4xx`)."));
                }
            }
        }
        for hm in self.matchers.headers.iter().chain(&self.matchers.resp_headers) {
            if hm.name.trim().is_empty() || !no_crlf_nul(&hm.name) {
                return Err("Header matcher `name` cannot be blank or contain CR/LF/NUL.".into());
            }
            if !hm.value_regex.is_empty() {
                compile_re(&hm.value_regex, "header value_regex")?;
            }
        }
        for action in &self.actions {
            match action {
                RewriteAction::SetMethod { value } => {
                    if self.phase != RewritePhase::Request {
                        return Err("`set_method` is only valid in the request phase.".into());
                    }
                    let m = value.trim().to_ascii_uppercase();
                    if m.is_empty() || m == "CONNECT" || !m.bytes().all(|b| b.is_ascii_alphabetic()) {
                        return Err(format!("invalid `set_method` value `{value}` (`CONNECT` is refused)."));
                    }
                }
                RewriteAction::SetPathQuery { value } => {
                    if self.phase != RewritePhase::Request {
                        return Err("`set_path_query` is only valid in the request phase.".into());
                    }
                    if !value.starts_with('/') || !no_crlf_nul(value) || value.contains(' ') {
                        return Err("`set_path_query` must start with `/` and contain no spaces or control characters.".into());
                    }
                    check_value_size(value, "set_path_query")?;
                }
                RewriteAction::ReplaceUrl { regex, value } => {
                    if self.phase != RewritePhase::Request {
                        return Err("`replace_url` is only valid in the request phase.".into());
                    }
                    compile_re(regex, "replace_url.regex")?;
                    if !no_crlf_nul(value) {
                        return Err("`replace_url` value cannot contain CR/LF/NUL.".into());
                    }
                    check_value_size(value, "replace_url.value")?;
                }
                RewriteAction::DeleteHeader { name } => {
                    if forbidden_header(name) {
                        return Err(format!("header `{name}` cannot be modified by rewrite rules."));
                    }
                }
                RewriteAction::SetHeader { name, value, .. } => {
                    if forbidden_header(name) {
                        return Err(format!("header `{name}` cannot be modified by rewrite rules."));
                    }
                    let val = value.as_deref().ok_or_else(|| format!("`set_header` `{name}` requires `value`."))?;
                    if !no_crlf_nul(val) {
                        return Err(format!("header `{name}` value cannot contain CR/LF/NUL."));
                    }
                    check_value_size(val, "set_header.value")?;
                }
                RewriteAction::ReplaceHeader { name, regex, value, .. } => {
                    if forbidden_header(name) {
                        return Err(format!("header `{name}` cannot be modified by rewrite rules."));
                    }
                    compile_re(regex, "replace_header.regex")?;
                    let val = value.as_deref().ok_or_else(|| format!("`replace_header` `{name}` requires `value`."))?;
                    if !no_crlf_nul(val) {
                        return Err(format!("header `{name}` replacement cannot contain CR/LF/NUL."));
                    }
                    check_value_size(val, "replace_header.value")?;
                }
                RewriteAction::SetBody { value, .. } => {
                    let val = value.as_deref().ok_or_else(|| "`set_body` requires `value`.".to_string())?;
                    check_value_size(val, "set_body.value")?;
                }
                RewriteAction::ReplaceBody { regex, value, .. } => {
                    compile_re(regex, "replace_body.regex")?;
                    let val = value.as_deref().ok_or_else(|| "`replace_body` requires `value`.".to_string())?;
                    check_value_size(val, "replace_body.value")?;
                }
                RewriteAction::SetStatus { value } => {
                    if self.phase != RewritePhase::Response {
                        return Err("`set_status` is only valid in the response phase.".into());
                    }
                    if !(200..=599).contains(value) || matches!(value, 204 | 304) {
                        return Err(format!("`set_status` must be 200..=599 excluding 204 and 304 (got {value})."));
                    }
                }
            }
        }
        Ok(())
    }

    /// API-safe JSON view: any `sensitive: true` action omits `value` and emits `"value_set": true`.
    pub fn redacted_view(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(actions) = v.get_mut("actions").and_then(serde_json::Value::as_array_mut) {
            for a in actions {
                if let Some(obj) = a.as_object_mut() {
                    if obj.get("sensitive").and_then(serde_json::Value::as_bool) == Some(true) {
                        let had = obj.remove("value").is_some_and(|x| !x.is_null());
                        obj.insert("value_set".into(), serde_json::json!(had));
                    }
                }
            }
        }
        v
    }
}

/// Keyed HMAC-SHA256 fingerprint for tracing sensitive rewrites without storing plaintext values.
pub fn sensitive_hmac_hex(key: &[u8], value: &[u8]) -> String {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        return String::new();
    };
    mac.update(value);
    hex::encode(mac.finalize().into_bytes())
}

struct CompiledHeaderMatch {
    name: String,
    regex: Option<Regex>,
}

enum CompiledAction {
    SetMethod(String),
    SetPathQuery(String),
    ReplaceUrl(Regex, String),
    DeleteHeader(String),
    SetHeader(String, String, bool),
    ReplaceHeader(String, Regex, String, bool),
    SetBody(String, bool),
    ReplaceBody(Regex, String, bool),
    SetStatus(u16),
}

struct CompiledRule {
    id: u64,
    phase: RewritePhase,
    methods: Vec<String>,
    host: Option<String>,
    url_regex: Option<Regex>,
    headers: Vec<CompiledHeaderMatch>,
    body_regex: Option<Regex>,
    status: Vec<String>,
    resp_headers: Vec<CompiledHeaderMatch>,
    resp_body_regex: Option<Regex>,
    actions: Vec<CompiledAction>,
    touches_body: bool,
    has_sensitive: bool,
}

impl CompiledRule {
    fn from_rule(rule: &RewriteRule) -> Result<Self, String> {
        rule.validate()?;
        let host = match rule.matchers.host.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(h) => Some(valid_host_matcher(h)?),
            None => None,
        };
        let url_regex = match rule.matchers.url_regex.as_deref().filter(|s| !s.is_empty()) {
            Some(r) => Some(compile_re(r, "url_regex")?),
            None => None,
        };
        let body_regex = match rule.matchers.body_regex.as_deref().filter(|s| !s.is_empty()) {
            Some(r) => Some(compile_re(r, "body_regex")?),
            None => None,
        };
        let resp_body_regex = match rule.matchers.resp_body_regex.as_deref().filter(|s| !s.is_empty()) {
            Some(r) => Some(compile_re(r, "resp_body_regex")?),
            None => None,
        };
        let compile_hms = |list: &[HeaderMatch]| -> Result<Vec<CompiledHeaderMatch>, String> {
            list.iter()
                .map(|hm| {
                    Ok(CompiledHeaderMatch {
                        name: hm.name.trim().to_string(),
                        regex: (!hm.value_regex.is_empty())
                            .then(|| compile_re(&hm.value_regex, "header"))
                            .transpose()?,
                    })
                })
                .collect()
        };
        let headers = compile_hms(&rule.matchers.headers)?;
        let resp_headers = compile_hms(&rule.matchers.resp_headers)?;

        let mut actions = Vec::with_capacity(rule.actions.len());
        let mut touches_body = body_regex.is_some() || resp_body_regex.is_some();
        let mut has_sensitive = false;
        for a in &rule.actions {
            match a {
                RewriteAction::SetMethod { value } => {
                    actions.push(CompiledAction::SetMethod(value.trim().to_ascii_uppercase()));
                }
                RewriteAction::SetPathQuery { value } => actions.push(CompiledAction::SetPathQuery(value.clone())),
                RewriteAction::ReplaceUrl { regex, value } => {
                    actions.push(CompiledAction::ReplaceUrl(compile_re(regex, "replace_url")?, value.clone()));
                }
                RewriteAction::DeleteHeader { name } => actions.push(CompiledAction::DeleteHeader(name.trim().into())),
                RewriteAction::SetHeader { name, value, sensitive } => {
                    has_sensitive |= *sensitive;
                    actions.push(CompiledAction::SetHeader(
                        name.trim().into(),
                        value.clone().unwrap_or_default(),
                        *sensitive,
                    ));
                }
                RewriteAction::ReplaceHeader { name, regex, value, sensitive } => {
                    has_sensitive |= *sensitive;
                    actions.push(CompiledAction::ReplaceHeader(
                        name.trim().into(),
                        compile_re(regex, "replace_header")?,
                        value.clone().unwrap_or_default(),
                        *sensitive,
                    ));
                }
                RewriteAction::SetBody { value, sensitive } => {
                    touches_body = true;
                    has_sensitive |= *sensitive;
                    actions.push(CompiledAction::SetBody(value.clone().unwrap_or_default(), *sensitive));
                }
                RewriteAction::ReplaceBody { regex, value, sensitive } => {
                    touches_body = true;
                    has_sensitive |= *sensitive;
                    actions.push(CompiledAction::ReplaceBody(
                        compile_re(regex, "replace_body")?,
                        value.clone().unwrap_or_default(),
                        *sensitive,
                    ));
                }
                RewriteAction::SetStatus { value } => actions.push(CompiledAction::SetStatus(*value)),
            }
        }

        Ok(Self {
            id: rule.id,
            phase: rule.phase,
            methods: rule.matchers.methods.iter().map(|m| m.trim().to_ascii_uppercase()).collect(),
            host,
            url_regex,
            headers,
            body_regex,
            status: rule.matchers.status.clone(),
            resp_headers,
            resp_body_regex,
            actions,
            touches_body,
            has_sensitive,
        })
    }

    fn headers_match(matchers: &[CompiledHeaderMatch], headers: &[(String, Vec<u8>)]) -> bool {
        matchers.iter().all(|m| {
            headers.iter().any(|(n, v)| {
                n.eq_ignore_ascii_case(&m.name)
                    && match &m.regex {
                        None => true,
                        Some(re) => std::str::from_utf8(v).is_ok_and(|s| re.is_match(s)),
                    }
            })
        })
    }

    fn matches_request(
        &self,
        host: &str,
        method: &str,
        target: &str,
        headers: &[(String, Vec<u8>)],
        body: Option<&[u8]>,
    ) -> bool {
        if !self.methods.is_empty() && !self.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            return false;
        }
        if let Some(h) = &self.host {
            if !host_matches(h, host) {
                return false;
            }
        }
        if let Some(re) = &self.url_regex {
            if !re.is_match(target) {
                return false;
            }
        }
        if !Self::headers_match(&self.headers, headers) {
            return false;
        }
        if let Some(re) = &self.body_regex {
            let Some(b) = body.and_then(|b| std::str::from_utf8(b).ok()) else {
                return false;
            };
            if !re.is_match(b) {
                return false;
            }
        }
        true
    }
}

/// Immutable compiled snapshot of enabled proxy rewrite rules.
#[derive(Clone)]
pub struct RewriteSet {
    rules: Arc<Vec<CompiledRule>>,
    sensitive_values: Arc<Vec<String>>,
    secrets: Arc<Secrets>,
    max_secret_len: usize,
}

impl Default for RewriteSet {
    fn default() -> Self {
        Self {
            rules: Arc::new(Vec::new()),
            sensitive_values: Arc::new(Vec::new()),
            secrets: Arc::new(Secrets::default()),
            max_secret_len: 0,
        }
    }
}

pub type HeaderList = Vec<(String, Vec<u8>)>;
pub type RewrittenRequestHead = (String, String, HeaderList, Vec<u64>);
pub type RewrittenResponse = (u16, HeaderList, Option<Vec<u8>>, Vec<u64>);

/// Result of rewriting a structured request head with separate wire and capture-safe headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewrittenHead {
    pub method: String,
    pub target: String,
    pub wire_headers: HeaderList,
    pub captured_headers: HeaderList,
    pub applied_ids: Vec<u64>,
    pub sensitive_applied: bool,
}

/// Result of rewriting a raw HTTP/1.1 request head with separate wire and capture-safe bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewrittenRawHead {
    pub wire_head: Vec<u8>,
    pub captured_head: Vec<u8>,
    pub method: String,
    pub target: String,
    pub applied_ids: Vec<u64>,
    pub sensitive_applied: bool,
}

fn collect_sensitive_values(compiled: &[CompiledRule]) -> (Vec<String>, Secrets, usize) {
    let mut raw = Vec::new();
    let mut seen = HashSet::new();
    let mut expanded = Vec::new();
    for rule in compiled {
        for action in &rule.actions {
            let (is_cookie_or_header, val) = match action {
                CompiledAction::SetHeader(name, v, true) | CompiledAction::ReplaceHeader(name, _, v, true) => {
                    (Some(name.as_str()), v.as_str())
                }
                CompiledAction::SetBody(v, true) | CompiledAction::ReplaceBody(_, v, true) => (None, v.as_str()),
                _ => continue,
            };
            if val.is_empty() {
                continue;
            }
            if seen.insert(val.to_string()) {
                raw.push(val.to_string());
            }
            expanded.push(val.to_string());
            // For `<scheme> <token>` headers (e.g. `Authorization: Bearer <tok>`), also redact the bare token.
            if is_cookie_or_header.is_some() && val.matches(' ').count() == 1 {
                if let Some((_, tok)) = val.split_once(' ') {
                    if !tok.is_empty() {
                        expanded.push(tok.to_string());
                    }
                }
            }
            // For `Cookie` headers (or semicolon-separated `k=v` pairs), also redact individual values.
            if is_cookie_or_header.is_some_and(|n| n.eq_ignore_ascii_case("cookie")) || val.contains('=') {
                for pair in val.split(';') {
                    if let Some((_, pv)) = pair.trim().split_once('=') {
                        let pv = pv.trim();
                        if !pv.is_empty() {
                            expanded.push(pv.to_string());
                        }
                    }
                }
            }
        }
    }
    let max_len = raw.iter().map(String::len).max().unwrap_or(0);
    (raw, Secrets::new(expanded), max_len)
}

impl RewriteSet {
    pub fn compile(rules: &[RewriteRule]) -> Self {
        let mut enabled: Vec<&RewriteRule> = rules.iter().filter(|r| r.enabled).collect();
        enabled.sort_by_key(|r| (r.priority, r.id));
        let compiled: Vec<CompiledRule> = enabled.into_iter().filter_map(|r| CompiledRule::from_rule(r).ok()).collect();
        let (sensitive_values, secrets, max_secret_len) = collect_sensitive_values(&compiled);
        Self {
            rules: Arc::new(compiled),
            sensitive_values: Arc::new(sensitive_values),
            secrets: Arc::new(secrets),
            max_secret_len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// All active `sensitive: true` action values from enabled rules, deduplicated in deterministic order.
    pub fn sensitive_values(&self) -> Vec<String> {
        (*self.sensitive_values).clone()
    }

    /// Precompiled [`Secrets`] redactor covering all active `sensitive: true` values (plus extracted
    /// `<scheme> <token>` and cookie pair values) for redacting captured traffic before storage.
    pub fn secrets(&self) -> Arc<Secrets> {
        self.secrets.clone()
    }

    /// Byte length of the longest active `sensitive: true` value (0 when none are active).
    pub(crate) fn max_secret_len(&self) -> usize {
        self.max_secret_len
    }

    /// Apply enabled request-phase head-only rules (skipping rules that touch the body).
    /// Returns `Some((method, target, headers, applied_rule_ids))` when at least one rule changed the head.
    pub fn apply_request_head(
        &self,
        host: &str,
        method: &str,
        target: &str,
        headers: &[(String, Vec<u8>)],
    ) -> Option<RewrittenRequestHead> {
        let rw = self.apply_request_head_for_capture(host, method, target, headers)?;
        Some((rw.method, rw.target, rw.wire_headers, rw.applied_ids))
    }

    /// Like [`RewriteSet::apply_request_head`], also returning capture-safe headers where every
    /// applied `sensitive: true` action substitutes `[redacted]` instead of the raw secret value.
    pub fn apply_request_head_for_capture(
        &self,
        host: &str,
        method: &str,
        target: &str,
        headers: &[(String, Vec<u8>)],
    ) -> Option<RewrittenHead> {
        if self.rules.is_empty() {
            return None;
        }
        let mut cur_method = method.to_string();
        let mut cur_target = target.to_string();
        let mut cur_headers = headers.to_vec();
        let mut cap_headers = headers.to_vec();
        let mut applied = Vec::new();
        let mut sensitive_applied = false;

        for rule in self.rules.iter().filter(|r| r.phase == RewritePhase::Request && !r.touches_body) {
            if !rule.matches_request(host, &cur_method, &cur_target, &cur_headers, None) {
                continue;
            }
            let mut next_method = cur_method.clone();
            let mut next_target = cur_target.clone();
            let mut next_headers = cur_headers.clone();
            if apply_head_actions(&rule.actions, &mut next_method, &mut next_target, &mut next_headers, false).is_ok()
                && (next_method != cur_method || next_target != cur_target || next_headers != cur_headers)
            {
                let mut cap_m = cur_method.clone();
                let mut cap_t = cur_target.clone();
                let mut next_cap = cap_headers.clone();
                let _ = apply_head_actions(&rule.actions, &mut cap_m, &mut cap_t, &mut next_cap, true);
                cur_method = next_method;
                cur_target = next_target;
                cur_headers = next_headers;
                cap_headers = next_cap;
                applied.push(rule.id);
                sensitive_applied |= rule.has_sensitive;
            }
        }
        (!applied.is_empty()).then_some(RewrittenHead {
            method: cur_method,
            target: cur_target,
            wire_headers: cur_headers,
            captured_headers: cap_headers,
            applied_ids: applied,
            sensitive_applied,
        })
    }

    /// Apply enabled request-phase head-only rules directly onto raw HTTP/1.1 request head bytes.
    pub fn apply_raw_request_head(&self, host: &str, raw_head: &[u8]) -> Option<(Vec<u8>, Vec<u64>)> {
        let (out, _method, _target, applied) = self.apply_raw_request_head_parts(host, raw_head)?;
        Some((out, applied))
    }

    /// Like [`RewriteSet::apply_raw_request_head`], also returning the final method and target.
    pub fn apply_raw_request_head_parts(
        &self,
        host: &str,
        raw_head: &[u8],
    ) -> Option<(Vec<u8>, String, String, Vec<u64>)> {
        let rw = self.apply_raw_request_head_for_capture(host, raw_head)?;
        Some((rw.wire_head, rw.method, rw.target, rw.applied_ids))
    }

    /// Like [`RewriteSet::apply_raw_request_head_parts`], returning both wire bytes and capture-safe
    /// bytes where `sensitive: true` actions are replaced by `[redacted]`.
    pub fn apply_raw_request_head_for_capture(&self, host: &str, raw_head: &[u8]) -> Option<RewrittenRawHead> {
        if self.rules.is_empty() {
            return None;
        }
        let mut slots = [httparse::EMPTY_HEADER; 128];
        let mut req = httparse::Request::new(&mut slots);
        let n = match req.parse(raw_head) {
            Ok(httparse::Status::Complete(n)) => n,
            _ => return None,
        };
        let method = req.method?;
        let target = req.path?;
        let ver = if req.version == Some(0) { "HTTP/1.0" } else { "HTTP/1.1" };
        let headers: Vec<(String, Vec<u8>)> =
            req.headers.iter().map(|h| (h.name.to_string(), h.value.to_vec())).collect();
        let rw = self.apply_request_head_for_capture(host, method, target, &headers)?;
        let trailing = raw_head.get(n..).unwrap_or(&[]);
        let render = |hdrs: &[(String, Vec<u8>)]| -> Vec<u8> {
            let mut out = format!("{} {} {ver}\r\n", rw.method, rw.target).into_bytes();
            for (name, val) in hdrs {
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(b": ");
                out.extend_from_slice(val);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\r\n");
            if !trailing.is_empty() {
                out.extend_from_slice(trailing);
            }
            out
        };
        let wire_head = render(&rw.wire_headers);
        let captured_head = if rw.sensitive_applied { render(&rw.captured_headers) } else { wire_head.clone() };
        Some(RewrittenRawHead {
            wire_head,
            captured_head,
            method: rw.method,
            target: rw.target,
            applied_ids: rw.applied_ids,
            sensitive_applied: rw.sensitive_applied,
        })
    }

    /// Apply enabled response-phase rules against a complete buffered response (head + optional text body).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_response(
        &self,
        host: &str,
        req_method: &str,
        req_target: &str,
        req_headers: &[(String, Vec<u8>)],
        status: u16,
        resp_headers: &[(String, Vec<u8>)],
        resp_body: Option<&[u8]>,
    ) -> Option<RewrittenResponse> {
        if self.rules.is_empty() {
            return None;
        }
        let compressed = resp_headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("content-encoding") && !v.eq_ignore_ascii_case(b"identity"));
        let mut cur_status = status;
        let mut cur_headers = resp_headers.to_vec();
        let mut cur_body = resp_body.map(|b| b.to_vec());
        let mut applied = Vec::new();

        for rule in self.rules.iter().filter(|r| r.phase == RewritePhase::Response) {
            if rule.touches_body {
                let Some(b) = cur_body.as_deref() else { continue };
                if compressed || b.len() > MAX_REWRITE_BODY_BYTES || std::str::from_utf8(b).is_err() {
                    continue;
                }
            }
            if !rule.matches_request(host, req_method, req_target, req_headers, None) {
                continue;
            }
            if !status_matches(&rule.status, cur_status) {
                continue;
            }
            if !CompiledRule::headers_match(&rule.resp_headers, &cur_headers) {
                continue;
            }
            if let Some(re) = &rule.resp_body_regex {
                let Some(text) = cur_body.as_deref().and_then(|b| std::str::from_utf8(b).ok()) else {
                    continue;
                };
                if !re.is_match(text) {
                    continue;
                }
            }
            let mut next_status = cur_status;
            let mut next_headers = cur_headers.clone();
            let mut next_body = cur_body.clone();
            if apply_response_actions(&rule.actions, &mut next_status, &mut next_headers, &mut next_body).is_ok()
                && (next_status != cur_status || next_headers != cur_headers || next_body != cur_body)
            {
                cur_status = next_status;
                cur_headers = next_headers;
                cur_body = next_body;
                applied.push(rule.id);
            }
        }
        (!applied.is_empty()).then_some((cur_status, cur_headers, cur_body, applied))
    }
}

fn apply_head_actions(
    actions: &[CompiledAction],
    method: &mut String,
    target: &mut String,
    headers: &mut Vec<(String, Vec<u8>)>,
    redact_sensitive: bool,
) -> Result<(), ()> {
    // Fixed deterministic order: method & URL -> delete_header -> set/replace_header.
    for a in actions {
        match a {
            CompiledAction::SetMethod(m) => *method = m.clone(),
            CompiledAction::SetPathQuery(p) => *target = p.clone(),
            CompiledAction::ReplaceUrl(re, rep) => {
                let next = re.replace_all(target, rep.as_str()).into_owned();
                if !next.starts_with('/') || !no_crlf_nul(&next) || next.contains(' ') {
                    return Err(());
                }
                *target = next;
            }
            _ => {}
        }
    }
    for a in actions {
        if let CompiledAction::DeleteHeader(name) = a {
            headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        }
    }
    for a in actions {
        match a {
            CompiledAction::SetHeader(name, val, sensitive) => {
                headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
                let out_val = if redact_sensitive && *sensitive { REDACTED.as_bytes() } else { val.as_bytes() };
                headers.push((name.clone(), out_val.to_vec()));
            }
            CompiledAction::ReplaceHeader(name, re, rep, sensitive) => {
                for (n, v) in headers.iter_mut() {
                    if n.eq_ignore_ascii_case(name) {
                        if let Ok(s) = std::str::from_utf8(v) {
                            let next = if redact_sensitive && *sensitive {
                                re.replace_all(s, regex::NoExpand(REDACTED)).into_owned()
                            } else {
                                re.replace_all(s, rep.as_str()).into_owned()
                            };
                            if !no_crlf_nul(&next) {
                                return Err(());
                            }
                            *v = next.into_bytes();
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn apply_response_actions(
    actions: &[CompiledAction],
    status: &mut u16,
    headers: &mut Vec<(String, Vec<u8>)>,
    body: &mut Option<Vec<u8>>,
) -> Result<(), ()> {
    for a in actions {
        if let CompiledAction::DeleteHeader(name) = a {
            headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        }
    }
    for a in actions {
        match a {
            CompiledAction::SetHeader(name, val, _) => {
                headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
                headers.push((name.clone(), val.as_bytes().to_vec()));
            }
            CompiledAction::ReplaceHeader(name, re, rep, _) => {
                for (n, v) in headers.iter_mut() {
                    if n.eq_ignore_ascii_case(name) {
                        if let Ok(s) = std::str::from_utf8(v) {
                            let next = re.replace_all(s, rep.as_str()).into_owned();
                            if !no_crlf_nul(&next) {
                                return Err(());
                            }
                            *v = next.into_bytes();
                        }
                    }
                }
            }
            _ => {}
        }
    }
    for a in actions {
        match a {
            CompiledAction::SetBody(val, _) => {
                if val.len() > MAX_REWRITE_BODY_BYTES {
                    return Err(());
                }
                *body = Some(val.as_bytes().to_vec());
            }
            CompiledAction::ReplaceBody(re, rep, _) => {
                let Some(b) = body.as_deref() else { return Err(()) };
                let Ok(s) = std::str::from_utf8(b) else { return Err(()) };
                let next = re.replace_all(s, rep.as_str()).into_owned();
                if next.len() > MAX_REWRITE_BODY_BYTES {
                    return Err(());
                }
                *body = Some(next.into_bytes());
            }
            CompiledAction::SetStatus(code) => *status = *code,
            _ => {}
        }
    }
    Ok(())
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct PersistedRules {
    next_id: u64,
    rules: Vec<RewriteRule>,
}

fn default_key_path(rules_path: &Path) -> PathBuf {
    match rules_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join("keys").join("rewrite.key"),
        None => PathBuf::from("keys").join("rewrite.key"),
    }
}

fn read_existing_key(path: &Path) -> Result<Option<[u8; 32]>, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                format!(
                    "The rewrite encryption key {} is not exactly 32 bytes, so it was left alone; \
                     restore it from a backup or move it away to start a new key.",
                    path.display()
                )
            })?;
            Ok(Some(arr))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Could not read the rewrite encryption key {}: {e}.", path.display())),
    }
}

fn load_or_create_key(path: &Path) -> Result<[u8; 32], String> {
    if let Some(k) = read_existing_key(path)? {
        return Ok(k);
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(parent)
            .map_err(|e| format!("Could not create the rewrite key directory {}: {e}.", parent.display()))?;
    }
    let mut key = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key)
        .map_err(|_| "Could not get random bytes for the rewrite encryption key.".to_string())?;
    ferret_core::journal::publish_new_file(path, &key)
        .map_err(|e| format!("Could not write the rewrite encryption key {}: {e}.", path.display()))?;
    read_existing_key(path)?
        .ok_or_else(|| format!("The rewrite encryption key {} disappeared right after it was written.", path.display()))
}

fn aead_key(key: &[u8; 32]) -> Result<ring::aead::LessSafeKey, String> {
    let unbound = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, key)
        .map_err(|_| "The rewrite encryption key is unusable.".to_string())?;
    Ok(ring::aead::LessSafeKey::new(unbound))
}

fn action_aad(rule: &RewriteRule, action_idx: usize, kind: &str, name: &str) -> String {
    let host = rule.matchers.host.as_deref().map(crate::inject::norm_host).unwrap_or_default();
    format!("ferret-rewrite-v1:{}:{action_idx}:{host}:{kind}:{}", rule.id, name.trim().to_ascii_lowercase())
}

fn seal_value(key: &[u8; 32], aad: &str, plaintext: &str) -> Result<String, String> {
    let mut nonce = [0u8; NONCE_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
        .map_err(|_| "Could not get random bytes to seal a sensitive rewrite rule.".to_string())?;
    let mut buf = plaintext.as_bytes().to_vec();
    aead_key(key)?
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(aad.as_bytes()),
            &mut buf,
        )
        .map_err(|_| "Could not seal a sensitive rewrite rule.".to_string())?;
    let mut raw = Vec::with_capacity(NONCE_LEN + buf.len());
    raw.extend_from_slice(&nonce);
    raw.extend_from_slice(&buf);
    Ok(format!("{ENC_PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(raw)))
}

fn open_value(key: &[u8; 32], aad: &str, rule_id: u64, encoded: &str) -> Result<String, String> {
    let fail = || {
        format!(
            "Could not decrypt sensitive value in rewrite rule {rule_id}: the file is damaged, \
             its rule context changed, or it was sealed with another key."
        )
    };
    let b64 = encoded.strip_prefix(ENC_PREFIX).ok_or_else(fail)?;
    let raw = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|_| fail())?;
    if raw.len() < NONCE_LEN + TAG_LEN {
        return Err(fail());
    }
    let (nonce_bytes, ct) = raw.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| fail())?;
    let mut buf = ct.to_vec();
    let plain = aead_key(key)?
        .open_in_place(ring::aead::Nonce::assume_unique_for_key(nonce), ring::aead::Aad::from(aad.as_bytes()), &mut buf)
        .map_err(|_| fail())?;
    String::from_utf8(plain.to_vec()).map_err(|_| fail())
}

fn sensitive_action_parts_mut(action: &mut RewriteAction) -> Option<(&'static str, String, &mut Option<String>)> {
    match action {
        RewriteAction::SetHeader { name, value, sensitive: true } => Some(("set_header", name.clone(), value)),
        RewriteAction::ReplaceHeader { name, value, sensitive: true, .. } => {
            Some(("replace_header", name.clone(), value))
        }
        RewriteAction::SetBody { value, sensitive: true } => Some(("set_body", String::new(), value)),
        RewriteAction::ReplaceBody { value, sensitive: true, .. } => Some(("replace_body", String::new(), value)),
        _ => None,
    }
}

fn has_sensitive_value(rules: &[RewriteRule]) -> bool {
    rules.iter().any(|r| {
        r.actions.iter().any(|a| {
            matches!(
                a,
                RewriteAction::SetHeader { value: Some(_), sensitive: true, .. }
                    | RewriteAction::ReplaceHeader { value: Some(_), sensitive: true, .. }
                    | RewriteAction::SetBody { value: Some(_), sensitive: true }
                    | RewriteAction::ReplaceBody { value: Some(_), sensitive: true, .. }
            )
        })
    })
}

/// Persistent file-backed store of operator-only rewrite rules (`<home>/rewrite_rules.json`),
/// with ChaCha20-Poly1305 encryption at rest for all `sensitive: true` action values.
#[derive(Clone)]
pub struct RewriteStore {
    path: PathBuf,
    key_path: PathBuf,
    state: Arc<Mutex<PersistedRules>>,
}

impl RewriteStore {
    /// Open `path`, placing the `0600` rewrite encryption key at `<parent>/keys/rewrite.key`.
    /// Any legacy plaintext `sensitive: true` values on disk are transparently migrated to ciphertext.
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let key_path = default_key_path(&path);
        Self::open_with_key(path, key_path)
    }

    /// Open `path` with an explicit encryption key file `key_path` (`0600`, 32 raw bytes).
    /// Any legacy plaintext `sensitive: true` values on disk are transparently migrated to ciphertext.
    pub fn open_with_key(path: PathBuf, key_path: PathBuf) -> Result<Self, String> {
        let mut state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<PersistedRules>(&bytes)
                .map_err(|e| format!("Could not parse `{}`: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PersistedRules { next_id: 1, rules: Vec::new() },
            Err(e) => return Err(format!("Could not read `{}`: {e}", path.display())),
        };
        let mut key: Option<[u8; 32]> = None;
        let mut migrated = false;
        for rule in &mut state.rules {
            let rule_id = rule.id;
            let rule_meta = rule.clone();
            for (idx, action) in rule.actions.iter_mut().enumerate() {
                let Some((kind, name, slot)) = sensitive_action_parts_mut(action) else { continue };
                let Some(stored) = slot.as_deref() else { continue };
                if stored.starts_with(ENC_PREFIX) {
                    let k = match key {
                        Some(k) => k,
                        None => {
                            let loaded = read_existing_key(&key_path)?.ok_or_else(|| {
                                format!(
                                    "The rewrite encryption key {} is missing, so sensitive rewrite rule {rule_id} cannot be decrypted.",
                                    key_path.display()
                                )
                            })?;
                            key = Some(loaded);
                            loaded
                        }
                    };
                    let aad = action_aad(&rule_meta, idx, kind, &name);
                    let plain = open_value(&k, &aad, rule_id, stored)?;
                    *slot = Some(plain);
                } else {
                    migrated = true;
                }
            }
        }
        if migrated {
            save_persisted(&path, &key_path, &state)?;
        }
        Ok(Self { path, key_path, state: Arc::new(Mutex::new(state)) })
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub fn list(&self) -> Vec<RewriteRule> {
        let mut list = self.state.lock().unwrap_or_else(|p| p.into_inner()).rules.clone();
        list.sort_by_key(|r| (r.priority, r.id));
        list
    }

    pub fn snapshot(&self) -> RewriteSet {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        RewriteSet::compile(&st.rules)
    }

    /// Create a rule. Newly created rules ALWAYS start disabled (`enabled = false`).
    pub fn create(&self, mut rule: RewriteRule) -> Result<RewriteRule, String> {
        rule.enabled = false;
        rule.validate()?;
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.rules.len() >= MAX_RULES {
            return Err(format!("Maximum of {MAX_RULES} rewrite rules reached."));
        }
        if st.next_id == 0 {
            st.next_id = 1;
        }
        rule.id = st.next_id;
        st.next_id = st.next_id.saturating_add(1);
        st.rules.push(rule.clone());
        save_persisted(&self.path, &self.key_path, &st)?;
        Ok(rule)
    }

    /// Replace an existing rule, preserving stored sensitive values only when `host` stays identical.
    pub fn update(&self, id: u64, mut incoming: RewriteRule) -> Result<RewriteRule, String> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let idx = st
            .rules
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| format!("There is no rewrite rule {id}."))?;
        let old = st.rules[idx].clone();
        incoming.id = id;

        let mut kept_secret = false;
        for act in &mut incoming.actions {
            let needs_keep = matches!(
                act,
                RewriteAction::SetHeader { sensitive: true, value: None, .. }
                    | RewriteAction::ReplaceHeader { sensitive: true, value: None, .. }
                    | RewriteAction::SetBody { sensitive: true, value: None }
                    | RewriteAction::ReplaceBody { sensitive: true, value: None, .. }
            );
            if needs_keep {
                let matches: Vec<String> = old
                    .actions
                    .iter()
                    .filter_map(|oa| match (oa, &*act) {
                        (
                            RewriteAction::SetHeader { name: on, value: Some(ov), sensitive: true },
                            RewriteAction::SetHeader { name: nn, .. },
                        ) if on.eq_ignore_ascii_case(nn) => Some(ov.clone()),
                        (
                            RewriteAction::ReplaceHeader { name: on, regex: or, value: Some(ov), sensitive: true },
                            RewriteAction::ReplaceHeader { name: nn, regex: nr, .. },
                        ) if on.eq_ignore_ascii_case(nn) && or == nr => Some(ov.clone()),
                        (
                            RewriteAction::SetBody { value: Some(ov), sensitive: true },
                            RewriteAction::SetBody { .. },
                        ) => Some(ov.clone()),
                        (
                            RewriteAction::ReplaceBody { regex: or, value: Some(ov), sensitive: true },
                            RewriteAction::ReplaceBody { regex: nr, .. },
                        ) if or == nr => Some(ov.clone()),
                        _ => None,
                    })
                    .collect();
                if matches.len() != 1 {
                    return Err(
                        "Cannot keep stored sensitive value: provide `value` explicitly when sensitive actions change."
                            .into(),
                    );
                }
                kept_secret = true;
                let secret = matches.into_iter().next().unwrap();
                match act {
                    RewriteAction::SetHeader { value, .. }
                    | RewriteAction::ReplaceHeader { value, .. }
                    | RewriteAction::SetBody { value, .. }
                    | RewriteAction::ReplaceBody { value, .. } => *value = Some(secret),
                    _ => {}
                }
            }
        }
        if kept_secret {
            let old_host = old.matchers.host.as_deref().map(crate::inject::norm_host);
            let new_host = incoming.matchers.host.as_deref().map(crate::inject::norm_host);
            if old_host != new_host {
                return Err(
                    "Cannot change `matchers.host` while keeping a stored sensitive value; resend the value explicitly."
                        .into(),
                );
            }
        }
        incoming.validate()?;
        let enabled_after = st.rules.iter().filter(|r| r.id != id && r.enabled).count() + usize::from(incoming.enabled);
        if enabled_after > MAX_ENABLED_RULES {
            return Err(format!("Maximum of {MAX_ENABLED_RULES} enabled rewrite rules reached."));
        }
        st.rules[idx] = incoming.clone();
        save_persisted(&self.path, &self.key_path, &st)?;
        Ok(incoming)
    }

    pub fn toggle(&self, id: u64, enabled: bool) -> Result<RewriteRule, String> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if enabled {
            let currently_enabled = st.rules.iter().filter(|r| r.id != id && r.enabled).count();
            if currently_enabled >= MAX_ENABLED_RULES {
                return Err(format!("Maximum of {MAX_ENABLED_RULES} enabled rewrite rules reached."));
            }
        }
        let idx = st
            .rules
            .iter()
            .position(|r| r.id == id)
            .ok_or_else(|| format!("There is no rewrite rule {id}."))?;
        if enabled {
            st.rules[idx].validate()?;
        }
        st.rules[idx].enabled = enabled;
        let out = st.rules[idx].clone();
        save_persisted(&self.path, &self.key_path, &st)?;
        Ok(out)
    }

    pub fn delete(&self, id: u64) -> Result<(), String> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let before = st.rules.len();
        st.rules.retain(|r| r.id != id);
        if st.rules.len() == before {
            return Err(format!("There is no rewrite rule {id}."));
        }
        save_persisted(&self.path, &self.key_path, &st)?;
        Ok(())
    }
}

fn save_persisted(path: &Path, key_path: &Path, st: &PersistedRules) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("Could not create `{}`: {e}", parent.display()))?;
    }
    let mut to_write = st.clone();
    if has_sensitive_value(&to_write.rules) {
        let key = load_or_create_key(key_path)?;
        for rule in &mut to_write.rules {
            let rule_meta = rule.clone();
            for (idx, action) in rule.actions.iter_mut().enumerate() {
                let Some((kind, name, slot)) = sensitive_action_parts_mut(action) else { continue };
                let Some(plain) = slot.as_deref() else { continue };
                let aad = action_aad(&rule_meta, idx, kind, &name);
                *slot = Some(seal_value(&key, &aad, plain)?);
            }
        }
    }
    let bytes = serde_json::to_vec_pretty(&to_write).map_err(|e| format!("Could not serialize rewrite rules: {e}"))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("rewrite_rules.json");
    let mut attempt = 0u8;
    let (tmp, mut f) = loop {
        let tmp = path.with_file_name(format!(".{name}.{}.tmp", hex::encode(rand::random::<u64>().to_le_bytes())));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        match o.open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 8 => attempt += 1,
            Err(e) => return Err(format!("Could not save `{}`: {e}", path.display())),
        }
    };
    let write_res = f
        .write_all(&bytes)
        .and_then(|()| f.sync_all())
        .and_then(|()| {
            drop(f);
            std::fs::rename(&tmp, path)
        });
    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Could not save `{}`: {e}", path.display()));
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(d) = std::fs::File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assessment_ua_matches_exact_origin_only_and_respects_explicit_ua() {
        let cfg = AssessmentUaCfg {
            origins: vec!["https://shop.example.test".into(), "http://app.test:8080".into()],
            reference: Some("FS-17".into()),
        };
        let aua = AssessmentUa::from_cfg(&cfg).unwrap();
        assert_eq!(aua.header_value(), "Ferret-Assessment/1.0 (engagement=FS-17)");
        assert!(aua.matches("https", "SHOP.EXAMPLE.TEST.", 443));
        assert!(aua.matches("http", "app.test", 8080));
        assert!(!aua.matches("http", "shop.example.test", 80));
        assert!(!aua.matches("https", "other.example.test", 443));

        let mut hdrs = vec![("Host".into(), b"shop.example.test".to_vec())];
        assert!(aua.apply_headers("https", "shop.example.test", 443, &mut hdrs));
        assert_eq!(hdrs[1].0, "User-Agent");
        // Explicit User-Agent wins
        assert!(!aua.apply_headers("https", "shop.example.test", 443, &mut hdrs));
    }

    #[test]
    fn rewrite_rules_validate_redact_pin_host_and_apply_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let store = RewriteStore::open(dir.path().join("rules.json")).unwrap();
        let rule = RewriteRule {
            id: 0,
            name: "staging auth".into(),
            enabled: true, // ignored on create!
            phase: RewritePhase::Request,
            priority: 10,
            matchers: RewriteMatcher {
                host: Some("*.staging.example.test".into()),
                methods: vec!["GET".into(), "POST".into()],
                ..Default::default()
            },
            actions: vec![
                RewriteAction::SetHeader { name: "Authorization".into(), value: Some("Bearer supersecret".into()), sensitive: true },
                RewriteAction::ReplaceUrl { regex: "^/v1/".into(), value: "/v2/".into() },
            ],
            note: "test".into(),
        };
        let created = store.create(rule).unwrap();
        assert!(!created.enabled, "new rules must start disabled");
        let view = created.redacted_view();
        assert!(!view.to_string().contains("supersecret"));
        assert_eq!(view["actions"][0]["value_set"], true);

        // Host change while keeping sensitive value is refused
        let mut moved = created.clone();
        moved.matchers.host = Some("evil.test".into());
        moved.actions[0] = RewriteAction::SetHeader { name: "Authorization".into(), value: None, sensitive: true };
        assert!(store.update(created.id, moved).unwrap_err().contains("matchers.host"));

        // Same host keeps stored secret cleanly
        let mut same = created.clone();
        same.actions[0] = RewriteAction::SetHeader { name: "Authorization".into(), value: None, sensitive: true };
        let updated = store.update(created.id, same).unwrap();
        assert!(matches!(&updated.actions[0], RewriteAction::SetHeader { value: Some(v), .. } if v == "Bearer supersecret"));

        store.toggle(created.id, true).unwrap();
        let set = store.snapshot();
        let raw = b"GET /v1/users HTTP/1.1\r\nHost: api.staging.example.test\r\n\r\n";
        let (rewritten, ids) = set.apply_raw_request_head("api.staging.example.test", raw).unwrap();
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(ids, vec![created.id]);
        assert!(text.starts_with("GET /v2/users HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Authorization: Bearer supersecret\r\n"), "{text}");
        // Apex domain does not match `*.staging.example.test`
        assert!(set.apply_raw_request_head("staging.example.test", raw).is_none());
    }

    #[test]
    fn sensitive_values_are_encrypted_at_rest_with_0600_key_and_bound_by_aad() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rewrite_rules.json");
        let store = RewriteStore::open(rules_path.clone()).unwrap();
        let key_path = dir.path().join("keys").join("rewrite.key");
        assert_eq!(store.key_path(), key_path.as_path());

        let secret = "Bearer s3cr3t-rewrite-token-0123456789";
        let rule = RewriteRule {
            id: 0,
            name: "auth header".into(),
            enabled: false,
            phase: RewritePhase::Request,
            priority: 1,
            matchers: RewriteMatcher { host: Some("api.example.test".into()), ..Default::default() },
            actions: vec![
                RewriteAction::SetHeader {
                    name: "Authorization".into(),
                    value: Some(secret.into()),
                    sensitive: true,
                },
                RewriteAction::SetHeader {
                    name: "X-Public-Tag".into(),
                    value: Some("visible-tag".into()),
                    sensitive: false,
                },
            ],
            note: String::new(),
        };
        let created = store.create(rule).unwrap();
        // Debug never leaks sensitive values.
        let dbg = format!("{created:?}");
        assert!(!dbg.contains(secret) && dbg.contains("[redacted]"), "{dbg}");

        // On-disk JSON encrypts sensitive values with enc:v1: and leaves non-sensitive values readable.
        let disk = std::fs::read_to_string(&rules_path).unwrap();
        assert!(!disk.contains("s3cr3t-rewrite-token"), "plaintext secret leaked to disk: {disk}");
        assert!(disk.contains("enc:v1:"), "expected encrypted prefix on disk: {disk}");
        assert!(disk.contains("visible-tag"), "non-sensitive value should remain readable: {disk}");
        assert_eq!(std::fs::read(&key_path).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(key_path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(std::fs::metadata(&rules_path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // Reopen decrypts faithfully.
        let reopened = RewriteStore::open(rules_path.clone()).unwrap();
        let loaded = reopened.list();
        assert_eq!(loaded.len(), 1);
        assert!(matches!(
            &loaded[0].actions[0],
            RewriteAction::SetHeader { value: Some(v), sensitive: true, .. } if v == secret
        ));

        // Wrong key refuses to decrypt without leaking plaintext.
        let other_key = dir.path().join("other.key");
        std::fs::write(&other_key, [9u8; 32]).unwrap();
        let err = RewriteStore::open_with_key(rules_path.clone(), other_key).err().unwrap();
        assert!(err.contains("Could not decrypt") && !err.contains("s3cr3t"), "{err}");

        // Missing key refuses to decrypt and does not create a replacement key.
        let missing_key = dir.path().join("missing.key");
        let err = RewriteStore::open_with_key(rules_path.clone(), missing_key.clone()).err().unwrap();
        assert!(err.contains("missing"), "{err}");
        assert!(!missing_key.exists());

        // Corrupt (short) key is left untouched and rejected.
        let short_key = dir.path().join("short.key");
        std::fs::write(&short_key, b"short").unwrap();
        let err = RewriteStore::open_with_key(rules_path.clone(), short_key.clone()).err().unwrap();
        assert!(err.contains("32 bytes"), "{err}");
        assert_eq!(std::fs::read(&short_key).unwrap(), b"short");

        // AAD binds ciphertext to host matcher: editing host on disk breaks decryption.
        let tampered_host = disk.replace("api.example.test", "evil.example.test");
        let tampered_path = dir.path().join("tampered_host.json");
        std::fs::write(&tampered_path, tampered_host).unwrap();
        let err = RewriteStore::open_with_key(tampered_path, key_path).err().unwrap();
        assert!(err.contains("Could not decrypt"), "{err}");
    }

    #[test]
    fn legacy_plaintext_sensitive_rules_are_migrated_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let rules_path = dir.path().join("rewrite_rules.json");
        let key_path = dir.path().join("keys").join("rewrite.key");
        let legacy = serde_json::json!({
            "next_id": 2,
            "rules": [{
                "id": 1,
                "name": "legacy secret",
                "enabled": true,
                "phase": "request",
                "priority": 1,
                "matchers": { "host": "legacy.example.test" },
                "actions": [{
                    "type": "set_header",
                    "name": "Authorization",
                    "value": "Bearer legacy-plaintext-secret-999",
                    "sensitive": true
                }],
                "note": ""
            }]
        });
        std::fs::write(&rules_path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let store = RewriteStore::open_with_key(rules_path.clone(), key_path.clone()).unwrap();
        let rules = store.list();
        assert!(matches!(
            &rules[0].actions[0],
            RewriteAction::SetHeader { value: Some(v), sensitive: true, .. } if v == "Bearer legacy-plaintext-secret-999"
        ));

        // File on disk was immediately rewritten with ciphertext, and key was created with 0600 perms.
        let on_disk = std::fs::read_to_string(&rules_path).unwrap();
        assert!(!on_disk.contains("legacy-plaintext-secret-999"), "{on_disk}");
        assert!(on_disk.contains("enc:v1:"), "{on_disk}");
        assert_eq!(std::fs::read(&key_path).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        // Reopening loads decrypted value from migrated ciphertext.
        let again = RewriteStore::open_with_key(rules_path, key_path).unwrap();
        assert_eq!(again.snapshot().sensitive_values(), vec!["Bearer legacy-plaintext-secret-999"]);
    }

    #[test]
    fn rewrite_set_sensitive_values_and_capture_redaction() {
        let rules = vec![
            RewriteRule {
                id: 1,
                name: "disabled secret".into(),
                enabled: false,
                phase: RewritePhase::Request,
                priority: 1,
                matchers: RewriteMatcher::default(),
                actions: vec![RewriteAction::SetHeader {
                    name: "X-Disabled".into(),
                    value: Some("disabled-secret-0000".into()),
                    sensitive: true,
                }],
                note: String::new(),
            },
            RewriteRule {
                id: 2,
                name: "active secrets".into(),
                enabled: true,
                phase: RewritePhase::Request,
                priority: 1,
                matchers: RewriteMatcher { host: Some("app.test".into()), ..Default::default() },
                actions: vec![
                    RewriteAction::SetHeader {
                        name: "Authorization".into(),
                        value: Some("Bearer active-token-123456".into()),
                        sensitive: true,
                    },
                    RewriteAction::SetHeader {
                        name: "X-Short-Pin".into(),
                        value: Some("9876".into()),
                        sensitive: true,
                    },
                    RewriteAction::SetHeader {
                        name: "X-Public".into(),
                        value: Some("hello".into()),
                        sensitive: false,
                    },
                ],
                note: String::new(),
            },
            RewriteRule {
                id: 3,
                name: "chained matcher on real header".into(),
                enabled: true,
                phase: RewritePhase::Request,
                priority: 2,
                matchers: RewriteMatcher {
                    host: Some("app.test".into()),
                    headers: vec![HeaderMatch { name: "Authorization".into(), value_regex: "active-token".into() }],
                    ..Default::default()
                },
                actions: vec![RewriteAction::SetHeader {
                    name: "X-Chained".into(),
                    value: Some("matched".into()),
                    sensitive: false,
                }],
                note: String::new(),
            },
        ];
        let set = RewriteSet::compile(&rules);
        assert_eq!(set.sensitive_values(), vec!["Bearer active-token-123456", "9876"]);
        let secrets = set.secrets();
        assert_eq!(secrets.redact("echo active-token-123456 here"), "echo [redacted] here");
        assert_eq!(secrets.redact("Bearer active-token-123456"), "[redacted]");

        let raw = b"GET /profile HTTP/1.1\r\nHost: app.test\r\n\r\n";
        let rw = set.apply_raw_request_head_for_capture("app.test", raw).unwrap();
        assert!(rw.sensitive_applied);
        assert_eq!(rw.applied_ids, vec![2, 3]);
        let wire = String::from_utf8(rw.wire_head).unwrap();
        let cap = String::from_utf8(rw.captured_head).unwrap();
        assert!(wire.contains("Authorization: Bearer active-token-123456\r\n"), "{wire}");
        assert!(wire.contains("X-Short-Pin: 9876\r\n"), "{wire}");
        assert!(wire.contains("X-Public: hello\r\n") && wire.contains("X-Chained: matched\r\n"), "{wire}");
        assert!(cap.contains("Authorization: [redacted]\r\n"), "{cap}");
        assert!(cap.contains("X-Short-Pin: [redacted]\r\n"), "{cap}");
        assert!(cap.contains("X-Public: hello\r\n") && cap.contains("X-Chained: matched\r\n"), "{cap}");
        assert!(!cap.contains("active-token-123456") && !cap.contains("9876"), "{cap}");
    }
}
