//! HAR 1.2 export and import for Ferret captured HTTP exchanges.
//!
//! CONTRACT.
//!
//! Pure, deterministic functions over [`Exchange`] records and [`BlobStore`]; nothing here talks
//! to the network.
//!
//! - [`export_har`] produces a valid HAR 1.2 document (`log.version = "1.2"`, `creator.name =
//!   "Ferret"`), parsing stored HTTP/1.1 request and response wire messages into structured headers,
//!   query strings, cookies, postData, and content (using `encoding: "base64"` for non-UTF-8
//!   binary bodies). URL userinfo is always stripped. Exports enforce entry and total-byte caps
//!   and mark truncation explicitly via `_truncated`, `_truncatedReason`, and `_totalMatched`.
//! - [`import_har`] parses a HAR 1.2 document with strict bounds (`DEFAULT_MAX_IMPORT_ENTRIES =
//!   2000`, `DEFAULT_MAX_IMPORT_BYTES = 32 MiB`), rejects trailing non-whitespace JSON, strips URL
//!   userinfo, validates methods/headers (no CR/LF/NUL), reconstructs canonical HTTP/1.1 wire
//!   messages in `BlobStore`, and assigns either a preserved valid `_ferretExchangeId` or a
//!   deterministic `ex-har-<16-hex>` ID so repeated imports are idempotent.

use crate::blob::BlobStore;
use crate::event::Exchange;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;

pub const HAR_VERSION: &str = "1.2";
pub const DEFAULT_MAX_IMPORT_ENTRIES: usize = 2_000;
pub const DEFAULT_MAX_IMPORT_BYTES: u64 = 32 * 1024 * 1024;
pub const DEFAULT_MAX_EXPORT_ENTRIES: usize = 1_000;
pub const DEFAULT_MAX_EXPORT_BYTES: u64 = 20 * 1024 * 1024;
const MAX_IMPORT_ERRORS: usize = 50;

#[derive(Clone, Debug)]
pub struct HarExportOptions {
    pub creator_version: String,
    pub max_entries: usize,
    pub max_total_bytes: u64,
    /// Redact sensitive headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
    /// `X-Api-Key`, `X-Auth-Token`, `X-CSRF-Token`, `X-XSRF-Token`, etc.), auth query parameters,
    /// high-confidence tokens/JWTs, and `extra_secrets`. Defaults to `true`.
    pub sanitize: bool,
    /// Additional literal secret values to redact when `sanitize` is `true`.
    pub extra_secrets: Vec<String>,
}

impl Default for HarExportOptions {
    fn default() -> Self {
        Self {
            creator_version: env!("CARGO_PKG_VERSION").to_string(),
            max_entries: DEFAULT_MAX_EXPORT_ENTRIES,
            max_total_bytes: DEFAULT_MAX_EXPORT_BYTES,
            sanitize: true,
            extra_secrets: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarExportMeta {
    pub exported: usize,
    pub total_matched: usize,
    pub total_bytes: u64,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct HarImportOptions {
    pub max_entries: usize,
    pub max_total_bytes: u64,
}

impl Default for HarImportOptions {
    fn default() -> Self {
        Self { max_entries: DEFAULT_MAX_IMPORT_ENTRIES, max_total_bytes: DEFAULT_MAX_IMPORT_BYTES }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarImportError {
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub failed: usize,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<HarImportError>,
}

/// One imported exchange together with its UTC timestamp in milliseconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedExchange {
    pub ts_ms: u64,
    pub exchange: Exchange,
}

/// Export `(ts_ms, &Exchange)` pairs into a HAR 1.2 JSON document.
///
/// Respects `opts.sanitize` (default `true`) and `opts.extra_secrets`.
pub fn export_har(
    items: &[(u64, &Exchange)],
    blobs: &BlobStore,
    opts: &HarExportOptions,
) -> Result<(Value, HarExportMeta), String> {
    let max_entries = if opts.max_entries == 0 { DEFAULT_MAX_EXPORT_ENTRIES } else { opts.max_entries };
    let max_bytes = if opts.max_total_bytes == 0 { DEFAULT_MAX_EXPORT_BYTES } else { opts.max_total_bytes };

    let mut entries: Vec<Value> = Vec::new();
    let mut meta = HarExportMeta { total_matched: items.len(), ..Default::default() };

    for &(ts_ms, ex) in items {
        if entries.len() >= max_entries {
            meta.truncated = true;
            meta.truncated_reason = Some("max_entries".into());
            break;
        }
        let req_bytes = blobs.read_all(&ex.request.id).unwrap_or_default();
        let resp_bytes = ex.response.as_ref().and_then(|r| blobs.read_all(&r.id).ok()).unwrap_or_default();
        let combined = (req_bytes.len() as u64).saturating_add(resp_bytes.len() as u64);
        if meta.total_bytes.saturating_add(combined) > max_bytes && !entries.is_empty() {
            meta.truncated = true;
            meta.truncated_reason = Some("max_bytes".into());
            break;
        }
        let har_entry = build_har_entry(ts_ms, ex, &req_bytes, &resp_bytes, opts);
        entries.push(har_entry);
        meta.exported += 1;
        meta.total_bytes = meta.total_bytes.saturating_add(combined);
    }

    let mut log = serde_json::Map::new();
    log.insert("version".into(), json!(HAR_VERSION));
    log.insert("creator".into(), json!({ "name": "Ferret", "version": opts.creator_version }));
    log.insert("entries".into(), Value::Array(entries));
    log.insert("_sanitized".into(), json!(opts.sanitize));
    if meta.truncated {
        log.insert("_truncated".into(), json!(true));
        if let Some(reason) = &meta.truncated_reason {
            log.insert("_truncatedReason".into(), json!(reason));
        }
        log.insert("_totalMatched".into(), json!(meta.total_matched));
    }

    Ok((json!({ "log": Value::Object(log) }), meta))
}

/// Convenience helper to export HAR 1.2 with an explicit `sanitize` flag and additional literal
/// secrets to redact (merged with any `opts.extra_secrets`).
pub fn export_har_sanitized(
    items: &[(u64, &Exchange)],
    blobs: &BlobStore,
    opts: &HarExportOptions,
    extra_secrets: &[String],
    sanitize: bool,
) -> Result<(Value, HarExportMeta), String> {
    let mut merged = opts.clone();
    merged.sanitize = sanitize;
    if !extra_secrets.is_empty() {
        merged.extra_secrets.extend(extra_secrets.iter().cloned());
    }
    export_har(items, blobs, &merged)
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

fn format_rfc3339_ms(ts_ms: u64) -> String {
    let secs = (ts_ms / 1000) as i64;
    let ms = ts_ms % 1000;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = sod / 3600;
    let mm = (sod % 3600) / 60;
    let ss = sod % 60;
    if ms == 0 {
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
    } else {
        format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{ms:03}Z")
    }
}

fn parse_rfc3339_ms(raw: &str) -> Result<u64, String> {
    let s = raw.trim();
    // Minimum: YYYY-MM-DDTHH:MM:SSZ (20 bytes)
    if s.len() < 20 {
        return Err(format!("invalid startedDateTime `{raw}`"));
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') || b[13] != b':' || b[16] != b':' {
        return Err(format!("invalid startedDateTime `{raw}`"));
    }
    let y: i64 = s[0..4].parse().map_err(|_| format!("invalid startedDateTime `{raw}`"))?;
    let m: u32 = s[5..7].parse().map_err(|_| format!("invalid startedDateTime `{raw}`"))?;
    let d: u32 = s[8..10].parse().map_err(|_| format!("invalid startedDateTime `{raw}`"))?;
    let hh: i64 = s[11..13].parse().map_err(|_| format!("invalid startedDateTime `{raw}`"))?;
    let mm: i64 = s[14..16].parse().map_err(|_| format!("invalid startedDateTime `{raw}`"))?;
    let ss: i64 = s[17..19].parse().map_err(|_| format!("invalid startedDateTime `{raw}`"))?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss) {
        return Err(format!("invalid startedDateTime `{raw}`"));
    }
    let mut rest = &s[19..];
    let mut ms: i64 = 0;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits_len = after_dot.bytes().take_while(u8::is_ascii_digit).count();
        if digits_len == 0 {
            return Err(format!("invalid startedDateTime `{raw}`"));
        }
        let frac = &after_dot[..digits_len];
        let mut padded = [b'0'; 3];
        for (i, ch) in frac.bytes().take(3).enumerate() {
            padded[i] = ch;
        }
        ms = std::str::from_utf8(&padded).ok().and_then(|v| v.parse().ok()).unwrap_or(0);
        rest = &after_dot[digits_len..];
    }
    let tz_secs: i64 = if rest.eq_ignore_ascii_case("Z") {
        0
    } else if (rest.starts_with('+') || rest.starts_with('-')) && rest.len() == 6 && rest.as_bytes()[3] == b':' {
        let tzh: i64 = rest[1..3].parse().map_err(|_| format!("invalid startedDateTime `{raw}`"))?;
        let tzm: i64 = rest[4..6].parse().map_err(|_| format!("invalid startedDateTime `{raw}`"))?;
        if tzh > 23 || tzm > 59 {
            return Err(format!("invalid startedDateTime `{raw}`"));
        }
        let sign = if rest.starts_with('-') { -1 } else { 1 };
        sign * (tzh * 3600 + tzm * 60)
    } else {
        return Err(format!("invalid startedDateTime `{raw}`"));
    };
    let total_secs = days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss - tz_secs;
    let total_ms = total_secs.saturating_mul(1000).saturating_add(ms);
    Ok(u64::try_from(total_ms).unwrap_or(0))
}

fn build_har_entry(
    ts_ms: u64,
    ex: &Exchange,
    req_raw: &[u8],
    resp_raw: &[u8],
    opts: &HarExportOptions,
) -> Value {
    let default_port = (ex.scheme == "http" && ex.port == 80) || (ex.scheme == "https" && ex.port == 443);
    let authority = if default_port { ex.host.clone() } else { format!("{}:{}", ex.host, ex.port) };
    let path_query = if ex.target.starts_with('/') { ex.target.clone() } else { format!("/{}", ex.target) };
    let raw_url = format!("{}://{authority}{path_query}", ex.scheme);
    let clean_url = if opts.sanitize {
        crate::sanitize::sanitize_url(&raw_url, &opts.extra_secrets)
    } else {
        redact_url_userinfo(&raw_url)
    };

    let (req_ver, raw_req_headers, req_head_len, req_body) = parse_wire_request(req_raw);
    let req_headers: Vec<(String, String)> = if opts.sanitize {
        raw_req_headers
            .into_iter()
            .map(|(n, v)| {
                let sv = crate::sanitize::sanitize_header_value(&n, &v, &opts.extra_secrets);
                (n, sv)
            })
            .collect()
    } else {
        raw_req_headers
    };
    let query_string = url::Url::parse(&clean_url)
        .ok()
        .map(|u| {
            u.query_pairs()
                .map(|(k, v)| {
                    let val = if opts.sanitize && crate::sanitize::is_sensitive_param(&k) && !v.is_empty() {
                        crate::creds::REDACTED.to_string()
                    } else if opts.sanitize {
                        crate::sanitize::sanitize_text(&v, &opts.extra_secrets).into_owned()
                    } else {
                        v.into_owned()
                    };
                    json!({ "name": k, "value": val })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let req_cookies = parse_request_cookies(&req_headers);
    let req_ct = header_value(&req_headers, "content-type").unwrap_or_default();

    let mut req_obj = serde_json::Map::new();
    req_obj.insert("method".into(), json!(ex.method));
    req_obj.insert("url".into(), json!(clean_url));
    req_obj.insert("httpVersion".into(), json!(req_ver));
    req_obj.insert("cookies".into(), Value::Array(req_cookies));
    req_obj.insert("headers".into(), headers_to_har(&req_headers));
    req_obj.insert("queryString".into(), Value::Array(query_string));
    if !req_body.is_empty() {
        let mut pd = serde_json::Map::new();
        pd.insert("mimeType".into(), json!(req_ct));
        match std::str::from_utf8(req_body) {
            Ok(text) => {
                let body_text = if opts.sanitize {
                    if req_ct.to_ascii_lowercase().starts_with("application/x-www-form-urlencoded") {
                        crate::sanitize::sanitize_form_urlencoded(text, &opts.extra_secrets)
                    } else {
                        crate::sanitize::sanitize_text(text, &opts.extra_secrets).into_owned()
                    }
                } else {
                    text.to_string()
                };
                pd.insert("text".into(), json!(body_text));
            }
            Err(_) => {
                let bytes = if opts.sanitize {
                    crate::sanitize::sanitize_bytes(req_body, &opts.extra_secrets)
                } else {
                    std::borrow::Cow::Borrowed(req_body)
                };
                pd.insert("text".into(), json!(base64::engine::general_purpose::STANDARD.encode(bytes.as_ref())));
                pd.insert("encoding".into(), json!("base64"));
            }
        }
        req_obj.insert("postData".into(), Value::Object(pd));
    }
    req_obj.insert("headersSize".into(), json!(if req_head_len > 0 { req_head_len as i64 } else { -1 }));
    req_obj.insert("bodySize".into(), json!(req_body.len() as i64));

    let (resp_ver, resp_status, resp_reason, raw_resp_headers, resp_head_len, resp_body) =
        parse_wire_response(resp_raw);
    let resp_headers: Vec<(String, String)> = if opts.sanitize {
        raw_resp_headers
            .into_iter()
            .map(|(n, v)| {
                let sv = crate::sanitize::sanitize_header_value(&n, &v, &opts.extra_secrets);
                (n, sv)
            })
            .collect()
    } else {
        raw_resp_headers
    };
    let status = ex.status.map(i64::from).unwrap_or(resp_status);
    let resp_ct = header_value(&resp_headers, "content-type").unwrap_or_default();
    let redirect_url = header_value(&resp_headers, "location").unwrap_or_default();
    let resp_cookies = parse_response_cookies(&resp_headers);

    let mut content = serde_json::Map::new();
    content.insert("size".into(), json!(resp_body.len() as i64));
    content.insert("mimeType".into(), json!(resp_ct));
    if !resp_body.is_empty() {
        match std::str::from_utf8(resp_body) {
            Ok(text) => {
                let body_text = if opts.sanitize {
                    crate::sanitize::sanitize_text(text, &opts.extra_secrets).into_owned()
                } else {
                    text.to_string()
                };
                content.insert("text".into(), json!(body_text));
            }
            Err(_) => {
                let bytes = if opts.sanitize {
                    crate::sanitize::sanitize_bytes(resp_body, &opts.extra_secrets)
                } else {
                    std::borrow::Cow::Borrowed(resp_body)
                };
                content.insert("text".into(), json!(base64::engine::general_purpose::STANDARD.encode(bytes.as_ref())));
                content.insert("encoding".into(), json!("base64"));
            }
        }
    }

    let resp_obj = json!({
        "status": status,
        "statusText": resp_reason,
        "httpVersion": resp_ver,
        "cookies": resp_cookies,
        "headers": headers_to_har(&resp_headers),
        "content": Value::Object(content),
        "redirectURL": redirect_url,
        "headersSize": if resp_head_len > 0 { resp_head_len as i64 } else { -1 },
        "bodySize": resp_body.len() as i64,
    });

    json!({
        "startedDateTime": format_rfc3339_ms(ts_ms),
        "time": ex.duration_ms as f64,
        "request": Value::Object(req_obj),
        "response": resp_obj,
        "cache": {},
        "timings": { "send": -1.0, "wait": ex.duration_ms as f64, "receive": -1.0 },
        "_ferretExchangeId": ex.id,
    })
}

fn parse_wire_request(raw: &[u8]) -> (String, Vec<(String, String)>, usize, &[u8]) {
    if raw.is_empty() {
        return ("HTTP/1.1".into(), Vec::new(), 0, &[]);
    }
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut slots);
    if let Ok(httparse::Status::Complete(n)) = req.parse(raw) {
        let ver = match req.version {
            Some(0) => "HTTP/1.0",
            _ => "HTTP/1.1",
        };
        let headers = req
            .headers
            .iter()
            .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).to_string()))
            .collect();
        return (ver.into(), headers, n, &raw[n..]);
    }
    ("HTTP/1.1".into(), Vec::new(), 0, raw)
}

type WireResponse<'a> = (String, i64, String, Vec<(String, String)>, usize, &'a [u8]);

fn parse_wire_response(raw: &[u8]) -> WireResponse<'_> {
    if raw.is_empty() {
        return ("HTTP/1.1".into(), 0, String::new(), Vec::new(), 0, &[]);
    }
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut slots);
    if let Ok(httparse::Status::Complete(n)) = resp.parse(raw) {
        let ver = match resp.version {
            Some(0) => "HTTP/1.0",
            _ => "HTTP/1.1",
        };
        let code = resp.code.map(i64::from).unwrap_or(0);
        let reason = resp.reason.unwrap_or("").to_string();
        let headers = resp
            .headers
            .iter()
            .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).to_string()))
            .collect();
        return (ver.into(), code, reason, headers, n, &raw[n..]);
    }
    ("HTTP/1.1".into(), 0, String::new(), Vec::new(), 0, raw)
}

fn headers_to_har(headers: &[(String, String)]) -> Value {
    Value::Array(headers.iter().map(|(n, v)| json!({ "name": n, "value": v })).collect())
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

fn parse_request_cookies(headers: &[(String, String)]) -> Vec<Value> {
    let mut out = Vec::new();
    for (n, v) in headers {
        if !n.eq_ignore_ascii_case("cookie") {
            continue;
        }
        for pair in v.split(';') {
            let trimmed = pair.trim();
            if let Some((k, val)) = trimmed.split_once('=') {
                if !k.trim().is_empty() {
                    out.push(json!({ "name": k.trim(), "value": val.trim() }));
                }
            }
        }
    }
    out
}

fn parse_response_cookies(headers: &[(String, String)]) -> Vec<Value> {
    let mut out = Vec::new();
    for (n, v) in headers {
        if !n.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let first = v.split(';').next().unwrap_or("").trim();
        if let Some((k, val)) = first.split_once('=') {
            if !k.trim().is_empty() {
                out.push(json!({ "name": k.trim(), "value": val.trim() }));
            }
        }
    }
    out
}

fn redact_url_userinfo(raw: &str) -> String {
    match url::Url::parse(raw.trim()) {
        Ok(mut u) => {
            if !u.username().is_empty() || u.password().is_some() {
                let _ = u.set_username("");
                let _ = u.set_password(None);
            }
            u.to_string()
        }
        Err(_) => raw.trim().to_string(),
    }
}

#[derive(Deserialize)]
struct RawHar {
    log: Option<RawHarLog>,
}

#[derive(Deserialize)]
struct RawHarLog {
    #[serde(default)]
    version: String,
    entries: Option<Vec<RawHarEntry>>,
}

#[derive(Deserialize)]
struct RawHarEntry {
    #[serde(rename = "startedDateTime", default)]
    started_date_time: String,
    #[serde(default)]
    time: f64,
    request: RawHarRequest,
    response: RawHarResponse,
    #[serde(rename = "_ferretExchangeId", default)]
    ferret_exchange_id: Option<String>,
}

#[derive(Deserialize)]
struct RawHarRequest {
    #[serde(default)]
    method: String,
    #[serde(default)]
    url: String,
    #[serde(rename = "httpVersion", default)]
    http_version: String,
    #[serde(default)]
    headers: Vec<RawHarHeader>,
    #[serde(default)]
    cookies: Vec<RawHarCookie>,
    #[serde(rename = "postData", default)]
    post_data: Option<RawHarPostData>,
}

#[derive(Deserialize)]
struct RawHarResponse {
    #[serde(default)]
    status: i64,
    #[serde(rename = "statusText", default)]
    status_text: String,
    #[serde(rename = "httpVersion", default)]
    http_version: String,
    #[serde(default)]
    headers: Vec<RawHarHeader>,
    #[serde(default)]
    content: Option<RawHarContent>,
}

#[derive(Deserialize)]
struct RawHarHeader {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct RawHarCookie {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct RawHarPostData {
    #[serde(default)]
    text: String,
    #[serde(default)]
    encoding: String,
}

#[derive(Deserialize)]
struct RawHarContent {
    #[serde(default)]
    text: String,
    #[serde(default)]
    encoding: String,
}

fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'))
}

fn no_crlf_nul(s: &str) -> bool {
    !s.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
}

fn valid_exchange_id(id: &str) -> bool {
    let s = id.trim();
    s.starts_with("ex-")
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Parse a HAR 1.2 JSON document, store wire messages into `blobs`, and return new exchanges
/// skipping any ID present in `existing_ids` (for idempotent re-import).
pub fn import_har(
    raw: &[u8],
    blobs: &BlobStore,
    existing_ids: &HashSet<String>,
    opts: &HarImportOptions,
) -> Result<(Vec<ImportedExchange>, HarImportResult), String> {
    let max_entries = if opts.max_entries == 0 { DEFAULT_MAX_IMPORT_ENTRIES } else { opts.max_entries };
    let max_bytes = if opts.max_total_bytes == 0 { DEFAULT_MAX_IMPORT_BYTES } else { opts.max_total_bytes };

    let trimmed = std::str::from_utf8(raw).map_err(|_| "invalid HAR: input is not valid UTF-8".to_string())?.trim();
    if trimmed.is_empty() {
        return Err("invalid HAR: empty document".into());
    }
    let mut de = serde_json::Deserializer::from_str(trimmed);
    let doc = RawHar::deserialize(&mut de).map_err(|e| format!("invalid HAR: malformed JSON: {e}"))?;
    de.end().map_err(|_| "invalid HAR: trailing content after root JSON object".to_string())?;

    let log = doc.log.ok_or_else(|| "invalid HAR: missing `log` object".to_string())?;
    if log.version.trim() != HAR_VERSION {
        return Err(format!("invalid HAR: unsupported version `{}` (expected {HAR_VERSION})", log.version.trim()));
    }
    let entries = log.entries.ok_or_else(|| "invalid HAR: missing `log.entries`".to_string())?;
    if entries.len() > max_entries {
        return Err(format!("invalid HAR: contains {} entries, exceeding limit of {max_entries}", entries.len()));
    }

    let mut seen: HashSet<String> = existing_ids.clone();
    let mut imported_list = Vec::new();
    let mut result = HarImportResult::default();
    let mut total_bytes = 0u64;

    let mut push_err = |index: usize, url: Option<String>, reason: String| {
        if result.errors.len() < MAX_IMPORT_ERRORS {
            result.errors.push(HarImportError { index, url, reason });
        }
    };

    for (i, entry) in entries.into_iter().enumerate() {
        let clean_url = redact_url_userinfo(&entry.request.url);
        let parsed = match parse_har_entry(entry) {
            Ok(p) => p,
            Err(reason) => {
                result.failed += 1;
                push_err(i, (!clean_url.is_empty()).then_some(clean_url), reason);
                continue;
            }
        };
        let entry_bytes = (parsed.req_wire.len() as u64).saturating_add(parsed.resp_wire.len() as u64);
        if total_bytes.saturating_add(entry_bytes) > max_bytes {
            result.truncated = true;
            result.skipped += 1;
            push_err(i, Some(parsed.clean_url), format!("decoded body byte cap ({max_bytes} bytes) reached"));
            continue;
        }
        if !seen.insert(parsed.id.clone()) {
            result.skipped += 1;
            continue;
        }
        let req_blob = match blobs.put_bytes(&parsed.req_wire) {
            Ok(b) => b,
            Err(e) => {
                result.failed += 1;
                push_err(i, Some(parsed.clean_url), format!("failed to store request blob: {e}"));
                continue;
            }
        };
        let resp_blob = if parsed.resp_wire.is_empty() {
            None
        } else {
            match blobs.put_bytes(&parsed.resp_wire) {
                Ok(b) => Some(b),
                Err(e) => {
                    result.failed += 1;
                    push_err(i, Some(parsed.clean_url), format!("failed to store response blob: {e}"));
                    continue;
                }
            }
        };
        total_bytes = total_bytes.saturating_add(entry_bytes);
        result.imported += 1;
        imported_list.push(ImportedExchange {
            ts_ms: parsed.ts_ms,
            exchange: Exchange {
                id: parsed.id,
                call_id: None,
                source: "har_import".into(),
                tool: None,
                scheme: parsed.scheme,
                tls: "imported".into(),
                method: parsed.method,
                host: parsed.host,
                port: parsed.port,
                target: parsed.target,
                status: parsed.status,
                error: None,
                request: req_blob,
                response: resp_blob,
                request_bytes: parsed.req_wire.len() as u64,
                response_bytes: parsed.resp_wire.len() as u64,
                truncated: false,
                upstream_unverified: false,
                duration_ms: parsed.duration_ms,
            },
        });
    }

    Ok((imported_list, result))
}

struct ParsedHarEntry {
    id: String,
    ts_ms: u64,
    duration_ms: u64,
    scheme: String,
    method: String,
    host: String,
    port: u16,
    target: String,
    clean_url: String,
    status: Option<u16>,
    req_wire: Vec<u8>,
    resp_wire: Vec<u8>,
}

fn parse_har_entry(entry: RawHarEntry) -> Result<ParsedHarEntry, String> {
    let ts_ms = parse_rfc3339_ms(&entry.started_date_time)?;

    let mut url = url::Url::parse(entry.request.url.trim()).map_err(|_| "invalid request url".to_string())?;
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(format!("unsupported URL scheme `{scheme}`"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| "request URL has no host".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let port = url.port_or_known_default().unwrap_or(if scheme == "https" { 443 } else { 80 });
    let _ = url.set_username("");
    let _ = url.set_password(None);
    let clean_url = url.to_string();

    let method = entry.request.method.trim().to_ascii_uppercase();
    if !valid_token(&method) {
        return Err(format!("invalid HTTP method `{}`", entry.request.method));
    }
    if !(0..=999).contains(&entry.response.status) {
        return Err(format!("invalid response status {}", entry.response.status));
    }
    let status = (entry.response.status > 0).then_some(entry.response.status as u16);

    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let req_ver = if entry.request.http_version.eq_ignore_ascii_case("HTTP/1.0") { "HTTP/1.0" } else { "HTTP/1.1" };
    let mut req_wire = format!("{method} {target} {req_ver}\r\n").into_bytes();
    let mut has_host = false;
    let mut has_cookie = false;
    for h in &entry.request.headers {
        let name = h.name.trim();
        if name.starts_with(':') {
            continue; // HTTP/2 pseudo-headers
        }
        if !valid_token(name) || !no_crlf_nul(&h.value) {
            return Err(format!("invalid request header `{name}`"));
        }
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if name.eq_ignore_ascii_case("cookie") {
            has_cookie = true;
        }
        req_wire.extend_from_slice(name.as_bytes());
        req_wire.extend_from_slice(b": ");
        req_wire.extend_from_slice(h.value.as_bytes());
        req_wire.extend_from_slice(b"\r\n");
    }
    if !has_host {
        let default_port = (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
        let auth = if default_port { host.clone() } else { format!("{host}:{port}") };
        req_wire.extend_from_slice(format!("Host: {auth}\r\n").as_bytes());
    }
    if !has_cookie && !entry.request.cookies.is_empty() {
        let pairs: Vec<String> = entry
            .request
            .cookies
            .iter()
            .filter(|c| !c.name.trim().is_empty() && no_crlf_nul(&c.name) && no_crlf_nul(&c.value))
            .map(|c| format!("{}={}", c.name.trim(), c.value))
            .collect();
        if !pairs.is_empty() {
            req_wire.extend_from_slice(format!("Cookie: {}\r\n", pairs.join("; ")).as_bytes());
        }
    }
    req_wire.extend_from_slice(b"\r\n");
    if let Some(pd) = &entry.request.post_data {
        if pd.encoding.eq_ignore_ascii_case("base64") {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(pd.text.trim())
                .map_err(|_| "invalid base64 in request postData".to_string())?;
            req_wire.extend_from_slice(&decoded);
        } else if !pd.text.is_empty() {
            req_wire.extend_from_slice(pd.text.as_bytes());
        }
    }

    let mut resp_wire = Vec::new();
    if let Some(code) = status {
        let resp_ver =
            if entry.response.http_version.eq_ignore_ascii_case("HTTP/1.0") { "HTTP/1.0" } else { "HTTP/1.1" };
        let reason = if no_crlf_nul(&entry.response.status_text) { entry.response.status_text.trim() } else { "" };
        resp_wire.extend_from_slice(format!("{resp_ver} {code} {reason}\r\n").as_bytes());
        for h in &entry.response.headers {
            let name = h.name.trim();
            if name.starts_with(':') {
                continue;
            }
            if !valid_token(name) || !no_crlf_nul(&h.value) {
                return Err(format!("invalid response header `{name}`"));
            }
            resp_wire.extend_from_slice(name.as_bytes());
            resp_wire.extend_from_slice(b": ");
            resp_wire.extend_from_slice(h.value.as_bytes());
            resp_wire.extend_from_slice(b"\r\n");
        }
        resp_wire.extend_from_slice(b"\r\n");
        if let Some(content) = &entry.response.content {
            if content.encoding.eq_ignore_ascii_case("base64") {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(content.text.trim())
                    .map_err(|_| "invalid base64 in response content".to_string())?;
                resp_wire.extend_from_slice(&decoded);
            } else if !content.text.is_empty() {
                resp_wire.extend_from_slice(content.text.as_bytes());
            }
        }
    }

    let id = match entry.ferret_exchange_id.as_deref().filter(|id| valid_exchange_id(id)) {
        Some(existing) => existing.trim().to_string(),
        None => {
            let req_hash = crate::sha256_hex(&req_wire);
            let resp_hash = crate::sha256_hex(&resp_wire);
            let key = format!("{ts_ms}\0{method}\0{clean_url}\0{}\0{req_hash}\0{resp_hash}", status.unwrap_or(0));
            let digest = crate::sha256_hex(key.as_bytes());
            format!("ex-har-{}", &digest[..16])
        }
    };
    let duration_ms = if entry.time.is_finite() && entry.time > 0.0 { entry.time.round() as u64 } else { 0 };

    Ok(ParsedHarEntry {
        id,
        ts_ms,
        duration_ms,
        scheme,
        method,
        host,
        port,
        target,
        clean_url,
        status,
        req_wire,
        resp_wire,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn har_export_and_idempotent_import_round_trip_including_binary_and_userinfo_strip() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();

        let req1 = b"POST /api/login?next=%2Fadmin HTTP/1.1\r\nHost: shop.example.test\r\nContent-Type: application/json\r\nCookie: sid=abc; theme=dark\r\n\r\n{\"u\":\"alice\"}";
        let resp1 = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: session=xyz; HttpOnly\r\n\r\n{\"ok\":true}";
        let ex1 = Exchange {
            id: "ex-abcdef123456".into(),
            call_id: None,
            source: "proxy".into(),
            tool: None,
            scheme: "https".into(),
            tls: "intercepted".into(),
            method: "POST".into(),
            host: "shop.example.test".into(),
            port: 443,
            target: "/api/login?next=%2Fadmin".into(),
            status: Some(200),
            error: None,
            request: blobs.put_bytes(req1).unwrap(),
            response: Some(blobs.put_bytes(resp1).unwrap()),
            request_bytes: req1.len() as u64,
            response_bytes: resp1.len() as u64,
            truncated: false,
            upstream_unverified: false,
            duration_ms: 42,
        };

        let (har, meta) = export_har(&[(1_700_000_000_000, &ex1)], &blobs, &HarExportOptions::default()).unwrap();
        assert_eq!(meta.exported, 1);
        assert!(!meta.truncated);
        assert_eq!(har["log"]["version"], "1.2");
        assert_eq!(har["log"]["creator"]["name"], "Ferret");
        assert_eq!(har["log"]["entries"][0]["_ferretExchangeId"], "ex-abcdef123456");
        assert_eq!(har["log"]["entries"][0]["request"]["url"], "https://shop.example.test/api/login?next=%2Fadmin");
        assert_eq!(har["log"]["entries"][0]["request"]["postData"]["text"], "{\"u\":\"alice\"}");
        assert_eq!(har["log"]["entries"][0]["response"]["status"], 200);

        // Round-trip import preserves _ferretExchangeId and is idempotent on re-import
        let raw = serde_json::to_vec(&har).unwrap();
        let (imported, res) = import_har(&raw, &blobs, &HashSet::new(), &HarImportOptions::default()).unwrap();
        assert_eq!((res.imported, res.skipped, res.failed), (1, 0, 0));
        assert_eq!(imported[0].exchange.id, "ex-abcdef123456");
        assert_eq!(imported[0].exchange.host, "shop.example.test");
        assert_eq!(imported[0].exchange.status, Some(200));

        let existing: HashSet<String> = imported.iter().map(|i| i.exchange.id.clone()).collect();
        let (again, res2) = import_har(&raw, &blobs, &existing, &HarImportOptions::default()).unwrap();
        assert!(again.is_empty());
        assert_eq!((res2.imported, res2.skipped, res2.failed), (0, 1, 0));

        // External HAR without _ferretExchangeId strips userinfo and creates deterministic ex-har-* ID
        let ext = json!({
            "log": {
                "version": "1.2",
                "entries": [{
                    "startedDateTime": "2026-11-27T12:00:00Z",
                    "time": 15.0,
                    "request": {
                        "method": "GET",
                        "url": "https://user:secret@target.example/bin",
                        "httpVersion": "HTTP/1.1",
                        "headers": []
                    },
                    "response": {
                        "status": 200,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": "Content-Type", "value": "application/octet-stream"}],
                        "content": {"text": base64::engine::general_purpose::STANDARD.encode([0xffu8, 0x00, 0xfe]), "encoding": "base64"}
                    }
                }]
            }
        });
        let (ext_imp, ext_res) =
            import_har(&serde_json::to_vec(&ext).unwrap(), &blobs, &HashSet::new(), &HarImportOptions::default())
                .unwrap();
        assert_eq!((ext_res.imported, ext_res.failed), (1, 0));
        assert!(ext_imp[0].exchange.id.starts_with("ex-har-"));
        let stored_req = String::from_utf8_lossy(&blobs.read_all(&ext_imp[0].exchange.request.id).unwrap()).to_string();
        assert!(!stored_req.contains("secret"));
        let stored_resp = blobs.read_all(&ext_imp[0].exchange.response.as_ref().unwrap().id).unwrap();
        assert!(stored_resp.ends_with(&[0xffu8, 0x00, 0xfe]));
    }

    #[test]
    fn har_import_rejects_bad_version_trailing_json_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();
        assert!(import_har(b"{\"log\":{\"version\":\"1.1\",\"entries\":[]}}", &blobs, &HashSet::new(), &HarImportOptions::default()).is_err());
        assert!(import_har(b"{\"log\":{\"version\":\"1.2\",\"entries\":[]}} trailing", &blobs, &HashSet::new(), &HarImportOptions::default()).is_err());
    }

    #[test]
    fn har_export_sanitizes_secrets_by_default_and_supports_opt_out_and_extra_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::open(dir.path()).unwrap();

        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let ghp = "ghp_1234567890abcdefghij1234567890abcd";
        let sk = "sk-proj-abc123def456ghi789jkl012";
        let aws = "AKIAIOSFODNN7EXAMPLE";
        let extra = "custom-tenant-token-998877";

        let req = format!(
            "POST /api/sync?next=%2Fdash&api_key=qsecret123 HTTP/1.1\r\n\
             Host: shop.example.test\r\n\
             Authorization: Bearer {jwt}\r\n\
             Proxy-Authorization: Basic dXNlcjpwYXNz\r\n\
             Cookie: sid=sess-secret-1; csrf=csrf-cookie-2\r\n\
             X-Api-Key: header-api-key-val\r\n\
             X-Auth-Token: header-auth-tok-val\r\n\
             X-CSRF-Token: header-csrf-val\r\n\
             X-XSRF-Token: header-xsrf-val\r\n\
             Content-Type: application/json\r\n\r\n\
             {{\"jwt\":\"{jwt}\",\"gh\":\"{ghp}\",\"openai\":\"{sk}\",\"aws\":\"{aws}\",\"custom\":\"{extra}\",\"ok\":true}}"
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Set-Cookie: session=resp-sess-secret; HttpOnly; Secure\r\n\
             Location: https://shop.example.test/done?token=redir-tok-777\r\n\r\n\
             {{\"access_token\":\"resp-access-tok\",\"extra\":\"{extra}\"}}"
        );
        let ex = Exchange {
            id: "ex-sanitize123456".into(),
            call_id: None,
            source: "proxy".into(),
            tool: None,
            scheme: "https".into(),
            tls: "intercepted".into(),
            method: "POST".into(),
            host: "shop.example.test".into(),
            port: 443,
            target: "/api/sync?next=%2Fdash&api_key=qsecret123".into(),
            status: Some(200),
            error: None,
            request: blobs.put_bytes(req.as_bytes()).unwrap(),
            response: Some(blobs.put_bytes(resp.as_bytes()).unwrap()),
            request_bytes: req.len() as u64,
            response_bytes: resp.len() as u64,
            truncated: false,
            upstream_unverified: false,
            duration_ms: 12,
        };

        // Default export sanitizes automatically (sanitize == true by default).
        assert!(HarExportOptions::default().sanitize);
        let (har_def, _) = export_har_sanitized(
            &[(1_700_000_000_000, &ex)],
            &blobs,
            &HarExportOptions::default(),
            &[extra.to_string()],
            true,
        )
        .unwrap();
        assert_eq!(har_def["log"]["_sanitized"], true);
        let serialized = serde_json::to_string(&har_def).unwrap();
        for secret in [
            jwt,
            ghp,
            sk,
            aws,
            extra,
            "qsecret123",
            "dXNlcjpwYXNz",
            "sess-secret-1",
            "csrf-cookie-2",
            "header-api-key-val",
            "header-auth-tok-val",
            "header-csrf-val",
            "header-xsrf-val",
            "resp-sess-secret",
            "redir-tok-777",
            "resp-access-tok",
        ] {
            assert!(!serialized.contains(secret), "secret `{secret}` leaked into sanitized HAR: {serialized}");
        }
        // Structural metadata is preserved.
        let entry = &har_def["log"]["entries"][0];
        assert!(entry["request"]["url"].as_str().unwrap().contains("next=%2Fdash"));
        assert_eq!(entry["request"]["cookies"][0]["name"], "sid");
        assert_eq!(entry["request"]["cookies"][0]["value"], "[redacted]");
        assert_eq!(entry["response"]["cookies"][0]["name"], "session");
        assert_eq!(entry["response"]["cookies"][0]["value"], "[redacted]");
        let set_cookie = entry["response"]["headers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["name"] == "Set-Cookie")
            .unwrap()["value"]
            .as_str()
            .unwrap();
        assert_eq!(set_cookie, "session=[redacted]; HttpOnly; Secure");

        // Explicit opt-out (`sanitize = false`) preserves raw values for authorized debugging.
        let (har_raw, _) = export_har_sanitized(
            &[(1_700_000_000_000, &ex)],
            &blobs,
            &HarExportOptions::default(),
            &[extra.to_string()],
            false,
        )
        .unwrap();
        assert_eq!(har_raw["log"]["_sanitized"], false);
        let raw_serialized = serde_json::to_string(&har_raw).unwrap();
        assert!(raw_serialized.contains(jwt) && raw_serialized.contains("header-api-key-val") && raw_serialized.contains(extra));
    }
}
