//! Pure-Rust, zero-panic, strictly bounded streaming passive security analyzer.
//!
//! CONTRACT.
//!
//! - [`analyze_exchange`] inspects **post-redaction** HTTP/1.1 request and response bytes (heads +
//!   at most the first [`PASSIVE_MAX_BODY_BYTES`] bytes of response body) and returns at most
//!   [`PASSIVE_MAX_SIGNALS`] deduplicated [`PassiveSignal`]s.
//! - Never panics on malformed, truncated, binary, compressed, or non-UTF-8 inputs.
//! - Binary and compressed (`Content-Encoding` != `identity`) bodies skip text-body detectors
//!   while response headers are still inspected.
//! - Never copies raw secrets, cookie values, JWT tokens, or sensitive parameter values into
//!   `PassiveSignal::summary` or `PassiveSignal::detail`, and never re-triggers on `[redacted]`.

use base64::Engine as _;
use ferret_core::creds::REDACTED;
use ferret_core::event::PassiveSignal;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::OnceLock;

/// Maximum number of response body bytes inspected by passive analysis (256 KiB).
pub const PASSIVE_MAX_BODY_BYTES: usize = 256 * 1024;

/// Maximum number of distinct passive signals emitted per exchange.
pub const PASSIVE_MAX_SIGNALS: usize = 16;

/// Maximum header bytes parsed per HTTP message.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Maximum header lines parsed per HTTP message.
const MAX_PARSED_HEADERS: usize = 256;

/// Maximum reflected-input signals per exchange so large query strings cannot crowd out other kinds.
const MAX_REFLECTED_SIGNALS: usize = 3;

/// Maximum JWT candidates inspected in headers / body.
const MAX_JWT_SCANS_HEADER: usize = 32;
const MAX_JWT_SCANS_BODY: usize = 64;

/// Analyze a captured post-redaction HTTP exchange and return deduplicated passive security signals
/// (capped at [`PASSIVE_MAX_SIGNALS`]).
pub fn analyze_exchange(
    method: &str,
    host: &str,
    target: &str,
    status: Option<u16>,
    request: &[u8],
    response: Option<&[u8]>,
) -> Vec<PassiveSignal> {
    let _ = method;
    let Some(resp_bytes) = response else {
        return Vec::new();
    };
    if resp_bytes.is_empty() {
        return Vec::new();
    }

    let req = parse_request_head(request);
    let Some(resp) = parse_final_response(resp_bytes) else {
        return Vec::new();
    };

    let effective_status = status.or(resp.status);
    let effective_host = if !host.trim().is_empty() {
        norm_host(host)
    } else {
        req.header("host").map(strip_host_port).map(norm_host).unwrap_or_default()
    };
    let effective_target =
        if target.contains('?') || req.target.is_none() { target } else { req.target.as_deref().unwrap_or(target) };

    let content_type = resp.header("content-type").unwrap_or("");
    let media_type = parse_media_type(content_type);
    let compressed = resp
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("content-encoding") && !v.trim().eq_ignore_ascii_case("identity"));
    let chunked = resp
        .headers
        .iter()
        .rev()
        .find(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .is_some_and(|(_, v)| v.rsplit(',').next().is_some_and(|c| c.trim().eq_ignore_ascii_case("chunked")));

    let body_text = if compressed || is_binary_media_type(&media_type) || resp.body.is_empty() {
        None
    } else {
        let decoded: Cow<'_, [u8]> = if chunked {
            match decode_chunked_prefix(resp.body, PASSIVE_MAX_BODY_BYTES) {
                Some(v) => Cow::Owned(v),
                None => Cow::Borrowed(&resp.body[..resp.body.len().min(PASSIVE_MAX_BODY_BYTES)]),
            }
        } else {
            Cow::Borrowed(&resp.body[..resp.body.len().min(PASSIVE_MAX_BODY_BYTES)])
        };
        if decoded.is_empty() || looks_binary(&decoded) {
            None
        } else {
            Some(String::from_utf8_lossy(&decoded).into_owned())
        }
    };

    let mut out = SignalCollector::new();

    // 1. CORS misconfigurations
    check_cors(&req, &resp, &effective_host, &mut out);

    // 2. Insecure cookies
    check_cookies(&resp, &mut out);

    // 3. Reflected query input in text/html
    if let Some(body) = body_text.as_deref() {
        if is_html_media_type(&media_type) {
            check_reflected_input(effective_target, body, &mut out);
        }
    }

    // 4. Verbose SQL / stack trace / framework debug errors
    if let Some(body) = body_text.as_deref() {
        check_verbose_error(effective_status, body, &mut out);
    }

    // 5. Weak / unsigned JWTs (alg: none) in response headers, Set-Cookie, and body
    check_weak_jwt(&resp, body_text.as_deref(), &mut out);

    // 6. Unredacted high-confidence secrets in response body
    if let Some(body) = body_text.as_deref() {
        check_secret_leak(body, &mut out);
    }

    // 7. Exposed JS source maps (headers or body comment)
    check_sourcemap(&resp, effective_target, &media_type, body_text.as_deref(), &mut out);

    // 8. Missing security headers on 2xx text/html responses
    check_missing_security_headers(effective_status, &media_type, &resp, &mut out);

    out.into_vec()
}

struct SignalCollector {
    signals: Vec<PassiveSignal>,
    seen: HashSet<(String, String)>,
}

impl SignalCollector {
    fn new() -> Self {
        Self { signals: Vec::new(), seen: HashSet::new() }
    }

    fn push(&mut self, kind: &str, severity: &str, summary: impl Into<String>, detail: impl Into<String>) {
        if self.signals.len() >= PASSIVE_MAX_SIGNALS {
            return;
        }
        let summary = clean_line(&summary.into(), 200);
        let detail = clean_line(&detail.into(), 300);
        if summary.is_empty() {
            return;
        }
        let key = (kind.to_string(), summary.clone());
        if self.seen.insert(key) {
            self.signals.push(PassiveSignal {
                kind: kind.to_string(),
                severity: severity.to_string(),
                summary,
                detail,
            });
        }
    }

    fn into_vec(self) -> Vec<PassiveSignal> {
        self.signals
    }
}

struct ParsedRequest {
    target: Option<String>,
    headers: Vec<(String, String)>,
}

impl ParsedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

struct ParsedResponse<'a> {
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: &'a [u8],
}

impl ParsedResponse<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn find_head_split(bytes: &[u8]) -> Option<(usize, usize)> {
    let limit = bytes.len().min(MAX_HEAD_BYTES);
    let head_window = &bytes[..limit];
    for i in 0..head_window.len() {
        if head_window.get(i..i + 4) == Some(b"\r\n\r\n") {
            return Some((i, i + 4));
        }
        if head_window.get(i..i + 2) == Some(b"\n\n") {
            return Some((i, i + 2));
        }
    }
    None
}

fn parse_header_lines(head: &[u8]) -> (Option<String>, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split('\n');
    let first = lines.next().map(|l| l.trim_end_matches('\r').to_string());
    let mut headers = Vec::new();
    for line in lines.take(MAX_PARSED_HEADERS) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((name, val)) = line.split_once(':') {
            let name = name.trim();
            if !name.is_empty() {
                headers.push((name.to_string(), val.trim().to_string()));
            }
        }
    }
    (first, headers)
}

fn parse_request_head(bytes: &[u8]) -> ParsedRequest {
    if bytes.is_empty() {
        return ParsedRequest { target: None, headers: Vec::new() };
    }
    let head = match find_head_split(bytes) {
        Some((end, _)) => &bytes[..end],
        None => &bytes[..bytes.len().min(MAX_HEAD_BYTES)],
    };
    let (first, headers) = parse_header_lines(head);
    let target = first.and_then(|l| l.split_whitespace().nth(1).map(str::to_string));
    ParsedRequest { target, headers }
}

fn parse_status_line(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    let ver = parts.next()?;
    if !ver.to_ascii_uppercase().starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

fn parse_final_response(mut bytes: &[u8]) -> Option<ParsedResponse<'_>> {
    // Advance past any interim 1xx (except 101) response heads.
    for _ in 0..8 {
        let (head, body) = match find_head_split(bytes) {
            Some((head_end, body_start)) => (&bytes[..head_end], &bytes[body_start..]),
            None => (&bytes[..bytes.len().min(MAX_HEAD_BYTES)], &[][..]),
        };
        let (first, headers) = parse_header_lines(head);
        let status = first.as_deref().and_then(parse_status_line);
        if status.is_some_and(|c| (100..200).contains(&c) && c != 101) && !body.is_empty() {
            bytes = body;
            continue;
        }
        if status.is_none() && headers.is_empty() {
            return None;
        }
        return Some(ParsedResponse { status, headers, body });
    }
    None
}

fn decode_chunked_prefix(raw: &[u8], max_out: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < raw.len() && out.len() < max_out {
        while raw.get(i).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            i += 1;
        }
        let mut size = 0usize;
        let mut digits = false;
        while let Some(&b) = raw.get(i) {
            let Some(d) = char::from(b).to_digit(16) else { break };
            digits = true;
            size = size.checked_mul(16)?.checked_add(d as usize)?;
            if size > 64 * 1024 * 1024 {
                return None;
            }
            i += 1;
        }
        if !digits {
            return None;
        }
        let mut saw_nl = false;
        while let Some(&b) = raw.get(i) {
            i += 1;
            if b == b'\n' {
                saw_nl = true;
                break;
            }
        }
        if !saw_nl {
            break;
        }
        if size == 0 {
            break;
        }
        let avail = raw.len().saturating_sub(i);
        let chunk_avail = size.min(avail);
        let room = max_out.saturating_sub(out.len());
        let take = chunk_avail.min(room);
        out.extend_from_slice(&raw[i..i + take]);
        if chunk_avail < size || out.len() >= max_out {
            break;
        }
        i += size;
        if raw.get(i) == Some(&b'\r') {
            i += 1;
        }
        if raw.get(i) == Some(&b'\n') {
            i += 1;
        } else {
            break;
        }
    }
    Some(out)
}

fn parse_media_type(content_type: &str) -> String {
    content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

fn is_html_media_type(media: &str) -> bool {
    matches!(media, "text/html" | "application/xhtml+xml")
}

fn is_js_media_type(media: &str) -> bool {
    media.contains("javascript") || media.contains("ecmascript")
}

fn is_binary_media_type(media: &str) -> bool {
    media.starts_with("image/")
        || media.starts_with("audio/")
        || media.starts_with("video/")
        || media.starts_with("font/")
        || matches!(
            media,
            "application/octet-stream"
                | "application/pdf"
                | "application/zip"
                | "application/gzip"
                | "application/x-gzip"
                | "application/wasm"
                | "application/x-tar"
                | "application/x-bzip2"
                | "application/x-xz"
                | "application/x-7z-compressed"
                | "application/x-rar-compressed"
                | "application/protobuf"
                | "application/grpc"
        )
        || media.starts_with("application/vnd.ms-")
}

fn looks_binary(bytes: &[u8]) -> bool {
    let sample = &bytes[..bytes.len().min(8192)];
    if sample.is_empty() {
        return false;
    }
    // Common binary magic prefixes (gzip, PNG, JPEG, GIF, PDF, ZIP, ELF, WASM).
    const MAGICS: &[&[u8]] = &[
        b"\x1f\x8b",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"GIF87a",
        b"GIF89a",
        b"%PDF-",
        b"PK\x03\x04",
        b"\x7fELF",
        b"\x00asm",
    ];
    if MAGICS.iter().any(|m| sample.starts_with(m)) {
        return true;
    }
    if sample.contains(&0) {
        return true;
    }
    let ctrl = sample.iter().filter(|&&b| (b < 0x20 && !matches!(b, b'\t' | b'\r' | b'\n')) || b == 0x7f).count();
    if ctrl * 100 > sample.len() * 10 {
        return true;
    }
    if std::str::from_utf8(sample).is_err() {
        let lossy = String::from_utf8_lossy(sample);
        let repl = lossy.chars().filter(|&c| c == '\u{FFFD}').count();
        let total = lossy.chars().count().max(1);
        if repl * 100 > total * 15 {
            return true;
        }
    }
    false
}

fn norm_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    let inner = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(trimmed);
    inner.to_ascii_lowercase()
}

fn strip_host_port(host_hdr: &str) -> &str {
    let trimmed = host_hdr.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &trimmed[..end + 2];
        }
    }
    match trimmed.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => trimmed,
    }
}

fn clean_line(s: &str, max_bytes: usize) -> String {
    let collapsed: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.len() <= max_bytes {
        return collapsed;
    }
    let mut end = max_bytes.saturating_sub(1);
    while end > 0 && !collapsed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &collapsed[..end])
}

// ---- 1. CORS misconfigurations ----

fn check_cors(req: &ParsedRequest, resp: &ParsedResponse<'_>, target_host: &str, out: &mut SignalCollector) {
    let Some(acao) = resp.header("access-control-allow-origin").map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    let acac_true =
        resp.header("access-control-allow-credentials").is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    if !acac_true {
        return;
    }

    if acao == "*" {
        out.push(
            "cors_misconfig",
            "high",
            "CORS wildcard Access-Control-Allow-Origin: * with Allow-Credentials: true",
            "Response combines Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
        );
        return;
    }
    if acao.eq_ignore_ascii_case("null") {
        out.push(
            "cors_misconfig",
            "high",
            "CORS allows null Origin with Allow-Credentials: true",
            "Response sets Access-Control-Allow-Origin: null with Access-Control-Allow-Credentials: true",
        );
        return;
    }
    let Some(req_origin) = req.header("origin").map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    if !acao.eq_ignore_ascii_case(req_origin) {
        return;
    }
    let Ok(origin_url) = url::Url::parse(req_origin) else {
        return;
    };
    let Some(origin_host) = origin_url.host_str().map(norm_host).filter(|s| !s.is_empty()) else {
        return;
    };
    if !target_host.is_empty() && origin_host != target_host {
        out.push(
            "cors_misconfig",
            "high",
            "CORS reflects cross-origin Origin with Allow-Credentials: true",
            format!(
                "Request Origin host '{origin_host}' reflected in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true (target host '{target_host}')"
            ),
        );
    }
}

// ---- 2. Insecure cookies ----

fn is_session_cookie_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    const SUBSTRS: &[&str] =
        &["session", "sess", "token", "auth", "jwt", "csrf", "xsrf", "connect.sid", "phpsessid", "jsessionid"];
    if SUBSTRS.iter().any(|k| lower.contains(k)) {
        return true;
    }
    lower == "sid" || lower.split(['_', '-', '.']).any(|seg| seg == "sid")
}

fn is_csrf_cookie_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    (lower.contains("csrf") || lower.contains("xsrf"))
        && !lower.contains("session")
        && !lower.contains("sess")
        && !lower.contains("auth")
        && !lower.contains("jwt")
}

fn check_cookies(resp: &ParsedResponse<'_>, out: &mut SignalCollector) {
    for (hdr_name, val) in &resp.headers {
        if !hdr_name.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let mut parts = val.split(';');
        let Some(first) = parts.next() else { continue };
        let Some((raw_name, raw_val)) = first.split_once('=') else { continue };
        let cookie_name = raw_name.trim();
        let cookie_val = raw_val.trim();
        if cookie_name.is_empty() {
            continue;
        }

        let mut has_httponly = false;
        let mut has_secure = false;
        let mut samesite_none = false;
        let mut clears_cookie = false;

        for attr in parts {
            let a = attr.trim();
            if a.eq_ignore_ascii_case("httponly") {
                has_httponly = true;
            } else if a.eq_ignore_ascii_case("secure") {
                has_secure = true;
            } else if let Some((k, v)) = a.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if k.eq_ignore_ascii_case("samesite") && v.eq_ignore_ascii_case("none") {
                    samesite_none = true;
                } else if (k.eq_ignore_ascii_case("max-age") && v.parse::<i64>().is_ok_and(|n| n <= 0))
                    || (k.eq_ignore_ascii_case("expires") && v.contains("1970"))
                {
                    clears_cookie = true;
                }
            }
        }

        // Skip explicit cookie deletion instructions (empty value with Max-Age<=0 or epoch Expires).
        if cookie_val.is_empty() && clears_cookie {
            continue;
        }

        if samesite_none && !has_secure {
            out.push(
                "cookie_insecure",
                "medium",
                format!("Cookie '{cookie_name}' has SameSite=None without Secure"),
                format!("Set-Cookie '{cookie_name}' sets SameSite=None without the Secure attribute"),
            );
        }

        if is_session_cookie_name(cookie_name) {
            let mut missing = Vec::new();
            if !has_httponly {
                missing.push("HttpOnly");
            }
            if !has_secure {
                missing.push("Secure");
            }
            if !missing.is_empty() {
                let severity =
                    if missing == ["HttpOnly"] && is_csrf_cookie_name(cookie_name) { "low" } else { "medium" };
                out.push(
                    "cookie_insecure",
                    severity,
                    format!("Session/auth cookie '{cookie_name}' missing {}", missing.join(" and ")),
                    format!("Set-Cookie for '{cookie_name}' omits {} flag(s)", missing.join(", ")),
                );
            }
        }
    }
}

// ---- 3. Reflected query input in text/html ----

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_pure_number(s: &str) -> bool {
    let s = s.strip_prefix('-').unwrap_or(s);
    if s.is_empty() {
        return false;
    }
    let mut dots = 0usize;
    for b in s.bytes() {
        if b == b'.' {
            dots += 1;
            if dots > 1 {
                return false;
            }
        } else if !b.is_ascii_digit() {
            return false;
        }
    }
    s.bytes().any(|b| b.is_ascii_digit())
}

fn is_trivial_query_value(val: &str) -> bool {
    if val.len() < 5 || val.len() > 512 {
        return true;
    }
    if val.contains(REDACTED) {
        return true;
    }
    if is_pure_number(val) {
        return true;
    }
    if val.bytes().all(|b| b.is_ascii_whitespace()) {
        return true;
    }
    let lower = val.to_ascii_lowercase();
    const STOPWORDS: &[&str] = &[
        "false",
        "undefined",
        "index",
        "default",
        "search",
        "login",
        "logout",
        "about",
        "contact",
        "active",
        "inactive",
        "pending",
        "closed",
        "latest",
        "newest",
        "oldest",
        "popular",
        "ascending",
        "descending",
        "english",
        "en-us",
        "en_us",
        "utf-8",
        "public",
        "private",
        "order",
        "title",
        "created",
        "updated",
        "price",
        "email",
        "status",
        "filter",
        "format",
        "theme",
        "light",
        "desktop",
        "mobile",
        "empty",
    ];
    STOPWORDS.contains(&lower.as_str())
}

fn check_reflected_input(target: &str, body: &str, out: &mut SignalCollector) {
    let without_frag = target.split('#').next().unwrap_or(target);
    let Some((_, query)) = without_frag.split_once('?') else {
        return;
    };
    let mut emitted = 0usize;
    for pair in query.split('&') {
        if emitted >= MAX_REFLECTED_SIGNALS {
            break;
        }
        let Some((raw_k, raw_v)) = pair.split_once('=') else { continue };
        let key = percent_decode(raw_k);
        let key = key.trim();
        if key.is_empty() || raw_v.is_empty() {
            continue;
        }
        let decoded = percent_decode(raw_v);
        if is_trivial_query_value(&decoded) {
            continue;
        }
        if body.contains(&decoded) {
            let has_html_meta = decoded.bytes().any(|b| matches!(b, b'<' | b'>' | b'"' | b'\'' | b'`'));
            let detail = if has_html_meta {
                format!(
                    "Query parameter '{key}' (len={}) with HTML-significant characters reflected verbatim unencoded in text/html response",
                    decoded.len()
                )
            } else {
                format!(
                    "Query parameter '{key}' (len={}) reflected verbatim unencoded in text/html response",
                    decoded.len()
                )
            };
            out.push(
                "reflected_input",
                "medium",
                format!("Query parameter '{key}' reflected unencoded in HTML body"),
                detail,
            );
            emitted += 1;
        }
    }
}

// ---- 4. Verbose errors / stack traces / debug pages ----

struct ErrorPatterns {
    sql: Regex,
    java_stack: Regex,
    node_stack: Regex,
    php_error: Regex,
    go_stack: Regex,
    rust_panic: Regex,
}

fn error_patterns() -> &'static ErrorPatterns {
    static PATS: OnceLock<ErrorPatterns> = OnceLock::new();
    PATS.get_or_init(|| ErrorPatterns {
        sql: Regex::new(
            r"(?i)(?:sql syntax|\bORA-\d{4,5}\b|PG::|sqlite3\.|SQLite3::|PSQLException|SQLSTATE\[|unclosed quotation mark|\[ODBC\b|\bODBC\s+(?:driver|error|exception|sql|syntax|failed)\b)",
        )
        .expect("valid sql error regex"),
        java_stack: Regex::new(r"(?:\bat\s+(?:java|javax|org\.springframework)\.|Exception in thread\s+)").expect("valid java stack regex"),
        node_stack: Regex::new(r"(?:at Object\.<anonymous>|\bReferenceError:)").expect("valid node stack regex"),
        php_error: Regex::new(r"(?i)(?:(?:<b>)?Fatal error(?:</b>)?\s*:|Stack trace:\s*(?:#0\b|\r?\n\s*#0\b))")
            .expect("valid php error regex"),
        go_stack: Regex::new(r"goroutine \d+ \[").expect("valid go stack regex"),
        rust_panic: Regex::new(r"panicked at ").expect("valid rust panic regex"),
    })
}

fn check_verbose_error(status: Option<u16>, body: &str, out: &mut SignalCollector) {
    let pats = error_patterns();

    if let Some(m) = pats.sql.find(body) {
        out.push(
            "verbose_error",
            "medium",
            "SQL syntax or database driver error disclosed in response",
            format!("Matched database error indicator '{}' in response body", clean_line(m.as_str(), 64)),
        );
    }

    // Framework debug pages (Django / Flask / Werkzeug / Rails)
    let django_debug = (body.contains("You're seeing this error because you have") && body.contains("DEBUG = True"))
        || (body.contains("Django Version:") && body.contains("Exception Location:"));
    let werkzeug_debug = body.contains("Werkzeug Debugger")
        || body.contains("The debugger caught an exception in your WSGI application")
        || body.contains("werkzeug.debug");
    let rails_debug = body.contains("Action Controller: Exception caught")
        || (body.contains("Rails.root:") && body.contains("Application Trace"));
    if django_debug {
        out.push(
            "verbose_error",
            "medium",
            "Django debug error page exposed",
            "Response contains Django DEBUG=True exception traceback page",
        );
    } else if werkzeug_debug {
        out.push(
            "verbose_error",
            "medium",
            "Flask/Werkzeug debug page exposed",
            "Response contains Werkzeug interactive debugger error output",
        );
    } else if rails_debug {
        out.push(
            "verbose_error",
            "medium",
            "Ruby on Rails debug error page exposed",
            "Response contains Rails Action Controller debug exception page",
        );
    }

    let stack_sev = if status.is_some_and(|c| c >= 500) { "medium" } else { "low" };
    let stack_hit: Option<(&str, &str)> = if body.contains("Traceback (most recent call last)") {
        Some(("Python", "Traceback (most recent call last)"))
    } else if pats.java_stack.is_match(body) {
        Some(("Java/Spring", "Java stack frame / exception trace"))
    } else if pats.node_stack.is_match(body) {
        Some(("Node.js/Express", "Node.js ReferenceError or stack frame"))
    } else if pats.php_error.is_match(body) {
        Some(("PHP", "PHP Fatal error or stack trace"))
    } else if pats.go_stack.is_match(body) {
        Some(("Go", "Go goroutine panic trace"))
    } else if pats.rust_panic.is_match(body) {
        Some(("Rust", "Rust panic trace"))
    } else {
        None
    };

    if let Some((lang, indicator)) = stack_hit {
        out.push(
            "verbose_error",
            stack_sev,
            format!("{lang} stack trace disclosed in response"),
            format!("Detected {indicator} in response body"),
        );
    }
}

// ---- 5. Weak / unsigned JWT (alg: none) ----

fn jwt_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{4,512}\.[A-Za-z0-9_-]{2,4096}\.[A-Za-z0-9_-]{0,1024}")
            .expect("valid jwt candidate regex")
    })
}

fn jwt_none_alg(candidate: &str) -> Option<String> {
    let header_b64 = candidate.split('.').next()?.trim_end_matches('=');
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    let alg = json.get("alg")?.as_str()?;
    alg.eq_ignore_ascii_case("none").then(|| alg.to_string())
}

fn check_weak_jwt(resp: &ParsedResponse<'_>, body: Option<&str>, out: &mut SignalCollector) {
    let re = jwt_regex();
    let mut scanned = 0usize;
    for (name, val) in &resp.headers {
        if scanned >= MAX_JWT_SCANS_HEADER {
            break;
        }
        if !val.contains("eyJ") {
            continue;
        }
        for m in re.find_iter(val) {
            scanned += 1;
            if let Some(alg) = jwt_none_alg(m.as_str()) {
                let location = if name.eq_ignore_ascii_case("set-cookie") {
                    "Set-Cookie header".to_string()
                } else {
                    format!("response header '{name}'")
                };
                out.push(
                    "weak_jwt",
                    "high",
                    format!("Unsigned JWT (alg={alg}) in {location}"),
                    format!("Decoded JWT header specifies algorithm '{alg}' in {location} (token omitted)"),
                );
                break;
            }
            if scanned >= MAX_JWT_SCANS_HEADER {
                break;
            }
        }
    }

    if let Some(body) = body {
        if body.contains("eyJ") {
            for m in re.find_iter(body).take(MAX_JWT_SCANS_BODY) {
                if let Some(alg) = jwt_none_alg(m.as_str()) {
                    out.push(
                        "weak_jwt",
                        "high",
                        format!("Unsigned JWT (alg={alg}) in response body"),
                        format!("Decoded JWT header specifies algorithm '{alg}' in response body (token omitted)"),
                    );
                    break;
                }
            }
        }
    }
}

// ---- 6. High-confidence unredacted secrets in response body ----

struct SecretPatterns {
    aws: Regex,
    github: Regex,
    stripe: Regex,
    slack: Regex,
    google: Regex,
    pem: Regex,
}

fn secret_patterns() -> &'static SecretPatterns {
    static PATS: OnceLock<SecretPatterns> = OnceLock::new();
    PATS.get_or_init(|| SecretPatterns {
        aws: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid aws regex"),
        github: Regex::new(r"\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b").expect("valid github regex"),
        stripe: Regex::new(r"\bsk_live_[A-Za-z0-9]{16,}\b").expect("valid stripe regex"),
        slack: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").expect("valid slack regex"),
        google: Regex::new(r"\bAIza[0-9A-Za-z_-]{35}\b").expect("valid google regex"),
        pem: Regex::new(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----").expect("valid pem regex"),
    })
}

fn check_secret_leak(body: &str, out: &mut SignalCollector) {
    let pats = secret_patterns();
    let checks: &[(&Regex, &str, &str)] = &[
        (&pats.aws, "AWS access key", "AKIA/ASIA"),
        (&pats.github, "GitHub personal access token", "ghp_/github_pat_"),
        (&pats.stripe, "Stripe live secret key", "sk_live_"),
        (&pats.slack, "Slack token", "xox*"),
        (&pats.google, "Google API key", "AIza"),
    ];
    for &(re, label, prefix_hint) in checks {
        if let Some(m) = re.find(body) {
            let matched = m.as_str();
            if matched.contains(REDACTED) {
                continue;
            }
            out.push(
                "secret_leak",
                "high",
                format!("Unredacted {label} detected in response body"),
                format!(
                    "Matched {label} pattern ({prefix_hint}, len={}) in response body; secret value omitted",
                    matched.len()
                ),
            );
        }
    }
    for m in pats.pem.find_iter(body) {
        let after = &body[m.end()..];
        if !after.trim_start().starts_with(REDACTED) {
            out.push(
                "secret_leak",
                "high",
                "Unredacted PEM private key detected in response body",
                "Matched PEM private key block header in response body; key material omitted",
            );
            break;
        }
    }
}

// ---- 7. Source maps exposed ----

fn sourcemap_comment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)//[#@]\s*sourceMappingURL=(\S+)").expect("valid sourcemap regex"))
}

fn check_sourcemap(
    resp: &ParsedResponse<'_>,
    target: &str,
    media_type: &str,
    body: Option<&str>,
    out: &mut SignalCollector,
) {
    for (name, val) in &resp.headers {
        if (name.eq_ignore_ascii_case("sourcemap") || name.eq_ignore_ascii_case("x-sourcemap"))
            && !val.trim().is_empty()
        {
            let clean_ref = ferret_core::sanitize::sanitize_url(val.trim(), &[]);
            out.push(
                "sourcemap_exposed",
                "low",
                format!("Source map exposed via {name} response header"),
                format!("{name}: {clean_ref}"),
            );
        }
    }

    let path = target.split(['?', '#']).next().unwrap_or(target).to_ascii_lowercase();
    let is_js =
        is_js_media_type(media_type) || path.ends_with(".js") || path.ends_with(".mjs") || path.ends_with(".cjs");
    if is_js {
        if let Some(body) = body {
            if let Some(caps) = sourcemap_comment_regex().captures(body) {
                let raw_url = caps.get(1).map_or("", |m| m.as_str()).trim();
                let detail = if raw_url.to_ascii_lowercase().starts_with("data:") {
                    "JavaScript body contains inline data: sourceMappingURL comment".to_string()
                } else {
                    let clean_ref = ferret_core::sanitize::sanitize_url(raw_url, &[]);
                    format!("JavaScript body references sourceMappingURL={clean_ref}")
                };
                out.push(
                    "sourcemap_exposed",
                    "info",
                    "JavaScript sourceMappingURL comment exposed in response body",
                    detail,
                );
            }
        }
    }
}

// ---- 8. Missing security headers ----

fn check_missing_security_headers(
    status: Option<u16>,
    media_type: &str,
    resp: &ParsedResponse<'_>,
    out: &mut SignalCollector,
) {
    let Some(code) = status else { return };
    if !(200..300).contains(&code) || media_type != "text/html" {
        return;
    }
    let has_csp = resp.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-security-policy"));
    let has_xfo = resp.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("x-frame-options"));
    if !has_csp && !has_xfo {
        out.push(
            "missing_security_headers",
            "info",
            "HTML response missing Content-Security-Policy and X-Frame-Options",
            "2xx text/html response omits both Content-Security-Policy and X-Frame-Options",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_resp(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status}\r\n").into_bytes();
        for (k, v) in headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(body);
        out
    }

    fn http_req(line: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut out = format!("{line}\r\n").into_bytes();
        for (k, v) in headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    #[test]
    fn cors_misconfigs_detect_wildcard_null_and_cross_origin_reflection_only_with_credentials() {
        let req = http_req("GET /api HTTP/1.1", &[("Host", "api.example.test"), ("Origin", "https://evil.test")]);

        // Wildcard + credentials
        let resp = http_resp(
            "200 OK",
            &[("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")],
            b"{}",
        );
        let sigs = analyze_exchange("GET", "api.example.test", "/api", Some(200), &req, Some(&resp));
        assert!(sigs.iter().any(|s| s.kind == "cors_misconfig" && s.severity == "high"), "{sigs:?}");

        // Wildcard WITHOUT credentials -> no signal
        let safe_wild = http_resp("200 OK", &[("Access-Control-Allow-Origin", "*")], b"{}");
        assert!(analyze_exchange("GET", "api.example.test", "/api", Some(200), &req, Some(&safe_wild)).is_empty());

        // null + credentials
        let null_resp = http_resp(
            "200 OK",
            &[("Access-Control-Allow-Origin", "null"), ("Access-Control-Allow-Credentials", "true")],
            b"{}",
        );
        let sigs = analyze_exchange("GET", "api.example.test", "/api", Some(200), &req, Some(&null_resp));
        assert!(sigs.iter().any(|s| s.kind == "cors_misconfig" && s.summary.contains("null")), "{sigs:?}");

        // Reflected cross-origin Origin + credentials
        let refl_resp = http_resp(
            "200 OK",
            &[("Access-Control-Allow-Origin", "https://evil.test"), ("Access-Control-Allow-Credentials", "true")],
            b"{}",
        );
        let sigs = analyze_exchange("GET", "api.example.test", "/api", Some(200), &req, Some(&refl_resp));
        assert!(sigs.iter().any(|s| s.kind == "cors_misconfig" && s.detail.contains("evil.test")), "{sigs:?}");

        // Same-origin reflected Origin + credentials -> NOT flagged
        let same_req =
            http_req("GET /api HTTP/1.1", &[("Host", "api.example.test"), ("Origin", "https://api.example.test")]);
        let same_resp = http_resp(
            "200 OK",
            &[
                ("Access-Control-Allow-Origin", "https://api.example.test"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
            b"{}",
        );
        assert!(analyze_exchange("GET", "api.example.test", "/api", Some(200), &same_req, Some(&same_resp)).is_empty());
    }

    #[test]
    fn cookie_insecure_detects_missing_flags_and_samesite_none_without_leaking_values() {
        let req = http_req("GET /login HTTP/1.1", &[("Host", "app.test")]);
        let resp = http_resp(
            "200 OK",
            &[
                ("Set-Cookie", "PHPSESSID=super-secret-cookie-val; Path=/"),
                ("Set-Cookie", "prefs=dark; SameSite=None; Path=/"),
                ("Set-Cookie", "sidebar=open; Path=/"),
                ("Set-Cookie", "connect.sid=safe-val; HttpOnly; Secure; SameSite=Lax"),
                ("Set-Cookie", "csrf_token=tok123; Secure"),
                ("Set-Cookie", "session=; Max-Age=0; Path=/"),
            ],
            b"ok",
        );
        let sigs = analyze_exchange("GET", "app.test", "/login", Some(200), &req, Some(&resp));
        assert!(sigs.iter().any(|s| s.kind == "cookie_insecure" && s.summary.contains("PHPSESSID")), "{sigs:?}");
        assert!(sigs.iter().any(|s| s.kind == "cookie_insecure" && s.summary.contains("prefs")), "{sigs:?}");
        assert!(
            sigs.iter().any(|s| s.kind == "cookie_insecure" && s.summary.contains("csrf_token") && s.severity == "low"),
            "{sigs:?}"
        );
        // Non-session cookie `sidebar`, hardened `connect.sid`, and logout deletion `session=; Max-Age=0` are ignored.
        assert!(!sigs.iter().any(|s| s.summary.contains("sidebar") || s.summary.contains("connect.sid")), "{sigs:?}");
        assert!(!sigs.iter().any(|s| s.summary.contains("'session'")), "{sigs:?}");
        // Raw cookie values never appear in summary or detail.
        for s in &sigs {
            assert!(!s.summary.contains("super-secret-cookie-val") && !s.detail.contains("super-secret-cookie-val"));
            assert!(!s.summary.contains("tok123") && !s.detail.contains("tok123"));
        }
    }

    #[test]
    fn reflected_input_flags_non_trivial_unencoded_html_reflection_and_skips_noise() {
        let req = http_req("GET /search HTTP/1.1", &[("Host", "app.test")]);
        let html_headers =
            &[("Content-Type", "text/html; charset=utf-8"), ("Content-Security-Policy", "default-src 'self'")];

        // Reflected non-trivial probe with HTML characters
        let body = b"<html><body>Results for <probe_token></body></html>";
        let resp = http_resp("200 OK", html_headers, body);
        let sigs = analyze_exchange(
            "GET",
            "app.test",
            "/search?q=%3Cprobe_token%3E&page=12345&active=false&short=abc",
            Some(200),
            &req,
            Some(&resp),
        );
        assert_eq!(sigs.len(), 1, "{sigs:?}");
        assert_eq!(sigs[0].kind, "reflected_input");
        assert_eq!(sigs[0].severity, "medium");
        assert!(sigs[0].summary.contains("'q'"));

        // Properly HTML-encoded output -> NOT flagged
        let encoded_resp = http_resp("200 OK", html_headers, b"<html>&lt;probe_token&gt;</html>");
        assert!(analyze_exchange(
            "GET",
            "app.test",
            "/search?q=%3Cprobe_token%3E",
            Some(200),
            &req,
            Some(&encoded_resp)
        )
        .is_empty());

        // JSON response -> NOT flagged
        let json_resp = http_resp("200 OK", &[("Content-Type", "application/json")], b"{\"q\":\"<probe_token>\"}");
        assert!(analyze_exchange("GET", "app.test", "/search?q=%3Cprobe_token%3E", Some(200), &req, Some(&json_resp))
            .is_empty());

        // Pure numbers, stopwords, and [redacted] are skipped
        let noise_resp = http_resp("200 OK", html_headers, b"<html>12345 false [redacted]</html>");
        assert!(analyze_exchange(
            "GET",
            "app.test",
            "/search?id=12345&flag=false&tok=[redacted]",
            Some(200),
            &req,
            Some(&noise_resp),
        )
        .is_empty());
    }

    #[test]
    fn verbose_error_detects_sql_stack_traces_and_debug_pages() {
        let req = http_req("GET /item HTTP/1.1", &[("Host", "app.test")]);
        let samples: &[(&str, &[u8])] = &[
            ("sql mysql", b"You have an error in your SQL syntax near ''"),
            ("sql oracle", b"ORA-00933: SQL command not properly ended"),
            ("sql pg", b"PG::SyntaxError: ERROR: syntax error at or near"),
            ("sql sqlite", b"sqlite3.OperationalError: near \"x\": syntax error"),
            ("sql odbc", b"[Microsoft][ODBC SQL Server Driver] Unclosed quotation mark"),
            ("python", b"Traceback (most recent call last):\n  File \"app.py\", line 12"),
            ("java", b"Exception in thread \"main\" java.lang.NullPointerException\n\tat java.base/Foo.bar"),
            ("node", b"ReferenceError: x is not defined\n    at Object.<anonymous> (/app/index.js:4:1)"),
            ("php", b"Fatal error: Uncaught Error in /var/www/index.php:9\nStack trace:\n#0 {main}"),
            ("go", b"panic: runtime error\ngoroutine 1 [running]:\nmain.main()"),
            ("rust", b"thread 'main' panicked at src/main.rs:10:5:\nindex out of bounds"),
            ("django", b"You're seeing this error because you have DEBUG = True in your Django settings file."),
            ("werkzeug", b"<title>Werkzeug Debugger</title>"),
            ("rails", b"<h1>Action Controller: Exception caught</h1>"),
        ];
        for (name, body) in samples {
            let resp = http_resp("500 Internal Server Error", &[("Content-Type", "text/plain")], body);
            let sigs = analyze_exchange("GET", "app.test", "/item", Some(500), &req, Some(&resp));
            assert!(sigs.iter().any(|s| s.kind == "verbose_error"), "missed {name}: {sigs:?}");
        }
    }

    #[test]
    fn weak_jwt_detects_alg_none_in_headers_cookies_and_body_without_flagging_signed_jwts() {
        let req = http_req("GET /auth HTTP/1.1", &[("Host", "app.test")]);
        let none_hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"sub":"u1"}"#);
        let unsigned_jwt = format!("{none_hdr}.{payload}.");

        let hs256_hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
        let signed_jwt = format!("{hs256_hdr}.{payload}.dummysig123456");

        // In Set-Cookie
        let resp = http_resp("200 OK", &[("Set-Cookie", &format!("auth={unsigned_jwt}; HttpOnly; Secure"))], b"ok");
        let sigs = analyze_exchange("GET", "app.test", "/auth", Some(200), &req, Some(&resp));
        assert!(sigs.iter().any(|s| s.kind == "weak_jwt" && s.severity == "high" && s.summary.contains("Set-Cookie")));
        assert!(!sigs.iter().any(|s| s.detail.contains(&unsigned_jwt)));

        // In response body
        let body_resp = http_resp(
            "200 OK",
            &[("Content-Type", "application/json")],
            format!("{{\"token\":\"{unsigned_jwt}\"}}").as_bytes(),
        );
        let sigs = analyze_exchange("GET", "app.test", "/auth", Some(200), &req, Some(&body_resp));
        assert!(sigs.iter().any(|s| s.kind == "weak_jwt" && s.summary.contains("response body")));

        // Signed HS256 JWT -> NOT flagged
        let ok_resp = http_resp(
            "200 OK",
            &[("Content-Type", "application/json")],
            format!("{{\"token\":\"{signed_jwt}\"}}").as_bytes(),
        );
        assert!(analyze_exchange("GET", "app.test", "/auth", Some(200), &req, Some(&ok_resp)).is_empty());
    }

    #[test]
    fn secret_leak_detects_vendor_keys_and_pem_and_never_triggers_on_redacted() {
        let req = http_req("GET /cfg HTTP/1.1", &[("Host", "app.test")]);
        // Construct synthetic test tokens via concat so static secret scanners don't treat test literals as real keys.
        let aws = format!("{}{}", "AKIA", "0123456789ABCDEF");
        let ghp = format!("{}{}", "ghp_", "AbCdEfGhIjKlMnOpQrStUvWx");
        let stripe = format!("{}{}", "sk_live_", "0123456789abcdef1234");
        let slack = format!("{}{}", "xoxb-", "1234567890-abcdefghij");
        let google = format!("{}{}", "AIza", "0123456789abcdefghijklmnopqrstuvwxy");
        let pem = format!("{}RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----", "-----BEGIN ");

        for (label, tok) in [
            ("aws", aws.as_str()),
            ("github", ghp.as_str()),
            ("stripe", stripe.as_str()),
            ("slack", slack.as_str()),
            ("google", google.as_str()),
            ("pem", pem.as_str()),
        ] {
            let resp = http_resp("200 OK", &[("Content-Type", "text/plain")], tok.as_bytes());
            let sigs = analyze_exchange("GET", "app.test", "/cfg", Some(200), &req, Some(&resp));
            assert!(sigs.iter().any(|s| s.kind == "secret_leak" && s.severity == "high"), "missed {label}: {sigs:?}");
            // Raw secret must NEVER be copied into PassiveSignal.summary or PassiveSignal.detail!
            for s in &sigs {
                assert!(!s.summary.contains(tok) && !s.detail.contains(tok), "leaked {label} in {s:?}");
            }
        }

        // Redacted placeholders must never trigger secret_leak
        let redacted_body = b"aws=[redacted] github=[redacted] -----BEGIN PRIVATE KEY-----[redacted]";
        let resp = http_resp("200 OK", &[("Content-Type", "text/plain")], redacted_body);
        assert!(analyze_exchange("GET", "app.test", "/cfg", Some(200), &req, Some(&resp)).is_empty());
    }

    #[test]
    fn sourcemap_and_missing_security_headers_are_detected_cleanly() {
        let req = http_req("GET /app.js HTTP/1.1", &[("Host", "app.test")]);
        let js_resp = http_resp(
            "200 OK",
            &[("Content-Type", "application/javascript"), ("X-SourceMap", "/static/app.js.map?token=secret123")],
            b"console.log(1);\n//# sourceMappingURL=app.js.map\n",
        );
        let sigs = analyze_exchange("GET", "app.test", "/app.js", Some(200), &req, Some(&js_resp));
        assert_eq!(sigs.iter().filter(|s| s.kind == "sourcemap_exposed").count(), 2, "{sigs:?}");
        // Query token in SourceMap URL is sanitized in detail
        assert!(!sigs.iter().any(|s| s.detail.contains("secret123")), "{sigs:?}");

        // 2xx text/html missing both CSP and XFO -> 1 combined signal
        let html_no_hdrs = http_resp("200 OK", &[("Content-Type", "text/html")], b"<html>hi</html>");
        let sigs = analyze_exchange("GET", "app.test", "/", Some(200), &req, Some(&html_no_hdrs));
        assert_eq!(sigs.len(), 1);
        assert_eq!((sigs[0].kind.as_str(), sigs[0].severity.as_str()), ("missing_security_headers", "info"));

        // Present X-Frame-Options OR CSP -> no missing_security_headers signal
        let html_xfo =
            http_resp("200 OK", &[("Content-Type", "text/html"), ("X-Frame-Options", "DENY")], b"<html>hi</html>");
        assert!(analyze_exchange("GET", "app.test", "/", Some(200), &req, Some(&html_xfo)).is_empty());

        // Non-2xx HTML -> no missing_security_headers signal
        let html_404 = http_resp("404 Not Found", &[("Content-Type", "text/html")], b"<html>not found</html>");
        assert!(analyze_exchange("GET", "app.test", "/404", Some(404), &req, Some(&html_404)).is_empty());
    }

    #[test]
    fn binary_gzipped_oversized_and_signal_cap_are_strictly_bounded_and_panic_free() {
        let req = http_req("GET /bin HTTP/1.1", &[("Host", "app.test")]);

        // Gzipped body containing text patterns after magic must not trigger text-body detectors
        let mut gz = b"\x1f\x8b\x08\x00".to_vec();
        gz.extend_from_slice(b"You have an error in your SQL syntax");
        let gz_resp = http_resp("200 OK", &[("Content-Encoding", "gzip"), ("Content-Type", "text/html")], &gz);
        let sigs = analyze_exchange("GET", "app.test", "/bin", Some(200), &req, Some(&gz_resp));
        assert!(!sigs.iter().any(|s| s.kind == "verbose_error"), "{sigs:?}");

        // Binary PNG body with embedded NUL bytes
        let mut png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec();
        png.extend_from_slice(b"Traceback (most recent call last):");
        let png_resp = http_resp("200 OK", &[("Content-Type", "image/png")], &png);
        assert!(analyze_exchange("GET", "app.test", "/img.png", Some(200), &req, Some(&png_resp)).is_empty());

        // Oversized body: pattern strictly past 256 KiB boundary is ignored (bounded work)
        let mut big = vec![b'a'; PASSIVE_MAX_BODY_BYTES + 64];
        big.extend_from_slice(b"You have an error in your SQL syntax");
        let big_resp = http_resp("500 Internal Server Error", &[("Content-Type", "text/plain")], &big);
        assert!(analyze_exchange("GET", "app.test", "/big", Some(500), &req, Some(&big_resp)).is_empty());

        // Cap at PASSIVE_MAX_SIGNALS (16) even with 30 insecure session cookies
        let mut hdrs = Vec::new();
        let mut cookie_strings = Vec::new();
        for i in 0..30 {
            cookie_strings.push(format!("session_{i}=v{i}; Path=/"));
        }
        for c in &cookie_strings {
            hdrs.push(("Set-Cookie", c.as_str()));
        }
        let many_resp = http_resp("200 OK", &hdrs, b"ok");
        let sigs = analyze_exchange("GET", "app.test", "/many", Some(200), &req, Some(&many_resp));
        assert_eq!(sigs.len(), PASSIVE_MAX_SIGNALS);

        // Arbitrary invalid UTF-8 / truncated bytes never panic
        assert!(
            analyze_exchange("GET", "app.test", "/", None, &[0xff, 0xfe, 0x00], Some(&[0xff, 0x00, 0x80])).is_empty()
        );
        assert!(analyze_exchange("GET", "app.test", "/", None, b"", None).is_empty());
    }

    #[test]
    fn chunked_interim_100_and_inline_data_sourcemap_are_analyzed_cleanly() {
        let req = http_req("POST /search?q=ferret_canary_99 HTTP/1.1", &[("Host", "app.test")]);
        let chunked_resp = concat!(
            "HTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/html\r\n",
            "Transfer-Encoding: chunked\r\n\r\n",
            "10\r\n<html>ferret_can\r\n",
            "f\r\nary_99</html>\r\n\r\n",
            "0\r\n\r\n"
        );
        let sigs = analyze_exchange(
            "POST",
            "app.test",
            "/search?q=ferret_canary_99",
            Some(200),
            &req,
            Some(chunked_resp.as_bytes()),
        );
        assert!(sigs.iter().any(|s| s.kind == "reflected_input"), "{sigs:?}");
        assert!(sigs.iter().any(|s| s.kind == "missing_security_headers"), "{sigs:?}");

        let inline_js = http_resp(
            "200 OK",
            &[("Content-Type", "text/javascript")],
            b"void 0;\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==\n",
        );
        let sigs = analyze_exchange("GET", "app.test", "/bundle.js", Some(200), &req, Some(&inline_js));
        assert!(sigs.iter().any(|s| s.kind == "sourcemap_exposed" && s.detail.contains("inline data:")), "{sigs:?}");
    }
}
