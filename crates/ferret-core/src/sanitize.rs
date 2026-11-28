//! Default-on secret sanitization for exported artifacts (HAR 1.2, SARIF 2.1.0).
//!
//! CONTRACT.
//!
//! Pure, deterministic scrubbing of HTTP headers, cookies, URL query/fragment parameters,
//! form-urlencoded payloads, free-text prose/PoCs/snippets, and binary byte slices.
//!
//! - Sensitive HTTP headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
//!   `X-Api-Key`, `X-Auth-Token`, `X-CSRF-Token`, `X-XSRF-Token`, etc.) are always redacted while
//!   preserving structural metadata (auth scheme prefix, cookie names, and `Set-Cookie` attributes
//!   such as `HttpOnly`/`Secure`/`SameSite`).
//! - High-confidence token patterns (PEM private keys, JWTs `eyJ...`, `sk-...`/`sk_live_...`,
//!   GitHub `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`github_pat_`, AWS `AKIA`/`ASIA`/`AIDA`/`AROA`,
//!   Slack `xox*`, Google `AIza`, GitLab `glpat-`, PyPI/npm/HF tokens, inline auth/cookie headers,
//!   URL userinfo, and sensitive JSON fields) plus caller-supplied `extra_secrets` are replaced
//!   with `[redacted]` (`crate::creds::REDACTED`).
//! - Scrubbing is idempotent (`sanitize_text(&sanitize_text(s, e), e) == sanitize_text(s, e)`) and
//!   returns `Cow::Borrowed` when no secret matched.

use crate::creds::REDACTED;
use regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

/// Case-insensitive HTTP header names whose values hold credentials, session tokens, or CSRF tokens.
pub const SENSITIVE_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-session-token",
    "x-secret-key",
    "x-amz-security-token",
    "private-token",
    "x-gitlab-token",
];

/// Case-insensitive URL query / fragment / form parameter names treated as secret-bearing.
pub const SENSITIVE_PARAM_NAMES: &[&str] = &[
    "access_token",
    "refresh_token",
    "id_token",
    "auth_token",
    "api_key",
    "apikey",
    "client_secret",
    "secret",
    "secret_key",
    "private_key",
    "password",
    "passwd",
    "pwd",
    "token",
    "jwt",
    "session_token",
    "csrf_token",
    "xsrf_token",
    "authenticity_token",
    "x-amz-signature",
    "x-amz-security-token",
    "x-amz-credential",
    "sig",
    "signature",
];

/// Whether `name` (ASCII case-insensitive) is a sensitive HTTP header.
pub fn is_sensitive_header(name: &str) -> bool {
    let trimmed = name.trim();
    SENSITIVE_HEADER_NAMES.iter().any(|h| trimmed.eq_ignore_ascii_case(h))
}

/// Whether `name` (ASCII case-insensitive) is a sensitive query/fragment/form parameter.
pub fn is_sensitive_param(name: &str) -> bool {
    let trimmed = name.trim();
    SENSITIVE_PARAM_NAMES.iter().any(|p| trimmed.eq_ignore_ascii_case(p))
}

/// Strip `username:password@` userinfo from an HTTP(S) URL.
pub fn strip_url_userinfo(raw: &str) -> String {
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

/// Sanitize a `Cookie` header value, preserving cookie names and replacing every value with `[redacted]`.
pub fn redact_cookie_header(value: &str) -> String {
    value
        .split(';')
        .map(|part| {
            let trimmed = part.trim();
            if let Some((k, v)) = trimmed.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if k.is_empty() {
                    trimmed.to_string()
                } else if v.is_empty() {
                    format!("{k}=")
                } else {
                    format!("{k}={REDACTED}")
                }
            } else {
                trimmed.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Sanitize a `Set-Cookie` header value, preserving the cookie name and attributes
/// (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`, etc.) while replacing the cookie value.
pub fn redact_set_cookie_header(value: &str) -> String {
    let mut parts = value.split(';');
    let Some(first) = parts.next() else {
        return String::new();
    };
    let redacted_first = if let Some((k, v)) = first.trim().split_once('=') {
        let k = k.trim();
        let v = v.trim();
        if k.is_empty() {
            first.trim().to_string()
        } else if v.is_empty() {
            format!("{k}=")
        } else {
            format!("{k}={REDACTED}")
        }
    } else {
        REDACTED.to_string()
    };
    let rest: Vec<&str> = parts.map(str::trim).filter(|p| !p.is_empty()).collect();
    if rest.is_empty() {
        redacted_first
    } else {
        format!("{redacted_first}; {}", rest.join("; "))
    }
}

/// Sanitize an `Authorization` or `Proxy-Authorization` value, preserving a standard auth scheme
/// prefix (such as `Bearer` or `Basic`) when present.
pub fn redact_authorization_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == REDACTED {
        return trimmed.to_string();
    }
    if let Some((scheme, rest)) = trimmed.split_once(|c: char| c.is_ascii_whitespace()) {
        let scheme_ok = !scheme.is_empty()
            && scheme.len() <= 32
            && scheme.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if scheme_ok && !rest.trim().is_empty() {
            return format!("{scheme} {REDACTED}");
        }
    }
    REDACTED.to_string()
}

/// Sanitize a single HTTP header value based on its header name, high-confidence token patterns,
/// and caller-supplied `extra_secrets`.
pub fn sanitize_header_value(name: &str, value: &str, extra_secrets: &[String]) -> String {
    let n = name.trim();
    if n.eq_ignore_ascii_case("authorization") || n.eq_ignore_ascii_case("proxy-authorization") {
        return redact_authorization_value(value);
    }
    if n.eq_ignore_ascii_case("cookie") {
        return redact_cookie_header(value);
    }
    if n.eq_ignore_ascii_case("set-cookie") {
        return redact_set_cookie_header(value);
    }
    if is_sensitive_header(n) {
        return if value.trim().is_empty() { String::new() } else { REDACTED.to_string() };
    }
    if n.eq_ignore_ascii_case("location") || n.eq_ignore_ascii_case("referer") {
        return sanitize_url(value, extra_secrets);
    }
    sanitize_text(value, extra_secrets).into_owned()
}

/// Sanitize an HTTP(S) URL (or relative `/path?query` endpoint): strips userinfo, redacts
/// sensitive query/fragment parameters, and scrubs high-confidence tokens and `extra_secrets`
/// from path/query/fragment.
pub fn sanitize_url(raw: &str, extra_secrets: &[String]) -> String {
    let stripped = strip_url_userinfo(raw);
    let Ok(mut u) = url::Url::parse(&stripped) else {
        if stripped.starts_with('/') && stripped.contains('?') {
            let (before_frag, frag_opt) = match stripped.split_once('#') {
                Some((b, f)) => (b, Some(f)),
                None => (stripped.as_str(), None),
            };
            let (path, query) = before_frag.split_once('?').unwrap_or((before_frag, ""));
            let clean_path = sanitize_text(path, extra_secrets);
            let (clean_q, _) = sanitize_kv_pairs(query, extra_secrets);
            return match frag_opt {
                Some(f) => {
                    let clean_f = if f.contains('=') {
                        sanitize_kv_pairs(f, extra_secrets).0
                    } else {
                        sanitize_text(f, extra_secrets).into_owned()
                    };
                    format!("{clean_path}?{clean_q}#{clean_f}")
                }
                None => format!("{clean_path}?{clean_q}"),
            };
        }
        return sanitize_text(&stripped, extra_secrets).into_owned();
    };
    let mut changed = false;

    let orig_path = u.path().to_string();
    let clean_path = sanitize_text(&orig_path, extra_secrets);
    if clean_path != orig_path {
        u.set_path(&clean_path);
        changed = true;
    }

    if let Some(raw_q) = u.query().map(str::to_string) {
        let (rebuilt, q_changed) = sanitize_kv_pairs(&raw_q, extra_secrets);
        if q_changed {
            u.set_query(Some(&rebuilt));
            changed = true;
        }
    }

    if let Some(raw_frag) = u.fragment().map(str::to_string) {
        let (rebuilt, f_changed) = if raw_frag.contains('=') {
            sanitize_kv_pairs(&raw_frag, extra_secrets)
        } else {
            let c = sanitize_text(&raw_frag, extra_secrets);
            let ch = c != raw_frag;
            (c.into_owned(), ch)
        };
        if f_changed {
            u.set_fragment(Some(&rebuilt));
            changed = true;
        }
    }

    if changed { u.to_string() } else { stripped }
}

/// Sanitize an `application/x-www-form-urlencoded` body: redacts sensitive parameter values and
/// scrubs tokens/`extra_secrets` from other values.
pub fn sanitize_form_urlencoded(body: &str, extra_secrets: &[String]) -> String {
    let (out, _) = sanitize_kv_pairs(body, extra_secrets);
    out
}

fn sanitize_kv_pairs(raw: &str, extra_secrets: &[String]) -> (String, bool) {
    let mut changed = false;
    let mut parts = Vec::new();
    for part in raw.split('&') {
        if let Some((k_raw, v_raw)) = part.split_once('=') {
            let k_dec = percent_decode_key(k_raw);
            if is_sensitive_param(&k_dec) && !v_raw.is_empty() && v_raw != REDACTED {
                parts.push(format!("{k_raw}={REDACTED}"));
                changed = true;
            } else {
                let v_clean = sanitize_text(v_raw, extra_secrets);
                if v_clean != v_raw {
                    parts.push(format!("{k_raw}={v_clean}"));
                    changed = true;
                } else {
                    parts.push(part.to_string());
                }
            }
        } else {
            let p_clean = sanitize_text(part, extra_secrets);
            if p_clean != part {
                changed = true;
            }
            parts.push(p_clean.into_owned());
        }
    }
    (parts.join("&"), changed)
}

fn percent_decode_key(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
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

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

struct Patterns {
    pem_private_key: Regex,
    jwt: Regex,
    vendor_key: Regex,
    url_userinfo: Regex,
    inline_auth_header: Regex,
    inline_secret_header: Regex,
    inline_cookie_header: Regex,
    inline_set_cookie_header: Regex,
    standalone_bearer: Regex,
    json_secret_field: Regex,
}

fn patterns() -> &'static Patterns {
    static PATS: OnceLock<Patterns> = OnceLock::new();
    PATS.get_or_init(|| Patterns {
        pem_private_key: Regex::new(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .expect("valid pem regex"),
        // Standard 3-segment JWT (JSON header starting with `eyJ`, JSON payload starting with `eyJ`, signature).
        jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")
            .expect("valid jwt regex"),
        // High-confidence provider API keys / PATs.
        vendor_key: Regex::new(
            r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{16,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|pypi-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,})\b",
        )
        .expect("valid vendor key regex"),
        // Inline `http(s)://user:pass@host` credentials in prose/PoCs.
        url_userinfo: Regex::new(r#"(https?://)([^/\s:@'"`]+):([^/\s@'"`]+)@"#)
            .expect("valid url userinfo regex"),
        // Inline `Authorization: Bearer <tok>` / `Proxy-Authorization: Basic <tok>` anywhere in text.
        inline_auth_header: Regex::new(
            r#"(?i)(\b(?:proxy-)?authorization\s*:\s*(?:bearer|basic|digest|token|apikey|aws4-hmac-sha256)\s+)(\[redacted\]|[^\s'"`,;}\]\r\n]+)"#,
        )
        .expect("valid inline auth header regex"),
        // Inline sensitive token headers anywhere in text (curl -H, HTTP wire excerpts, PoCs).
        inline_secret_header: Regex::new(
            r#"(?i)(\b(?:x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token|x-session-token|x-secret-key|x-amz-security-token|private-token|x-gitlab-token)\s*:\s*)(\[redacted\]|[^\s'"`,;}\]\r\n]+)"#,
        )
        .expect("valid inline secret header regex"),
        // Inline `Cookie: a=1; b=2` (line or quoted curl header).
        inline_cookie_header: Regex::new(r#"(?im)(^|\s|['"`])(cookie\s*:\s*)([^\r\n'"`]+)"#)
            .expect("valid inline cookie header regex"),
        // Inline `Set-Cookie: sid=abc; HttpOnly`.
        inline_set_cookie_header: Regex::new(r#"(?im)(^|\s|['"`])(set-cookie\s*:\s*)([^\r\n'"`]+)"#)
            .expect("valid inline set-cookie header regex"),
        // Standalone `Bearer <token>` (filtered in callback to avoid English words like "Bearer authentication").
        standalone_bearer: Regex::new(r#"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{10,})"#)
            .expect("valid standalone bearer regex"),
        // Sensitive JSON string fields (`"access_token": "..."`, `"api_key": "..."`, `"password": "..."`).
        json_secret_field: Regex::new(
            r#"(?i)("(?:[A-Za-z0-9_-]*(?:access_token|refresh_token|id_token|client_secret|api_key|apikey|auth_token|session_token|csrf_token|xsrf_token|private_key|secret_key|password|passwd))"\s*:\s*")([^"\\]+)(")"#,
        )
        .expect("valid json secret field regex"),
    })
}

fn looks_like_bearer_secret(tok: &str) -> bool {
    if tok == REDACTED || tok.starts_with('[') {
        return false;
    }
    let has_digit_or_sym =
        tok.bytes().any(|b| b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.' | b'/' | b'+' | b'='));
    if has_digit_or_sym {
        return true;
    }
    // Pure ASCII letters: require mixed case and substantial length so English words never match.
    tok.len() >= 24 && tok.bytes().any(|b| b.is_ascii_uppercase()) && tok.bytes().any(|b| b.is_ascii_lowercase())
}

fn replace_extra_secrets<'a>(text: &'a str, extra_secrets: &[String]) -> Cow<'a, str> {
    if extra_secrets.is_empty() || text.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut vals: Vec<&str> = extra_secrets.iter().map(String::as_str).filter(|s| !s.is_empty()).collect();
    if vals.is_empty() {
        return Cow::Borrowed(text);
    }
    vals.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    vals.dedup();
    match replace_bytes_literals(text.as_bytes(), &vals) {
        Some(out) => match String::from_utf8(out) {
            Ok(s) => Cow::Owned(s),
            Err(_) => Cow::Borrowed(text),
        },
        None => Cow::Borrowed(text),
    }
}

fn replace_bytes_literals(bytes: &[u8], vals: &[&str]) -> Option<Vec<u8>> {
    if vals.is_empty() || bytes.is_empty() {
        return None;
    }
    let mut out: Option<Vec<u8>> = None;
    let mut copied = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let rest = &bytes[i..];
        if let Some(v) = vals.iter().find(|v| rest.starts_with(v.as_bytes())) {
            let o = out.get_or_insert_with(|| Vec::with_capacity(bytes.len()));
            o.extend_from_slice(&bytes[copied..i]);
            o.extend_from_slice(REDACTED.as_bytes());
            i += v.len();
            copied = i;
        } else {
            i += 1;
        }
    }
    out.map(|mut o| {
        o.extend_from_slice(&bytes[copied..]);
        o
    })
}

/// Scrub `extra_secrets` from raw bytes (used for non-UTF-8 binary bodies in HAR export).
pub fn sanitize_bytes<'a>(bytes: &'a [u8], extra_secrets: &[String]) -> Cow<'a, [u8]> {
    if extra_secrets.is_empty() || bytes.is_empty() {
        return Cow::Borrowed(bytes);
    }
    let mut vals: Vec<&str> = extra_secrets.iter().map(String::as_str).filter(|s| !s.is_empty()).collect();
    if vals.is_empty() {
        return Cow::Borrowed(bytes);
    }
    vals.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    vals.dedup();
    match replace_bytes_literals(bytes, &vals) {
        Some(out) => Cow::Owned(out),
        None => Cow::Borrowed(bytes),
    }
}

/// Scrub secrets from free text (HTTP bodies, header values, SARIF descriptions, PoCs, snippets).
///
/// Applies `extra_secrets` first (longest-first), then high-confidence secret/token/header patterns.
/// Returns `Cow::Borrowed` when nothing matched; applying twice yields identical output.
pub fn sanitize_text<'a>(text: &'a str, extra_secrets: &[String]) -> Cow<'a, str> {
    if text.is_empty() {
        return Cow::Borrowed(text);
    }
    let mut cur: Cow<'a, str> = replace_extra_secrets(text, extra_secrets);
    let p = patterns();

    macro_rules! apply_re {
        ($re:expr, $rep:expr) => {
            if $re.is_match(cur.as_ref()) {
                let next = $re.replace_all(cur.as_ref(), $rep).into_owned();
                if next != cur.as_ref() {
                    cur = Cow::Owned(next);
                }
            }
        };
    }

    apply_re!(&p.pem_private_key, REDACTED);
    apply_re!(&p.jwt, REDACTED);
    apply_re!(&p.vendor_key, REDACTED);

    // URL userinfo: skip already-redacted passwords.
    if p.url_userinfo.is_match(cur.as_ref()) {
        let next = p
            .url_userinfo
            .replace_all(cur.as_ref(), |caps: &regex::Captures<'_>| {
                if &caps[3] == REDACTED {
                    caps[0].to_string()
                } else {
                    format!("{}{}:{REDACTED}@", &caps[1], &caps[2])
                }
            })
            .into_owned();
        if next != cur.as_ref() {
            cur = Cow::Owned(next);
        }
    }

    // Inline Authorization / Proxy-Authorization headers.
    if p.inline_auth_header.is_match(cur.as_ref()) {
        let next = p
            .inline_auth_header
            .replace_all(cur.as_ref(), |caps: &regex::Captures<'_>| {
                if &caps[2] == REDACTED {
                    caps[0].to_string()
                } else {
                    format!("{}{REDACTED}", &caps[1])
                }
            })
            .into_owned();
        if next != cur.as_ref() {
            cur = Cow::Owned(next);
        }
    }

    // Inline sensitive token headers (X-Api-Key, X-CSRF-Token, X-Auth-Token, ...).
    if p.inline_secret_header.is_match(cur.as_ref()) {
        let next = p
            .inline_secret_header
            .replace_all(cur.as_ref(), |caps: &regex::Captures<'_>| {
                if &caps[2] == REDACTED {
                    caps[0].to_string()
                } else {
                    format!("{}{REDACTED}", &caps[1])
                }
            })
            .into_owned();
        if next != cur.as_ref() {
            cur = Cow::Owned(next);
        }
    }

    // Inline Cookie / Set-Cookie headers.
    if p.inline_cookie_header.is_match(cur.as_ref()) {
        let next = p
            .inline_cookie_header
            .replace_all(cur.as_ref(), |caps: &regex::Captures<'_>| {
                // Only redact when it actually looks like a `name=value` cookie pair.
                if caps[3].contains('=') {
                    format!("{}{}{}", &caps[1], &caps[2], redact_cookie_header(&caps[3]))
                } else {
                    caps[0].to_string()
                }
            })
            .into_owned();
        if next != cur.as_ref() {
            cur = Cow::Owned(next);
        }
    }
    if p.inline_set_cookie_header.is_match(cur.as_ref()) {
        let next = p
            .inline_set_cookie_header
            .replace_all(cur.as_ref(), |caps: &regex::Captures<'_>| {
                if caps[3].contains('=') {
                    format!("{}{}{}", &caps[1], &caps[2], redact_set_cookie_header(&caps[3]))
                } else {
                    caps[0].to_string()
                }
            })
            .into_owned();
        if next != cur.as_ref() {
            cur = Cow::Owned(next);
        }
    }

    // Standalone `Bearer <token>` outside an explicit Authorization header.
    if p.standalone_bearer.is_match(cur.as_ref()) {
        let next = p
            .standalone_bearer
            .replace_all(cur.as_ref(), |caps: &regex::Captures<'_>| {
                if looks_like_bearer_secret(&caps[2]) {
                    format!("{}{REDACTED}", &caps[1])
                } else {
                    caps[0].to_string()
                }
            })
            .into_owned();
        if next != cur.as_ref() {
            cur = Cow::Owned(next);
        }
    }

    // JSON secret fields (`"access_token": "..."`, `"api_key": "..."`, `"password": "..."`).
    if p.json_secret_field.is_match(cur.as_ref()) {
        let next = p
            .json_secret_field
            .replace_all(cur.as_ref(), |caps: &regex::Captures<'_>| {
                if &caps[2] == REDACTED {
                    caps[0].to_string()
                } else {
                    format!("{}{REDACTED}{}", &caps[1], &caps[3])
                }
            })
            .into_owned();
        if next != cur.as_ref() {
            cur = Cow::Owned(next);
        }
    }

    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_prose_and_code_remain_borrowed_unchanged() {
        for clean in [
            "The `q` parameter is interpolated directly into a SQL query.",
            "cur.execute(f\"SELECT * FROM users WHERE name = '{q}'\")",
            "Bearer authentication is required for admin routes.",
            "{\"u\":\"alice\",\"ok\":true}",
            "Tested with standard member token; no role check enforced.",
        ] {
            let out = sanitize_text(clean, &[]);
            assert!(matches!(out, Cow::Borrowed(_)), "unexpectedly modified: {clean} -> {out}");
            assert_eq!(out.as_ref(), clean);
        }
    }

    #[test]
    fn high_confidence_tokens_headers_and_extra_secrets_are_redacted_idempotently() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let ghp = "ghp_1234567890abcdefghij1234567890abcd";
        let sk = "sk-proj-abc123def456ghi789jkl012";
        let aws = "AKIAIOSFODNN7EXAMPLE";
        let custom = "my-custom-tenant-secret-42";
        let sample = format!(
            "curl -H 'Authorization: Bearer {jwt}' -H 'X-Api-Key: secret-key-val' -H 'X-CSRF-Token: csrf123' \
             -H 'Cookie: sid=sess999; prefs=dark' https://alice:hunter2@api.example.test/v1 \
             body: {{\"access_token\":\"tok_live_987654321\",\"user\":\"alice\"}} \
             keys: {ghp} {sk} {aws} {custom} Bearer tok_standalone_999"
        );
        let once = sanitize_text(&sample, &[custom.to_string()]).into_owned();
        for leaked in [jwt, ghp, sk, aws, custom, "secret-key-val", "csrf123", "sess999", "hunter2", "tok_live_987654321", "tok_standalone_999"] {
            assert!(!once.contains(leaked), "leaked `{leaked}` in: {once}");
        }
        assert!(once.contains("Authorization: Bearer [redacted]'"), "{once}");
        assert!(once.contains("X-Api-Key: [redacted]'"), "{once}");
        assert!(once.contains("X-CSRF-Token: [redacted]'"), "{once}");
        assert!(!once.contains("[redacted]]"), "{once}");
        assert!(once.contains("Cookie: sid=[redacted]; prefs=[redacted]"), "{once}");
        assert!(once.contains("\"user\":\"alice\""), "{once}");
        assert!(once.contains("\"access_token\":\"[redacted]\""), "{once}");
        assert_eq!(sanitize_text(&once, &[custom.to_string()]).as_ref(), once);
    }

    #[test]
    fn header_and_url_helpers_preserve_structure_while_scrubbing_values() {
        assert_eq!(sanitize_header_value("Authorization", "Bearer topsecret", &[]), "Bearer [redacted]");
        assert_eq!(sanitize_header_value("Proxy-Authorization", "Basic dXNlcjpwYXNz", &[]), "Basic [redacted]");
        assert_eq!(sanitize_header_value("X-Api-Key", "k-12345", &[]), "[redacted]");
        assert_eq!(sanitize_header_value("X-Auth-Token", "t-12345", &[]), "[redacted]");
        assert_eq!(sanitize_header_value("X-CSRF-Token", "c-12345", &[]), "[redacted]");
        assert_eq!(sanitize_header_value("X-XSRF-Token", "x-12345", &[]), "[redacted]");
        assert_eq!(sanitize_header_value("Cookie", "sid=abc; theme=dark", &[]), "sid=[redacted]; theme=[redacted]");
        assert_eq!(
            sanitize_header_value("Set-Cookie", "session=xyz; HttpOnly; Secure; Path=/", &[]),
            "session=[redacted]; HttpOnly; Secure; Path=/"
        );

        let clean_url = sanitize_url("https://shop.example.test/api/login?next=%2Fadmin", &[]);
        assert_eq!(clean_url, "https://shop.example.test/api/login?next=%2Fadmin");

        let dirty_url = sanitize_url(
            "https://u:p@shop.example.test/cb?next=%2Fadmin&access_token=tok999&api_key=k123#id_token=idt555",
            &[],
        );
        assert!(!dirty_url.contains("u:p") && !dirty_url.contains("tok999") && !dirty_url.contains("k123") && !dirty_url.contains("idt555"), "{dirty_url}");
        assert!(dirty_url.contains("next=%2Fadmin"), "{dirty_url}");
        assert!(dirty_url.contains("access_token=[redacted]"), "{dirty_url}");
    }
}
