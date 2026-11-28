//! Pure-Rust attack-surface and bug-bounty scope ingestion parsers.
//!
//! - [`parse_bounty_scope`]: HackerOne (JSON/CSV), Bugcrowd (JSON/CSV), Intigriti (JSON),
//!   Burp Suite scope JSON (regex → host/wildcard), and generic CSV.
//! - [`parse_openapi`]: OpenAPI 3.x and Swagger 2.x JSON specifications.
//! - [`parse_graphql_introspection`]: GraphQL introspection JSON (`QUERY`/`MUTATION`/`SUBSCRIPTION`).
//! - [`parse_js_sourcemap`]: JavaScript `.js.map` source maps (source file paths + embedded API routes).

use crate::target::Scope;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

/// Upper bound on surfaces emitted by any single parser call.
pub const MAX_DISCOVERED_SURFACES: usize = 2_000;

/// Parsed bug-bounty scope ready for [`crate::target::TargetStore::merge_scope`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedScope {
    pub format: String,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub notes: Vec<String>,
}

/// One discovered API or code surface extracted from OpenAPI, GraphQL introspection, or a JS sourcemap.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredSurface {
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    #[serde(default)]
    pub auth_required: bool,
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
}

// ---------------------------------------------------------------------------
// 1. Bounty scope ingestion (HackerOne / Bugcrowd / Intigriti / Burp / CSV)
// ---------------------------------------------------------------------------

/// Parse a bug-bounty scope document in HackerOne, Bugcrowd, Intigriti, Burp, generic CSV, or `"auto"` format.
pub fn parse_bounty_scope(input: &str, format: &str) -> Result<ImportedScope, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("scope input is empty".to_string());
    }
    let fmt_norm = format.trim().to_ascii_lowercase();
    let resolved = match fmt_norm.as_str() {
        "" | "auto" => detect_scope_format(trimmed)?,
        "hackerone" | "h1" => "hackerone",
        "bugcrowd" | "bc" => "bugcrowd",
        "intigriti" => "intigriti",
        "burp" | "burpsuite" => "burp",
        "csv" => "csv",
        other => {
            return Err(format!(
                "unsupported scope format `{other}` (expected one of: auto, hackerone, bugcrowd, intigriti, burp, csv)"
            ));
        }
    };

    let mut out = ImportedScope { format: resolved.to_string(), ..Default::default() };
    let mut seen_in: HashSet<String> = HashSet::new();
    let mut seen_out: HashSet<String> = HashSet::new();

    match resolved {
        "hackerone" => parse_hackerone(trimmed, &mut out, &mut seen_in, &mut seen_out)?,
        "bugcrowd" => parse_bugcrowd(trimmed, &mut out, &mut seen_in, &mut seen_out)?,
        "intigriti" => parse_intigriti(trimmed, &mut out, &mut seen_in, &mut seen_out)?,
        "burp" => parse_burp(trimmed, &mut out, &mut seen_in, &mut seen_out)?,
        "csv" => parse_generic_csv(trimmed, &mut out, &mut seen_in, &mut seen_out)?,
        _ => unreachable!(),
    }

    Ok(out)
}

fn detect_scope_format(input: &str) -> Result<&'static str, String> {
    if input.starts_with('{') || input.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<Value>(input) {
            if is_burp_json(&v) {
                return Ok("burp");
            }
            if is_hackerone_json(&v) {
                return Ok("hackerone");
            }
            if is_bugcrowd_json(&v) {
                return Ok("bugcrowd");
            }
            if is_intigriti_json(&v) {
                return Ok("intigriti");
            }
            return Err(
                "could not auto-detect JSON scope format; specify format explicitly (hackerone, bugcrowd, intigriti, burp)"
                    .to_string(),
            );
        }
    }
    let first_line = input.lines().find(|l| !l.trim().is_empty()).unwrap_or("").to_ascii_lowercase();
    if first_line.contains("eligible_for_submission")
        || (first_line.contains("asset_identifier") && first_line.contains("asset_type"))
        || (first_line.contains("identifier") && first_line.contains("asset_type"))
    {
        return Ok("hackerone");
    }
    if first_line.contains("target") && (first_line.contains("category") || first_line.contains("bugcrowd")) {
        return Ok("bugcrowd");
    }
    Ok("csv")
}

fn is_burp_json(v: &Value) -> bool {
    let scope = v.get("target").and_then(|t| t.get("scope")).or_else(|| v.get("scope")).unwrap_or(v);
    let has_inc_exc =
        scope.get("include").is_some_and(Value::is_array) || scope.get("exclude").is_some_and(Value::is_array);
    if !has_inc_exc {
        return false;
    }
    if v.get("target").and_then(|t| t.get("scope")).is_some() {
        return true;
    }
    let sample = scope
        .get("include")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .or_else(|| scope.get("exclude").and_then(Value::as_array).and_then(|a| a.first()));
    sample.is_some_and(|item| item.get("host").is_some() || item.get("enabled").is_some())
}

fn is_hackerone_json(v: &Value) -> bool {
    if v.pointer("/relationships/structured_scopes/data").is_some_and(Value::is_array)
        || v.pointer("/data/relationships/structured_scopes/data").is_some_and(Value::is_array)
        || v.get("structured_scopes").is_some_and(Value::is_array)
    {
        return true;
    }
    let arr = v.as_array().or_else(|| v.get("data").and_then(Value::as_array));
    arr.is_some_and(|items| {
        items.iter().any(|item| {
            let attrs = item.get("attributes").unwrap_or(item);
            attrs.get("asset_identifier").is_some() || attrs.get("eligible_for_submission").is_some()
        })
    })
}

fn is_bugcrowd_json(v: &Value) -> bool {
    let targets = v.get("targets").unwrap_or(v);
    targets.get("in_scope").is_some_and(Value::is_array) || targets.get("out_of_scope").is_some_and(Value::is_array)
}

fn is_intigriti_json(v: &Value) -> bool {
    let items = v
        .pointer("/domains/content")
        .and_then(Value::as_array)
        .or_else(|| v.get("domains").and_then(Value::as_array))
        .or_else(|| v.get("content").and_then(Value::as_array))
        .or_else(|| v.as_array());
    items.is_some_and(|arr| arr.iter().any(|item| item.get("endpoint").is_some()))
}

fn is_non_network_asset_type(raw_type: &str) -> bool {
    let norm = raw_type.trim().to_ascii_uppercase().replace(['-', ' '], "_");
    matches!(
        norm.as_str(),
        "SOURCE_CODE"
            | "SOURCE"
            | "REPO"
            | "REPOSITORY"
            | "GITHUB"
            | "APPLE_STORE_APP_ID"
            | "GOOGLE_PLAY_APP_ID"
            | "WINDOWS_APP_STORE_APP_ID"
            | "OTHER_APK"
            | "OTHER_IPA"
            | "APK"
            | "IPA"
            | "IOS"
            | "IOS_APP"
            | "ANDROID"
            | "ANDROID_APP"
            | "MOBILE"
            | "TESTFLIGHT"
            | "DOWNLOADABLE_EXECUTABLES"
            | "EXECUTABLE"
            | "BINARY"
            | "HARDWARE"
            | "IOT"
            | "DEVICE"
            | "SMART_CONTRACT"
            | "AI_MODEL"
            | "LLM"
    )
}

fn push_scope_entry(
    raw: &str,
    asset_type: Option<&str>,
    in_scope: bool,
    out: &mut ImportedScope,
    seen_in: &mut HashSet<String>,
    seen_out: &mut HashSet<String>,
) {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Some(ty) = asset_type.map(str::trim).filter(|s| !s.is_empty()) {
        if is_non_network_asset_type(ty) {
            out.notes.push(format!("skipped non-network asset ({ty}): {trimmed}"));
            return;
        }
    }
    match normalize_scope_identifier(trimmed) {
        Ok(entries) => {
            for entry in entries {
                let key = entry.to_ascii_lowercase();
                if in_scope {
                    if seen_in.insert(key) {
                        out.in_scope.push(entry);
                    }
                } else if seen_out.insert(key) {
                    out.out_of_scope.push(entry);
                }
            }
        }
        Err(reason) => {
            out.notes.push(format!("skipped `{trimmed}`: {reason}"));
        }
    }
}

fn normalize_scope_identifier(raw: &str) -> Result<Vec<String>, String> {
    let s = raw.trim().trim_matches('"').trim_matches('\'').trim();
    if s.is_empty() {
        return Err("empty identifier".to_string());
    }
    // Fast path: already a valid Scope entry (CIDR, IP, host, or `*.domain`).
    if Scope::parse(&[s.to_string()], &[]).is_ok() {
        return Ok(vec![canonical_scope_display(s)]);
    }

    // Strip common URL schemes (including `http(s)://`).
    let mut work = s;
    for prefix in ["http(s)://", "HTTP(S)://", "https://", "http://", "wss://", "ws://"] {
        if work.len() >= prefix.len() && work[..prefix.len()].eq_ignore_ascii_case(prefix) {
            work = &work[prefix.len()..];
            break;
        }
    }
    // Reject non-HTTP/WS schemes like `mailto:`, `ftp://`, `ssh://`, `arn:...`.
    if work.contains("://") {
        return Err("unsupported URL scheme".to_string());
    }

    // Strip path, query, and fragment (CIDRs already matched the fast path above).
    let authority = work.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split_once(']').map_or(v6, |(h, _)| h)
    } else if hostport.parse::<IpAddr>().is_ok() {
        hostport
    } else if let Some((h, port)) = hostport.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit() || b == b'*') {
            h
        } else {
            hostport
        }
    } else {
        hostport
    };

    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err("no host in identifier".to_string());
    }

    // Handle optional-wildcard shorthand like `(*.)example.com` or `(*.).example.com`.
    if let Some(rest) = host.strip_prefix("(*.)").or_else(|| host.strip_prefix("(*).")) {
        let bare = rest.trim_start_matches('.');
        let glob = format!("*.{bare}");
        if Scope::parse(&[bare.to_string(), glob.clone()], &[]).is_ok() {
            return Ok(vec![bare.to_string(), glob]);
        }
    }

    if Scope::parse(std::slice::from_ref(&host), &[]).is_ok() {
        return Ok(vec![host]);
    }
    Err("not a valid host, wildcard, IP, or CIDR".to_string())
}

fn canonical_scope_display(s: &str) -> String {
    let t = s.trim();
    if t.contains('/') {
        // CIDR: lowercase IPv6 hex while preserving prefix length.
        t.to_ascii_lowercase()
    } else {
        let lower = t.trim_end_matches('.').to_ascii_lowercase();
        lower.strip_prefix('[').and_then(|x| x.strip_suffix(']')).map(str::to_string).unwrap_or(lower)
    }
}

fn parse_hackerone(
    input: &str,
    out: &mut ImportedScope,
    seen_in: &mut HashSet<String>,
    seen_out: &mut HashSet<String>,
) -> Result<(), String> {
    if input.starts_with('{') || input.starts_with('[') {
        let v: Value = serde_json::from_str(input).map_err(|e| format!("invalid HackerOne JSON: {e}"))?;
        let items = v
            .pointer("/relationships/structured_scopes/data")
            .and_then(Value::as_array)
            .or_else(|| v.pointer("/data/relationships/structured_scopes/data").and_then(Value::as_array))
            .or_else(|| v.get("structured_scopes").and_then(Value::as_array))
            .or_else(|| v.get("data").and_then(Value::as_array))
            .or_else(|| v.as_array())
            .ok_or_else(|| {
                "HackerOne JSON must contain relationships.structured_scopes.data or an array of scope objects"
                    .to_string()
            })?;
        for item in items {
            let attrs = item.get("attributes").unwrap_or(item);
            let ident =
                attrs.get("asset_identifier").or_else(|| attrs.get("identifier")).and_then(Value::as_str).unwrap_or("");
            let asset_type = attrs.get("asset_type").and_then(Value::as_str);
            let eligible = attrs.get("eligible_for_submission").and_then(Value::as_bool).unwrap_or(true);
            push_scope_entry(ident, asset_type, eligible, out, seen_in, seen_out);
        }
        return Ok(());
    }

    // HackerOne CSV: identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission,...
    let rows = parse_csv_rows(input);
    if rows.is_empty() {
        return Err("HackerOne CSV is empty".to_string());
    }
    let header: Vec<String> = rows[0].iter().map(|c| c.trim().to_ascii_lowercase()).collect();
    let id_col =
        header.iter().position(|h| matches!(h.as_str(), "identifier" | "asset_identifier" | "asset")).unwrap_or(0);
    let type_col = header.iter().position(|h| matches!(h.as_str(), "asset_type" | "type"));
    let elig_col = header.iter().position(|h| matches!(h.as_str(), "eligible_for_submission" | "in_scope"));
    let start = if header.iter().any(|h| matches!(h.as_str(), "identifier" | "asset_identifier" | "asset_type")) {
        1
    } else {
        0
    };
    for row in rows.iter().skip(start) {
        let Some(ident) = row.get(id_col) else { continue };
        let asset_type = type_col.and_then(|i| row.get(i)).map(String::as_str);
        let eligible = elig_col.and_then(|i| row.get(i)).map(|v| parse_boolish(v, true)).unwrap_or(true);
        push_scope_entry(ident, asset_type, eligible, out, seen_in, seen_out);
    }
    Ok(())
}

fn parse_bugcrowd(
    input: &str,
    out: &mut ImportedScope,
    seen_in: &mut HashSet<String>,
    seen_out: &mut HashSet<String>,
) -> Result<(), String> {
    if input.starts_with('{') {
        let v: Value = serde_json::from_str(input).map_err(|e| format!("invalid Bugcrowd JSON: {e}"))?;
        let targets = v.get("targets").unwrap_or(&v);
        let in_arr = targets.get("in_scope").and_then(Value::as_array);
        let out_arr = targets.get("out_of_scope").and_then(Value::as_array);
        if in_arr.is_none() && out_arr.is_none() {
            return Err("Bugcrowd JSON must contain targets.in_scope or targets.out_of_scope".to_string());
        }
        for (arr_opt, is_in) in [(in_arr, true), (out_arr, false)] {
            if let Some(arr) = arr_opt {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        push_scope_entry(s, None, is_in, out, seen_in, seen_out);
                    } else if let Some(obj) = item.as_object() {
                        let ident = obj
                            .get("target")
                            .or_else(|| obj.get("uri"))
                            .or_else(|| obj.get("name"))
                            .or_else(|| obj.get("host"))
                            .or_else(|| obj.get("endpoint"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let ty = obj.get("type").or_else(|| obj.get("category")).and_then(Value::as_str);
                        push_scope_entry(ident, ty, is_in, out, seen_in, seen_out);
                    }
                }
            }
        }
        return Ok(());
    }

    parse_generic_csv(input, out, seen_in, seen_out)
}

fn parse_intigriti(
    input: &str,
    out: &mut ImportedScope,
    seen_in: &mut HashSet<String>,
    seen_out: &mut HashSet<String>,
) -> Result<(), String> {
    let v: Value = serde_json::from_str(input).map_err(|e| format!("invalid Intigriti JSON: {e}"))?;
    let items = v
        .pointer("/domains/content")
        .and_then(Value::as_array)
        .or_else(|| v.get("domains").and_then(Value::as_array))
        .or_else(|| v.get("content").and_then(Value::as_array))
        .or_else(|| v.as_array())
        .ok_or_else(|| "Intigriti JSON must contain `domains`, `content`, or an array of domain objects".to_string())?;

    for item in items {
        let ident = item.get("endpoint").or_else(|| item.get("target")).and_then(Value::as_str).unwrap_or("");
        let asset_type = match item.get("type") {
            Some(Value::String(s)) => Some(s.as_str()),
            Some(Value::Object(m)) => m.get("value").or_else(|| m.get("name")).and_then(Value::as_str),
            Some(Value::Number(n)) => match n.as_u64() {
                Some(1) => Some("URL"),
                Some(2) => Some("ANDROID"),
                Some(3) => Some("IOS"),
                Some(4) => Some("CIDR"),
                Some(5) => Some("DEVICE"),
                Some(7) => Some("WILDCARD"),
                _ => None,
            },
            _ => None,
        };
        let in_scope = if let Some(b) = item.get("in_scope").and_then(Value::as_bool) {
            b
        } else {
            match item.get("tier") {
                Some(Value::String(s)) => !is_out_of_scope_label(s),
                Some(Value::Object(m)) => {
                    let by_val = m
                        .get("value")
                        .or_else(|| m.get("name"))
                        .and_then(Value::as_str)
                        .map(|s| !is_out_of_scope_label(s));
                    let by_id = m.get("id").and_then(Value::as_u64).map(|id| id != 5);
                    by_val.or(by_id).unwrap_or(true)
                }
                Some(Value::Number(n)) => n.as_u64() != Some(5),
                _ => true,
            }
        };
        push_scope_entry(ident, asset_type, in_scope, out, seen_in, seen_out);
    }
    Ok(())
}

fn parse_burp(
    input: &str,
    out: &mut ImportedScope,
    seen_in: &mut HashSet<String>,
    seen_out: &mut HashSet<String>,
) -> Result<(), String> {
    let v: Value = serde_json::from_str(input).map_err(|e| format!("invalid Burp scope JSON: {e}"))?;
    let scope = v.get("target").and_then(|t| t.get("scope")).or_else(|| v.get("scope")).unwrap_or(&v);
    let inc = scope.get("include").and_then(Value::as_array);
    let exc = scope.get("exclude").and_then(Value::as_array);
    if inc.is_none() && exc.is_none() {
        return Err("Burp JSON must contain target.scope.include or target.scope.exclude".to_string());
    }

    for (arr_opt, is_in) in [(inc, true), (exc, false)] {
        let Some(arr) = arr_opt else { continue };
        for rule in arr {
            if rule.get("enabled").and_then(Value::as_bool) == Some(false) {
                let raw_host = rule.get("host").and_then(Value::as_str).unwrap_or("<empty>");
                out.notes.push(format!("skipped disabled Burp rule: {raw_host}"));
                continue;
            }
            let Some(host_rx) = rule.get("host").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
            else {
                continue;
            };
            match burp_regex_to_scope_entries(host_rx) {
                Ok(entries) => {
                    for entry in entries {
                        let key = entry.to_ascii_lowercase();
                        if is_in {
                            if seen_in.insert(key) {
                                out.in_scope.push(entry);
                            }
                        } else if seen_out.insert(key) {
                            out.out_of_scope.push(entry);
                        }
                    }
                    if let Some(file_rx) = rule.get("file").and_then(Value::as_str).filter(|f| !f.trim().is_empty()) {
                        out.notes.push(format!(
                            "Burp path filter `{file_rx}` on `{host_rx}` noted (target scope is host-level)"
                        ));
                    }
                }
                Err(reason) => {
                    out.notes.push(format!("skipped Burp regex `{host_rx}`: {reason}"));
                }
            }
        }
    }
    Ok(())
}

/// Convert a Burp Suite host regex (e.g. `^api\.example\.com$`, `^.*\.example\.com$`,
/// `^(?:.+\.)?example\.com$`, `^(a|b)\.example\.com$`) into one or more valid [`Scope`] entries.
fn burp_regex_to_scope_entries(raw: &str) -> Result<Vec<String>, String> {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix('^') {
        s = rest;
    }
    if let Some(rest) = s.strip_suffix('$') {
        s = rest;
    }
    let s = s.trim();
    if s.is_empty() {
        return Err("empty host regex".to_string());
    }

    // Optional subdomain prefix: `(?:.*\.)?example\.com`, `(.*\.)?example\.com`, `(.+\.)?example\.com`, `([^.]+\.)?example\.com`.
    for opt_prefix in [
        r"(?:.*\.)?",
        r"(?:.+\.)?",
        r"(?:[^.]+\.)?",
        r"(?:[\w-]+\.)?",
        r"(?:[a-z0-9-]+\.)?",
        r"(?:[a-zA-Z0-9-]+\.)?",
        r"(.*\.)?",
        r"(.+\.)?",
        r"([^.]+\.)?",
        r"([\w-]+\.)?",
    ] {
        if let Some(rest) = s.strip_prefix(opt_prefix) {
            let domain = unescape_burp_literal(rest)?;
            let glob = format!("*.{domain}");
            if Scope::parse(&[domain.clone(), glob.clone()], &[]).is_ok() {
                return Ok(vec![domain, glob]);
            }
        }
    }

    // Required wildcard subdomain prefix: `.*\.example\.com`, `.+\.example\.com`, `[^.]+\.example\.com`, etc.
    for wild_prefix in
        [r".*\.", r".+\.", r"[^.]+\.", r"[^.]*\.", r"[\w-]+\.", r"[a-z0-9-]+\.", r"[a-zA-Z0-9-]+\.", r"[a-z0-9._-]+\."]
    {
        if let Some(rest) = s.strip_prefix(wild_prefix) {
            let domain = unescape_burp_literal(rest)?;
            let glob = format!("*.{domain}");
            if Scope::parse(std::slice::from_ref(&glob), &[]).is_ok() {
                return Ok(vec![glob]);
            }
        }
    }

    // Simple leading alternation: `(a|b)\.example\.com` or `(?:a|b)\.example\.com`.
    if let Some(inner_start) = s.strip_prefix("(?:").or_else(|| s.strip_prefix('(')) {
        if let Some((alts, rest)) = inner_start.split_once(')') {
            if alts.contains('|') && !alts.contains('(') && !alts.contains(')') {
                let tail = unescape_burp_literal(rest)?;
                let mut results = Vec::new();
                for alt in alts.split('|') {
                    let piece = unescape_burp_literal(alt)?;
                    let full = format!("{piece}{tail}");
                    if Scope::parse(std::slice::from_ref(&full), &[]).is_ok() {
                        results.push(full);
                    } else {
                        return Err("alternation produced invalid host".to_string());
                    }
                }
                if !results.is_empty() {
                    return Ok(results);
                }
            }
        }
    }

    let literal = unescape_burp_literal(s)?;
    if Scope::parse(std::slice::from_ref(&literal), &[]).is_ok() {
        return Ok(vec![literal]);
    }
    Err("regex is too complex to convert safely to a host or wildcard".to_string())
}

fn unescape_burp_literal(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('.') => out.push('.'),
                Some('-') => out.push('-'),
                Some('_') => out.push('_'),
                Some(':') => out.push(':'),
                _ => return Err("unsupported regex escape".to_string()),
            }
        } else if matches!(c, '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | '$') {
            return Err("unsupported regex metacharacter".to_string());
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    let cleaned = out.trim().trim_end_matches('.').to_string();
    if cleaned.is_empty() {
        return Err("empty host after unescaping".to_string());
    }
    Ok(cleaned)
}

fn parse_generic_csv(
    input: &str,
    out: &mut ImportedScope,
    seen_in: &mut HashSet<String>,
    seen_out: &mut HashSet<String>,
) -> Result<(), String> {
    let rows = parse_csv_rows(input);
    if rows.is_empty() {
        return Err("CSV scope input is empty".to_string());
    }
    let header: Vec<String> = rows[0].iter().map(|c| c.trim().to_ascii_lowercase()).collect();
    let has_header = header.iter().any(|h| {
        matches!(
            h.as_str(),
            "identifier"
                | "asset_identifier"
                | "target"
                | "host"
                | "domain"
                | "url"
                | "endpoint"
                | "asset"
                | "scope"
                | "asset_type"
                | "category"
                | "in_scope"
                | "eligible_for_submission"
        )
    });
    let id_col = if has_header {
        header
            .iter()
            .position(|h| {
                matches!(
                    h.as_str(),
                    "identifier"
                        | "asset_identifier"
                        | "target"
                        | "host"
                        | "domain"
                        | "url"
                        | "endpoint"
                        | "asset"
                        | "scope"
                )
            })
            .unwrap_or(0)
    } else {
        0
    };
    let type_col = if has_header {
        header.iter().position(|h| matches!(h.as_str(), "asset_type" | "type" | "category"))
    } else {
        None
    };
    let scope_col = if has_header {
        header.iter().position(|h| {
            matches!(
                h.as_str(),
                "eligible_for_submission"
                    | "in_scope"
                    | "scope_status"
                    | "status"
                    | "tier"
                    | "out_of_scope"
                    | "excluded"
            )
        })
    } else {
        None
    };
    let inverted_col =
        scope_col.and_then(|i| header.get(i)).is_some_and(|h| matches!(h.as_str(), "out_of_scope" | "excluded"));

    for row in rows.iter().skip(usize::from(has_header)) {
        let Some(ident) = row.get(id_col) else { continue };
        let asset_type = type_col.and_then(|i| row.get(i)).map(String::as_str);
        let in_scope = match scope_col.and_then(|i| row.get(i)) {
            Some(val) if inverted_col => !parse_boolish(val, false),
            Some(val) => !is_out_of_scope_label(val) && parse_boolish(val, true),
            None => true,
        };
        push_scope_entry(ident, asset_type, in_scope, out, seen_in, seen_out);
    }
    Ok(())
}

fn is_out_of_scope_label(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "out of scope"
            | "out_of_scope"
            | "out-of-scope"
            | "oos"
            | "out"
            | "excluded"
            | "exclude"
            | "false"
            | "no"
            | "0"
    )
}

fn parse_boolish(raw: &str, default: bool) -> bool {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "y" | "1" | "in_scope" | "in scope" | "in" => true,
        "false" | "no" | "n" | "0" | "out_of_scope" | "out of scope" | "out" | "excluded" | "exclude" => false,
        _ => default,
    }
}

/// Minimal RFC 4180 CSV parser supporting quoted fields, escaped quotes `""`, and CRLF/LF newlines.
fn parse_csv_rows(input: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' if field.is_empty() => in_quotes = true,
                ',' => {
                    row.push(std::mem::take(&mut field));
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    row.push(std::mem::take(&mut field));
                    if row.iter().any(|cell| !cell.trim().is_empty()) {
                        rows.push(std::mem::take(&mut row));
                    } else {
                        row.clear();
                    }
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    if row.iter().any(|cell| !cell.trim().is_empty()) {
                        rows.push(std::mem::take(&mut row));
                    } else {
                        row.clear();
                    }
                }
                other => field.push(other),
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        if row.iter().any(|cell| !cell.trim().is_empty()) {
            rows.push(row);
        }
    }
    rows
}

// ---------------------------------------------------------------------------
// 2. OpenAPI 3.x & Swagger 2.x JSON parser
// ---------------------------------------------------------------------------

const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options", "trace"];

/// Parse an OpenAPI 3.x or Swagger 2.x JSON specification into bounded [`DiscoveredSurface`] entries
/// (capped at [`MAX_DISCOVERED_SURFACES`]).
pub fn parse_openapi(input: &str) -> Result<Vec<DiscoveredSurface>, String> {
    let root: Value = serde_json::from_str(input.trim()).map_err(|e| format!("invalid OpenAPI JSON: {e}"))?;
    let obj = root.as_object().ok_or_else(|| "OpenAPI spec must be a JSON object".to_string())?;

    let is_oa3 = obj.get("openapi").and_then(Value::as_str).is_some();
    let is_sw2 = obj.get("swagger").and_then(Value::as_str).is_some();
    if !is_oa3 && !is_sw2 {
        return Err("JSON is neither OpenAPI 3.x (`openapi`) nor Swagger 2.x (`swagger`)".to_string());
    }
    let paths = obj
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| "OpenAPI spec is missing a `paths` object".to_string())?;

    let (default_host, base_path) = if is_oa3 {
        extract_oa3_server(obj.get("servers"))
    } else {
        let host = obj
            .get("host")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|h| h.to_ascii_lowercase());
        let bp = obj.get("basePath").and_then(Value::as_str).unwrap_or("").trim().trim_end_matches('/').to_string();
        (host, bp)
    };

    let global_auth = security_array_requires_auth(obj.get("security"));

    let mut path_keys: Vec<&String> = paths.keys().collect();
    path_keys.sort();

    let mut out = Vec::new();
    for raw_path in path_keys {
        if out.len() >= MAX_DISCOVERED_SURFACES {
            break;
        }
        let Some(path_item_raw) = paths.get(raw_path) else { continue };
        let path_item = resolve_local_ref(&root, path_item_raw, 0);
        let Some(path_obj) = path_item.as_object() else { continue };

        let path_params = extract_openapi_param_names(&root, path_obj.get("parameters"));
        let (path_host_override, path_bp_override) = if is_oa3 && path_obj.get("servers").is_some() {
            extract_oa3_server(path_obj.get("servers"))
        } else {
            (None, String::new())
        };

        for &m in HTTP_METHODS {
            if out.len() >= MAX_DISCOVERED_SURFACES {
                break;
            }
            let Some(op_obj) = path_obj.get(m).and_then(Value::as_object) else { continue };
            let (op_host, op_bp) = if is_oa3 && op_obj.get("servers").is_some() {
                extract_oa3_server(op_obj.get("servers"))
            } else if path_host_override.is_some() || !path_bp_override.is_empty() {
                (path_host_override.clone(), path_bp_override.clone())
            } else {
                (default_host.clone(), base_path.clone())
            };

            let full_path = join_base_and_path(&op_bp, raw_path);
            let mut params = path_params.clone();
            for p in extract_openapi_param_names(&root, op_obj.get("parameters")) {
                if !params.contains(&p) {
                    params.push(p);
                }
            }
            if is_oa3 {
                for p in extract_oa3_body_params(&root, op_obj.get("requestBody")) {
                    if !params.contains(&p) {
                        params.push(p);
                    }
                }
            } else {
                for p in extract_sw2_body_params(&root, op_obj.get("parameters")) {
                    if !params.contains(&p) {
                        params.push(p);
                    }
                }
            }
            params.truncate(64);

            let auth_required = match op_obj.get("security") {
                Some(sec) => security_array_requires_auth(Some(sec)),
                None => global_auth,
            };

            let summary = op_obj
                .get("summary")
                .and_then(Value::as_str)
                .or_else(|| op_obj.get("operationId").and_then(Value::as_str))
                .or_else(|| op_obj.get("description").and_then(Value::as_str))
                .map(|s| compact_summary(s, 200))
                .unwrap_or_default();

            out.push(DiscoveredSurface {
                method: m.to_ascii_uppercase(),
                path: full_path,
                host: op_host,
                params,
                auth_required,
                source: "openapi".to_string(),
                summary,
            });
        }
    }

    Ok(out)
}

fn security_array_requires_auth(sec: Option<&Value>) -> bool {
    let Some(arr) = sec.and_then(Value::as_array) else { return false };
    if arr.is_empty() {
        return false;
    }
    // An empty object `{}` inside `security` explicitly marks anonymous access as allowed.
    !arr.iter().any(|item| item.as_object().is_some_and(|o| o.is_empty()))
}

fn extract_oa3_server(servers: Option<&Value>) -> (Option<String>, String) {
    let Some(first) = servers.and_then(Value::as_array).and_then(|a| a.first()) else {
        return (None, String::new());
    };
    let Some(raw_url) = first.get("url").and_then(Value::as_str) else {
        return (None, String::new());
    };
    let mut expanded = raw_url.trim().to_string();
    if let Some(vars) = first.get("variables").and_then(Value::as_object) {
        for (k, v) in vars {
            if let Some(def) = v.get("default").and_then(Value::as_str) {
                expanded = expanded.replace(&format!("{{{k}}}"), def);
            }
        }
    }
    if let Ok(u) = url::Url::parse(&expanded) {
        if matches!(u.scheme(), "http" | "https") {
            let host = u.host_str().map(|h| {
                let h_low = h.trim_end_matches('.').to_ascii_lowercase();
                match u.port() {
                    Some(p) if h_low.contains(':') => format!("[{h_low}]:{p}"),
                    Some(p) => format!("{h_low}:{p}"),
                    None => h_low,
                }
            });
            let bp = u.path().trim_end_matches('/').to_string();
            return (host, bp);
        }
    }
    if expanded.starts_with('/') {
        return (None, expanded.trim_end_matches('/').to_string());
    }
    (None, String::new())
}

fn join_base_and_path(base: &str, path: &str) -> String {
    let b = base.trim_end_matches('/');
    let p = path.trim();
    let combined = if b.is_empty() {
        if p.starts_with('/') {
            p.to_string()
        } else {
            format!("/{p}")
        }
    } else if p.starts_with('/') {
        format!("{b}{p}")
    } else {
        format!("{b}/{p}")
    };
    if combined.is_empty() {
        "/".to_string()
    } else {
        combined
    }
}

fn resolve_local_ref<'a>(root: &'a Value, val: &'a Value, depth: usize) -> &'a Value {
    if depth >= 4 {
        return val;
    }
    if let Some(ref_str) = val.get("$ref").and_then(Value::as_str) {
        if let Some(ptr) = ref_str.strip_prefix('#') {
            if let Some(target) = root.pointer(ptr) {
                return resolve_local_ref(root, target, depth + 1);
            }
        }
    }
    val
}

fn extract_openapi_param_names(root: &Value, params: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(arr) = params.and_then(Value::as_array) else { return out };
    for raw in arr {
        let p = resolve_local_ref(root, raw, 0);
        if p.get("in").and_then(Value::as_str) == Some("body") {
            continue;
        }
        if let Some(name) = p.get("name").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
            let s = name.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

fn extract_oa3_body_params(root: &Value, req_body: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(raw_rb) = req_body else { return out };
    let rb = resolve_local_ref(root, raw_rb, 0);
    let Some(content) = rb.get("content").and_then(Value::as_object) else { return out };
    for media in content.values() {
        if let Some(schema) = media.get("schema") {
            collect_schema_properties(root, schema, 0, &mut out);
        }
    }
    out
}

fn extract_sw2_body_params(root: &Value, params: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    let Some(arr) = params.and_then(Value::as_array) else { return out };
    for raw in arr {
        let p = resolve_local_ref(root, raw, 0);
        if p.get("in").and_then(Value::as_str) == Some("body") {
            if let Some(schema) = p.get("schema") {
                collect_schema_properties(root, schema, 0, &mut out);
            }
        }
    }
    out
}

fn collect_schema_properties(root: &Value, schema: &Value, depth: usize, out: &mut Vec<String>) {
    if depth >= 3 || out.len() >= 64 {
        return;
    }
    let resolved = resolve_local_ref(root, schema, 0);
    if let Some(props) = resolved.get("properties").and_then(Value::as_object) {
        let mut keys: Vec<&String> = props.keys().collect();
        keys.sort();
        for k in keys {
            if !out.contains(k) && out.len() < 64 {
                out.push(k.clone());
            }
        }
    }
    for combiner in ["allOf", "oneOf", "anyOf"] {
        if let Some(arr) = resolved.get(combiner).and_then(Value::as_array) {
            for sub in arr {
                collect_schema_properties(root, sub, depth + 1, out);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. GraphQL Introspection JSON parser
// ---------------------------------------------------------------------------

/// Parse a GraphQL introspection JSON response (`{ "data": { "__schema": ... } }` or `{ "__schema": ... }`)
/// into `QUERY` / `MUTATION` / `SUBSCRIPTION` [`DiscoveredSurface`] entries (skipping `__*` fields,
/// bounded at [`MAX_DISCOVERED_SURFACES`]).
pub fn parse_graphql_introspection(input: &str) -> Result<Vec<DiscoveredSurface>, String> {
    let root: Value =
        serde_json::from_str(input.trim()).map_err(|e| format!("invalid GraphQL introspection JSON: {e}"))?;
    let schema = root
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| root.get("__schema"))
        .ok_or_else(|| "GraphQL introspection JSON is missing `__schema`".to_string())?;
    let types = schema
        .get("types")
        .and_then(Value::as_array)
        .ok_or_else(|| "GraphQL `__schema` is missing `types` array".to_string())?;

    let mut by_name: BTreeMap<&str, &Value> = BTreeMap::new();
    for t in types {
        if let Some(name) = t.get("name").and_then(Value::as_str) {
            by_name.insert(name, t);
        }
    }

    let roots = [
        ("QUERY", schema.get("queryType").and_then(|t| t.get("name")).and_then(Value::as_str)),
        ("MUTATION", schema.get("mutationType").and_then(|t| t.get("name")).and_then(Value::as_str)),
        ("SUBSCRIPTION", schema.get("subscriptionType").and_then(|t| t.get("name")).and_then(Value::as_str)),
    ];

    let mut out = Vec::new();
    for (op_method, root_name_opt) in roots {
        let Some(root_name) = root_name_opt else { continue };
        let Some(type_obj) = by_name.get(root_name) else { continue };
        let Some(fields) = type_obj.get("fields").and_then(Value::as_array) else { continue };
        for field in fields {
            if out.len() >= MAX_DISCOVERED_SURFACES {
                break;
            }
            let Some(name) = field.get("name").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) else {
                continue;
            };
            if name.starts_with("__") {
                continue;
            }
            let mut params = Vec::new();
            if let Some(args) = field.get("args").and_then(Value::as_array) {
                for arg in args.iter().take(64) {
                    let Some(arg_name) = arg.get("name").and_then(Value::as_str) else { continue };
                    let arg_ty = arg.get("type").map(|t| render_gql_type(t, 0)).unwrap_or_default();
                    if arg_ty.is_empty() {
                        params.push(arg_name.to_string());
                    } else {
                        params.push(format!("{arg_name}: {arg_ty}"));
                    }
                }
            }
            let desc =
                field.get("description").and_then(Value::as_str).map(|s| compact_summary(s, 180)).unwrap_or_default();
            let ret_ty = field.get("type").map(|t| render_gql_type(t, 0)).unwrap_or_default();
            let summary = match (desc.is_empty(), ret_ty.is_empty()) {
                (false, false) => format!("{desc} -> {ret_ty}"),
                (false, true) => desc,
                (true, false) => format!("returns {ret_ty}"),
                (true, true) => String::new(),
            };
            out.push(DiscoveredSurface {
                method: op_method.to_string(),
                path: name.to_string(),
                host: None,
                params,
                auth_required: false,
                source: "graphql".to_string(),
                summary,
            });
        }
    }

    Ok(out)
}

fn render_gql_type(ty: &Value, depth: usize) -> String {
    if depth >= 8 {
        return "…".to_string();
    }
    let kind = ty.get("kind").and_then(Value::as_str).unwrap_or("");
    match kind {
        "NON_NULL" => {
            let inner = ty.get("ofType").map(|t| render_gql_type(t, depth + 1)).unwrap_or_default();
            if inner.is_empty() {
                String::new()
            } else {
                format!("{inner}!")
            }
        }
        "LIST" => {
            let inner = ty.get("ofType").map(|t| render_gql_type(t, depth + 1)).unwrap_or_default();
            if inner.is_empty() {
                String::new()
            } else {
                format!("[{inner}]")
            }
        }
        _ => ty.get("name").and_then(Value::as_str).unwrap_or("").to_string(),
    }
}

// ---------------------------------------------------------------------------
// 4. JavaScript Source Map (.js.map) parser
// ---------------------------------------------------------------------------

const MAX_SOURCEMAP_ROUTES: usize = 1_500;
const MAX_SOURCEMAP_SOURCES: usize = 500;
const MAX_SOURCE_CONTENT_SCAN_BYTES: usize = 2 * 1024 * 1024;

fn axios_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\baxios\.(get|post|put|patch|delete|head|options)\s*\(\s*["'`]([^"'`\r\n]{1,256})["'`]"#)
            .expect("valid axios regex")
    })
}

fn fetch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"\bfetch\s*\(\s*["'`]([^"'`\r\n]{1,256})["'`](?:\s*,\s*\{[^}]{0,240}?\bmethod\s*:\s*["']([A-Za-z]{3,10})["'])?"#,
        )
        .expect("valid fetch regex")
    })
}

fn route_literal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"["'`]((?:https?://[^\s"'`<>]{1,128})?/(?:api|v[0-9]+|graphql|auth|admin|oauth|internal|rest|rpc|webhooks?)(?:/[^\s"'`<>]{0,200})?)["'`]"#,
        )
        .expect("valid route literal regex")
    })
}

fn template_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$\{([A-Za-z0-9_.$-]{1,48})\}").expect("valid template var regex"))
}

/// Parse a `.js.map` JSON source map, extracting bounded embedded API routes and source file paths
/// cleanly deduplicated (capped at [`MAX_DISCOVERED_SURFACES`]).
pub fn parse_js_sourcemap(input: &str, source_url: Option<&str>) -> Result<Vec<DiscoveredSurface>, String> {
    let root: Value = serde_json::from_str(input.trim()).map_err(|e| format!("invalid JS sourcemap JSON: {e}"))?;
    let obj = root.as_object().ok_or_else(|| "JS sourcemap must be a JSON object".to_string())?;
    if !obj.contains_key("sources") && !obj.contains_key("sections") && !obj.contains_key("mappings") {
        return Err("JSON does not look like a JS sourcemap (missing `sources`, `sections`, or `mappings`)".to_string());
    }

    let default_host = source_url.and_then(|raw| {
        url::Url::parse(raw.trim()).ok().and_then(|u| {
            if !matches!(u.scheme(), "http" | "https") {
                return None;
            }
            u.host_str().map(|h| {
                let low = h.trim_end_matches('.').to_ascii_lowercase();
                match u.port() {
                    Some(p) if low.contains(':') => format!("[{low}]:{p}"),
                    Some(p) => format!("{low}:{p}"),
                    None => low,
                }
            })
        })
    });

    let mut entries: Vec<(String, Option<&str>)> = Vec::new();
    collect_sourcemap_entries(obj, &mut entries);

    // Extract routes first (highest signal), deduplicating by (method, host, path).
    let mut routes: Vec<DiscoveredSurface> = Vec::new();
    let mut route_idx: BTreeMap<(String, Option<String>, String), usize> = BTreeMap::new();
    let mut scanned_bytes = 0usize;

    for (src_path, content_opt) in &entries {
        if routes.len() >= MAX_SOURCEMAP_ROUTES || scanned_bytes >= MAX_SOURCE_CONTENT_SCAN_BYTES {
            break;
        }
        let Some(content) = content_opt else { continue };
        let remaining = MAX_SOURCE_CONTENT_SCAN_BYTES.saturating_sub(scanned_bytes);
        let slice = if content.len() > remaining {
            let mut cut = remaining;
            while !content.is_char_boundary(cut) {
                cut -= 1;
            }
            &content[..cut]
        } else {
            *content
        };
        scanned_bytes += slice.len();

        let mut push_route = |method: &str, raw_target: &str, skip_if_specific: bool| {
            if routes.len() >= MAX_SOURCEMAP_ROUTES {
                return;
            }
            let Some((host, path, params)) = normalize_js_route(raw_target, default_host.as_deref()) else {
                return;
            };
            if skip_if_specific {
                let has_specific = ["POST", "PUT", "PATCH", "DELETE"]
                    .iter()
                    .any(|m| route_idx.contains_key(&(m.to_string(), host.clone(), path.clone())));
                if has_specific {
                    return;
                }
            }
            let method_up = method.to_ascii_uppercase();
            let key = (method_up.clone(), host.clone(), path.clone());
            if let Some(&idx) = route_idx.get(&key) {
                for p in params {
                    if !routes[idx].params.contains(&p) && routes[idx].params.len() < 32 {
                        routes[idx].params.push(p);
                    }
                }
            } else {
                let idx = routes.len();
                route_idx.insert(key, idx);
                routes.push(DiscoveredSurface {
                    method: method_up,
                    path,
                    host,
                    params,
                    auth_required: false,
                    source: "js_sourcemap".to_string(),
                    summary: format!("route in {src_path}"),
                });
            }
        };

        // 1. axios.<method>("...")
        for cap in axios_re().captures_iter(slice) {
            if let (Some(m), Some(url)) = (cap.get(1), cap.get(2)) {
                push_route(m.as_str(), url.as_str(), false);
            }
        }
        // 2. fetch("...", { method: "..." })
        for cap in fetch_re().captures_iter(slice) {
            if let Some(url) = cap.get(1) {
                let m = cap.get(2).map_or("GET", |mm| mm.as_str());
                push_route(m, url.as_str(), false);
            }
        }
        // 3. Embedded route literals (/api/..., /v1/..., /graphql, /auth/..., /admin/...)
        for cap in route_literal_re().captures_iter(slice) {
            if let Some(url) = cap.get(1) {
                push_route("GET", url.as_str(), true);
            }
        }
    }

    // Collect deduplicated source file paths (preferring non-node_modules application code).
    let mut app_sources: Vec<String> = Vec::new();
    let mut vendor_sources: Vec<String> = Vec::new();
    let mut seen_src: BTreeSet<String> = BTreeSet::new();
    for (src_path, _) in &entries {
        if src_path.is_empty() || !seen_src.insert(src_path.clone()) {
            continue;
        }
        if src_path.contains("node_modules/") {
            if vendor_sources.len() < 100 {
                vendor_sources.push(src_path.clone());
            }
        } else if app_sources.len() < MAX_SOURCEMAP_SOURCES {
            app_sources.push(src_path.clone());
        }
    }

    let mut out = routes;
    let chosen_sources = if app_sources.is_empty() { vendor_sources } else { app_sources };
    for src in chosen_sources {
        if out.len() >= MAX_DISCOVERED_SURFACES {
            break;
        }
        out.push(DiscoveredSurface {
            method: "SOURCE".to_string(),
            path: src,
            host: default_host.clone(),
            params: Vec::new(),
            auth_required: false,
            source: "js_sourcemap".to_string(),
            summary: "sourcemap source file".to_string(),
        });
    }

    Ok(out)
}

fn collect_sourcemap_entries<'a>(obj: &'a serde_json::Map<String, Value>, out: &mut Vec<(String, Option<&'a str>)>) {
    if let Some(sources) = obj.get("sources").and_then(Value::as_array) {
        let contents = obj.get("sourcesContent").and_then(Value::as_array);
        for (i, s) in sources.iter().enumerate() {
            let Some(raw) = s.as_str() else { continue };
            let clean = clean_sourcemap_path(raw);
            let content = contents.and_then(|c| c.get(i)).and_then(Value::as_str);
            out.push((clean, content));
        }
    }
    if let Some(sections) = obj.get("sections").and_then(Value::as_array) {
        for sec in sections {
            if let Some(map_obj) = sec.get("map").and_then(Value::as_object) {
                collect_sourcemap_entries(map_obj, out);
            }
        }
    }
}

fn clean_sourcemap_path(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix("webpack:///") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("webpack://") {
        // Strip `webpack://<app-name>/`
        if let Some((_, after)) = rest.split_once('/') {
            s = after;
        }
    } else if let Some(rest) = s.strip_prefix("file://") {
        s = rest;
    }
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    s.trim().to_string()
}

fn normalize_js_route(raw: &str, default_host: Option<&str>) -> Option<(Option<String>, String, Vec<String>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 256 || trimmed.chars().any(char::is_whitespace) {
        return None;
    }
    if trimmed.contains('<') || trimmed.contains('>') || trimmed.contains('\\') {
        return None;
    }
    // Extract `${var}` interpolations and replace them with `{var}`.
    let mut params: Vec<String> = Vec::new();
    let replaced = template_var_re().replace_all(trimmed, |caps: &regex::Captures| {
        let var = caps.get(1).map(|m| m.as_str()).unwrap_or("id");
        let leaf = var.rsplit('.').next().unwrap_or(var);
        if !leaf.is_empty() && !params.contains(&leaf.to_string()) {
            params.push(leaf.to_string());
        }
        format!("{{{leaf}}}")
    });

    let (host, path_and_query) = if let Ok(u) = url::Url::parse(&replaced) {
        if !matches!(u.scheme(), "http" | "https") {
            return None;
        }
        let h = u.host_str().map(|host_str| {
            let low = host_str.trim_end_matches('.').to_ascii_lowercase();
            match u.port() {
                Some(p) if low.contains(':') => format!("[{low}]:{p}"),
                Some(p) => format!("{low}:{p}"),
                None => low,
            }
        });
        let pq = match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        };
        (h, pq)
    } else if replaced.starts_with('/') {
        (default_host.map(str::to_string), replaced.into_owned())
    } else {
        return None;
    };

    let (path_raw, query_raw) = path_and_query.split_once('?').unwrap_or((&path_and_query, ""));
    let path_raw = path_raw.split('#').next().unwrap_or(path_raw);
    if path_raw.is_empty() || path_raw == "/" || path_raw.starts_with("//") {
        return None;
    }
    let lower = path_raw.to_ascii_lowercase();
    for static_ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".eot"] {
        if lower.ends_with(static_ext) {
            return None;
        }
    }
    for pair in query_raw.split('&').filter(|s| !s.is_empty()) {
        let k = pair.split('=').next().unwrap_or("").trim();
        if !k.is_empty() && !k.contains('{') && !params.contains(&k.to_string()) {
            params.push(k.to_string());
        }
    }
    let path = if path_raw.len() > 1 { path_raw.trim_end_matches('/').to_string() } else { path_raw.to_string() };
    Some((host, path, params))
}

fn compact_summary(text: &str, max_chars: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max_chars {
        flat
    } else {
        let cut: String = flat.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bounty_scope_hackerone_json_and_csv() {
        let h1_json = json!({
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {
                            "attributes": {
                                "asset_identifier": "https://api.example.com/v1",
                                "asset_type": "URL",
                                "eligible_for_submission": true
                            }
                        },
                        {
                            "attributes": {
                                "asset_identifier": "*.example.com",
                                "asset_type": "WILDCARD",
                                "eligible_for_submission": true
                            }
                        },
                        {
                            "attributes": {
                                "asset_identifier": "10.20.0.0/24",
                                "asset_type": "CIDR",
                                "eligible_for_submission": true
                            }
                        },
                        {
                            "attributes": {
                                "asset_identifier": "staging.example.com",
                                "asset_type": "URL",
                                "eligible_for_submission": false
                            }
                        },
                        {
                            "attributes": {
                                "asset_identifier": "com.example.ios",
                                "asset_type": "APPLE_STORE_APP_ID",
                                "eligible_for_submission": true
                            }
                        },
                        {
                            "attributes": {
                                "asset_identifier": "https://github.com/example/app",
                                "asset_type": "SOURCE_CODE",
                                "eligible_for_submission": true
                            }
                        }
                    ]
                }
            }
        });
        let res = parse_bounty_scope(&h1_json.to_string(), "auto").unwrap();
        assert_eq!(res.format, "hackerone");
        assert_eq!(res.in_scope, vec!["api.example.com", "*.example.com", "10.20.0.0/24"]);
        assert_eq!(res.out_of_scope, vec!["staging.example.com"]);
        assert_eq!(res.notes.len(), 2, "{:?}", res.notes);
        assert!(Scope::parse(&res.in_scope, &res.out_of_scope).is_ok());

        let h1_csv = "\
identifier,asset_type,instruction,eligible_for_bounty,eligible_for_submission\n\
https://app.example.com/login,URL,\"Main app, web\",true,true\n\
*.api.example.com,WILDCARD,,true,true\n\
admin.example.com,URL,,false,false\n\
https://github.com/example/repo,SOURCE_CODE,,true,true\n";
        let csv_res = parse_bounty_scope(h1_csv, "auto").unwrap();
        assert_eq!(csv_res.format, "hackerone");
        assert_eq!(csv_res.in_scope, vec!["app.example.com", "*.api.example.com"]);
        assert_eq!(csv_res.out_of_scope, vec!["admin.example.com"]);
        assert!(csv_res.notes.iter().any(|n| n.contains("SOURCE_CODE")));
    }

    #[test]
    fn bounty_scope_bugcrowd_intigriti_burp_and_generic_csv() {
        let bc = json!({
            "targets": {
                "in_scope": [
                    {"target": "https://portal.acme.test:8443/app", "type": "website"},
                    {"target": "*.acme.test", "type": "api"},
                    {"target": "com.acme.android", "type": "android"}
                ],
                "out_of_scope": [
                    {"target": "blog.acme.test", "type": "website"}
                ]
            }
        });
        let bc_res = parse_bounty_scope(&bc.to_string(), "auto").unwrap();
        assert_eq!(bc_res.format, "bugcrowd");
        assert_eq!(bc_res.in_scope, vec!["portal.acme.test", "*.acme.test"]);
        assert_eq!(bc_res.out_of_scope, vec!["blog.acme.test"]);
        assert!(bc_res.notes.iter().any(|n| n.contains("android")));

        let intigriti = json!({
            "domains": {
                "content": [
                    {"endpoint": "https://shop.inti.test/v2", "type": {"value": "Url"}, "tier": {"value": "Tier 1", "id": 1}},
                    {"endpoint": "*.inti.test", "type": 7, "tier": {"value": "Tier 2", "id": 2}},
                    {"endpoint": "legacy.inti.test", "type": 1, "tier": {"value": "Out of Scope", "id": 5}},
                    {"endpoint": "id123456789", "type": 3, "tier": {"value": "Tier 1", "id": 1}}
                ]
            }
        });
        let inti_res = parse_bounty_scope(&intigriti.to_string(), "auto").unwrap();
        assert_eq!(inti_res.format, "intigriti");
        assert_eq!(inti_res.in_scope, vec!["shop.inti.test", "*.inti.test"]);
        assert_eq!(inti_res.out_of_scope, vec!["legacy.inti.test"]);
        assert!(inti_res.notes.iter().any(|n| n.contains("IOS")));

        let burp = json!({
            "target": {
                "scope": {
                    "include": [
                        {"enabled": true, "host": r"^api\.burp\.test$", "protocol": "https"},
                        {"enabled": true, "host": r"^.*\.sub\.burp\.test$"},
                        {"enabled": true, "host": r"^(?:.+\.)?opt\.burp\.test$"},
                        {"enabled": true, "host": r"^(a|b)\.alt\.burp\.test$"},
                        {"enabled": false, "host": r"^disabled\.burp\.test$"},
                        {"enabled": true, "host": r"^api-[0-9]+\.complex\.test$"}
                    ],
                    "exclude": [
                        {"enabled": true, "host": r"^logout\.burp\.test$", "file": r"^/logout"}
                    ]
                }
            }
        });
        let burp_res = parse_bounty_scope(&burp.to_string(), "auto").unwrap();
        assert_eq!(burp_res.format, "burp");
        assert_eq!(
            burp_res.in_scope,
            vec![
                "api.burp.test",
                "*.sub.burp.test",
                "opt.burp.test",
                "*.opt.burp.test",
                "a.alt.burp.test",
                "b.alt.burp.test"
            ]
        );
        assert_eq!(burp_res.out_of_scope, vec!["logout.burp.test"]);
        assert!(burp_res.notes.iter().any(|n| n.contains("disabled")));
        assert!(burp_res.notes.iter().any(|n| n.contains("complex")));
        assert!(Scope::parse(&burp_res.in_scope, &burp_res.out_of_scope).is_ok());

        let generic_csv = "host,in_scope\nhttps://a.csv.test/x,true\nb.csv.test,false\n";
        let g_res = parse_bounty_scope(generic_csv, "csv").unwrap();
        assert_eq!(g_res.format, "csv");
        assert_eq!(g_res.in_scope, vec!["a.csv.test"]);
        assert_eq!(g_res.out_of_scope, vec!["b.csv.test"]);
    }

    #[test]
    fn openapi3_and_swagger2_parsing() {
        let oa3 = json!({
            "openapi": "3.0.3",
            "servers": [{"url": "https://{env}.api.acme.test/v1", "variables": {"env": {"default": "prod"}}}],
            "security": [{"bearerAuth": []}],
            "components": {
                "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
                "schemas": {
                    "OrderBody": {
                        "type": "object",
                        "properties": {
                            "amount": {"type": "integer"},
                            "currency": {"type": "string"}
                        }
                    }
                }
            },
            "paths": {
                "/health": {
                    "get": {
                        "summary": "Health check",
                        "security": []
                    }
                },
                "/orders/{id}": {
                    "parameters": [{"name": "id", "in": "path"}],
                    "post": {
                        "summary": "Create or update order",
                        "parameters": [{"name": "dry_run", "in": "query"}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/OrderBody"}
                                }
                            }
                        }
                    }
                }
            }
        });
        let surfaces = parse_openapi(&oa3.to_string()).unwrap();
        assert_eq!(surfaces.len(), 2);
        let health = surfaces.iter().find(|s| s.path == "/v1/health").unwrap();
        assert_eq!(health.method, "GET");
        assert_eq!(health.host.as_deref(), Some("prod.api.acme.test"));
        assert!(!health.auth_required);
        assert_eq!(health.source, "openapi");

        let order = surfaces.iter().find(|s| s.path == "/v1/orders/{id}").unwrap();
        assert_eq!(order.method, "POST");
        assert!(order.auth_required);
        assert_eq!(order.params, vec!["id", "dry_run", "amount", "currency"]);

        let sw2 = json!({
            "swagger": "2.0",
            "host": "legacy.acme.test:8443",
            "basePath": "/api",
            "definitions": {
                "Login": {"type": "object", "properties": {"email": {"type": "string"}, "password": {"type": "string"}}}
            },
            "paths": {
                "/login": {
                    "post": {
                        "operationId": "loginUser",
                        "parameters": [
                            {"name": "body", "in": "body", "schema": {"$ref": "#/definitions/Login"}}
                        ]
                    }
                }
            }
        });
        let sw_surfaces = parse_openapi(&sw2.to_string()).unwrap();
        assert_eq!(sw_surfaces.len(), 1);
        assert_eq!(sw_surfaces[0].method, "POST");
        assert_eq!(sw_surfaces[0].path, "/api/login");
        assert_eq!(sw_surfaces[0].host.as_deref(), Some("legacy.acme.test:8443"));
        assert_eq!(sw_surfaces[0].params, vec!["email", "password"]);
        assert_eq!(sw_surfaces[0].summary, "loginUser");
    }

    #[test]
    fn graphql_introspection_parses_operations_and_skips_dunder_fields() {
        let gql = json!({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": {"name": "Subscription"},
                    "types": [
                        {
                            "name": "Query",
                            "fields": [
                                {"name": "__typename", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                                {
                                    "name": "order",
                                    "description": "Fetch order by id",
                                    "args": [
                                        {"name": "id", "type": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}}
                                    ],
                                    "type": {"kind": "OBJECT", "name": "Order"}
                                }
                            ]
                        },
                        {
                            "name": "Mutation",
                            "fields": [
                                {
                                    "name": "deleteUsers",
                                    "description": "Bulk delete users",
                                    "args": [
                                        {
                                            "name": "ids",
                                            "type": {
                                                "kind": "NON_NULL",
                                                "ofType": {
                                                    "kind": "LIST",
                                                    "ofType": {"kind": "NON_NULL", "ofType": {"kind": "SCALAR", "name": "ID"}}
                                                }
                                            }
                                        }
                                    ],
                                    "type": {"kind": "SCALAR", "name": "Boolean"}
                                }
                            ]
                        },
                        {
                            "name": "Subscription",
                            "fields": [
                                {"name": "auditEvents", "args": [], "type": {"kind": "OBJECT", "name": "AuditEvent"}}
                            ]
                        }
                    ]
                }
            }
        });
        let surfaces = parse_graphql_introspection(&gql.to_string()).unwrap();
        assert_eq!(surfaces.len(), 3);
        assert!(surfaces.iter().all(|s| !s.path.starts_with("__")));
        assert_eq!(surfaces[0].method, "QUERY");
        assert_eq!(surfaces[0].path, "order");
        assert_eq!(surfaces[0].params, vec!["id: ID!"]);
        assert!(surfaces[0].summary.contains("Fetch order by id") && surfaces[0].summary.contains("Order"));

        assert_eq!(surfaces[1].method, "MUTATION");
        assert_eq!(surfaces[1].path, "deleteUsers");
        assert_eq!(surfaces[1].params, vec!["ids: [ID!]!"]);

        assert_eq!(surfaces[2].method, "SUBSCRIPTION");
        assert_eq!(surfaces[2].path, "auditEvents");
        assert_eq!(surfaces[2].source, "graphql");
    }

    #[test]
    fn js_sourcemap_extracts_sources_and_deduped_routes() {
        let map = json!({
            "version": 3,
            "sources": [
                "webpack:///./src/api/orders.ts",
                "webpack:///./src/admin/panel.tsx",
                "webpack:///./node_modules/lodash/index.js"
            ],
            "sourcesContent": [
                r#"
                export async function getOrder(orderId) {
                    const r = await fetch(`/api/v1/orders/${orderId}?include=items`, { method: "GET" });
                    await axios.post("/api/v1/orders/refund", { id: orderId });
                    await axios.post("/api/v1/orders/refund", { id: orderId }); // duplicate
                    return fetch("/graphql", { method: "POST" });
                }
                "#,
                r#"
                const ADMIN_EP = "/admin/impersonate";
                const AUTH_EP = "https://auth.acme.test/auth/token";
                const V2_EP = "/v2/billing/export";
                const IMG = "/api/logo.png";
                "#,
                "module.exports = {};"
            ]
        });
        let surfaces = parse_js_sourcemap(&map.to_string(), Some("https://app.acme.test/static/main.js.map")).unwrap();

        let refund: Vec<&DiscoveredSurface> = surfaces.iter().filter(|s| s.path == "/api/v1/orders/refund").collect();
        assert_eq!(refund.len(), 1, "duplicate POST route should be deduplicated");
        assert_eq!(refund[0].method, "POST");
        assert_eq!(refund[0].host.as_deref(), Some("app.acme.test"));

        let order = surfaces.iter().find(|s| s.path == "/api/v1/orders/{orderId}").unwrap();
        assert_eq!(order.method, "GET");
        assert_eq!(order.params, vec!["orderId", "include"]);

        let gql = surfaces.iter().find(|s| s.path == "/graphql").unwrap();
        assert_eq!(gql.method, "POST");

        assert!(surfaces.iter().any(|s| s.path == "/admin/impersonate"));
        assert!(surfaces.iter().any(|s| s.path == "/v2/billing/export"));
        let auth = surfaces.iter().find(|s| s.path == "/auth/token").unwrap();
        assert_eq!(auth.host.as_deref(), Some("auth.acme.test"));
        assert!(!surfaces.iter().any(|s| s.path.ends_with(".png")));

        // Application source paths are emitted while node_modules bloat is skipped when app sources exist.
        assert!(surfaces.iter().any(|s| s.method == "SOURCE" && s.path == "src/api/orders.ts"));
        assert!(surfaces.iter().any(|s| s.method == "SOURCE" && s.path == "src/admin/panel.tsx"));
        assert!(!surfaces.iter().any(|s| s.path.contains("node_modules")));

        // Sources-only sourcemap (no sourcesContent) and indexed sections still parse cleanly.
        let bare_map = json!({
            "version": 3,
            "sections": [{
                "offset": {"line": 0, "column": 0},
                "map": {
                    "version": 3,
                    "sources": ["webpack://frontend/src/checkout.ts"],
                    "mappings": ""
                }
            }]
        });
        let bare = parse_js_sourcemap(&bare_map.to_string(), None).unwrap();
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].method, "SOURCE");
        assert_eq!(bare[0].path, "src/checkout.ts");
    }

    #[test]
    fn parsers_reject_malformed_inputs_and_enforce_bounds() {
        assert!(parse_bounty_scope("", "auto").is_err());
        assert!(parse_bounty_scope("a.example.com", "unknown_fmt").is_err());
        assert!(parse_openapi("{}").is_err());
        assert!(parse_graphql_introspection("{}").is_err());
        assert!(parse_js_sourcemap("{\"foo\":1}", None).is_err());

        // Direct `{ "__schema": ... }` without `data` wrapper works too.
        let direct_gql = json!({
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [{"name": "Query", "fields": [{"name": "ping", "args": [], "type": {"kind": "SCALAR", "name": "String"}}]}]
            }
        });
        let res = parse_graphql_introspection(&direct_gql.to_string()).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].path, "ping");

        // Bugcrowd CSV format with category & out_of_scope column.
        let bc_csv = "target,category,in_scope\nhttps://app.bc.test/home,website,true\ncom.bc.app,android,true\nold.bc.test,website,false\n";
        let bc = parse_bounty_scope(bc_csv, "bugcrowd").unwrap();
        assert_eq!(bc.in_scope, vec!["app.bc.test"]);
        assert_eq!(bc.out_of_scope, vec!["old.bc.test"]);
        assert!(bc.notes.iter().any(|n| n.contains("android")));
    }
}
