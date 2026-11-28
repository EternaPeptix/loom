//! Read-only HTTP traffic inspection tools: `traffic_query` and `traffic_diff`.
//!
//! CONTRACT:
//! - Strictly read-only (`ToolClass::Read`): safe for verifiers / triage judges (`read_only = true`).
//! - Reads captured `Event::Exchange` entries from this mission (`Shared::traffic.mission`, with
//!   session log fallback) and blobs from `ToolCtx::blobs`.
//! - Secret redaction invariant: every request/response blob is redacted through the session's
//!   union `Secrets` (`ctx.capabilities.secrets` / `shared.traffic.secrets`) BEFORE substring
//!   searching (`traffic_query.search`), header/body diffing (`traffic_diff`), and output
//!   rendering, so mounted credential secrets can neither leak nor be probed as a blind oracle.

use super::Shared;
use async_trait::async_trait;
use ferret_core::creds::Secrets;
use ferret_core::event::{Event, Exchange, PassiveSignal, ToolClass, ToolSpec};
use ferret_tools::params::{opt, req, spec};
use ferret_tools::{Body, Tool, ToolCtx, ToolOutput};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

pub struct TrafficQuery(pub Arc<Shared>);
pub struct TrafficDiff(pub Arc<Shared>);

const DEFAULT_QUERY_LIMIT: usize = 30;
const MAX_QUERY_LIMIT: usize = 100;
const SEARCH_SNIPPET_BYTES: usize = 16 * 1024;
const DIFF_MAX_BODY_BYTES: usize = 256 * 1024;
const DIFF_MAX_TEXT_LINES: usize = 400;
const DIFF_MAX_SNIPPET_LINES: usize = 80;
const DIFF_MAX_SNIPPET_BYTES: usize = 8 * 1024;
const DIFF_MAX_JSON_ITEMS: usize = 30;
const DIFF_MAX_PREVIEW_CHARS: usize = 180;

/// Volatile HTTP response headers ignored when computing header diffs.
const VOLATILE_HEADERS: &[&str] = &[
    "date",
    "etag",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "x-amzn-requestid",
    "x-amzn-trace-id",
    "cf-ray",
    "age",
    "x-runtime",
    "x-response-time",
    "server-timing",
    "via",
    "x-served-by",
    "x-cache",
    "x-cache-hits",
    "x-timer",
    "report-to",
    "nel",
];

/// Volatile JSON keys stripped recursively before structural JSON diffing (matches `http_authz_matrix`).
const VOLATILE_JSON_KEYS: &[&str] = &[
    "timestamp",
    "timestamps",
    "ts",
    "time",
    "request_id",
    "requestid",
    "req_id",
    "trace_id",
    "traceid",
    "correlation_id",
    "correlationid",
    "span_id",
    "nonce",
    "date",
    "expires_at",
    "expiresat",
    "created_at",
    "updated_at",
    "server_time",
    "etag",
    "csrf_token",
    "csrf",
    "x_request_id",
    "duration_ms",
    "latency_ms",
];

fn active_secrets(shared: &Shared, ctx: &ToolCtx) -> Option<Arc<Secrets>> {
    ctx.capabilities
        .secrets
        .get()
        .or_else(|| shared.traffic.secrets.get())
        .filter(|s| !s.is_empty())
        .cloned()
}

fn redact_bytes(secrets: Option<&Secrets>, bytes: &[u8]) -> Vec<u8> {
    match secrets {
        Some(s) => s.redact_bytes(bytes).into_owned(),
        None => bytes.to_vec(),
    }
}

fn redact_str(secrets: Option<&Secrets>, text: &str) -> String {
    match secrets {
        Some(s) => s.redact(text).into_owned(),
        None => text.to_string(),
    }
}

fn cut_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Collect all exchanges recorded in this mission, oldest first, deduplicated by `id`.
fn mission_exchanges(shared: &Shared) -> Vec<Exchange> {
    let mut out = shared.traffic.mission.all();
    let mut seen: HashSet<String> = out.iter().map(|x| x.id.clone()).collect();
    if shared.log_path.is_file() {
        if let Ok(report) = ferret_core::log::read_records(&shared.log_path) {
            for r in report.records {
                if let Event::Exchange(x) = r.event {
                    if seen.insert(x.id.clone()) {
                        out.push(x);
                    }
                }
            }
        }
    }
    out
}

fn find_mission_exchange(shared: &Shared, id: &str) -> Option<Exchange> {
    let id = id.trim();
    if let Some(x) = shared.traffic.mission.find(id) {
        return Some(x);
    }
    mission_exchanges(shared).into_iter().find(|x| x.id == id)
}

fn matches_principal(actual: Option<&str>, want: &str) -> bool {
    let want = want.trim().to_ascii_lowercase();
    if want.is_empty() {
        return true;
    }
    let Some(raw) = actual.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let low = raw.to_ascii_lowercase();
    if low == want {
        return true;
    }
    if let Some(stripped) = low.strip_prefix("profile:") {
        if stripped == want {
            return true;
        }
    }
    if let Some(want_stripped) = want.strip_prefix("profile:") {
        if low == want_stripped {
            return true;
        }
    }
    false
}

fn exchange_matches_search(
    x: &Exchange,
    needle_low: &str,
    ctx: &ToolCtx,
    secrets: Option<&Secrets>,
) -> bool {
    let target_clean = redact_str(secrets, &x.target);
    let in_meta = x.id.to_ascii_lowercase().contains(needle_low)
        || x.host.to_ascii_lowercase().contains(needle_low)
        || target_clean.to_ascii_lowercase().contains(needle_low)
        || x.method.to_ascii_lowercase().contains(needle_low)
        || x.principal.as_deref().is_some_and(|p| p.to_ascii_lowercase().contains(needle_low))
        || x.passive_signals.iter().any(|s| {
            let sum = redact_str(secrets, &s.summary).to_ascii_lowercase();
            let det = redact_str(secrets, &s.detail).to_ascii_lowercase();
            s.kind.to_ascii_lowercase().contains(needle_low) || sum.contains(needle_low) || det.contains(needle_low)
        });
    if in_meta {
        return true;
    }
    let check_blob = |blob_id: &ferret_core::BlobId| -> bool {
        let Ok(raw) = ctx.blobs.read_all(blob_id) else { return false };
        let capped = &raw[..raw.len().min(SEARCH_SNIPPET_BYTES)];
        // Redact BEFORE searching so mounted secrets cannot be probed as a blind oracle.
        let clean = redact_bytes(secrets, capped);
        String::from_utf8_lossy(&clean).to_ascii_lowercase().contains(needle_low)
    };
    if check_blob(&x.request.id) {
        return true;
    }
    x.response.as_ref().is_some_and(|r| check_blob(&r.id))
}

fn format_signals_compact(signals: &[PassiveSignal]) -> String {
    if signals.is_empty() {
        return "-".into();
    }
    signals
        .iter()
        .take(4)
        .map(|s| format!("{}:{}", s.severity, s.kind))
        .collect::<Vec<_>>()
        .join(",")
}

#[async_trait]
impl Tool for TrafficQuery {
    fn spec(&self) -> ToolSpec {
        spec(
            "traffic_query",
            "Read-only query over captured HTTP exchanges (ex-*) recorded in this mission. Filter by host, method, path, status, principal, passive security signal kind/severity, or case-insensitive text search across redacted headers/body snippets.",
            ToolClass::Read,
            &[
                opt("host", "string", "Filter by host (case-insensitive substring)."),
                opt("method", "string", "Filter by HTTP method (case-insensitive, e.g. GET, POST)."),
                opt("path_contains", "string", "Filter by substring in the request target/path (case-insensitive)."),
                opt("status", "integer", "Exact HTTP response status code.").min(100),
                opt("status_min", "integer", "Minimum HTTP response status code.").min(100),
                opt("status_max", "integer", "Maximum HTTP response status code.").min(100),
                opt("principal", "string", "Filter by principal / credential profile (e.g. anon, user_b, profile:user_b)."),
                opt("signal_kind", "string", "Filter exchanges carrying a passive signal of this kind (or `*` for any signal)."),
                opt("signal_severity", "string", "Filter exchanges carrying a passive signal of this severity.")
                    .one_of(&["high", "medium", "low", "info"]),
                opt("search", "string", "Case-insensitive substring search in host, path, passive signals, and redacted headers/body snippet."),
                opt("limit", "integer", "Maximum exchanges to return (default 30, max 100).").min(1),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let host_f = args.get("host").and_then(Value::as_str).map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty());
        let method_f = args.get("method").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
        let path_f = args
            .get("path_contains")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let status_f = args.get("status").and_then(Value::as_u64).and_then(|v| u16::try_from(v).ok());
        let status_min_f = args.get("status_min").and_then(Value::as_u64).and_then(|v| u16::try_from(v).ok());
        let status_max_f = args.get("status_max").and_then(Value::as_u64).and_then(|v| u16::try_from(v).ok());
        let principal_f = args.get("principal").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty());
        let signal_kind_f = args
            .get("signal_kind")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let signal_sev_f = args
            .get("signal_severity")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let search_f = args
            .get("search")
            .and_then(Value::as_str)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map(|n| (n as usize).clamp(1, MAX_QUERY_LIMIT))
            .unwrap_or(DEFAULT_QUERY_LIMIT);

        let secrets = active_secrets(&self.0, ctx);
        let all = mission_exchanges(&self.0);
        let total = all.len();

        let matched: Vec<Exchange> = all
            .into_iter()
            .filter(|x| {
                host_f.as_deref().is_none_or(|h| x.host.to_ascii_lowercase().contains(h))
                    && method_f.is_none_or(|m| x.method.eq_ignore_ascii_case(m))
                    && path_f
                        .as_deref()
                        .is_none_or(|p| redact_str(secrets.as_deref(), &x.target).to_ascii_lowercase().contains(p))
                    && status_f.is_none_or(|s| x.status == Some(s))
                    && status_min_f.is_none_or(|min| x.status.is_some_and(|s| s >= min))
                    && status_max_f.is_none_or(|max| x.status.is_some_and(|s| s <= max))
                    && principal_f.is_none_or(|p| matches_principal(x.principal.as_deref(), p))
                    && signal_kind_f.as_deref().is_none_or(|k| {
                        if k == "*" || k == "any" {
                            !x.passive_signals.is_empty()
                        } else {
                            x.passive_signals.iter().any(|s| s.kind.eq_ignore_ascii_case(k))
                        }
                    })
                    && signal_sev_f
                        .as_deref()
                        .is_none_or(|sev| x.passive_signals.iter().any(|s| s.severity.eq_ignore_ascii_case(sev)))
                    && search_f
                        .as_deref()
                        .is_none_or(|q| exchange_matches_search(x, q, ctx, secrets.as_deref()))
            })
            .collect();

        let matched_total = matched.len();
        if matched_total == 0 {
            let msg = format!(
                "No captured exchanges matched the query (0 of {total} mission exchange(s))."
            );
            return ToolOutput::ok("traffic query", Body::Message(msg));
        }

        // Keep the most recent `limit` matches, preserving chronological order.
        let skip = matched_total.saturating_sub(limit);
        let shown = &matched[skip..];

        let mut out = String::new();
        out.push_str(&format!(
            "Showing {} of {} matching exchange(s) ({total} total in mission).\n",
            shown.len(),
            matched_total
        ));
        out.push_str("ID | METHOD | STATUS | HOST | TARGET | PRINCIPAL | SIGNALS | BYTES (req/resp)\n");
        let mut signal_details: Vec<String> = Vec::new();
        for x in shown {
            let status = x.status.map_or_else(|| "err".to_string(), |s| s.to_string());
            let principal = x.principal.as_deref().unwrap_or("-");
            let sigs = format_signals_compact(&x.passive_signals);
            let target_disp = cut_chars(&redact_str(secrets.as_deref(), &x.target), 120);
            out.push_str(&format!(
                "{} | {} | {} | {} | {} | {} | {} | {}/{}\n",
                x.id, x.method, status, x.host, target_disp, principal, sigs, x.request_bytes, x.response_bytes
            ));
            for sig in &x.passive_signals {
                if signal_details.len() < 40 {
                    signal_details.push(format!(
                        "- {} [{}] {}: {}",
                        x.id,
                        sig.severity,
                        sig.kind,
                        cut_chars(&redact_str(secrets.as_deref(), &sig.summary), 160)
                    ));
                }
            }
        }
        if !signal_details.is_empty() {
            out.push_str("\nPassive signals:\n");
            for line in signal_details {
                out.push_str(&line);
                out.push('\n');
            }
        }
        let clean = redact_str(secrets.as_deref(), &out);
        ToolOutput::ok("traffic query", Body::Raw(clean.into_bytes()))
    }
}

// ---- traffic_diff ----------------------------------------------------------------------------------

struct ParsedHttp<'a> {
    headers: BTreeMap<String, Vec<String>>,
    body: &'a [u8],
}

fn split_http_message(bytes: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
        (&bytes[..pos], &bytes[pos + 4..])
    } else if let Some(pos) = bytes.windows(2).position(|w| w == b"\n\n") {
        (&bytes[..pos], &bytes[pos + 2..])
    } else {
        (bytes, &[])
    }
}

fn parse_http_headers_and_body(bytes: &[u8]) -> ParsedHttp<'_> {
    let (head, body) = split_http_message(bytes);
    let head_str = String::from_utf8_lossy(head);
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in head_str.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            if !key.is_empty() {
                headers.entry(key).or_default().push(v.trim().to_string());
            }
        }
    }
    ParsedHttp { headers, body }
}

fn is_volatile_header(name: &str) -> bool {
    VOLATILE_HEADERS.contains(&name)
}

fn is_volatile_json_key(key: &str) -> bool {
    let norm = key.trim().to_ascii_lowercase().replace('-', "_");
    VOLATILE_JSON_KEYS.contains(&norm.as_str())
}

fn normalize_json_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                if !is_volatile_json_key(k) {
                    out.insert(k.clone(), normalize_json_value(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(normalize_json_value).collect()),
        other => other.clone(),
    }
}

fn collect_json_leaves(v: &Value, path: &str, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(map) => {
            if map.is_empty() {
                out.insert(path.to_string(), "{}".to_string());
            } else {
                for (k, val) in map {
                    collect_json_leaves(val, &format!("{path}.{k}"), out);
                }
            }
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                out.insert(path.to_string(), "[]".to_string());
            } else {
                for (i, val) in arr.iter().take(64).enumerate() {
                    collect_json_leaves(val, &format!("{path}[{i}]"), out);
                }
            }
        }
        leaf => {
            out.insert(path.to_string(), cut_chars(&leaf.to_string(), DIFF_MAX_PREVIEW_CHARS));
        }
    }
}

/// Compact bounded unified-style line diff using LCS on up to `DIFF_MAX_TEXT_LINES` lines per side.
fn unified_text_diff(left: &str, right: &str) -> (bool, String) {
    if left == right {
        return (true, String::new());
    }
    let a: Vec<&str> = left.lines().take(DIFF_MAX_TEXT_LINES).collect();
    let b: Vec<&str> = right.lines().take(DIFF_MAX_TEXT_LINES).collect();
    let (n, m) = (a.len(), b.len());
    let mut dp = vec![vec![0u16; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1].saturating_add(1)
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut ops: Vec<(char, &str)> = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push((' ', a[i]));
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            ops.push(('-', a[i]));
            i += 1;
        } else {
            ops.push(('+', b[j]));
            j += 1;
        }
    }
    while i < n {
        ops.push(('-', a[i]));
        i += 1;
    }
    while j < m {
        ops.push(('+', b[j]));
        j += 1;
    }

    // Keep lines within 1 context line of any change.
    let changed: Vec<bool> = ops.iter().map(|(tag, _)| *tag != ' ').collect();
    let mut keep = vec![false; ops.len()];
    for (idx, &is_chg) in changed.iter().enumerate() {
        if is_chg {
            if idx > 0 {
                keep[idx - 1] = true;
            }
            keep[idx] = true;
            if idx + 1 < ops.len() {
                keep[idx + 1] = true;
            }
        }
    }

    let mut out = String::new();
    let mut emitted = 0usize;
    let mut in_hunk = false;
    let mut truncated = false;
    for (idx, (tag, line)) in ops.iter().enumerate() {
        if !keep[idx] {
            in_hunk = false;
            continue;
        }
        if !in_hunk && !out.is_empty() {
            out.push_str("@@ ... @@\n");
        }
        in_hunk = true;
        if emitted >= DIFF_MAX_SNIPPET_LINES || out.len() >= DIFF_MAX_SNIPPET_BYTES {
            truncated = true;
            break;
        }
        out.push(*tag);
        out.push_str(&cut_chars(line, 240));
        out.push('\n');
        emitted += 1;
    }
    if truncated || left.lines().count() > DIFF_MAX_TEXT_LINES || right.lines().count() > DIFF_MAX_TEXT_LINES {
        out.push_str("... [diff truncated]\n");
    }
    (false, out)
}

fn diff_headers(
    left: &BTreeMap<String, Vec<String>>,
    right: &BTreeMap<String, Vec<String>>,
) -> Value {
    let mut added = Map::new();
    let mut removed = Map::new();
    let mut changed = Map::new();
    let mut ignored_volatile = 0usize;
    let keys: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
    for k in keys {
        if is_volatile_header(k) {
            ignored_volatile += 1;
            continue;
        }
        match (left.get(k), right.get(k)) {
            (None, Some(rv)) => {
                added.insert(k.clone(), json!(rv.join(", ")));
            }
            (Some(lv), None) => {
                removed.insert(k.clone(), json!(lv.join(", ")));
            }
            (Some(lv), Some(rv)) if lv != rv => {
                changed.insert(k.clone(), json!({ "left": lv.join(", "), "right": rv.join(", ") }));
            }
            _ => {}
        }
    }
    json!({
        "added": added,
        "removed": removed,
        "changed": changed,
        "ignored_volatile_headers": ignored_volatile,
    })
}

fn diff_bodies(left_body: &[u8], right_body: &[u8]) -> Value {
    let lb = &left_body[..left_body.len().min(DIFF_MAX_BODY_BYTES)];
    let rb = &right_body[..right_body.len().min(DIFF_MAX_BODY_BYTES)];

    if let (Ok(lj), Ok(rj)) = (serde_json::from_slice::<Value>(lb), serde_json::from_slice::<Value>(rb)) {
        let nl = normalize_json_value(&lj);
        let nr = normalize_json_value(&rj);
        let equal = nl == nr;
        let (mut l_leaves, mut r_leaves) = (BTreeMap::new(), BTreeMap::new());
        collect_json_leaves(&nl, "$", &mut l_leaves);
        collect_json_leaves(&nr, "$", &mut r_leaves);

        let mut added: Map<String, Value> = Map::new();
        let mut removed: Map<String, Value> = Map::new();
        let mut changed: Map<String, Value> = Map::new();
        for (k, rv) in &r_leaves {
            if !l_leaves.contains_key(k) && added.len() < DIFF_MAX_JSON_ITEMS {
                added.insert(k.clone(), json!(rv));
            }
        }
        for (k, lv) in &l_leaves {
            match r_leaves.get(k) {
                None if removed.len() < DIFF_MAX_JSON_ITEMS => {
                    removed.insert(k.clone(), json!(lv));
                }
                Some(rv) if rv != lv && changed.len() < DIFF_MAX_JSON_ITEMS => {
                    changed.insert(k.clone(), json!({ "left": lv, "right": rv }));
                }
                _ => {}
            }
        }
        return json!({
            "kind": "json",
            "normalized_equal": equal,
            "added": added,
            "removed": removed,
            "changed": changed,
        });
    }

    let is_binary = lb.contains(&0) || rb.contains(&0) || std::str::from_utf8(lb).is_err() || std::str::from_utf8(rb).is_err();
    if is_binary {
        return json!({
            "kind": "binary",
            "equal": left_body == right_body,
            "left_bytes": left_body.len(),
            "right_bytes": right_body.len(),
        });
    }

    let ls = String::from_utf8_lossy(lb);
    let rs = String::from_utf8_lossy(rb);
    let (equal, snippet) = unified_text_diff(&ls, &rs);
    json!({
        "kind": "text",
        "equal": equal,
        "unified_diff": snippet,
    })
}

fn diff_passive_signals(left: &[PassiveSignal], right: &[PassiveSignal]) -> Value {
    let key = |s: &PassiveSignal| (s.kind.clone(), s.severity.clone(), s.summary.clone());
    let lset: BTreeSet<(String, String, String)> = left.iter().map(key).collect();
    let rset: BTreeSet<(String, String, String)> = right.iter().map(key).collect();
    let render = |(kind, severity, summary): &(String, String, String)| {
        json!({ "kind": kind, "severity": severity, "summary": summary })
    };
    json!({
        "only_left": lset.difference(&rset).map(render).collect::<Vec<_>>(),
        "only_right": rset.difference(&lset).map(render).collect::<Vec<_>>(),
        "shared": lset.intersection(&rset).map(render).collect::<Vec<_>>(),
    })
}

#[async_trait]
impl Tool for TrafficDiff {
    fn spec(&self) -> ToolSpec {
        spec(
            "traffic_diff",
            "Read-only structured comparison of two captured HTTP exchanges (ex-*) from this mission: compares status, non-volatile headers, body byte length, normalized JSON or bounded text diff, and passive-signal delta (fully redacted).",
            ToolClass::Read,
            &[
                req("left_id", "string", "Baseline / left exchange ID (ex-*) from this mission."),
                req("right_id", "string", "Comparison / right exchange ID (ex-*) from this mission."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let left_id = args.get("left_id").and_then(Value::as_str).map(str::trim).unwrap_or("");
        let right_id = args.get("right_id").and_then(Value::as_str).map(str::trim).unwrap_or("");
        if left_id.is_empty() || right_id.is_empty() {
            return ToolOutput::error("Provide both `left_id` and `right_id` (ex-* exchange IDs from this mission).");
        }
        let Some(left) = find_mission_exchange(&self.0, left_id) else {
            return ToolOutput::error(format!(
                "Exchange `{left_id}` does not exist in this mission's traffic log. Use `traffic_query` to list captured exchange IDs."
            ));
        };
        let Some(right) = find_mission_exchange(&self.0, right_id) else {
            return ToolOutput::error(format!(
                "Exchange `{right_id}` does not exist in this mission's traffic log. Use `traffic_query` to list captured exchange IDs."
            ));
        };

        let secrets = active_secrets(&self.0, ctx);
        let load_resp = |x: &Exchange| -> Result<Vec<u8>, String> {
            match &x.response {
                Some(r) => {
                    let raw = ctx
                        .blobs
                        .read_all(&r.id)
                        .map_err(|e| format!("Could not read response blob of {}: {e}", x.id))?;
                    Ok(redact_bytes(secrets.as_deref(), &raw))
                }
                None => Ok(Vec::new()),
            }
        };
        let left_raw = match load_resp(&left) {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(e),
        };
        let right_raw = match load_resp(&right) {
            Ok(b) => b,
            Err(e) => return ToolOutput::error(e),
        };

        let left_parsed = parse_http_headers_and_body(&left_raw);
        let right_parsed = parse_http_headers_and_body(&right_raw);

        let left_body_len = left_parsed.body.len();
        let right_body_len = right_parsed.body.len();
        let delta_bytes = right_body_len as i64 - left_body_len as i64;

        let report = json!({
            "left": {
                "id": left.id,
                "method": left.method,
                "host": left.host,
                "target": redact_str(secrets.as_deref(), &left.target),
                "status": left.status,
                "principal": left.principal,
                "request_bytes": left.request_bytes,
                "response_bytes": left.response_bytes,
            },
            "right": {
                "id": right.id,
                "method": right.method,
                "host": right.host,
                "target": redact_str(secrets.as_deref(), &right.target),
                "status": right.status,
                "principal": right.principal,
                "request_bytes": right.request_bytes,
                "response_bytes": right.response_bytes,
            },
            "status_diff": {
                "left": left.status,
                "right": right.status,
                "changed": left.status != right.status,
            },
            "header_diff": diff_headers(&left_parsed.headers, &right_parsed.headers),
            "body_length_diff": {
                "left_body_bytes": left_body_len,
                "right_body_bytes": right_body_len,
                "delta_bytes": delta_bytes,
                "left_wire_response_bytes": left.response_bytes,
                "right_wire_response_bytes": right.response_bytes,
            },
            "body_diff": diff_bodies(left_parsed.body, right_parsed.body),
            "passive_signal_delta": diff_passive_signals(&left.passive_signals, &right.passive_signals),
        });

        match serde_json::to_string_pretty(&report) {
            Ok(text) => {
                let clean = redact_str(secrets.as_deref(), &text);
                ToolOutput::ok("traffic diff", Body::Raw(clean.into_bytes()))
            }
            Err(_) => ToolOutput::error("Could not serialize traffic diff report."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtools::testkit::{core_role, rig_with, Rig};
    use ferret_core::config::AgentsCfg;
    use ferret_core::creds::{Item, ItemKind, Secrets};
    use ferret_core::event::ToolStatus as Status;
    use serde_json::json;

    fn traffic_rig(read_only: bool) -> Rig {
        let mut role = core_role(if read_only { "verifier" } else { "lead" });
        role.read_only = read_only;
        role.tools.extend(["traffic_query".into(), "traffic_diff".into()]);
        rig_with(role, read_only, true, AgentsCfg::default())
    }

    #[allow(clippy::too_many_arguments)]
    fn push_exchange(
        r: &Rig,
        id: &str,
        method: &str,
        host: &str,
        target: &str,
        status: Option<u16>,
        principal: Option<&str>,
        req_raw: &[u8],
        resp_raw: Option<&[u8]>,
        signals: Vec<PassiveSignal>,
    ) {
        let req = r.env.ctx.blobs.put_bytes(req_raw).unwrap();
        let resp = resp_raw.map(|b| r.env.ctx.blobs.put_bytes(b).unwrap());
        r.shared.traffic.mission.add(&Exchange {
            id: id.into(),
            call_id: None,
            source: "tool".into(),
            tool: Some("http_send".into()),
            scheme: "https".into(),
            tls: "tool".into(),
            method: method.into(),
            host: host.into(),
            port: 443,
            target: target.into(),
            status,
            error: None,
            request: req,
            response: resp,
            request_bytes: req_raw.len() as u64,
            response_bytes: resp_raw.map_or(0, |b| b.len() as u64),
            truncated: false,
            upstream_unverified: false,
            duration_ms: 5,
            passive_signals: signals,
            principal: principal.map(str::to_string),
        });
    }

    fn body_json(text: &str) -> Value {
        let start = text.find('{').unwrap();
        serde_json::Deserializer::from_str(&text[start..]).into_iter::<Value>().next().unwrap().unwrap()
    }

    #[tokio::test]
    async fn traffic_query_filters_and_redacts_secrets_before_search() {
        let r = traffic_rig(true);
        let secret = "super-secret-bearer-token-999";
        let secrets = Arc::new(Secrets::for_items(&[Item {
            kind: ItemKind::Header,
            name: "Authorization".into(),
            value: secret.into(),
            host: "api.acme.test".into(),
        }]));
        let _ = r.env.ctx.capabilities.secrets.set(secrets);

        push_exchange(
            &r,
            "ex-query0000001",
            "GET",
            "api.acme.test",
            "/v1/invoices/42",
            Some(200),
            Some("profile:user_a"),
            format!("GET /v1/invoices/42 HTTP/1.1\r\nAuthorization: Bearer {secret}\r\n\r\n").as_bytes(),
            Some(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{{\"owner\":\"alice\",\"echo\":\"{secret}\"}}").as_bytes()),
            vec![PassiveSignal {
                kind: "cors_misconfig".into(),
                severity: "high".into(),
                summary: "Reflected Origin with credentials".into(),
                detail: "ACAO echoed".into(),
            }],
        );
        push_exchange(
            &r,
            "ex-query0000002",
            "POST",
            "admin.acme.test",
            "/v1/export",
            Some(403),
            Some("anon"),
            b"POST /v1/export HTTP/1.1\r\n\r\n",
            Some(b"HTTP/1.1 403 Forbidden\r\n\r\nforbidden"),
            vec![],
        );

        // Filter by signal_kind + signal_severity.
        let by_sig = r
            .call("traffic_query", json!({"signal_kind": "cors_misconfig", "signal_severity": "high"}))
            .await;
        assert_eq!(by_sig.status, Status::Ok, "{}", by_sig.text);
        assert!(by_sig.text.contains("ex-query0000001") && !by_sig.text.contains("ex-query0000002"), "{}", by_sig.text);
        assert!(!by_sig.text.contains(secret), "secret leaked: {}", by_sig.text);

        // Filter by principal shorthand (`user_a` matches `profile:user_a`) and status range.
        let by_princ = r.call("traffic_query", json!({"principal": "user_a", "status_min": 200, "status_max": 299})).await;
        assert!(by_princ.text.contains("ex-query0000001") && !by_princ.text.contains("ex-query0000002"));

        // Search works on visible body content ("alice")...
        let hit = r.call("traffic_query", json!({"search": "alice"})).await;
        assert!(hit.text.contains("ex-query0000001"), "{}", hit.text);

        // ...but NEVER acts as a blind oracle for mounted secrets (neither in bodies nor query strings)!
        let probe = r.call("traffic_query", json!({"search": secret})).await;
        assert_eq!(probe.status, Status::Ok);
        assert!(probe.text.contains("0 of 2"), "secret search must not match: {}", probe.text);

        // Even if a secret ever appeared in `x.target` query string, neither `path_contains` nor `search` can probe it.
        push_exchange(
            &r,
            "ex-query0000003",
            "GET",
            "api.acme.test",
            &format!("/v1/callback?token={secret}"),
            Some(200),
            Some("profile:user_a"),
            b"GET /v1/callback HTTP/1.1\r\n\r\n",
            Some(b"HTTP/1.1 200 OK\r\n\r\nok"),
            vec![],
        );
        let probe_path = r.call("traffic_query", json!({"path_contains": secret})).await;
        assert!(probe_path.text.contains("0 of 3"), "secret path_contains must not match: {}", probe_path.text);
        let probe_search = r.call("traffic_query", json!({"search": secret})).await;
        assert!(probe_search.text.contains("0 of 3"), "secret search on target must not match: {}", probe_search.text);
        let visible_path = r.call("traffic_query", json!({"path_contains": "/v1/callback"})).await;
        assert!(visible_path.text.contains("ex-query0000003") && !visible_path.text.contains(secret));
    }

    #[tokio::test]
    async fn traffic_diff_compares_json_text_headers_signals_and_redacts() {
        let r = traffic_rig(true);
        let secret = "top-secret-session-cookie-777";
        let _ = r.env.ctx.capabilities.secrets.set(Arc::new(Secrets::for_items(&[Item {
            kind: ItemKind::Cookie,
            name: "sid".into(),
            value: secret.into(),
            host: "api.acme.test".into(),
        }])));

        push_exchange(
            &r,
            "ex-diff00000001",
            "GET",
            "api.acme.test",
            "/v1/profile",
            Some(200),
            Some("profile:user_a"),
            b"GET /v1/profile HTTP/1.1\r\n\r\n",
            Some(
                format!(
                    "HTTP/1.1 200 OK\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\nETag: \"v1\"\r\nX-Request-Id: aaa\r\nX-Role: user\r\nContent-Type: application/json\r\n\r\n{{\"id\":42,\"email\":\"a@acme.test\",\"timestamp\":1000,\"token\":\"{secret}\"}}"
                )
                .as_bytes(),
            ),
            vec![PassiveSignal {
                kind: "cookie_insecure".into(),
                severity: "medium".into(),
                summary: "Missing HttpOnly".into(),
                detail: "".into(),
            }],
        );
        push_exchange(
            &r,
            "ex-diff00000002",
            "GET",
            "api.acme.test",
            "/v1/profile",
            Some(200),
            Some("profile:user_b"),
            b"GET /v1/profile HTTP/1.1\r\n\r\n",
            Some(
                format!(
                    "HTTP/1.1 200 OK\r\nDate: Tue, 02 Jan 2026 00:00:00 GMT\r\nETag: \"v2\"\r\nX-Request-Id: bbb\r\nX-Role: admin\r\nX-Extra: yes\r\nContent-Type: application/json\r\n\r\n{{\"id\":42,\"email\":\"a@acme.test\",\"timestamp\":2000,\"token\":\"{secret}\"}}"
                )
                .as_bytes(),
            ),
            vec![PassiveSignal {
                kind: "verbose_error".into(),
                severity: "low".into(),
                summary: "Debug header".into(),
                detail: "".into(),
            }],
        );

        let res = r.call("traffic_diff", json!({"left_id": "ex-diff00000001", "right_id": "ex-diff00000002"})).await;
        assert_eq!(res.status, Status::Ok, "{}", res.text);
        assert!(!res.text.contains(secret), "secret leaked in diff: {}", res.text);
        let j = body_json(&res.text);
        assert_eq!(j["status_diff"]["changed"], false);
        // Volatile headers (Date, ETag, X-Request-Id) ignored; X-Role changed and X-Extra added.
        assert_eq!(j["header_diff"]["ignored_volatile_headers"], 3);
        assert_eq!(j["header_diff"]["added"]["x-extra"], "yes");
        assert_eq!(j["header_diff"]["changed"]["x-role"]["left"], "user");
        assert_eq!(j["header_diff"]["changed"]["x-role"]["right"], "admin");
        // Normalized JSON ignores `timestamp` -> normalized_equal == true!
        assert_eq!(j["body_diff"]["kind"], "json");
        assert_eq!(j["body_diff"]["normalized_equal"], true);
        // Passive signal delta computed cleanly.
        assert_eq!(j["passive_signal_delta"]["only_left"][0]["kind"], "cookie_insecure");
        assert_eq!(j["passive_signal_delta"]["only_right"][0]["kind"], "verbose_error");

        // Missing exchange returns clean error.
        let miss = r.call("traffic_diff", json!({"left_id": "ex-diff00000001", "right_id": "ex-missing00000"})).await;
        assert_eq!(miss.status, Status::Error);
        assert!(miss.text.contains("ex-missing00000"));
    }
}
