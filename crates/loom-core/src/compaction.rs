//! What a compaction puts in the window, as pure functions of the log (CONTRACTS-COMPACTION K5, K6).
//!
//! CONTRACT.
//!
//! `item_text(records, c)`: the body of the one `<harness kind="compaction">` item the weave renders for the
//! latest [`Compaction`] `c` of `records` (the whole log), in this order, each part omitted when empty and
//! the parts separated by a blank line:
//! 1. [`head`]`(step, c.reason)`, `step` being the latest step request before the compaction record.
//! 2. The operator's messages (`UserMessage` records at or before `c.upto_seq`), oldest first, each headed
//!    `Operator, step {n}, {date}:`. When together they pass 20% of `c.compact_at` (tokens), the oldest become
//!    one line each (their first 120 characters and a pointer to `log_search`) until they fit.
//! 3. `c.brief` under `The mission ledger at this point:`.
//! 4. [`pinned_split`]'s verbatim part, newest first, under `Pinned outputs:`.
//! 5. `c.table`.
//! 6. `c.note` under [`NOTE_LABEL`].
//!
//! `build_table(input)`: the key table (K5), deterministic: the same log and input give the same text. Output
//! rows are chosen by class: (a) outputs the ledger cites and pinned outputs that did not fit the pin budget
//! and (b) outputs the note cites, then (c) the last 40 calls before the tail, then (d) the rows of the
//! previous compaction's table. More than 400 rows drop (d) rows oldest first, then (c) rows oldest first;
//! (a) and (b) are kept newest first up to 800. The rest are counted in one line. Dates are UTC.
//!
//! Tested in `weave` (rendering) and in the session tests (what is chosen and when).

use crate::estimate::TokenEstimator;
use crate::event::{Compaction, Event, Purpose, Record, Seq, ToolClass, ToolResult, ToolStatus};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// Hex characters of an output key.
pub const KEY_LEN: usize = 16;
/// Calls before the tail whose outputs are listed (class c).
pub const RECENT_CALLS: usize = 40;
/// Most rows of the outputs section before the (c) and (d) rows give way.
pub const ROWS_SOFT_CAP: usize = 400;
/// Most rows when only (a) and (b) rows are left.
pub const ROWS_HARD_CAP: usize = 800;
/// `compact_at` of a record that did not state it.
pub const DEFAULT_COMPACT_AT: u64 = 400_000;

/// Line before the model's note in the item.
pub const NOTE_LABEL: &str =
    "Your note from before the compaction (written by you, not verified: check a key before relying on it):";

/// First paragraph of the item.
pub fn head(step: u32, reason: &str) -> String {
    format!(
        "Context was compacted at step {step} ({reason}). Earlier messages are out of view; nothing was deleted. Read any output by its key with read (path `out:…`); log_search searches the whole log."
    )
}

fn tokens(chars: usize) -> u64 {
    TokenEstimator::default().tokens(chars)
}

/// `s` on one line, cut to `max` characters (`…` marks a cut).
pub fn one_line_cut(s: &str, max: usize) -> String {
    let flat: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let kept: String = flat.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// UTC `(year, month, day, hour, minute)` of a time in milliseconds since the epoch.
fn civil(ms: u64) -> (i64, u32, u32, u32, u32) {
    let secs = i64::try_from(ms / 1000).unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let y = yoe + era * 400 + i64::from(m <= 2);
    let hh = u32::try_from(rem / 3600).unwrap_or(0);
    let mm = u32::try_from(rem % 3600 / 60).unwrap_or(0);
    (y, m, d, hh, mm)
}

/// `2026-11-19 14:02` (UTC).
pub fn date_time(ms: u64) -> String {
    let (y, m, d, hh, mm) = civil(ms);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}")
}

fn short_time(ms: u64) -> String {
    let (_, m, d, hh, mm) = civil(ms);
    format!("{m:02}-{d:02} {hh:02}:{mm:02}")
}

/// The number of the latest step request at or before `seq` (0 before the first).
pub fn step_at(records: &[Record], seq: Seq) -> u32 {
    let mut step = 0;
    for r in records {
        if r.seq > seq {
            break;
        }
        if let Event::ModelRequest(q) = &r.event {
            if q.purpose == Purpose::Step {
                step = q.step;
            }
        }
    }
    step
}

fn operator_messages(records: &[Record], upto: Seq, budget_tokens: u64) -> String {
    let mut items: Vec<(String, String)> = Vec::new();
    let mut step = 0;
    for r in records {
        if r.seq > upto {
            break;
        }
        match &r.event {
            Event::ModelRequest(q) if q.purpose == Purpose::Step => step = q.step,
            Event::UserMessage { text, images } => {
                let head = format!("Operator, step {step}, {}:", date_time(r.ts_ms));
                let mut body = text.trim().to_string();
                if !images.is_empty() {
                    let _ = write!(body, "\n[{} image(s) attached; see the log]", images.len());
                }
                items.push((head, body));
            }
            _ => {}
        }
    }
    let size = |items: &[(String, String)]| -> u64 { items.iter().map(|(h, b)| tokens(h.len() + b.len() + 2)).sum() };
    let mut total = size(&items);
    for i in 0..items.len() {
        if total <= budget_tokens {
            break;
        }
        if let Some((h, b)) = items.get_mut(i) {
            let before = tokens(h.len() + b.len() + 2);
            *b = format!("{} (cut; log_search finds the rest)", one_line_cut(b, 120));
            let after = tokens(h.len() + b.len() + 2);
            total = total.saturating_sub(before.saturating_sub(after));
        }
    }
    items.iter().map(|(h, b)| format!("{h}\n{b}")).collect::<Vec<_>>().join("\n\n")
}

/// Pinned outputs of the log up to `upto`: those shown verbatim in the item (newest pin first, together at
/// most 10% of `compact_at`) and the call ids of the rest, which the table lists.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Pins {
    /// `(call id, reason, result text)`.
    pub verbatim: Vec<(String, String, String)>,
    pub rest: Vec<String>,
}

pub fn pinned_split(records: &[Record], upto: Seq, compact_at: u64) -> Pins {
    let mut pinned: Vec<(String, String)> = Vec::new();
    let mut results: HashMap<&str, &ToolResult> = HashMap::new();
    for r in records {
        if r.seq > upto {
            break;
        }
        match &r.event {
            Event::Pin { call_id, reason } => {
                pinned.retain(|(c, _)| c != call_id.as_str());
                pinned.push((call_id.to_string(), reason.clone()));
            }
            Event::Unpin { call_id } => pinned.retain(|(c, _)| c != call_id.as_str()),
            Event::ToolResult(t) => {
                results.insert(t.call_id.as_str(), t);
            }
            _ => {}
        }
    }
    let budget = tokens(usize::try_from(compact_at / 10).unwrap_or(usize::MAX));
    let mut used = 0;
    let mut out = Pins::default();
    for (call, reason) in pinned.into_iter().rev() {
        let Some(t) = results.get(call.as_str()) else { continue };
        let cost = tokens(t.text.len());
        if used + cost <= budget {
            used += cost;
            out.verbatim.push((call, reason, t.text.clone()));
        } else {
            out.rest.push(call);
        }
    }
    out
}

/// The body of the compaction item (see the module contract).
pub fn item_text(records: &[Record], comp_seq: Seq, c: &Compaction) -> String {
    let compact_at = if c.compact_at == 0 { DEFAULT_COMPACT_AT } else { c.compact_at };
    let mut parts: Vec<String> = vec![head(step_at(records, comp_seq), &c.reason)];
    let ops = operator_messages(records, c.upto_seq, tokens(usize::try_from(compact_at / 5).unwrap_or(usize::MAX)));
    if !ops.is_empty() {
        parts.push(ops);
    }
    if !c.brief.trim().is_empty() {
        parts.push(format!("The mission ledger at this point:\n{}", c.brief.trim_end()));
    }
    let pins = pinned_split(records, c.upto_seq, compact_at);
    if !pins.verbatim.is_empty() {
        let shown: Vec<String> = pins
            .verbatim
            .iter()
            .map(|(call, reason, text)| format!("[pinned {call}: {}]\n{text}", one_line_cut(reason, 160)))
            .collect();
        parts.push(format!("Pinned outputs:\n\n{}", shown.join("\n\n")));
    }
    if !c.table.trim().is_empty() {
        parts.push(c.table.trim_end().to_string());
    }
    if let Some(note) = c.note.as_deref().filter(|n| !n.trim().is_empty()) {
        parts.push(format!("{NOTE_LABEL}\n{}", note.trim()));
    }
    parts.join("\n\n")
}

// ---- the key table ----

/// What [`build_table`] needs besides the log.
#[derive(Clone, Debug, Default)]
pub struct TableInput {
    /// Records at or before this seq are summarized.
    pub upto_seq: Seq,
    /// Keys (`out:` + 16 hex) the note cites, already checked.
    pub note_keys: Vec<String>,
    /// Call ids whose outputs the ledger cites (evidence).
    pub cited_calls: HashSet<String>,
    /// Keys of the previous compaction's table.
    pub prev_keys: Vec<String>,
    pub compact_at: u64,
}

struct Row {
    seq: Seq,
    key: String,
    text: String,
}

/// Every key of an output the log stored for a call (`out:` + 16 hex), by call id.
fn handle_of(t: &ToolResult) -> Option<String> {
    t.output.as_ref().map(crate::blob::BlobRef::handle)
}

fn arg_summary(args: &Value) -> String {
    for k in ["command", "cmd", "path", "file_path", "pattern", "query", "url", "name"] {
        if let Some(v) = args.get(k).and_then(Value::as_str).filter(|v| !v.trim().is_empty()) {
            return one_line_cut(v, 80);
        }
    }
    if let Some(map) = args.as_object() {
        for v in map.values() {
            if let Some(v) = v.as_str().filter(|v| !v.trim().is_empty()) {
                return one_line_cut(v, 80);
            }
        }
    }
    String::new()
}

fn path_of(t: &ToolResult, args: &Value) -> Option<String> {
    if let Some(p) = t.meta.get(crate::event::META_PATH).and_then(Value::as_str).filter(|p| !p.is_empty()) {
        return Some(p.to_string());
    }
    ["path", "file_path", "absolute_path", "target_file", "file"]
        .iter()
        .find_map(|k| args.get(*k).and_then(Value::as_str).filter(|p| !p.is_empty()))
        .map(str::to_string)
}

/// `(added, removed)` lines of the unified diff an edit or write result shows.
pub fn diff_stat(text: &str) -> (u64, u64) {
    let (mut add, mut del) = (0, 0);
    for l in text.lines() {
        if l.starts_with("+++") || l.starts_with("---") {
            continue;
        }
        if l.starts_with('+') {
            add += 1;
        } else if l.starts_with('-') {
            del += 1;
        }
    }
    (add, del)
}

fn status_word(s: ToolStatus) -> &'static str {
    match s {
        ToolStatus::Ok => "ok",
        ToolStatus::Error => "error",
        ToolStatus::Invalid => "invalid",
        ToolStatus::Denied => "denied",
        ToolStatus::Timeout => "timeout",
        ToolStatus::Interrupted => "interrupted",
    }
}

/// Build the key table and the keys it lists, in order.
pub fn build_table(records: &[Record], input: &TableInput) -> (String, Vec<String>) {
    let upto = input.upto_seq;
    let mut calls: HashMap<&str, &crate::event::ToolCall> = HashMap::new();
    let mut step = 0;
    let mut outputs: Vec<(Seq, &ToolResult, u64, u32)> = Vec::new(); // seq, result, ts, step
    let mut files: Vec<(String, u64, u64, u32, Seq, Option<String>)> = Vec::new();
    let mut jobs: Vec<(String, String, u32)> = Vec::new();
    let mut agents: Vec<(String, String, String, String, Option<String>)> = Vec::new();
    for r in records {
        if r.seq > upto {
            break;
        }
        match &r.event {
            Event::ModelRequest(q) if q.purpose == Purpose::Step => step = q.step,
            Event::ToolCall(c) => {
                calls.insert(c.call_id.as_str(), c);
            }
            Event::ToolResult(t) => {
                // A finish or conclusion is a verdict, not an output to go back to: its answer stays in the log.
                let ending = matches!(t.name.as_str(), "finish" | "conclude");
                if t.output.is_some() && !ending {
                    outputs.push((r.seq, t, r.ts_ms, step));
                }
                if t.class == ToolClass::Write && t.status == ToolStatus::Ok {
                    let args = calls.get(t.call_id.as_str()).map_or(&Value::Null, |c| &c.args);
                    if let Some(p) = path_of(t, args) {
                        let (a, d) = diff_stat(&t.text);
                        match files.iter_mut().find(|f| f.0 == p) {
                            Some(f) => {
                                f.1 += a;
                                f.2 += d;
                                f.3 += 1;
                                f.4 = r.seq;
                                f.5 = handle_of(t);
                            }
                            None => files.push((p, a, d, 1, r.seq, handle_of(t))),
                        }
                    }
                }
            }
            Event::JobRegistered { job_id, command, .. } => {
                jobs.push((job_id.clone(), one_line_cut(command, 80), step));
            }
            Event::JobSettled { job_id, .. } => jobs.retain(|j| &j.0 != job_id),
            Event::ChildSpawned(c) => {
                agents.push((
                    c.child.to_string(),
                    one_line_cut(&c.brief.question, 60),
                    c.role.clone(),
                    "running".to_string(),
                    None,
                ));
            }
            Event::ChildSettled(c) if !c.inline || c.full.is_some() => {
                let outcome = serde_json::to_value(c.outcome).ok().and_then(|v| v.as_str().map(str::to_string));
                if let Some(a) = agents.iter_mut().find(|a| a.0 == c.child.to_string()) {
                    a.3 = outcome.unwrap_or_else(|| "finished".to_string());
                    a.4 = c.full.as_ref().map(crate::blob::BlobRef::handle);
                }
            }
            _ => {}
        }
    }

    // Classes of rows.
    let pins = pinned_split(records, upto, input.compact_at.max(1));
    let keep_calls: HashSet<&str> =
        input.cited_calls.iter().map(String::as_str).chain(pins.rest.iter().map(String::as_str)).collect();
    let note: HashSet<&str> = input.note_keys.iter().map(String::as_str).collect();
    let prev: HashSet<&str> = input.prev_keys.iter().map(String::as_str).collect();
    let recent: HashSet<Seq> = outputs.iter().rev().take(RECENT_CALLS).map(|o| o.0).collect();

    // class: 0 = a/b, 1 = c, 2 = d
    let mut chosen: Vec<(u8, Row)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut last_by_key: HashMap<String, usize> = HashMap::new();
    for (i, (_, t, _, _)) in outputs.iter().enumerate() {
        if let Some(k) = handle_of(t) {
            last_by_key.insert(k, i);
        }
    }
    for (i, (seq, t, ts, st)) in outputs.iter().enumerate() {
        let Some(key) = handle_of(t) else { continue };
        if last_by_key.get(&key) != Some(&i) || !seen.insert(key.clone()) {
            continue;
        }
        let class = if keep_calls.contains(t.call_id.as_str()) || note.contains(key.as_str()) {
            0
        } else if recent.contains(seq) {
            1
        } else if prev.contains(key.as_str()) {
            2
        } else {
            continue;
        };
        let call = calls.get(t.call_id.as_str());
        let args = call.map_or(&Value::Null, |c| &c.args);
        let mut cols = vec![key.clone(), t.name.clone()];
        let what = arg_summary(args);
        if !what.is_empty() {
            cols.push(what);
        }
        let outcome = match t.meta.get(crate::event::META_EXIT_CODE).and_then(Value::as_i64) {
            Some(code) => format!("exit {code}"),
            None if t.class == ToolClass::Write && t.status == ToolStatus::Ok => {
                if t.name == "write" { "wrote" } else { "edited" }.to_string()
            }
            None => status_word(t.status).to_string(),
        };
        cols.push(outcome);
        if t.class == ToolClass::Write && t.status == ToolStatus::Ok {
            let (a, d) = diff_stat(&t.text);
            cols.push(format!("+{a} −{d}"));
        } else if let Some(b) = &t.output {
            cols.push(format!("{} lines", b.lines));
        }
        cols.push(format!("step {st}, {}", short_time(*ts)));
        chosen.push((class, Row { seq: *seq, key, text: cols.join(" · ") }));
    }

    // Caps.
    let mut total = chosen.len();
    for class in [2u8, 1u8] {
        if total <= ROWS_SOFT_CAP {
            break;
        }
        let mut idx: Vec<usize> = chosen.iter().enumerate().filter(|(_, (c, _))| *c == class).map(|(i, _)| i).collect();
        idx.sort_by_key(|&i| chosen.get(i).map_or(0, |(_, r)| r.seq));
        let drop_n = idx.len().min(total - ROWS_SOFT_CAP);
        let drop: HashSet<usize> = idx.into_iter().take(drop_n).collect();
        let mut i = 0;
        chosen.retain(|_| {
            let keep = !drop.contains(&i);
            i += 1;
            keep
        });
        total = chosen.len();
    }
    if chosen.len() > ROWS_HARD_CAP {
        chosen.sort_by_key(|(_, r)| std::cmp::Reverse(r.seq));
        chosen.truncate(ROWS_HARD_CAP);
    }
    chosen.sort_by_key(|(_, r)| r.seq);

    let mut keys: Vec<String> = Vec::new();
    let mut sections: Vec<String> = Vec::new();
    if !chosen.is_empty() || !outputs.is_empty() {
        let mut s =
            String::from("Outputs — read one with read(path: \"out:<key>\"); search everything with log_search");
        for (_, r) in &chosen {
            s.push('\n');
            s.push_str(&r.text);
            keys.push(r.key.clone());
        }
        let listed: HashSet<&str> = chosen.iter().map(|(_, r)| r.key.as_str()).collect();
        let unlisted: Vec<u32> = outputs
            .iter()
            .filter(|(_, t, _, _)| handle_of(t).is_some_and(|k| !listed.contains(k.as_str())))
            .map(|o| o.3)
            .collect();
        if let (Some(lo), Some(hi)) = (unlisted.iter().min(), unlisted.iter().max()) {
            let _ = write!(
                s,
                "\n… {} earlier outputs (steps {lo}–{hi}) are not listed: search them with log_search.",
                unlisted.len()
            );
        }
        sections.push(s);
    }
    if !files.is_empty() {
        files.sort_by_key(|f| std::cmp::Reverse(f.4));
        let mut s = String::from("Files changed by edit/write (shell commands are not tracked)");
        for (p, a, d, n, _, last) in &files {
            let edits = if *n == 1 { "1 edit".to_string() } else { format!("{n} edits") };
            let _ = write!(s, "\n{p} · +{a} −{d} · {edits}");
            if let Some(k) = last {
                let _ = write!(s, " · last {k}");
            }
        }
        sections.push(s);
    }
    if !agents.is_empty() {
        let mut s = String::from("Agents");
        for (id, what, role, state, report) in &agents {
            let _ = write!(s, "\n{id} · {what} · {role} · {state}");
            if let Some(k) = report {
                let _ = write!(s, " · report {k}");
                if !keys.contains(k) {
                    keys.push(k.clone());
                }
            }
        }
        sections.push(s);
    }
    if !jobs.is_empty() {
        let mut s = String::from("Jobs still running");
        for (id, cmd, since) in &jobs {
            let _ = write!(s, "\n{id} · {cmd} · since step {since}");
        }
        sections.push(s);
    }
    (sections.join("\n\n"), keys)
}
