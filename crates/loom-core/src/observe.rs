//! Derived facts about what a session has looked at. All functions are pure over log records.
//!
//! CONTRACT.
//!
//! ## Coverage
//! For every stored output, the set of its lines that some `tool` message in the given records put in
//! front of the model. Sources, per `tool_result` record:
//! - its own `output` blob with `meta[META_SHOWN]` ranges (admission wrote them); a result with an
//!   `output`, no `META_SHOWN` and `cut == false` counts as fully shown;
//! - a view of another blob: `meta[META_OF_BLOB]` (full id) with `meta[META_SHOWN]` ranges
//!   (`out_read`, `out_grep`).
//!   Malformed meta is ignored. Ranges are merged; `total_lines` comes from the `BlobRef` when the
//!   records contain one for that blob, else 0 (unknown).
//!
//! ## Unviewed output
//! `unviewed(records, min_lines)` lists `Exec` results whose own output has at least `min_lines`
//! lines never shown, newest first — the agent layer shows these in the HUD.
//!
//! ## Repetition
//! A repetition is the same tool name with the same canonical arguments (`serde_json` compact form of
//! `tool_call.args`) and the same output blob id, completed at least `min_count` times. Only calls of
//! class `Nav`, `Read` and `Exec` count.
//!
//! ## Staleness
//! Using `meta[META_PATH]` on results of class `Read` (a file was read) and `Write` (a file was
//! changed, status `Ok`):
//! - `StaleKind::ReadBeforeWrite`: a path whose latest read is older than its latest write;
//! - `StaleKind::ExecBeforeWrite`: the most recent `Exec` result with status `Ok` or `Error` is older
//!   than a later write (reported once, for the latest such `Exec`, naming the first write after it).
//!   Records are compared by `seq`.
//!
//! ## Quote check
//! `check_quote(haystack, quote, first_line)` — `haystack` is a range of lines of a stored output and
//! `first_line` the number its first line has in that output. Both sides are prepared the same way:
//! each line has trailing whitespace removed; leading/trailing blank lines of the quote are ignored.
//! The quote is looked for as it is. Only when it does not occur that way, and every non-blank line
//! of it starts with a line-number prefix as produced by the read tools (`^\s*\d+[:\-│|\t]\s?`, the
//! numbers increasing; a line of digits alone is the number of a blank line), the prefixes are removed
//! and the rest is looked for (blank lines at either end of it are ignored again). No other leniency:
//! case, indentation, inner spacing and punctuation must be exact.
//! An occurrence is accepted when both hold:
//! - if the quote carried line numbers, each number is the number of the line its text is on;
//! - it spans whole lines, or has at least `MIN_PARTIAL_QUOTE_CHARS` (8) non-whitespace characters.
//!
//! The first accepted occurrence wins and `Ok(text)` is the text to record: the quote's lines joined
//! by `\n`, without the prefixes. Otherwise `Err`: `NotFound` (the text does not occur; also an empty
//! or whitespace-only quote), `WrongLine { quoted, actual }` (it occurs, but never on the lines the
//! quote numbers: for the first occurrence, the first wrong number and the line that text is on), or
//! `TooShort` (it occurs where the numbers allow, but only as a fragment of fewer than 8 characters).
//! The haystack is walked once, whatever the number of occurrences.
//! `quote_matches(haystack, quote)` is `check_quote(haystack, quote, 1).is_ok()`.
//! `nearest_line(haystack, quote)` returns the 1-based number and text of the haystack line sharing
//! the longest common prefix with the first non-blank quote line (for error messages), if any shares
//! at least 8 characters.
//!
//! Tests required: coverage from own output, from views, merged ranges, malformed meta; unviewed
//! ordering and threshold; repetition counting across different outputs; both staleness kinds and
//! their absence after a re-read / re-run; check_quote positives, prefix stripping in every separator
//! style, wrong line numbers, the minimum length, and negatives.

use crate::event::{
    Event, Record, Seq, ToolCall, ToolClass, ToolResult, ToolStatus, META_OF_BLOB, META_PATH, META_SHOWN,
};
use crate::ids::{BlobId, CallId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// 0 when unknown.
    pub total_lines: u64,
    /// Sorted, merged, 1-based inclusive.
    pub seen: Vec<(u64, u64)>,
}

impl Coverage {
    /// Add a range and keep `seen` sorted and merged. Ranges with `first > last` or `first == 0` are ignored.
    pub fn add(&mut self, first: u64, last: u64) {
        if first == 0 || first > last {
            return;
        }
        self.seen.push((first, last));
        self.seen.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.seen.len());
        for &(a, b) in &self.seen {
            match merged.last_mut() {
                Some(prev) if a <= prev.1.saturating_add(1) => prev.1 = prev.1.max(b),
                _ => merged.push((a, b)),
            }
        }
        self.seen = merged;
    }

    /// True when every line in `first..=last` has been shown.
    pub fn covers(&self, first: u64, last: u64) -> bool {
        if first == 0 || first > last {
            return false;
        }
        self.seen.iter().any(|&(a, b)| a <= first && last <= b)
    }

    pub fn seen_lines(&self) -> u64 {
        self.seen.iter().fold(0u64, |acc, &(a, b)| acc.saturating_add(b.saturating_sub(a).saturating_add(1)))
    }

    /// `total_lines - seen_lines`, or 0 when the total is unknown.
    pub fn unseen_lines(&self) -> u64 {
        if self.total_lines == 0 {
            return 0;
        }
        let seen_in_total = self
            .seen
            .iter()
            .filter(|&&(a, _)| a <= self.total_lines)
            .fold(0u64, |acc, &(a, b)| acc.saturating_add(b.min(self.total_lines).saturating_sub(a).saturating_add(1)));
        self.total_lines.saturating_sub(seen_in_total)
    }

    /// The gaps within `1..=total_lines`.
    pub fn gaps(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        if self.total_lines == 0 {
            return out;
        }
        let mut next = 1u64; // first line not yet accounted for
        for &(a, b) in &self.seen {
            if next > self.total_lines {
                break;
            }
            if a > next {
                out.push((next, (a - 1).min(self.total_lines)));
            }
            next = next.max(b.saturating_add(1));
        }
        if next <= self.total_lines {
            out.push((next, self.total_lines));
        }
        out
    }
}

/// The `[[first, last], …]` ranges in `META_SHOWN`. `None` when the key is absent; a malformed value
/// or malformed entries contribute nothing.
fn shown_ranges(result: &ToolResult) -> Option<Vec<(u64, u64)>> {
    let v = result.meta.get(META_SHOWN)?;
    let Some(items) = v.as_array() else {
        return Some(Vec::new());
    };
    let ranges = items
        .iter()
        .filter_map(|item| {
            let pair = item.as_array()?;
            if pair.len() != 2 {
                return None;
            }
            Some((pair.first()?.as_u64()?, pair.get(1)?.as_u64()?))
        })
        .collect();
    Some(ranges)
}

/// Coverage of every stored output referenced by `records`, keyed by full blob id.
pub fn coverage(records: &[Record]) -> BTreeMap<BlobId, Coverage> {
    // Known sizes. Differing sizes for one id: keep the larger, so unseen counts are never understated.
    let mut totals: BTreeMap<BlobId, u64> = BTreeMap::new();
    let mut note_total = |id: &BlobId, lines: u64| {
        let t = totals.entry(id.clone()).or_insert(0);
        *t = (*t).max(lines);
    };
    for r in records {
        match &r.event {
            Event::ToolResult(t) => {
                if let Some(o) = &t.output {
                    note_total(&o.id, o.lines);
                }
            }
            Event::JobSettled { output: Some(o), .. } => note_total(&o.id, o.lines),
            Event::ChildSettled(c) => {
                if let Some(o) = &c.full {
                    note_total(&o.id, o.lines);
                }
            }
            _ => {}
        }
    }

    let mut map: BTreeMap<BlobId, Coverage> = BTreeMap::new();
    for r in records {
        let Event::ToolResult(t) = &r.event else { continue };
        if let Some(o) = &t.output {
            map.entry(o.id.clone()).or_default();
        }
        match t.meta.get(META_OF_BLOB) {
            Some(Value::String(id)) if !id.is_empty() => {
                let cov = map.entry(BlobId::from(id.as_str())).or_default();
                for (a, b) in shown_ranges(t).unwrap_or_default() {
                    cov.add(a, b);
                }
            }
            // A view of something that cannot be identified: nothing is credited.
            Some(_) => {}
            None => {
                let Some(o) = &t.output else { continue };
                let cov = map.entry(o.id.clone()).or_default();
                match shown_ranges(t) {
                    Some(ranges) => {
                        for (a, b) in ranges {
                            cov.add(a, b);
                        }
                    }
                    None if !t.cut => cov.add(1, o.lines),
                    None => {}
                }
            }
        }
    }

    for (id, cov) in map.iter_mut() {
        cov.total_lines = totals.get(id).copied().unwrap_or(0);
        if cov.total_lines > 0 {
            // Ranges past the end of the output show nothing.
            let total = cov.total_lines;
            let old = std::mem::take(&mut cov.seen);
            for (a, b) in old {
                if a <= total {
                    cov.add(a, b.min(total));
                }
            }
        }
    }
    map
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unviewed {
    pub seq: Seq,
    pub call_id: CallId,
    pub tool: String,
    /// The handle (`out:…`).
    pub handle: String,
    pub total_lines: u64,
    pub unseen_lines: u64,
    pub gaps: Vec<(u64, u64)>,
}

/// `Exec` results whose output has at least `min_lines` (and at least one) never-shown lines, newest
/// first. An output produced by several results is listed once, at its newest result.
pub fn unviewed(records: &[Record], min_lines: u64) -> Vec<Unviewed> {
    let cov = coverage(records);
    let mut out: Vec<Unviewed> = Vec::new();
    let mut listed: Vec<&BlobId> = Vec::new();
    let mut results: Vec<(&Record, &ToolResult)> = records
        .iter()
        .filter_map(|r| match &r.event {
            Event::ToolResult(t) if t.class == ToolClass::Exec => Some((r, t)),
            _ => None,
        })
        .collect();
    results.sort_by_key(|r| std::cmp::Reverse(r.0.seq));
    for (r, t) in results {
        let Some(o) = &t.output else { continue };
        let Some(c) = cov.get(&o.id) else { continue };
        let unseen = c.unseen_lines();
        if unseen == 0 || unseen < min_lines || listed.contains(&&o.id) {
            continue;
        }
        listed.push(&o.id);
        out.push(Unviewed {
            seq: r.seq,
            call_id: t.call_id.clone(),
            tool: t.name.clone(),
            handle: o.handle(),
            total_lines: c.total_lines,
            unseen_lines: unseen,
            gaps: c.gaps(),
        });
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repetition {
    pub tool: String,
    /// Canonical arguments, cut to 200 characters.
    pub args: String,
    pub count: u32,
    pub last_seq: Seq,
}

/// Compact JSON with object keys sorted, so reordered keys are the same call.
fn canonical(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(x) = m.get(k) {
                    out.insert(k.clone(), canonical(x));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

/// Same tool, same arguments, same output blob, completed at least `min_count` times; most repeated first.
pub fn repetitions(records: &[Record], min_count: u32) -> Vec<Repetition> {
    let mut calls: HashMap<&CallId, &ToolCall> = HashMap::new();
    for r in records {
        if let Event::ToolCall(c) = &r.event {
            calls.insert(&c.call_id, c);
        }
    }
    let mut groups: BTreeMap<(String, String, BlobId), (u32, Seq)> = BTreeMap::new();
    for r in records {
        let Event::ToolResult(t) = &r.event else { continue };
        let Some(call) = calls.get(&t.call_id) else { continue };
        if !matches!(call.class, ToolClass::Nav | ToolClass::Read | ToolClass::Exec) {
            continue;
        }
        let Some(o) = &t.output else { continue };
        let args = serde_json::to_string(&canonical(&call.args)).unwrap_or_default();
        let e = groups.entry((call.name.clone(), args, o.id.clone())).or_insert((0, 0));
        e.0 = e.0.saturating_add(1);
        e.1 = e.1.max(r.seq);
    }
    let mut out: Vec<Repetition> = groups
        .into_iter()
        .filter(|(_, (count, _))| *count >= min_count)
        .map(|((tool, args, _), (count, last_seq))| Repetition {
            tool,
            args: args.chars().take(200).collect(),
            count,
            last_seq,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count).then(b.last_seq.cmp(&a.last_seq)));
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleKind {
    ReadBeforeWrite,
    ExecBeforeWrite,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stale {
    pub kind: StaleKind,
    /// The read or run that is now out of date.
    pub seq: Seq,
    /// The later write.
    pub write_seq: Seq,
    /// The file (for `ReadBeforeWrite`: the file read; for `ExecBeforeWrite`: the file written).
    pub path: String,
}

/// Reads and runs that a later write has made out of date. Only successful reads and writes that name
/// their path count; an `Exec` counts when it ran to a result (`Ok` or `Error`).
pub fn stale(records: &[Record]) -> Vec<Stale> {
    let mut reads: BTreeMap<&str, Seq> = BTreeMap::new();
    let mut writes: BTreeMap<&str, Seq> = BTreeMap::new();
    let mut all_writes: Vec<(Seq, &str)> = Vec::new();
    let mut last_exec: Option<Seq> = None;
    for r in records {
        let Event::ToolResult(t) = &r.event else { continue };
        let path = t.meta.get(META_PATH).and_then(Value::as_str);
        match t.class {
            ToolClass::Read if t.status == ToolStatus::Ok => {
                if let Some(p) = path {
                    let e = reads.entry(p).or_insert(r.seq);
                    *e = (*e).max(r.seq);
                }
            }
            ToolClass::Write if t.status == ToolStatus::Ok => {
                if let Some(p) = path {
                    let e = writes.entry(p).or_insert(r.seq);
                    *e = (*e).max(r.seq);
                    all_writes.push((r.seq, p));
                }
            }
            ToolClass::Exec if matches!(t.status, ToolStatus::Ok | ToolStatus::Error) => {
                last_exec = Some(last_exec.map_or(r.seq, |s| s.max(r.seq)));
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for (path, &read_seq) in &reads {
        if let Some(&write_seq) = writes.get(path) {
            if read_seq < write_seq {
                out.push(Stale {
                    kind: StaleKind::ReadBeforeWrite,
                    seq: read_seq,
                    write_seq,
                    path: (*path).to_string(),
                });
            }
        }
    }
    if let Some(exec_seq) = last_exec {
        if let Some(&(write_seq, path)) = all_writes.iter().filter(|(s, _)| *s > exec_seq).min_by_key(|(s, _)| *s) {
            out.push(Stale { kind: StaleKind::ExecBeforeWrite, seq: exec_seq, write_seq, path: path.to_string() });
        }
    }
    out
}

/// Split a read-tool line number prefix (`^\s*\d+[:\-│|\t]\s?`) off `line`, giving the number and the
/// rest. A line of digits alone is a number with an empty rest (a blank line of a numbered listing).
fn split_line_prefix(line: &str) -> Option<(u64, &str)> {
    let t = line.trim_start();
    let digits = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    if digits == 0 {
        return None;
    }
    let n: u64 = t.get(..digits)?.parse().ok()?;
    let rest = t.get(digits..)?;
    if rest.is_empty() {
        return Some((n, ""));
    }
    let mut chars = rest.chars();
    let sep = chars.next()?;
    if !matches!(sep, ':' | '-' | '│' | '|' | '\t') {
        return None;
    }
    let after = chars.as_str();
    if sep == '\t' {
        return Some((n, after));
    }
    let mut again = after.chars();
    let rest = match again.next() {
        Some(c) if c.is_whitespace() => again.as_str(),
        _ => after,
    };
    Some((n, rest))
}

fn prepare_haystack(h: &str) -> String {
    h.lines().map(str::trim_end).collect::<Vec<_>>().join("\n")
}

/// The quote's lines without leading or trailing blank lines, each with trailing whitespace removed.
fn quote_lines(quote: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = quote.lines().map(str::trim_end).collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let lead = lines.iter().take_while(|l| l.is_empty()).count();
    lines.split_off(lead)
}

/// The quote with line-number prefixes removed, and the number each line carried (`None` for a blank
/// line), or `None` when it does not consistently carry them: every non-blank line needs one and the
/// numbers must increase. Lines at either end that are empty once stripped are left out, as
/// [`quote_lines`] leaves them out of a quote without numbers.
fn strip_prefixes<'a>(lines: &[&'a str]) -> Option<(Vec<&'a str>, Vec<Option<u64>>)> {
    let mut out = Vec::with_capacity(lines.len());
    let mut numbers = Vec::with_capacity(lines.len());
    let mut prev: Option<u64> = None;
    for l in lines {
        if l.is_empty() {
            out.push("");
            numbers.push(None);
            continue;
        }
        let (n, rest) = split_line_prefix(l)?;
        if prev.is_some_and(|p| n <= p) {
            return None;
        }
        prev = Some(n);
        out.push(rest);
        numbers.push(Some(n));
    }
    while out.last().is_some_and(|l| l.is_empty()) {
        out.pop();
        numbers.pop();
    }
    let lead = out.iter().take_while(|l| l.is_empty()).count();
    Some((out.into_iter().skip(lead).collect(), numbers.into_iter().skip(lead).collect()))
}

/// A quote that does not span whole lines must have at least this many non-whitespace characters.
pub const MIN_PARTIAL_QUOTE_CHARS: usize = 8;

/// Why a quote was not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuoteError {
    /// The text does not occur.
    NotFound,
    /// The text occurs, but the line numbers in the quote are not those of the lines it is on: `actual`
    /// is where the line numbered `quoted` really is.
    WrongLine { quoted: u64, actual: u64 },
    /// The text occurs but is a fragment of fewer than [`MIN_PARTIAL_QUOTE_CHARS`] characters.
    TooShort,
}

/// Walk the occurrences of `text` in `hay` front to back, overlapping ones included, and accept the first
/// that is a valid quote: the numbers the quote gave its lines (`numbers`, one entry per line of `text`)
/// are the numbers of the lines it is on, and it spans whole lines or is long enough. `first_line` is the
/// number of the first line of `hay`. One pass: the line count is carried from one occurrence to the next,
/// so the lines of `hay` are counted once however many occurrences are passed over.
fn scan_quote(hay: &str, text: &str, numbers: Option<&[Option<u64>]>, first_line: u64) -> Result<(), QuoteError> {
    if text.is_empty() {
        return Err(QuoteError::NotFound);
    }
    let long_enough = text.chars().filter(|c| !c.is_whitespace()).count() >= MIN_PARTIAL_QUOTE_CHARS;
    let mut wrong: Option<QuoteError> = None;
    let mut short = false;
    // `line` is the number of the line that byte `counted` of `hay` is on.
    let (mut line, mut counted) = (first_line, 0usize);
    let mut from = 0usize;
    while let Some(off) = hay.get(from..).and_then(|rest| rest.find(text)).map(|at| from.saturating_add(at)) {
        let newlines = hay.get(counted..off).map_or(0, |between| between.matches('\n').count());
        line = line.saturating_add(newlines as u64);
        counted = off;
        from = off.saturating_add(hay.get(off..).and_then(|r| r.chars().next()).map_or(1, char::len_utf8));
        if let Some(numbers) = numbers {
            let bad = numbers.iter().enumerate().find_map(|(k, n)| {
                let actual = line.saturating_add(k as u64);
                n.filter(|n| *n != actual).map(|n| QuoteError::WrongLine { quoted: n, actual })
            });
            if bad.is_some() {
                wrong = wrong.or(bad);
                continue;
            }
        }
        let starts_line = off == 0 || hay.get(..off).is_some_and(|before| before.ends_with('\n'));
        let after = hay.get(off.saturating_add(text.len())..);
        let ends_line = after.is_some_and(|after| after.is_empty() || after.starts_with('\n'));
        if (starts_line && ends_line) || long_enough {
            return Ok(());
        }
        short = true;
    }
    match wrong {
        _ if short => Err(QuoteError::TooShort),
        Some(e) => Err(e),
        None => Err(QuoteError::NotFound),
    }
}

/// Check `quote` against `haystack`, whose first line is line `first_line` of the stored output. Returns
/// the quoted text as it is to be recorded: with line-number prefixes removed. Prefixes, when present,
/// must be the real line numbers; a quote that is not whole lines needs [`MIN_PARTIAL_QUOTE_CHARS`]
/// non-whitespace characters.
pub fn check_quote(haystack: &str, quote: &str, first_line: u64) -> Result<String, QuoteError> {
    if quote.trim().is_empty() {
        return Err(QuoteError::NotFound);
    }
    let hay = prepare_haystack(haystack);
    let lines = quote_lines(quote);
    let literal = lines.join("\n");
    // A literal fragment that is too short may still be a numbered quote ("3: ok" where line 3 is "ok"
    // and the literal text also sits inside a longer line): the numbered reading gets its turn, and
    // "too short" is the answer only when both fail.
    let literal_short = match scan_quote(&hay, &literal, None, first_line) {
        Err(QuoteError::NotFound) => false,
        Err(QuoteError::TooShort) => true,
        verdict => return verdict.map(|()| literal),
    };
    let numbered = match strip_prefixes(&lines) {
        Some((stripped, numbers)) => {
            let text = stripped.join("\n");
            scan_quote(&hay, &text, Some(numbers.as_slice()), first_line).map(|()| text)
        }
        None => Err(QuoteError::NotFound),
    };
    match numbered {
        Err(_) if literal_short => Err(QuoteError::TooShort),
        verdict => verdict,
    }
}

/// [`check_quote`] for a haystack that starts at line 1, when only the answer matters.
pub fn quote_matches(haystack: &str, quote: &str) -> bool {
    check_quote(haystack, quote, 1).is_ok()
}

fn common_prefix_chars(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count()
}

pub fn nearest_line(haystack: &str, quote: &str) -> Option<(u64, String)> {
    let first = quote.lines().map(str::trim_end).find(|l| !l.trim().is_empty())?;
    let stripped = split_line_prefix(first).map(|(_, rest)| rest);
    let mut best: Option<(usize, u64, &str)> = None;
    for (i, line) in haystack.lines().enumerate() {
        let line_t = line.trim_end();
        let mut n = common_prefix_chars(line_t, first);
        if let Some(s) = stripped {
            n = n.max(common_prefix_chars(line_t, s));
        }
        if n >= 8 && best.is_none_or(|(b, _, _)| n > b) {
            best = Some((n, (i as u64).saturating_add(1), line));
        }
    }
    best.map(|(_, no, text)| (no, text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::BlobRef;
    use crate::event::Author;
    use serde_json::json;

    fn rec(seq: Seq, event: Event) -> Record {
        Record { seq, ts_ms: seq, author: Author::Tool, prev: "0".repeat(64), event }
    }

    fn blob(id: &str, lines: u64) -> BlobRef {
        BlobRef { id: BlobId::from(id), bytes: lines * 10, lines }
    }

    fn result(
        seq: Seq,
        call: &str,
        class: ToolClass,
        status: ToolStatus,
        output: Option<BlobRef>,
        cut: bool,
        meta: Value,
    ) -> Record {
        let meta = meta.as_object().cloned().unwrap_or_default();
        rec(
            seq,
            Event::ToolResult(ToolResult {
                call_id: CallId::from(call),
                name: "t".into(),
                status,
                text: String::new(),
                output,
                cut,
                class,
                meta,
                duration_ms: 0,
            }),
        )
    }

    fn call(seq: Seq, id: &str, name: &str, args: Value, class: ToolClass) -> Record {
        rec(
            seq,
            Event::ToolCall(ToolCall {
                call_id: CallId::from(id),
                req_id: "r".into(),
                name: name.into(),
                args,
                class,
            }),
        )
    }

    fn exec(seq: Seq, id: &str, out: Option<BlobRef>, cut: bool, meta: Value) -> Record {
        result(seq, id, ToolClass::Exec, ToolStatus::Ok, out, cut, meta)
    }

    #[test]
    fn range_arithmetic() {
        let mut c = Coverage { total_lines: 20, seen: vec![] };
        c.add(0, 5);
        c.add(9, 3);
        assert!(c.seen.is_empty());
        c.add(10, 12);
        c.add(1, 3);
        c.add(4, 5);
        c.add(11, 14);
        assert_eq!(c.seen, vec![(1, 5), (10, 14)]);
        assert_eq!(c.seen_lines(), 10);
        assert_eq!(c.unseen_lines(), 10);
        assert_eq!(c.gaps(), vec![(6, 9), (15, 20)]);
        assert!(c.covers(2, 5));
        assert!(!c.covers(5, 10));
        assert!(!c.covers(0, 1));
        assert!(!c.covers(3, 2));
        let unknown = Coverage { total_lines: 0, seen: vec![(1, 3)] };
        assert_eq!(unknown.unseen_lines(), 0);
        assert!(unknown.gaps().is_empty());
    }

    #[test]
    fn own_output_full_cut_and_shown() {
        let recs = vec![
            exec(1, "a", Some(blob("aa", 10)), false, json!({})),
            exec(2, "b", Some(blob("bb", 100)), true, json!({})),
            exec(3, "c", Some(blob("cc", 100)), true, json!({ "shown": [[1, 40], [91, 100]] })),
        ];
        let cov = coverage(&recs);
        let a = &cov[&BlobId::from("aa")];
        assert_eq!((a.total_lines, a.seen.clone()), (10, vec![(1, 10)]));
        let b = &cov[&BlobId::from("bb")];
        assert_eq!((b.total_lines, b.seen_lines(), b.unseen_lines()), (100, 0, 100));
        let c = &cov[&BlobId::from("cc")];
        assert_eq!(c.seen, vec![(1, 40), (91, 100)]);
        assert_eq!(c.gaps(), vec![(41, 90)]);
    }

    #[test]
    fn views_add_to_the_viewed_blob() {
        let recs = vec![
            exec(1, "a", Some(blob("aa", 100)), true, json!({ "shown": [[1, 10]] })),
            result(
                3,
                "r1",
                ToolClass::Read,
                ToolStatus::Ok,
                None,
                false,
                json!({ "of_blob": "aa", "shown": [[11, 30]] }),
            ),
            result(
                5,
                "r2",
                ToolClass::Read,
                ToolStatus::Ok,
                None,
                false,
                json!({ "of_blob": "aa", "shown": [[31, 50], [60, 70]] }),
            ),
        ];
        let cov = coverage(&recs);
        let a = &cov[&BlobId::from("aa")];
        assert_eq!(a.seen, vec![(1, 50), (60, 70)]);
        assert_eq!(a.total_lines, 100);
        assert_eq!(a.unseen_lines(), 39);
    }

    #[test]
    fn view_of_blob_without_a_blobref_has_unknown_total() {
        let recs = vec![result(
            1,
            "r",
            ToolClass::Read,
            ToolStatus::Ok,
            None,
            false,
            json!({ "of_blob": "zz", "shown": [[1, 5]] }),
        )];
        let cov = coverage(&recs);
        let z = &cov[&BlobId::from("zz")];
        assert_eq!((z.total_lines, z.seen.clone(), z.unseen_lines()), (0, vec![(1, 5)], 0));
    }

    #[test]
    fn malformed_meta_counts_as_not_shown() {
        let recs = vec![
            exec(1, "a", Some(blob("aa", 50)), true, json!({ "shown": "all" })),
            exec(2, "b", Some(blob("bb", 50)), false, json!({ "shown": 7 })),
            exec(3, "c", Some(blob("cc", 50)), true, json!({ "shown": [[1], "x", [3, "y"], [-1, 4], [5, 2], [0, 3], [7, 9]] })),
            exec(4, "d", Some(blob("dd", 50)), false, json!({ "of_blob": 12, "shown": [[1, 50]] })),
            exec(5, "e", Some(blob("ee", 50)), false, json!({ "of_blob": "", "shown": [[1, 50]] })),
            exec(6, "f", Some(blob("ff", 10)), true, json!({ "shown": [[1, 1000]] })),
        ];
        let cov = coverage(&recs);
        assert!(cov[&BlobId::from("aa")].seen.is_empty());
        assert!(cov[&BlobId::from("bb")].seen.is_empty());
        assert_eq!(cov[&BlobId::from("cc")].seen, vec![(7, 9)]);
        assert!(cov[&BlobId::from("dd")].seen.is_empty());
        assert!(cov[&BlobId::from("ee")].seen.is_empty());
        // Ranges past the end are cut to the known size.
        assert_eq!(cov[&BlobId::from("ff")].seen, vec![(1, 10)]);
        assert!(!cov.contains_key(&BlobId::from("")));
    }

    #[test]
    fn unviewed_threshold_and_order() {
        let recs = vec![
            exec(1, "a", Some(blob("aaaaaaaaaaaaaaaaaaaa", 500)), true, json!({ "shown": [[1, 100]] })),
            exec(3, "b", Some(blob("bb", 30)), true, json!({})),
            exec(5, "c", Some(blob("cc", 200)), true, json!({ "shown": [[1, 200]] })),
            exec(7, "d", Some(blob("dd", 1000)), true, json!({ "shown": [[1, 10]] })),
            result(8, "w", ToolClass::Write, ToolStatus::Ok, Some(blob("ww", 900)), true, json!({})),
            exec(9, "n", None, false, json!({})),
            result(
                11,
                "v",
                ToolClass::Read,
                ToolStatus::Ok,
                None,
                false,
                json!({ "of_blob": "aaaaaaaaaaaaaaaaaaaa", "shown": [[101, 150]] }),
            ),
        ];
        let u = unviewed(&recs, 25);
        let seqs: Vec<Seq> = u.iter().map(|x| x.seq).collect();
        assert_eq!(seqs, vec![7, 3, 1]);
        assert_eq!(u[0].unseen_lines, 990);
        assert_eq!(u[0].gaps, vec![(11, 1000)]);
        assert_eq!(u[1].unseen_lines, 30);
        assert_eq!(u[2].unseen_lines, 350);
        assert_eq!(u[2].handle, "out:aaaaaaaaaaaaaaaa");
        assert_eq!(u[2].total_lines, 500);
        assert_eq!(unviewed(&recs, 400).len(), 1);
        assert!(unviewed(&recs, 2000).is_empty());
    }

    #[test]
    fn repeated_output_is_listed_once_at_its_newest_result() {
        let recs = vec![
            exec(1, "a", Some(blob("aa", 50)), true, json!({})),
            exec(3, "b", Some(blob("aa", 50)), true, json!({})),
        ];
        let u = unviewed(&recs, 1);
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].seq, 3);
    }

    #[test]
    fn repetitions_need_same_args_and_same_output() {
        let same = json!({ "cmd": "cargo test", "cwd": "/w" });
        let reordered = json!({ "cwd": "/w", "cmd": "cargo test" });
        let recs = vec![
            call(0, "1", "bash", same.clone(), ToolClass::Exec),
            exec(1, "1", Some(blob("o1", 5)), false, json!({})),
            call(2, "2", "bash", reordered, ToolClass::Exec),
            exec(3, "2", Some(blob("o1", 5)), false, json!({})),
            call(4, "3", "bash", same.clone(), ToolClass::Exec),
            exec(5, "3", Some(blob("o2", 5)), false, json!({})),
            call(6, "4", "bash", same, ToolClass::Exec),
            exec(7, "4", Some(blob("o1", 5)), false, json!({})),
            // Different output every time: not a repetition.
            call(8, "5", "grep", json!({ "p": "x" }), ToolClass::Nav),
            result(9, "5", ToolClass::Nav, ToolStatus::Ok, Some(blob("g1", 1)), false, json!({})),
            call(10, "6", "grep", json!({ "p": "x" }), ToolClass::Nav),
            result(11, "6", ToolClass::Nav, ToolStatus::Ok, Some(blob("g2", 1)), false, json!({})),
            // Writes never count.
            call(12, "7", "edit", json!({ "f": 1 }), ToolClass::Write),
            result(13, "7", ToolClass::Write, ToolStatus::Ok, Some(blob("e1", 1)), false, json!({})),
            call(14, "8", "edit", json!({ "f": 1 }), ToolClass::Write),
            result(15, "8", ToolClass::Write, ToolStatus::Ok, Some(blob("e1", 1)), false, json!({})),
        ];
        let r = repetitions(&recs, 3);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].tool, "bash");
        assert_eq!(r[0].count, 3);
        assert_eq!(r[0].last_seq, 7);
        assert_eq!(r[0].args, "{\"cmd\":\"cargo test\",\"cwd\":\"/w\"}");
        let all = repetitions(&recs, 1);
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].count, 3);
        assert!(repetitions(&recs, 4).is_empty());
    }

    #[test]
    fn repetition_args_are_cut() {
        let long = json!({ "q": "x".repeat(500) });
        let recs = vec![
            call(0, "1", "grep", long.clone(), ToolClass::Nav),
            result(1, "1", ToolClass::Nav, ToolStatus::Ok, Some(blob("g", 1)), false, json!({})),
            call(2, "2", "grep", long, ToolClass::Nav),
            result(3, "2", ToolClass::Nav, ToolStatus::Ok, Some(blob("g", 1)), false, json!({})),
        ];
        let r = repetitions(&recs, 2);
        assert_eq!(r[0].args.chars().count(), 200);
    }

    fn read(seq: Seq, path: &str) -> Record {
        result(seq, &format!("c{seq}"), ToolClass::Read, ToolStatus::Ok, None, false, json!({ "path": path }))
    }

    fn write(seq: Seq, path: &str) -> Record {
        result(seq, &format!("c{seq}"), ToolClass::Write, ToolStatus::Ok, None, false, json!({ "path": path }))
    }

    #[test]
    fn read_before_write_and_its_absence_after_reread() {
        let mut recs = vec![read(1, "/a"), read(2, "/b"), write(3, "/a")];
        let s = stale(&recs);
        assert_eq!(
            s,
            vec![Stale { kind: StaleKind::ReadBeforeWrite, seq: 1, write_seq: 3, path: "/a".into() }]
        );
        recs.push(read(4, "/a"));
        assert!(stale(&recs).is_empty());
        recs.push(write(6, "/a"));
        assert_eq!(stale(&recs).len(), 1);
        assert_eq!(stale(&recs)[0].seq, 4);
        assert_eq!(stale(&recs)[0].write_seq, 6);
    }

    #[test]
    fn failed_reads_and_writes_do_not_count() {
        let recs = vec![
            read(1, "/a"),
            result(2, "w", ToolClass::Write, ToolStatus::Error, None, false, json!({ "path": "/a" })),
            result(3, "w2", ToolClass::Write, ToolStatus::Denied, None, false, json!({ "path": "/a" })),
            write(4, "/other"),
        ];
        assert!(stale(&recs).is_empty());
    }

    #[test]
    fn exec_before_write_and_its_absence_after_rerun() {
        let mut recs = vec![
            exec(1, "e1", None, false, json!({})),
            write(2, "/x"),
            write(3, "/y"),
        ];
        let s = stale(&recs);
        assert_eq!(
            s,
            vec![Stale { kind: StaleKind::ExecBeforeWrite, seq: 1, write_seq: 2, path: "/x".into() }]
        );
        recs.push(result(5, "e2", ToolClass::Exec, ToolStatus::Error, None, false, json!({})));
        assert!(stale(&recs).is_empty());
        // A run that timed out does not count as a run.
        recs.push(write(6, "/z"));
        recs.push(result(7, "e3", ToolClass::Exec, ToolStatus::Timeout, None, false, json!({})));
        let s = stale(&recs);
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].seq, s[0].write_seq, s[0].path.as_str()), (5, 6, "/z"));
    }

    #[test]
    fn quote_exact_and_multiline() {
        let hay = "fn main() {\n    let x = 1;   \n    println!(\"{x}\");\n}\n";
        // A fragment of seven characters is too short; the whole line is not.
        assert!(!quote_matches(hay, "let x = 1;"));
        assert!(quote_matches(hay, "    let x = 1;"));
        assert!(quote_matches(hay, "println!(\"{x}\");"));
        assert!(quote_matches(hay, "    let x = 1;\n    println!(\"{x}\");"));
        assert!(quote_matches(hay, "\n\n    let x = 1;  \n\n"));
        assert!(quote_matches("a\r\nb\r\n", "a\nb"));
    }

    #[test]
    fn quote_strips_line_number_prefixes() {
        let hay = "alpha\n    beta();\n\ngamma\n";
        assert!(quote_matches(hay, "1: alpha\n2:     beta();"));
        assert!(quote_matches(hay, "  1│alpha\n  2│     beta();"));
        assert!(quote_matches(hay, "1|alpha\n2|     beta();\n3|\n4|gamma"));
        assert!(quote_matches(hay, "4-gamma"));
        assert!(!quote_matches(hay, "7-gamma"));
        // Line numbers are those of the stored output: the haystack here starts at line 11.
        assert!(check_quote(hay, "  12:     beta();", 11).is_ok());
        assert_eq!(check_quote(hay, "  12:     beta();", 1), Err(QuoteError::WrongLine { quoted: 12, actual: 2 }));
    }

    #[test]
    fn quote_line_numbers_must_be_the_real_ones() {
        let hay = "0 of 40 tests passed\nsecond line here\n";
        assert_eq!(check_quote(hay, "40: tests passed", 1), Err(QuoteError::WrongLine { quoted: 40, actual: 1 }));
        assert_eq!(check_quote(hay, "2: tests passed", 1), Err(QuoteError::WrongLine { quoted: 2, actual: 1 }));
        assert_eq!(check_quote(hay, "1: tests passed", 1), Ok("tests passed".to_string()));
        assert_eq!(check_quote(hay, "40: tests passed", 40), Ok("tests passed".to_string()));
        // Every separator style, TAB included, is accepted and the stored text is stripped.
        let hay = "alpha line\n    beta line\n\ngamma line\n";
        for q in [
            "1: alpha line\n2:     beta line",
            "1- alpha line\n2-     beta line",
            "1| alpha line\n2|     beta line",
            "1│alpha line\n2│     beta line",
            "1\talpha line\n2\t    beta line",
            "     1\talpha line\n     2\t    beta line",
        ] {
            assert_eq!(check_quote(hay, q, 1), Ok("alpha line\n    beta line".to_string()), "{q:?}");
        }
        assert_eq!(
            check_quote(hay, "1\talpha line\n3\t    beta line", 1),
            Err(QuoteError::WrongLine { quoted: 3, actual: 2 })
        );
        // Unprefixed quotes are returned as they are.
        assert_eq!(check_quote(hay, "gamma line", 1), Ok("gamma line".to_string()));
    }

    #[test]
    fn numbered_blank_lines_at_the_ends_of_a_quote_are_left_out() {
        let hay = "alpha line\n    beta line\n\ngamma line\n";
        // As for a quote without numbers, where blank lines at either end are ignored.
        assert_eq!(check_quote(hay, "\n\ngamma line\n", 1), Ok("gamma line".to_string()));
        assert_eq!(check_quote(hay, "3\t\n4\tgamma line", 1), Ok("gamma line".to_string()));
        assert_eq!(check_quote(hay, "2:     beta line\n3:", 1), Ok("    beta line".to_string()));
        // A blank line at an end is not recorded, so nothing is claimed about the line next to the text.
        assert_eq!(check_quote(hay, "1\t\n2\t    beta line", 1), Ok("    beta line".to_string()));
        // A blank line inside the quote is part of the text and has to be there.
        let inside = check_quote(hay, "2\t    beta line\n3\t\n4\tgamma line", 1);
        assert_eq!(inside, Ok("    beta line\n\ngamma line".to_string()));
        assert_eq!(check_quote(hay, "1\talpha line\n2\t\n3\t    beta line", 1), Err(QuoteError::NotFound));
        // Nothing but numbers is not a quote.
        assert_eq!(check_quote(hay, "3\t\n4\t", 1), Err(QuoteError::NotFound));
    }

    #[test]
    fn quote_check_walks_a_large_output_once() {
        let started = std::time::Instant::now();
        // Every one of 200 000 lines ends in the fragment, and no occurrence of it is acceptable.
        let hay: String = (1..=200_000).map(|i| format!("run {i} ... ok\n")).collect();
        assert_eq!(check_quote(&hay, "... ok", 1), Err(QuoteError::TooShort));
        // The same line 200 000 times: the numbers decide which occurrence is quoted.
        let hay = "same line of output\n".repeat(200_000);
        assert_eq!(check_quote(&hay, "200000\tsame line of output", 1), Ok("same line of output".to_string()));
        assert_eq!(
            check_quote(&hay, "200001: same line of output", 1),
            Err(QuoteError::WrongLine { quoted: 200_001, actual: 1 })
        );
        // Counting the lines again from the top for each occurrence takes minutes here.
        assert!(started.elapsed() < std::time::Duration::from_secs(60), "took {:?}", started.elapsed());
    }

    #[test]
    fn quote_minimum_length_applies_to_fragments_only() {
        let hay = "ok\nthe build is green now\n7\n";
        assert_eq!(check_quote(hay, "green", 1), Err(QuoteError::TooShort));
        assert_eq!(check_quote(hay, "is gre", 1), Err(QuoteError::TooShort));
        assert!(check_quote(hay, "build is green", 1).is_ok());
        assert!(check_quote(hay, "ok", 1).is_ok());
        assert!(check_quote(hay, "7", 1).is_ok());
        assert!(check_quote(hay, "ok\nthe build is green now", 1).is_ok());
        assert_eq!(check_quote(hay, "o", 1), Err(QuoteError::TooShort));
        assert_eq!(check_quote(hay, "zzz", 1), Err(QuoteError::NotFound));
        // A whole line with indentation is a whole line only when the indentation is quoted too.
        assert_eq!(check_quote("  ab\n", "ab", 1), Err(QuoteError::TooShort));
        assert!(check_quote("  ab\n", "  ab  ", 1).is_ok());
    }

    #[test]
    fn a_numbered_short_quote_is_tried_after_the_literal_one_is_too_short() {
        // "3: ok" occurs literally inside line 4, as a fragment; it is also line 3 with its number.
        let hay = "first\nsecond\nok\nsee 3: ok and 5: ok today\n";
        assert_eq!(check_quote(hay, "3: ok", 1), Ok("ok".to_string()));
        assert_eq!(check_quote(hay, "3\tok", 1), Ok("ok".to_string()));
        // Number 5 is not where a line "ok" is: both readings fail, and the answer is still "too short".
        assert_eq!(check_quote(hay, "5: ok", 1), Err(QuoteError::TooShort));
    }

    #[test]
    fn quote_negatives() {
        let hay = "Hello World\n  let  x = 1;\nfoo(a, b)\n";
        assert!(!quote_matches(hay, ""));
        assert!(!quote_matches(hay, "  \n\t\n"));
        assert!(!quote_matches(hay, "hello world"));
        assert!(!quote_matches(hay, "let x = 1;"));
        assert!(!quote_matches(hay, "foo(a,b)"));
        assert!(!quote_matches(hay, "Hello World\nfoo(a, b)"));
        // Prefix stripping only applies when every line carries a prefix, numbers increasing.
        assert!(!quote_matches("alpha\nbeta\n", "1: alpha\nbeta"));
        assert!(!quote_matches("alpha\nbeta\n", "2: alpha\n1: beta"));
        // The stripped text must still be literally present.
        assert!(!quote_matches("alpha\n", "1: alphabet"));
        // A bare prefix is not a quote.
        assert!(!quote_matches("x\n", "3:"));
        // Prefix text that is in the haystack literally is matched literally.
        assert!(quote_matches("12: note\n", "12: note"));
    }

    #[test]
    fn nearest_line_reports_longest_shared_prefix() {
        let hay = "fn other() {}\nfn parse_config(path: &Path) {}\nfn parse_cfg() {}\n";
        let n = nearest_line(hay, "\n  \nfn parse_config(path: &str) {}").unwrap_or_default();
        assert_eq!(n, (2, "fn parse_config(path: &Path) {}".to_string()));
        assert_eq!(nearest_line(hay, "zzz"), None);
        assert_eq!(nearest_line(hay, "fn x"), None);
        assert_eq!(nearest_line(hay, "   "), None);
        let n = nearest_line(hay, "2: fn parse_config(path: &str) {}").unwrap_or_default();
        assert_eq!(n.0, 2);
    }
}
