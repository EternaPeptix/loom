//! Admission: what the model is shown of a tool output.
//!
//! CONTRACT.
//!
//! The caller stores the complete output first (`BlobStore`), then calls [`admit`] to build the text
//! of the `tool` message. Nothing here discards anything; the stored output is always complete.
//!
//! ## `normalize(raw)`
//! Turns raw bytes into the text that is stored and shown. Every step keeps the number of `\n`
//! unchanged, so line numbers are the same before and after:
//! - invalid UTF-8 → U+FFFD (counted in `invalid_utf8`, one per replacement character);
//! - ANSI/VT escape sequences (CSI `ESC [ … final`, OSC `ESC ] … BEL|ESC \`, two-byte `ESC x`) removed
//!   (`ansi_removed` = number of sequences);
//! - within a line, text before the last `\r` that is not at the end of the line is removed, and a
//!   trailing `\r` is removed (`cr_collapsed` = number of lines changed by the first rule);
//! - remaining C0 control characters other than `\t` and `\n`, and DEL, are written as `\xNN`
//!   (`controls_escaped`).
//! - `binary` is true when the input contains a NUL byte or more than 30% of the first 8 KiB is
//!   neither printable ASCII, whitespace, nor part of valid UTF-8. For binary input `text` is a
//!   one-line description: `binary data, {n} bytes, starts with {first 32 bytes as hex}`.
//!   `changed` is true when `text` differs from the input bytes.
//!
//! ## The envelope
//! `admit` returns `{header}\n{body}\n{footer}`:
//! - header: `[{tool} · {facts joined by " · "} · {lines} lines · {handle}]`; when the body is a cut the
//!   segment ` · CUT` follows the line count; when `normalized` notes exist they follow as
//!   ` · {notes}` (see `Normalized::notes`). With no facts the facts segment is omitted.
//! - body: see below. An output with zero bytes has the body `(no output)`.
//! - footer: `[end of {tool} output · {outcome}]` where `{outcome}` is `facts.outcome`.
//!   `facts.outcome` is also the first fact in the header (the caller passes it separately so that it
//!   appears both first and last).
//!
//! ## Body
//! Let `est` be the estimated tokens of the whole stored text.
//! - `est <= policy.max_inline_tokens`: the stored text, unmodified, without a trailing newline.
//!   `shown = [(1, lines)]` (empty for zero lines), `cut = false`.
//! - otherwise (`cut = true`): lines `1..=head_lines`, then the cut marker, then the last
//!   `tail_lines` lines. If `head_lines + tail_lines >= lines` the whole text would be shown, so the
//!   head and tail are both halved until the body fits `max_inline_tokens` (minimum 1 line each).
//!   In a cut body, a line longer than `max_line_chars` is shown as its first `max_line_chars`
//!   characters followed by `…[+{n} chars]` (`long_lines_cut` counts them). The marker is:
//!
//!   ```text
//!   [cut by harness: lines {a}-{b} of {total} are not shown here ({omitted_bytes} bytes). Nothing was discarded.
//!    Read them with out_read("{handle}", start, end) or search with out_grep("{handle}", pattern).]
//!   ```
//!
//!   followed, when the omitted region contains lines matching `policy.salient_patterns`, by:
//!
//!   ```text
//!   [pattern scan of the lines not shown — {k} of {m} matching lines, by line number; this is a text match, not a reading:]
//!   {line_no}: {line}
//!   …
//!   ```
//!
//!   with at most `policy.salient_max` lines, spread evenly over the matches when there are more
//!   (always including the first and the last match), each cut at `max_line_chars` like other lines.
//!   Lines listed by the scan count as shown: each adds `(n, n)` to `shown`.
//! - `shown` is sorted, merged, 1-based inclusive.
//! - Numbers in markers are plain digits (no thousands separators).
//!
//! `policy.salient_patterns` are regexes matched case-insensitively against single lines. An invalid
//! pattern is skipped (never an error). The defaults are in `AdmitPolicy::default`.
//!
//! Tests required: normalize (each rule, line-count preservation on random-ish inputs, binary); whole
//! admission is byte-identical to the stored text; envelope shape incl. empty output; cut boundaries
//! (exact line numbers in marker and `shown`); tiny head/tail when lines are huge; long-line cut;
//! scan lines present, capped, evenly spread, and included in `shown`; invalid pattern ignored;
//! multi-byte text never split inside a character.

use crate::blob::{BlobRef, BlobStore};
use crate::estimate::TokenEstimator;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdmitPolicy {
    /// Outputs estimated at or below this many tokens are shown whole.
    pub max_inline_tokens: u64,
    pub head_lines: u64,
    pub tail_lines: u64,
    /// Longest line shown inside a cut body.
    pub max_line_chars: usize,
    /// Most lines listed by the pattern scan of the omitted region.
    pub salient_max: usize,
    pub salient_patterns: Vec<String>,
}

impl Default for AdmitPolicy {
    fn default() -> Self {
        Self {
            max_inline_tokens: 60_000,
            head_lines: 400,
            tail_lines: 400,
            max_line_chars: 4_000,
            salient_max: 40,
            salient_patterns: vec![
                r"\b(error|errors|failed|failure|fatal|panic|panicked|exception|traceback|denied|refused|forbidden|unauthorized|timed? ?out|segfault|abort(ed)?|cannot|unable to|not found|no such)\b".to_string(),
                r"\bwarn(ing)?\b".to_string(),
                r"^HTTP/\d(\.\d)? \d{3}\b".to_string(),
                r"\bexit(ed)? (code|status) [1-9]".to_string(),
            ],
        }
    }
}

/// Result of [`normalize`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Normalized {
    pub text: String,
    pub binary: bool,
    pub changed: bool,
    pub invalid_utf8: u64,
    pub ansi_removed: u64,
    pub cr_collapsed: u64,
    pub controls_escaped: u64,
}

impl Normalized {
    /// Header notes for the non-zero counts, joined by `, `:
    /// `{n} terminal escape sequences removed`, `{n} overwritten lines collapsed`,
    /// `{n} invalid bytes replaced`, `{n} control characters escaped`, `binary`. `None` when clean.
    pub fn notes(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        if self.ansi_removed > 0 {
            parts.push(format!("{} terminal escape sequences removed", self.ansi_removed));
        }
        if self.cr_collapsed > 0 {
            parts.push(format!("{} overwritten lines collapsed", self.cr_collapsed));
        }
        if self.invalid_utf8 > 0 {
            parts.push(format!("{} invalid bytes replaced", self.invalid_utf8));
        }
        if self.controls_escaped > 0 {
            parts.push(format!("{} control characters escaped", self.controls_escaped));
        }
        if self.binary {
            parts.push("binary".to_string());
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    }
}

/// Decode UTF-8, replacing each invalid sequence with one U+FFFD. Returns the text and the number
/// of replacements made.
fn decode_utf8(raw: &[u8]) -> (String, u64) {
    let mut out = String::with_capacity(raw.len());
    let mut invalid = 0u64;
    let mut rest = raw;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                out.push_str(&String::from_utf8_lossy(rest.get(..valid).unwrap_or(&[])));
                out.push('\u{FFFD}');
                invalid += 1;
                let skip = e.error_len().unwrap_or_else(|| rest.len().saturating_sub(valid)).max(1);
                rest = rest.get(valid.saturating_add(skip)..).unwrap_or(&[]);
            }
        }
    }
    (out, invalid)
}

/// Count characters that are ASCII but neither printable, whitespace nor ESC.
fn count_ascii_bad(s: &str) -> usize {
    s.chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_graphic() && !c.is_ascii_whitespace() && *c != ' ' && *c != '\u{1b}')
        .count()
}

/// True when the input is binary: it has a NUL byte, or more than 30% of its first 8 KiB is neither
/// printable ASCII, whitespace nor part of valid UTF-8. ESC is not counted against the input: escape
/// sequences are text that normalisation removes.
fn looks_binary(raw: &[u8]) -> bool {
    if raw.contains(&0) {
        return true;
    }
    let head = raw.get(..raw.len().min(8192)).unwrap_or(raw);
    let mut bad = 0usize;
    let mut rest = head;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                bad = bad.saturating_add(count_ascii_bad(s));
                break;
            }
            Err(e) => {
                let valid = e.valid_up_to();
                bad = bad.saturating_add(count_ascii_bad(&String::from_utf8_lossy(rest.get(..valid).unwrap_or(&[]))));
                match e.error_len() {
                    Some(n) => {
                        bad = bad.saturating_add(n);
                        rest = rest.get(valid.saturating_add(n)..).unwrap_or(&[]);
                    }
                    // A character cut off by the 8 KiB window is not evidence of binary data.
                    None => break,
                }
            }
        }
    }
    bad.saturating_mul(10) > head.len().saturating_mul(3)
}

/// Remove escape sequences. A newline is never part of a sequence: it ends an unfinished one and is
/// kept, so the number of lines does not change. Returns the text and the sequences removed.
fn strip_ansi(text: &str) -> (String, u64) {
    let cs: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut removed = 0u64;
    let mut i = 0usize;
    while let Some(&c) = cs.get(i) {
        i += 1;
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        removed += 1;
        match cs.get(i) {
            None | Some('\n') => {}
            Some('[') => {
                i += 1;
                while let Some(&d) = cs.get(i) {
                    if ('\u{20}'..='\u{3f}').contains(&d) {
                        i += 1;
                    } else {
                        if ('\u{40}'..='\u{7e}').contains(&d) {
                            i += 1;
                        }
                        break;
                    }
                }
            }
            Some(']') => {
                i += 1;
                while let Some(&d) = cs.get(i) {
                    match d {
                        '\u{7}' => {
                            i += 1;
                            break;
                        }
                        '\u{1b}' => {
                            if cs.get(i + 1) == Some(&'\\') {
                                i += 2;
                            }
                            break;
                        }
                        '\n' => break,
                        _ => i += 1,
                    }
                }
            }
            Some(&d) if ('\u{20}'..='\u{2f}').contains(&d) => {
                while cs.get(i).is_some_and(|x| ('\u{20}'..='\u{2f}').contains(x)) {
                    i += 1;
                }
                if cs.get(i).is_some_and(|x| ('\u{30}'..='\u{7e}').contains(x)) {
                    i += 1;
                }
            }
            Some(_) => i += 1,
        }
    }
    (out, removed)
}

/// See the module contract.
pub fn normalize(raw: &[u8]) -> Normalized {
    if looks_binary(raw) {
        let hex: String = raw.iter().take(32).map(|b| format!("{b:02x}")).collect();
        let text = format!("binary data, {} bytes, starts with {}", raw.len(), hex);
        return Normalized {
            changed: text.as_bytes() != raw,
            text,
            binary: true,
            invalid_utf8: 0,
            ansi_removed: 0,
            cr_collapsed: 0,
            controls_escaped: 0,
        };
    }
    let (decoded, invalid_utf8) = decode_utf8(raw);
    let (stripped, ansi_removed) = strip_ansi(&decoded);
    let mut cr_collapsed = 0u64;
    let mut controls_escaped = 0u64;
    let mut text = String::with_capacity(stripped.len());
    for (n, line) in stripped.split('\n').enumerate() {
        if n > 0 {
            text.push('\n');
        }
        let mut l = line.trim_end_matches('\r');
        if let Some(p) = l.rfind('\r') {
            l = l.get(p + 1..).unwrap_or("");
            cr_collapsed += 1;
        }
        for ch in l.chars() {
            if (ch < ' ' && ch != '\t') || ch == '\u{7f}' {
                text.push_str(&format!("\\x{:02x}", ch as u32));
                controls_escaped += 1;
            } else {
                text.push(ch);
            }
        }
    }
    let changed = text.as_bytes() != raw;
    Normalized { text, binary: false, changed, invalid_utf8, ansi_removed, cr_collapsed, controls_escaped }
}

/// Facts for the envelope, supplied by whoever ran the tool.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Tool name.
    pub tool: String,
    /// The outcome in a few words: `exit 0`, `exit 1`, `killed by signal 9`, `ok`, `error`,
    /// `timed out after 300s — continues as job j3`, `denied`. Shown first in the header and in the footer.
    pub outcome: String,
    /// Further header facts in order, e.g. `3.4s`, `lines 1-200 of 950`, a path.
    pub more: Vec<String>,
    /// From [`Normalized::notes`], when normalisation changed the output.
    pub notes: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The complete text of the `tool` message.
    pub text: String,
    pub cut: bool,
    /// Line ranges of the stored output present in `text` (1-based, inclusive, sorted, merged).
    pub shown: Vec<(u64, u64)>,
    pub long_lines_cut: u64,
    /// Lines listed by the pattern scan, and how many lines matched in total.
    pub scan_listed: u64,
    pub scan_matched: u64,
}

/// Build the tool message text for the stored output `blob`. See the module contract.
pub fn admit(
    store: &BlobStore,
    blob: &BlobRef,
    facts: &Facts,
    policy: &AdmitPolicy,
    estimator: &TokenEstimator,
) -> io::Result<Admitted> {
    let bytes = store.read_all(&blob.id)?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let handle = blob.handle();
    let lines = split_lines(&text);
    let n = lines.len();
    let est = estimator.tokens(text.chars().count());

    let mut cut = false;
    let mut shown: Vec<(u64, u64)> = Vec::new();
    let mut long_lines_cut = 0u64;
    let mut scan_listed = 0u64;
    let mut scan_matched = 0u64;
    let body: String;

    if text.is_empty() {
        body = "(no output)".to_string();
    } else if est <= policy.max_inline_tokens {
        body = text.strip_suffix('\n').unwrap_or(&text).to_string();
        shown.push((1, n as u64));
    } else {
        cut = true;
        let mut starts = Vec::with_capacity(n + 1);
        let mut at = 0usize;
        for l in &lines {
            starts.push(at);
            at = at.saturating_add(l.len() + 1).min(text.len());
        }
        starts.push(text.len());
        let regexes: Vec<Regex> = policy
            .salient_patterns
            .iter()
            .filter_map(|p| RegexBuilder::new(p).case_insensitive(true).build().ok())
            .collect();
        let matching: Vec<usize> = if regexes.is_empty() || policy.salient_max == 0 {
            Vec::new()
        } else {
            lines.iter().enumerate().filter(|(_, l)| regexes.iter().any(|r| r.is_match(l))).map(|(i, _)| i).collect()
        };
        let inp =
            CutInput { text: &text, lines: &lines, starts: &starts, matching: &matching, handle: &handle, policy };
        let mut head = usize::try_from(policy.head_lines).unwrap_or(usize::MAX);
        let mut tail = usize::try_from(policy.tail_lines).unwrap_or(usize::MAX);
        // Halve head and tail until something is omitted and the body fits (never below one line each).
        let r = loop {
            let r = render_cut(&inp, head, tail);
            let omission = head.saturating_add(tail) < n;
            let fits = estimator.tokens(r.body.chars().count()) <= policy.max_inline_tokens;
            if (omission && fits) || (head <= 1 && tail <= 1) {
                break r;
            }
            head = halve(head);
            tail = halve(tail);
        };
        let head_c = head.min(n);
        let tail_c = tail.min(n - head_c);
        scan_matched = matching.iter().filter(|i| **i >= head_c && **i < n - tail_c).count() as u64;
        scan_listed = r.scan_listed;
        long_lines_cut = r.long_lines_cut;
        shown = merge_ranges(r.shown);
        body = r.body;
    }

    let mut head_parts = vec![facts.tool.clone()];
    head_parts.extend(header_facts(facts));
    let mut count = format!("{n} lines");
    if cut {
        count.push_str(" · CUT");
    }
    if let Some(notes) = &facts.notes {
        count.push_str(" · ");
        count.push_str(notes);
    }
    head_parts.push(count);
    head_parts.push(handle);
    let header = format!("[{}]", head_parts.join(" · "));
    let text = format!("{header}\n{body}\n{}", footer(facts));
    Ok(Admitted { text, cut, shown, long_lines_cut, scan_listed, scan_matched })
}

fn header_facts(facts: &Facts) -> Vec<String> {
    let mut v = Vec::new();
    if !facts.outcome.is_empty() {
        v.push(facts.outcome.clone());
    }
    v.extend(facts.more.iter().filter(|m| !m.is_empty()).cloned());
    v
}

fn footer(facts: &Facts) -> String {
    format!("[end of {} output · {}]", facts.tool, facts.outcome)
}

/// Split stored text into lines the way the blob store counts them: a final newline ends the last
/// line instead of starting another one.
fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    text.strip_suffix('\n').unwrap_or(text).split('\n').collect()
}

/// `line` cut to `max` characters with a marker saying how many were left out; `None` when it fits.
fn cut_line(line: &str, max: usize) -> Option<String> {
    let (idx, _) = line.char_indices().nth(max)?;
    let kept = line.get(..idx).unwrap_or(line);
    let rest = line.get(idx..).map_or(0, |r| r.chars().count());
    Some(format!("{kept}…[+{rest} chars]"))
}

struct Rendered {
    body: String,
    /// Zero-based indexes of the lines present in full (lines cut at `max_line_chars` are not).
    shown: Vec<usize>,
    long_lines_cut: u64,
    scan_listed: u64,
}

struct CutInput<'a> {
    text: &'a str,
    lines: &'a [&'a str],
    /// Byte offset of each line start, plus the text length at the end.
    starts: &'a [usize],
    /// Zero-based indexes of lines matching the salient patterns.
    matching: &'a [usize],
    handle: &'a str,
    policy: &'a AdmitPolicy,
}

fn halve(x: usize) -> usize {
    (x / 2).max(1).min(x)
}

fn render_cut(inp: &CutInput<'_>, head: usize, tail: usize) -> Rendered {
    let n = inp.lines.len();
    let max = inp.policy.max_line_chars;
    let head = head.min(n);
    let tail = tail.min(n - head);
    let mut out: Vec<String> = Vec::new();
    let mut shown = Vec::new();
    let mut long_cut = 0u64;
    let mut listed = 0u64;
    let push_line =
        |out: &mut Vec<String>, shown: &mut Vec<usize>, long_cut: &mut u64, idx: usize, prefix: Option<usize>| {
            let line = inp.lines.get(idx).copied().unwrap_or("");
            let (text, was_cut) = match cut_line(line, max) {
                Some(c) => (c, true),
                None => (line.to_string(), false),
            };
            if was_cut {
                *long_cut += 1;
            } else {
                shown.push(idx);
            }
            out.push(match prefix {
                Some(no) => format!("{no}: {text}"),
                None => text,
            });
        };
    for idx in 0..head {
        push_line(&mut out, &mut shown, &mut long_cut, idx, None);
    }
    let first_omitted = head;
    let end_omitted = n - tail;
    if first_omitted < end_omitted {
        let at = |i: usize| inp.starts.get(i).copied().unwrap_or(inp.text.len());
        let omitted_bytes = at(end_omitted).saturating_sub(at(first_omitted));
        out.push(format!(
            "[cut by harness: lines {}-{} of {} are not shown here ({} bytes). Nothing was discarded.\n Read them with out_read(\"{h}\", start, end) or search with out_grep(\"{h}\", pattern).]",
            first_omitted + 1,
            end_omitted,
            n,
            omitted_bytes,
            h = inp.handle
        ));
        let hits: Vec<usize> =
            inp.matching.iter().copied().filter(|i| *i >= first_omitted && *i < end_omitted).collect();
        let m = hits.len();
        let k = m.min(inp.policy.salient_max);
        if k > 0 {
            out.push(format!("[pattern scan of the lines not shown — {k} of {m} matching lines, by line number; this is a text match, not a reading:]"));
            for j in 0..k {
                // Evenly spread over the matches, first and last included.
                let pick = if k == 1 { 0 } else { ((j as u128 * (m as u128 - 1)) / (k as u128 - 1)) as usize };
                if let Some(&idx) = hits.get(pick) {
                    push_line(&mut out, &mut shown, &mut long_cut, idx, Some(idx + 1));
                    listed += 1;
                }
            }
        }
    }
    for idx in end_omitted..n {
        push_line(&mut out, &mut shown, &mut long_cut, idx, None);
    }
    Rendered { body: out.join("\n"), shown, long_lines_cut: long_cut, scan_listed: listed }
}

fn merge_ranges(mut idx: Vec<usize>) -> Vec<(u64, u64)> {
    idx.sort_unstable();
    idx.dedup();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for i in idx {
        let no = i as u64 + 1;
        match out.last_mut() {
            Some(last) if last.1 + 1 == no => last.1 = no,
            _ => out.push((no, no)),
        }
    }
    out
}

/// Envelope for a result that has no stored output (validation failures, denials, runtime-owned
/// tools): `[{tool} · {outcome}{ · more…}]\n{body}\n[end of {tool} output · {outcome}]`.
pub fn envelope_plain(facts: &Facts, body: &str) -> String {
    let mut parts = vec![facts.tool.clone()];
    parts.extend(header_facts(facts));
    format!("[{}]\n{body}\n{}", parts.join(" · "), footer(facts))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path().join("blobs")).unwrap();
        (dir, store)
    }

    fn facts() -> Facts {
        Facts { tool: "bash".into(), outcome: "exit 1".into(), more: vec!["2.4s".into()], notes: None }
    }

    fn admit_text(text: &str, policy: &AdmitPolicy) -> (Admitted, BlobRef) {
        let (_d, s) = store();
        let b = s.put_bytes(text.as_bytes()).unwrap();
        let a = admit(&s, &b, &facts(), policy, &TokenEstimator::with_ratio(1.5)).unwrap();
        (a, b)
    }

    fn numbered(n: usize) -> String {
        (1..=n).map(|i| format!("line {i}\n")).collect()
    }

    fn small_policy(head: u64, tail: u64) -> AdmitPolicy {
        AdmitPolicy {
            max_inline_tokens: 1000,
            head_lines: head,
            tail_lines: tail,
            salient_patterns: vec![],
            ..AdmitPolicy::default()
        }
    }

    fn newlines(s: &str) -> usize {
        s.matches('\n').count()
    }

    #[test]
    fn notes_list_non_zero_counts() {
        assert_eq!(normalize(b"clean\n").notes(), None);
        let n = Normalized {
            text: String::new(),
            binary: true,
            changed: true,
            invalid_utf8: 2,
            ansi_removed: 1,
            cr_collapsed: 3,
            controls_escaped: 4,
        };
        assert_eq!(
            n.notes().unwrap(),
            "1 terminal escape sequences removed, 3 overwritten lines collapsed, 2 invalid bytes replaced, 4 control characters escaped, binary"
        );
    }

    #[test]
    fn plain_text_is_unchanged() {
        let n = normalize("héllo\tworld\nsecond\n".as_bytes());
        assert_eq!(n.text, "héllo\tworld\nsecond\n");
        assert!(!n.changed && !n.binary);
    }

    #[test]
    fn invalid_utf8_is_replaced_one_per_sequence() {
        let pad = "plain text padding. ".repeat(10);
        let mut raw = pad.clone().into_bytes();
        raw.extend_from_slice(b"a\xffb\xc3\n");
        let n = normalize(&raw);
        assert_eq!(n.text, format!("{pad}a\u{FFFD}b\u{FFFD}\n"));
        assert_eq!(n.invalid_utf8, 2);
        assert!(n.changed);
    }

    #[test]
    fn ansi_sequences_are_removed() {
        let n = normalize(b"\x1b[31mred\x1b[0m \x1b]0;title\x07ok \x1b]8;;http://x\x1b\\link\x1bc!\n");
        assert_eq!(n.text, "red ok link!\n");
        assert_eq!(n.ansi_removed, 5);
    }

    #[test]
    fn escape_never_swallows_a_newline() {
        let n = normalize(b"a\x1b]0;unfinished\nb\x1b[1;\nc\x1b");
        assert_eq!(n.text, "a\nb\nc");
        assert_eq!(n.ansi_removed, 3);
    }

    #[test]
    fn carriage_returns() {
        let n = normalize(b"10%\r50%\r100%\nwin\r\nlone\r");
        assert_eq!(n.text, "100%\nwin\nlone");
        assert_eq!(n.cr_collapsed, 1);
        let n = normalize(b"a\rb\r\r\n");
        assert_eq!(n.text, "b\n");
    }

    #[test]
    fn controls_are_escaped() {
        let pad = "plain text padding. ".repeat(10);
        let mut raw = pad.clone().into_bytes();
        raw.extend_from_slice(b"a\x01b\x7fc\x08\td\n");
        let n = normalize(&raw);
        assert_eq!(n.text, format!("{pad}a\\x01b\\x7fc\\x08\td\n"));
        assert_eq!(n.controls_escaped, 3);
    }

    #[test]
    fn binary_is_described() {
        let n = normalize(b"ab\x00cd");
        assert!(n.binary && n.changed);
        assert_eq!(n.text, "binary data, 5 bytes, starts with 6162006364");
        let many_invalid: Vec<u8> = (0..100).map(|i| if i % 2 == 0 { 0xff } else { b'a' }).collect();
        assert!(normalize(&many_invalid).binary);
        let few_invalid: Vec<u8> = (0..100).map(|i| if i % 10 == 0 { 0xff } else { b'a' }).collect();
        assert!(!normalize(&few_invalid).binary);
        // Colour-heavy terminal output is text.
        assert!(!normalize(b"\x1b[1m\x1b[2m\x1b[3m\x1b[4m\x1b[5mx\n").binary);
        assert!(!normalize("日本語のテキスト\n".as_bytes()).binary);
        assert!(!normalize(b"").binary);
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> usize {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) as usize
        }
    }

    #[test]
    fn line_count_is_preserved_on_generated_inputs() {
        let pieces: [&[u8]; 22] = [
            b"abc",
            b" ",
            b"\n",
            b"\n",
            b"\r",
            b"\r\n",
            b"\x1b",
            b"\x1b[",
            b"\x1b[31m",
            b"\x1b]0;t",
            b"\x07",
            b"\x1b\\",
            b"\xff",
            b"\xc3",
            b"\xe2\x82",
            "é".as_bytes(),
            "日".as_bytes(),
            b"\x01",
            b"\x7f",
            b"\t",
            b";",
            b"\x1b[1;",
        ];
        let mut rng = Lcg(42);
        let mut checked = 0;
        for _ in 0..600 {
            // Plain padding keeps these inputs below the binary threshold.
            let mut input = b"padding padding padding padding padding padding padding padding\n".repeat(2);
            for _ in 0..(rng.next() % 40) {
                input.extend_from_slice(pieces[rng.next() % pieces.len()]);
            }
            let n = normalize(&input);
            assert!(!n.binary, "no NUL and few invalid bytes: {input:?}");
            let before = input.iter().filter(|b| **b == b'\n').count();
            assert_eq!(newlines(&n.text), before, "input {input:?} became {:?}", n.text);
            assert_eq!(n.changed, n.text.as_bytes() != input.as_slice());
            checked += 1;
        }
        assert_eq!(checked, 600);
        for tail in [&b"x\x1b"[..], b"x\x1b[", b"x\x1b]abc", b"\r", b"\xe2\x82", b"a\n\x1b[3"] {
            let mut padded = b"padding padding padding padding padding padding\n".repeat(2);
            padded.extend_from_slice(tail);
            let tail = padded.as_slice();
            let n = normalize(tail);
            assert!(!n.binary);
            assert_eq!(newlines(&n.text), tail.iter().filter(|b| **b == b'\n').count());
        }
    }

    #[test]
    fn uncut_admission_is_the_stored_text() {
        let stored = "alpha\n\nbeta ünï\ntail with no newline";
        let (a, b) = admit_text(stored, &AdmitPolicy::default());
        assert!(!a.cut);
        assert_eq!(a.shown, vec![(1, 4)]);
        let header = format!("[bash · exit 1 · 2.4s · 4 lines · {}]\n", b.handle());
        assert_eq!(a.text, format!("{header}{stored}\n[end of bash output · exit 1]"));
        // A trailing newline in the stored text is the only thing dropped.
        let (a, _) = admit_text("one\ntwo\n\n", &AdmitPolicy::default());
        assert!(a.text.contains("\none\ntwo\n\n[end of bash"));
        assert_eq!(a.shown, vec![(1, 3)]);
    }

    #[test]
    fn empty_output_and_envelope_shape() {
        let (a, b) = admit_text("", &AdmitPolicy::default());
        assert_eq!(
            a.text,
            format!("[bash · exit 1 · 2.4s · 0 lines · {}]\n(no output)\n[end of bash output · exit 1]", b.handle())
        );
        assert!(a.shown.is_empty() && !a.cut);
        let (_d, s) = store();
        let b = s.put_bytes(b"x\n").unwrap();
        let mut f = Facts { tool: "grep".into(), ..Facts::default() };
        f.notes = Some("1 invalid bytes replaced".into());
        let a = admit(&s, &b, &f, &AdmitPolicy::default(), &TokenEstimator::default()).unwrap();
        assert_eq!(
            a.text,
            format!("[grep · 1 lines · 1 invalid bytes replaced · {}]\nx\n[end of grep output · ]", b.handle())
        );
        let p = envelope_plain(&facts(), "bad arguments: pass a path.");
        assert_eq!(p, "[bash · exit 1 · 2.4s]\nbad arguments: pass a path.\n[end of bash output · exit 1]");
    }

    #[test]
    fn cut_boundaries_are_exact() {
        let text = numbered(1000);
        let (a, b) = admit_text(&text, &small_policy(3, 2));
        assert!(a.cut);
        assert_eq!(a.shown, vec![(1, 3), (999, 1000)]);
        let omitted: usize = text.lines().skip(3).take(995).map(|l| l.len() + 1).sum();
        let expect_body = format!(
            "line 1\nline 2\nline 3\n[cut by harness: lines 4-998 of 1000 are not shown here ({omitted} bytes). Nothing was discarded.\n Read them with out_read(\"{h}\", start, end) or search with out_grep(\"{h}\", pattern).]\nline 999\nline 1000",
            h = b.handle()
        );
        let header = format!("[bash · exit 1 · 2.4s · 1000 lines · CUT · {}]\n", b.handle());
        assert_eq!(a.text, format!("{header}{expect_body}\n[end of bash output · exit 1]"));
        assert_eq!((a.scan_listed, a.scan_matched, a.long_lines_cut), (0, 0, 0));
    }

    #[test]
    fn head_and_tail_halve_when_they_would_cover_everything() {
        // 40 lines of 10 chars: over the budget, and 30 + 30 covers all of it.
        let text: String = (0..40).map(|i| format!("row {i:05}\n")).collect();
        let policy = AdmitPolicy {
            max_inline_tokens: 100,
            head_lines: 30,
            tail_lines: 30,
            salient_patterns: vec![],
            ..AdmitPolicy::default()
        };
        let (a, _) = admit_text(&text, &policy);
        assert!(a.cut);
        // 30/30 -> 15/15 fits 100 tokens (150 chars) with marker? 30 lines * 10 > 150 chars, so it halves again.
        let marker_at = a.text.find("[cut by harness: lines ").unwrap();
        let rest = &a.text[marker_at + "[cut by harness: lines ".len()..];
        let (range, _) = rest.split_once(" of 40").unwrap();
        let (from, to) = range.split_once('-').unwrap();
        let (from, to): (u64, u64) = (from.parse().unwrap(), to.parse().unwrap());
        assert!(from >= 2 && to <= 39 && from <= to);
        assert_eq!(a.shown, vec![(1, from - 1), (to + 1, 40)]);
    }

    #[test]
    fn huge_lines_leave_one_line_each_side() {
        let long = "x".repeat(3000);
        let text: String = (0..10).map(|_| format!("{long}\n")).collect();
        let policy = AdmitPolicy {
            max_inline_tokens: 100,
            head_lines: 4,
            tail_lines: 4,
            max_line_chars: 50,
            salient_patterns: vec![],
            ..AdmitPolicy::default()
        };
        let (a, _) = admit_text(&text, &policy);
        assert!(a.cut);
        assert!(a.text.contains("lines 2-9 of 10"));
        assert!(a.text.contains("…[+2950 chars]"));
        assert_eq!(a.long_lines_cut, 2);
        // Cut lines are only partly shown, so they are not reported as shown.
        assert!(a.shown.is_empty());
    }

    #[test]
    fn long_lines_are_cut_only_in_a_cut_body() {
        let mut text = "é".repeat(60);
        text.push('\n');
        text.push_str(&numbered(500));
        let policy = AdmitPolicy {
            max_inline_tokens: 1000,
            head_lines: 2,
            tail_lines: 2,
            max_line_chars: 10,
            salient_patterns: vec![],
            ..AdmitPolicy::default()
        };
        let (a, _) = admit_text(&text, &policy);
        assert!(a.text.contains(&format!("\n{}…[+50 chars]\n", "é".repeat(10))));
        assert_eq!(a.long_lines_cut, 1);
        assert_eq!(a.shown, vec![(2, 2), (500, 501)]);
        let (a, _) = admit_text(
            &text[..200],
            &AdmitPolicy { max_inline_tokens: 1000, max_line_chars: 10, ..AdmitPolicy::default() },
        );
        assert!(!a.cut && a.text.contains(&"é".repeat(60)));
    }

    fn scan_policy(max: usize) -> AdmitPolicy {
        AdmitPolicy {
            max_inline_tokens: 1000,
            head_lines: 2,
            tail_lines: 2,
            salient_max: max,
            salient_patterns: vec!["BOOM".into(), "(unclosed".into()],
            ..AdmitPolicy::default()
        }
    }

    fn scan_text() -> String {
        (1..=300)
            .map(|i| if i % 10 == 0 && i != 300 { format!("Boom at {i}\n") } else { format!("line {i}\n") })
            .collect()
    }

    #[test]
    fn scan_lists_matches_in_the_omitted_region() {
        let (a, _) = admit_text(&scan_text(), &scan_policy(40));
        // Matches are lines 10..=290 step 10: 29 of them, all listed.
        assert!(a.text.contains("[pattern scan of the lines not shown — 29 of 29 matching lines, by line number; this is a text match, not a reading:]\n10: Boom at 10\n20: Boom at 20\n"));
        assert!(a.text.contains("\n290: Boom at 290\nline 299\nline 300\n[end"));
        assert_eq!((a.scan_listed, a.scan_matched), (29, 29));
        assert!(a.shown.contains(&(10, 10)) && a.shown.contains(&(290, 290)));
        assert_eq!(a.shown.len(), 2 + 29);
    }

    #[test]
    fn scan_is_capped_and_evenly_spread() {
        let (a, _) = admit_text(&scan_text(), &scan_policy(5));
        assert!(a.text.contains("5 of 29 matching lines"));
        let listed: Vec<u64> = a
            .text
            .lines()
            .filter(|l| l.contains(": Boom at"))
            .map(|l| l.split(':').next().unwrap().parse().unwrap())
            .collect();
        // Indexes 0, 7, 14, 21, 28 of the 29 matches.
        assert_eq!(listed, vec![10, 80, 150, 220, 290]);
        assert_eq!((a.scan_listed, a.scan_matched), (5, 29));
        let (a, _) = admit_text(&scan_text(), &scan_policy(1));
        assert!(a.text.contains("1 of 29") && a.text.contains("\n10: Boom at 10\n"));
        let (a, _) = admit_text(&scan_text(), &scan_policy(0));
        assert!(!a.text.contains("pattern scan"));
    }

    #[test]
    fn scan_ignores_shown_lines_and_invalid_patterns() {
        // The only matches are in the head and tail: nothing to scan.
        let mut text = String::from("boom first\n");
        text.push_str(&numbered(400));
        text.push_str("boom last\n");
        let (a, _) = admit_text(&text, &scan_policy(40));
        assert!(a.cut && !a.text.contains("pattern scan"));
        assert_eq!(a.scan_matched, 0);
        // The invalid pattern in scan_policy was skipped, the valid one still worked above; and the
        // default patterns are case-insensitive.
        let (a, _) = admit_text(
            &format!("a\nb\n{}ERROR: Failed to open\nz\ny\n", numbered(300)),
            &AdmitPolicy { max_inline_tokens: 1000, head_lines: 2, tail_lines: 2, ..AdmitPolicy::default() },
        );
        assert!(a.text.contains("1 of 1 matching lines"));
    }

    #[test]
    fn multibyte_text_is_never_split() {
        let text: String = (0..300).map(|i| format!("{i} 日本語日本語日本語日本語日本語\n")).collect();
        let policy = AdmitPolicy {
            max_inline_tokens: 1000,
            head_lines: 2,
            tail_lines: 2,
            max_line_chars: 7,
            salient_patterns: vec![],
            ..AdmitPolicy::default()
        };
        let (a, _) = admit_text(&text, &policy);
        assert!(a.cut);
        assert!(a.text.contains("0 日本語日本…[+"));
        assert!(a.text.contains("…[+"));
    }

    #[test]
    fn cut_bodies_fit_when_they_can() {
        let text = numbered(5000);
        let policy = AdmitPolicy {
            max_inline_tokens: 500,
            head_lines: 400,
            tail_lines: 400,
            salient_patterns: vec![],
            ..AdmitPolicy::default()
        };
        let (a, _) = admit_text(&text, &policy);
        assert!(a.cut);
        assert!(TokenEstimator::with_ratio(1.5).tokens(a.text.chars().count()) <= 500 + 60);
    }
}
