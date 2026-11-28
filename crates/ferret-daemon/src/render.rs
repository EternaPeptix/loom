//! Records and listings as terminal text. Pure functions: same input, same text.
//!
//! CONTRACT.
//!
//! ## Style
//! `Style{color, width}`. With `color` false the output contains no escape sequence at all. With
//! colour: dim = `\x1b[2m`, bold = `\x1b[1m`, red = `\x1b[31m`, yellow = `\x1b[33m`, green =
//! `\x1b[32m`, cyan = `\x1b[36m`, each closed with `\x1b[0m`. Text that comes from a record is
//! passed through [`clean`] first: escape (`\x1b`) and the other C0 controls except `\n` and `\t`
//! are replaced by `·`, so stored output can never drive the operator's terminal.
//!
//! ## `record(rec, style, opts)` — one record as text ending in a newline, or empty for kinds that
//! are not shown. `{…}` are fields; (dim) etc. apply with colour only.
//! - `session_start`: `● session {session} · {role} · {model.model} · {workspace}` (bold).
//! - `forked`: `● agent {session} · {role} · forked from {parent}` (bold), then the brief's
//!   question indented two spaces.
//! - `user_message`: `▌ you` (cyan), then the text.
//! - `harness_note`: `▌ harness · {note kind in snake case}` (dim), then the text (dim). A note
//!   authored by an agent says `▌ agent {id} · {kind}`.
//! - `model_response`: `▌ model · {tokens(prompt)} in ({pct}% cached) · {tokens(completion)} out ·
//!   {seconds(total_ms)}` (green; ` · attempt {n}` appended when `attempts > 1`; ` · cut off by the
//!   output limit` (yellow) when `finish` is `Length`). Then the reasoning: with
//!   `opts.reasoning`, the text (dim); otherwise, when not empty, `  (reasoning: {n} lines)` (dim).
//!   Then the text. Tool calls are not printed here (their `tool_call` records follow).
//! - `stored_action`: `∙ controller · {plan_id} node {node} · {tool} · callback
//!   {omitted_callback} omitted` (dim). Its ordinary tool records carry arguments and results;
//!   this is never rendered as a model inference or charged fabricated token usage.
//! - `tool_call`: `→ {name} {args}` where `args` is the compact JSON, cut to `3 * width`
//!   characters with `…` unless `opts.full`.
//! - `tool_result`: `← ` followed by the text. Lines after the first are indented two spaces. Only
//!   the first `opts.max_output_lines` lines are printed unless `opts.full`; then `  … {n} more
//!   lines` and, when the result has a stored output, ` — ferret out {handle}` (dim). The first line
//!   is red when the status is not `Ok`.
//! - `reweave`: `⟲ context re-woven ({reason}): {evictions} items folded out of view, about
//!   {tokens(before)} → {tokens(after)} tokens` (yellow; old logs).
//! - `compaction`: `⟲ context compacted ({reason}): {keys} outputs in the key table, about {tokens(before)} →
//!   {tokens(after)} tokens`, plus ` (no note)` when the note request failed (yellow).
//! - `pin` / `unpin`: `∙ pinned {call_id}: {reason}` / `∙ unpinned {call_id}` (dim).
//! - `child_spawned`: `⇢ agent {child} ({role}, {mode}): {brief.question}` (cyan).
//! - `child_settled`: `⇠ agent {child} {outcome word}` (cyan), then the report indented two spaces,
//!   cut like a tool result. An `inline` settlement prints only the first line.
//! - `job_registered`: `⚙ job {job_id}: {command}`; `job_settled`: `⚙ job {job_id} ended: {detail}`;
//!   `job_matched`: `⚙ job {job_id} wrote {matches} line(s) matching /{pattern}/`.
//! - `inbox_opened`: `✉ {kind}` + ` (waiting for you)` when blocking (bold yellow), the text, the
//!   options numbered `  1. …`, then `  answer: ferret answer {item_id} "…"` (dim) unless the kind is
//!   `Finished`. A scope request (see [`scope_request_hosts`]) is `✉ scope request`, the text, `  hosts: a, b`
//!   and `  approve: see ferret inbox` (dim); it has no answer line, since answering it grants nothing.
//! - `inbox_resolved`: `✉ answered: {answer}` (`✉ dismissed` for an empty answer).
//! - `ledger`: `▪ ledger #{n}: {summary}` (dim).
//! - `cache_break`: `! cache break at message {first_diff_message}: {detail}` (yellow).
//! - `model_switched`: `⇄ model {profile} ({model}, window {window}) → {…same for to} · {reason}` (cyan;
//!   a window of 0 reads `unknown`; no `· …` when the reason is empty).
//! - `interrupted`: `! interrupted: {reason}` (yellow).
//! - `turn_end`: `— turn ended: {reason in words} —` (dim): `yielded`, `finished`, `asked the
//!   operator`, `blocked`, `waiting for jobs or agents`, `stopped`, `parked for the operator`,
//!   `budget used up`, `error`.
//! - `session_end`: `● session ended: {outcome}` + `: {detail}` when not empty (bold).
//! - `turn_start`, `model_request`, `net`, unknown kinds: empty — except with `opts.verbose`, where
//!   `model_request` prints `… request {req_id} · step {step} · epoch {epoch} · about
//!   {tokens(est_tokens)} tokens` (dim).
//! - With `opts.verbose`, continuation authorship/stopping, deferred-output observation and the
//!   child's durable outbox receipt print a concise metadata line (dim). The outbox receipt never
//!   repeats the parent-facing child report.
//!
//! ## Small formats
//! - `tokens(n)`: `812`, `12.3k` (from 1 000), `1.05M` (from 1 000 000).
//! - `seconds(ms)`: `0.4s`, `12.3s`, `4m 05s` (from 60 s), `2h 03m` (from 60 min).
//! - `age(ms)`: `12s`, `5m`, `3h`, `2d` (largest unit, rounded down).
//! - `cut(text, max)`: at most `max` characters, the last being `…` when something was removed;
//!   never splits a character.
//!
//! ## Listings (columns separated by two spaces, widths from the content, a header line, rows cut
//! to `style.width`)
//! - `sessions_table(list, now_ms, style)`: one row per session, children indented under their
//!   parent (`  └ `): `ID  ROLE  MODEL  STATE  STEP  CONTEXT  AGE  TITLE`. `MODEL`: the session's profile name (`meta.profile`). `STATE`: `running`, `ended
//!   ({outcome})`, else the last turn end in the words above, else `new`; ` *` appended when
//!   `open_inbox > 0`. `CONTEXT`: `tokens(prompt_tokens)`. Empty list: `No sessions.`
//! - `inbox_list(list, now_ms, style)`: per item `{item_id}  {kind}  {age}  {session}  {title}` and
//!   the text indented, then the options numbered; `Nothing is waiting for you.` when empty. A scope
//!   request is listed as `scope request`, with `hosts: a, b` and `approve: ferret scope {session} a b`
//!   (a host with a character the shell would read is single-quoted). Every other item names how to
//!   act on it, as the streaming view does: a finished report gets `dismiss: ferret answer {item_id}`;
//!   anything else gets `answer: ferret answer {item_id} "…"`, and a blocking `Blocker` or `Parked`
//!   item also gets `close as blocked: ferret release {session} "why"`; a blocker says to name the next
//!   step, not ask a yes or no question. `granted_hosts_line(hosts)` is the line `ferret net` ends with.
//! - `window_table(view, style)`: a summary line (`epoch {e} · about {tokens} tokens in view ·
//!   folds at {target} down to {floor} · window {context_window or "unknown"} · last request
//!   {prompt} in, {pct}% cached`), then per item `#{seq}  {kind}  {state}  {chars}  {pin}
//!   {preview}`.
//! - `status(view, style)`: the daemon line; the free space of the volume of the ferret home (`{free}
//!   GiB free of {total} GiB ({pct}%) on the volume of the ferret home`, or `unknown`) and, when it is low
//!   (`DiskSpace::is_low`), a warning that sessions will fail when the disk fills (bold yellow); when the
//!   daemon reports it (`view.egress`), the egress line of the sandbox self-probe (`EgressView::line`: `egress:
//!   bounded (…)` plain, `egress: UNBOUNDED, …` bold yellow, `egress: not probed yet` plain); one
//!   line per model (`✓`/`✗`, base URL, model, window, detail when unreachable); the counts.
//! - `models_table(view, style)`: one line per live profile, `✓`/`✗ {profile}[ (default)] · {model} ·
//!   {base_url} · window {window} · {max_concurrent} at once · vision {yes|no}[ · {detail}]`; then a line when no
//!   `default_model` is set; `No model profiles are configured.` when there is none.
//! - `models_reload(report)`: `No profile changed.` or one `added|changed|removed: a, b` line per
//!   non-empty list; `{n} session(s) moved to the new settings of a changed profile`; `default model:
//!   {name or none}`; then one `! {note}` per note.
//! - `model_switch_line(receipt)`: `{session} now uses {profile} ({model}, window {window}), from its
//!   next step` (or `when it next runs` when no task took it).
//! - `net_table(entries, style)`: `TIME  VERDICT  METHOD  HOST:PORT  RULE` (time as `HH:MM:SS` UTC).
//! - `score_table(view, style)`: what a mission's work took. `SESSION  ROLE`, then the headings of
//!   `ferret_core::scorecard::COLUMNS` in capitals; one row per session with its `Scorecard::cells()`
//!   (a session with a parent as `  └ {id}`), and for a mission of more than one session a last row
//!   `total` with the view's total. Unlike the other listings its rows are not cut to the width: a
//!   number cut off at the right edge would read as not there. When a card is `unrecorded`, a line
//!   (dim) follows saying what `?` means: `? = not recorded: this log was written before ferret recorded
//!   verdicts and quote refusals.`
//!
//! Tests required: every record kind (the shape above, with and without colour — no escape byte
//! without colour); `clean` on escape sequences; reasoning shown/hidden; output cutting with and
//! without a handle and with `full`; each small format at its boundaries; each listing including
//! the empty cases and the child indentation; rows never exceed `width` characters; the score table
//! for one session and for several, with a card that is not recorded, wider than the width.

use crate::wire::{McpCheckView, McpConfigured, ModelsView, SignalStatusView, StatusView};
use ferret_agent::runtime::{
    ExchangeEntry, InboxEntry, MissionModels, ModelSwitchReceipt, ModelsReload, NetEntry, NoiseStatusView, PackView,
    ProfileShow, RoleModelReceipt, RoleModels, ScoreView, SessionInfo, WindowView, ANY_ROLE,
};
use ferret_agent::session::{Phase, QueuedMessage};
use ferret_core::event::{
    Author, ChildOutcome, Event, FinishReason, InboxItem, InboxKind, Record, SessionOutcome, SpawnMode, ToolStatus,
    TurnEndReason,
};
use ferret_core::ledger::LedgerState;
use ferret_core::scorecard::COLUMNS;
use ferret_core::security_state::{Finding, FindingSeverity, FindingStatus};
use ferret_core::weave::ItemState;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    pub color: bool,
    /// Terminal width in characters (`usize::MAX` for unclipped / piped output).
    pub width: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordOpts {
    /// Print reasoning in full.
    pub reasoning: bool,
    /// Never cut arguments, outputs or reports.
    pub full: bool,
    /// Print request records, `#seq` prefixes, and verbose metadata.
    pub verbose: bool,
    /// Suppress per-request `⇄` HTTP exchange lines.
    pub hide_exchanges: bool,
    pub max_output_lines: usize,
}

impl Default for RecordOpts {
    fn default() -> Self {
        RecordOpts { reasoning: false, full: false, verbose: false, hide_exchanges: false, max_output_lines: 40 }
    }
}

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const BOLD_YELLOW: &str = "\x1b[1m\x1b[33m";

/// Width used for cutting when a style says 0.
const DEFAULT_WIDTH: usize = 80;

fn width_of(style: &Style) -> usize {
    if style.width == 0 {
        DEFAULT_WIDTH
    } else {
        style.width
    }
}

/// Cleans `text` and, with colour, wraps each of its lines in `code` … reset. Every piece of text
/// that reaches the output goes through here or through [`clean`].
fn paint(style: &Style, code: &str, text: &str) -> String {
    let text = clean(text);
    if !style.color {
        return text;
    }
    text.split('\n')
        .map(|line| if line.is_empty() { String::new() } else { format!("{code}{line}{RESET}") })
        .collect::<Vec<_>>()
        .join("\n")
}

fn paint_opt(style: &Style, code: Option<&str>, text: &str) -> String {
    match code {
        Some(code) => paint(style, code, text),
        None => clean(text),
    }
}

/// Appends each line of `text` to `out`, indented by `pad`, in colour `code`.
fn push_block(out: &mut Vec<String>, style: &Style, code: Option<&str>, text: &str, pad: &str) {
    for line in text.lines() {
        if line.is_empty() {
            out.push(String::new());
        } else {
            out.push(format!("{pad}{}", paint_opt(style, code, line)));
        }
    }
}

fn finish(lines: Vec<String>) -> String {
    if lines.is_empty() {
        String::new()
    } else {
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }
}

/// Replaces what could drive a terminal with `·`: C0 controls except `\n` and `\t`, DEL, C1
/// controls and the bidirectional overrides.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}' => '·',
            _ => c,
        })
        .collect()
}

pub fn tokens(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        let tenths = n / 100;
        format!("{}.{}k", tenths / 10, tenths % 10)
    } else {
        let hundredths = n / 10_000;
        format!("{}.{:02}M", hundredths / 100, hundredths % 100)
    }
}

pub fn seconds(ms: u64) -> String {
    let secs = ms / 1_000;
    if secs < 60 {
        let tenths = ms / 100;
        format!("{}.{}s", tenths / 10, tenths % 10)
    } else if secs < 3_600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3_600, (secs % 3_600) / 60)
    }
}

pub fn age(ms: u64) -> String {
    let secs = ms / 1_000;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3_600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// Terminal display width of one Unicode scalar value (0 for combining/zero-width marks,
/// 2 for East Asian Wide/Fullwidth & common Emoji blocks, 1 otherwise).
pub fn char_display_width(c: char) -> usize {
    let cp = u32::from(c);
    if matches!(
        cp,
        0x0000..=0x001F
            | 0x007F..=0x009F
            | 0x0300..=0x036F
            | 0x1AB0..=0x1AFF
            | 0x1DC0..=0x1DFF
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2066..=0x2069
            | 0x20D0..=0x20FF
            | 0xFE00..=0xFE0F
            | 0xFE20..=0xFE2F
            | 0xFEFF
            | 0xE0100..=0xE01EF
    ) {
        return 0;
    }
    if matches!(
        cp,
        0x1100..=0x115F
            | 0x2329..=0x232A
            | 0x2E80..=0x303E
            | 0x3040..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1FAFF
            | 0x20000..=0x3FFFD
    ) {
        return 2;
    }
    1
}

/// Terminal display width of `text` in columns.
pub fn display_width(text: &str) -> usize {
    text.chars().map(char_display_width).sum()
}

/// Wrap `text` into visual terminal rows of at most `max_cols` display columns each.
/// Expands `\t` to spaces (4 columns) so tab stops never cause extra terminal wraps
/// that desynchronize cursor-up erasure.
pub fn wrap_display_rows(text: &str, max_cols: usize) -> Vec<String> {
    let max_cols = max_cols.max(2);
    let mut rows = Vec::new();
    for line in text.lines() {
        let expanded = line.replace('\t', "    ");
        if expanded.is_empty() {
            rows.push(String::new());
            continue;
        }
        let mut cur = String::new();
        let mut cols = 0usize;
        for ch in expanded.chars() {
            let cw = char_display_width(ch);
            if cols > 0 && cols + cw > max_cols {
                rows.push(std::mem::take(&mut cur));
                cols = 0;
            }
            cur.push(ch);
            cols += cw;
        }
        if !cur.is_empty() || cols == 0 {
            rows.push(cur);
        }
    }
    rows
}

pub fn cut(text: &str, max: usize) -> String {
    if max == usize::MAX || text.chars().count() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    if max > 0 {
        out.push('…');
    }
    out
}

/// Whole percent of `part` in `whole`, 0 when `whole` is 0.
fn percent(part: u64, whole: u64) -> u64 {
    if whole == 0 {
        0
    } else {
        u64::try_from(u128::from(part) * 100 / u128::from(whole)).unwrap_or(u64::MAX)
    }
}

fn turn_end_words(reason: TurnEndReason) -> &'static str {
    match reason {
        TurnEndReason::Yielded => "yielded",
        TurnEndReason::Finished => "finished",
        TurnEndReason::Asked => "asked the operator",
        TurnEndReason::Blocked => "blocked",
        TurnEndReason::Waiting => "waiting for jobs or agents",
        TurnEndReason::Stopped => "stopped",
        TurnEndReason::Parked => "parked for the operator",
        TurnEndReason::BudgetExhausted => "budget used up",
        TurnEndReason::Error => "error",
    }
}

fn session_outcome_words(outcome: SessionOutcome) -> &'static str {
    match outcome {
        SessionOutcome::Done => "done",
        SessionOutcome::Stopped => "stopped",
        SessionOutcome::Failed => "failed",
        SessionOutcome::BudgetExhausted => "budget used up",
    }
}

fn child_outcome_words(outcome: ChildOutcome) -> &'static str {
    match outcome {
        ChildOutcome::Returned => "returned",
        ChildOutcome::Blocked => "blocked",
        ChildOutcome::BudgetExhausted => "budget used up",
        ChildOutcome::Stopped => "stopped",
        ChildOutcome::Failed => "failed",
    }
}

fn inbox_kind_word(kind: InboxKind) -> &'static str {
    match kind {
        InboxKind::Approval => "approval",
        InboxKind::Question => "question",
        InboxKind::Blocker => "blocker",
        InboxKind::Parked => "parked",
        InboxKind::Finished => "finished",
    }
}

/// The hosts a scope request asks for, when `item` is one. A scope request is the non-blocking `Approval`
/// item the `request_scope` tool opens: its options are the requested hosts, in order, its text says why.
/// The ui (`scopeRequestHosts`) and the app (`isScopeRequest`) detect it the same way; the mechanism must
/// open the item with `InboxKind::Approval`, `blocking: false` and the hosts as `options`. Any other
/// item, and an `Approval` with no hosts, is not one.
pub fn scope_request_hosts(item: &InboxItem) -> Option<&[String]> {
    (item.kind == InboxKind::Approval && !item.blocking && !item.options.is_empty()).then_some(item.options.as_slice())
}

/// `word` as one shell argument: as it is when it holds only plain characters, else in single quotes.
fn shell_word(word: &str) -> String {
    let plain = !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || "._:-/".contains(c));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// The hosts a session has been granted, as `ferret net` ends: the operator's grants, or that there are none.
pub fn granted_hosts_line(hosts: &[String]) -> String {
    if hosts.is_empty() {
        return "No hosts granted by the operator.".to_string();
    }
    let hosts: Vec<String> = hosts.iter().map(|h| flat(h)).collect();
    format!("Hosts granted by the operator: {}", hosts.join(", "))
}

/// The lines of `text` to print and how many were left out.
fn limited_lines<'a>(text: &'a str, opts: &RecordOpts) -> (Vec<&'a str>, usize) {
    let all: Vec<&str> = text.lines().collect();
    let keep = opts.max_output_lines.max(1);
    if opts.full || all.len() <= keep {
        return (all, 0);
    }
    let hidden = all.len().saturating_sub(keep);
    (all.into_iter().take(keep).collect(), hidden)
}

/// The `  … n more lines` notice, with the handle of the stored output when there is one.
fn more_lines_notice(style: &Style, hidden: usize, handle: Option<String>) -> String {
    let mut notice = format!("… {hidden} more lines");
    if let Some(handle) = handle {
        notice.push_str(&format!(" — ferret out {handle}"));
    }
    format!("  {}", paint(style, DIM, &notice))
}

pub fn record(rec: &Record, style: &Style, opts: &RecordOpts) -> String {
    let mut out: Vec<String> = Vec::new();
    match &rec.event {
        Event::SessionStart(s) => {
            let head = format!("● session {} · {} · {} · {}", s.session, s.role, s.model.model, s.workspace);
            out.push(paint(style, BOLD, &head));
        }
        Event::Forked(f) => {
            let head = format!("● agent {} · {} · forked from {}", f.session, f.role, f.parent);
            out.push(paint(style, BOLD, &head));
            push_block(&mut out, style, None, &f.brief.question, "  ");
        }
        Event::UserMessage { text, images } => {
            out.push(paint(style, CYAN, "▌ you"));
            push_block(&mut out, style, None, text, "");
            if !images.is_empty() {
                let n = images.len();
                let label =
                    if n == 1 { "  [1 image attached]".to_string() } else { format!("  [{n} images attached]") };
                out.push(paint(style, DIM, &label));
            }
        }
        Event::HarnessNote { note, text } => {
            let head = match &rec.author {
                Author::Agent(id) => format!("▌ agent {id} · {}", note.as_str()),
                _ => format!("▌ harness · {}", note.as_str()),
            };
            out.push(paint(style, DIM, &head));
            push_block(&mut out, style, Some(DIM), text, "");
        }
        Event::ModelResponse(m) => {
            let mut head = format!(
                "▌ model · {} in ({}% cached) · {} out · {}",
                tokens(m.usage.prompt_tokens),
                percent(m.usage.cached_tokens, m.usage.prompt_tokens),
                tokens(m.usage.completion_tokens),
                seconds(m.timing.total_ms)
            );
            if m.attempts > 1 {
                head.push_str(&format!(" · attempt {}", m.attempts));
            }
            let mut line = paint(style, GREEN, &head);
            if m.finish == FinishReason::Length {
                line.push_str(&paint(style, YELLOW, " · cut off by the output limit"));
            }
            out.push(line);
            if !m.reasoning.is_empty() {
                if opts.reasoning {
                    push_block(&mut out, style, Some(DIM), &m.reasoning, "");
                } else {
                    let note = format!("  (reasoning: {} lines)", m.reasoning.lines().count());
                    out.push(paint(style, DIM, &note));
                }
            }
            push_block(&mut out, style, None, &m.text, "");
        }
        Event::StoredAction(action) => {
            let text = format!(
                "∙ controller · {} node {} · {} · callback {} omitted",
                action.plan_id, action.node, action.call.name, action.omitted_callback
            );
            out.push(paint(style, DIM, &text));
        }
        Event::ContinuationPlanned { plan_id, source_call, .. } => {
            if opts.verbose {
                out.push(paint(style, DIM, &format!("∙ continuation {plan_id} authored by call {source_call}")));
            }
        }
        Event::ContinuationStopped { plan_id, reason } => {
            if opts.verbose {
                out.push(paint(style, DIM, &format!("∙ continuation {plan_id} stopped: {reason}")));
            }
        }
        Event::OutputsObserved { req_id, calls } => {
            if opts.verbose {
                out.push(paint(style, DIM, &format!("∙ request {req_id} observed {} deferred outputs", calls.len())));
            }
        }
        Event::ToolCall(c) => {
            let args = serde_json::to_string(&c.args).unwrap_or_default();
            let args = clean(&args);
            let args = if opts.full { args } else { cut(&args, width_of(style).saturating_mul(3)) };
            out.push(format!("→ {} {}", clean(&c.name), args));
        }
        Event::ToolResult(r) => {
            let (shown, hidden) = limited_lines(&r.text, opts);
            let first_code = (r.status != ToolStatus::Ok).then_some(RED);
            for (i, line) in shown.iter().enumerate() {
                if i == 0 {
                    out.push(format!("← {}", paint_opt(style, first_code, line)));
                } else if line.is_empty() {
                    out.push(String::new());
                } else {
                    out.push(format!("  {}", clean(line)));
                }
            }
            if shown.is_empty() {
                out.push("←".to_string());
            }
            if hidden > 0 {
                out.push(more_lines_notice(style, hidden, r.output.as_ref().map(|b| b.handle())));
            }
        }
        Event::Reweave(w) => {
            let text = format!(
                "⟲ context re-woven ({}): {} items folded out of view, about {} → {} tokens",
                w.reason,
                w.evictions.len(),
                tokens(w.before_tokens),
                tokens(w.after_tokens_est)
            );
            out.push(paint(style, YELLOW, &text));
        }
        Event::Exchange(x) => {
            if !opts.hide_exchanges {
                // One line per captured exchange.
                let status =
                    x.status.map(|c| c.to_string()).or_else(|| x.error.clone()).unwrap_or_else(|| "no response".into());
                let line = format!(
                    "⇄ {} {} {}://{}{} · {} · {}",
                    x.id, x.method, x.scheme, x.host, x.target, status, x.source
                );
                out.push(paint(style, DIM, &line));
            }
        }
        Event::Compaction(c) => {
            let text = format!(
                "⟲ context compacted ({}): {} outputs in the key table, about {} → {} tokens{}",
                c.reason,
                c.keys.len(),
                tokens(c.before_tokens),
                tokens(c.after_tokens_est),
                if c.note.is_some() { "" } else { " (no note)" }
            );
            out.push(paint(style, YELLOW, &text));
        }
        Event::Pin { call_id, reason } => {
            out.push(paint(style, DIM, &format!("∙ pinned {call_id}: {reason}")));
        }
        Event::Unpin { call_id } => {
            out.push(paint(style, DIM, &format!("∙ unpinned {call_id}")));
        }
        Event::ChildSpawned(c) => {
            let mode = match c.mode {
                SpawnMode::Fresh => "fresh",
                SpawnMode::Fork => "fork",
            };
            let text = format!("⇢ agent {} ({}, {}): {}", c.child, c.role, mode, c.brief.question);
            out.push(paint(style, CYAN, &text));
        }
        Event::ChildSettled(c) => {
            out.push(paint(style, CYAN, &format!("⇠ agent {} {}", c.child, child_outcome_words(c.outcome))));
            if c.inline {
                if let Some(first) = c.report.lines().next() {
                    out.push(format!("  {}", clean(first)));
                }
            } else {
                let (shown, hidden) = limited_lines(&c.report, opts);
                for line in shown {
                    out.push(if line.is_empty() { String::new() } else { format!("  {}", clean(line)) });
                }
                if hidden > 0 {
                    out.push(more_lines_notice(style, hidden, c.full.as_ref().map(|b| b.handle())));
                }
            }
        }
        Event::ChildCompleted(c) => {
            if opts.verbose {
                let text = format!("∙ child outbox {} persisted: {}", c.child, child_outcome_words(c.outcome));
                out.push(paint(style, DIM, &text));
            }
        }
        Event::JobRegistered { job_id, command, .. } => {
            out.push(format!("⚙ job {}: {}", clean(job_id), clean(command)));
        }
        Event::JobSettled { job_id, detail, .. } => {
            out.push(format!("⚙ job {} ended: {}", clean(job_id), clean(detail)));
        }
        Event::JobMatched { job_id, pattern, matches, .. } => {
            let lines = if *matches == 1 { "line" } else { "lines" };
            out.push(format!("⚙ job {} wrote {matches} {lines} matching /{}/", clean(job_id), clean(pattern)));
        }
        Event::InboxOpened(item) => {
            if let Some(hosts) = scope_request_hosts(item) {
                out.push(paint(style, BOLD_YELLOW, "✉ scope request"));
                push_block(&mut out, style, None, &item.text, "");
                let hosts: Vec<String> = hosts.iter().map(|h| clean(h)).collect();
                out.push(format!("  hosts: {}", hosts.join(", ")));
                out.push(paint(style, DIM, "  approve: see ferret inbox"));
            } else {
                let mut head = format!("✉ {}", inbox_kind_word(item.kind));
                if item.blocking {
                    head.push_str(" (waiting for you)");
                }
                out.push(paint(style, BOLD_YELLOW, &head));
                push_block(&mut out, style, None, &item.text, "");
                for (i, option) in item.options.iter().enumerate() {
                    out.push(format!("  {}. {}", i + 1, clean(option)));
                }
                if item.kind != InboxKind::Finished {
                    let hint = format!("  answer: ferret answer {} \"…\"", item.item_id);
                    out.push(paint(style, DIM, &hint));
                }
            }
        }
        Event::InboxResolved { answer, .. } => {
            if answer.is_empty() {
                out.push("✉ dismissed".to_string());
            } else {
                out.push(format!("✉ answered: {}", clean(answer)));
            }
        }
        Event::Ledger { n, summary } => {
            out.push(paint(style, DIM, &format!("▪ ledger #{n}: {summary}")));
        }
        Event::CacheBreak { first_diff_message, detail, .. } => {
            let text = format!("! cache break at message {first_diff_message}: {detail}");
            out.push(paint(style, YELLOW, &text));
        }
        Event::ModelSwitched(m) => {
            let side = |r: &ferret_core::event::ModelRef| {
                let window = if r.context_window > 0 { tokens(r.context_window) } else { "unknown".to_string() };
                format!("{} ({}, window {window})", clean(&r.profile), clean(&r.model))
            };
            let mut text = format!("⇄ model {} → {}", side(&m.from), side(&m.to));
            if !m.reason.is_empty() {
                text.push_str(&format!(" · {}", clean(&m.reason)));
            }
            out.push(paint(style, CYAN, &text));
        }
        Event::Interrupted { reason } => {
            out.push(paint(style, YELLOW, &format!("! interrupted: {reason}")));
        }
        Event::TurnEnd { reason } => {
            out.push(paint(style, DIM, &format!("— turn ended: {} —", turn_end_words(*reason))));
        }
        Event::SessionEnd { outcome, detail } => {
            let mut text = format!("● session ended: {}", session_outcome_words(*outcome));
            if !detail.is_empty() {
                text.push_str(&format!(": {detail}"));
            }
            out.push(paint(style, BOLD, &text));
        }
        Event::ModelRequest(r) => {
            if opts.verbose {
                let text = format!(
                    "… request {} · step {} · epoch {} · about {} tokens",
                    r.req_id,
                    r.step,
                    r.epoch,
                    tokens(r.est_tokens)
                );
                out.push(paint(style, DIM, &text));
            }
        }
        Event::BudgetClock { .. }
        | Event::ExecStarted { .. }
        | Event::TurnStart { .. }
        | Event::Net(_)
        | Event::Unknown => {}
    }
    if opts.verbose {
        if let Some(first) = out.first_mut() {
            let prefix = paint(style, DIM, &format!("#{}", rec.seq));
            *first = format!("{prefix} {first}");
        }
    }
    finish(out)
}

/// Flattens a table cell to one line.
fn flat(text: &str) -> String {
    clean(text).replace(['\n', '\t'], " ")
}

/// A header line and rows, columns separated by two spaces and sized to their content (the last
/// column is not padded). Every line is cut to the style's width.
fn table(style: &Style, header: &[&str], rows: &[Vec<String>]) -> String {
    let columns = header.len();
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let width = width_of(style);
    let layout = |cells: Vec<&str>| -> String {
        let mut line = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                line.push_str("  ");
            }
            line.push_str(cell);
            if i + 1 < columns {
                let pad = widths.get(i).copied().unwrap_or(0).saturating_sub(cell.chars().count());
                line.push_str(&" ".repeat(pad));
            }
        }
        cut(line.trim_end(), width)
    };
    let mut out = vec![paint(style, DIM, &layout(header.to_vec()))];
    for row in rows {
        out.push(layout(row.iter().map(String::as_str).collect()));
    }
    finish(out)
}

/// Sessions with children directly after their parent, each with its depth.
fn session_order(list: &[SessionInfo]) -> Vec<(&SessionInfo, usize)> {
    fn walk<'a>(
        list: &'a [SessionInfo],
        parent: &str,
        depth: usize,
        seen: &mut HashSet<usize>,
        out: &mut Vec<(&'a SessionInfo, usize)>,
    ) {
        for (i, s) in list.iter().enumerate() {
            if s.meta.parent.as_ref().is_some_and(|p| p.as_str() == parent) && seen.insert(i) {
                out.push((s, depth));
                walk(list, s.meta.id.as_str(), depth + 1, seen, out);
            }
        }
    }
    let ids: HashSet<&str> = list.iter().map(|s| s.meta.id.as_str()).collect();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (i, s) in list.iter().enumerate() {
        let orphan = s.meta.parent.as_ref().is_none_or(|p| !ids.contains(p.as_str()));
        if orphan && seen.insert(i) {
            out.push((s, 0));
            walk(list, s.meta.id.as_str(), 1, &mut seen, &mut out);
        }
    }
    // Whatever is left belongs to a parent cycle; list it flat rather than lose it.
    for (i, s) in list.iter().enumerate() {
        if seen.insert(i) {
            out.push((s, 0));
            walk(list, s.meta.id.as_str(), 1, &mut seen, &mut out);
        }
    }
    out
}

fn turn_end_table_words(reason: TurnEndReason) -> &'static str {
    match reason {
        TurnEndReason::Yielded => "yielded",
        TurnEndReason::Finished => "finished",
        TurnEndReason::Asked => "asked",
        TurnEndReason::Blocked => "blocked",
        TurnEndReason::Waiting => "waiting",
        TurnEndReason::Stopped => "stopped",
        TurnEndReason::Parked => "parked",
        TurnEndReason::BudgetExhausted => "budget",
        TurnEndReason::Error => "error",
    }
}

fn session_outcome_table_words(outcome: SessionOutcome) -> &'static str {
    match outcome {
        SessionOutcome::Done => "done",
        SessionOutcome::Stopped => "stopped",
        SessionOutcome::Failed => "failed",
        SessionOutcome::BudgetExhausted => "budget",
    }
}

fn session_state(info: &SessionInfo) -> String {
    let st = &info.status;
    let mut state = match st.phase {
        Phase::Running => "running".to_string(),
        Phase::Ended => match st.outcome {
            Some(outcome) => format!("ended ({})", session_outcome_table_words(outcome)),
            None => "ended".to_string(),
        },
        Phase::Idle => st.last_end.map_or("new", turn_end_table_words).to_string(),
    };
    if st.open_inbox > 0 {
        state.push_str(" *");
    }
    state
}

pub fn sessions_table(list: &[SessionInfo], now_ms: u64, style: &Style) -> String {
    sessions_table_opts(list, now_ms, style, false)
}

pub fn sessions_table_opts(list: &[SessionInfo], now_ms: u64, style: &Style, wide: bool) -> String {
    if list.is_empty() {
        return "No sessions.\n".to_string();
    }
    let has_inbox = list.iter().any(|s| s.status.open_inbox > 0);
    let ordered = session_order(list);
    let mut out = if wide {
        let rows: Vec<Vec<String>> = ordered
            .into_iter()
            .map(|(s, depth)| {
                let id = if depth == 0 {
                    flat(s.meta.id.as_str())
                } else {
                    format!("{}  └ {}", "  ".repeat(depth.saturating_sub(1)), flat(s.meta.id.as_str()))
                };
                let mission = if depth == 0 { flat(s.meta.mission.as_str()) } else { String::new() };
                vec![
                    id,
                    mission,
                    flat(&s.meta.role),
                    flat(&s.meta.pack),
                    flat(&s.meta.profile),
                    flat(&session_state(s)),
                    s.status.step.to_string(),
                    tokens(s.status.prompt_tokens),
                    age(now_ms.saturating_sub(s.meta.created_ms)),
                    flat(&s.meta.workspace),
                    flat(&s.meta.title),
                ]
            })
            .collect();
        table(
            style,
            &["ID", "MISSION", "ROLE", "PACK", "MODEL", "STATE", "STEP", "CONTEXT", "AGE", "WORKSPACE", "TITLE"],
            &rows,
        )
    } else {
        let rows: Vec<Vec<String>> = ordered
            .into_iter()
            .map(|(s, depth)| {
                let id = if depth == 0 {
                    flat(s.meta.id.as_str())
                } else {
                    format!("{}  └ {}", "  ".repeat(depth.saturating_sub(1)), flat(s.meta.id.as_str()))
                };
                let mission = if depth == 0 { flat(s.meta.mission.as_str()) } else { String::new() };
                vec![
                    id,
                    mission,
                    flat(&s.meta.role),
                    flat(&s.meta.profile),
                    flat(&session_state(s)),
                    s.status.step.to_string(),
                    tokens(s.status.prompt_tokens),
                    age(now_ms.saturating_sub(s.meta.created_ms)),
                    flat(&s.meta.title),
                ]
            })
            .collect();
        table(style, &["ID", "MISSION", "ROLE", "MODEL", "STATE", "STEP", "CONTEXT", "AGE", "TITLE"], &rows)
    };
    if has_inbox {
        let legend = cut("* = waiting in inbox (run `ferret inbox`)", width_of(style));
        out.push_str(&paint(style, DIM, &legend));
        out.push('\n');
    }
    out
}

pub fn inbox_list(list: &[InboxEntry], now_ms: u64, style: &Style) -> String {
    if list.is_empty() {
        return "Nothing is waiting for you.\n".to_string();
    }
    let mut out = Vec::new();
    for entry in list {
        let head = format!(
            "{}  {}  {}  {}  {}",
            flat(&entry.item.item_id),
            inbox_kind_word(entry.item.kind),
            age(now_ms.saturating_sub(entry.opened_ms)),
            flat(entry.session.as_str()),
            flat(&entry.title)
        );
        let item = &entry.item;
        let scope = scope_request_hosts(item);
        let head = if scope.is_some() { head.replacen(inbox_kind_word(item.kind), "scope request", 1) } else { head };
        out.push(cut(head.trim_end(), width_of(style)));
        push_block(&mut out, style, None, &item.text, "  ");
        // Never truncate actionable commands (`ferret scope`, `ferret answer`, `ferret release`):
        // operators copy-paste them verbatim.
        let dim = |text: String| paint(style, DIM, &text);
        if let Some(hosts) = scope {
            let shown: Vec<String> = hosts.iter().map(|h| flat(h)).collect();
            out.push(format!("  hosts: {}", shown.join(", ")));
            let args: Vec<String> = shown.iter().map(|h| shell_word(h)).collect();
            out.push(dim(format!(
                "  approve: ferret scope {} {}",
                shell_word(&flat(entry.session.as_str())),
                args.join(" ")
            )));
            continue;
        }
        for (i, option) in item.options.iter().enumerate() {
            out.push(format!("  {}. {}", i + 1, flat(option)));
        }
        // Every item but a finished report can be acted on with `ferret answer`; the streaming view
        // (`record`) already shows this for every kind, so the list does too. A finished report is
        // only cleared, and a blocked/parked session can also be closed outright.
        if item.kind == InboxKind::Finished {
            out.push(dim(format!("  dismiss: ferret answer {}", flat(&item.item_id))));
        } else {
            let next =
                if item.kind == InboxKind::Blocker { " (name the next step, not a yes or no question)" } else { "" };
            out.push(dim(format!("  answer: ferret answer {} \"…\"{next}", flat(&item.item_id))));
            if item.blocking && matches!(item.kind, InboxKind::Blocker | InboxKind::Parked) {
                let session = shell_word(&flat(entry.session.as_str()));
                out.push(dim(format!("  close as blocked: ferret release {session} \"why\"")));
            }
        }
    }
    finish(out)
}

fn item_state_word(state: ItemState) -> &'static str {
    match state {
        ItemState::Live => "live",
        ItemState::Stubbed => "stubbed",
        ItemState::ReasoningDropped => "reasoning_dropped",
        ItemState::Dropped => "dropped",
    }
}

pub fn window_table(view: &WindowView, style: &Style) -> String {
    let window = view.context_window.map_or_else(|| "unknown".to_string(), tokens);
    let in_view = match view.measured_now {
        Some(m) => format!("{} tokens in view", tokens(m)),
        None => format!("about {} tokens in view", tokens(view.est_tokens)),
    };
    let compact_at = view.fold_at.unwrap_or(view.target_tokens);
    let fold_part = if view.floor_tokens > 0 {
        format!("folds at {} down to {}", tokens(compact_at), tokens(view.floor_tokens))
    } else {
        format!("compacts at {}", tokens(compact_at))
    };
    let summary = format!(
        "epoch {} · {in_view} · {fold_part} · window {window} · last request {} in, {}% cached",
        view.epoch,
        tokens(view.prompt_tokens),
        percent(view.cached_tokens, view.prompt_tokens)
    );
    let mut out = cut(&summary, width_of(style));
    out.push('\n');
    if view.items.is_empty() {
        out.push_str("The window holds no items.\n");
        return out;
    }
    let rows: Vec<Vec<String>> = view
        .items
        .iter()
        .map(|item| {
            vec![
                format!("#{}", item.seq),
                flat(&item.kind),
                item_state_word(item.state).to_string(),
                item.chars.to_string(),
                if item.pinned { "pinned".to_string() } else { String::new() },
                flat(&item.preview),
            ]
        })
        .collect();
    out.push_str(&table(style, &["SEQ", "KIND", "STATE", "CHARS", "PIN", "PREVIEW"], &rows));
    out
}

/// What `status` says when the volume of the ferret home is nearly full (`DiskSpace::is_low`).
const LOW_DISK_WARNING: &str = "! Low disk space: sessions will fail when the disk fills. Run `ferret gc`.";

/// Bytes in GiB with one decimal, rounded down: `0.4 GiB`, `926.4 GiB`.
fn gib(bytes: u64) -> String {
    let tenths = u128::from(bytes) * 10 / (1u128 << 30);
    format!("{}.{} GiB", tenths / 10, tenths % 10)
}

fn format_signal_status(sig: &SignalStatusView, style: &Style, width: usize, out: &mut Vec<String>) {
    if !sig.enabled {
        return;
    }
    let mark = if sig.connected { paint(style, GREEN, "✓") } else { paint(style, RED, "✗") };
    let state = if sig.connected { "connected" } else { "disconnected" };
    let mut parts = vec![format!("signal: {state}")];
    if !sig.account.is_empty() || !sig.recipient.is_empty() {
        parts.push(format!("{} -> {}", flat(&sig.account), flat(&sig.recipient)));
    }
    if sig.pending_sends > 0 {
        parts.push(format!("pending {}", sig.pending_sends));
    }
    if sig.dropped_events > 0 {
        parts.push(format!("dropped {}", sig.dropped_events));
    }
    if sig.muted_until_ms.is_some() {
        parts.push("muted".to_string());
    }
    let line = parts.join(" · ");
    out.push(format!("{mark} {}", cut(&line, width.saturating_sub(2))));
    if let Some(err) = sig.last_error.as_deref().filter(|s| !s.trim().is_empty()) {
        out.push(format!("  {}", paint(style, RED, &format!("error: {}", flat(err)))));
    }
}

pub fn status(view: &StatusView, style: &Style) -> String {
    let width = width_of(style);
    let mut out = Vec::new();
    let daemon = format!(
        "ferret {} · pid {} · {} · proxy port {} · home {}",
        view.version, view.pid, view.bind, view.proxy_port, view.home
    );
    out.push(cut(&flat(&daemon), width));
    // The security posture, at the place an operator checks the daemon. A missing field means an older
    // daemon that does not report it, so skip the line rather than show blanks.
    if !view.sandbox.is_empty() {
        let line = format!("sandbox: {} · network: {}", flat(&view.sandbox), flat(&view.network));
        // `none` (commands unconfined) and `open` (tools reach any host) are the postures worth a warning.
        let unsafe_posture = view.sandbox == "none" || view.network == "open";
        out.push(if unsafe_posture { paint(style, BOLD_YELLOW, &cut(&line, width)) } else { cut(&line, width) });
    }
    match &view.disk {
        Some(disk) => {
            let (free, total) = (disk.free_bytes, disk.total_bytes);
            let pct = percent(free, total);
            let line = format!("{} free of {} ({pct}%) on the volume of the ferret home", gib(free), gib(total));
            out.push(cut(&line, width));
            if disk.is_low() {
                out.push(paint(style, BOLD_YELLOW, &cut(LOW_DISK_WARNING, width)));
            }
        }
        None => out.push(cut("free space on the volume of the ferret home: unknown", width)),
    }
    if let Some(egress) = &view.egress {
        let line = cut(&flat(&egress.line(ferret_core::now_ms())), width);
        out.push(if egress.level == ferret_agent::egress::Level::Unbounded {
            paint(style, BOLD_YELLOW, &line)
        } else {
            line
        });
    }
    if view.models.is_empty() {
        out.push("no models configured".to_string());
    }
    for m in &view.models {
        let mark = if m.reachable { paint(style, GREEN, "✓") } else { paint(style, RED, "✗") };
        let default = if view.default_model.as_deref() == Some(m.profile.as_str()) { " (default)" } else { "" };
        let window = m.context_window.map_or_else(|| "unknown".to_string(), tokens);
        let text =
            format!("{}{default} · {} · {} · window {window}", flat(&m.profile), flat(&m.model), flat(&m.base_url),);
        // The mark takes two columns; the rest of the line is cut to what is left.
        out.push(format!("{mark} {}", cut(&text, width.saturating_sub(2))));
        // Never truncate failure details — put them intact on an indented continuation line.
        if !m.reachable && !m.detail.is_empty() {
            out.push(format!("  {}", paint(style, RED, &format!("error: {}", flat(&m.detail)))));
        }
    }
    if let Some(sig) = &view.signal {
        format_signal_status(sig, style, width, &mut out);
    }
    let counts = format!(
        "{} sessions · {} active · {} running · {} waiting in the inbox",
        view.sessions_total, view.sessions_active, view.sessions_running, view.inbox_open
    );
    out.push(cut(&counts, width));
    finish(out)
}

/// `ferret models list`: one line per live profile — ✓/✗ for its server, the default one marked.
pub fn models_table(view: &ModelsView, style: &Style) -> String {
    if view.models.is_empty() {
        return "No model profiles are configured.\n".to_string();
    }
    let width = width_of(style);
    let mut out = Vec::new();
    for m in &view.models {
        let mark = if m.reachable { paint(style, GREEN, "✓") } else { paint(style, RED, "✗") };
        let default = if m.profile == view.default_model { " (default)" } else { "" };
        let window = m.context_window.map_or_else(|| "unknown".to_string(), tokens);
        let text = format!(
            "{}{default} · {} · {} · window {window} · {} at once · vision {}",
            flat(&m.profile),
            flat(&m.model),
            flat(&m.base_url),
            m.max_concurrent,
            if m.vision { "yes" } else { "no" }
        );
        out.push(format!("{mark} {}", cut(&text, width.saturating_sub(2))));
        if !m.reachable && !m.detail.is_empty() {
            out.push(format!("  {}", paint(style, RED, &format!("error: {}", flat(&m.detail)))));
        }
    }
    if view.default_model.is_empty() {
        out.push(cut("no default_model: a new session names its model with --model", width));
    }
    finish(out)
}

/// `ferret mcp list`: one line per configured server. Names only: a secret value is never in it.
pub fn mcp_list(servers: &[McpConfigured]) -> String {
    if servers.is_empty() {
        return "No MCP servers are configured. Add them under [mcp.servers.NAME] in the config.\n".to_string();
    }
    let rows: Vec<Vec<String>> = servers
        .iter()
        .map(|s| {
            let roles =
                if s.roles.is_empty() { "every role that is not read-only".to_string() } else { s.roles.join(", ") };
            let mut extra = Vec::new();
            if s.read_only {
                extra.push("read_only".to_string());
            }
            if !s.hosts.is_empty() {
                extra.push(format!("hosts {}", s.hosts.join(", ")));
            }
            if let Some(t) = &s.tools {
                extra.push(format!("tools {}", t.join(", ")));
            }
            vec![flat(&s.server), s.transport.clone(), flat(&roles), flat(&extra.join(" · "))]
        })
        .collect();
    let mut out = vec![format!("{} configured", servers.len())];
    for r in rows {
        out.push(format!(
            "{} · {} · roles: {}{}",
            r[0],
            r[1],
            r[2],
            if r[3].is_empty() { String::new() } else { format!(" · {}", r[3]) }
        ));
    }
    finish(out)
}

/// `ferret mcp check`: the tools the server lists, or why it could not, with what it wrote to stderr.
pub fn mcp_check(v: &McpCheckView) -> String {
    let mut out = Vec::new();
    match &v.error {
        Some(e) => out.push(format!("{} ({}) failed: {}", flat(&v.server), v.transport, flat(e))),
        None => {
            out.push(format!(
                "{} ({}) · {} {} · protocol {} · {} tools",
                flat(&v.server),
                v.transport,
                flat(&v.server_name),
                flat(&v.server_version),
                flat(&v.protocol),
                v.tools.len()
            ));
            for t in &v.tools {
                let first = t.description.lines().next().unwrap_or("");
                let ro = if t.read_only_hint == Some(true) { " [read-only]" } else { "" };
                out.push(format!(
                    "  {}{ro}{}",
                    flat(&t.name),
                    if first.is_empty() { String::new() } else { format!(" · {}", flat(first)) }
                ));
            }
        }
    }
    if !v.stderr_tail.is_empty() {
        out.push("stderr:".to_string());
        for l in &v.stderr_tail {
            out.push(format!("  {}", flat(l)));
        }
    }
    finish(out)
}

/// `ferret models reload`: what changed, then what needs the operator (`! …`).
pub fn models_reload(r: &ModelsReload) -> String {
    let list = |names: &[String]| names.iter().map(|n| flat(n)).collect::<Vec<_>>().join(", ");
    let mut out = Vec::new();
    if r.added.is_empty() && r.changed.is_empty() && r.removed.is_empty() {
        out.push("No profile changed.".to_string());
    }
    for (word, names) in [("added", &r.added), ("changed", &r.changed), ("removed", &r.removed)] {
        if !names.is_empty() {
            out.push(format!("{word}: {}", list(names)));
        }
    }
    if !r.rebound.is_empty() {
        let n = r.rebound.len();
        out.push(format!(
            "{n} {} moved to the new settings of a changed profile",
            if n == 1 { "session" } else { "sessions" }
        ));
    }
    out.push(format!("default model: {}", if r.default_model.is_empty() { "none" } else { r.default_model.as_str() }));
    for note in &r.notes {
        out.push(format!("! {}", flat(note)));
    }
    finish(out)
}

/// `ferret models set`: whom it switched, to what, and from when.
pub fn model_switch_line(r: &ModelSwitchReceipt) -> String {
    let when = if r.live { "from its next step" } else { "when it next runs" };
    let window = if r.model.context_window > 0 { tokens(r.model.context_window) } else { "unknown".to_string() };
    format!(
        "{} now uses {} ({}, window {window}), {when}",
        flat(r.session.as_str()),
        flat(&r.model.profile),
        flat(&r.model.model)
    )
}

/// What the pack chooses for a role's agents when the operator chose nothing.
fn pack_choice_words(r: &RoleModels) -> String {
    let mut words = if !r.alloy_models.is_empty() {
        format!("rotates {}", r.alloy_models.iter().map(|m| flat(m)).collect::<Vec<_>>().join(", "))
    } else if let Some(m) = &r.pack_model {
        flat(m)
    } else {
        "the lead's".to_string()
    };
    if let Some(e) = &r.escalation_model {
        words.push_str(&format!(", {} after a failed agent", flat(e)));
    }
    words
}

/// `ferret models show`: the lead's model, the choice for every role, one line per role of its agents
/// (the choice in force, whether it is the finish gate's, its agents running now), the profiles.
pub fn mission_models_table(m: &MissionModels, style: &Style) -> String {
    let width = width_of(style);
    let window = |w: u64| if w > 0 { tokens(w) } else { "unknown".to_string() };
    let mut out = vec![cut(
        &format!(
            "mission {} · lead {} on {} ({}, window {})",
            flat(m.mission.as_str()),
            flat(m.lead.as_str()),
            flat(&m.lead_model.profile),
            flat(&m.lead_model.model),
            window(m.lead_model.context_window)
        ),
        width,
    )];
    out.push(match &m.any_role {
        Some(p) => cut(&format!("agents of every role: {}", flat(p)), width),
        None => cut("agents of every role: as each role's pack setting says", width),
    });
    if m.roles.is_empty() {
        out.push("this lead starts no agents".to_string());
    }
    let pad = m.roles.iter().map(|r| flat(&r.role).chars().count()).max().unwrap_or(0);
    for r in &m.roles {
        let choice = match (&r.chosen, &m.any_role) {
            (Some(p), _) => format!("{} (chosen)", flat(p)),
            (None, Some(p)) if !r.verifier => format!("{} (every role)", flat(p)),
            _ => format!("pack: {}", pack_choice_words(r)),
        };
        let gate = if r.verifier { " · finish gate" } else { "" };
        let running = if r.agents.is_empty() {
            "none".to_string()
        } else {
            r.agents
                .iter()
                .map(|a| {
                    format!(
                        "{} on {}{}",
                        flat(a.session.as_str()),
                        flat(&a.profile),
                        if a.forked { " (forked)" } else { "" }
                    )
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push(cut(&format!("{:pad$}  {choice}{gate} · running: {running}", flat(&r.role)), width));
    }
    let profiles: Vec<String> = m
        .profiles
        .iter()
        .map(|p| if *p == m.default_model { format!("{} (default)", flat(p)) } else { flat(p) })
        .collect();
    out.push(cut(&format!("profiles: {}", profiles.join(", ")), width));
    finish(out)
}

/// `ferret models role`: what changed, who moved now, then [`mission_models_table`].
pub fn role_model_receipt(r: &RoleModelReceipt, role: &str, profile: Option<&str>, style: &Style) -> String {
    let who = if role == ANY_ROLE { "every role".to_string() } else { format!("`{}`", flat(role)) };
    let mut out = vec![match profile {
        Some(p) => format!("agents of {who} start on {} from now on", flat(p)),
        None => format!("the choice for {who} is cleared: the pack chooses again"),
    }];
    if !r.switched.is_empty() {
        out.push(format!("moved now: {}", r.switched.iter().map(|s| flat(s.as_str())).collect::<Vec<_>>().join(", ")));
    }
    let mut text = finish(out);
    text.push_str(&mission_models_table(&r.models, style));
    text
}

pub fn net_table(entries: &[NetEntry], style: &Style) -> String {
    if entries.is_empty() {
        return "No network decisions.\n".to_string();
    }
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            let secs = e.ts_ms / 1_000;
            vec![
                format!("{:02}:{:02}:{:02}", (secs / 3_600) % 24, (secs / 60) % 60, secs % 60),
                if e.decision.allowed { "allowed" } else { "denied" }.to_string(),
                flat(&e.decision.method),
                format!("{}:{}", flat(&e.decision.host), e.decision.port),
                flat(&e.decision.rule),
            ]
        })
        .collect();
    table(style, &["TIME", "VERDICT", "METHOD", "HOST:PORT", "RULE"], &rows)
}

fn counts_line(v: &ferret_agent::runtime::TargetView) -> String {
    ["finding", "tested", "deferred", "untested", "not_seen"]
        .iter()
        .map(|k| format!("{} {}", k.replace('_', " "), v.counts.get(*k).copied().unwrap_or(0)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `ferret target list`: one line per target, sanitized.
pub fn target_list(list: &[ferret_agent::runtime::TargetView]) -> String {
    let mut out = String::new();
    for v in list {
        out.push_str(&format!("{}  {} scope entries  {}\n", flat(&v.name), v.scope.len(), counts_line(v)));
    }
    out
}

/// `ferret target show`: the settings and the counts, sanitized.
pub fn target_show(v: &ferret_agent::runtime::TargetView) -> String {
    let join_clean = |xs: &[String]| xs.iter().map(|s| flat(s)).collect::<Vec<_>>().join(", ");
    let scope = if v.scope.is_empty() { "(none)".to_string() } else { join_clean(&v.scope) };
    let mut out = format!("{}\nscope: {scope}\n", flat(&v.name));
    if !v.exclude.is_empty() {
        out.push_str(&format!("exclude: {}\n", join_clean(&v.exclude)));
    }
    if !v.upstream_insecure.is_empty() {
        out.push_str(&format!("upstream_insecure: {}\n", join_clean(&v.upstream_insecure)));
    }
    if !v.intercept_passthrough.is_empty() {
        out.push_str(&format!("intercept_passthrough: {}\n", join_clean(&v.intercept_passthrough)));
    }
    if !v.notes.trim().is_empty() {
        out.push_str(&format!("notes: {}\n", flat(&v.notes)));
    }
    out.push_str(&format!("nodes: {}\n", counts_line(v)));
    out
}

/// `ferret target show --nodes`: each node with its status.
pub fn target_nodes(g: &ferret_agent::runtime::GraphView) -> String {
    if g.nodes.is_empty() {
        return "No nodes.\n".to_string();
    }
    let mut out = String::new();
    for n in &g.nodes {
        let status =
            serde_json::to_value(n.status).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        out.push_str(&format!("{:<10} {}\n", flat(&status), flat(&n.locator)));
    }
    out
}

/// `ferret creds list` / `show` summary row, sanitized against untrusted target names.
pub fn creds_summary_row(p: &ferret_core::creds::ProfileSummary) -> String {
    let plural = |n: usize, w: &str| if n == 1 { format!("{n} {w}") } else { format!("{n} {w}s") };
    let mut out = format!("{} · {}, {}", flat(&p.profile), plural(p.cookies, "cookie"), plural(p.headers, "header"));
    if !p.hosts.is_empty() {
        let hosts: Vec<String> = p.hosts.iter().map(|h| flat(h)).collect();
        out.push_str(&format!(" · {}", hosts.join(", ")));
    }
    if let Some(e) = &p.error {
        out.push_str(&format!(" · {}", flat(e)));
    }
    out
}

/// `ferret creds show`: summary plus sanitized item kinds, names and hosts (never values).
pub fn creds_show(v: &ProfileShow) -> String {
    let mut out = format!("{}\n", creds_summary_row(&v.summary));
    for i in &v.items {
        let kind = match i.kind {
            ferret_core::creds::ItemKind::Cookie => "cookie",
            ferret_core::creds::ItemKind::Header => "header",
        };
        out.push_str(&format!("{kind} {} {}\n", flat(&i.name), flat(&i.host)));
    }
    out
}

/// `ferret packs`: installed packs, flags, descriptions, and roles.
pub fn packs_list(packs: &[PackView], style: &Style) -> String {
    if packs.is_empty() {
        return "No packs installed.\n".to_string();
    }
    let width = width_of(style);
    let mut out = Vec::new();
    for p in packs {
        let mut flags = Vec::new();
        if p.intercept {
            flags.push("intercept");
        }
        if p.requires_restricted_network {
            flags.push("restricted-net");
        }
        let flag_str = if flags.is_empty() { String::new() } else { format!(" [{}]", flags.join(", ")) };
        let head = format!(
            "{} (default role: {}){flag_str}{}",
            flat(&p.name),
            flat(&p.default_role),
            if p.description.trim().is_empty() { String::new() } else { format!(" — {}", flat(&p.description)) }
        );
        out.push(paint(style, BOLD, &cut(&head, width)));
        for r in &p.roles {
            let mut tags = Vec::new();
            if r.name == p.default_role {
                tags.push("default");
            } else if r.top_level {
                tags.push("top-level");
            }
            if r.starts_agents {
                tags.push("spawns");
            }
            let tag_str = if tags.is_empty() { String::new() } else { format!(" ({})", tags.join(", ")) };
            let desc =
                if r.description.trim().is_empty() { String::new() } else { format!(" — {}", flat(&r.description)) };
            out.push(cut(&format!("  {}{tag_str}{desc}", flat(&r.name)), width));
        }
    }
    finish(out)
}

fn severity_rank(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
        FindingSeverity::Info => 4,
    }
}

/// `ferret findings`: structured findings sorted by severity, plus coverage summary counts.
pub fn findings_table(
    state: &LedgerState,
    include_withdrawn: bool,
    severity_filter: Option<&str>,
    style: &Style,
) -> String {
    let mut list: Vec<&Finding> = state
        .security
        .findings
        .values()
        .filter(|f| include_withdrawn || f.status == FindingStatus::Active)
        .filter(|f| severity_filter.is_none_or(|s| f.severity.as_str().eq_ignore_ascii_case(s.trim())))
        .collect();
    list.sort_by(|a, b| (severity_rank(a.severity), a.id.as_str()).cmp(&(severity_rank(b.severity), b.id.as_str())));

    let active_total = state.security.findings.values().filter(|f| f.status == FindingStatus::Active).count();
    let withdrawn_total = state.security.findings.len().saturating_sub(active_total);
    let cov_total = state.security.surface_coverage.len();

    let mut out = String::new();
    if list.is_empty() {
        out.push_str("No findings recorded.\n");
    } else {
        let rows: Vec<Vec<String>> = list
            .iter()
            .map(|f| {
                let cvss = f.cvss.map_or_else(|| "-".to_string(), |c| format!("{}.{}", c.0 / 10, c.0 % 10));
                let cwe = f.cwe.as_deref().map(flat).unwrap_or_else(|| "-".to_string());
                let loc = match (f.method.as_deref(), f.endpoint.as_deref()) {
                    (Some(m), Some(e)) => format!("{} {}", flat(m), flat(e)),
                    (None, Some(e)) => flat(e),
                    _ => flat(&f.target),
                };
                vec![
                    flat(&f.id),
                    f.severity.as_str().to_string(),
                    cvss,
                    f.confidence.as_str().to_string(),
                    f.status.as_str().to_string(),
                    cwe,
                    loc,
                    flat(&f.title),
                ]
            })
            .collect();
        out.push_str(&table(style, &["ID", "SEVERITY", "CVSS", "CONF", "STATUS", "CWE", "TARGET", "TITLE"], &rows));
    }
    let summary =
        format!("findings: {active_total} active, {withdrawn_total} withdrawn · surface coverage rows: {cov_total}");
    out.push_str(&paint(style, DIM, &cut(&summary, width_of(style))));
    out.push('\n');
    out
}

/// `ferret traffic`: captured HTTP exchanges table.
pub fn traffic_table(entries: &[ExchangeEntry], style: &Style) -> String {
    if entries.is_empty() {
        return "No captured exchanges.\n".to_string();
    }
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            let secs = e.ts_ms / 1_000;
            let x = &e.exchange;
            let status = x
                .status
                .map(|c| c.to_string())
                .or_else(|| x.error.as_deref().map(flat))
                .unwrap_or_else(|| "-".to_string());
            let url = format!("{}://{}{}", flat(&x.scheme), flat(&x.host), flat(&x.target));
            vec![
                format!("{:02}:{:02}:{:02}", (secs / 3_600) % 24, (secs / 60) % 60, secs % 60),
                flat(&x.id),
                flat(&x.method),
                status,
                format!("{}B", x.response_bytes),
                format!("{}ms", x.duration_ms),
                flat(&x.source),
                url,
            ]
        })
        .collect();
    table(style, &["TIME", "ID", "METHOD", "STATUS", "SIZE", "DUR", "SRC", "URL"], &rows)
}

/// `ferret net --noise`: egress noise governor profile and per-host pacing metrics.
pub fn noise_status(view: &NoiseStatusView, style: &Style) -> String {
    let mut out =
        format!("noise profile: {} · assessment_ua origins: {}\n", flat(&view.profile), view.assessment_ua_origins);
    if view.hosts.is_empty() {
        out.push_str("No host traffic paced yet.\n");
        return out;
    }
    let rows: Vec<Vec<String>> = view
        .hosts
        .iter()
        .map(|h| {
            vec![
                flat(&h.host),
                h.sent.to_string(),
                h.inflight.to_string(),
                h.peak_inflight.to_string(),
                h.backoffs.to_string(),
            ]
        })
        .collect();
    out.push_str(&table(style, &["HOST", "SENT", "INFLIGHT", "PEAK", "BACKOFFS"], &rows));
    out
}

/// `ferret queued list`: queued messages waiting for the lead's turn to end.
pub fn queued_list(items: &[QueuedMessage], now_ms: u64, style: &Style) -> String {
    if items.is_empty() {
        return "No queued messages.\n".to_string();
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|q| {
            vec![flat(&q.id), age(now_ms.saturating_sub(q.created_ms)), q.attachments.len().to_string(), flat(&q.text)]
        })
        .collect();
    table(style, &["ID", "AGE", "FILES", "TEXT"], &rows)
}

/// `ferret rewrite list`: human-readable table of operator proxy rewrite rules.
pub fn rewrite_rules_table(rules: &[serde_json::Value], style: &Style) -> String {
    if rules.is_empty() {
        return "No proxy rewrite rules configured.\n".to_string();
    }
    let rows: Vec<Vec<String>> = rules
        .iter()
        .map(|r| {
            let id = r.get("id").and_then(|v| v.as_u64()).map(|n| n.to_string()).unwrap_or_else(|| "-".into());
            let enabled =
                if r.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) { "enabled" } else { "disabled" };
            let phase = r.get("phase").and_then(|v| v.as_str()).map(flat).unwrap_or_else(|| "-".into());
            let priority =
                r.get("priority").and_then(|v| v.as_i64()).map(|n| n.to_string()).unwrap_or_else(|| "0".into());
            let name = r.get("name").and_then(|v| v.as_str()).map(flat).unwrap_or_default();
            let actions = r.get("actions").and_then(|v| v.as_array()).map_or(0, Vec::len).to_string();
            let note = r.get("note").and_then(|v| v.as_str()).map(flat).unwrap_or_default();
            vec![id, enabled.to_string(), phase, priority, name, actions, note]
        })
        .collect();
    table(style, &["ID", "STATE", "PHASE", "PRIO", "NAME", "ACTIONS", "NOTE"], &rows)
}

pub fn score_table(view: &ScoreView, style: &Style) -> String {
    let mut header = vec!["SESSION".to_string(), "ROLE".to_string()];
    header.extend(COLUMNS.iter().map(|c| c.to_uppercase()));
    let mut rows: Vec<Vec<String>> = view
        .sessions
        .iter()
        .map(|s| {
            let id = flat(s.session.as_str());
            let mut row = vec![if s.parent.is_some() { format!("  └ {id}") } else { id }, flat(&s.role)];
            row.extend(s.card.cells());
            row
        })
        .collect();
    if view.sessions.len() > 1 {
        let mut row = vec!["total".to_string(), String::new()];
        row.extend(view.total.cells());
        rows.push(row);
    }
    // A number cut off at the right edge would read as not there: these rows keep their width.
    let whole = Style { color: style.color, width: usize::MAX };
    let header: Vec<&str> = header.iter().map(String::as_str).collect();
    let mut text = table(&whole, &header, &rows);
    if view.sessions.iter().any(|s| s.card.unrecorded) {
        let note = "? = not recorded: this log was written before ferret recorded verdicts and quote refusals.";
        text.push_str(&paint(style, DIM, note));
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferret_agent::runtime::SessionMeta;
    use ferret_agent::session::Status;
    use ferret_core::blob::BlobRef;
    use ferret_core::event::*;
    use ferret_core::ids::{BlobId, CallId, MissionId, SessionId};
    use ferret_core::message::Role;
    use ferret_core::weave::WindowItem;
    use serde_json::Map;

    const MONO: Style = Style { color: false, width: 100 };
    const COLOR: Style = Style { color: true, width: 100 };
    /// Text a hostile tool could produce.
    const EVIL: &str = "\x1b[31mR\x1b]0;title\x07\x1b[2J\u{9b}31m";

    fn rec(author: Author, event: Event) -> Record {
        Record { seq: 1, ts_ms: 1, author, prev: "0".repeat(64), event }
    }

    fn render(event: Event, style: &Style) -> String {
        record(&rec(Author::Harness, event), style, &RecordOpts::default())
    }

    fn blob() -> BlobRef {
        BlobRef { id: BlobId::from("ab".repeat(32)), bytes: 10, lines: 2 }
    }

    fn result(text: &str, status: ToolStatus, output: Option<BlobRef>) -> Event {
        Event::ToolResult(ToolResult {
            exchanges: Vec::new(),
            call_id: CallId::from("c1"),
            name: "bash".into(),
            status,
            text: text.into(),
            output,
            cut: false,
            class: ToolClass::Exec,
            meta: Map::new(),
            duration_ms: 5,
            images: Vec::new(),
        })
    }

    fn no_escape(text: &str) {
        assert!(!text.contains('\x1b'), "escape byte in {text:?}");
    }

    fn brief(q: &str) -> Brief {
        Brief { question: q.into(), ..Default::default() }
    }

    fn continuation_and_outbox_events(s: &str) -> Vec<Event> {
        vec![
            Event::ContinuationPlanned {
                plan_id: s.into(),
                source_call: s.into(),
                plan: serde_json::json!({"nodes":[]}),
            },
            Event::StoredAction(StoredAction {
                plan_id: s.into(),
                source_call: s.into(),
                node: 2,
                omitted_callback: s.into(),
                call: ToolCallRequest {
                    call_id: s.into(),
                    name: s.into(),
                    arguments: "{\"command\":\"printf literal\"}".into(),
                    complete: true,
                },
                arguments_hash: s.into(),
                predecessor: Some(s.into()),
                file_guards: serde_json::json!([]),
                guard_ms: 3,
            }),
            Event::ContinuationStopped { plan_id: s.into(), reason: s.into() },
            Event::OutputsObserved { req_id: s.into(), calls: vec![s.into()] },
            Event::ChildCompleted(ChildCompleted {
                child: s.into(),
                role: s.into(),
                outcome: ChildOutcome::Returned,
                report: "parent-facing report must not repeat".into(),
                full: Some(blob()),
                payload: serde_json::json!({"verdict":"accept"}),
                steps: 3,
                usage: Usage { prompt_tokens: 1234, ..Usage::default() },
            }),
        ]
    }

    /// One event of every kind; each string field holds `s`.
    fn one_of_each(s: &str) -> Vec<Event> {
        let sid = || SessionId::from(s);
        let cid = || CallId::from(s);
        let budget = Budget { max_steps: Some(5), max_minutes: Some(9) };
        let mut events = vec![
            Event::SessionStart(SessionStart {
                session: sid(),
                mission: MissionId::from("m-a"),
                parent: Some(sid()),
                workspace: s.into(),
                pack: s.into(),
                role: s.into(),
                termination: Termination::Explicit,
                model: ModelRef { profile: s.into(), model: s.into(), context_window: 1000, lineage: None },
                reasoning_replay: ReasoningReplay::All,
                system_prompt: s.into(),
                tools: vec![],
                budget: budget.clone(),
                unattended: true,
                schema: ferret_core::event::SCHEMA,
                intercept: false,
                target: None,
                creds: None,
                title: s.into(),
                project_instructions: Vec::new(),
                mcp: Vec::new(),
            }),
            Event::Forked(Forked {
                session: sid(),
                parent: sid(),
                upto_seq: 4,
                role: s.into(),
                termination: Termination::Explicit,
                budget: budget.clone(),
                brief: brief(s),
                contract: s.into(),
                allowed_tools: None,
                title: s.into(),
            }),
            Event::UserMessage { text: s.into(), images: vec![] },
            Event::HarnessNote { note: NoteKind::Nudge, text: s.into() },
            Event::TurnStart { trigger: Trigger::User },
            Event::ModelRequest(ModelRequest {
                req_id: s.into(),
                step: 1,
                epoch: 0,
                purpose: Purpose::Step,
                n_messages: 3,
                stable_hash: s.into(),
                hud: None,
                est_tokens: 9,
            }),
            Event::ModelResponse(ModelResponse {
                req_id: s.into(),
                text: s.into(),
                reasoning: s.into(),
                tool_calls: vec![],
                finish: FinishReason::Length,
                usage: Usage { prompt_tokens: 5, cached_tokens: 4, completion_tokens: 3, reasoning_tokens: 2 },
                timing: Timing { queue_ms: 1, ttft_ms: 2, total_ms: 3 },
                attempts: 2,
            }),
            Event::ToolCall(ToolCall {
                call_id: cid(),
                req_id: s.into(),
                name: s.into(),
                args: serde_json::json!({ "command": s }),
                class: ToolClass::Exec,
            }),
            result(s, ToolStatus::Error, Some(blob())),
            Event::Reweave(Reweave {
                epoch: 1,
                upto_seq: 7,
                evictions: vec![Eviction { seq: 3, action: EvictAction::Drop }],
                brief: s.into(),
                digest: Some(s.into()),
                reason: s.into(),
                before_tokens: 9,
                after_tokens_est: 4,
            }),
            Event::Pin { call_id: cid(), reason: s.into() },
            Event::Unpin { call_id: cid() },
            Event::ChildSpawned(ChildSpawned {
                child: sid(),
                role: s.into(),
                mode: SpawnMode::Fork,
                brief: brief(s),
                budget,
                call_id: Some(cid()),
            }),
            Event::ChildSettled(ChildSettled {
                child: sid(),
                outcome: ChildOutcome::Failed,
                report: s.into(),
                full: Some(blob()),
                usage: Usage::default(),
                steps: 2,
                inline: false,
            }),
            Event::ChildSettled(ChildSettled {
                child: sid(),
                outcome: ChildOutcome::Returned,
                report: s.into(),
                full: None,
                usage: Usage::default(),
                steps: 2,
                inline: true,
            }),
            Event::JobRegistered { job_id: s.into(), call_id: cid(), command: s.into() },
            Event::JobSettled { job_id: s.into(), exit_code: Some(0), output: None, detail: s.into() },
            Event::JobMatched {
                job_id: s.into(),
                pattern: s.into(),
                output: None,
                from: 0,
                shown: vec![1],
                matches: 1,
            },
            Event::InboxOpened(InboxItem {
                item_id: s.into(),
                kind: InboxKind::Question,
                text: s.into(),
                options: vec![s.into()],
                blocking: true,
                call_id: None,
                reference: None,
            }),
            Event::InboxResolved { item_id: s.into(), answer: s.into() },
            Event::Ledger { n: 3, summary: s.into() },
            Event::Net(NetDecision {
                host: s.into(),
                port: 443,
                method: s.into(),
                allowed: false,
                rule: s.into(),
                resolved: None,
                sni: None,
                paced_ms: None,
            }),
            Event::CacheBreak { req_id: s.into(), first_diff_message: 2, detail: s.into() },
            Event::Interrupted { reason: s.into() },
            Event::TurnEnd { reason: TurnEndReason::Finished },
            Event::SessionEnd { outcome: SessionOutcome::Failed, detail: s.into() },
            Event::ModelSwitched(ferret_core::event::ModelSwitched {
                from: ferret_core::event::ModelRef {
                    profile: s.into(),
                    model: s.into(),
                    context_window: 1000,
                    lineage: None,
                },
                to: ferret_core::event::ModelRef {
                    profile: s.into(),
                    model: s.into(),
                    context_window: 0,
                    lineage: None,
                },
                reasoning_replay: ferret_core::event::ReasoningReplay::None,
                reason: s.into(),
            }),
            Event::Unknown,
        ];
        events.extend(continuation_and_outbox_events(s));
        events
    }

    #[test]
    fn no_raw_escape_survives_for_any_kind() {
        let opts =
            RecordOpts { reasoning: true, full: true, verbose: true, hide_exchanges: false, max_output_lines: 40 };
        let known = [RESET, DIM, BOLD, RED, YELLOW, GREEN, CYAN];
        for event in one_of_each(EVIL) {
            for style in [MONO, COLOR] {
                let r = rec(Author::Agent(SessionId::from(EVIL)), event.clone());
                let text = record(&r, &style, &opts);
                if !style.color {
                    no_escape(&text);
                } else {
                    let mut rest = text.clone();
                    for code in known {
                        rest = rest.replace(code, "");
                    }
                    no_escape(&rest);
                }
                assert!(!text.contains('\u{9b}'), "C1 control in {text:?}");
                assert!(!text.contains('\x07'), "bell in {text:?}");
            }
        }
        // Listings clean what they show too.
        let hostile = |s: &str| SessionInfo {
            meta: meta(s, None, s, 0),
            active: false,
            status: status_of(Phase::Idle, None, None, 0),
            last_ms: None,
        };
        no_escape(&sessions_table(&[hostile(EVIL)], 10, &MONO));
        let entry = InboxEntry {
            session: SessionId::from(EVIL),
            mission: MissionId::from("m"),
            title: EVIL.into(),
            opened_ms: 0,
            item: InboxItem {
                item_id: EVIL.into(),
                kind: InboxKind::Blocker,
                text: EVIL.into(),
                options: vec![],
                blocking: false,
                call_id: None,
                reference: None,
            },
        };
        no_escape(&inbox_list(&[entry], 10, &MONO));
    }

    #[test]
    fn clean_replaces_controls_only() {
        assert_eq!(clean("a\x1b[31mb"), "a·[31mb");
        assert_eq!(clean("a\r\nb\tc\x00d\x7fe\u{85}f"), "a·\nb\tc·d·e·f");
        assert_eq!(clean("héllo → 日本 \u{1f600}"), "héllo → 日本 \u{1f600}");
        assert_eq!(clean("\u{202e}x"), "·x");
        assert_eq!(clean(""), "");
    }

    #[test]
    fn small_formats() {
        assert_eq!(tokens(0), "0");
        assert_eq!(tokens(812), "812");
        assert_eq!(tokens(999), "999");
        assert_eq!(tokens(1_000), "1.0k");
        assert_eq!(tokens(12_345), "12.3k");
        assert_eq!(tokens(999_999), "999.9k");
        assert_eq!(tokens(1_000_000), "1.00M");
        assert_eq!(tokens(1_050_000), "1.05M");
        assert!(tokens(u64::MAX).ends_with('M'));
        assert_eq!(seconds(0), "0.0s");
        assert_eq!(seconds(400), "0.4s");
        assert_eq!(seconds(12_345), "12.3s");
        assert_eq!(seconds(59_999), "59.9s");
        assert_eq!(seconds(60_000), "1m 00s");
        assert_eq!(seconds(245_000), "4m 05s");
        assert_eq!(seconds(3_599_999), "59m 59s");
        assert_eq!(seconds(3_600_000), "1h 00m");
        assert_eq!(seconds(7_380_000), "2h 03m");
        assert_eq!(age(0), "0s");
        assert_eq!(age(12_999), "12s");
        assert_eq!(age(59_999), "59s");
        assert_eq!(age(60_000), "1m");
        assert_eq!(age(300_000), "5m");
        assert_eq!(age(3_600_000), "1h");
        assert_eq!(age(3 * 3_600_000 + 59), "3h");
        assert_eq!(age(86_400_000), "1d");
        assert_eq!(age(2 * 86_400_000 + 5), "2d");
        assert!(!age(u64::MAX).is_empty());
    }

    #[test]
    fn cut_is_on_character_boundaries() {
        assert_eq!(cut("hello", 5), "hello");
        assert_eq!(cut("hello", 4), "hel…");
        assert_eq!(cut("hello", 1), "…");
        assert_eq!(cut("hello", 0), "");
        assert_eq!(cut("", 0), "");
        assert_eq!(cut("héllo wörld", 5), "héll…");
        assert_eq!(cut("日本語日本語", 4), "日本語…");
        assert_eq!(cut("日本語", 3), "日本語");
        assert_eq!(cut("a\u{1f600}b\u{1f600}c", 3), "a\u{1f600}…");
    }

    #[test]
    fn header_kinds_without_colour() {
        let sid = SessionId::from("s-a");
        let start = Event::SessionStart(SessionStart {
            session: sid.clone(),
            mission: MissionId::from("m-a"),
            parent: None,
            workspace: "/w".into(),
            pack: "core".into(),
            role: "lead".into(),
            termination: Termination::Free,
            model: ModelRef { profile: "local".into(), model: "mm".into(), context_window: 1, lineage: None },
            reasoning_replay: ReasoningReplay::All,
            system_prompt: String::new(),
            tools: vec![],
            budget: Budget::default(),
            unattended: false,
            schema: ferret_core::event::SCHEMA,
            intercept: false,
            target: None,
            creds: None,
            title: String::new(),
            project_instructions: Vec::new(),
            mcp: Vec::new(),
        });
        assert_eq!(render(start, &MONO), "● session s-a · lead · mm · /w\n");
        let forked = Event::Forked(Forked {
            session: sid.clone(),
            parent: SessionId::from("s-p"),
            upto_seq: 1,
            role: "worker".into(),
            termination: Termination::Explicit,
            budget: Budget::default(),
            brief: brief("why?\nreally"),
            contract: String::new(),
            allowed_tools: None,
            title: String::new(),
        });
        assert_eq!(render(forked, &MONO), "● agent s-a · worker · forked from s-p\n  why?\n  really\n");
        assert_eq!(
            render(Event::UserMessage { text: "hi\nthere".into(), images: vec![] }, &MONO),
            "▌ you\nhi\nthere\n"
        );
        assert_eq!(
            render(Event::HarnessNote { note: NoteKind::OutputCut, text: "cut".into() }, &MONO),
            "▌ harness · output_cut\ncut\n"
        );
        let by_agent =
            rec(Author::Agent(SessionId::from("s-x")), Event::HarnessNote { note: NoteKind::Info, text: "t".into() });
        assert_eq!(record(&by_agent, &MONO, &RecordOpts::default()), "▌ agent s-x · info\nt\n");
        assert_eq!(
            render(
                Event::Reweave(Reweave {
                    epoch: 1,
                    upto_seq: 7,
                    evictions: vec![
                        Eviction { seq: 1, action: EvictAction::Drop },
                        Eviction { seq: 2, action: EvictAction::Drop },
                    ],
                    brief: String::new(),
                    digest: None,
                    reason: "target".into(),
                    before_tokens: 12_345,
                    after_tokens_est: 800,
                }),
                &MONO
            ),
            "⟲ context re-woven (target): 2 items folded out of view, about 12.3k → 800 tokens\n"
        );
        assert_eq!(
            render(Event::Pin { call_id: CallId::from("c1"), reason: "keep".into() }, &MONO),
            "∙ pinned c1: keep\n"
        );
        assert_eq!(render(Event::Unpin { call_id: CallId::from("c1") }, &MONO), "∙ unpinned c1\n");
        assert_eq!(
            render(
                Event::ChildSpawned(ChildSpawned {
                    child: sid.clone(),
                    role: "worker".into(),
                    mode: SpawnMode::Fresh,
                    brief: brief("find it"),
                    budget: Budget::default(),
                    call_id: None,
                }),
                &MONO
            ),
            "⇢ agent s-a (worker, fresh): find it\n"
        );
        assert_eq!(
            render(
                Event::JobRegistered { job_id: "j1".into(), call_id: CallId::from("c"), command: "make".into() },
                &MONO
            ),
            "⚙ job j1: make\n"
        );
        assert_eq!(
            render(
                Event::JobSettled { job_id: "j1".into(), exit_code: Some(1), output: None, detail: "exit 1".into() },
                &MONO
            ),
            "⚙ job j1 ended: exit 1\n"
        );
        assert_eq!(
            render(
                Event::JobMatched {
                    job_id: "j1".into(),
                    pattern: "CRASH".into(),
                    output: None,
                    from: 0,
                    shown: vec![4, 9],
                    matches: 3,
                },
                &MONO
            ),
            "⚙ job j1 wrote 3 lines matching /CRASH/\n"
        );
        assert_eq!(render(Event::Ledger { n: 4, summary: "claim".into() }, &MONO), "▪ ledger #4: claim\n");
        assert_eq!(
            render(Event::CacheBreak { req_id: "r".into(), first_diff_message: 7, detail: "d".into() }, &MONO),
            "! cache break at message 7: d\n"
        );
        assert_eq!(render(Event::Interrupted { reason: "restart".into() }, &MONO), "! interrupted: restart\n");
        assert_eq!(
            render(Event::SessionEnd { outcome: SessionOutcome::Done, detail: String::new() }, &MONO),
            "● session ended: done\n"
        );
        assert_eq!(
            render(Event::SessionEnd { outcome: SessionOutcome::Failed, detail: "oops".into() }, &MONO),
            "● session ended: failed: oops\n"
        );
        assert_eq!(
            render(Event::InboxResolved { item_id: "i".into(), answer: "yes".into() }, &MONO),
            "✉ answered: yes\n"
        );
        assert_eq!(render(Event::InboxResolved { item_id: "i".into(), answer: String::new() }, &MONO), "✉ dismissed\n");
        assert_eq!(
            render(
                Event::ToolCall(ToolCall {
                    call_id: CallId::from("c1"),
                    req_id: "r".into(),
                    name: "bash".into(),
                    args: serde_json::json!({"command": "ls"}),
                    class: ToolClass::Exec,
                }),
                &MONO
            ),
            "→ bash {\"command\":\"ls\"}\n"
        );
    }

    #[test]
    fn turn_end_words_all() {
        let all = [
            (TurnEndReason::Yielded, "yielded"),
            (TurnEndReason::Finished, "finished"),
            (TurnEndReason::Asked, "asked the operator"),
            (TurnEndReason::Blocked, "blocked"),
            (TurnEndReason::Waiting, "waiting for jobs or agents"),
            (TurnEndReason::Stopped, "stopped"),
            (TurnEndReason::Parked, "parked for the operator"),
            (TurnEndReason::BudgetExhausted, "budget used up"),
            (TurnEndReason::Error, "error"),
        ];
        for (reason, words) in all {
            assert_eq!(render(Event::TurnEnd { reason }, &MONO), format!("— turn ended: {words} —\n"));
        }
    }

    #[test]
    fn colours_wrap_each_line() {
        assert_eq!(
            render(Event::UserMessage { text: "x".into(), images: vec![] }, &COLOR),
            "\x1b[36m▌ you\x1b[0m\nx\n"
        );
        assert_eq!(
            render(Event::HarnessNote { note: NoteKind::Info, text: "a\nb".into() }, &COLOR),
            "\x1b[2m▌ harness · info\x1b[0m\n\x1b[2ma\x1b[0m\n\x1b[2mb\x1b[0m\n"
        );
        assert_eq!(render(Event::Interrupted { reason: "r".into() }, &COLOR), "\x1b[33m! interrupted: r\x1b[0m\n");
        assert_eq!(
            render(Event::SessionEnd { outcome: SessionOutcome::Done, detail: String::new() }, &COLOR),
            "\x1b[1m● session ended: done\x1b[0m\n"
        );
    }

    fn response(reasoning: &str, text: &str, finish: FinishReason, attempts: u32) -> Event {
        Event::ModelResponse(ModelResponse {
            req_id: "r".into(),
            text: text.into(),
            reasoning: reasoning.into(),
            tool_calls: vec![],
            finish,
            usage: Usage { prompt_tokens: 12_345, cached_tokens: 6_000, completion_tokens: 812, reasoning_tokens: 0 },
            timing: Timing { queue_ms: 0, ttft_ms: 0, total_ms: 12_300 },
            attempts,
        })
    }

    #[test]
    fn model_response_header_reasoning_and_text() {
        let head = "▌ model · 12.3k in (48% cached) · 812 out · 12.3s";
        let hidden = render(response("one\ntwo\nthree", "answer", FinishReason::Stop, 1), &MONO);
        assert_eq!(hidden, format!("{head}\n  (reasoning: 3 lines)\nanswer\n"));
        let opts = RecordOpts { reasoning: true, ..RecordOpts::default() };
        let shown = record(&rec(Author::Model, response("one\ntwo", "answer", FinishReason::Stop, 1)), &MONO, &opts);
        assert_eq!(shown, format!("{head}\none\ntwo\nanswer\n"));
        let none = render(response("", "answer", FinishReason::Stop, 1), &MONO);
        assert_eq!(none, format!("{head}\nanswer\n"));
        let retried = render(response("", "", FinishReason::Length, 3), &MONO);
        assert_eq!(retried, format!("{head} · attempt 3 · cut off by the output limit\n"));
        let colored = render(response("", "", FinishReason::Length, 1), &COLOR);
        assert_eq!(colored, format!("\x1b[32m{head}\x1b[0m\x1b[33m · cut off by the output limit\x1b[0m\n"));
        // No prompt tokens: no division by zero.
        let zero = Event::ModelResponse(ModelResponse {
            req_id: "r".into(),
            text: String::new(),
            reasoning: String::new(),
            tool_calls: vec![],
            finish: FinishReason::Stop,
            usage: Usage::default(),
            timing: Timing::default(),
            attempts: 0,
        });
        assert_eq!(render(zero, &MONO), "▌ model · 0 in (0% cached) · 0 out · 0.0s\n");
    }

    #[test]
    fn tool_call_arguments_are_cut_unless_full() {
        let long = "x".repeat(500);
        let event = Event::ToolCall(ToolCall {
            call_id: CallId::from("c1"),
            req_id: "r".into(),
            name: "bash".into(),
            args: serde_json::json!({ "command": long }),
            class: ToolClass::Exec,
        });
        let style = Style { color: false, width: 40 };
        let cutoff = record(&rec(Author::Model, event.clone()), &style, &RecordOpts::default());
        let args = cutoff.trim_end().strip_prefix("→ bash ").unwrap_or("");
        assert_eq!(args.chars().count(), 120);
        assert!(args.ends_with('…'));
        let full = RecordOpts { full: true, ..RecordOpts::default() };
        let all = record(&rec(Author::Model, event), &style, &full);
        assert!(all.contains(&long));
    }

    #[test]
    fn tool_result_cutting() {
        let text: String = (1..=10).map(|i| format!("line {i}\n")).collect();
        let opts = RecordOpts { max_output_lines: 3, ..RecordOpts::default() };
        let r = |event: Event, style: &Style, opts: &RecordOpts| record(&rec(Author::Tool, event), style, opts);
        let with_handle = r(result(&text, ToolStatus::Ok, Some(blob())), &MONO, &opts);
        assert_eq!(
            with_handle,
            format!("← line 1\n  line 2\n  line 3\n  … 7 more lines — ferret out out:{}\n", "ab".repeat(8))
        );
        let without = r(result(&text, ToolStatus::Ok, None), &MONO, &opts);
        assert_eq!(without, "← line 1\n  line 2\n  line 3\n  … 7 more lines\n");
        let full = RecordOpts { full: true, max_output_lines: 3, ..RecordOpts::default() };
        let all = r(result(&text, ToolStatus::Ok, Some(blob())), &MONO, &full);
        assert!(all.contains("  line 10\n"));
        assert!(!all.contains("more lines"));
        let exact = r(result("a\nb\nc", ToolStatus::Ok, None), &MONO, &opts);
        assert_eq!(exact, "← a\n  b\n  c\n");
        assert_eq!(r(result("", ToolStatus::Ok, None), &MONO, &opts), "←\n");
        // Blank lines in the output stay blank.
        assert_eq!(r(result("a\n\nb", ToolStatus::Ok, None), &MONO, &opts), "← a\n\n  b\n");
        // A failed call is red on its first line only; the notice is dim.
        let red = r(result("boom\nmore", ToolStatus::Error, None), &COLOR, &opts);
        assert_eq!(red, "← \x1b[31mboom\x1b[0m\n  more\n");
        let ok = r(result("fine", ToolStatus::Ok, None), &COLOR, &opts);
        assert_eq!(ok, "← fine\n");
        let dim = r(result(&text, ToolStatus::Ok, Some(blob())), &COLOR, &opts);
        assert!(dim.ends_with(&format!("  \x1b[2m… 7 more lines — ferret out out:{}\x1b[0m\n", "ab".repeat(8))));
    }

    #[test]
    fn child_settled_report() {
        let settled = |report: &str, inline: bool, full: Option<BlobRef>| {
            Event::ChildSettled(ChildSettled {
                child: SessionId::from("s-c"),
                outcome: ChildOutcome::Blocked,
                report: report.into(),
                full,
                usage: Usage::default(),
                steps: 1,
                inline,
            })
        };
        let opts = RecordOpts { max_output_lines: 2, ..RecordOpts::default() };
        let r = |event: Event| record(&rec(Author::Agent(SessionId::from("s-c")), event), &MONO, &opts);
        assert_eq!(r(settled("a\nb", false, None)), "⇠ agent s-c blocked\n  a\n  b\n");
        assert_eq!(
            r(settled("a\nb\nc\nd", false, Some(blob()))),
            format!("⇠ agent s-c blocked\n  a\n  b\n  … 2 more lines — ferret out out:{}\n", "ab".repeat(8))
        );
        assert_eq!(r(settled("a\nb\nc", true, Some(blob()))), "⇠ agent s-c blocked\n  a\n");
        assert_eq!(r(settled("", false, None)), "⇠ agent s-c blocked\n");
    }

    #[test]
    fn inbox_opened_shapes() {
        let open = |kind: InboxKind, blocking: bool, options: Vec<&str>| {
            Event::InboxOpened(InboxItem {
                item_id: "i-1".into(),
                kind,
                text: "Which?".into(),
                options: options.into_iter().map(String::from).collect(),
                blocking,
                call_id: None,
                reference: None,
            })
        };
        assert_eq!(
            render(open(InboxKind::Question, true, vec!["a", "b"]), &MONO),
            "✉ question (waiting for you)\nWhich?\n  1. a\n  2. b\n  answer: ferret answer i-1 \"…\"\n"
        );
        assert_eq!(
            render(open(InboxKind::Blocker, false, vec![]), &MONO),
            "✉ blocker\nWhich?\n  answer: ferret answer i-1 \"…\"\n"
        );
        assert_eq!(render(open(InboxKind::Finished, false, vec![]), &MONO), "✉ finished\nWhich?\n");
        let colored = render(open(InboxKind::Approval, true, vec![]), &COLOR);
        assert!(colored.starts_with("\x1b[1m\x1b[33m✉ approval (waiting for you)\x1b[0m\n"));
        assert!(colored.ends_with("\x1b[2m  answer: ferret answer i-1 \"…\"\x1b[0m\n"));
    }

    #[test]
    fn a_scope_request_shows_its_hosts_and_how_to_approve_and_no_answer_line() {
        let item = |blocking: bool, options: Vec<&str>| InboxItem {
            item_id: "i-7".into(),
            kind: InboxKind::Approval,
            text: "Needs docs.example.test to read the API reference.".into(),
            options: options.into_iter().map(String::from).collect(),
            blocking,
            call_id: None,
            reference: None,
        };
        let open = |i: InboxItem| render(Event::InboxOpened(i), &MONO);
        assert_eq!(
            open(item(false, vec!["docs.example.test", "*.cdn.test"])),
            "✉ scope request\nNeeds docs.example.test to read the API reference.\n  hosts: docs.example.test, *.cdn.test\n  approve: see ferret inbox\n"
        );
        // An approval that blocks, or names no hosts, is an ordinary approval.
        assert!(open(item(true, vec!["a.test"])).starts_with("✉ approval (waiting for you)"));
        assert!(open(item(false, vec![])).starts_with("✉ approval\n"));
        assert_eq!(scope_request_hosts(&item(false, vec!["a.test"])), Some(&["a.test".to_string()][..]));
        assert_eq!(scope_request_hosts(&item(true, vec!["a.test"])), None);
        assert!(!open(item(false, vec!["a.test"])).contains('\x1b'));
        // The listing names the exact command, quoting a host the shell would expand.
        let mut e = entry(0);
        e.item = item(false, vec!["docs.example.test", "*.cdn.test"]);
        assert_eq!(
            inbox_list(&[e], 5_000, &MONO),
            "i-7  scope request  5s  s-a  main job\n  Needs docs.example.test to read the API reference.\n  hosts: docs.example.test, *.cdn.test\n  approve: ferret scope s-a docs.example.test '*.cdn.test'\n"
        );
    }

    #[test]
    fn a_hostile_host_is_quoted_in_the_approve_command() {
        assert_eq!(shell_word("a.test"), "a.test");
        assert_eq!(shell_word("*.a.test"), "'*.a.test'");
        assert_eq!(shell_word("x';rm"), "'x'\\'';rm'");
        assert_eq!(shell_word(""), "''");
    }

    #[test]
    fn granted_hosts_are_listed_or_the_absence_is_said() {
        assert_eq!(granted_hosts_line(&[]), "No hosts granted by the operator.");
        let hosts = vec!["a.test".to_string(), "*.b.test".to_string()];
        assert_eq!(granted_hosts_line(&hosts), "Hosts granted by the operator: a.test, *.b.test");
    }

    #[test]
    fn unshown_kinds_are_empty_and_verbose_shows_requests() {
        let request = Event::ModelRequest(ModelRequest {
            req_id: "r-1".into(),
            step: 2,
            epoch: 1,
            purpose: Purpose::Step,
            n_messages: 3,
            stable_hash: "h".into(),
            hud: None,
            est_tokens: 12_345,
        });
        assert_eq!(render(request.clone(), &MONO), "");
        let verbose = RecordOpts { verbose: true, ..RecordOpts::default() };
        assert_eq!(
            record(&rec(Author::Harness, request), &MONO, &verbose),
            "#1 … request r-1 · step 2 · epoch 1 · about 12.3k tokens\n"
        );
        assert_eq!(render(Event::TurnStart { trigger: Trigger::Start }, &MONO), "");
        let net = Event::Net(NetDecision {
            host: "h".into(),
            port: 1,
            method: "GET".into(),
            allowed: true,
            rule: "r".into(),
            resolved: None,
            sni: None,
            paced_ms: None,
        });
        assert_eq!(record(&rec(Author::Harness, net), &MONO, &verbose), "");
        assert_eq!(record(&rec(Author::Harness, Event::Unknown), &MONO, &verbose), "");
    }

    #[test]
    fn continuation_and_outbox_metadata_roundtrip_without_fabricating_inference() {
        let verbose = RecordOpts { verbose: true, full: true, ..RecordOpts::default() };
        let expected = [
            "∙ continuation audit authored by call audit\n",
            "∙ controller · audit node 2 · audit · callback audit omitted\n",
            "∙ continuation audit stopped: audit\n",
            "∙ request audit observed 1 deferred outputs\n",
            "∙ child outbox audit persisted: returned\n",
        ];
        for (event, expected) in continuation_and_outbox_events("audit").into_iter().zip(expected) {
            let original = rec(Author::Harness, event);
            let encoded = serde_json::to_vec(&original).unwrap();
            let decoded: Record = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, original);
            assert_eq!(record(&decoded, &MONO, &verbose), format!("#1 {expected}"));
            let ordinary = record(&decoded, &MONO, &RecordOpts::default());
            assert_eq!(ordinary, if matches!(decoded.event, Event::StoredAction(_)) { expected } else { "" });
            for style in [MONO, COLOR] {
                let rendered = record(&decoded, &style, &verbose);
                assert!(!rendered.contains("▌ model"));
                assert!(!rendered.contains("cached"));
                assert!(!rendered.contains("1234"));
                assert!(!rendered.contains("printf literal"));
                assert!(!rendered.contains("parent-facing report"));
            }
        }
    }

    #[test]
    fn every_kind_has_no_escape_without_colour_and_ends_in_newline() {
        for event in one_of_each("plain") {
            let text = render(event, &MONO);
            no_escape(&text);
            assert!(text.is_empty() || text.ends_with('\n'));
        }
    }

    fn meta(id: &str, parent: Option<&str>, title: &str, created_ms: u64) -> SessionMeta {
        SessionMeta {
            id: SessionId::from(id),
            mission: MissionId::from("m-a"),
            intercept: false,
            parent: parent.map(SessionId::from),
            workspace: "/w".into(),
            copy_of: None,
            pack: "core".into(),
            role: "lead".into(),
            profile: "local".into(),
            model: "mm".into(),
            context_window: None,
            title: title.into(),
            created_ms,
            mode: None,
            awaited: false,
            unattended: false,
            archived: false,
            gate: None,
            prior: Vec::new(),
            role_models: Default::default(),
            target: None,
            creds: None,
        }
    }

    fn status_of(phase: Phase, last_end: Option<TurnEndReason>, outcome: Option<SessionOutcome>, open: u32) -> Status {
        Status {
            phase,
            step: 7,
            last_end,
            outcome,
            fork_point: None,
            epoch: 0,
            prompt_tokens: 12_345,
            cached_tokens: 0,
            completion_tokens_total: 0,
            open_inbox: open,
        }
    }

    fn info(id: &str, parent: Option<&str>, title: &str, status: Status) -> SessionInfo {
        SessionInfo { meta: meta(id, parent, title, 1_000), active: false, status, last_ms: None }
    }

    #[test]
    fn sessions_table_rows_and_children() {
        assert_eq!(sessions_table(&[], 0, &MONO), "No sessions.\n");
        let list = vec![
            info(
                "s-child",
                Some("s-root"),
                "look into it",
                status_of(Phase::Idle, Some(TurnEndReason::Finished), None, 0),
            ),
            info("s-root", None, "main job", status_of(Phase::Running, None, None, 1)),
            info("s-grand", Some("s-child"), "deeper", status_of(Phase::Ended, None, Some(SessionOutcome::Done), 0)),
            info("s-other", None, "second\nline", status_of(Phase::Idle, None, None, 0)),
            info("s-lost", Some("s-gone"), "orphan", status_of(Phase::Idle, Some(TurnEndReason::Asked), None, 0)),
        ];
        let text = sessions_table(&list, 61_000, &MONO);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 7);
        assert!(lines[0].starts_with("ID"));
        assert!(lines[0].contains("MISSION"));
        assert!(lines[0].ends_with("TITLE"));
        assert!(lines[1].starts_with("s-root"));
        assert!(lines[1].contains("m-a"));
        assert!(lines[1].contains("running *"));
        assert!(lines[1].contains("12.3k"));
        assert!(lines[1].ends_with("main job"));
        assert!(lines[2].starts_with("  └ s-child"), "{}", lines[2]);
        assert!(lines[2].contains("finished"));
        assert!(lines[3].starts_with("    └ s-grand"), "{}", lines[3]);
        assert!(lines[3].contains("ended (done)"));
        assert!(lines[4].starts_with("s-other"));
        assert!(lines[4].contains("new"));
        assert!(lines[4].ends_with("second line"));
        assert!(lines[5].starts_with("s-lost"));
        assert!(lines[5].contains("asked"));
        assert!(lines[4].contains("1m"));
        assert!(lines[6].contains("waiting in inbox"), "{}", lines[6]);
        // Columns line up: the ROLE column starts at the same offset on every row.
        let col = lines[0].find("ROLE").unwrap_or(usize::MAX);
        for line in &lines[1..6] {
            assert_eq!(line.chars().nth(col), Some('l'), "{line}");
        }
    }

    #[test]
    fn sessions_table_shows_the_profile_after_role() {
        let mut root = info("s-root", None, "main", status_of(Phase::Idle, None, None, 0));
        root.meta.profile = "dsv41".into();
        let mut kid = info("s-kid", Some("s-root"), "sub", status_of(Phase::Idle, None, None, 0));
        kid.meta.profile = "qwen\nx".into();
        let text = sessions_table(&[root, kid], 0, &MONO);
        let lines: Vec<&str> = text.lines().collect();
        let header: Vec<&str> = lines[0].split_whitespace().collect();
        assert_eq!(&header[..5], ["ID", "MISSION", "ROLE", "MODEL", "STATE"], "{}", lines[0]);
        let col = lines[0].find("MODEL").unwrap_or(usize::MAX);
        assert!(
            lines[1][lines[1].char_indices().nth(col).map_or(0, |(i, _)| i)..].starts_with("dsv41"),
            "{}",
            lines[1]
        );
        assert!(lines[2].contains("qwen x"), "{}", lines[2]);
        assert!(lines[2].starts_with("  └ s-kid"), "{}", lines[2]);
        let kid_col = lines[2].chars().take(col).count();
        assert_eq!(kid_col, col);
    }

    #[test]
    fn sessions_table_survives_a_parent_cycle() {
        let list = vec![
            info("s-a", Some("s-b"), "a", status_of(Phase::Idle, None, None, 0)),
            info("s-b", Some("s-a"), "b", status_of(Phase::Idle, None, None, 0)),
        ];
        let text = sessions_table(&list, 0, &MONO);
        assert_eq!(text.lines().count(), 3);
    }

    #[test]
    fn rows_never_exceed_the_width() {
        let list =
            vec![info("s-root", None, &"a very long title ".repeat(20), status_of(Phase::Running, None, None, 0))];
        for width in [10, 30, 60, 120] {
            let style = Style { color: false, width };
            for line in sessions_table(&list, 5_000, &style).lines() {
                assert!(line.chars().count() <= width, "{line:?} at {width}");
            }
        }
        let long = Style { color: false, width: 60 };
        let text = sessions_table(&list, 5_000, &long);
        assert!(text.lines().nth(1).is_some_and(|l| l.ends_with('…')));
        // Colour is applied after cutting, so a cut header still closes its colour.
        let colored = sessions_table(&list, 5_000, &Style { color: true, width: 20 });
        let header = colored.lines().next().unwrap_or("");
        assert!(header.starts_with(DIM) && header.ends_with(RESET));
        assert_eq!(header.replace(DIM, "").replace(RESET, "").chars().count(), 20);
    }

    fn entry(opened_ms: u64) -> InboxEntry {
        InboxEntry {
            session: SessionId::from("s-a"),
            mission: MissionId::from("m-a"),
            title: "main job".into(),
            opened_ms,
            item: InboxItem {
                item_id: "i-1".into(),
                kind: InboxKind::Approval,
                text: "May I?\nPlease.".into(),
                options: vec![],
                blocking: true,
                call_id: None,
                reference: None,
            },
        }
    }

    #[test]
    fn inbox_list_shapes() {
        assert_eq!(inbox_list(&[], 0, &MONO), "Nothing is waiting for you.\n");
        let text = inbox_list(&[entry(0), entry(60_000)], 3_600_000, &MONO);
        // A blocking approval that is not a scope request still needs the operator, so it names how
        // to answer — as the streaming view (`record`) does for every kind but a finished report.
        assert_eq!(
            text,
            "i-1  approval  1h  s-a  main job\n  May I?\n  Please.\n  answer: ferret answer i-1 \"…\"\ni-1  approval  59m  s-a  main job\n  May I?\n  Please.\n  answer: ferret answer i-1 \"…\"\n"
        );
        let narrow = inbox_list(&[entry(0)], 5_000, &Style { color: false, width: 12 });
        assert_eq!(narrow.lines().next().map(|l| l.chars().count()), Some(12));
    }

    #[test]
    fn a_blocking_blocker_or_park_offers_the_answer_and_closing_as_blocked() {
        let with = |kind: InboxKind, blocking: bool, options: &[&str]| {
            let mut e = entry(0);
            e.item.kind = kind;
            e.item.blocking = blocking;
            e.item.options = options.iter().map(|o| o.to_string()).collect();
            inbox_list(&[e], 5_000, &MONO)
        };
        assert_eq!(
            with(InboxKind::Blocker, true, &[]),
            "i-1  blocker  5s  s-a  main job\n  May I?\n  Please.\n  answer: ferret answer i-1 \"…\" (name the next step, not a yes or no question)\n  close as blocked: ferret release s-a \"why\"\n"
        );
        let parked = with(InboxKind::Parked, true, &["Keep working", "Accept as blocked and close"]);
        assert_eq!(
            parked,
            "i-1  parked  5s  s-a  main job\n  May I?\n  Please.\n  1. Keep working\n  2. Accept as blocked and close\n  answer: ferret answer i-1 \"…\"\n  close as blocked: ferret release s-a \"why\"\n"
        );
        // A notice that does not block is not a park.
        assert!(!with(InboxKind::Blocker, false, &[]).contains("ferret release"));
        // A question — the most common operator action — names how to answer it, with no release line.
        let question = with(InboxKind::Question, true, &[]);
        assert!(question.contains("answer: ferret answer i-1 \"…\""), "{question}");
        assert!(!question.contains("ferret release"), "{question}");
        // A finished report is cleared, not answered: it offers `dismiss`, never `answer …`.
        let finished = with(InboxKind::Finished, false, &[]);
        assert!(finished.contains("dismiss: ferret answer i-1"), "{finished}");
        assert!(!finished.contains("answer: ferret answer"), "{finished}");
    }

    fn window_item(seq: u64, state: ItemState, pinned: bool) -> WindowItem {
        WindowItem {
            seq,
            kind: "tool_result".into(),
            role: Role::Tool,
            chars: 1234,
            state,
            pinned,
            call_id: None,
            class: None,
            preview: "first\nline".into(),
            note: None,
            image_tokens: 0,
        }
    }

    #[test]
    fn window_table_shapes() {
        let mut view = WindowView {
            epoch: 2,
            items: vec![],
            est_tokens: 123_456,
            target_tokens: 800_000,
            floor_tokens: 400_000,
            context_window: None,
            prompt_tokens: 120_000,
            cached_tokens: 90_000,
            ..Default::default()
        };
        let empty = window_table(&view, &Style { color: false, width: 200 });
        assert_eq!(
            empty,
            "epoch 2 · about 123.4k tokens in view · folds at 800.0k down to 400.0k · window unknown · last request 120.0k in, 75% cached\nThe window holds no items.\n"
        );
        view.context_window = Some(1_000_000);
        view.items = vec![window_item(3, ItemState::Live, false), window_item(14, ItemState::Stubbed, true)];
        let text = window_table(&view, &MONO);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].contains("window 1.00M"));
        assert!(lines[1].starts_with("SEQ"));
        assert!(lines[2].starts_with("#3 "));
        assert!(lines[2].contains("live"));
        assert!(lines[2].ends_with("first line"));
        assert!(lines[3].starts_with("#14"));
        assert!(lines[3].contains("stubbed"));
        assert!(lines[3].contains("pinned"));
        for line in &lines {
            assert!(line.chars().count() <= 100);
        }
    }

    fn health(reachable: bool) -> ferret_agent::runtime::ModelHealth {
        ferret_agent::runtime::ModelHealth {
            profile: "local".into(),
            base_url: "http://10.0.0.1:8000/v1".into(),
            model: "big".into(),
            reachable,
            detail: if reachable { String::new() } else { "connection refused".into() },
            context_window: if reachable { Some(1_000_000) } else { None },
            max_concurrent: 4,
            vision: false,
        }
    }

    #[test]
    fn models_list_reload_report_and_switch_line_shapes() {
        let mut other = health(false);
        other.profile = "other".into();
        let view = ModelsView { default_model: "local".into(), models: vec![health(true), other] };
        assert_eq!(
            models_table(&view, &MONO),
            concat!(
                "✓ local (default) · big · http://10.0.0.1:8000/v1 · window 1.00M · 4 at once · vision no\n",
                "✗ other · big · http://10.0.0.1:8000/v1 · window unknown · 4 at once · vision no\n",
                "  error: connection refused\n",
            )
        );
        let none = ModelsView { default_model: String::new(), models: vec![health(true)] };
        assert!(models_table(&none, &MONO).ends_with("no default_model: a new session names its model with --model\n"));
        assert_eq!(
            models_table(&ModelsView { default_model: String::new(), models: vec![] }, &MONO),
            "No model profiles are configured.\n"
        );

        assert_eq!(models_reload(&ModelsReload::default()), "No profile changed.\ndefault model: none\n");
        let report = ModelsReload {
            added: vec!["fast".into()],
            changed: vec!["big".into()],
            removed: vec!["old".into()],
            default_model: "big".into(),
            rebound: vec![SessionId::from("s-1"), SessionId::from("s-2")],
            notes: vec!["\"old\" is no longer configured".into()],
        };
        assert_eq!(
            models_reload(&report),
            "added: fast\nchanged: big\nremoved: old\n2 sessions moved to the new settings of a changed profile\ndefault model: big\n! \"old\" is no longer configured\n"
        );

        let receipt = |live: bool| ModelSwitchReceipt {
            session: SessionId::from("s-1"),
            model: ferret_core::event::ModelRef {
                profile: "fast".into(),
                model: "m".into(),
                context_window: 200_000,
                lineage: None,
            },
            live,
        };
        assert_eq!(model_switch_line(&receipt(true)), "s-1 now uses fast (m, window 200.0k), from its next step");
        assert_eq!(model_switch_line(&receipt(false)), "s-1 now uses fast (m, window 200.0k), when it next runs");
    }

    #[test]
    fn mission_models_and_role_receipt_shapes() {
        use ferret_agent::runtime::{AgentModel, MissionModels, RoleModelReceipt, RoleModels};
        let role = |name: &str, verifier: bool| RoleModels {
            role: name.into(),
            verifier,
            chosen: None,
            pack_model: None,
            alloy_models: vec![],
            escalation_model: None,
            agents: vec![],
        };
        let mut worker = role("worker", false);
        worker.chosen = Some("fast".into());
        worker.agents = vec![
            AgentModel { session: SessionId::from("s-a"), profile: "fast".into(), forked: false },
            AgentModel { session: SessionId::from("s-b"), profile: "big".into(), forked: true },
        ];
        let mut solver = role("solver", false);
        solver.alloy_models = vec!["big".into(), "fast".into()];
        solver.escalation_model = Some("huge".into());
        let mut verifier = role("verifier", true);
        verifier.pack_model = Some("big".into());
        let mut m = MissionModels {
            mission: ferret_core::MissionId::from("m-1"),
            lead: SessionId::from("s-l"),
            lead_model: ferret_core::event::ModelRef {
                profile: "big".into(),
                model: "b".into(),
                context_window: 1_000_000,
                lineage: None,
            },
            any_role: None,
            roles: vec![worker, solver, verifier],
            profiles: vec!["big".into(), "fast".into()],
            default_model: "big".into(),
        };
        assert_eq!(
            mission_models_table(&m, &MONO),
            "mission m-1 · lead s-l on big (b, window 1.00M)\n\
             agents of every role: as each role's pack setting says\n\
             worker    fast (chosen) · running: s-a on fast, s-b on big (forked)\n\
             solver    pack: rotates big, fast, huge after a failed agent · running: none\n\
             verifier  pack: big · finish gate · running: none\n\
             profiles: big (default), fast\n"
        );
        // A choice for every role covers the roles without their own, not the finish gate's verifier.
        m.any_role = Some("fast".into());
        let text = mission_models_table(&m, &MONO);
        assert!(
            text.contains("agents of every role: fast\n") && text.contains("solver    fast (every role) ·"),
            "{text}"
        );
        assert!(text.contains("verifier  pack: big · finish gate"), "{text}");

        let r = RoleModelReceipt { switched: vec![SessionId::from("s-a")], models: m.clone() };
        assert!(role_model_receipt(&r, "worker", Some("fast"), &MONO)
            .starts_with("agents of `worker` start on fast from now on\nmoved now: s-a\nmission m-1"));
        let cleared = RoleModelReceipt { switched: vec![], models: m };
        assert!(role_model_receipt(&cleared, "*", None, &MONO)
            .starts_with("the choice for every role is cleared: the pack chooses again\nmission m-1"));
    }

    #[test]
    fn status_shapes() {
        let mut view = StatusView {
            version: "0.1.0".into(),
            pid: 42,
            started_ms: 0,
            bind: "127.0.0.1:7878".into(),
            proxy_port: 7879,
            home: "/home/u/.ferret".into(),
            sandbox: "seatbelt".into(),
            network: "deny_all".into(),
            disk: Some(crate::wire::DiskSpace { free_bytes: 400 << 30, total_bytes: (1000 << 30) + (1 << 29) }),
            models: vec![health(true), health(false)],
            sessions_total: 5,
            sessions_active: 2,
            sessions_running: 1,
            inbox_open: 3,
            egress: None,
            monitor: None,
            default_model: Some("local".into()),
            signal: None,
        };
        assert_eq!(
            status(&view, &MONO),
            concat!(
                "ferret 0.1.0 · pid 42 · 127.0.0.1:7878 · proxy port 7879 · home /home/u/.ferret\n",
                "sandbox: seatbelt · network: deny_all\n",
                "400.0 GiB free of 1000.5 GiB (39%) on the volume of the ferret home\n",
                "✓ local (default) · big · http://10.0.0.1:8000/v1 · window 1.00M\n",
                "✗ local (default) · big · http://10.0.0.1:8000/v1 · window unknown\n",
                "  error: connection refused\n",
                "5 sessions · 2 active · 1 running · 3 waiting in the inbox\n",
            )
        );
        let colored = status(&view, &COLOR);
        assert!(colored.contains("\x1b[32m✓\x1b[0m local"));
        assert!(colored.contains("\x1b[31m✗\x1b[0m local"));
        // Signal health is rendered when enabled, with uncut error detail on the next line.
        view.signal = Some(SignalStatusView {
            enabled: true,
            connected: false,
            account: "+15550100".into(),
            recipient: "+15550199".into(),
            last_event_ms: None,
            last_send_ms: None,
            last_error: Some("UNTRUSTED_IDENTITY: trust safety number".into()),
            dropped_events: 2,
            pending_sends: 1,
            muted_until_ms: Some(999999),
        });
        let with_sig = status(&view, &MONO);
        assert!(
            with_sig.contains("✗ signal: disconnected · +15550100 -> +15550199 · pending 1 · dropped 2 · muted\n"),
            "{with_sig}"
        );
        assert!(with_sig.contains("  error: UNTRUSTED_IDENTITY: trust safety number\n"), "{with_sig}");
        view.signal = None;
        // An unsafe posture (unconfined, or open network) is warned in bold yellow.
        view.sandbox = "none".into();
        assert!(
            status(&view, &COLOR).contains(&format!("{BOLD_YELLOW}sandbox: none · network: deny_all{RESET}")),
            "{}",
            status(&view, &COLOR)
        );
        assert!(status(&view, &MONO).contains("\nsandbox: none · network: deny_all\n"));
        view.sandbox = "seatbelt".into();
        view.models.clear();
        assert!(status(&view, &MONO).contains("no models configured\n"));
        let narrow = status(&view, &Style { color: false, width: 20 });
        for line in narrow.lines() {
            assert!(line.chars().count() <= 20, "{line}");
        }
    }

    #[test]
    fn status_shows_the_egress_line_when_the_daemon_reports_one() {
        use ferret_agent::egress::{EgressView, Level};
        let mut view = StatusView {
            version: "0.1.0".into(),
            pid: 1,
            started_ms: 0,
            bind: "127.0.0.1:7878".into(),
            proxy_port: 7879,
            home: "/h".into(),
            sandbox: "seatbelt".into(),
            network: "deny_all".into(),
            disk: None,
            models: vec![],
            sessions_total: 0,
            sessions_active: 0,
            sessions_running: 0,
            inbox_open: 0,
            egress: None,
            monitor: None,
            default_model: None,
            signal: None,
        };
        assert!(!status(&view, &MONO).contains("egress"), "an older daemon says nothing");
        view.egress = Some(EgressView { level: Level::Unprobed, ..EgressView::default() });
        assert!(status(&view, &MONO).contains("egress: not probed yet\n"));
        view.egress = Some(EgressView {
            level: Level::Unbounded,
            reasons: vec!["sandbox.allow_fetch_services is set".into(), "second".into()],
            ..EgressView::default()
        });
        let plain = status(&view, &MONO);
        assert!(plain.contains("egress: UNBOUNDED, sandbox.allow_fetch_services is set (+1 more)\n"), "{plain}");
        assert!(status(&view, &COLOR).contains("\x1b[1m\x1b[33megress: UNBOUNDED"), "{}", status(&view, &COLOR));
        let narrow = status(&view, &Style { color: false, width: 20 });
        for line in narrow.lines() {
            assert!(line.chars().count() <= 20, "{line}");
        }
    }

    #[test]
    fn wrap_display_rows_handles_tabs_wide_chars_and_uncut_inbox_commands() {
        let rows = wrap_display_rows("a\tb", 8);
        assert_eq!(rows, vec!["a    b"]);
        // CJK chars occupy 2 display columns each: 3 CJK chars = 6 cols, wraps at width 4 -> 2 chars + 1 char.
        let cjk = wrap_display_rows("日本語", 4);
        assert_eq!(cjk, vec!["日本", "語"]);
        // Inbox scope/answer command hints are never truncated even on narrow terminals.
        let mut e = entry(0);
        e.item.kind = InboxKind::Approval;
        e.item.blocking = false;
        e.item.options =
            vec!["api.staging.example.com".into(), "auth.staging.example.com".into(), "cdn.staging.example.com".into()];
        let narrow = inbox_list(&[e], 5_000, &Style { color: false, width: 40 });
        assert!(
            narrow.contains(
                "  approve: ferret scope s-a api.staging.example.com auth.staging.example.com cdn.staging.example.com\n"
            ),
            "{narrow}"
        );
    }

    #[test]
    fn window_compacts_at_without_down_to_zero_and_uses_measured_now() {
        let view = WindowView {
            epoch: 1,
            items: vec![],
            est_tokens: 50_000,
            target_tokens: 400_000,
            floor_tokens: 0,
            context_window: Some(1_000_000),
            prompt_tokens: 60_000,
            cached_tokens: 30_000,
            measured_now: Some(55_000),
            fold_at: Some(400_000),
            ..Default::default()
        };
        let text = window_table(&view, &Style { color: false, width: usize::MAX });
        assert!(text.contains("55.0k tokens in view"), "{text}");
        assert!(text.contains("compacts at 400.0k"), "{text}");
        assert!(!text.contains("down to 0"), "{text}");
    }

    #[test]
    fn target_and_creds_renderers_sanitize_escapes_and_new_views_render() {
        let t = ferret_agent::runtime::TargetView {
            name: EVIL.into(),
            scope: vec![EVIL.into()],
            exclude: vec![EVIL.into()],
            upstream_insecure: vec![],
            intercept_passthrough: vec![],
            notes: EVIL.into(),
            counts: Default::default(),
        };
        no_escape(&target_list(std::slice::from_ref(&t)));
        no_escape(&target_show(&t));
        assert_eq!(
            target_nodes(&ferret_agent::runtime::GraphView { name: "t".into(), nodes: vec![], edges: vec![] }),
            "No nodes.\n"
        );

        let p = ferret_core::creds::ProfileSummary {
            profile: EVIL.into(),
            cookies: 1,
            headers: 2,
            hosts: vec![EVIL.into()],
            recorded_ms: 0,
            error: Some(EVIL.into()),
        };
        no_escape(&creds_summary_row(&p));
        let show = ProfileShow {
            summary: p,
            items: vec![ferret_core::creds::ItemView {
                kind: ferret_core::creds::ItemKind::Cookie,
                name: EVIL.into(),
                host: EVIL.into(),
            }],
        };
        no_escape(&creds_show(&show));

        // UserMessage with images renders attachment notice.
        let img_msg = render(
            Event::UserMessage {
                text: String::new(),
                images: vec![ferret_core::ImageRef {
                    blob: "abc".into(),
                    mime: "image/png".into(),
                    bytes: 10,
                    width: 1,
                    height: 1,
                    name: None,
                }],
            },
            &MONO,
        );
        assert_eq!(img_msg, "▌ you\n  [1 image attached]\n");

        // Exchange can be hidden via hide_exchanges.
        let ex = Event::Exchange(Exchange {
            id: "ex-1".into(),
            call_id: None,
            source: "proxy".into(),
            tool: None,
            scheme: "https".into(),
            tls: "intercepted".into(),
            method: "GET".into(),
            host: "a.test".into(),
            port: 443,
            target: "/".into(),
            status: Some(200),
            error: None,
            request: blob(),
            response: None,
            request_bytes: 10,
            response_bytes: 20,
            truncated: false,
            upstream_unverified: false,
            duration_ms: 5,
        });
        assert!(!record(&rec(Author::Harness, ex.clone()), &MONO, &RecordOpts::default()).is_empty());
        assert_eq!(
            record(&rec(Author::Harness, ex), &MONO, &RecordOpts { hide_exchanges: true, ..RecordOpts::default() }),
            ""
        );

        // Packs, findings, traffic, noise, queued, rewrite tables.
        let packs = vec![PackView {
            name: "core".into(),
            description: "General".into(),
            default_role: "lead".into(),
            intercept: false,
            requires_restricted_network: false,
            roles: vec![ferret_agent::runtime::RoleView {
                name: "lead".into(),
                description: "Owns mission".into(),
                starts_agents: true,
                top_level: true,
            }],
        }];
        let pt = packs_list(&packs, &MONO);
        assert!(pt.contains("core (default role: lead)") && pt.contains("lead (default, spawns)"), "{pt}");
        assert_eq!(rewrite_rules_table(&[], &MONO), "No proxy rewrite rules configured.\n");
        let rt = rewrite_rules_table(
            &[
                serde_json::json!({"id": 1, "enabled": true, "phase": "request", "priority": 0, "name": "auth", "actions": [{}], "note": "n"}),
            ],
            &MONO,
        );
        assert!(rt.contains("enabled") && rt.contains("auth"), "{rt}");
        assert_eq!(queued_list(&[], 0, &MONO), "No queued messages.\n");
        assert!(findings_table(&LedgerState::default(), false, None, &MONO).contains("No findings recorded."));
    }

    #[test]
    fn status_warns_below_5_gib_or_5_percent_free_and_says_when_space_is_unknown() {
        use crate::wire::DiskSpace;
        let g = |n: u64| n << 30;
        let with = |disk: Option<DiskSpace>| StatusView {
            version: "0.1.0".into(),
            pid: 42,
            started_ms: 0,
            bind: "127.0.0.1:7878".into(),
            proxy_port: 7879,
            home: "/home/u/.ferret".into(),
            // This test indexes lines by position and is about disk, not posture: leave the sandbox line
            // off (the renderer skips it when the field is empty).
            sandbox: String::new(),
            network: String::new(),
            disk,
            models: vec![health(true)],
            sessions_total: 0,
            sessions_active: 0,
            sessions_running: 0,
            inbox_open: 0,
            egress: None,
            monitor: None,
            default_model: None,
            signal: None,
        };
        let warning = "! Low disk space: sessions will fail when the disk fills. Run `ferret gc`.\n";
        // (free, total, low): under 5 GiB whatever the volume, under 5 percent whatever the bytes; neither at the line.
        let cases = [(g(5) - 1, g(20), true), (g(5), g(100), false), (g(49), g(1000), true), (g(50), g(1000), false)];
        for (free, total, low) in cases {
            let disk = DiskSpace { free_bytes: free, total_bytes: total };
            assert_eq!(disk.is_low(), low, "{disk:?}");
            let text = status(&with(Some(disk)), &MONO);
            let lines: Vec<&str> = text.lines().collect();
            assert!(
                lines[1].contains(" free of ") && lines[1].ends_with(" on the volume of the ferret home"),
                "{text}"
            );
            assert_eq!(text.contains(warning), low, "{text}");
            if low {
                assert_eq!(format!("{}\n", lines[2]), warning);
            }
        }
        let low = with(Some(DiskSpace { free_bytes: g(1), total_bytes: g(500) }));
        assert!(status(&low, &MONO).starts_with(&format!(
            "ferret 0.1.0 · pid 42 · 127.0.0.1:7878 · proxy port 7879 · home /home/u/.ferret\n\
             1.0 GiB free of 500.0 GiB (0%) on the volume of the ferret home\n{warning}"
        )));
        assert!(status(&low, &COLOR).contains(&format!("{BOLD_YELLOW}{}{RESET}\n", warning.trim_end())));
        let unknown = status(&with(None), &MONO);
        assert!(unknown.contains("\nfree space on the volume of the ferret home: unknown\n"), "{unknown}");
        assert!(!unknown.contains(warning));
    }

    #[test]
    fn net_table_shapes() {
        assert_eq!(net_table(&[], &MONO), "No network decisions.\n");
        let e = |ts_ms: u64, allowed: bool| NetEntry {
            ts_ms,
            decision: NetDecision {
                host: "example.test".into(),
                port: 443,
                method: "CONNECT".into(),
                allowed,
                rule: "default deny".into(),
                resolved: None,
                sni: None,
                paced_ms: None,
            },
        };
        let text = net_table(&[e(3_723_000, false), e(86_400_000 + 59_000, true)], &MONO);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("TIME"));
        assert!(lines[1].starts_with("01:02:03  denied "));
        assert!(lines[1].contains("CONNECT  example.test:443  default deny"));
        assert!(lines[2].starts_with("00:00:59  allowed"));
    }

    #[test]
    fn score_table_shapes() {
        use ferret_agent::runtime::SessionScore;
        use ferret_core::scorecard::Scorecard;
        let lead = Scorecard {
            steps: 10,
            finished: true,
            steps_to_finish: Some(10),
            calls: 12,
            malformed_calls: 3,
            finish_calls: 2,
            finish_refusals: 1,
            quote_refusals: 2,
            verifier_accepts: 1,
            verifier_rejections: 1,
            fresh_starts: 1,
            hand_offs: 0,
            asks: 1,
            unrecorded: false,
            ..Scorecard::default()
        };
        let verifier = Scorecard { steps: 2, calls: 2, ..Scorecard::default() };
        let scored = |id: &str, role: &str, parent: Option<&str>, card: &Scorecard| SessionScore {
            session: SessionId::from(id),
            role: role.into(),
            parent: parent.map(SessionId::from),
            card: card.clone(),
        };
        // One session: its row, and no total to repeat it.
        let alone = ScoreView {
            mission: MissionId::from("m-1"),
            sessions: vec![scored("s-lead", "lead", None, &lead)],
            total: lead.clone(),
        };
        let expected = "\
SESSION  ROLE  STEPS  TO FINISH  CALLS  MALFORMED  FINISH REFUSED  QUOTE REFUSED  VERIFIER  FRESH STARTS  HAND OFFS  ASKS
s-lead   lead  10     10         12     3 (25%)    1 of 2          2              1 of 2    1             0          1
";
        assert_eq!(score_table(&alone, &MONO), expected);

        // Several: the others under the lead, then the total. A row is not cut to the width.
        let mut total = lead.clone();
        total.add(&verifier);
        total.add(&verifier);
        let view = ScoreView {
            mission: MissionId::from("m-1"),
            sessions: vec![
                scored("s-lead", "lead", None, &lead),
                scored("s-check-1", "verifier", Some("s-lead"), &verifier),
                scored("s-check-2", "verifier", Some("s-lead"), &verifier),
            ],
            total,
        };
        let narrow = Style { color: false, width: 40 };
        let expected = "\
SESSION        ROLE      STEPS  TO FINISH  CALLS  MALFORMED  FINISH REFUSED  QUOTE REFUSED  VERIFIER  FRESH STARTS  HAND OFFS  ASKS
s-lead         lead      10     10         12     3 (25%)    1 of 2          2              1 of 2    1             0          1
  └ s-check-1  verifier  2      -          2      0 (0%)     0 of 0          0              -         0             0          0
  └ s-check-2  verifier  2      -          2      0 (0%)     0 of 0          0              -         0             0          0
total                    14     10         16     3 (19%)    1 of 2          2              1 of 2    1             0          1
";
        assert_eq!(score_table(&view, &narrow), expected);

        // A log from before the facts were recorded: `?`, and a line that says what it means.
        let old = Scorecard { unrecorded: true, ..lead.clone() };
        let view = ScoreView {
            mission: MissionId::from("m-1"),
            sessions: vec![scored("s-\x1b[31mold", "lead", None, &old)],
            total: old,
        };
        let text = score_table(&view, &MONO);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[1].starts_with("s-·[31mold  lead  10") && lines[1].contains("  ?  "), "{text}");
        assert_eq!(
            lines[2],
            "? = not recorded: this log was written before ferret recorded verdicts and quote refusals."
        );
        assert!(!text.contains('\x1b'));
        assert!(score_table(&view, &COLOR).contains(DIM));
    }
}
