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
//!   lines` and, when the result has a stored output, ` — loom out {handle}` (dim). The first line
//!   is red when the status is not `Ok`.
//! - `reweave`: `⟲ context re-woven ({reason}): {evictions} items folded out of view, about
//!   {tokens(before)} → {tokens(after)} tokens` (yellow).
//! - `pin` / `unpin`: `∙ pinned {call_id}: {reason}` / `∙ unpinned {call_id}` (dim).
//! - `child_spawned`: `⇢ agent {child} ({role}, {mode}): {brief.question}` (cyan).
//! - `child_settled`: `⇠ agent {child} {outcome word}` (cyan), then the report indented two spaces,
//!   cut like a tool result. An `inline` settlement prints only the first line.
//! - `job_registered`: `⚙ job {job_id}: {command}`; `job_settled`: `⚙ job {job_id} ended: {detail}`;
//!   `job_matched`: `⚙ job {job_id} wrote {matches} line(s) matching /{pattern}/`.
//! - `inbox_opened`: `✉ {kind}` + ` (waiting for you)` when blocking (bold yellow), the text, the
//!   options numbered `  1. …`, then `  answer: loom answer {item_id} "…"` (dim) unless the kind is
//!   `Finished`. A scope request (see [`scope_request_hosts`]) is `✉ scope request`, the text, `  hosts: a, b`
//!   and `  approve: see loom inbox` (dim); it has no answer line, since answering it grants nothing.
//! - `inbox_resolved`: `✉ answered: {answer}` (`✉ dismissed` for an empty answer).
//! - `ledger`: `▪ ledger #{n}: {summary}` (dim).
//! - `cache_break`: `! cache break at message {first_diff_message}: {detail}` (yellow).
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
//!   parent (`  └ `): `ID  ROLE  STATE  STEP  CONTEXT  AGE  TITLE`. `STATE`: `running`, `ended
//!   ({outcome})`, else the last turn end in the words above, else `new`; ` *` appended when
//!   `open_inbox > 0`. `CONTEXT`: `tokens(prompt_tokens)`. Empty list: `No sessions.`
//! - `inbox_list(list, now_ms, style)`: per item `{item_id}  {kind}  {age}  {session} {title}` and
//!   the text indented, then the options numbered; `Nothing is waiting for you.` when empty. A scope
//!   request is listed as `scope request`, with `hosts: a, b` and `approve: loom scope {session} a b`
//!   (a host with a character the shell would read is single-quoted). A blocking `Blocker` or `Parked`
//!   item gets the ways to answer it: `answer: loom answer {item_id} "…"` and `close as blocked: loom
//!   release {session} "why"`; a blocker also says to name the next step, not ask a yes or no question.
//!   `granted_hosts_line(hosts)` is the line `loom net` ends with.
//! - `window_table(view, style)`: a summary line (`epoch {e} · about {tokens} tokens in view ·
//!   folds at {target} down to {floor} · window {context_window or "unknown"} · last request
//!   {prompt} in, {pct}% cached`), then per item `#{seq}  {kind}  {state}  {chars}  {pin}
//!   {preview}`.
//! - `status(view, style)`: the daemon line; the free space of the volume of the loom home (`{free}
//!   GiB free of {total} GiB ({pct}%) on the volume of the loom home`, or `unknown`) and, when it is low
//!   (`DiskSpace::is_low`), a warning that sessions will fail when the disk fills (bold yellow); one
//!   line per model (`✓`/`✗`, base URL, model, window, detail when unreachable); the counts.
//! - `net_table(entries, style)`: `TIME  VERDICT  METHOD  HOST:PORT  RULE` (time as `HH:MM:SS` UTC).
//! - `score_table(view, style)`: what a mission's work took. `SESSION  ROLE`, then the headings of
//!   `loom_core::scorecard::COLUMNS` in capitals; one row per session with its `Scorecard::cells()`
//!   (a session with a parent as `  └ {id}`), and for a mission of more than one session a last row
//!   `total` with the view's total. Unlike the other listings its rows are not cut to the width: a
//!   number cut off at the right edge would read as not there. When a card is `unrecorded`, a line
//!   (dim) follows saying what `?` means: `? = not recorded: this log was written before loom recorded
//!   verdicts and quote refusals.`
//!
//! Tests required: every record kind (the shape above, with and without colour — no escape byte
//! without colour); `clean` on escape sequences; reasoning shown/hidden; output cutting with and
//! without a handle and with `full`; each small format at its boundaries; each listing including
//! the empty cases and the child indentation; rows never exceed `width` characters; the score table
//! for one session and for several, with a card that is not recorded, wider than the width.

use crate::wire::StatusView;
use loom_agent::runtime::{InboxEntry, NetEntry, ScoreView, SessionInfo, WindowView};
use loom_agent::session::Phase;
use loom_core::event::{
    Author, ChildOutcome, Event, FinishReason, InboxItem, InboxKind, Record, SessionOutcome, SpawnMode, ToolStatus,
    TurnEndReason,
};
use loom_core::scorecard::COLUMNS;
use loom_core::weave::ItemState;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    pub color: bool,
    /// Terminal width in characters.
    pub width: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordOpts {
    /// Print reasoning in full.
    pub reasoning: bool,
    /// Never cut arguments, outputs or reports.
    pub full: bool,
    /// Print request records too.
    pub verbose: bool,
    pub max_output_lines: usize,
}

impl Default for RecordOpts {
    fn default() -> Self {
        RecordOpts { reasoning: false, full: false, verbose: false, max_output_lines: 40 }
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

pub fn cut(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
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

/// The hosts a session has been granted, as `loom net` ends: the operator's grants, or that there are none.
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
        notice.push_str(&format!(" — loom out {handle}"));
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
        Event::UserMessage { text } => {
            out.push(paint(style, CYAN, "▌ you"));
            push_block(&mut out, style, None, text, "");
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
                out.push(paint(style, DIM, "  approve: see loom inbox"));
                return finish(out);
            }
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
                let hint = format!("  answer: loom answer {} \"…\"", item.item_id);
                out.push(paint(style, DIM, &hint));
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

fn session_state(info: &SessionInfo) -> String {
    let st = &info.status;
    let mut state = match st.phase {
        Phase::Running => "running".to_string(),
        Phase::Ended => match st.outcome {
            Some(outcome) => format!("ended ({})", session_outcome_words(outcome)),
            None => "ended".to_string(),
        },
        Phase::Idle => st.last_end.map_or("new", turn_end_words).to_string(),
    };
    if st.open_inbox > 0 {
        state.push_str(" *");
    }
    state
}

pub fn sessions_table(list: &[SessionInfo], now_ms: u64, style: &Style) -> String {
    if list.is_empty() {
        return "No sessions.\n".to_string();
    }
    let rows: Vec<Vec<String>> = session_order(list)
        .into_iter()
        .map(|(s, depth)| {
            let id = if depth == 0 {
                flat(s.meta.id.as_str())
            } else {
                format!("{}  └ {}", "  ".repeat(depth.saturating_sub(1)), flat(s.meta.id.as_str()))
            };
            vec![
                id,
                flat(&s.meta.role),
                flat(&session_state(s)),
                s.status.step.to_string(),
                tokens(s.status.prompt_tokens),
                age(now_ms.saturating_sub(s.meta.created_ms)),
                flat(&s.meta.title),
            ]
        })
        .collect();
    table(style, &["ID", "ROLE", "STATE", "STEP", "CONTEXT", "AGE", "TITLE"], &rows)
}

pub fn inbox_list(list: &[InboxEntry], now_ms: u64, style: &Style) -> String {
    if list.is_empty() {
        return "Nothing is waiting for you.\n".to_string();
    }
    let mut out = Vec::new();
    for entry in list {
        let head = format!(
            "{}  {}  {}  {} {}",
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
        let dim = |text: String| paint(style, DIM, &cut(&text, width_of(style)));
        if let Some(hosts) = scope {
            let shown: Vec<String> = hosts.iter().map(|h| flat(h)).collect();
            out.push(format!("  hosts: {}", shown.join(", ")));
            let args: Vec<String> = shown.iter().map(|h| shell_word(h)).collect();
            out.push(dim(format!(
                "  approve: loom scope {} {}",
                shell_word(&flat(entry.session.as_str())),
                args.join(" ")
            )));
            continue;
        }
        for (i, option) in item.options.iter().enumerate() {
            out.push(format!("  {}. {}", i + 1, flat(option)));
        }
        if item.blocking && matches!(item.kind, InboxKind::Blocker | InboxKind::Parked) {
            let next =
                if item.kind == InboxKind::Blocker { " (name the next step, not a yes or no question)" } else { "" };
            out.push(dim(format!("  answer: loom answer {} \"…\"{next}", flat(&item.item_id))));
            let session = shell_word(&flat(entry.session.as_str()));
            out.push(dim(format!("  close as blocked: loom release {session} \"why\"")));
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
    let summary = format!(
        "epoch {} · about {} tokens in view · folds at {} down to {} · window {} · last request {} in, {}% cached",
        view.epoch,
        tokens(view.est_tokens),
        tokens(view.target_tokens),
        tokens(view.floor_tokens),
        window,
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

/// What `status` says when the volume of the loom home is nearly full (`DiskSpace::is_low`).
const LOW_DISK_WARNING: &str = "! Low disk space: sessions will fail when the disk fills. Run `loom gc`.";

/// Bytes in GiB with one decimal, rounded down: `0.4 GiB`, `926.4 GiB`.
fn gib(bytes: u64) -> String {
    let tenths = u128::from(bytes) * 10 / (1u128 << 30);
    format!("{}.{} GiB", tenths / 10, tenths % 10)
}

pub fn status(view: &StatusView, style: &Style) -> String {
    let width = width_of(style);
    let mut out = Vec::new();
    let daemon = format!(
        "loom {} · pid {} · {} · proxy port {} · home {}",
        view.version, view.pid, view.bind, view.proxy_port, view.home
    );
    out.push(cut(&flat(&daemon), width));
    match &view.disk {
        Some(disk) => {
            let (free, total) = (disk.free_bytes, disk.total_bytes);
            let pct = percent(free, total);
            let line = format!("{} free of {} ({pct}%) on the volume of the loom home", gib(free), gib(total));
            out.push(cut(&line, width));
            if disk.is_low() {
                out.push(paint(style, BOLD_YELLOW, &cut(LOW_DISK_WARNING, width)));
            }
        }
        None => out.push(cut("free space on the volume of the loom home: unknown", width)),
    }
    if view.models.is_empty() {
        out.push("no models configured".to_string());
    }
    for m in &view.models {
        let mark = if m.reachable { paint(style, GREEN, "✓") } else { paint(style, RED, "✗") };
        let window = m.context_window.map_or_else(|| "unknown".to_string(), tokens);
        let mut text = format!("{} · {} · window {}", flat(&m.base_url), flat(&m.model), window);
        if !m.reachable && !m.detail.is_empty() {
            text.push_str(&format!(" · {}", flat(&m.detail)));
        }
        // The mark takes two columns; the rest of the line is cut to what is left.
        out.push(format!("{mark} {}", cut(&text, width.saturating_sub(2))));
    }
    let counts = format!(
        "{} sessions · {} active · {} running · {} waiting in the inbox",
        view.sessions_total, view.sessions_active, view.sessions_running, view.inbox_open
    );
    out.push(cut(&counts, width));
    finish(out)
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
        let note = "? = not recorded: this log was written before loom recorded verdicts and quote refusals.";
        text.push_str(&paint(style, DIM, note));
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_agent::runtime::SessionMeta;
    use loom_agent::session::Status;
    use loom_core::blob::BlobRef;
    use loom_core::event::*;
    use loom_core::ids::{BlobId, CallId, MissionId, SessionId};
    use loom_core::message::Role;
    use loom_core::weave::WindowItem;
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
            call_id: CallId::from("c1"),
            name: "bash".into(),
            status,
            text: text.into(),
            output,
            cut: false,
            class: ToolClass::Exec,
            meta: Map::new(),
            duration_ms: 5,
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
                model: ModelRef { profile: s.into(), model: s.into(), context_window: 1000 },
                reasoning_replay: ReasoningReplay::All,
                system_prompt: s.into(),
                tools: vec![],
                budget: budget.clone(),
                unattended: true,
                schema: loom_core::event::SCHEMA,
                title: s.into(),
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
            Event::UserMessage { text: s.into() },
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
            }),
            Event::CacheBreak { req_id: s.into(), first_diff_message: 2, detail: s.into() },
            Event::Interrupted { reason: s.into() },
            Event::TurnEnd { reason: TurnEndReason::Finished },
            Event::SessionEnd { outcome: SessionOutcome::Failed, detail: s.into() },
            Event::Unknown,
        ];
        events.extend(continuation_and_outbox_events(s));
        events
    }

    #[test]
    fn no_raw_escape_survives_for_any_kind() {
        let opts = RecordOpts { reasoning: true, full: true, verbose: true, max_output_lines: 40 };
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
            model: ModelRef { profile: "local".into(), model: "mm".into(), context_window: 1 },
            reasoning_replay: ReasoningReplay::All,
            system_prompt: String::new(),
            tools: vec![],
            budget: Budget::default(),
            unattended: false,
            schema: loom_core::event::SCHEMA,
            title: String::new(),
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
        assert_eq!(render(Event::UserMessage { text: "hi\nthere".into() }, &MONO), "▌ you\nhi\nthere\n");
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
        assert_eq!(render(Event::UserMessage { text: "x".into() }, &COLOR), "\x1b[36m▌ you\x1b[0m\nx\n");
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
            format!("← line 1\n  line 2\n  line 3\n  … 7 more lines — loom out out:{}\n", "ab".repeat(8))
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
        assert!(dim.ends_with(&format!("  \x1b[2m… 7 more lines — loom out out:{}\x1b[0m\n", "ab".repeat(8))));
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
            format!("⇠ agent s-c blocked\n  a\n  b\n  … 2 more lines — loom out out:{}\n", "ab".repeat(8))
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
            "✉ question (waiting for you)\nWhich?\n  1. a\n  2. b\n  answer: loom answer i-1 \"…\"\n"
        );
        assert_eq!(
            render(open(InboxKind::Blocker, false, vec![]), &MONO),
            "✉ blocker\nWhich?\n  answer: loom answer i-1 \"…\"\n"
        );
        assert_eq!(render(open(InboxKind::Finished, false, vec![]), &MONO), "✉ finished\nWhich?\n");
        let colored = render(open(InboxKind::Approval, true, vec![]), &COLOR);
        assert!(colored.starts_with("\x1b[1m\x1b[33m✉ approval (waiting for you)\x1b[0m\n"));
        assert!(colored.ends_with("\x1b[2m  answer: loom answer i-1 \"…\"\x1b[0m\n"));
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
            "✉ scope request\nNeeds docs.example.test to read the API reference.\n  hosts: docs.example.test, *.cdn.test\n  approve: see loom inbox\n"
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
            "i-7  scope request  5s  s-a main job\n  Needs docs.example.test to read the API reference.\n  hosts: docs.example.test, *.cdn.test\n  approve: loom scope s-a docs.example.test '*.cdn.test'\n"
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
            "… request r-1 · step 2 · epoch 1 · about 12.3k tokens\n"
        );
        assert_eq!(render(Event::TurnStart { trigger: Trigger::Start }, &MONO), "");
        let net = Event::Net(NetDecision {
            host: "h".into(),
            port: 1,
            method: "GET".into(),
            allowed: true,
            rule: "r".into(),
            resolved: None,
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
            assert_eq!(record(&decoded, &MONO, &verbose), expected);
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
        SessionInfo { meta: meta(id, parent, title, 1_000), active: false, status }
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
        assert_eq!(lines.len(), 6);
        assert!(lines[0].starts_with("ID"));
        assert!(lines[0].ends_with("TITLE"));
        assert!(lines[1].starts_with("s-root"));
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
        assert!(lines[5].contains("asked the operator"));
        assert!(lines[4].contains("1m"));
        // Columns line up: the ROLE column starts at the same offset on every row.
        let col = lines[0].find("ROLE").unwrap_or(usize::MAX);
        for line in &lines[1..] {
            assert_eq!(line.chars().nth(col), Some('l'), "{line}");
        }
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
        assert_eq!(
            text,
            "i-1  approval  1h  s-a main job\n  May I?\n  Please.\ni-1  approval  59m  s-a main job\n  May I?\n  Please.\n"
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
            "i-1  blocker  5s  s-a main job\n  May I?\n  Please.\n  answer: loom answer i-1 \"…\" (name the next step, not a yes or no question)\n  close as blocked: loom release s-a \"why\"\n"
        );
        let parked = with(InboxKind::Parked, true, &["Keep working", "Accept as blocked and close"]);
        assert_eq!(
            parked,
            "i-1  parked  5s  s-a main job\n  May I?\n  Please.\n  1. Keep working\n  2. Accept as blocked and close\n  answer: loom answer i-1 \"…\"\n  close as blocked: loom release s-a \"why\"\n"
        );
        // A notice that does not block is not a park.
        assert!(!with(InboxKind::Blocker, false, &[]).contains("loom release"));
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

    fn health(reachable: bool) -> loom_agent::runtime::ModelHealth {
        loom_agent::runtime::ModelHealth {
            profile: "local".into(),
            base_url: "http://10.0.0.1:8000/v1".into(),
            model: "big".into(),
            reachable,
            detail: if reachable { String::new() } else { "connection refused".into() },
            context_window: if reachable { Some(1_000_000) } else { None },
            max_concurrent: 4,
        }
    }

    #[test]
    fn status_shapes() {
        let mut view = StatusView {
            version: "0.1.0".into(),
            pid: 42,
            started_ms: 0,
            bind: "127.0.0.1:7878".into(),
            proxy_port: 7879,
            home: "/home/u/.loom".into(),
            disk: Some(crate::wire::DiskSpace { free_bytes: 400 << 30, total_bytes: (1000 << 30) + (1 << 29) }),
            models: vec![health(true), health(false)],
            sessions_total: 5,
            sessions_active: 2,
            sessions_running: 1,
            inbox_open: 3,
        };
        assert_eq!(
            status(&view, &MONO),
            "loom 0.1.0 · pid 42 · 127.0.0.1:7878 · proxy port 7879 · home /home/u/.loom\n\
             400.0 GiB free of 1000.5 GiB (39%) on the volume of the loom home\n\
             ✓ http://10.0.0.1:8000/v1 · big · window 1.00M\n\
             ✗ http://10.0.0.1:8000/v1 · big · window unknown · connection refused\n\
             5 sessions · 2 active · 1 running · 3 waiting in the inbox\n"
        );
        let colored = status(&view, &COLOR);
        assert!(colored.contains("\x1b[32m✓\x1b[0m http://"));
        assert!(colored.contains("\x1b[31m✗\x1b[0m http://"));
        view.models.clear();
        assert!(status(&view, &MONO).contains("no models configured\n"));
        let narrow = status(&view, &Style { color: false, width: 20 });
        for line in narrow.lines() {
            assert!(line.chars().count() <= 20, "{line}");
        }
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
            home: "/home/u/.loom".into(),
            disk,
            models: vec![health(true)],
            sessions_total: 0,
            sessions_active: 0,
            sessions_running: 0,
            inbox_open: 0,
        };
        let warning = "! Low disk space: sessions will fail when the disk fills. Run `loom gc`.\n";
        // (free, total, low): under 5 GiB whatever the volume, under 5 percent whatever the bytes; neither at the line.
        let cases = [(g(5) - 1, g(20), true), (g(5), g(100), false), (g(49), g(1000), true), (g(50), g(1000), false)];
        for (free, total, low) in cases {
            let disk = DiskSpace { free_bytes: free, total_bytes: total };
            assert_eq!(disk.is_low(), low, "{disk:?}");
            let text = status(&with(Some(disk)), &MONO);
            let lines: Vec<&str> = text.lines().collect();
            assert!(lines[1].contains(" free of ") && lines[1].ends_with(" on the volume of the loom home"), "{text}");
            assert_eq!(text.contains(warning), low, "{text}");
            if low {
                assert_eq!(format!("{}\n", lines[2]), warning);
            }
        }
        let low = with(Some(DiskSpace { free_bytes: g(1), total_bytes: g(500) }));
        assert!(status(&low, &MONO).starts_with(&format!(
            "loom 0.1.0 · pid 42 · 127.0.0.1:7878 · proxy port 7879 · home /home/u/.loom\n\
             1.0 GiB free of 500.0 GiB (0%) on the volume of the loom home\n{warning}"
        )));
        assert!(status(&low, &COLOR).contains(&format!("{BOLD_YELLOW}{}{RESET}\n", warning.trim_end())));
        let unknown = status(&with(None), &MONO);
        assert!(unknown.contains("\nfree space on the volume of the loom home: unknown\n"), "{unknown}");
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
        use loom_agent::runtime::SessionScore;
        use loom_core::scorecard::Scorecard;
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
            unrecorded: false,
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
SESSION  ROLE  STEPS  TO FINISH  CALLS  MALFORMED  FINISH REFUSED  QUOTE REFUSED  VERIFIER  FRESH STARTS
s-lead   lead  10     10         12     3 (25%)    1 of 2          2              1 of 2    1
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
SESSION        ROLE      STEPS  TO FINISH  CALLS  MALFORMED  FINISH REFUSED  QUOTE REFUSED  VERIFIER  FRESH STARTS
s-lead         lead      10     10         12     3 (25%)    1 of 2          2              1 of 2    1
  └ s-check-1  verifier  2      -          2      0 (0%)     0 of 0          0              -         0
  └ s-check-2  verifier  2      -          2      0 (0%)     0 of 0          0              -         0
total                    14     10         16     3 (19%)    1 of 2          2              1 of 2    1
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
            "? = not recorded: this log was written before loom recorded verdicts and quote refusals."
        );
        assert!(!text.contains('\x1b'));
        assert!(score_table(&view, &COLOR).contains(DIM));
    }
}
