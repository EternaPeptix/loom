//! Records and listings as terminal text. Pure functions: same input, same text.
//!
//! CONTRACT (bodies are placeholders for the implementer; public signatures and types are fixed).
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
//! - `job_registered`: `⚙ job {job_id}: {command}`; `job_settled`: `⚙ job {job_id} ended: {detail}`.
//! - `inbox_opened`: `✉ {kind}` + ` (waiting for you)` when blocking (bold yellow), the text, the
//!   options numbered `  1. …`, then `  answer: loom answer {item_id} "…"` (dim) unless the kind is
//!   `Finished`.
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
//!   the text indented; `Nothing is waiting for you.` when empty.
//! - `window_table(view, style)`: a summary line (`epoch {e} · about {tokens} tokens in view ·
//!   folds at {target} down to {floor} · window {context_window or "unknown"} · last request
//!   {prompt} in, {pct}% cached`), then per item `#{seq}  {kind}  {state}  {chars}  {pin}
//!   {preview}`.
//! - `status(view, style)`: the daemon line, one line per model (`✓`/`✗`, base URL, model, window,
//!   detail when unreachable), the counts.
//! - `net_table(entries, style)`: `TIME  VERDICT  METHOD  HOST:PORT  RULE` (time as `HH:MM:SS` UTC).
//!
//! Tests required: every record kind (the shape above, with and without colour — no escape byte
//! without colour); `clean` on escape sequences; reasoning shown/hidden; output cutting with and
//! without a handle and with `full`; each small format at its boundaries; each listing including
//! the empty cases and the child indentation; rows never exceed `width` characters.

use crate::wire::StatusView;
use loom_agent::runtime::{InboxEntry, NetEntry, SessionInfo, WindowView};
use loom_core::event::Record;

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

pub fn record(rec: &Record, style: &Style, opts: &RecordOpts) -> String {
    let _ = (rec, style, opts);
    todo!("implement per module contract")
}

pub fn clean(text: &str) -> String {
    let _ = text;
    todo!("implement per module contract")
}

pub fn tokens(n: u64) -> String {
    let _ = n;
    todo!("implement per module contract")
}

pub fn seconds(ms: u64) -> String {
    let _ = ms;
    todo!("implement per module contract")
}

pub fn age(ms: u64) -> String {
    let _ = ms;
    todo!("implement per module contract")
}

pub fn cut(text: &str, max: usize) -> String {
    let _ = (text, max);
    todo!("implement per module contract")
}

pub fn sessions_table(list: &[SessionInfo], now_ms: u64, style: &Style) -> String {
    let _ = (list, now_ms, style);
    todo!("implement per module contract")
}

pub fn inbox_list(list: &[InboxEntry], now_ms: u64, style: &Style) -> String {
    let _ = (list, now_ms, style);
    todo!("implement per module contract")
}

pub fn window_table(view: &WindowView, style: &Style) -> String {
    let _ = (view, style);
    todo!("implement per module contract")
}

pub fn status(view: &StatusView, style: &Style) -> String {
    let _ = (view, style);
    todo!("implement per module contract")
}

pub fn net_table(entries: &[NetEntry], style: &Style) -> String {
    let _ = (entries, style);
    todo!("implement per module contract")
}
