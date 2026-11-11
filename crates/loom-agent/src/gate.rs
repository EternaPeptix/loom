//! The stop gate: what happens when the model stops calling tools, and what a `finish` must satisfy.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! ## `on_yield` — the model replied without a tool call
//! - `Termination::Free` → `Yield::End`.
//! - `Termination::Explicit`:
//!   - `nudges >= max_nudges` → `Yield::Park(text)`. The text is for the operator: the session
//!     replied {nudges} times in a row without calling a tool or ending its turn, what is still open
//!     (the same list as below), and that a message to the session resumes it.
//!   - otherwise → `Yield::Nudge(text)`. The text is for the model. It states, in this order:
//!     1. what happened: `Your reply ended without a tool call, so nothing was delivered and the turn
//!        has not ended.` If `reply_was_empty`: `Your reply was empty.` instead of the first clause's
//!        subject (keep the rest). If `looks_like_call` (see below): add `The reply contains text
//!        shaped like a tool call; text is never executed — send it as an actual tool call.`
//!     2. what is open, when a lead (`!is_child`) and the ledger has open items: the heading `Still
//!        open:` and one line per item, grouped as `plan step p2 (doing): {text}`, `obligation o1
//!        (job): {text}`, `claim c3 (no evidence attached): {text}`, `question q1 (waiting for the
//!        operator): {text}`; at most 12 lines, then `(+k more)`; text cut to 120 characters.
//!     3. what is running, when `running_jobs + running_children > 0`: the counts, and that `wait`
//!        ends the turn until one of them reports.
//!     4. how to proceed — exactly one closing paragraph by case:
//!        lead: `To keep working, call a tool. To end the turn, call finish (the goal is met),
//!        ask_user (you need the operator), report_blocker (you cannot proceed), or wait (things are
//!        running).`
//!        child: `To keep working, call a tool. To deliver your result, call finish; if the
//!        assignment cannot be done, call report_blocker.`
//!        If the role lacks one of the named tools (`tools` is the session's tool names), that
//!        clause is left out; a verifier (has `verdict`) is told `To deliver your verdict, call
//!        verdict.` in place of the finish clause.
//! `looks_like_call(text)`: true when the text contains a DSML/XML-style call marker (`<｜DSML｜`,
//! `<tool_call`, `<function_call`, `<invoke`), or a fenced or bare JSON object that has a string
//! `"name"` key together with an `"arguments"` or `"parameters"` key.
//!
//! The runtime resets `nudges` to 0 whenever a tool call completes with status `Ok`.
//!
//! ## `check_finish_lead` — a lead called `finish`
//! Returns `Err(text)` when `ledger.open_items()` is not empty. The text lists every open item (same
//! line format as above, no cap) and, per group present, how to close it: plan steps — `step` with
//! status done (say what showed it) or dropped (say why); obligations — wait for the job/agent, or
//! stop it; claims — attach evidence with `evidence` and set the status with `claim_update`, or
//! withdraw it; questions — they wait for the operator: `ask_user` ends the turn until answered.
//! Also `Err` when `answer` is empty or whitespace. Otherwise `Ok(())`.
//!
//! ## `check_quotes` — any `finish` with quotes
//! For each quote, in order: resolve `handle` with `BlobStore::resolve` (failure → `quote {i}: there
//! is no stored output {handle}; handles are the out:… ids in result headers`); `start`/`end` must be
//! `1 <= start <= end` and `start <= total lines` (else a sentence giving the output's line count);
//! read the lines (`end` clamped to the last line) and require `observe::quote_matches(lines, text)`.
//! On a mismatch the sentence is `quote {i}: the text does not occur in {handle} lines {start}-{end}.`
//! followed, when `observe::nearest_line` finds one in that range, by ` The closest line there is
//! {n}: {line}` (line cut to 200 characters) and always by ` Copy the text exactly from the output.`
//! An empty `text` is a mismatch with the sentence `quote {i}: the text is empty.`
//! Returns `Ok(verified)` when every quote passes (blob id, the clamped range, the text), else
//! `Err(all sentences, one per line)`.
//!
//! ## `render_report` — what a parent sees of a child's result
//! ```text
//! Outcome: {outcome}                       (returned | blocked | budget exhausted | stopped | failed)
//! Answer:
//! {answer}
//!
//! Quotes (checked against the stored output by the harness):
//! - {handle} lines {start}-{end}: {text}
//!
//! Not established (stated by the agent):
//! {not_established}
//!
//! This report was written by a sub-agent. The quotes are verbatim; everything else is unverified.
//! ```
//! Sections with nothing to show are omitted; the last line is always present. The answer is cut at
//! `max_chars` characters with the line `[report cut at {max_chars} characters; the full text is
//! {full_handle}]` when it is longer (the handle is given by the caller). Quote text longer than 400
//! characters is cut with `…`.
//!
//! Tests required: every branch of `on_yield`, including each tool-availability variant of the
//! closing paragraph and exact text of at least one full nudge; `looks_like_call` positives and
//! negatives (ordinary prose and ordinary JSON must be negative); `check_finish_lead` for each kind
//! of open item; `check_quotes` success, each failure sentence, clamping, several failures at once;
//! `render_report` full, minimal, and cut.

use loom_core::event::{ChildOutcome, Termination};
use loom_core::ledger::LedgerState;
use loom_core::{BlobId, BlobStore};
use serde::{Deserialize, Serialize};

pub struct YieldCtx<'a> {
    pub termination: Termination,
    pub is_child: bool,
    /// Names of the tools this session can call.
    pub tools: &'a [String],
    /// The mission ledger; `None` for sessions without one.
    pub ledger: Option<&'a LedgerState>,
    /// The text of the reply that ended without a tool call.
    pub reply: &'a str,
    /// Consecutive nudges already given without a successful tool call in between.
    pub nudges: u32,
    pub max_nudges: u32,
    pub running_jobs: usize,
    pub running_children: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Yield {
    /// The turn ends normally.
    End,
    /// Append this note for the model and continue.
    Nudge(String),
    /// Stop and hand to the operator with this text.
    Park(String),
}

pub fn on_yield(ctx: &YieldCtx<'_>) -> Yield {
    let _ = ctx;
    todo!("implement per module contract")
}

pub fn looks_like_call(text: &str) -> bool {
    let _ = text;
    todo!("implement per module contract")
}

/// A quote as the model gives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    pub handle: String,
    pub start: u64,
    pub end: u64,
    pub text: String,
}

/// A quote that was found in the stored output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedQuote {
    pub blob: BlobId,
    pub start: u64,
    pub end: u64,
    pub text: String,
}

pub fn check_finish_lead(ledger: &LedgerState, answer: &str) -> Result<(), String> {
    let _ = (ledger, answer);
    todo!("implement per module contract")
}

pub fn check_quotes(blobs: &BlobStore, quotes: &[Quote]) -> Result<Vec<VerifiedQuote>, String> {
    let _ = (blobs, quotes);
    todo!("implement per module contract")
}

pub struct ReportInput<'a> {
    pub outcome: ChildOutcome,
    pub answer: &'a str,
    pub quotes: &'a [VerifiedQuote],
    pub not_established: Option<&'a str>,
    pub max_chars: usize,
    /// Handle of the stored full answer, used in the cut marker.
    pub full_handle: &'a str,
}

pub fn render_report(input: &ReportInput<'_>) -> String {
    let _ = input;
    todo!("implement per module contract")
}
