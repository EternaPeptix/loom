//! The harness-state block: what the model is told, fresh at every step, about where things stand.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! The block is the last message of each request and is not part of the stored prefix, so it can
//! change freely. It carries what a model otherwise loses track of over a long session: the mission
//! state, what it has not looked at, what is running. It never mentions context size, message
//! counts, or how long the session has run — those are not the model's concern (DESIGN §2.2). The
//! only budget shown is a child's own step/time budget.
//!
//! `render(input)` is pure and deterministic. Output, sections in this order, each omitted when it
//! has nothing to show, separated by one blank line:
//!
//! ```text
//! Now: 2026-11-11 21:40 UTC
//!
//! Mission state (from the ledger — the ledger tools change it):
//! {LedgerState::brief(&input.brief)}
//!
//! Outputs you have not fully looked at ({n}):
//! - out:7f3a9c1e (bash): 18412 lines, 17612 never shown — lines 401-18012
//!
//! Repeated calls ({n}) — the result will not change; do something different:
//! - bash {"command":"ls"} — 4 times, same result
//!
//! Out of date ({n}):
//! - src/a.rs changed after you last read it — read it again before relying on what you saw
//! - src/a.rs changed after you ran `cargo test -p x` — run it again before relying on its result
//!
//! Running ({n}):
//! - job j3 `cargo build --release` — 4 min, 220 lines so far
//! - agent s-01jabc (worker) "Find the callers of parse()" — step 12
//!
//! Waiting on the operator ({n}):
//! - q2: Which branch should this target?
//!
//! Budget: step 37 of 200; 84 of 120 minutes left
//! ```
//!
//! Details:
//! - `Now`: `input.now_ms` as UTC, minute precision (implement the civil-date arithmetic here; no
//!   date crate).
//! - Mission state: only when `input.ledger` is `Some` and the brief is non-empty.
//! - Not looked at: `observe::unviewed(records, input.unviewed_min_lines)`; gaps as `a-b` joined by
//!   `, `, at most 4 gaps then `, …`.
//! - Repeated: `observe::repetitions(records, 3)`.
//! - Out of date: `observe::stale(records)`. For `ExecBeforeWrite` the command shown is the `command`
//!   argument of the `tool_call` at `Stale::seq` (first line, cut to 80 chars with `…`), or the tool
//!   name when it has none. Entries are de-duplicated by (kind, path, command) keeping the newest,
//!   and a `ReadBeforeWrite` is dropped when a later successful read of the same path exists.
//! - Running: `input.jobs` then `input.children`, in the order given. Job age in whole minutes
//!   (`<1 min` below one).
//! - Waiting on the operator: ledger questions with no answer (id and text), only when
//!   `input.ledger` is `Some`.
//! - Budget: only when `input.is_child` and the budget has a limit. Steps: `step {step} of {max}`.
//!   Minutes: whole minutes left, from `started_ms`, floor at 0. Both parts when both limits exist.
//! - Every list shows at most `MAX_ITEMS` entries, then `- (+{k} more)`. Every entry is one line,
//!   cut to `MAX_LINE` characters with `…`; newlines inside values are replaced by spaces.
//! - When nothing at all would be shown except `Now`, the output is just the `Now` line.
//!
//! Tests required: each section alone and all together (compare against exact expected text); empty
//! input; caps and `(+k more)`; line cutting on multi-byte text; date rendering for several instants
//! (epoch, a leap day, end of year); child budget variants and floor at 0; stale de-duplication and
//! the re-read rule; determinism.

use loom_core::event::{Budget, Record};
use loom_core::ledger::{BriefOpts, LedgerState};

pub const MAX_ITEMS: usize = 8;
pub const MAX_LINE: usize = 240;

/// A background job as the block shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HudJob {
    pub id: String,
    pub command: String,
    pub started_ms: u64,
    pub lines: u64,
}

/// A running child agent as the block shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HudChild {
    pub id: String,
    pub role: String,
    pub title: String,
    pub step: u32,
}

pub struct HudInput<'a> {
    pub now_ms: u64,
    pub records: &'a [Record],
    pub ledger: Option<&'a LedgerState>,
    pub brief: BriefOpts,
    pub unviewed_min_lines: u64,
    pub jobs: &'a [HudJob],
    pub children: &'a [HudChild],
    pub is_child: bool,
    pub step: u32,
    pub started_ms: u64,
    pub budget: Budget,
}

pub fn render(input: &HudInput<'_>) -> String {
    let _ = input;
    todo!("implement per module contract")
}

/// `ms` since the Unix epoch as `YYYY-MM-DD HH:MM UTC`.
pub fn format_utc(ms: u64) -> String {
    let _ = ms;
    todo!("implement per module contract")
}
