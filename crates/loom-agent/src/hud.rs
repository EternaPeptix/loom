//! The harness-state block: what the model is told, fresh at every step, about where things stand.
//!
//! CONTRACT.
//!
//! The block is the last message of each request and is not part of the stored prefix, so it can
//! change freely. It carries what a model otherwise loses track of over a long session: the mission
//! state, what it has not looked at, what is running. It never mentions context size, message
//! counts, or how long the session has run — those are not the model's concern (DESIGN §2.2). The
//! only budget shown is the session's own step/time budget.
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
//! - Mission state: only when `input.ledger` is `Some` and the brief is non-empty. Followed, when
//!   `input.ledger_skipped` is `n > 0`, by its own line `{n} ledger entries written by a newer loom are
//!   not shown` (`1 ledger entry … is not shown`): the ledger as read lacks entries this build cannot parse.
//! - Finish: a line of its own after the mission state, in a lead only (`!input.is_child`): `Finish: rejected
//!   {n}; needs new execution evidence` while an objection of a finish verifier is an open obligation (n = the
//!   rejected finishes since the latest accepted one), else `Finish: unavailable — goal not concluded` while a
//!   goal is set, its goal-met claim is not concluded and the operator has not released the mission. The
//!   goal status itself is a line of the mission state.
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
//! - Budget: only when the budget has a limit; named `Budget` for a child (its assignment's) and
//!   `Session budget` for a root. Steps: `step {step} of {max}`. Minutes: whole minutes left, from
//!   `started_ms`, floor at 0. Both parts when both limits exist. `step` and `started_ms` count from
//!   where the budget was granted: the session's start, or the turn that gave a root a fresh one.
//! - Every list shows at most `MAX_ITEMS` entries, then `- (+{k} more)`. Every entry is one line,
//!   cut to `MAX_LINE` characters with `…`; newlines inside values are replaced by spaces.
//! - When nothing at all would be shown except `Now`, the output is just the `Now` line.
//!
//! Tests required: each section alone and all together (compare against exact expected text); empty
//! input; caps and `(+k more)`; line cutting on multi-byte text; date rendering for several instants
//! (epoch, a leap day, end of year); child budget variants and floor at 0; stale de-duplication and
//! the re-read rule; determinism.

use crate::texts;
use loom_core::event::{Budget, Event, Record, ToolClass, ToolStatus, META_PATH};
use loom_core::ledger::{BriefOpts, LedgerState, ObligationKind};
use loom_core::observe::{self, StaleKind};
use serde_json::Value;

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
    /// Entries of the ledger written by a newer loom, which `ledger` leaves out.
    pub ledger_skipped: u64,
    pub brief: BriefOpts,
    pub unviewed_min_lines: u64,
    pub jobs: &'a [HudJob],
    pub children: &'a [HudChild],
    pub is_child: bool,
    pub step: u32,
    pub started_ms: u64,
    pub budget: Budget,
    /// The session's `finish` waits for a conclusion of the goal-met claim (an explicit-termination role that
    /// has `conclude`); only then is the state of that claim said.
    pub finish_gated: bool,
}

pub fn render(input: &HudInput<'_>) -> String {
    let mut sections: Vec<String> = vec![format!("Now: {}", format_utc(input.now_ms))];

    if let Some(ledger) = input.ledger {
        let brief = ledger.brief(&input.brief);
        if !brief.trim().is_empty() {
            sections.push(format!("Mission state (from the ledger — the ledger tools change it):\n{}", brief.trim_end()));
        }
        if !input.is_child {
            if let Some(line) = finish_line(ledger, input.finish_gated) {
                sections.push(line);
            }
        }
        if input.ledger_skipped > 0 {
            let n = input.ledger_skipped;
            sections.push(if n == 1 {
                "1 ledger entry written by a newer loom is not shown".to_string()
            } else {
                format!("{n} ledger entries written by a newer loom are not shown")
            });
        }
    }

    let unviewed: Vec<String> = observe::unviewed(input.records, input.unviewed_min_lines)
        .iter()
        .map(|u| {
            let mut gaps: Vec<String> = u.gaps.iter().take(4).map(|(a, b)| format!("{a}-{b}")).collect();
            if u.gaps.len() > 4 {
                gaps.push("…".to_string());
            }
            format!(
                "- {} ({}): {} lines, {} never shown — lines {}",
                u.handle,
                u.tool,
                u.total_lines,
                u.unseen_lines,
                gaps.join(", ")
            )
        })
        .collect();
    push_list(&mut sections, "Outputs you have not fully looked at", "", unviewed);

    let repeated: Vec<String> = observe::repetitions(input.records, 3)
        .iter()
        .map(|r| format!("- {} {} — {} times, same result", r.tool, r.args, r.count))
        .collect();
    push_list(&mut sections, "Repeated calls", " — the result will not change; do something different", repeated);

    push_list(&mut sections, "Out of date", "", stale_lines(input.records));

    let mut running: Vec<String> = Vec::new();
    for j in input.jobs {
        let minutes = input.now_ms.saturating_sub(j.started_ms) / 60_000;
        let age = if minutes < 1 { "<1 min".to_string() } else { format!("{minutes} min") };
        running.push(format!("- job {} `{}` — {}, {} lines so far", j.id, j.command, age, j.lines));
    }
    for c in input.children {
        running.push(format!("- agent {} ({}) \"{}\" — step {}", c.id, c.role, c.title, c.step));
    }
    push_list(&mut sections, "Running", "", running);

    if let Some(ledger) = input.ledger {
        let waiting: Vec<String> =
            ledger.questions.iter().filter(|q| q.answer.is_none()).map(|q| format!("- {}: {}", q.id, q.text)).collect();
        push_list(&mut sections, "Waiting on the operator", "", waiting);
    }

    let mut parts: Vec<String> = Vec::new();
    if let Some(max) = input.budget.max_steps {
        parts.push(format!("step {} of {}", input.step, max));
    }
    if let Some(max) = input.budget.max_minutes {
        let elapsed = input.now_ms.saturating_sub(input.started_ms) / 60_000;
        let left = u64::from(max).saturating_sub(elapsed);
        parts.push(format!("{left} of {max} minutes left"));
    }
    if !parts.is_empty() {
        let name = if input.is_child { "Budget" } else { "Session budget" };
        sections.push(format!("{name}: {}", parts.join("; ")));
    }

    sections.join("\n\n")
}

/// Why `finish` is closed, from the ledger: `Finish: rejected {n}; needs new execution evidence` while an
/// objection of a verifier is open and the operator has not released (n = rejections since the latest accepted finish), else `Finish:
/// unavailable — goal not concluded` while the goal claim is open and the operator has not released.
fn finish_line(ledger: &LedgerState, gated: bool) -> Option<String> {
    let objected = ledger.release.is_none()
        && ledger.obligations.iter().any(|o| o.outcome.is_none() && o.kind == ObligationKind::Objection);
    let rejected = if objected {
        let since = ledger.finishes.iter().rposition(|f| f.accepted == Some(true)).map_or(0, |i| i.saturating_add(1));
        ledger.finishes.iter().skip(since).filter(|f| f.accepted == Some(false)).count()
    } else {
        0
    };
    texts::finish_status_line(gated && crate::gate::goal_unconcluded(ledger), rejected)
}

/// One section: `{title} ({n}){suffix}:` and its entries, capped at `MAX_ITEMS`. Omitted when empty.
fn push_list(sections: &mut Vec<String>, title: &str, suffix: &str, entries: Vec<String>) {
    if entries.is_empty() {
        return;
    }
    let total = entries.len();
    let mut out = format!("{title} ({total}){suffix}:");
    for e in entries.iter().take(MAX_ITEMS) {
        out.push('\n');
        out.push_str(&one_line(e));
    }
    if total > MAX_ITEMS {
        out.push_str(&format!("\n- (+{} more)", total.saturating_sub(MAX_ITEMS)));
    }
    sections.push(out);
}

/// `s` on one line, cut to `MAX_LINE` characters with a trailing `…`.
fn one_line(s: &str) -> String {
    let flat: String = s.chars().map(|c| if c == '\n' || c == '\r' { ' ' } else { c }).collect();
    cut(&flat, MAX_LINE)
}

fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// The "Out of date" entries: de-duplicated by (kind, path, command), newest kept, and a stale read
/// dropped when a later successful read of the same path exists.
fn stale_lines(records: &[Record]) -> Vec<String> {
    struct Item {
        kind: StaleKind,
        path: String,
        command: String,
        seq: u64,
    }
    let mut items: Vec<Item> = Vec::new();
    for s in observe::stale(records) {
        let command = match s.kind {
            StaleKind::ReadBeforeWrite => {
                let reread = records.iter().any(|r| match &r.event {
                    Event::ToolResult(t) => {
                        r.seq > s.seq
                            && t.class == ToolClass::Read
                            && t.status == ToolStatus::Ok
                            && t.meta.get(META_PATH).and_then(Value::as_str) == Some(s.path.as_str())
                    }
                    _ => false,
                });
                if reread {
                    continue;
                }
                String::new()
            }
            StaleKind::ExecBeforeWrite => exec_command(records, s.seq),
        };
        match items.iter_mut().find(|i| i.kind == s.kind && i.path == s.path && i.command == command) {
            Some(existing) => existing.seq = existing.seq.max(s.seq),
            None => items.push(Item { kind: s.kind, path: s.path.clone(), command, seq: s.seq }),
        }
    }
    items.sort_by_key(|i| i.seq);
    items
        .iter()
        .map(|i| match i.kind {
            StaleKind::ReadBeforeWrite => {
                format!("- {} changed after you last read it — read it again before relying on what you saw", i.path)
            }
            StaleKind::ExecBeforeWrite => format!(
                "- {} changed after you ran `{}` — run it again before relying on its result",
                i.path, i.command
            ),
        })
        .collect()
}

/// What to call the run whose result is at `seq`: the first line of the `command` argument of its
/// call (cut to 80 characters), or the tool name when the call has none.
fn exec_command(records: &[Record], seq: u64) -> String {
    let Some(rec) = records.iter().find(|r| r.seq == seq) else { return String::new() };
    let (call_id, name) = match &rec.event {
        Event::ToolResult(t) => (&t.call_id, t.name.clone()),
        Event::ToolCall(c) => (&c.call_id, c.name.clone()),
        _ => return String::new(),
    };
    let command = records.iter().find_map(|r| match &r.event {
        Event::ToolCall(c) if &c.call_id == call_id => c.args.get("command").and_then(Value::as_str).map(str::to_string),
        _ => None,
    });
    match command {
        Some(c) => {
            let first = c.lines().next().unwrap_or("").trim();
            if first.is_empty() {
                name
            } else {
                cut(first, 80)
            }
        }
        None => name,
    }
}

/// `ms` since the Unix epoch as `YYYY-MM-DD HH:MM UTC`.
pub fn format_utc(ms: u64) -> String {
    let secs = ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (hour, minute) = (rem / 3600, (rem % 3600) / 60);
    // Civil date from a day count (proleptic Gregorian), days counted from 1970-01-01.
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::blob::BlobRef;
    use loom_core::event::{Author, ToolCall, ToolResult};
    use loom_core::ledger::{PlanStep, Question, StepStatus};
    use loom_core::{BlobId, CallId};
    use serde_json::json;

    const EMPTY: &[Record] = &[];

    fn rec(seq: u64, event: Event) -> Record {
        Record { seq, ts_ms: seq, author: Author::Tool, prev: "0".repeat(64), event }
    }

    fn call(seq: u64, id: &str, name: &str, args: Value, class: ToolClass) -> Record {
        rec(seq, Event::ToolCall(ToolCall { call_id: CallId::from(id), req_id: "r".into(), name: name.into(), args, class }))
    }

    fn result(seq: u64, id: &str, name: &str, class: ToolClass, out: Option<BlobRef>, cut: bool, meta: Value) -> Record {
        rec(
            seq,
            Event::ToolResult(ToolResult {
                call_id: CallId::from(id),
                name: name.into(),
                status: ToolStatus::Ok,
                text: String::new(),
                output: out,
                cut,
                class,
                meta: meta.as_object().cloned().unwrap_or_default(),
                duration_ms: 0,
            }),
        )
    }

    fn blob(id: &str, lines: u64) -> BlobRef {
        BlobRef { id: BlobId::from(id), bytes: lines * 10, lines }
    }

    fn input<'a>(records: &'a [Record]) -> HudInput<'a> {
        HudInput {
            now_ms: 0,
            records,
            ledger: None,
            ledger_skipped: 0,
            brief: BriefOpts::default(),
            unviewed_min_lines: 1,
            jobs: &[],
            children: &[],
            is_child: false,
            step: 0,
            started_ms: 0,
            budget: Budget::default(),
            finish_gated: true,
        }
    }

    #[test]
    fn dates() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        // 2024-02-29 12:34:56 UTC
        assert_eq!(format_utc(1_709_210_096_000), "2024-02-29 12:34 UTC");
        // 2023-12-31 23:59:59.999 UTC
        assert_eq!(format_utc(1_704_067_199_999), "2023-12-31 23:59 UTC");
        // 2026-11-11 21:40 UTC
        assert_eq!(format_utc(1_794_433_200_000), "2026-11-11 21:40 UTC");
        // 2000-03-01 00:00 UTC (after a century leap day)
        assert_eq!(format_utc(951_868_800_000), "2000-03-01 00:00 UTC");
    }

    #[test]
    fn empty_input_is_just_now() {
        assert_eq!(render(&input(EMPTY)), "Now: 1970-01-01 00:00 UTC");
    }

    #[test]
    fn deterministic() {
        let recs = vec![result(1, "a", "bash", ToolClass::Exec, Some(blob("aa", 10)), true, json!({}))];
        assert_eq!(render(&input(&recs)), render(&input(&recs)));
    }

    fn ledger() -> LedgerState {
        LedgerState {
            goal: Some("Fix the parser".into()),
            plan: vec![PlanStep {
                id: "p1".into(),
                text: "Reproduce".into(),
                status: StepStatus::Doing,
                note: String::new(),
                evidence: vec![],
            }],
            questions: vec![
                Question { id: "q1".into(), text: "done one".into(), blocking: true, answer: Some("x".into()) },
                Question { id: "q2".into(), text: "Which branch should this target?".into(), blocking: true, answer: None },
            ],
            ..LedgerState::default()
        }
    }

    #[test]
    fn skipped_ledger_entries_are_said_in_the_state_block() {
        let l = ledger();
        let mut i = input(EMPTY);
        i.ledger = Some(&l);
        assert!(!render(&i).contains("newer loom"));
        i.ledger_skipped = 3;
        let text = render(&i);
        assert!(text.contains("\n\n3 ledger entries written by a newer loom are not shown\n\n"), "{text}");
        i.ledger_skipped = 1;
        assert!(render(&i).contains("1 ledger entry written by a newer loom is not shown"));
        // Without a ledger there is nothing to qualify.
        i.ledger = None;
        assert!(!render(&i).contains("newer loom"));
    }

    #[test]
    fn mission_and_waiting_sections() {
        let l = ledger();
        let mut i = input(EMPTY);
        i.ledger = Some(&l);
        let expected = format!(
            "Now: 1970-01-01 00:00 UTC\n\nMission state (from the ledger — the ledger tools change it):\n{}\n\nFinish: unavailable — goal not concluded\n\nWaiting on the operator (1):\n- q2: Which branch should this target?",
            l.brief(&BriefOpts::default())
        );
        assert_eq!(render(&i), expected);
        assert!(expected.contains("Goal: Fix the parser"));
        // An empty ledger shows nothing.
        let empty = LedgerState::default();
        i.ledger = Some(&empty);
        assert_eq!(render(&i), "Now: 1970-01-01 00:00 UTC");
    }

    #[test]
    fn unviewed_section_with_gap_cap() {
        let recs = vec![
            result(1, "a", "bash", ToolClass::Exec, Some(blob("7f3a9c1e00000000aa", 18412)), true, json!({ "shown": [[1, 400], [18013, 18412]] })),
            result(
                2,
                "b",
                "bash",
                ToolClass::Exec,
                Some(blob("bbbbbbbbbbbbbbbbbb", 100)),
                true,
                json!({ "shown": [[2, 3], [5, 6], [8, 9], [11, 12], [14, 15]] }),
            ),
        ];
        let out = render(&input(&recs));
        assert_eq!(
            out,
            "Now: 1970-01-01 00:00 UTC\n\nOutputs you have not fully looked at (2):\n\
- out:bbbbbbbbbbbbbbbb (bash): 100 lines, 90 never shown — lines 1-1, 4-4, 7-7, 10-10, …\n\
- out:7f3a9c1e00000000 (bash): 18412 lines, 17612 never shown — lines 401-18012"
        );
    }

    #[test]
    fn repeated_section() {
        let mut recs = Vec::new();
        for k in 0..4u64 {
            let id = format!("c{k}");
            recs.push(call(k * 2, &id, "bash", json!({"command": "ls"}), ToolClass::Exec));
            recs.push(result(k * 2 + 1, &id, "bash", ToolClass::Exec, Some(blob("aa", 3)), false, json!({})));
        }
        assert_eq!(
            render(&input(&recs)),
            "Now: 1970-01-01 00:00 UTC\n\nRepeated calls (1) — the result will not change; do something different:\n- bash {\"command\":\"ls\"} — 4 times, same result"
        );
    }

    fn stale_records() -> Vec<Record> {
        vec![
            call(1, "r1", "read", json!({"path": "src/a.rs"}), ToolClass::Read),
            result(2, "r1", "read", ToolClass::Read, None, false, json!({"path": "src/a.rs"})),
            call(3, "t1", "bash", json!({"command": "cargo test -p x\nsecond line"}), ToolClass::Exec),
            result(4, "t1", "bash", ToolClass::Exec, Some(blob("cc", 2)), false, json!({})),
            call(5, "w1", "edit", json!({"path": "src/a.rs"}), ToolClass::Write),
            result(6, "w1", "edit", ToolClass::Write, None, false, json!({"path": "src/a.rs"})),
        ]
    }

    #[test]
    fn stale_section() {
        let recs = stale_records();
        assert_eq!(
            render(&input(&recs)),
            "Now: 1970-01-01 00:00 UTC\n\nOut of date (2):\n\
- src/a.rs changed after you last read it — read it again before relying on what you saw\n\
- src/a.rs changed after you ran `cargo test -p x` — run it again before relying on its result"
        );
    }

    #[test]
    fn stale_exec_without_command_uses_tool_name() {
        let recs = vec![
            call(1, "t1", "run_tests", json!({}), ToolClass::Exec),
            result(2, "t1", "run_tests", ToolClass::Exec, Some(blob("cc", 2)), false, json!({})),
            result(4, "w1", "edit", ToolClass::Write, None, false, json!({"path": "p.rs"})),
        ];
        let out = render(&input(&recs));
        assert!(out.contains("p.rs changed after you ran `run_tests`"), "{out}");
    }

    #[test]
    fn stale_command_is_cut_to_80() {
        let long = "x".repeat(200);
        let recs = vec![
            call(1, "t1", "bash", json!({ "command": long }), ToolClass::Exec),
            result(2, "t1", "bash", ToolClass::Exec, Some(blob("cc", 2)), false, json!({})),
            result(4, "w1", "edit", ToolClass::Write, None, false, json!({"path": "p.rs"})),
        ];
        let out = render(&input(&recs));
        let want = format!("`{}…`", "x".repeat(79));
        assert!(out.contains(&want), "{out}");
    }

    #[test]
    fn running_section_and_ages() {
        let jobs = vec![
            HudJob { id: "j3".into(), command: "cargo build --release".into(), started_ms: 1_000_000 - 4 * 60_000 - 5, lines: 220 },
            HudJob { id: "j4".into(), command: "sleep 9".into(), started_ms: 1_000_000 - 59_999, lines: 0 },
        ];
        let kids = vec![HudChild { id: "s-01jabc".into(), role: "worker".into(), title: "Find the callers of parse()".into(), step: 12 }];
        let mut i = input(EMPTY);
        i.now_ms = 1_000_000;
        i.jobs = &jobs;
        i.children = &kids;
        assert_eq!(
            render(&i),
            "Now: 1970-01-01 00:16 UTC\n\nRunning (3):\n\
- job j3 `cargo build --release` — 4 min, 220 lines so far\n\
- job j4 `sleep 9` — <1 min, 0 lines so far\n\
- agent s-01jabc (worker) \"Find the callers of parse()\" — step 12"
        );
    }

    #[test]
    fn budget_variants() {
        let mut i = input(EMPTY);
        i.is_child = true;
        i.step = 37;
        i.now_ms = 36 * 60_000;
        i.budget = Budget { max_steps: Some(200), max_minutes: Some(120) };
        assert!(render(&i).ends_with("\n\nBudget: step 37 of 200; 84 of 120 minutes left"));
        i.budget = Budget { max_steps: Some(200), max_minutes: None };
        assert!(render(&i).ends_with("\n\nBudget: step 37 of 200"));
        i.budget = Budget { max_steps: None, max_minutes: Some(30) };
        i.now_ms = 36 * 60_000;
        assert!(render(&i).ends_with("\n\nBudget: 0 of 30 minutes left"));
        i.budget = Budget::default();
        assert_eq!(render(&i), "Now: 1970-01-01 00:36 UTC");
        i.budget = Budget { max_steps: Some(5), max_minutes: None };
        i.is_child = false;
        assert!(render(&i).ends_with("\n\nSession budget: step 37 of 5"));
    }

    #[test]
    fn a_root_budget_is_named_and_counted_from_where_it_was_granted() {
        // A root whose fresh budget was granted by the turn that started at minute 30, two steps ago.
        let mut i = input(EMPTY);
        i.step = 2;
        i.started_ms = 30 * 60_000;
        i.now_ms = 36 * 60_000;
        i.budget = Budget { max_steps: Some(10), max_minutes: Some(20) };
        assert!(render(&i).ends_with("\n\nSession budget: step 2 of 10; 14 of 20 minutes left"), "{}", render(&i));
        // No limit, no line.
        i.budget = Budget::default();
        assert_eq!(render(&i), "Now: 1970-01-01 00:36 UTC");
    }

    #[test]
    fn the_finish_line_says_why_finish_is_closed() {
        use loom_core::ledger::{FinishRecord, GoalMet, GoalMetStatus, Obligation, Release};
        let mut l = LedgerState { goal: Some("fix it".into()), ..LedgerState::default() };
        l.goal_met = Some(GoalMet { status: GoalMetStatus::Open, note: String::new(), evidence: vec![], n: 0 });
        let mut i = input(EMPTY);
        i.ledger = Some(&l);
        assert!(render(&i).contains("\n\nFinish: unavailable — goal not concluded"), "{}", render(&i));
        // A child is not told about finish.
        i.is_child = true;
        assert!(!render(&i).contains("Finish:"));
        i.is_child = false;

        // An open objection of a verifier: the count of rejections since the latest accepted finish.
        let rejected = |id: &str, accepted: bool| FinishRecord {
            id: id.into(),
            summary: "s".into(),
            evidence: vec![],
            accepted: Some(accepted),
            objections: vec!["o".into()],
        };
        let mut done = l.clone();
        done.goal_met = Some(GoalMet { status: GoalMetStatus::Supported, note: "ran".into(), evidence: vec!["e1".into()], n: 4 });
        done.finishes = vec![rejected("f1", false), rejected("f2", true), rejected("f3", false), rejected("f4", false)];
        done.obligations.push(Obligation {
            id: "o1".into(),
            kind: ObligationKind::Objection,
            text: "no run".into(),
            reference: "f4".into(),
            outcome: None,
        });
        i.ledger = Some(&done);
        assert!(render(&i).contains("\n\nFinish: rejected 2; needs new execution evidence"), "{}", render(&i));
        // Settled objection and a concluded goal: no line. Neither with a release.
        let mut settled = done.clone();
        settled.obligations[0].outcome = Some("settled".into());
        i.ledger = Some(&settled);
        assert!(!render(&i).contains("Finish:"), "{}", render(&i));
        let mut released = l.clone();
        released.release = Some(Release { reason: "stop".into(), n: 2 });
        i.ledger = Some(&released);
        assert!(!render(&i).contains("Finish:"), "{}", render(&i));
        // A release also hides an open objection: finish will be allowed.
        let mut released_objected = done.clone();
        released_objected.release = Some(Release { reason: "stop".into(), n: 9 });
        i.ledger = Some(&released_objected);
        assert!(!render(&i).contains("Finish:"), "{}", render(&i));
    }

    #[test]
    fn all_sections_together() {
        let l = ledger();
        let mut recs = stale_records();
        recs.push(result(0, "u", "bash", ToolClass::Exec, Some(blob("dd00000000000000", 50)), true, json!({ "shown": [[1, 10]] })));
        let jobs = vec![HudJob { id: "j1".into(), command: "make".into(), started_ms: 0, lines: 1 }];
        let mut i = input(&recs);
        i.ledger = Some(&l);
        i.jobs = &jobs;
        i.is_child = true;
        i.step = 2;
        i.budget = Budget { max_steps: Some(10), max_minutes: None };
        let expected = format!(
            "Now: 1970-01-01 00:00 UTC\n\n\
Mission state (from the ledger — the ledger tools change it):\n{}\n\n\
Outputs you have not fully looked at (1):\n\
- out:dd00000000000000 (bash): 50 lines, 40 never shown — lines 11-50\n\n\
Out of date (2):\n\
- src/a.rs changed after you last read it — read it again before relying on what you saw\n\
- src/a.rs changed after you ran `cargo test -p x` — run it again before relying on its result\n\n\
Running (1):\n- job j1 `make` — <1 min, 1 lines so far\n\n\
Waiting on the operator (1):\n- q2: Which branch should this target?\n\n\
Budget: step 2 of 10",
            l.brief(&BriefOpts::default())
        );
        assert_eq!(render(&i), expected);
    }

    #[test]
    fn caps_and_more_marker() {
        let kids: Vec<HudChild> =
            (0..11).map(|k| HudChild { id: format!("s{k}"), role: "w".into(), title: "t".into(), step: k }).collect();
        let mut i = input(EMPTY);
        i.children = &kids;
        let out = render(&i);
        assert!(out.contains("Running (11):"));
        assert!(out.contains("- agent s7 (w)"));
        assert!(!out.contains("- agent s8 (w)"));
        assert!(out.ends_with("\n- (+3 more)"));
    }

    #[test]
    fn lines_are_flat_and_cut_on_characters() {
        let title = format!("é\nñ{}", "漢".repeat(400));
        let kids = vec![HudChild { id: "s1".into(), role: "w".into(), title, step: 1 }];
        let mut i = input(EMPTY);
        i.children = &kids;
        let out = render(&i);
        let entry = out.lines().last().unwrap_or("");
        assert_eq!(entry.chars().count(), MAX_LINE);
        assert!(entry.ends_with('…'));
        assert!(entry.contains("é ñ"));
        assert_eq!(out.lines().count(), 4);
    }

    #[test]
    fn re_read_drops_stale_read() {
        let mut recs = stale_records();
        // A newer read of the same path after the edit.
        recs.push(result(8, "r2", "read", ToolClass::Read, None, false, json!({"path": "src/a.rs"})));
        let out = render(&input(&recs));
        assert!(!out.contains("changed after you last read it"), "{out}");
    }

    #[test]
    fn stale_dedup_keeps_one_entry_per_key() {
        let items = stale_lines(&stale_records());
        assert_eq!(items.len(), 2);
    }
}
