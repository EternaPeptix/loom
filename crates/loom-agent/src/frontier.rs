//! The frontier: an honest, rising picture of how far the work has got, read from the ledger alone.
//!
//! CONTRACT.
//!
//! On a hard task a model sees time pass but not progress, and over-reads a pile of failed attempts as
//! "impossible". The frontier separates what is established, what is ruled out WITH evidence, what is
//! merely set aside, and what is still open. It gives no percentage of an unknown total and judges only
//! by ledger evidence, never by prose.
//!
//! - `frontier(ledger, now_ms)` is pure. `established`: claims `Supported` (with text), then security
//!   hypotheses `Supported` (id only), in ledger order. `ruled_out`: claims `Refuted` that carry at least
//!   one evidence id (a refutation without evidence is not shown), then security hypotheses `Refuted`
//!   with at least one evidence or counterevidence id (id only). `set_aside`: dead ends, text
//!   `{what} — {why}`; set aside by the model, not refuted. `open_leads`: plan steps `Todo`/`Doing`,
//!   claims `Open`, security hypotheses `Open` (priority descending, then id), routes to revisit
//!   (`security.newly_unlocked_at(now_ms)`), in that order. `untested`: security assets with coverage
//!   `Untested`, mandatory ones first, then by id. `surfaces_closed` counts assets that are `Tested` or
//!   `Deferred`. Security items carry no text: their free-form text can hold secrets.
//! - `attempts_run(records)` counts admitted execution attempts the way the session's exec budget does:
//!   one per call id among `exec_started` records and `tool_result` records of class `Exec` whose status
//!   is neither `Denied` nor `Invalid`. `frontier` leaves `attempts_run` 0; the caller sets it.
//! - Kinds inside `open_leads` are told apart by id: `hy-…` is a hypothesis, `p{n}` a plan step, `c{n}` a
//!   claim, anything else a route to revisit.
//! - `render(f)` gives the block shown in the HUD (see `hud`), or `None` when `f.is_empty()`. Lines, only
//!   the non-empty ones, in this order:
//!   `Where the work stands:`, `- Established: …`, `- Ruled out with evidence: …`,
//!   `- Set aside without evidence: …`, `- Open leads: …`, `- Surfaces: …`, `- Attempts run in this
//!   session: …`. Id lists show at most 8 ids then `, …`. Every line is cut to `hud::MAX_LINE`.
//! - `directions(f, max)` gives up to `max` one-line open routes, in the priority: untested surfaces,
//!   open plan steps, open claims, routes to revisit, open hypotheses, set-aside approaches; then
//!   `- (+{k} more)` when more remain.
//!
//! Tests required: each classification, `no_open_route`, `is_empty`, `attempts_run`, exact `render` text
//! with caps and multi-byte cutting, `directions` order, cap and remainder.

use crate::hud::one_line;
use loom_core::event::{Event, Record, ToolClass, ToolStatus};
use loom_core::ledger::{ClaimStatus, LedgerState, StepStatus};
use loom_core::security_state::{CoverageDisposition, HypothesisStatus};
use loom_core::CallId;
use std::collections::HashSet;

/// Ids shown in one line of the block.
const MAX_IDS: usize = 8;

/// One entry. `text` is empty for security records: their free-form text is never shown (it can hold secrets).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontierItem {
    pub id: String,
    pub text: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frontier {
    /// Claims `Supported` (text), then security hypotheses `Supported` (id only). Ledger order.
    pub established: Vec<FrontierItem>,
    /// Claims `Refuted` that have at least one evidence id (text), then security hypotheses `Refuted`
    /// with at least one evidence or counterevidence id (id only).
    pub ruled_out: Vec<FrontierItem>,
    /// Ledger dead ends (`x{i}`), text `"{what} — {why}"`. Set aside by the model, NOT refuted.
    pub set_aside: Vec<FrontierItem>,
    /// Plan steps Todo/Doing (text), claims Open (text), security hypotheses Open (id only, priority
    /// desc then id), routes to revisit `security.newly_unlocked_at(now_ms)` (id only). In that order.
    pub open_leads: Vec<FrontierItem>,
    /// Security assets whose coverage is `Untested` (id only): mandatory ones first, then by id.
    pub untested: Vec<FrontierItem>,
    pub surfaces_total: usize,
    /// Assets whose coverage is not `Untested` (Tested or Deferred).
    pub surfaces_closed: usize,
    /// Admitted execution attempts of the session the caller describes (see `attempts_run`); 0 when
    /// the caller has no records.
    pub attempts_run: u64,
}

fn item(id: &str, text: &str) -> FrontierItem {
    FrontierItem { id: id.to_string(), text: text.to_string() }
}

/// Pure; reads only the ledger. `attempts_run` is left 0.
pub fn frontier(ledger: &LedgerState, now_ms: u64) -> Frontier {
    let sec = &ledger.security;
    let mut f = Frontier::default();

    for c in ledger.claims.iter().filter(|c| c.status == ClaimStatus::Supported) {
        f.established.push(item(&c.id, &c.text));
    }
    let mut hyps: Vec<_> = sec.hypotheses.values().collect();
    hyps.sort_by(|a, b| a.n.cmp(&b.n).then_with(|| a.id.cmp(&b.id)));
    for h in hyps.iter().filter(|h| h.status == HypothesisStatus::Supported) {
        f.established.push(item(&h.id, ""));
    }

    for c in ledger.claims.iter().filter(|c| c.status == ClaimStatus::Refuted && !c.evidence.is_empty()) {
        f.ruled_out.push(item(&c.id, &c.text));
    }
    for h in hyps
        .iter()
        .filter(|h| h.status == HypothesisStatus::Refuted && !(h.evidence.is_empty() && h.counterevidence.is_empty()))
    {
        f.ruled_out.push(item(&h.id, ""));
    }

    for d in &ledger.dead_ends {
        f.set_aside.push(item(&d.id, &format!("{} — {}", d.what, d.why)));
    }

    for p in ledger.plan.iter().filter(|p| matches!(p.status, StepStatus::Todo | StepStatus::Doing)) {
        f.open_leads.push(item(&p.id, &p.text));
    }
    for c in ledger.claims.iter().filter(|c| c.status == ClaimStatus::Open) {
        f.open_leads.push(item(&c.id, &c.text));
    }
    let mut open: Vec<_> = sec.hypotheses.values().filter(|h| h.status == HypothesisStatus::Open).collect();
    open.sort_by(|a, b| b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id)));
    for h in open {
        f.open_leads.push(item(&h.id, ""));
    }
    for id in sec.newly_unlocked_at(now_ms) {
        f.open_leads.push(item(&id, ""));
    }

    let mut untested: Vec<_> = sec.assets.values().filter(|a| a.coverage == CoverageDisposition::Untested).collect();
    untested.sort_by(|a, b| b.mandatory.cmp(&a.mandatory).then_with(|| a.id.cmp(&b.id)));
    f.untested = untested.iter().map(|a| item(&a.id, "")).collect();
    f.surfaces_total = sec.assets.len();
    f.surfaces_closed = f.surfaces_total.saturating_sub(f.untested.len());
    f
}

/// Admitted execution attempts in `records`: one per call id among `exec_started` records and `tool_result`
/// records of class `Exec` whose status is neither Denied nor Invalid (as the session's exec budget counts).
pub fn attempts_run(records: &[Record]) -> u64 {
    let mut admitted: HashSet<&CallId> = HashSet::new();
    for r in records {
        match &r.event {
            Event::ExecStarted { call_id } => {
                admitted.insert(call_id);
            }
            Event::ToolResult(t)
                if t.class == ToolClass::Exec && !matches!(t.status, ToolStatus::Denied | ToolStatus::Invalid) =>
            {
                admitted.insert(&t.call_id);
            }
            _ => {}
        }
    }
    u64::try_from(admitted.len()).unwrap_or(u64::MAX)
}

impl Frontier {
    /// No open lead, no untested surface and nothing set aside: the ledger shows no open route.
    pub fn no_open_route(&self) -> bool {
        self.open_leads.is_empty() && self.untested.is_empty() && self.set_aside.is_empty()
    }

    /// True when there is nothing at all to show (all lists empty, no surfaces, attempts 0).
    pub fn is_empty(&self) -> bool {
        self.established.is_empty()
            && self.ruled_out.is_empty()
            && self.set_aside.is_empty()
            && self.open_leads.is_empty()
            && self.untested.is_empty()
            && self.surfaces_total == 0
            && self.attempts_run == 0
    }
}

/// `a, b, c` with at most `MAX_IDS` ids, then `, …`.
pub(crate) fn id_list(items: &[FrontierItem]) -> String {
    let mut ids: Vec<&str> = items.iter().take(MAX_IDS).map(|i| i.id.as_str()).collect();
    if items.len() > MAX_IDS {
        ids.push("…");
    }
    ids.join(", ")
}

/// The HUD/brief block, or None when `is_empty()`.
pub fn render(f: &Frontier) -> Option<String> {
    if f.is_empty() {
        return None;
    }
    let mut lines: Vec<String> = vec!["Where the work stands:".to_string()];
    if let Some(last) = f.established.last() {
        let mut line = format!("- Established: {} ({})", f.established.len(), id_list(&f.established));
        if !last.text.is_empty() {
            line.push_str(&format!("; latest {}: {}", last.id, last.text));
        }
        lines.push(line);
    }
    if !f.ruled_out.is_empty() {
        lines.push(format!("- Ruled out with evidence: {} ({})", f.ruled_out.len(), id_list(&f.ruled_out)));
    }
    if !f.set_aside.is_empty() {
        lines.push(format!(
            "- Set aside without evidence: {} ({}) — set aside is not refuted; a different attempt can reopen it",
            f.set_aside.len(),
            id_list(&f.set_aside)
        ));
    }
    if !f.open_leads.is_empty() {
        lines.push(format!("- Open leads: {} ({})", f.open_leads.len(), id_list(&f.open_leads)));
    }
    if f.surfaces_total > 0 {
        let mut line = format!("- Surfaces: {} of {} closed", f.surfaces_closed, f.surfaces_total);
        if !f.untested.is_empty() {
            line.push_str(&format!("; untested: {}", id_list(&f.untested)));
        }
        lines.push(line);
    }
    if f.attempts_run > 0 {
        lines.push(format!(
            "- Attempts run in this session: {}; ruled out with evidence: {}. A failed attempt rules out that attempt, not the approach.",
            f.attempts_run,
            f.ruled_out.len()
        ));
    }
    Some(lines.iter().map(|l| one_line(l)).collect::<Vec<_>>().join("\n"))
}

#[derive(PartialEq)]
enum Kind {
    Plan,
    Claim,
    Route,
    Hypothesis,
}

fn numbered(id: &str, prefix: char) -> bool {
    id.strip_prefix(prefix).is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()))
}

fn kind_of(id: &str) -> Kind {
    if id.starts_with("hy-") {
        Kind::Hypothesis
    } else if numbered(id, 'p') {
        Kind::Plan
    } else if numbered(id, 'c') {
        Kind::Claim
    } else {
        Kind::Route
    }
}

/// Up to `max` one-line open routes for "what to try next" lists: untested surfaces, open plan steps, open
/// claims, routes to revisit, open hypotheses, set-aside approaches; then `- (+{k} more)` if more remain.
pub fn directions(f: &Frontier, max: usize) -> Vec<String> {
    let mut all: Vec<String> = Vec::new();
    for u in &f.untested {
        all.push(format!("- untested surface {}", u.id));
    }
    let leads = |kind: Kind| f.open_leads.iter().filter(move |i| kind_of(&i.id) == kind);
    for i in leads(Kind::Plan) {
        all.push(format!("- open plan step {}: {}", i.id, i.text));
    }
    for i in leads(Kind::Claim) {
        all.push(format!("- open claim {}: {}", i.id, i.text));
    }
    for i in leads(Kind::Route) {
        all.push(format!("- route to revisit {}", i.id));
    }
    for i in leads(Kind::Hypothesis) {
        all.push(format!("- open hypothesis {} (security_query for details)", i.id));
    }
    for i in &f.set_aside {
        all.push(format!("- set aside, not refuted, {}: {} — a different attempt can reopen it", i.id, i.text));
    }
    let total = all.len();
    let mut out: Vec<String> = all.iter().take(max).map(|l| one_line(l)).collect();
    if total > max {
        out.push(format!("- (+{} more)", total.saturating_sub(max)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::event::{Author, ToolResult};
    use loom_core::ledger::{Claim, DeadEnd, PlanStep};
    use loom_core::security_state::{Asset, AssetKind, BlockedRoute, Condition, ConditionKind, Hypothesis};
    use loom_core::SessionId;

    fn claim(id: &str, text: &str, status: ClaimStatus, evidence: &[&str]) -> Claim {
        Claim {
            id: id.into(),
            text: text.into(),
            status,
            note: String::new(),
            evidence: evidence.iter().map(|e| e.to_string()).collect(),
        }
    }

    fn step(id: &str, status: StepStatus) -> PlanStep {
        PlanStep { id: id.into(), text: format!("step {id}"), status, note: String::new(), evidence: vec![] }
    }

    fn hyp(id: &str, status: HypothesisStatus, priority: u8, n: u64, ev: usize, counter: usize) -> Hypothesis {
        Hypothesis {
            id: id.into(),
            text: "SECRET hypothesis".into(),
            priority,
            owner: SessionId::from("s-owner"),
            status,
            evidence: vec!["e".into(); ev],
            counterevidence: vec!["e".into(); counter],
            note: "SECRET note".into(),
            judge: None,
            n,
        }
    }

    fn asset(id: &str, mandatory: bool, coverage: CoverageDisposition) -> Asset {
        Asset {
            id: id.into(),
            kind: AssetKind::Host,
            locator: "SECRET locator".into(),
            evidence: vec![],
            mandatory,
            parent: None,
            coverage,
            n: 1,
        }
    }

    fn ids(items: &[FrontierItem]) -> Vec<&str> {
        items.iter().map(|i| i.id.as_str()).collect()
    }

    fn rec(seq: u64, event: Event) -> Record {
        Record { seq, ts_ms: seq, author: Author::Tool, prev: "0".repeat(64), event }
    }

    fn result(seq: u64, id: &str, class: ToolClass, status: ToolStatus) -> Record {
        rec(
            seq,
            Event::ToolResult(ToolResult {
                call_id: CallId::from(id),
                name: "t".into(),
                status,
                text: String::new(),
                output: None,
                cut: false,
                class,
                meta: Default::default(),
                duration_ms: 0,
            }),
        )
    }

    #[test]
    fn claims_are_classified_by_status_and_evidence() {
        let l = LedgerState {
            claims: vec![
                claim("c1", "works", ClaimStatus::Supported, &["e1"]),
                claim("c2", "is a bug", ClaimStatus::Refuted, &["e2"]),
                claim("c3", "is slow", ClaimStatus::Refuted, &[]),
                claim("c4", "maybe", ClaimStatus::Open, &[]),
                claim("c5", "dropped", ClaimStatus::Withdrawn, &["e3"]),
                claim("c6", "also works", ClaimStatus::Supported, &["e4"]),
            ],
            ..Default::default()
        };
        let f = frontier(&l, 0);
        assert_eq!(ids(&f.established), ["c1", "c6"]);
        assert_eq!(f.established[1].text, "also works");
        assert_eq!(ids(&f.ruled_out), ["c2"]);
        assert_eq!(ids(&f.open_leads), ["c4"]);
        assert!(f.set_aside.is_empty() && f.untested.is_empty());
        assert_eq!((f.surfaces_total, f.surfaces_closed, f.attempts_run), (0, 0, 0));
    }

    #[test]
    fn plan_steps_and_dead_ends() {
        let l = LedgerState {
            plan: vec![
                step("p1", StepStatus::Done),
                step("p2", StepStatus::Doing),
                step("p3", StepStatus::Dropped),
                step("p4", StepStatus::Todo),
            ],
            claims: vec![claim("c1", "q", ClaimStatus::Open, &[])],
            dead_ends: vec![DeadEnd { id: "x1".into(), what: "tried mmap".into(), why: "segfaults".into(), n: 1 }],
            ..Default::default()
        };
        let f = frontier(&l, 0);
        assert_eq!(ids(&f.open_leads), ["p2", "p4", "c1"]);
        assert_eq!(f.open_leads[0].text, "step p2");
        assert_eq!(ids(&f.set_aside), ["x1"]);
        assert_eq!(f.set_aside[0].text, "tried mmap — segfaults");
        assert!(f.ruled_out.is_empty());
    }

    #[test]
    fn security_hypotheses_assets_and_routes() {
        let mut l = LedgerState::default();
        let s = &mut l.security;
        for h in [
            hyp("hy-b", HypothesisStatus::Open, 1, 1, 0, 0),
            hyp("hy-a", HypothesisStatus::Open, 1, 2, 0, 0),
            hyp("hy-c", HypothesisStatus::Open, 5, 3, 0, 0),
            hyp("hy-s2", HypothesisStatus::Supported, 1, 5, 1, 0),
            hyp("hy-s1", HypothesisStatus::Supported, 1, 4, 1, 0),
            hyp("hy-r1", HypothesisStatus::Refuted, 1, 6, 0, 0),
            hyp("hy-r2", HypothesisStatus::Refuted, 1, 7, 0, 1),
            hyp("hy-r3", HypothesisStatus::Refuted, 1, 8, 2, 0),
        ] {
            s.hypotheses.insert(h.id.clone(), h);
        }
        for a in [
            asset("as-3", false, CoverageDisposition::Untested),
            asset("as-2", true, CoverageDisposition::Untested),
            asset("as-1", true, CoverageDisposition::Untested),
            asset("as-4", true, CoverageDisposition::Tested { evidence: vec![] }),
            asset("as-5", true, CoverageDisposition::Deferred { reason: "later".into() }),
        ] {
            s.assets.insert(a.id.clone(), a);
        }
        s.blocked.insert(
            "as-9".into(),
            BlockedRoute {
                target: "as-9".into(),
                conditions: vec![Condition { kind: ConditionKind::Auth, value: "v".into() }],
                n: 1,
            },
        );
        let f = frontier(&l, 0);
        assert_eq!(ids(&f.established), ["hy-s1", "hy-s2"]);
        assert!(f.established.iter().all(|i| i.text.is_empty()));
        assert_eq!(ids(&f.ruled_out), ["hy-r2", "hy-r3"]);
        assert_eq!(ids(&f.open_leads), ["hy-c", "hy-a", "hy-b"]);
        assert_eq!(ids(&f.untested), ["as-1", "as-2", "as-3"]);
        assert_eq!((f.surfaces_total, f.surfaces_closed), (5, 2));

        l.security.unlocked.insert(Condition { kind: ConditionKind::Auth, value: "v".into() });
        let f = frontier(&l, 0);
        assert_eq!(ids(&f.open_leads), ["hy-c", "hy-a", "hy-b", "as-9"]);
    }

    #[test]
    fn open_route_and_emptiness() {
        let mut f = Frontier::default();
        assert!(f.is_empty() && f.no_open_route());
        f.established.push(item("c1", "t"));
        assert!(!f.is_empty() && f.no_open_route());
        f.set_aside.push(item("x1", "a — b"));
        assert!(!f.no_open_route());
        f.set_aside.clear();
        f.untested.push(item("as-1", ""));
        assert!(!f.no_open_route());
        f.untested.clear();
        f.open_leads.push(item("p1", "t"));
        assert!(!f.no_open_route());
        let attempts = Frontier { attempts_run: 1, ..Frontier::default() };
        assert!(!attempts.is_empty() && attempts.no_open_route());
        let surfaces = Frontier { surfaces_total: 1, surfaces_closed: 1, ..Frontier::default() };
        assert!(!surfaces.is_empty());
    }

    #[test]
    fn attempts_count_admitted_exec_calls_once() {
        let recs = vec![
            result(1, "a", ToolClass::Exec, ToolStatus::Ok),
            result(2, "b", ToolClass::Exec, ToolStatus::Error),
            result(3, "c", ToolClass::Exec, ToolStatus::Denied),
            result(4, "d", ToolClass::Exec, ToolStatus::Invalid),
            result(5, "e", ToolClass::Read, ToolStatus::Ok),
            rec(6, Event::ExecStarted { call_id: CallId::from("a") }),
            rec(7, Event::ExecStarted { call_id: CallId::from("f") }),
        ];
        // a (counted once although started and finished), b, and f (started, no result yet).
        assert_eq!(attempts_run(&recs), 3);
        assert_eq!(attempts_run(&[]), 0);
    }

    fn full() -> Frontier {
        Frontier {
            established: vec![item("c1", "a"), item("c3", "the parser drops the last token")],
            ruled_out: vec![item("c2", "b")],
            set_aside: vec![item("x1", "tried mmap — segfaults")],
            open_leads: vec![item("p2", "t"), item("c4", "u")],
            untested: vec![item("as-1", ""), item("as-2", "")],
            surfaces_total: 3,
            surfaces_closed: 1,
            attempts_run: 7,
        }
    }

    #[test]
    fn render_none_when_empty_and_exact_when_full() {
        assert_eq!(render(&Frontier::default()), None);
        let want = "Where the work stands:\n\
- Established: 2 (c1, c3); latest c3: the parser drops the last token\n\
- Ruled out with evidence: 1 (c2)\n\
- Set aside without evidence: 1 (x1) — set aside is not refuted; a different attempt can reopen it\n\
- Open leads: 2 (p2, c4)\n\
- Surfaces: 1 of 3 closed; untested: as-1, as-2\n\
- Attempts run in this session: 7; ruled out with evidence: 1. A failed attempt rules out that attempt, not the approach.";
        assert_eq!(render(&full()).as_deref(), Some(want));
    }

    #[test]
    fn render_each_line_alone() {
        let one = |f: Frontier| render(&f).unwrap_or_default();
        let head = "Where the work stands:\n";
        assert_eq!(
            one(Frontier { established: vec![item("hy-1", "")], ..Frontier::default() }),
            format!("{head}- Established: 1 (hy-1)")
        );
        assert_eq!(
            one(Frontier { ruled_out: vec![item("c2", "b")], ..Frontier::default() }),
            format!("{head}- Ruled out with evidence: 1 (c2)")
        );
        assert_eq!(
            one(Frontier { open_leads: vec![item("p1", "x")], ..Frontier::default() }),
            format!("{head}- Open leads: 1 (p1)")
        );
        assert_eq!(
            one(Frontier { surfaces_total: 2, surfaces_closed: 2, ..Frontier::default() }),
            format!("{head}- Surfaces: 2 of 2 closed")
        );
        assert_eq!(
            one(Frontier { attempts_run: 2, ..Frontier::default() }),
            format!(
                "{head}- Attempts run in this session: 2; ruled out with evidence: 0. A failed attempt rules out that attempt, not the approach."
            )
        );
    }

    #[test]
    fn render_caps_ids_and_cuts_long_multibyte_lines() {
        let many: Vec<FrontierItem> = (1..=10).map(|i| item(&format!("c{i}"), "")).collect();
        let f = Frontier { open_leads: many, ..Frontier::default() };
        let text = render(&f).unwrap_or_default();
        assert!(text.ends_with("- Open leads: 10 (c1, c2, c3, c4, c5, c6, c7, c8, …)"), "{text}");

        let long = "é".repeat(400);
        let f = Frontier { established: vec![item("c1", &format!("{long}\nsecond line"))], ..Frontier::default() };
        let text = render(&f).unwrap_or_default();
        let line = text.lines().nth(1).unwrap_or_default();
        assert_eq!(line.chars().count(), crate::hud::MAX_LINE);
        assert!(line.ends_with('…'));
        assert!(line.starts_with("- Established: 1 (c1); latest c1: ééé"));
    }

    #[test]
    fn directions_order_cap_and_remainder() {
        let mut f = full();
        f.open_leads = vec![item("p1", "read"), item("c4", "claim text"), item("hy-9", ""), item("as-7", "")];
        let all = directions(&f, 20);
        assert_eq!(
            all,
            [
                "- untested surface as-1",
                "- untested surface as-2",
                "- open plan step p1: read",
                "- open claim c4: claim text",
                "- route to revisit as-7",
                "- open hypothesis hy-9 (security_query for details)",
                "- set aside, not refuted, x1: tried mmap — segfaults — a different attempt can reopen it",
            ]
        );
        let cut = directions(&f, 3);
        assert_eq!(cut.len(), 4);
        assert_eq!(cut[2], "- open plan step p1: read");
        assert_eq!(cut[3], "- (+4 more)");
        assert_eq!(directions(&f, 7).len(), 7);
        assert!(directions(&Frontier::default(), 5).is_empty());
        let long = Frontier { open_leads: vec![item("c1", &"x".repeat(500))], ..Frontier::default() };
        assert_eq!(directions(&long, 1)[0].chars().count(), crate::hud::MAX_LINE);
    }

    #[test]
    fn security_text_never_appears() {
        let mut l = LedgerState::default();
        l.security.hypotheses.insert("hy-1".into(), hyp("hy-1", HypothesisStatus::Supported, 1, 1, 1, 0));
        l.security.hypotheses.insert("hy-2".into(), hyp("hy-2", HypothesisStatus::Open, 1, 2, 0, 0));
        l.security.assets.insert("as-1".into(), asset("as-1", true, CoverageDisposition::Untested));
        let f = frontier(&l, 0);
        let text = render(&f).unwrap_or_default();
        assert!(text.contains("hy-1") && text.contains("hy-2") && text.contains("as-1"), "{text}");
        assert!(!text.contains("SECRET"), "{text}");
        assert!(!directions(&f, 9).join("\n").contains("SECRET"));
    }
}
