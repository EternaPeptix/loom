//! The ledger: typed mission state that must outlive any context window.
//!
//! This file defines the ops (what gets written to the journal) and the folded state (what readers
//! see). `LedgerState::fold` is the only reader of ops; nothing parses the generated Markdown.
//!
//! Authorship rules enforced by the runtime before an op is appended:
//! - `GoalSet`, `ConstraintAdd`, `ApprovalGrant`, `QuestionAnswer` come only from user input.
//! - `EvidenceAdd` is attested: the runtime confirms the cited tool call exists in the cited session
//!   log, copies the stored output's hash, and checks any quote verbatim.

use crate::ids::{BlobId, CallId, SessionId};
use serde::{Deserialize, Serialize};

/// One journal entry's payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum LedgerOp {
    /// The mission goal, in the user's words.
    GoalSet { text: String },
    /// A standing instruction or prohibition from the user, verbatim.
    ConstraintAdd { text: String },
    ConstraintRetire { id: String, reason: String },
    /// Replace the plan with these steps (ids `p1`, `p2`, … are assigned in order).
    PlanSet { steps: Vec<String> },
    PlanAdd { text: String },
    PlanUpdate {
        id: String,
        status: StepStatus,
        /// How it was verified, or why it was dropped.
        #[serde(default)]
        note: String,
        #[serde(default)]
        evidence: Vec<String>,
    },
    /// A choice and why it was made.
    Decision { text: String, reason: String },
    /// Something tried or considered that did not work, and why. Prevents retries of dead ends.
    DeadEnd { what: String, why: String },
    /// A statement that could reach a report.
    ClaimAdd { text: String },
    ClaimUpdate { id: String, status: ClaimStatus, #[serde(default)] note: String },
    EvidenceAdd(EvidenceInput),
    /// Something owed: a running job, a child, an unanswered question, an unverified edit, a promise.
    ObligationOpen { kind: ObligationKind, text: String, #[serde(default)] reference: String },
    ObligationSettle { id: String, outcome: String },
    /// A user approval, verbatim, with what it covers.
    ApprovalGrant { text: String, scope: String },
    ApprovalUse { id: String, used_for: String },
    QuestionAsk { text: String, #[serde(default)] blocking: bool },
    QuestionAnswer { id: String, answer: String },
    /// The agent says the goal is met.
    FinishClaim { summary: String, #[serde(default)] evidence: Vec<String> },
    FinishVerdict { claim: String, accepted: bool, #[serde(default)] objections: Vec<String>, #[serde(default)] verifier: Option<SessionId> },
    /// The agent concludes that the goal is met (`supported`) or cannot be met as stated (`refuted`),
    /// citing execution evidence. `open` is never a write target and there is no way back to nothing.
    GoalMetSet {
        status: GoalMetStatus,
        #[serde(default)]
        note: String,
        #[serde(default)]
        evidence: Vec<String>,
    },
    /// The operator accepts the result short of the goal and the work may stop. Operator only.
    OperatorRelease { reason: String },
    /// Network hosts the operator has authorized for this mission, one host per entry. Operator only.
    ScopeGrant {
        hosts: Vec<String>,
        #[serde(default)]
        note: Option<String>,
    },
}

/// Where the goal-met claim stands. There is deliberately no `Withdrawn`: once concluded it can only
/// move to the other terminal state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalMetStatus {
    /// Not yet concluded.
    #[default]
    Open,
    /// The goal is met.
    Supported,
    /// The goal cannot be met as stated.
    Refuted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Todo,
    Doing,
    Done,
    Dropped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Open,
    Supported,
    Refuted,
    Withdrawn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Something was run and its behaviour observed.
    Execution,
    /// Something was read.
    Static,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationKind {
    Job,
    Child,
    Question,
    UnverifiedEdit,
    Promise,
}

/// What `evidence_add` records. `blob` and `attested` are filled in by the runtime, never by the model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceInput {
    /// Claim id this supports or undermines.
    pub claim: String,
    pub kind: EvidenceKind,
    pub supports: bool,
    pub session: SessionId,
    pub call_id: CallId,
    #[serde(default)]
    pub blob: Option<BlobId>,
    /// 1-based inclusive line range within the stored output.
    #[serde(default)]
    pub lines: Option<(u64, u64)>,
    /// Verbatim text from that range.
    #[serde(default)]
    pub quote: Option<String>,
    /// What this observation shows, and what it does not.
    pub note: String,
    #[serde(default)]
    pub attested: bool,
}

/// One line of a mission journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Position in the journal, starting at 1.
    pub n: u64,
    pub ts_ms: u64,
    /// The session whose action produced this entry.
    pub session: SessionId,
    /// True when the entry came from user input rather than a model tool call.
    #[serde(default)]
    pub from_user: bool,
    #[serde(flatten)]
    pub op: LedgerOp,
    /// HMAC-SHA256 chain value (hex). See `journal`.
    pub mac: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    pub id: String,
    pub text: String,
    pub retired: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: String,
    pub text: String,
    pub status: StepStatus,
    pub note: String,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub id: String,
    pub text: String,
    pub reason: String,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadEnd {
    pub id: String,
    pub what: String,
    pub why: String,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub id: String,
    pub text: String,
    pub status: ClaimStatus,
    pub note: String,
    /// Evidence ids attached to this claim.
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    #[serde(flatten)]
    pub input: EvidenceInput,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obligation {
    pub id: String,
    pub kind: ObligationKind,
    pub text: String,
    pub reference: String,
    /// `None` while open.
    pub outcome: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub text: String,
    pub scope: String,
    /// What it was used for, once used.
    pub used_for: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Question {
    pub id: String,
    pub text: String,
    pub blocking: bool,
    pub answer: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishRecord {
    pub id: String,
    pub summary: String,
    pub evidence: Vec<String>,
    /// `None` until a verdict is recorded.
    pub accepted: Option<bool>,
    pub objections: Vec<String>,
}

/// The harness-held claim about whether the goal is met. A singleton, not one of `claims`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalMet {
    pub status: GoalMetStatus,
    pub note: String,
    /// Evidence ids cited for the current status.
    pub evidence: Vec<String>,
    /// Journal position of the entry that set the current status; 0 while open.
    pub n: u64,
}

/// The operator's acceptance of the result short of the goal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    pub reason: String,
    /// Journal position of the release entry.
    pub n: u64,
}

/// One operator grant of network hosts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeGrantRecord {
    pub id: String,
    /// The hosts as written.
    pub hosts: Vec<String>,
    pub note: Option<String>,
    pub n: u64,
}

/// The folded state of a mission. Ids are assigned by `fold`: constraints `k1…`, plan steps `p1…`,
/// decisions `d1…`, dead ends `x1…`, claims `c1…`, evidence `e1…`, obligations `o1…`,
/// approvals `a1…`, questions `q1…`, finish claims `f1…`, scope grants `s1…`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerState {
    pub goal: Option<String>,
    pub constraints: Vec<Constraint>,
    pub plan: Vec<PlanStep>,
    pub decisions: Vec<Decision>,
    pub dead_ends: Vec<DeadEnd>,
    pub claims: Vec<Claim>,
    pub evidence: Vec<Evidence>,
    pub obligations: Vec<Obligation>,
    pub approvals: Vec<Approval>,
    pub questions: Vec<Question>,
    pub finishes: Vec<FinishRecord>,
    /// The goal-met claim: `None` until a goal is set, then `Open` or terminal.
    #[serde(default)]
    pub goal_met: Option<GoalMet>,
    /// The operator's release, if given. Never evicted.
    #[serde(default)]
    pub release: Option<Release>,
    /// Operator grants of network hosts, in order. Never evicted.
    #[serde(default)]
    pub scope_grants: Vec<ScopeGrantRecord>,
    /// Number of entries folded.
    pub entries: u64,
}

// ---------------------------------------------------------------------------------------------
// CONTRACT.
//
// Ids are assigned by position: the i-th `ConstraintAdd` is `k{i}`, plan steps `p{i}` (a `PlanSet`
// REPLACES the plan: earlier steps not `Done` become `Dropped` with note "replaced by a new plan" and
// stay listed; numbering continues, it never restarts), decisions `d{i}`, dead ends `x{i}`, claims
// `c{i}`, evidence `e{i}`, obligations `o{i}`, approvals `a{i}`, questions `q{i}`, finish claims
// `f{i}`. `apply` never fails: an op that refers to an unknown id is ignored (validation happens
// before an op is written, in `validate`).
//
// `apply` effects beyond the obvious:
// - `EvidenceAdd` appends the evidence and adds its id to the claim's `evidence` list.
// - `ClaimUpdate`/`PlanUpdate` overwrite status and note; `PlanUpdate.evidence` is appended.
// - `QuestionAnswer` sets the answer; `ObligationSettle` sets the outcome; `ApprovalUse` sets
//   `used_for`; `ConstraintRetire` sets `retired`.
// - `FinishVerdict.claim` names a finish id; it sets `accepted` and `objections`.
//
// `validate(op, from_user)` returns `Err(message)` (a sentence telling the model what to do instead):
// - `GoalSet`, `ConstraintAdd`, `ConstraintRetire`, `ApprovalGrant`, `QuestionAnswer` require
//   `from_user`; the message says these record the operator's words and cannot be written by a tool
//   call;
// - any op naming an id that does not exist → message lists the ids that do exist for that kind;
// - `PlanSet` with no steps, or any empty/whitespace `text`/`what`/`summary` → refused;
// - `PlanUpdate` to `Done` requires a non-empty `note` or at least one evidence id, and every
//   evidence id must exist; to `Dropped` requires a non-empty `note`;
// - `ClaimUpdate` to `Supported` requires the claim to have at least one evidence record with
//   `supports == true` and `attested == true`; to `Refuted`/`Withdrawn` requires a non-empty note;
// - `EvidenceAdd` requires the claim id to exist and a non-empty `note`;
// - `ObligationSettle`/`ApprovalUse` on an already settled/used item → refused, saying so;
// - `FinishClaim` is refused while `open_items()` is not empty; the message lists every open item by
//   id and first 80 characters, and for each kind how to close it;
// - `FinishVerdict` may be written with either value of `from_user`; the finish id must exist and
//   must not have a verdict yet.
//
// Goal-met claim (`GoalMetSet`, model-authored). `LedgerState.goal_met` is `None` before any goal is
// set and `Open` from the `GoalSet` that sets one; it is a singleton and is not in `claims`, so
// `open_items()` never counts it. Its status is `Open`, `Supported` (the goal is met) or `Refuted` (the
// goal cannot be met as stated). There is NO withdrawn state: `Open` is never a write target (a
// `GoalMetSet` with `Open` is refused by `validate` and ignored by `apply`), so the model can move the
// claim toward a conclusion but never retract it. `validate` requires: a goal is set; the target is
// `Supported` or `Refuted`; a non-blank `note`; at least one named evidence id, every id existing, every
// one attested and supporting; at least one of them of kind `Execution` (reading source alone is
// refused: run the target and cite the run). Once terminal it may be written again only with the OTHER
// terminal status and at least one execution evidence record added after the entry that set the current
// status (`GoalMet.n`); repeating the current status is refused. `apply` replaces status, note and
// evidence and records the entry position.
//
// Operator release (`OperatorRelease`, `from_user` only): sets `LedgerState.release` (reason, entry
// position) once; refused for a model, with a blank reason, before a goal is set, or when already
// released. It does not touch `goal_met`: the views say "released by the operator (goal not established)".
//
// Scope grant (`ScopeGrant`, `from_user` only): appends a `ScopeGrantRecord` with id `s{i}` (the i-th
// grant; the letter `s` is used for nothing else). Hosts are kept as written and are not parsed; `validate`
// requires a non-empty list, no blank entry, and no entry containing whitespace or a comma (one host per
// entry). `granted_hosts()` returns every host granted so far, de-duplicated ignoring ASCII case, in
// first-seen order. Release and grants are never evicted.
//
// `open_items()`: plan steps `Todo`/`Doing`; obligations with no outcome; claims with status `Open`;
// questions with `blocking` and no answer.
//
// `brief(opts)` renders the compact state text used in the HUD and after a re-weave, in this order,
// omitting empty sections: `Goal:` (full text), `Constraints:` (active only, verbatim), `Plan:` (one
// line per non-dropped step: `[x] p1 text — note` / `[>] doing` / `[ ] todo`), `Open obligations:`,
// `Claims:` (id, status, text, evidence ids), `Decisions:` (last `opts.max_decisions`),
// `Dead ends:` (last `opts.max_dead_ends`) — each of these two starts, right under its heading, with the
// line `(N older not shown: {first id}–{last id}, or the one id when N is 1; call `ledger` to read them)` when older items were left out —,
// `Approvals:` (unused ones, verbatim, with scope),
// `Unanswered questions:`. Right after `Goal:` (when a goal is set, or grants exist) comes a section of
// lines: `Goal status: open (not yet concluded)` / `Goal status: met — note (evidence: ids)` /
// `Goal status: cannot be met as stated — note (evidence: ids)`; when released `released by the operator
// (goal not established): reason`; and `authorized hosts: a, b, c` or `authorized hosts: none granted`.
// The reason and the hosts are the operator's words and are never cut. Evidence quotes are not included. Each line is cut at `opts.max_line`
// characters with `…`. The output is deterministic.
//
// `render_markdown()` renders everything (all sections, all records including evidence with handle,
// line range and quote) as a Markdown document that begins with the line
// `<!-- generated from the mission journal; edits here are ignored -->`.
//
// Tests required: id assignment incl. PlanSet replacement; every validate rule (accept and refuse);
// open_items; apply ignores unknown ids; fold == repeated apply; brief ordering/omission/cutting and
// determinism; markdown contains every record; serde round trip of every op variant.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenItems {
    /// Plan step ids not done or dropped.
    pub plan: Vec<String>,
    pub obligations: Vec<String>,
    /// Claim ids still `Open`.
    pub claims: Vec<String>,
    /// Blocking questions without an answer.
    pub questions: Vec<String>,
}

impl OpenItems {
    pub fn is_empty(&self) -> bool {
        self.plan.is_empty() && self.obligations.is_empty() && self.claims.is_empty() && self.questions.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BriefOpts {
    pub max_decisions: usize,
    pub max_dead_ends: usize,
    pub max_line: usize,
}

impl Default for BriefOpts {
    fn default() -> Self {
        Self { max_decisions: 12, max_dead_ends: 20, max_line: 400 }
    }
}

fn next_id(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", len.saturating_add(1))
}

fn blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// Cut `s` to at most `max` characters, ending in `…` when something was removed.
fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    if max > 0 {
        out.push('…');
    }
    out
}

/// A single-line, cut rendering of free text (newlines and runs of spaces collapse to one space).
fn line(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    cut(&flat, max)
}

/// The first 80 characters of `s` on one line, followed by `…` when more follows.
fn preview(s: &str) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = flat.chars().take(80).collect();
    if flat.chars().count() > 80 {
        out.push('…');
    }
    out
}

fn ids<'a>(it: impl Iterator<Item = &'a str>) -> String {
    let v: Vec<&str> = it.collect();
    if v.is_empty() {
        "none".to_string()
    } else {
        v.join(", ")
    }
}

/// The line that tells the brief's reader that `hidden` oldest items were left out: it names the ids
/// hidden and where to read them. `None` when nothing is hidden.
fn elision<'a>(mut ids: impl Iterator<Item = &'a str>, hidden: usize) -> Option<String> {
    let first = ids.next().filter(|_| hidden > 0)?;
    let range = match ids.nth(hidden.saturating_sub(2)).filter(|_| hidden > 1) {
        Some(last) => format!("{first}–{last}"),
        None => first.to_string(),
    };
    Some(format!("({hidden} older not shown: {range}; call `ledger` to read them)"))
}

/// Refusal text for an id that does not exist: names the ids that do.
fn no_such(kind: &str, id: &str, existing: String) -> String {
    if existing == "none" {
        format!("There is no {kind} with id `{id}`: no {kind} has been recorded yet. Check the id against the ledger brief before using it.")
    } else {
        format!("There is no {kind} with id `{id}`. Existing {kind} ids: {existing}. Use one of those ids exactly as written; ids are never renumbered.")
    }
}

fn user_only(what: &str) -> String {
    format!("{what} records the operator's own words and cannot be written by a tool call. Do not try to record it yourself; if you need the operator to decide or confirm something, use ask_user and the runtime will record their answer.")
}

fn needs_text(what: &str, field: &str) -> String {
    format!("The {field} of {what} is empty. Write what you actually mean, in a sentence or more, and call it again.")
}

impl LedgerState {
    pub fn fold(entries: &[Entry]) -> LedgerState {
        let mut state = LedgerState::default();
        for entry in entries {
            state.apply(entry);
        }
        state
    }

    pub fn apply(&mut self, entry: &Entry) {
        self.entries = self.entries.saturating_add(1);
        let n = entry.n;
        match &entry.op {
            LedgerOp::GoalSet { text } => {
                self.goal = Some(text.clone());
                if self.goal_met.is_none() {
                    self.goal_met = Some(GoalMet { status: GoalMetStatus::Open, note: String::new(), evidence: Vec::new(), n: 0 });
                }
            }
            LedgerOp::ConstraintAdd { text } => {
                let id = next_id("k", self.constraints.len());
                self.constraints.push(Constraint { id, text: text.clone(), retired: None });
            }
            LedgerOp::ConstraintRetire { id, reason } => {
                if let Some(c) = self.constraints.iter_mut().find(|c| &c.id == id) {
                    if c.retired.is_none() {
                        c.retired = Some(reason.clone());
                    }
                }
            }
            LedgerOp::PlanSet { steps } => {
                for step in &mut self.plan {
                    if matches!(step.status, StepStatus::Todo | StepStatus::Doing) {
                        step.status = StepStatus::Dropped;
                        step.note = "replaced by a new plan".to_string();
                    }
                }
                for text in steps {
                    self.push_step(text);
                }
            }
            LedgerOp::PlanAdd { text } => self.push_step(text),
            LedgerOp::PlanUpdate { id, status, note, evidence } => {
                if let Some(step) = self.plan.iter_mut().find(|p| &p.id == id) {
                    step.status = *status;
                    step.note = note.clone();
                    step.evidence.extend(evidence.iter().cloned());
                }
            }
            LedgerOp::Decision { text, reason } => {
                let id = next_id("d", self.decisions.len());
                self.decisions.push(Decision { id, text: text.clone(), reason: reason.clone(), n });
            }
            LedgerOp::DeadEnd { what, why } => {
                let id = next_id("x", self.dead_ends.len());
                self.dead_ends.push(DeadEnd { id, what: what.clone(), why: why.clone(), n });
            }
            LedgerOp::ClaimAdd { text } => {
                let id = next_id("c", self.claims.len());
                self.claims.push(Claim { id, text: text.clone(), status: ClaimStatus::Open, note: String::new(), evidence: Vec::new() });
            }
            LedgerOp::ClaimUpdate { id, status, note } => {
                if let Some(c) = self.claims.iter_mut().find(|c| &c.id == id) {
                    c.status = *status;
                    c.note = note.clone();
                }
            }
            LedgerOp::EvidenceAdd(input) => {
                if let Some(claim) = self.claims.iter_mut().find(|c| c.id == input.claim) {
                    let id = next_id("e", self.evidence.len());
                    claim.evidence.push(id.clone());
                    self.evidence.push(Evidence { id, input: input.clone(), n });
                }
            }
            LedgerOp::ObligationOpen { kind, text, reference } => {
                let id = next_id("o", self.obligations.len());
                self.obligations.push(Obligation { id, kind: *kind, text: text.clone(), reference: reference.clone(), outcome: None });
            }
            LedgerOp::ObligationSettle { id, outcome } => {
                if let Some(o) = self.obligations.iter_mut().find(|o| &o.id == id) {
                    o.outcome = Some(outcome.clone());
                }
            }
            LedgerOp::ApprovalGrant { text, scope } => {
                let id = next_id("a", self.approvals.len());
                self.approvals.push(Approval { id, text: text.clone(), scope: scope.clone(), used_for: None });
            }
            LedgerOp::ApprovalUse { id, used_for } => {
                if let Some(a) = self.approvals.iter_mut().find(|a| &a.id == id) {
                    a.used_for = Some(used_for.clone());
                }
            }
            LedgerOp::QuestionAsk { text, blocking } => {
                let id = next_id("q", self.questions.len());
                self.questions.push(Question { id, text: text.clone(), blocking: *blocking, answer: None });
            }
            LedgerOp::QuestionAnswer { id, answer } => {
                if let Some(q) = self.questions.iter_mut().find(|q| &q.id == id) {
                    q.answer = Some(answer.clone());
                }
            }
            LedgerOp::FinishClaim { summary, evidence } => {
                let id = next_id("f", self.finishes.len());
                self.finishes.push(FinishRecord { id, summary: summary.clone(), evidence: evidence.clone(), accepted: None, objections: Vec::new() });
            }
            LedgerOp::FinishVerdict { claim, accepted, objections, .. } => {
                if let Some(f) = self.finishes.iter_mut().find(|f| &f.id == claim) {
                    f.accepted = Some(*accepted);
                    f.objections = objections.clone();
                }
            }
            LedgerOp::GoalMetSet { status, note, evidence } => {
                // `Open` is never a write target: ignoring it keeps a forged entry from retracting a conclusion.
                if *status != GoalMetStatus::Open {
                    if let Some(gm) = self.goal_met.as_mut() {
                        *gm = GoalMet { status: *status, note: note.clone(), evidence: evidence.clone(), n };
                    }
                }
            }
            LedgerOp::OperatorRelease { reason } => {
                if self.release.is_none() {
                    self.release = Some(Release { reason: reason.clone(), n });
                }
            }
            LedgerOp::ScopeGrant { hosts, note } => {
                let id = next_id("s", self.scope_grants.len());
                self.scope_grants.push(ScopeGrantRecord { id, hosts: hosts.clone(), note: note.clone(), n });
            }
        }
    }

    /// Every host the operator has granted so far, de-duplicated (ignoring ASCII case) in first-seen order.
    pub fn granted_hosts(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for host in self.scope_grants.iter().flat_map(|g| g.hosts.iter()) {
            if !out.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                out.push(host.clone());
            }
        }
        out
    }

    fn push_step(&mut self, text: &str) {
        let id = next_id("p", self.plan.len());
        self.plan.push(PlanStep { id, text: text.to_string(), status: StepStatus::Todo, note: String::new(), evidence: Vec::new() });
    }

    fn check_evidence_ids(&self, wanted: &[String], what: &str) -> Result<(), String> {
        for id in wanted {
            if !self.evidence.iter().any(|e| &e.id == id) {
                let mut msg = no_such("evidence record", id, ids(self.evidence.iter().map(|e| e.id.as_str())));
                msg.push_str(&format!(" Evidence ids are created by the `evidence` tool; record the evidence first, then cite its id in {what}."));
                return Err(msg);
            }
        }
        Ok(())
    }

    pub fn validate(&self, op: &LedgerOp, from_user: bool) -> Result<(), String> {
        match op {
            LedgerOp::GoalSet { text } => {
                if !from_user {
                    return Err(user_only("The goal"));
                }
                if blank(text) {
                    return Err(needs_text("the goal", "text"));
                }
            }
            LedgerOp::ConstraintAdd { text } => {
                if !from_user {
                    return Err(user_only("A constraint"));
                }
                if blank(text) {
                    return Err(needs_text("the constraint", "text"));
                }
            }
            LedgerOp::ConstraintRetire { id, reason } => {
                if !from_user {
                    return Err(user_only("Retiring a constraint"));
                }
                let Some(c) = self.constraints.iter().find(|c| &c.id == id) else {
                    return Err(no_such("constraint", id, ids(self.constraints.iter().map(|c| c.id.as_str()))));
                };
                if c.retired.is_some() {
                    return Err(format!("Constraint {id} is already retired; nothing to do."));
                }
                if blank(reason) {
                    return Err(needs_text("the retirement", "reason"));
                }
            }
            LedgerOp::PlanSet { steps } => {
                if steps.is_empty() {
                    return Err("A plan needs at least one step. List the steps you will take, in order, as the `steps` array.".to_string());
                }
                if steps.iter().any(|s| blank(s)) {
                    return Err(needs_text("a plan step", "text"));
                }
            }
            LedgerOp::PlanAdd { text } => {
                if blank(text) {
                    return Err(needs_text("the plan step", "text"));
                }
            }
            LedgerOp::PlanUpdate { id, status, note, evidence } => {
                if !self.plan.iter().any(|p| &p.id == id) {
                    return Err(no_such("plan step", id, ids(self.plan.iter().map(|p| p.id.as_str()))));
                }
                self.check_evidence_ids(evidence, "`step`")?;
                match status {
                    StepStatus::Done if blank(note) && evidence.is_empty() => {
                        return Err(format!("Plan step {id} cannot be marked done without saying how it was verified. Call `step` again with a `note` describing the check you ran and what it showed, or with `evidence` ids from the `evidence` tool."));
                    }
                    StepStatus::Dropped if blank(note) => {
                        return Err(format!("Plan step {id} cannot be dropped without a reason. Call `step` again with a `note` saying why the step is no longer needed."));
                    }
                    _ => {}
                }
            }
            LedgerOp::Decision { text, reason } => {
                if blank(text) {
                    return Err(needs_text("the decision", "text"));
                }
                // Named as the `note` tool names them: a decision's reason is `why`, a dead end's what is `text`.
                if blank(reason) {
                    return Err(needs_text("the decision", "`why`"));
                }
            }
            LedgerOp::DeadEnd { what, why } => {
                if blank(what) {
                    return Err(needs_text("the dead end", "`text`"));
                }
                if blank(why) {
                    return Err(needs_text("the dead end", "`why`"));
                }
            }
            LedgerOp::ClaimAdd { text } => {
                if blank(text) {
                    return Err(needs_text("the claim", "text"));
                }
            }
            LedgerOp::ClaimUpdate { id, status, note } => {
                let Some(claim) = self.claims.iter().find(|c| &c.id == id) else {
                    return Err(no_such("claim", id, ids(self.claims.iter().map(|c| c.id.as_str()))));
                };
                match status {
                    ClaimStatus::Supported => {
                        let backed = self.evidence.iter().any(|e| e.input.claim == claim.id && e.input.supports && e.input.attested);
                        if !backed {
                            return Err(format!("Claim {id} cannot be marked supported: it has no attested evidence that supports it. Run or read something that shows it, then call `evidence` with claim {id}, the `out:` handle of that output, the line range `start` and `end`, and a `quote` copied from those lines; evidence the harness did not witness does not count. Then call `claim_update` again."));
                        }
                    }
                    ClaimStatus::Refuted | ClaimStatus::Withdrawn if blank(note) => {
                        return Err(format!("Claim {id} cannot be marked {} without a note. Call claim_update again with a `note` saying what showed it false or why you are withdrawing it.", if *status == ClaimStatus::Refuted { "refuted" } else { "withdrawn" }));
                    }
                    _ => {}
                }
            }
            LedgerOp::EvidenceAdd(input) => {
                if !self.claims.iter().any(|c| c.id == input.claim) {
                    return Err(no_such("claim", &input.claim, ids(self.claims.iter().map(|c| c.id.as_str()))) + " Add the claim with `claim` first, then attach evidence to it.");
                }
                if blank(&input.note) {
                    return Err(needs_text("the evidence", "note") + " Say what the observation shows and what it does not show.");
                }
            }
            LedgerOp::ObligationOpen { text, .. } => {
                if blank(text) {
                    return Err(needs_text("the obligation", "text"));
                }
            }
            LedgerOp::ObligationSettle { id, outcome } => {
                let Some(o) = self.obligations.iter().find(|o| &o.id == id) else {
                    return Err(no_such("obligation", id, ids(self.obligations.iter().map(|o| o.id.as_str()))));
                };
                if let Some(prev) = &o.outcome {
                    return Err(format!("Obligation {id} is already settled (outcome: {}). Records are never edited.", line(prev, 120)));
                }
                if blank(outcome) {
                    return Err(needs_text("the settlement", "outcome"));
                }
            }
            LedgerOp::ApprovalGrant { text, scope } => {
                if !from_user {
                    return Err(user_only("An approval"));
                }
                if blank(text) {
                    return Err(needs_text("the approval", "text"));
                }
                if blank(scope) {
                    return Err(needs_text("the approval", "scope"));
                }
            }
            LedgerOp::ApprovalUse { id, used_for } => {
                let Some(a) = self.approvals.iter().find(|a| &a.id == id) else {
                    return Err(no_such("approval", id, ids(self.approvals.iter().map(|a| a.id.as_str()))));
                };
                if let Some(prev) = &a.used_for {
                    return Err(format!("Approval {id} was already used (for: {}). An approval covers one use; if you need to do this again, ask the operator with ask_user.", line(prev, 120)));
                }
                if blank(used_for) {
                    return Err(needs_text("the approval use", "used_for"));
                }
            }
            LedgerOp::QuestionAsk { text, .. } => {
                if blank(text) {
                    return Err(needs_text("the question", "text"));
                }
            }
            LedgerOp::QuestionAnswer { id, answer } => {
                if !from_user {
                    return Err(user_only("An answer to a question"));
                }
                if !self.questions.iter().any(|q| &q.id == id) {
                    return Err(no_such("question", id, ids(self.questions.iter().map(|q| q.id.as_str()))));
                }
                if blank(answer) {
                    return Err(needs_text("the answer", "answer"));
                }
            }
            LedgerOp::FinishClaim { summary, evidence } => {
                if blank(summary) {
                    return Err(needs_text("the finish claim", "summary"));
                }
                self.check_evidence_ids(evidence, "the finish claim")?;
                let open = self.open_items();
                if !open.is_empty() {
                    return Err(self.open_items_refusal(&open));
                }
            }
            LedgerOp::FinishVerdict { claim, .. } => {
                let Some(f) = self.finishes.iter().find(|f| &f.id == claim) else {
                    return Err(no_such("finish claim", claim, ids(self.finishes.iter().map(|f| f.id.as_str()))));
                };
                if let Some(acc) = f.accepted {
                    return Err(format!("Finish claim {claim} already has a verdict ({}). Verdicts are final; a new finish claim gets its own verdict.", if acc { "accepted" } else { "rejected" }));
                }
            }
            LedgerOp::GoalMetSet { status, note, evidence } => self.validate_goal_met(*status, note, evidence)?,
            LedgerOp::OperatorRelease { reason } => {
                if !from_user {
                    return Err(user_only("A release"));
                }
                if self.goal.is_none() {
                    return Err("There is no goal to release the mission from: no goal has been set yet. Set the goal first.".to_string());
                }
                if let Some(r) = &self.release {
                    return Err(format!("The mission was already released (reason: {}). Records are never edited.", line(&r.reason, 120)));
                }
                if blank(reason) {
                    return Err(needs_text("the release", "reason"));
                }
            }
            LedgerOp::ScopeGrant { hosts, .. } => {
                if !from_user {
                    return Err(user_only("A network scope grant"));
                }
                if hosts.is_empty() {
                    return Err("A scope grant needs at least one host. List the hosts to authorize in `hosts`, one host per entry.".to_string());
                }
                for h in hosts {
                    if blank(h) {
                        return Err(needs_text("a scope grant host", "entry"));
                    }
                    if h.chars().any(|c| c.is_whitespace() || c == ',') {
                        return Err(format!("The host entry `{h}` contains whitespace or a comma. Give one host per entry in `hosts`, for example [\"a.example\", \"b.example\"]."));
                    }
                }
            }
        }
        Ok(())
    }

    /// The rules for writing the goal-met claim (see CONTRACT).
    fn validate_goal_met(&self, status: GoalMetStatus, note: &str, evidence: &[String]) -> Result<(), String> {
        let Some(current) = &self.goal_met else {
            return Err("There is no goal yet, so there is nothing to conclude. The operator sets the goal; wait for it.".to_string());
        };
        if status == GoalMetStatus::Open {
            return Err("The goal-met status can only be set to supported (the goal is met) or refuted (the goal cannot be met as stated); it cannot be reopened or withdrawn. Run the target, record the run with `evidence`, then conclude.".to_string());
        }
        if current.status == status {
            return Err(format!("The goal is already recorded as {}. Change it only to the other conclusion, with new execution evidence recorded after that.", goal_met_label(status)));
        }
        if blank(note) {
            return Err(needs_text("the goal-met conclusion", "note") + " Say what the evidence shows about the goal.");
        }
        if evidence.is_empty() {
            return Err("The goal-met conclusion needs evidence. Run the target, record the run with the `evidence` tool, and cite its id in `evidence`.".to_string());
        }
        self.check_evidence_ids(evidence, "the goal-met conclusion")?;
        let cited: Vec<&Evidence> = self.evidence.iter().filter(|e| evidence.contains(&e.id)).collect();
        if let Some(e) = cited.iter().find(|e| !(e.input.supports && e.input.attested)) {
            return Err(format!("Evidence {} is not attested evidence that supports the conclusion, so it cannot back it. Cite only attested, supporting evidence records.", e.id));
        }
        let executed: Vec<&&Evidence> = cited.iter().filter(|e| e.input.kind == EvidenceKind::Execution).collect();
        if executed.is_empty() {
            return Err("The cited evidence is static only (something was read, nothing was run). Reading source does not show the goal is met or unmeetable: run the target, record the run with `evidence`, and cite that execution.".to_string());
        }
        if current.status != GoalMetStatus::Open && !executed.iter().any(|e| e.n > current.n) {
            return Err(format!("The goal is recorded as {}. To change it, run the target again and cite execution evidence recorded after that conclusion (entry {}).", goal_met_label(current.status), current.n));
        }
        Ok(())
    }

    fn open_items_refusal(&self, open: &OpenItems) -> String {
        let mut out = String::from("Cannot finish yet: the ledger still has open items. Close each one, then call finish again.\n");
        if !open.plan.is_empty() {
            out.push_str("Plan steps still todo or doing (close with `step`: status done with a note saying how it was verified or with evidence ids, or status dropped with a note saying why):\n");
            for id in &open.plan {
                if let Some(p) = self.plan.iter().find(|p| &p.id == id) {
                    out.push_str(&format!("- {} {}\n", p.id, preview(&p.text)));
                }
            }
        }
        if !open.obligations.is_empty() {
            out.push_str("Obligations with no outcome (wait for the job or agent to report, or stop it):\n");
            for id in &open.obligations {
                if let Some(o) = self.obligations.iter().find(|o| &o.id == id) {
                    out.push_str(&format!("- {} {}\n", o.id, preview(&o.text)));
                }
            }
        }
        if !open.claims.is_empty() {
            out.push_str("Claims still open (close with `claim_update`: supported once `evidence` has attached attested supporting evidence, or refuted/withdrawn with a note):\n");
            for id in &open.claims {
                if let Some(c) = self.claims.iter().find(|c| &c.id == id) {
                    out.push_str(&format!("- {} {}\n", c.id, preview(&c.text)));
                }
            }
        }
        if !open.questions.is_empty() {
            out.push_str("Blocking questions without an answer (only the operator can answer them; use ask_user to wait for the answer, do not finish around them):\n");
            for id in &open.questions {
                if let Some(q) = self.questions.iter().find(|q| &q.id == id) {
                    out.push_str(&format!("- {} {}\n", q.id, preview(&q.text)));
                }
            }
        }
        out.truncate(out.trim_end().len());
        out
    }

    pub fn open_items(&self) -> OpenItems {
        OpenItems {
            plan: self.plan.iter().filter(|p| matches!(p.status, StepStatus::Todo | StepStatus::Doing)).map(|p| p.id.clone()).collect(),
            obligations: self.obligations.iter().filter(|o| o.outcome.is_none()).map(|o| o.id.clone()).collect(),
            claims: self.claims.iter().filter(|c| c.status == ClaimStatus::Open).map(|c| c.id.clone()).collect(),
            questions: self.questions.iter().filter(|q| q.blocking && q.answer.is_none()).map(|q| q.id.clone()).collect(),
        }
    }

    /// Compact state text for the HUD and for re-weaves. Goal, constraints and approvals are the
    /// operator's words and are never cut; every other line is cut at `opts.max_line`.
    pub fn brief(&self, opts: &BriefOpts) -> String {
        let max = opts.max_line;
        let mut sections: Vec<String> = Vec::new();

        if let Some(goal) = &self.goal {
            sections.push(format!("Goal: {goal}"));
        }

        if self.goal.is_some() || !self.scope_grants.is_empty() {
            let mut s = String::new();
            if let Some(gm) = &self.goal_met {
                if gm.status == GoalMetStatus::Open {
                    s.push_str("Goal status: open (not yet concluded)");
                } else {
                    let mut l = format!("Goal status: {}", goal_met_label(gm.status));
                    if !blank(&gm.note) {
                        l.push_str(&format!(" — {}", gm.note));
                    }
                    if !gm.evidence.is_empty() {
                        l.push_str(&format!(" (evidence: {})", gm.evidence.join(", ")));
                    }
                    s.push_str(&line(&l, max));
                }
            }
            if let Some(r) = &self.release {
                if !s.is_empty() {
                    s.push('\n');
                }
                s.push_str(&format!("released by the operator (goal not established): {}", r.reason));
            }
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(&authorized_hosts_line(&self.granted_hosts()));
            sections.push(s);
        }

        let active: Vec<&Constraint> = self.constraints.iter().filter(|c| c.retired.is_none()).collect();
        if !active.is_empty() {
            let mut s = String::from("Constraints:");
            for c in active {
                s.push_str(&format!("\n- {}: {}", c.id, c.text));
            }
            sections.push(s);
        }

        let steps: Vec<&PlanStep> = self.plan.iter().filter(|p| p.status != StepStatus::Dropped).collect();
        if !steps.is_empty() {
            let mut s = String::from("Plan:");
            for p in steps {
                let mark = match p.status {
                    StepStatus::Done => "[x]",
                    StepStatus::Doing => "[>]",
                    _ => "[ ]",
                };
                let mut l = format!("{mark} {} {}", p.id, p.text);
                if !blank(&p.note) {
                    l.push_str(&format!(" — {}", p.note));
                }
                s.push('\n');
                s.push_str(&line(&l, max));
            }
            sections.push(s);
        }

        let obligations: Vec<&Obligation> = self.obligations.iter().filter(|o| o.outcome.is_none()).collect();
        if !obligations.is_empty() {
            let mut s = String::from("Open obligations:");
            for o in obligations {
                let mut l = format!("- {} ({}) {}", o.id, obligation_kind(o.kind), o.text);
                if !blank(&o.reference) {
                    l.push_str(&format!(" [{}]", o.reference));
                }
                s.push('\n');
                s.push_str(&line(&l, max));
            }
            sections.push(s);
        }

        if !self.claims.is_empty() {
            let mut s = String::from("Claims:");
            for c in &self.claims {
                let mut l = format!("- {} [{}] {}", c.id, claim_status(c.status), c.text);
                if !c.evidence.is_empty() {
                    l.push_str(&format!(" (evidence: {})", c.evidence.join(", ")));
                }
                s.push('\n');
                s.push_str(&line(&l, max));
            }
            sections.push(s);
        }

        if opts.max_decisions > 0 && !self.decisions.is_empty() {
            let skip = self.decisions.len().saturating_sub(opts.max_decisions);
            let mut s = String::from("Decisions:");
            if let Some(hidden) = elision(self.decisions.iter().map(|d| d.id.as_str()), skip) {
                s.push('\n');
                s.push_str(&hidden);
            }
            for d in self.decisions.iter().skip(skip) {
                s.push('\n');
                s.push_str(&line(&format!("- {}: {} — {}", d.id, d.text, d.reason), max));
            }
            sections.push(s);
        }

        if opts.max_dead_ends > 0 && !self.dead_ends.is_empty() {
            let skip = self.dead_ends.len().saturating_sub(opts.max_dead_ends);
            let mut s = String::from("Dead ends:");
            if let Some(hidden) = elision(self.dead_ends.iter().map(|d| d.id.as_str()), skip) {
                s.push('\n');
                s.push_str(&hidden);
            }
            for d in self.dead_ends.iter().skip(skip) {
                s.push('\n');
                s.push_str(&line(&format!("- {}: {} — {}", d.id, d.what, d.why), max));
            }
            sections.push(s);
        }

        let approvals: Vec<&Approval> = self.approvals.iter().filter(|a| a.used_for.is_none()).collect();
        if !approvals.is_empty() {
            let mut s = String::from("Approvals:");
            for a in approvals {
                s.push_str(&format!("\n- {} [{}]: {}", a.id, a.scope, a.text));
            }
            sections.push(s);
        }

        let questions: Vec<&Question> = self.questions.iter().filter(|q| q.answer.is_none()).collect();
        if !questions.is_empty() {
            let mut s = String::from("Unanswered questions:");
            for q in questions {
                let l = format!("- {}{} {}", q.id, if q.blocking { " (blocking)" } else { "" }, q.text);
                s.push('\n');
                s.push_str(&line(&l, max));
            }
            sections.push(s);
        }

        sections.join("\n\n")
    }

    pub fn render_markdown(&self) -> String {
        let mut o = String::from("<!-- generated from the mission journal; edits here are ignored -->\n\n# Mission ledger\n");
        o.push_str(&format!("\nEntries folded: {}\n", self.entries));

        o.push_str("\n## Goal\n\n");
        match &self.goal {
            Some(g) => o.push_str(&format!("{g}\n")),
            None => o.push_str("(not set)\n"),
        }

        o.push_str("\n## Goal status\n\n");
        match &self.goal_met {
            None => o.push_str("(no goal set)\n"),
            Some(gm) if gm.status == GoalMetStatus::Open => o.push_str("open (not yet concluded)\n"),
            Some(gm) => {
                o.push_str(goal_met_label(gm.status));
                if !blank(&gm.note) {
                    o.push_str(&format!(" — {}", md_inline(&gm.note)));
                }
                if !gm.evidence.is_empty() {
                    o.push_str(&format!(" (evidence: {})", gm.evidence.join(", ")));
                }
                o.push_str(&format!(" (entry {})\n", gm.n));
            }
        }
        if let Some(r) = &self.release {
            o.push_str(&format!("\nreleased by the operator (goal not established): {} (entry {})\n", md_inline(&r.reason), r.n));
        }

        o.push_str("\n## Constraints\n\n");
        if self.constraints.is_empty() {
            o.push_str("(none)\n");
        }
        for c in &self.constraints {
            match &c.retired {
                None => o.push_str(&format!("- **{}**: {}\n", c.id, md_inline(&c.text))),
                Some(r) => o.push_str(&format!("- **{}** (retired: {}): {}\n", c.id, md_inline(r), md_inline(&c.text))),
            }
        }

        o.push_str("\n## Plan\n\n");
        if self.plan.is_empty() {
            o.push_str("(none)\n");
        }
        for p in &self.plan {
            let mark = match p.status {
                StepStatus::Done => "[x]",
                StepStatus::Doing => "[>]",
                StepStatus::Todo => "[ ]",
                StepStatus::Dropped => "[-]",
            };
            o.push_str(&format!("- {mark} **{}** {}", p.id, md_inline(&p.text)));
            if p.status == StepStatus::Dropped {
                o.push_str(" (dropped)");
            }
            if !blank(&p.note) {
                o.push_str(&format!(" — {}", md_inline(&p.note)));
            }
            if !p.evidence.is_empty() {
                o.push_str(&format!(" (evidence: {})", p.evidence.join(", ")));
            }
            o.push('\n');
        }

        o.push_str("\n## Decisions\n\n");
        if self.decisions.is_empty() {
            o.push_str("(none)\n");
        }
        for d in &self.decisions {
            o.push_str(&format!("- **{}** (entry {}): {} — {}\n", d.id, d.n, md_inline(&d.text), md_inline(&d.reason)));
        }

        o.push_str("\n## Dead ends\n\n");
        if self.dead_ends.is_empty() {
            o.push_str("(none)\n");
        }
        for d in &self.dead_ends {
            o.push_str(&format!("- **{}** (entry {}): {} — {}\n", d.id, d.n, md_inline(&d.what), md_inline(&d.why)));
        }

        o.push_str("\n## Claims\n\n");
        if self.claims.is_empty() {
            o.push_str("(none)\n");
        }
        for c in &self.claims {
            o.push_str(&format!("- **{}** [{}] {}", c.id, claim_status(c.status), md_inline(&c.text)));
            if !blank(&c.note) {
                o.push_str(&format!(" — {}", md_inline(&c.note)));
            }
            if !c.evidence.is_empty() {
                o.push_str(&format!(" (evidence: {})", c.evidence.join(", ")));
            }
            o.push('\n');
        }

        o.push_str("\n## Evidence\n");
        if self.evidence.is_empty() {
            o.push_str("\n(none)\n");
        }
        for e in &self.evidence {
            let i = &e.input;
            o.push_str(&format!(
                "\n### {} (entry {})\n\n- claim: {}\n- {} the claim; kind: {}; attested: {}\n- source: session {}, call {}\n",
                e.id,
                e.n,
                i.claim,
                if i.supports { "supports" } else { "undermines" },
                match i.kind {
                    EvidenceKind::Execution => "execution",
                    EvidenceKind::Static => "static",
                },
                if i.attested { "yes" } else { "no" },
                i.session,
                i.call_id,
            ));
            if let Some(b) = &i.blob {
                o.push_str(&format!("- handle: {b}\n"));
            }
            if let Some((a, b)) = i.lines {
                o.push_str(&format!("- lines: {a}-{b}\n"));
            }
            o.push_str(&format!("- note: {}\n", md_inline(&i.note)));
            if let Some(q) = &i.quote {
                let fence = fence_for(q);
                o.push_str(&format!("\n{fence}\n{q}\n{fence}\n"));
            }
        }

        o.push_str("\n## Obligations\n\n");
        if self.obligations.is_empty() {
            o.push_str("(none)\n");
        }
        for ob in &self.obligations {
            o.push_str(&format!("- **{}** ({}) {}", ob.id, obligation_kind(ob.kind), md_inline(&ob.text)));
            if !blank(&ob.reference) {
                o.push_str(&format!(" [{}]", md_inline(&ob.reference)));
            }
            match &ob.outcome {
                Some(r) => o.push_str(&format!(" — settled: {}", md_inline(r))),
                None => o.push_str(" — OPEN"),
            }
            o.push('\n');
        }

        o.push_str("\n## Approvals\n\n");
        if self.approvals.is_empty() {
            o.push_str("(none)\n");
        }
        for a in &self.approvals {
            o.push_str(&format!("- **{}** [{}]: {}", a.id, md_inline(&a.scope), md_inline(&a.text)));
            match &a.used_for {
                Some(u) => o.push_str(&format!(" — used for: {}", md_inline(u))),
                None => o.push_str(" — unused"),
            }
            o.push('\n');
        }

        o.push_str("\n## Questions\n\n");
        if self.questions.is_empty() {
            o.push_str("(none)\n");
        }
        for q in &self.questions {
            o.push_str(&format!("- **{}**{}: {}", q.id, if q.blocking { " (blocking)" } else { "" }, md_inline(&q.text)));
            match &q.answer {
                Some(a) => o.push_str(&format!(" — answer: {}", md_inline(a))),
                None => o.push_str(" — UNANSWERED"),
            }
            o.push('\n');
        }

        o.push_str("\n## Network scope\n\n");
        o.push_str(&authorized_hosts_line(&self.granted_hosts()));
        o.push('\n');
        for g in &self.scope_grants {
            o.push_str(&format!("- **{}** (entry {}): {}", g.id, g.n, md_inline(&g.hosts.join(", "))));
            if let Some(note) = g.note.as_deref().filter(|n| !blank(n)) {
                o.push_str(&format!(" — {}", md_inline(note)));
            }
            o.push('\n');
        }

        o.push_str("\n## Finish claims\n\n");
        if self.finishes.is_empty() {
            o.push_str("(none)\n");
        }
        for f in &self.finishes {
            let verdict = match f.accepted {
                None => "no verdict yet",
                Some(true) => "accepted",
                Some(false) => "rejected",
            };
            o.push_str(&format!("- **{}** [{}] {}", f.id, verdict, md_inline(&f.summary)));
            if !f.evidence.is_empty() {
                o.push_str(&format!(" (evidence: {})", f.evidence.join(", ")));
            }
            o.push('\n');
            for obj in &f.objections {
                o.push_str(&format!("  - objection: {}\n", md_inline(obj)));
            }
        }
        o
    }

    /// One line describing an op, for the session log's `ledger` event (`summary`).
    pub fn summarize(op: &LedgerOp) -> String {
        let s = match op {
            LedgerOp::GoalSet { text } => format!("goal set: {text}"),
            LedgerOp::ConstraintAdd { text } => format!("constraint added: {text}"),
            LedgerOp::ConstraintRetire { id, reason } => format!("constraint {id} retired: {reason}"),
            LedgerOp::PlanSet { steps } => format!("plan set ({} steps): {}", steps.len(), steps.join("; ")),
            LedgerOp::PlanAdd { text } => format!("plan step added: {text}"),
            LedgerOp::PlanUpdate { id, status, note, .. } => format!("plan step {id} -> {}{}", step_status(*status), suffix(note)),
            LedgerOp::Decision { text, reason } => format!("decision: {text} — {reason}"),
            LedgerOp::DeadEnd { what, why } => format!("dead end: {what} — {why}"),
            LedgerOp::ClaimAdd { text } => format!("claim added: {text}"),
            LedgerOp::ClaimUpdate { id, status, note } => format!("claim {id} -> {}{}", claim_status(*status), suffix(note)),
            LedgerOp::EvidenceAdd(i) => format!(
                "evidence for {} ({}, {}) from call {}: {}",
                i.claim,
                if i.supports { "supports" } else { "undermines" },
                match i.kind {
                    EvidenceKind::Execution => "execution",
                    EvidenceKind::Static => "static",
                },
                i.call_id,
                i.note
            ),
            LedgerOp::ObligationOpen { kind, text, .. } => format!("obligation opened ({}): {text}", obligation_kind(*kind)),
            LedgerOp::ObligationSettle { id, outcome } => format!("obligation {id} settled: {outcome}"),
            LedgerOp::ApprovalGrant { text, scope } => format!("approval granted [{scope}]: {text}"),
            LedgerOp::ApprovalUse { id, used_for } => format!("approval {id} used for: {used_for}"),
            LedgerOp::QuestionAsk { text, blocking } => format!("question asked{}: {text}", if *blocking { " (blocking)" } else { "" }),
            LedgerOp::QuestionAnswer { id, answer } => format!("question {id} answered: {answer}"),
            LedgerOp::FinishClaim { summary, .. } => format!("finish claimed: {summary}"),
            LedgerOp::FinishVerdict { claim, accepted, .. } => format!("finish {claim} {}", if *accepted { "accepted" } else { "rejected" }),
            LedgerOp::GoalMetSet { status, note, .. } => format!("goal {}{}", goal_met_label(*status), suffix(note)),
            LedgerOp::OperatorRelease { reason } => format!("released by the operator (goal not established): {reason}"),
            LedgerOp::ScopeGrant { hosts, note } => format!("scope granted: {}{}", hosts.join(", "), suffix(note.as_deref().unwrap_or(""))),
        };
        line(&s, 200)
    }
}

fn suffix(note: &str) -> String {
    if blank(note) {
        String::new()
    } else {
        format!(": {note}")
    }
}

fn step_status(s: StepStatus) -> &'static str {
    match s {
        StepStatus::Todo => "todo",
        StepStatus::Doing => "doing",
        StepStatus::Done => "done",
        StepStatus::Dropped => "dropped",
    }
}

fn claim_status(s: ClaimStatus) -> &'static str {
    match s {
        ClaimStatus::Open => "open",
        ClaimStatus::Supported => "supported",
        ClaimStatus::Refuted => "refuted",
        ClaimStatus::Withdrawn => "withdrawn",
    }
}

/// The single line that shows the agent its network scope.
fn authorized_hosts_line(hosts: &[String]) -> String {
    if hosts.is_empty() {
        "authorized hosts: none granted".to_string()
    } else {
        format!("authorized hosts: {}", hosts.join(", "))
    }
}

fn goal_met_label(s: GoalMetStatus) -> &'static str {
    match s {
        GoalMetStatus::Open => "open",
        GoalMetStatus::Supported => "met",
        GoalMetStatus::Refuted => "cannot be met as stated",
    }
}

fn obligation_kind(k: ObligationKind) -> &'static str {
    match k {
        ObligationKind::Job => "job",
        ObligationKind::Child => "child",
        ObligationKind::Question => "question",
        ObligationKind::UnverifiedEdit => "unverified_edit",
        ObligationKind::Promise => "promise",
    }
}

/// Free text on one Markdown list line: line breaks would end the list item.
fn md_inline(s: &str) -> String {
    s.replace("\r\n", " ⏎ ").replace(['\n', '\r'], " ⏎ ")
}

/// A code fence longer than any backtick run in `text`.
fn fence_for(text: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for ch in text.chars() {
        if ch == '`' {
            run = run.saturating_add(1);
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat(longest.saturating_add(1).max(3))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: u64, op: LedgerOp) -> Entry {
        Entry { n, ts_ms: 1000 + n, session: SessionId::from("s-test"), from_user: false, op, mac: String::new() }
    }

    fn build(ops: Vec<LedgerOp>) -> LedgerState {
        let entries: Vec<Entry> = ops.into_iter().enumerate().map(|(i, op)| entry(i as u64 + 1, op)).collect();
        LedgerState::fold(&entries)
    }

    fn ev(claim: &str, supports: bool, attested: bool) -> EvidenceInput {
        EvidenceInput {
            claim: claim.into(),
            kind: EvidenceKind::Execution,
            supports,
            session: SessionId::from("s-x"),
            call_id: CallId::from("call-1"),
            blob: Some(BlobId::from("ab12")),
            lines: Some((2, 4)),
            quote: Some("hello ``` world".into()),
            note: "ran it".into(),
            attested,
        }
    }

    fn refusal(state: &LedgerState, op: LedgerOp, from_user: bool) -> String {
        match state.validate(&op, from_user) {
            Err(m) => m,
            Ok(()) => panic!("expected refusal for {op:?}"),
        }
    }

    fn all_ops() -> Vec<LedgerOp> {
        vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ConstraintAdd { text: "never touch prod".into() },
            LedgerOp::ConstraintRetire { id: "k1".into(), reason: "lifted".into() },
            LedgerOp::PlanSet { steps: vec!["a".into(), "b".into()] },
            LedgerOp::PlanAdd { text: "c".into() },
            LedgerOp::PlanUpdate { id: "p1".into(), status: StepStatus::Done, note: "n".into(), evidence: vec!["e1".into()] },
            LedgerOp::Decision { text: "t".into(), reason: "r".into() },
            LedgerOp::DeadEnd { what: "w".into(), why: "y".into() },
            LedgerOp::ClaimAdd { text: "it works".into() },
            LedgerOp::ClaimUpdate { id: "c1".into(), status: ClaimStatus::Supported, note: String::new() },
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
            LedgerOp::ObligationOpen { kind: ObligationKind::Job, text: "job".into(), reference: "pid 4".into() },
            LedgerOp::ObligationSettle { id: "o1".into(), outcome: "done".into() },
            LedgerOp::ApprovalGrant { text: "ok to push".into(), scope: "git push".into() },
            LedgerOp::ApprovalUse { id: "a1".into(), used_for: "pushed".into() },
            LedgerOp::QuestionAsk { text: "which?".into(), blocking: true },
            LedgerOp::QuestionAnswer { id: "q1".into(), answer: "this".into() },
            LedgerOp::FinishClaim { summary: "done".into(), evidence: vec!["e1".into()] },
            LedgerOp::FinishVerdict { claim: "f1".into(), accepted: false, objections: vec!["no".into()], verifier: Some(SessionId::from("s-v")) },
            LedgerOp::GoalMetSet { status: GoalMetStatus::Supported, note: "ran it".into(), evidence: vec!["e1".into()] },
            LedgerOp::OperatorRelease { reason: "good enough".into() },
            LedgerOp::ScopeGrant { hosts: vec!["a.example".into(), "b.example".into()], note: Some("for the crawl".into()) },
        ]
    }

    #[test]
    fn ids_are_assigned_by_position() {
        let s = build(vec![
            LedgerOp::ConstraintAdd { text: "a".into() },
            LedgerOp::ConstraintAdd { text: "b".into() },
            LedgerOp::PlanSet { steps: vec!["one".into(), "two".into()] },
            LedgerOp::PlanAdd { text: "three".into() },
            LedgerOp::Decision { text: "d".into(), reason: "r".into() },
            LedgerOp::DeadEnd { what: "w".into(), why: "y".into() },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
            LedgerOp::ObligationOpen { kind: ObligationKind::Promise, text: "o".into(), reference: String::new() },
            LedgerOp::ApprovalGrant { text: "a".into(), scope: "s".into() },
            LedgerOp::QuestionAsk { text: "q".into(), blocking: false },
            LedgerOp::FinishClaim { summary: "f".into(), evidence: vec![] },
        ]);
        assert_eq!(s.constraints.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["k1", "k2"]);
        assert_eq!(s.plan.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), ["p1", "p2", "p3"]);
        assert_eq!(s.decisions[0].id, "d1");
        assert_eq!(s.decisions[0].n, 5);
        assert_eq!(s.dead_ends[0].id, "x1");
        assert_eq!(s.claims[0].id, "c1");
        assert_eq!(s.evidence[0].id, "e1");
        assert_eq!(s.claims[0].evidence, ["e1"]);
        assert_eq!(s.obligations[0].id, "o1");
        assert_eq!(s.approvals[0].id, "a1");
        assert_eq!(s.questions[0].id, "q1");
        assert_eq!(s.finishes[0].id, "f1");
        assert_eq!(s.entries, 12);
    }

    #[test]
    fn plan_set_replaces_and_numbering_continues() {
        let s = build(vec![
            LedgerOp::PlanSet { steps: vec!["a".into(), "b".into(), "c".into()] },
            LedgerOp::PlanUpdate { id: "p1".into(), status: StepStatus::Done, note: "checked".into(), evidence: vec![] },
            LedgerOp::PlanUpdate { id: "p3".into(), status: StepStatus::Dropped, note: "not needed".into(), evidence: vec![] },
            LedgerOp::PlanSet { steps: vec!["d".into(), "e".into()] },
        ]);
        let st: Vec<(&str, StepStatus)> = s.plan.iter().map(|p| (p.id.as_str(), p.status)).collect();
        assert_eq!(
            st,
            [("p1", StepStatus::Done), ("p2", StepStatus::Dropped), ("p3", StepStatus::Dropped), ("p4", StepStatus::Todo), ("p5", StepStatus::Todo)]
        );
        assert_eq!(s.plan[0].note, "checked");
        assert_eq!(s.plan[1].note, "replaced by a new plan");
        assert_eq!(s.plan[2].note, "not needed");
    }

    #[test]
    fn effects_of_updates() {
        let s = build(vec![
            LedgerOp::ConstraintAdd { text: "a".into() },
            LedgerOp::ConstraintRetire { id: "k1".into(), reason: "lifted".into() },
            LedgerOp::PlanAdd { text: "x".into() },
            LedgerOp::PlanUpdate { id: "p1".into(), status: StepStatus::Doing, note: String::new(), evidence: vec!["e1".into()] },
            LedgerOp::PlanUpdate { id: "p1".into(), status: StepStatus::Done, note: "ok".into(), evidence: vec!["e2".into()] },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::ClaimUpdate { id: "c1".into(), status: ClaimStatus::Withdrawn, note: "wrong".into() },
            LedgerOp::ObligationOpen { kind: ObligationKind::Job, text: "o".into(), reference: String::new() },
            LedgerOp::ObligationSettle { id: "o1".into(), outcome: "finished".into() },
            LedgerOp::ApprovalGrant { text: "a".into(), scope: "s".into() },
            LedgerOp::ApprovalUse { id: "a1".into(), used_for: "push".into() },
            LedgerOp::QuestionAsk { text: "q".into(), blocking: true },
            LedgerOp::QuestionAnswer { id: "q1".into(), answer: "yes".into() },
            LedgerOp::FinishClaim { summary: "f".into(), evidence: vec![] },
            LedgerOp::FinishVerdict { claim: "f1".into(), accepted: true, objections: vec!["minor".into()], verifier: None },
        ]);
        assert_eq!(s.constraints[0].retired.as_deref(), Some("lifted"));
        assert_eq!(s.plan[0].status, StepStatus::Done);
        assert_eq!(s.plan[0].note, "ok");
        assert_eq!(s.plan[0].evidence, ["e1", "e2"]);
        assert_eq!(s.claims[0].status, ClaimStatus::Withdrawn);
        assert_eq!(s.claims[0].note, "wrong");
        assert_eq!(s.obligations[0].outcome.as_deref(), Some("finished"));
        assert_eq!(s.approvals[0].used_for.as_deref(), Some("push"));
        assert_eq!(s.questions[0].answer.as_deref(), Some("yes"));
        assert_eq!(s.finishes[0].accepted, Some(true));
        assert_eq!(s.finishes[0].objections, ["minor"]);
    }

    #[test]
    fn apply_ignores_unknown_ids() {
        let base = build(vec![LedgerOp::ClaimAdd { text: "c".into() }, LedgerOp::PlanAdd { text: "p".into() }]);
        let mut s = base.clone();
        let ops = vec![
            LedgerOp::ConstraintRetire { id: "k9".into(), reason: "r".into() },
            LedgerOp::PlanUpdate { id: "p9".into(), status: StepStatus::Done, note: "n".into(), evidence: vec![] },
            LedgerOp::ClaimUpdate { id: "c9".into(), status: ClaimStatus::Refuted, note: "n".into() },
            LedgerOp::EvidenceAdd(ev("c9", true, true)),
            LedgerOp::ObligationSettle { id: "o9".into(), outcome: "x".into() },
            LedgerOp::ApprovalUse { id: "a9".into(), used_for: "x".into() },
            LedgerOp::QuestionAnswer { id: "q9".into(), answer: "x".into() },
            LedgerOp::FinishVerdict { claim: "f9".into(), accepted: true, objections: vec![], verifier: None },
        ];
        for (i, op) in ops.into_iter().enumerate() {
            s.apply(&entry(10 + i as u64, op));
        }
        assert_eq!(s.claims, base.claims);
        assert_eq!(s.plan, base.plan);
        assert!(s.evidence.is_empty());
        assert_eq!(s.entries, 10);
    }

    #[test]
    fn fold_equals_repeated_apply() {
        let entries: Vec<Entry> = all_ops().into_iter().enumerate().map(|(i, op)| entry(i as u64 + 1, op)).collect();
        let mut s = LedgerState::default();
        for e in &entries {
            s.apply(e);
        }
        assert_eq!(s, LedgerState::fold(&entries));
        assert_eq!(s.entries, entries.len() as u64);
    }

    #[test]
    fn user_only_ops_are_refused_from_a_tool_call() {
        let s = build(vec![LedgerOp::ConstraintAdd { text: "a".into() }, LedgerOp::QuestionAsk { text: "q".into(), blocking: true }]);
        let ops = vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ConstraintAdd { text: "c".into() },
            LedgerOp::ConstraintRetire { id: "k1".into(), reason: "r".into() },
            LedgerOp::ApprovalGrant { text: "t".into(), scope: "s".into() },
            LedgerOp::QuestionAnswer { id: "q1".into(), answer: "a".into() },
        ];
        for op in ops {
            let m = refusal(&s, op.clone(), false);
            assert!(m.contains("operator's own words") && m.contains("cannot be written by a tool call"), "{m}");
            assert!(s.validate(&op, true).is_ok(), "{op:?}");
        }
    }

    #[test]
    fn unknown_ids_are_refused_with_the_known_ones_listed() {
        let s = build(vec![
            LedgerOp::ConstraintAdd { text: "a".into() },
            LedgerOp::PlanSet { steps: vec!["a".into(), "b".into()] },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::ObligationOpen { kind: ObligationKind::Job, text: "o".into(), reference: String::new() },
            LedgerOp::ApprovalGrant { text: "a".into(), scope: "s".into() },
            LedgerOp::QuestionAsk { text: "q".into(), blocking: false },
            LedgerOp::FinishClaim { summary: "f".into(), evidence: vec![] },
        ]);
        let m = refusal(&s, LedgerOp::PlanUpdate { id: "p7".into(), status: StepStatus::Doing, note: String::new(), evidence: vec![] }, false);
        assert!(m.contains("`p7`") && m.contains("p1, p2"), "{m}");
        let m = refusal(&s, LedgerOp::ClaimUpdate { id: "c5".into(), status: ClaimStatus::Open, note: String::new() }, false);
        assert!(m.contains("`c5`") && m.contains("c1"), "{m}");
        let m = refusal(&s, LedgerOp::EvidenceAdd(ev("c5", true, true)), false);
        assert!(m.contains("c1"), "{m}");
        let m = refusal(&s, LedgerOp::ObligationSettle { id: "o5".into(), outcome: "x".into() }, false);
        assert!(m.contains("o1"), "{m}");
        let m = refusal(&s, LedgerOp::ApprovalUse { id: "a5".into(), used_for: "x".into() }, false);
        assert!(m.contains("a1"), "{m}");
        let m = refusal(&s, LedgerOp::QuestionAnswer { id: "q5".into(), answer: "x".into() }, true);
        assert!(m.contains("q1"), "{m}");
        let m = refusal(&s, LedgerOp::ConstraintRetire { id: "k5".into(), reason: "x".into() }, true);
        assert!(m.contains("k1"), "{m}");
        let m = refusal(&s, LedgerOp::FinishVerdict { claim: "f5".into(), accepted: true, objections: vec![], verifier: None }, false);
        assert!(m.contains("f1"), "{m}");
        let m = refusal(&s, LedgerOp::PlanUpdate { id: "p1".into(), status: StepStatus::Done, note: String::new(), evidence: vec!["e4".into()] }, false);
        assert!(m.contains("`e4`") && m.contains("`evidence` tool"), "{m}");
        let empty = LedgerState::default();
        let m = refusal(&empty, LedgerOp::PlanUpdate { id: "p1".into(), status: StepStatus::Doing, note: String::new(), evidence: vec![] }, false);
        assert!(m.contains("no plan step has been recorded"), "{m}");
    }

    #[test]
    fn empty_text_is_refused() {
        let s = LedgerState::default();
        let ops = vec![
            LedgerOp::PlanSet { steps: vec![] },
            LedgerOp::PlanSet { steps: vec!["ok".into(), "  \n".into()] },
            LedgerOp::PlanAdd { text: " ".into() },
            LedgerOp::Decision { text: "".into(), reason: "r".into() },
            LedgerOp::DeadEnd { what: "\t".into(), why: "y".into() },
            LedgerOp::ClaimAdd { text: "".into() },
            LedgerOp::ObligationOpen { kind: ObligationKind::Job, text: " ".into(), reference: String::new() },
            LedgerOp::QuestionAsk { text: "".into(), blocking: false },
            LedgerOp::FinishClaim { summary: "  ".into(), evidence: vec![] },
        ];
        for op in ops {
            refusal(&s, op, false);
        }
        refusal(&s, LedgerOp::GoalSet { text: " ".into() }, true);
        refusal(&s, LedgerOp::ConstraintAdd { text: "".into() }, true);
        // The sentence names the parameter of the `note` tool that was empty, not the field of the record.
        let m = refusal(&s, LedgerOp::DeadEnd { what: "\t".into(), why: "y".into() }, false);
        assert!(m.starts_with("The `text` of the dead end is empty."), "{m}");
        let m = refusal(&s, LedgerOp::DeadEnd { what: "w".into(), why: "".into() }, false);
        assert!(m.starts_with("The `why` of the dead end is empty."), "{m}");
        let m = refusal(&s, LedgerOp::Decision { text: "t".into(), reason: " ".into() }, false);
        assert!(m.starts_with("The `why` of the decision is empty."), "{m}");
        assert!(s.validate(&LedgerOp::PlanSet { steps: vec!["x".into()] }, false).is_ok());
    }

    #[test]
    fn plan_update_rules() {
        let s = build(vec![
            LedgerOp::PlanAdd { text: "a".into() },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
        ]);
        let upd = |status, note: &str, evidence: Vec<&str>| LedgerOp::PlanUpdate {
            id: "p1".into(),
            status,
            note: note.into(),
            evidence: evidence.into_iter().map(String::from).collect(),
        };
        let m = refusal(&s, upd(StepStatus::Done, "  ", vec![]), false);
        assert!(m.contains("p1") && m.contains("note") && m.contains("evidence"), "{m}");
        assert!(s.validate(&upd(StepStatus::Done, "ran the tests", vec![]), false).is_ok());
        assert!(s.validate(&upd(StepStatus::Done, "", vec!["e1"]), false).is_ok());
        refusal(&s, upd(StepStatus::Done, "", vec!["e2"]), false);
        refusal(&s, upd(StepStatus::Dropped, "", vec![]), false);
        assert!(s.validate(&upd(StepStatus::Dropped, "obsolete", vec![]), false).is_ok());
        assert!(s.validate(&upd(StepStatus::Doing, "", vec![]), false).is_ok());
    }

    #[test]
    fn claim_update_rules() {
        let mut ops = vec![LedgerOp::ClaimAdd { text: "c".into() }];
        let upd = |status, note: &str| LedgerOp::ClaimUpdate { id: "c1".into(), status, note: note.into() };
        let s = build(ops.clone());
        let m = refusal(&s, upd(ClaimStatus::Supported, ""), false);
        assert!(m.contains("`evidence`") && m.contains("attested"), "{m}");
        ops.push(LedgerOp::EvidenceAdd(ev("c1", true, false)));
        refusal(&build(ops.clone()), upd(ClaimStatus::Supported, "n"), false);
        ops.push(LedgerOp::EvidenceAdd(ev("c1", false, true)));
        refusal(&build(ops.clone()), upd(ClaimStatus::Supported, "n"), false);
        ops.push(LedgerOp::EvidenceAdd(ev("c1", true, true)));
        let s = build(ops);
        assert!(s.validate(&upd(ClaimStatus::Supported, ""), false).is_ok());
        refusal(&s, upd(ClaimStatus::Refuted, " "), false);
        refusal(&s, upd(ClaimStatus::Withdrawn, ""), false);
        assert!(s.validate(&upd(ClaimStatus::Refuted, "it fails"), false).is_ok());
        assert!(s.validate(&upd(ClaimStatus::Open, ""), false).is_ok());
    }

    #[test]
    fn evidence_add_rules() {
        let s = build(vec![LedgerOp::ClaimAdd { text: "c".into() }]);
        assert!(s.validate(&LedgerOp::EvidenceAdd(ev("c1", true, true)), false).is_ok());
        let mut no_note = ev("c1", true, true);
        no_note.note = "  ".into();
        refusal(&s, LedgerOp::EvidenceAdd(no_note), false);
    }

    #[test]
    fn settle_and_use_twice_are_refused() {
        let s = build(vec![
            LedgerOp::ObligationOpen { kind: ObligationKind::Child, text: "o".into(), reference: String::new() },
            LedgerOp::ApprovalGrant { text: "a".into(), scope: "s".into() },
        ]);
        let settle = LedgerOp::ObligationSettle { id: "o1".into(), outcome: "done".into() };
        let used = LedgerOp::ApprovalUse { id: "a1".into(), used_for: "x".into() };
        assert!(s.validate(&settle, false).is_ok());
        assert!(s.validate(&used, false).is_ok());
        let mut s2 = s.clone();
        s2.apply(&entry(3, settle.clone()));
        s2.apply(&entry(4, used.clone()));
        assert!(refusal(&s2, settle, false).contains("already settled"));
        assert!(refusal(&s2, used, false).contains("already used"));
        refusal(&s, LedgerOp::ObligationSettle { id: "o1".into(), outcome: " ".into() }, false);
    }

    #[test]
    fn constraint_retire_twice_is_refused() {
        let s = build(vec![LedgerOp::ConstraintAdd { text: "a".into() }, LedgerOp::ConstraintRetire { id: "k1".into(), reason: "r".into() }]);
        assert!(refusal(&s, LedgerOp::ConstraintRetire { id: "k1".into(), reason: "again".into() }, true).contains("already retired"));
    }

    #[test]
    fn finish_claim_is_refused_while_items_are_open() {
        let long = "x".repeat(200);
        let s = build(vec![
            LedgerOp::PlanSet { steps: vec![long.clone(), "second".into()] },
            LedgerOp::PlanUpdate { id: "p2".into(), status: StepStatus::Done, note: "ok".into(), evidence: vec![] },
            LedgerOp::ObligationOpen { kind: ObligationKind::Job, text: "benchmark job".into(), reference: String::new() },
            LedgerOp::ClaimAdd { text: "it is fast".into() },
            LedgerOp::QuestionAsk { text: "blocking q".into(), blocking: true },
            LedgerOp::QuestionAsk { text: "idle q".into(), blocking: false },
        ]);
        let m = refusal(&s, LedgerOp::FinishClaim { summary: "done".into(), evidence: vec![] }, false);
        assert!(m.contains(&format!("- p1 {}", "x".repeat(80))) && !m.contains(&"x".repeat(81)), "{m}");
        assert!(!m.contains("p2 second"), "{m}");
        assert!(m.contains("- o1 benchmark job") && m.contains("- c1 it is fast") && m.contains("- q1 blocking q"), "{m}");
        assert!(!m.contains("q2"), "{m}");
        for tool in ["`step`", "wait for the job or agent", "claim_update", "ask_user"] {
            assert!(m.contains(tool), "{tool} missing: {m}");
        }
        let clean = build(vec![
            LedgerOp::PlanAdd { text: "a".into() },
            LedgerOp::PlanUpdate { id: "p1".into(), status: StepStatus::Dropped, note: "n".into(), evidence: vec![] },
            LedgerOp::QuestionAsk { text: "idle".into(), blocking: false },
        ]);
        assert!(clean.validate(&LedgerOp::FinishClaim { summary: "done".into(), evidence: vec![] }, false).is_ok());
        refusal(&clean, LedgerOp::FinishClaim { summary: "done".into(), evidence: vec!["e1".into()] }, false);
    }

    #[test]
    fn finish_verdict_rules() {
        let s = build(vec![LedgerOp::FinishClaim { summary: "f".into(), evidence: vec![] }]);
        let v = |claim: &str| LedgerOp::FinishVerdict { claim: claim.into(), accepted: true, objections: vec![], verifier: None };
        assert!(s.validate(&v("f1"), false).is_ok());
        assert!(s.validate(&v("f1"), true).is_ok());
        refusal(&s, v("f2"), false);
        let mut s2 = s.clone();
        s2.apply(&entry(2, v("f1")));
        assert!(refusal(&s2, v("f1"), false).contains("already has a verdict"));
    }

    #[test]
    fn open_items_lists_each_kind() {
        let s = build(vec![
            LedgerOp::PlanSet { steps: vec!["a".into(), "b".into(), "c".into(), "d".into()] },
            LedgerOp::PlanUpdate { id: "p2".into(), status: StepStatus::Doing, note: String::new(), evidence: vec![] },
            LedgerOp::PlanUpdate { id: "p3".into(), status: StepStatus::Done, note: "n".into(), evidence: vec![] },
            LedgerOp::PlanUpdate { id: "p4".into(), status: StepStatus::Dropped, note: "n".into(), evidence: vec![] },
            LedgerOp::ObligationOpen { kind: ObligationKind::Job, text: "a".into(), reference: String::new() },
            LedgerOp::ObligationOpen { kind: ObligationKind::Job, text: "b".into(), reference: String::new() },
            LedgerOp::ObligationSettle { id: "o1".into(), outcome: "x".into() },
            LedgerOp::ClaimAdd { text: "a".into() },
            LedgerOp::ClaimAdd { text: "b".into() },
            LedgerOp::ClaimUpdate { id: "c2".into(), status: ClaimStatus::Withdrawn, note: "n".into() },
            LedgerOp::QuestionAsk { text: "a".into(), blocking: true },
            LedgerOp::QuestionAsk { text: "b".into(), blocking: true },
            LedgerOp::QuestionAsk { text: "c".into(), blocking: false },
            LedgerOp::QuestionAnswer { id: "q2".into(), answer: "x".into() },
        ]);
        let o = s.open_items();
        assert_eq!(o.plan, ["p1", "p2"]);
        assert_eq!(o.obligations, ["o2"]);
        assert_eq!(o.claims, ["c1"]);
        assert_eq!(o.questions, ["q1"]);
        assert!(!o.is_empty());
        assert!(LedgerState::default().open_items().is_empty());
    }

    fn rich_state() -> LedgerState {
        build(vec![
            LedgerOp::GoalSet { text: "Ship the parser\nwith tests".into() },
            LedgerOp::ConstraintAdd { text: "never touch prod".into() },
            LedgerOp::ConstraintAdd { text: "old rule".into() },
            LedgerOp::ConstraintRetire { id: "k2".into(), reason: "lifted".into() },
            LedgerOp::PlanSet { steps: vec!["read".into(), "write".into(), "test".into(), "scrapped".into()] },
            LedgerOp::PlanUpdate { id: "p1".into(), status: StepStatus::Done, note: "read it".into(), evidence: vec![] },
            LedgerOp::PlanUpdate { id: "p2".into(), status: StepStatus::Doing, note: String::new(), evidence: vec![] },
            LedgerOp::PlanUpdate { id: "p4".into(), status: StepStatus::Dropped, note: "no".into(), evidence: vec![] },
            LedgerOp::ObligationOpen { kind: ObligationKind::Job, text: "bench running".into(), reference: "pid 7".into() },
            LedgerOp::ObligationOpen { kind: ObligationKind::Promise, text: "settled one".into(), reference: String::new() },
            LedgerOp::ObligationSettle { id: "o2".into(), outcome: "kept".into() },
            LedgerOp::ClaimAdd { text: "parser handles nesting".into() },
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
            LedgerOp::Decision { text: "use nom".into(), reason: "speed".into() },
            LedgerOp::Decision { text: "drop serde".into(), reason: "size".into() },
            LedgerOp::Decision { text: "pin rust".into(), reason: "ci".into() },
            LedgerOp::DeadEnd { what: "regex parser".into(), why: "no recursion".into() },
            LedgerOp::DeadEnd { what: "peg".into(), why: "slow".into() },
            LedgerOp::ApprovalGrant { text: "ok to push".into(), scope: "git push".into() },
            LedgerOp::ApprovalGrant { text: "ok to delete".into(), scope: "rm".into() },
            LedgerOp::ApprovalUse { id: "a2".into(), used_for: "cleanup".into() },
            LedgerOp::QuestionAsk { text: "which dialect?".into(), blocking: true },
            LedgerOp::QuestionAsk { text: "answered one".into(), blocking: false },
            LedgerOp::QuestionAnswer { id: "q2".into(), answer: "x".into() },
        ])
    }

    #[test]
    fn brief_order_omission_and_content() {
        let b = rich_state().brief(&BriefOpts::default());
        let order = [
            "Goal: Ship the parser\nwith tests",
            "Constraints:\n- k1: never touch prod",
            "Plan:\n[x] p1 read — read it\n[>] p2 write\n[ ] p3 test",
            "Open obligations:\n- o1 (job) bench running [pid 7]",
            "Claims:\n- c1 [open] parser handles nesting (evidence: e1)",
            "Decisions:",
            "Dead ends:",
            "Approvals:\n- a1 [git push]: ok to push",
            "Unanswered questions:\n- q1 (blocking) which dialect?",
        ];
        let mut at = 0;
        for part in order {
            let found = b[at..].find(part);
            assert!(found.is_some(), "{part:?} missing or out of order in:\n{b}");
            at += found.unwrap_or(0) + part.len();
        }
        for absent in ["old rule", "scrapped", "settled one", "ok to delete", "answered one", "hello", "ran it"] {
            assert!(!b.contains(absent), "{absent} should be omitted:\n{b}");
        }
        assert_eq!(b, rich_state().brief(&BriefOpts::default()));
        assert_eq!(LedgerState::default().brief(&BriefOpts::default()), "");
        let only_goal = build(vec![LedgerOp::GoalSet { text: "g".into() }]).brief(&BriefOpts::default());
        assert_eq!(only_goal, "Goal: g\n\nGoal status: open (not yet concluded)\nauthorized hosts: none granted");
    }

    #[test]
    fn brief_limits_and_cuts() {
        let s = rich_state();
        let b = s.brief(&BriefOpts { max_decisions: 2, max_dead_ends: 1, max_line: 400 });
        assert!(!b.contains("d1:") && b.contains("d2: drop serde — size") && b.contains("d3: pin rust — ci"), "{b}");
        assert!(!b.contains("x1:") && b.contains("x2: peg — slow"), "{b}");
        let long = "y".repeat(100);
        let s = build(vec![
            LedgerOp::GoalSet { text: long.clone() },
            LedgerOp::ConstraintAdd { text: long.clone() },
            LedgerOp::PlanAdd { text: long.clone() },
            LedgerOp::ClaimAdd { text: "é".repeat(100) },
        ]);
        let b = s.brief(&BriefOpts { max_decisions: 1, max_dead_ends: 1, max_line: 20 });
        // the operator's words are never cut
        assert!(b.contains(&format!("Goal: {long}")) && b.contains(&format!("k1: {long}")), "{b}");
        let plan_line = b.lines().find(|l| l.starts_with("[ ] p1")).unwrap_or("");
        assert_eq!(plan_line.chars().count(), 20);
        assert!(plan_line.ends_with('…'));
        let claim_line = b.lines().find(|l| l.starts_with("- c1")).unwrap_or("");
        assert_eq!(claim_line.chars().count(), 20);
        assert!(claim_line.ends_with('…'));
    }

    #[test]
    fn brief_says_when_older_items_are_hidden() {
        let s = rich_state();
        let b = s.brief(&BriefOpts { max_decisions: 2, max_dead_ends: 1, max_line: 400 });
        assert!(b.contains("(1 older not shown: d1; call `ledger` to read them)"), "{b}");
        assert!(b.contains("(1 older not shown: x1; call `ledger` to read them)"), "{b}");
        let b = s.brief(&BriefOpts { max_decisions: 1, max_dead_ends: 2, max_line: 400 });
        assert!(b.contains("(2 older not shown: d1–d2; call `ledger` to read them)"), "{b}");
        let b = s.brief(&BriefOpts::default());
        assert!(!b.contains("not shown"), "{b}");
    }

    #[test]
    fn markdown_contains_every_record() {
        let md = rich_state().render_markdown();
        assert!(md.starts_with("<!-- generated from the mission journal; edits here are ignored -->\n"));
        for needle in [
            "Ship the parser",
            "never touch prod",
            "old rule",
            "lifted",
            "read it",
            "scrapped",
            "bench running",
            "pid 7",
            "settled one",
            "kept",
            "parser handles nesting",
            "use nom",
            "speed",
            "regex parser",
            "no recursion",
            "ok to push",
            "ok to delete",
            "cleanup",
            "which dialect?",
            "answered one",
            "### e1",
            "handle: ab12",
            "lines: 2-4",
            "call call-1",
            "session s-x",
            "ran it",
        ] {
            assert!(md.contains(needle), "{needle} missing:\n{md}");
        }
        // The quote contains a triple backtick, so its fence must be longer.
        assert!(md.contains("````\nhello ``` world\n````"), "{md}");
        assert_eq!(md, rich_state().render_markdown());
    }

    #[test]
    fn summarize_is_one_short_line() {
        for op in all_ops() {
            let s = LedgerState::summarize(&op);
            assert!(!s.is_empty() && !s.contains('\n') && s.chars().count() <= 200, "{s}");
        }
        let long = LedgerOp::GoalSet { text: "z\n".repeat(500) };
        let s = LedgerState::summarize(&long);
        assert_eq!(s.chars().count(), 200);
        assert!(s.contains("goal set"));
    }

    #[test]
    fn every_op_round_trips_through_serde() {
        for op in all_ops() {
            let json = serde_json::to_string(&op).unwrap_or_default();
            let back: Result<LedgerOp, _> = serde_json::from_str(&json);
            assert_eq!(back.ok(), Some(op.clone()), "{json}");
        }
        // Defaulted fields may be absent on the wire.
        let op: Result<LedgerOp, _> = serde_json::from_str(r#"{"op":"plan_update","id":"p1","status":"done"}"#);
        assert!(matches!(op, Ok(LedgerOp::PlanUpdate { evidence, note, .. }) if evidence.is_empty() && note.is_empty()));
        let state = rich_state();
        let json = serde_json::to_string(&state).unwrap_or_default();
        assert_eq!(serde_json::from_str::<LedgerState>(&json).ok(), Some(state));
    }

    fn static_ev(claim: &str) -> EvidenceInput {
        EvidenceInput { kind: EvidenceKind::Static, ..ev(claim, true, true) }
    }

    /// A goal, an ordinary claim `c1`, and execution evidence `e1` (entry 3).
    fn with_goal_and_run() -> LedgerState {
        build(vec![LedgerOp::GoalSet { text: "g".into() }, LedgerOp::ClaimAdd { text: "it runs".into() }, LedgerOp::EvidenceAdd(ev("c1", true, true))])
    }

    fn conclude(status: GoalMetStatus, evidence: &[&str]) -> LedgerOp {
        LedgerOp::GoalMetSet { status, note: "ran the target".into(), evidence: evidence.iter().map(|e| e.to_string()).collect() }
    }

    #[test]
    fn goal_met_is_absent_before_a_goal_and_open_after() {
        assert_eq!(LedgerState::default().goal_met, None);
        assert_eq!(build(vec![LedgerOp::ClaimAdd { text: "c".into() }]).goal_met, None);
        let s = build(vec![LedgerOp::GoalSet { text: "g".into() }]);
        assert_eq!(s.goal_met.as_ref().map(|g| g.status), Some(GoalMetStatus::Open));
        // Setting the goal again does not reopen a conclusion.
        let s = build(vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
            conclude(GoalMetStatus::Supported, &["e1"]),
            LedgerOp::GoalSet { text: "g2".into() },
        ]);
        assert_eq!(s.goal_met.as_ref().map(|g| g.status), Some(GoalMetStatus::Supported));
    }

    #[test]
    fn goal_met_needs_a_goal_and_execution_evidence() {
        // before any goal
        let s = build(vec![LedgerOp::ClaimAdd { text: "c".into() }, LedgerOp::EvidenceAdd(ev("c1", true, true))]);
        for st in [GoalMetStatus::Supported, GoalMetStatus::Refuted] {
            assert!(refusal(&s, conclude(st, &["e1"]), false).contains("no goal yet"));
        }
        let s = with_goal_and_run();
        // model-authored: accepted from a tool call
        assert!(s.validate(&conclude(GoalMetStatus::Supported, &["e1"]), false).is_ok());
        assert!(s.validate(&conclude(GoalMetStatus::Refuted, &["e1"]), false).is_ok());
        let folded = build(vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
            conclude(GoalMetStatus::Refuted, &["e1"]),
        ]);
        let gm = folded.goal_met.unwrap_or_else(|| panic!("goal_met"));
        assert_eq!((gm.status, gm.evidence, gm.n), (GoalMetStatus::Refuted, vec!["e1".to_string()], 4));
        // no evidence, unknown evidence, blank note
        assert!(refusal(&s, conclude(GoalMetStatus::Supported, &[]), false).contains("needs evidence"));
        assert!(refusal(&s, conclude(GoalMetStatus::Supported, &["e9"]), false).contains("Existing evidence record ids: e1"));
        let blank_note = LedgerOp::GoalMetSet { status: GoalMetStatus::Supported, note: " ".into(), evidence: vec!["e1".into()] };
        assert!(refusal(&s, blank_note, false).contains("note"));
        // static-only basis
        let s = build(vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::EvidenceAdd(static_ev("c1")),
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
        ]);
        for st in [GoalMetStatus::Supported, GoalMetStatus::Refuted] {
            let m = refusal(&s, conclude(st, &["e1"]), false);
            assert!(m.contains("static only") && m.contains("run the target"), "{m}");
        }
        // static plus execution is enough
        assert!(s.validate(&conclude(GoalMetStatus::Supported, &["e1", "e2"]), false).is_ok());
        // evidence that does not support, or is not attested, is refused
        let s = build(vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::EvidenceAdd(ev("c1", false, true)),
            LedgerOp::EvidenceAdd(ev("c1", true, false)),
        ]);
        assert!(refusal(&s, conclude(GoalMetStatus::Supported, &["e1"]), false).contains("not attested evidence that supports"));
        assert!(refusal(&s, conclude(GoalMetStatus::Supported, &["e2"]), false).contains("not attested evidence that supports"));
    }

    #[test]
    fn goal_met_cannot_be_withdrawn_or_repeated() {
        let s = with_goal_and_run();
        let m = refusal(&s, conclude(GoalMetStatus::Open, &["e1"]), false);
        assert!(m.contains("cannot be reopened or withdrawn"), "{m}");
        // No wire spelling of a withdrawn status exists.
        let w: Result<LedgerOp, _> = serde_json::from_str(r#"{"op":"goal_met_set","status":"withdrawn"}"#);
        assert!(w.is_err());
        // A forged Open entry cannot retract a conclusion.
        let mut s = build(vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
            conclude(GoalMetStatus::Supported, &["e1"]),
        ]);
        s.apply(&entry(5, LedgerOp::GoalMetSet { status: GoalMetStatus::Open, note: String::new(), evidence: vec![] }));
        assert_eq!(s.goal_met.as_ref().map(|g| g.status), Some(GoalMetStatus::Supported));
        // The same conclusion again is refused; the other one needs execution evidence recorded after it.
        assert!(refusal(&s, conclude(GoalMetStatus::Supported, &["e1"]), false).contains("already recorded as met"));
        let m = refusal(&s, conclude(GoalMetStatus::Refuted, &["e1"]), false);
        assert!(m.contains("run the target again") && m.contains("entry 4"), "{m}");
        s.apply(&entry(5, LedgerOp::EvidenceAdd(static_ev("c1"))));
        assert!(refusal(&s, conclude(GoalMetStatus::Refuted, &["e2"]), false).contains("static only"));
        s.apply(&entry(6, LedgerOp::EvidenceAdd(ev("c1", true, true))));
        assert!(s.validate(&conclude(GoalMetStatus::Refuted, &["e3"]), false).is_ok());
        s.apply(&entry(7, conclude(GoalMetStatus::Refuted, &["e3"])));
        assert_eq!(s.goal_met.as_ref().map(|g| (g.status, g.n)), Some((GoalMetStatus::Refuted, 7)));
    }

    #[test]
    fn goal_met_is_not_an_ordinary_open_claim() {
        let s = build(vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ClaimAdd { text: "c".into() },
            LedgerOp::EvidenceAdd(ev("c1", true, true)),
            LedgerOp::ClaimUpdate { id: "c1".into(), status: ClaimStatus::Supported, note: String::new() },
        ]);
        assert_eq!(s.goal_met.as_ref().map(|g| g.status), Some(GoalMetStatus::Open));
        assert!(s.open_items().claims.is_empty());
        assert!(s.open_items().is_empty());
        assert_eq!(s.claims.len(), 1);
        assert!(s.validate(&LedgerOp::FinishClaim { summary: "done".into(), evidence: vec![] }, false).is_ok());
    }

    #[test]
    fn goal_met_is_rendered_in_brief_and_markdown() {
        let open = build(vec![LedgerOp::GoalSet { text: "g".into() }]);
        assert!(open.brief(&BriefOpts::default()).contains("Goal status: open (not yet concluded)"));
        assert!(open.render_markdown().contains("## Goal status\n\nopen (not yet concluded)"));
        assert!(LedgerState::default().render_markdown().contains("(no goal set)"));
        let ops = |st| {
            vec![
                LedgerOp::GoalSet { text: "g".into() },
                LedgerOp::ClaimAdd { text: "c".into() },
                LedgerOp::EvidenceAdd(ev("c1", true, true)),
                conclude(st, &["e1"]),
            ]
        };
        let met = build(ops(GoalMetStatus::Supported));
        assert!(met.brief(&BriefOpts::default()).contains("Goal status: met — ran the target (evidence: e1)"));
        assert!(met.render_markdown().contains("met — ran the target (evidence: e1) (entry 4)"));
        let no = build(ops(GoalMetStatus::Refuted));
        assert!(no.brief(&BriefOpts::default()).contains("Goal status: cannot be met as stated — ran the target (evidence: e1)"));
        assert!(!no.brief(&BriefOpts::default()).contains("not yet concluded"));
    }

    #[test]
    fn release_is_operator_only_and_never_reads_as_success() {
        let with_goal = build(vec![LedgerOp::GoalSet { text: "g".into() }]);
        let op = LedgerOp::OperatorRelease { reason: "good enough for now".into() };
        let m = refusal(&with_goal, op.clone(), false);
        assert!(m.contains("operator's own words") && m.contains("cannot be written by a tool call"), "{m}");
        assert!(with_goal.validate(&op, true).is_ok());
        let blank_reason = LedgerOp::OperatorRelease { reason: "  ".into() };
        assert!(refusal(&with_goal, blank_reason, true).contains("reason"));
        let m = refusal(&LedgerState::default(), op.clone(), true);
        assert!(m.contains("no goal has been set"), "{m}");
        let released = build(vec![LedgerOp::GoalSet { text: "g".into() }, op.clone()]);
        assert_eq!(released.release, Some(Release { reason: "good enough for now".into(), n: 2 }));
        assert!(refusal(&released, op, true).contains("already released"));
        let b = released.brief(&BriefOpts::default());
        assert!(b.contains("released by the operator (goal not established): good enough for now"), "{b}");
        assert!(b.contains("Goal status: open (not yet concluded)"), "{b}");
        let md = released.render_markdown();
        assert!(md.contains("released by the operator (goal not established): good enough for now (entry 2)"), "{md}");
        // A release leaves the goal-met claim alone.
        assert_eq!(released.goal_met.as_ref().map(|g| g.status), Some(GoalMetStatus::Open));
    }

    #[test]
    fn scope_grants_are_operator_only_and_listed() {
        let s = build(vec![LedgerOp::GoalSet { text: "g".into() }]);
        let grant = |hosts: &[&str]| LedgerOp::ScopeGrant { hosts: hosts.iter().map(|h| h.to_string()).collect(), note: None };
        let m = refusal(&s, grant(&["a.example"]), false);
        assert!(m.contains("operator's own words") && m.contains("cannot be written by a tool call"), "{m}");
        assert!(s.validate(&grant(&["a.example", "*.b.example", "10.0.0.1:8080"]), true).is_ok());
        assert!(refusal(&s, grant(&[]), true).contains("at least one host"));
        assert!(refusal(&s, grant(&["a.example", " "]), true).contains("entry"));
        assert!(refusal(&s, grant(&[""]), true).contains("entry"));
        for bad in ["a.example,b.example", "a.example b.example", " a.example", "a.example\n"] {
            let m = refusal(&s, grant(&[bad]), true);
            assert!(m.contains("one host per entry"), "{bad:?}: {m}");
        }
        // none granted
        let b = s.brief(&BriefOpts::default());
        assert!(b.contains("authorized hosts: none granted"), "{b}");
        assert!(s.granted_hosts().is_empty());
        // grants accumulate, de-duplicated, first-seen order
        let s = build(vec![
            LedgerOp::GoalSet { text: "g".into() },
            LedgerOp::ScopeGrant { hosts: vec!["b.example".into(), "a.example".into()], note: Some("crawl".into()) },
            LedgerOp::ScopeGrant { hosts: vec!["A.example".into(), "c.example".into(), "b.example".into()], note: None },
        ]);
        assert_eq!(s.granted_hosts(), ["b.example", "a.example", "c.example"]);
        assert_eq!(s.scope_grants.iter().map(|g| (g.id.as_str(), g.n)).collect::<Vec<_>>(), [("s1", 2), ("s2", 3)]);
        let b = s.brief(&BriefOpts::default());
        assert!(b.contains("authorized hosts: b.example, a.example, c.example"), "{b}");
        let md = s.render_markdown();
        assert!(md.contains("authorized hosts: b.example, a.example, c.example"), "{md}");
        assert!(md.contains("- **s1** (entry 2): b.example, a.example — crawl"), "{md}");
        assert!(md.contains("- **s2** (entry 3): A.example, c.example, b.example"), "{md}");
        assert!(build(vec![LedgerOp::GoalSet { text: "g".into() }]).render_markdown().contains("authorized hosts: none granted"));
    }

    #[test]
    fn a_journal_written_before_these_records_still_folds() {
        // The entries as the base version wrote them: no goal-met, release or scope-grant fields anywhere.
        let lines = [
            r#"{"n":1,"ts_ms":1,"session":"s-1","from_user":true,"op":"goal_set","text":"g","mac":""}"#,
            r#"{"n":2,"ts_ms":2,"session":"s-1","op":"claim_add","text":"c","mac":""}"#,
            r#"{"n":3,"ts_ms":3,"session":"s-1","op":"plan_add","text":"p","mac":""}"#,
        ];
        let entries: Vec<Entry> = lines.iter().filter_map(|l| serde_json::from_str(l).ok()).collect();
        assert_eq!(entries.len(), 3);
        let s = LedgerState::fold(&entries);
        assert_eq!(s.entries, 3);
        assert_eq!(s.release, None);
        assert!(s.scope_grants.is_empty());
        assert_eq!(s.granted_hosts(), Vec::<String>::new());
        // A goal opens the goal-met claim; that is the only non-empty new field.
        assert_eq!(s.goal_met.as_ref().map(|g| g.status), Some(GoalMetStatus::Open));
        let goalless = LedgerState::fold(&entries[1..]);
        assert_eq!((goalless.goal_met, goalless.release, goalless.scope_grants), (None, None, vec![]));
        // A persisted state without the new keys deserializes with the empty defaults.
        let old = r#"{"goal":"g","constraints":[],"plan":[],"decisions":[],"dead_ends":[],"claims":[],"evidence":[],"obligations":[],"approvals":[],"questions":[],"finishes":[],"entries":1}"#;
        let st: Result<LedgerState, _> = serde_json::from_str(old);
        let st = st.unwrap_or_else(|e| panic!("{e}"));
        assert_eq!((st.goal_met, st.release, st.scope_grants), (None, None, vec![]));
        // Optional fields may be absent on the wire for the new ops.
        let op: Result<LedgerOp, _> = serde_json::from_str(r#"{"op":"scope_grant","hosts":["a.example"]}"#);
        assert!(matches!(op, Ok(LedgerOp::ScopeGrant { note: None, .. })));
    }
}
