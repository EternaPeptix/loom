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

/// The folded state of a mission. Ids are assigned by `fold`: constraints `k1…`, plan steps `p1…`,
/// decisions `d1…`, dead ends `x1…`, claims `c1…`, evidence `e1…`, obligations `o1…`,
/// approvals `a1…`, questions `q1…`, finish claims `f1…`.
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
    /// Number of entries folded.
    pub entries: u64,
}

// ---------------------------------------------------------------------------------------------
// CONTRACT for the implementer (bodies below are placeholders; signatures and types are fixed).
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
// `open_items()`: plan steps `Todo`/`Doing`; obligations with no outcome; claims with status `Open`;
// questions with `blocking` and no answer.
//
// `brief(opts)` renders the compact state text used in the HUD and after a re-weave, in this order,
// omitting empty sections: `Goal:` (full text), `Constraints:` (active only, verbatim), `Plan:` (one
// line per non-dropped step: `[x] p1 text — note` / `[>] doing` / `[ ] todo`), `Open obligations:`,
// `Claims:` (id, status, text, evidence ids), `Decisions:` (last `opts.max_decisions`),
// `Dead ends:` (last `opts.max_dead_ends`), `Approvals:` (unused ones, verbatim, with scope),
// `Unanswered questions:`. Evidence quotes are not included. Each line is cut at `opts.max_line`
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

impl LedgerState {
    pub fn fold(entries: &[Entry]) -> LedgerState {
        let mut state = LedgerState::default();
        for entry in entries {
            state.apply(entry);
        }
        state
    }

    pub fn apply(&mut self, entry: &Entry) {
        let _ = entry;
        todo!("implement per contract above")
    }

    pub fn validate(&self, op: &LedgerOp, from_user: bool) -> Result<(), String> {
        let _ = (op, from_user);
        todo!("implement per contract above")
    }

    pub fn open_items(&self) -> OpenItems {
        todo!("implement per contract above")
    }

    pub fn brief(&self, opts: &BriefOpts) -> String {
        let _ = opts;
        todo!("implement per contract above")
    }

    pub fn render_markdown(&self) -> String {
        todo!("implement per contract above")
    }

    /// One line describing an op, for the session log's `ledger` event (`summary`).
    pub fn summarize(op: &LedgerOp) -> String {
        let _ = op;
        todo!("implement per contract above")
    }
}
