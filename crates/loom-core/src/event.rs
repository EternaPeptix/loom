//! The normative event schema. A session log is a sequence of [`Record`]s, one JSON object per line.
//!
//! Field and variant names here are the wire format: the daemon serves records exactly as stored and
//! the UI reads them directly. Add fields with `#[serde(default)]`; never rename or repurpose one.

use crate::blob::BlobRef;
use crate::ids::{CallId, MissionId, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Position of a record in its session log, starting at 0.
pub type Seq = u64;

/// `ToolResult::meta` key: line ranges of a stored output that `text` put in front of the model, as
/// `[[first, last], …]` (1-based, inclusive). Refers to `META_OF_BLOB` when present, else to `output`.
pub const META_SHOWN: &str = "shown";
/// `ToolResult::meta` key: full id of the stored output this result is a view of (`out_read`,
/// `out_grep`). Absent when the result shows its own `output`.
pub const META_OF_BLOB: &str = "of_blob";
/// `ToolResult::meta` key: process exit code (integer).
pub const META_EXIT_CODE: &str = "exit_code";
/// `ToolResult::meta` key: signal number that ended the process.
pub const META_SIGNAL: &str = "signal";
/// `ToolResult::meta` key: absolute path of the file a `read`/`write`/`edit` touched.
pub const META_PATH: &str = "path";
/// `ToolResult::meta` key: full id of the raw bytes, when the stored text differs from them.
pub const META_RAW_BLOB: &str = "raw_blob";
/// `ToolResult::meta` key: id of the background job a call turned into or started.
pub const META_JOB: &str = "job";

/// Who produced an item. Never changed by projection, eviction or summarisation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Author {
    /// The human operator.
    User,
    /// The model driving this session.
    Model,
    /// A tool, reporting what it observed.
    Tool,
    /// loom itself.
    Harness,
    /// Another session (a child reporting to its parent, or a parent briefing a child).
    Agent(SessionId),
}

/// One line of a session log.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub seq: Seq,
    pub ts_ms: u64,
    pub author: Author,
    /// SHA-256 (hex) of the previous line's bytes, without its newline; 64 zeros for `seq` 0.
    pub prev: String,
    #[serde(flatten)]
    pub event: Event,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// Always `seq` 0. Fixes everything that sits at the head of the prompt.
    SessionStart(SessionStart),
    /// First record after a copied parent prefix in a forked child. Overrides identity and contract.
    Forked(Forked),
    UserMessage {
        text: String,
    },
    /// Text from the harness that the model must see and that stays in the window.
    HarnessNote {
        note: NoteKind,
        text: String,
    },
    TurnStart {
        trigger: Trigger,
    },
    /// Bookkeeping for one model request. Not rendered.
    ModelRequest(ModelRequest),
    ModelResponse(ModelResponse),
    /// Intent to run a tool. Appended and synced before the tool starts.
    ToolCall(ToolCall),
    ToolResult(ToolResult),
    Reweave(Reweave),
    /// Keep this call's output verbatim through evictions until unpinned.
    Pin {
        call_id: CallId,
        reason: String,
    },
    Unpin {
        call_id: CallId,
    },
    ChildSpawned(ChildSpawned),
    ChildSettled(ChildSettled),
    JobRegistered {
        job_id: String,
        call_id: CallId,
        command: String,
    },
    JobSettled {
        job_id: String,
        exit_code: Option<i32>,
        output: Option<BlobRef>,
        detail: String,
    },
    InboxOpened(InboxItem),
    InboxResolved {
        item_id: String,
        answer: String,
    },
    /// A ledger op written by this session (the op itself lives in the mission journal).
    Ledger {
        n: u64,
        summary: String,
    },
    Net(NetDecision),
    /// The stable prefix changed without a re-weave. Always a defect worth looking at.
    CacheBreak {
        req_id: String,
        first_diff_message: u32,
        detail: String,
    },
    /// The session was cut off (daemon restart, damaged log, user stop mid-step).
    Interrupted {
        reason: String,
    },
    TurnEnd {
        reason: TurnEndReason,
    },
    SessionEnd {
        outcome: SessionOutcome,
        detail: String,
    },
    /// A kind this build does not know. Preserved on disk, ignored by the weave.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionStart {
    pub session: SessionId,
    pub mission: MissionId,
    #[serde(default)]
    pub parent: Option<SessionId>,
    /// Absolute path of the workspace directory.
    pub workspace: String,
    pub pack: String,
    pub role: String,
    pub termination: Termination,
    pub model: ModelRef,
    #[serde(default)]
    pub reasoning_replay: ReasoningReplay,
    /// The complete system message, fixed for the life of the session.
    pub system_prompt: String,
    /// The complete tool set, fixed for the life of the session.
    pub tools: Vec<ToolSpec>,
    #[serde(default)]
    pub budget: Budget,
    /// Resume after a daemon restart without waiting for the operator.
    #[serde(default)]
    pub unattended: bool,
    #[serde(default)]
    pub title: String,
    /// Log format version; absent in logs written before the field existed (version 1). A log with
    /// a higher number is read-only for this build.
    #[serde(default = "schema_v1")]
    pub schema: u32,
}

/// The log schema version this build writes and supports.
pub const SCHEMA: u32 = 1;

fn schema_v1() -> u32 {
    1
}

/// A fork: the child's log begins with a byte-for-byte copy of the parent's log up to and including
/// `upto_seq`, then this record. The child therefore shares the parent's request prefix exactly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Forked {
    pub session: SessionId,
    pub parent: SessionId,
    pub upto_seq: Seq,
    pub role: String,
    pub termination: Termination,
    #[serde(default)]
    pub budget: Budget,
    pub brief: Brief,
    /// The child role's contract text, rendered with the brief as the child's assignment.
    #[serde(default)]
    pub contract: String,
    /// Tool names the child role may call. The tool list sent to the model stays the parent's (the
    /// request head must not change); calls outside this list are refused at call time.
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(default)]
    pub title: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelRef {
    /// Name of the profile in the config.
    pub profile: String,
    pub model: String,
    pub context_window: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningReplay {
    /// Reasoning is sent back with the response it belongs to and stays in place (append-only), until
    /// a re-weave drops it. The default: the target chat template keeps replayed reasoning where it
    /// was and renders an empty reasoning block when it is missing.
    #[default]
    All,
    /// Reasoning is never sent back.
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    /// A reply without tool calls ends the turn (interactive chat).
    Free,
    /// The session ends work only through a terminating tool; anything else goes through the stop gate.
    Explicit,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    #[serde(default)]
    pub max_steps: Option<u32>,
    #[serde(default)]
    pub max_minutes: Option<u32>,
}

/// What a tool does, used for scheduling, eviction order and evidence rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolClass {
    /// Finding things: listings, searches. First to be evicted.
    Nav,
    /// Reading content: files, pages, stored output.
    Read,
    /// Running something and observing it.
    Exec,
    /// Changing files.
    Write,
    /// Ledger and agent management.
    State,
    /// Ends or parks the session's work.
    Terminal,
}

impl ToolClass {
    /// Safe to run concurrently with other calls of the same response.
    pub fn is_read_only(self) -> bool {
        matches!(self, ToolClass::Nav | ToolClass::Read)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the arguments object.
    pub parameters: Value,
    pub class: ToolClass,
}

impl ToolSpec {
    /// The OpenAI `tools[]` entry.
    pub fn to_openai(&self) -> Value {
        serde_json::json!({
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            }
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteKind {
    /// The stop gate listing what is still open.
    Nudge,
    /// The model's output hit the output limit.
    OutputCut,
    /// Something was interrupted and its outcome is unknown.
    Interrupted,
    /// A user approval, verbatim, with its scope. Never evicted.
    Approval,
    /// A standing user constraint, verbatim. Never evicted.
    Constraint,
    /// A budget was reached or is about to be.
    Budget,
    /// Result of the finish gate or a verifier.
    Verdict,
    /// A background job or inbox answer arrived.
    Arrival,
    /// A task handed to this session by its parent (role contract and brief). Never evicted.
    Assignment,
    /// The session has gone a while without recorded progress.
    Stall,
    Info,
}

impl NoteKind {
    /// Notes that survive every re-weave.
    pub fn is_protected(self) -> bool {
        matches!(self, NoteKind::Approval | NoteKind::Constraint | NoteKind::Assignment)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NoteKind::Nudge => "nudge",
            NoteKind::OutputCut => "output_cut",
            NoteKind::Interrupted => "interrupted",
            NoteKind::Approval => "approval",
            NoteKind::Constraint => "constraint",
            NoteKind::Budget => "budget",
            NoteKind::Verdict => "verdict",
            NoteKind::Arrival => "arrival",
            NoteKind::Assignment => "assignment",
            NoteKind::Stall => "stall",
            NoteKind::Info => "info",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Start,
    User,
    ChildSettled,
    JobSettled,
    InboxAnswer,
    Resume,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// An ordinary agent step.
    Step,
    /// A digest request made on the existing prefix before a re-weave.
    Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelRequest {
    pub req_id: String,
    /// 1-based step number within the session.
    pub step: u32,
    pub epoch: u32,
    pub purpose: Purpose,
    /// Number of stable messages sent (the HUD is not counted).
    pub n_messages: u32,
    /// SHA-256 over the stable messages' canonical JSON, in order.
    pub stable_hash: String,
    /// The ephemeral HUD text sent with this request, stored for inspection.
    #[serde(default)]
    pub hud: Option<BlobRef>,
    pub est_tokens: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelResponse {
    pub req_id: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub reasoning: String,
    #[serde(default)]
    pub tool_calls: Vec<ToolCallRequest>,
    pub finish: FinishReason,
    #[serde(default)]
    pub usage: Usage,
    #[serde(default)]
    pub timing: Timing,
    /// How many attempts the request took (1 = no retry).
    #[serde(default)]
    pub attempts: u32,
}

/// A tool call as the model wrote it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallRequest {
    pub call_id: CallId,
    pub name: String,
    /// The arguments exactly as produced (may be invalid JSON).
    pub arguments: String,
    /// False when the output limit cut the call short. Incomplete calls are never run or rendered.
    #[serde(default = "yes")]
    pub complete: bool,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    ToolCalls,
    /// The output limit was reached.
    Length,
    /// The request was cancelled.
    Aborted,
    /// The request failed after retries; `text` holds the error.
    Error,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub cached_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub reasoning_tokens: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timing {
    /// Waiting for a scheduler slot.
    #[serde(default)]
    pub queue_ms: u64,
    /// Request sent to first streamed token.
    #[serde(default)]
    pub ttft_ms: u64,
    /// Request sent to end of stream.
    #[serde(default)]
    pub total_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub call_id: CallId,
    pub req_id: String,
    pub name: String,
    /// Parsed arguments (`null` when the model's JSON was invalid).
    pub args: Value,
    pub class: ToolClass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Ok,
    /// The tool ran and reported failure (non-zero exit, file not found, …).
    Error,
    /// Arguments failed validation or the tool does not exist; nothing ran.
    Invalid,
    /// Refused by policy (sandbox, scope, approval).
    Denied,
    Timeout,
    /// Cut off; effects unknown.
    Interrupted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub call_id: CallId,
    pub name: String,
    pub status: ToolStatus,
    /// Exactly what the model sees for this result.
    pub text: String,
    /// The complete output, when it was stored (always, for anything a tool produced).
    #[serde(default)]
    pub output: Option<BlobRef>,
    /// True when `text` is a cut of `output`.
    #[serde(default)]
    pub cut: bool,
    pub class: ToolClass,
    /// Tool-specific facts. Well-known keys are the `META_*` constants in this module.
    #[serde(default)]
    pub meta: Map<String, Value>,
    #[serde(default)]
    pub duration_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reweave {
    /// The epoch this re-weave starts (first re-weave is 1).
    pub epoch: u32,
    /// Evictions apply to records at or before this seq; the brief is rendered right after it.
    pub upto_seq: Seq,
    /// New evictions made by this re-weave. Earlier re-weaves' evictions still apply.
    pub evictions: Vec<Eviction>,
    /// Harness note rendered after the evicted span: ledger snapshot and how to resume.
    pub brief: String,
    /// Model-written leads about evicted narration, rendered inside the brief, marked as unverified.
    #[serde(default)]
    pub digest: Option<String>,
    pub reason: String,
    pub before_tokens: u64,
    pub after_tokens_est: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eviction {
    pub seq: Seq,
    pub action: EvictAction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictAction {
    /// Replace the rendered content with this text (tool results, agent reports).
    Stub { text: String },
    /// Remove the content. For a model response this removes text and reasoning but keeps tool calls.
    Drop,
    /// For a model response: stop replaying its reasoning; text and tool calls stay.
    DropReasoning,
}

/// A typed task hand-off. Rendered for the child by the harness, never by the parent's prose.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Brief {
    /// One sentence: what must be answered.
    pub question: String,
    #[serde(default)]
    pub hypothesis: Option<String>,
    /// Files, symbols, systems the child may touch, and why they matter.
    #[serde(default)]
    pub scope: Option<String>,
    /// Neighbouring work that belongs to someone else.
    #[serde(default)]
    pub do_not: Option<String>,
    /// What the result must contain.
    #[serde(default, rename = "return")]
    pub returns: Option<String>,
    #[serde(default)]
    pub stop_when: Option<String>,
    /// Anything else the child needs that is not in its starting context.
    #[serde(default)]
    pub context: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnMode {
    /// Starts from the role prompt and the brief.
    Fresh,
    /// Starts from the parent's exact prefix plus the brief.
    Fork,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChildSpawned {
    pub child: SessionId,
    pub role: String,
    pub mode: SpawnMode,
    pub brief: Brief,
    #[serde(default)]
    pub budget: Budget,
    /// The tool call that asked for it, when the model did.
    #[serde(default)]
    pub call_id: Option<CallId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildOutcome {
    /// Returned a result that met its contract.
    Returned,
    /// Returned an objective blocker.
    Blocked,
    BudgetExhausted,
    Stopped,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChildSettled {
    pub child: SessionId,
    pub outcome: ChildOutcome,
    /// The framed, capped report as the parent sees it.
    pub report: String,
    /// The complete report.
    #[serde(default)]
    pub full: Option<BlobRef>,
    #[serde(default)]
    pub usage: Usage,
    #[serde(default)]
    pub steps: u32,
    /// The report was returned as the result of the tool call that was waiting for the child. The
    /// record is kept for the session's history; the weave does not render it (the report is
    /// already in view as that call's result).
    #[serde(default)]
    pub inline: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxKind {
    Approval,
    Question,
    Blocker,
    /// The stop gate gave up nudging.
    Parked,
    /// The mission finished and passed its gate.
    Finished,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InboxItem {
    pub item_id: String,
    /// On the wire this is `item_kind`: a record is flat and `kind` is the record's own tag.
    #[serde(rename = "item_kind")]
    pub kind: InboxKind,
    pub text: String,
    #[serde(default)]
    pub options: Vec<String>,
    /// The session cannot continue until this is answered.
    #[serde(default)]
    pub blocking: bool,
    #[serde(default)]
    pub call_id: Option<CallId>,
    /// The ledger question (`q3`) this item belongs to; answering the item answers the question.
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetDecision {
    pub host: String,
    pub port: u16,
    /// `CONNECT` or the HTTP method of a plain request.
    pub method: String,
    pub allowed: bool,
    /// The rule that decided it, e.g. `allow *.example.test`, `deny private-address`, `default deny`.
    pub rule: String,
    #[serde(default)]
    pub resolved: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnEndReason {
    /// Replied without tool calls in a `free` session.
    Yielded,
    Finished,
    Asked,
    Blocked,
    /// Waiting for jobs or children.
    Waiting,
    Stopped,
    /// The stop gate parked it for the operator.
    Parked,
    BudgetExhausted,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionOutcome {
    Done,
    Stopped,
    Failed,
    BudgetExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::BlobId;

    fn record(event: Event) -> Record {
        Record { seq: 3, ts_ms: 1, author: Author::Harness, prev: "0".repeat(64), event }
    }

    #[test]
    fn record_is_flat_and_tagged() {
        let r = record(Event::UserMessage { text: "hi".into() });
        let v: Value = serde_json::to_value(&r).unwrap();
        assert_eq!(v["kind"], "user_message");
        assert_eq!(v["text"], "hi");
        assert_eq!(v["seq"], 3);
        assert_eq!(v["author"], "harness");
        let back: Record = serde_json::from_value(v).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn agent_author_round_trips() {
        let mut r = record(Event::TurnStart { trigger: Trigger::User });
        r.author = Author::Agent(SessionId::from("s-abc"));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"author\":{\"agent\":\"s-abc\"}"));
        assert_eq!(serde_json::from_str::<Record>(&s).unwrap(), r);
    }

    #[test]
    fn unknown_kind_is_tolerated() {
        let line = format!(
            "{{\"seq\":9,\"ts_ms\":1,\"author\":\"harness\",\"prev\":\"{}\",\"kind\":\"from_the_future\",\"x\":1}}",
            "0".repeat(64)
        );
        let r: Record = serde_json::from_str(&line).unwrap();
        assert_eq!(r.event, Event::Unknown);
        assert_eq!(r.seq, 9);
    }

    /// One record of every kind. A record is flat, so a field of an event that shares a name with a
    /// field of the record (or with the `kind` tag) would silently produce a line that cannot be read
    /// back; this is the guard against that.
    fn one_of_each() -> Vec<(&'static str, Event)> {
        let s = || SessionId::from("s-a");
        let c = || CallId::from("c1");
        let blob = || BlobRef { id: BlobId::from("ab".repeat(32)), bytes: 10, lines: 2 };
        let brief = || Brief { question: "q".into(), returns: Some("r".into()), ..Default::default() };
        let budget = || Budget { max_steps: Some(5), max_minutes: Some(9) };
        vec![
            (
                "session_start",
                Event::SessionStart(SessionStart {
                    session: s(),
                    mission: MissionId::from("m-a"),
                    parent: Some(SessionId::from("s-p")),
                    workspace: "/w".into(),
                    pack: "core".into(),
                    role: "lead".into(),
                    termination: Termination::Explicit,
                    model: ModelRef { profile: "local".into(), model: "m".into(), context_window: 1000 },
                    reasoning_replay: ReasoningReplay::All,
                    system_prompt: "sys".into(),
                    tools: vec![ToolSpec {
                        name: "bash".into(),
                        description: "d".into(),
                        parameters: serde_json::json!({"type": "object"}),
                        class: ToolClass::Exec,
                    }],
                    budget: budget(),
                    unattended: true,
                    schema: SCHEMA,
                    title: "t".into(),
                }),
            ),
            (
                "forked",
                Event::Forked(Forked {
                    session: s(),
                    parent: SessionId::from("s-p"),
                    upto_seq: 4,
                    role: "worker".into(),
                    termination: Termination::Explicit,
                    budget: budget(),
                    brief: brief(),
                    contract: "c".into(),
                    allowed_tools: Some(vec!["read".into()]),
                    title: "t".into(),
                }),
            ),
            ("user_message", Event::UserMessage { text: "hi".into() }),
            ("harness_note", Event::HarnessNote { note: NoteKind::Nudge, text: "n".into() }),
            ("turn_start", Event::TurnStart { trigger: Trigger::User }),
            (
                "model_request",
                Event::ModelRequest(ModelRequest {
                    req_id: "r-1".into(),
                    step: 1,
                    epoch: 0,
                    purpose: Purpose::Step,
                    n_messages: 3,
                    stable_hash: "h".into(),
                    hud: Some(blob()),
                    est_tokens: 9,
                }),
            ),
            (
                "model_response",
                Event::ModelResponse(ModelResponse {
                    req_id: "r-1".into(),
                    text: "t".into(),
                    reasoning: "r".into(),
                    tool_calls: vec![ToolCallRequest {
                        call_id: c(),
                        name: "bash".into(),
                        arguments: "{}".into(),
                        complete: true,
                    }],
                    finish: FinishReason::ToolCalls,
                    usage: Usage { prompt_tokens: 5, cached_tokens: 4, completion_tokens: 3, reasoning_tokens: 2 },
                    timing: Timing { queue_ms: 1, ttft_ms: 2, total_ms: 3 },
                    attempts: 1,
                }),
            ),
            (
                "tool_call",
                Event::ToolCall(ToolCall {
                    call_id: c(),
                    req_id: "r-1".into(),
                    name: "bash".into(),
                    args: serde_json::json!({"command": "ls"}),
                    class: ToolClass::Exec,
                }),
            ),
            (
                "tool_result",
                Event::ToolResult(ToolResult {
                    call_id: c(),
                    name: "bash".into(),
                    status: ToolStatus::Ok,
                    text: "ok".into(),
                    output: Some(blob()),
                    cut: true,
                    class: ToolClass::Exec,
                    meta: Map::new(),
                    duration_ms: 5,
                }),
            ),
            (
                "reweave",
                Event::Reweave(Reweave {
                    epoch: 1,
                    upto_seq: 7,
                    evictions: vec![
                        Eviction { seq: 3, action: EvictAction::Stub { text: "s".into() } },
                        Eviction { seq: 4, action: EvictAction::Drop },
                        Eviction { seq: 5, action: EvictAction::DropReasoning },
                    ],
                    brief: "b".into(),
                    digest: Some("d".into()),
                    reason: "target".into(),
                    before_tokens: 9,
                    after_tokens_est: 4,
                }),
            ),
            ("pin", Event::Pin { call_id: c(), reason: "r".into() }),
            ("unpin", Event::Unpin { call_id: c() }),
            (
                "child_spawned",
                Event::ChildSpawned(ChildSpawned {
                    child: s(),
                    role: "worker".into(),
                    mode: SpawnMode::Fork,
                    brief: brief(),
                    budget: budget(),
                    call_id: Some(c()),
                }),
            ),
            (
                "child_settled",
                Event::ChildSettled(ChildSettled {
                    child: s(),
                    outcome: ChildOutcome::Returned,
                    report: "r".into(),
                    full: Some(blob()),
                    usage: Usage::default(),
                    steps: 2,
                    inline: true,
                }),
            ),
            ("job_registered", Event::JobRegistered { job_id: "j1".into(), call_id: c(), command: "make".into() }),
            (
                "job_settled",
                Event::JobSettled { job_id: "j1".into(), exit_code: Some(0), output: Some(blob()), detail: "d".into() },
            ),
            (
                "inbox_opened",
                Event::InboxOpened(InboxItem {
                    item_id: "i-1".into(),
                    kind: InboxKind::Question,
                    text: "t".into(),
                    options: vec!["a".into()],
                    blocking: true,
                    call_id: Some(c()),
                    reference: Some("q1".into()),
                }),
            ),
            ("inbox_resolved", Event::InboxResolved { item_id: "i-1".into(), answer: "a".into() }),
            ("ledger", Event::Ledger { n: 3, summary: "s".into() }),
            (
                "net",
                Event::Net(NetDecision {
                    host: "h".into(),
                    port: 443,
                    method: "CONNECT".into(),
                    allowed: false,
                    rule: "deny".into(),
                    resolved: Some("1.2.3.4".into()),
                }),
            ),
            ("cache_break", Event::CacheBreak { req_id: "r-1".into(), first_diff_message: 2, detail: "d".into() }),
            ("interrupted", Event::Interrupted { reason: "r".into() }),
            ("turn_end", Event::TurnEnd { reason: TurnEndReason::Finished }),
            ("session_end", Event::SessionEnd { outcome: SessionOutcome::Done, detail: "d".into() }),
        ]
    }

    #[test]
    fn every_kind_is_tagged_with_its_own_name_and_reads_back() {
        for (name, event) in one_of_each() {
            let r = record(event);
            let line = serde_json::to_string(&r).unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["kind"], name, "tag of {name}: {line}");
            assert_eq!(v["seq"], 3, "seq of {name}");
            assert_eq!(v["author"], "harness", "author of {name}");
            let back: Record = serde_json::from_str(&line).unwrap_or_else(|e| panic!("{name} does not read back: {e}\n{line}"));
            assert_eq!(back, r, "{name}");
            assert_ne!(back.event, Event::Unknown, "{name}");
        }
    }

    #[test]
    fn struct_variants_round_trip() {
        let r = record(Event::ToolResult(ToolResult {
            call_id: CallId::from("c1"),
            name: "bash".into(),
            status: ToolStatus::Ok,
            text: "ok".into(),
            output: None,
            cut: false,
            class: ToolClass::Exec,
            meta: Map::new(),
            duration_ms: 5,
        }));
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<Record>(&s).unwrap(), r);
        let brief = Brief { question: "q".into(), returns: Some("r".into()), ..Default::default() };
        let v = serde_json::to_value(&brief).unwrap();
        assert_eq!(v["return"], "r");
    }
}
