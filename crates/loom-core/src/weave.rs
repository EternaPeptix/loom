//! The weave: session log → the stable request prefix, and re-weave planning.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//! `docs/DESIGN.md` §5 is the base text; where this file is more specific, this file wins.
//!
//! `weave(records)` is a pure function: same records, same output, byte for byte.
//!
//! Rendering, in log order:
//! - `session_start` → one `system` message (`system_prompt`). `Weave::tools` = its `tools`, unchanged.
//! - `user_message` → `user` message, text verbatim.
//! - `harness_note` → `user`-role `<harness kind="{kind}">\n{text}\n</harness>`. If the record's author
//!   is `Agent(id)`, the opening tag is `<harness kind="{kind}" from="{id}">`.
//! - `forked` → `user`-role `<harness kind="assignment" from="{parent}">\n{contract}\n\n{brief}\n</harness>`
//!   where the brief is rendered by [`render_brief`]. Records before it are the parent's and render as
//!   they would in the parent.
//! - `model_response` → `assistant` message with `text`, the tool calls whose `complete` is true (id =
//!   call id, arguments string verbatim), and `reasoning` when the session's `reasoning_replay` is `All`
//!   and the reasoning is non-empty. Responses with `finish` `Aborted` or `Error` are not rendered. A
//!   response with no text and no complete tool calls is not rendered.
//! - `tool_result` → `tool` message, `tool_call_id` = call id, content = `text` verbatim.
//! - `child_settled` → `user`-role `<harness kind="agent-report" agent="{child}" outcome="{outcome}">\n{report}\n</harness>`.
//! - everything else → nothing.
//!
//! Pairing: every rendered assistant tool call is followed (before the next assistant or user-role
//! item) by exactly one `tool` message per call, in call order. If the log holds no result for a call,
//! [`MISSING_RESULT`] is rendered for it. Results that arrive in the log in a different order than the
//! calls are rendered in call order.
//!
//! Merging: consecutive `user`-role items become one `user` message joined by a blank line, except
//! that a `user`-role item directly after a `tool` message starts its own message. `Message::origin`
//! lists the seqs merged into it.
//!
//! Re-weaves: each `reweave` record adds its evictions to those of earlier ones (later wins for the
//! same seq) and replaces the brief. Evictions are applied while rendering: `Stub{text}` replaces a
//! tool result's or agent report's content; `Drop` on a tool result is treated as a stub with
//! [`DROPPED_RESULT`]; `Drop` on a model response removes text and reasoning but keeps its tool calls
//! (so pairing still holds), and removes the message entirely when it has no tool calls; `Drop` on a
//! droppable harness note removes it; `DropReasoning` removes only the replayed reasoning. Evictions
//! naming protected items (system, user messages, protected notes, forked) are ignored. The latest
//! brief (plus its digest, when present, under the line `Leads from earlier work (written by the
//! model, not verified — re-check before relying on them):`) is rendered as a `user`-role
//! `<harness kind="resume">` item directly after the last item whose seq is `<= upto_seq`.
//! `Weave::epoch` is the latest re-weave's epoch, or 0.
//!
//! Pins: `pin`/`unpin` records set `WindowItem::pinned` for a call's result; `plan_reweave` never
//! evicts a pinned result.
//!
//! `plan_reweave` chooses evictions for a new re-weave so that the estimated size falls to
//! `floor_tokens` or below, stopping as soon as it does. `upto_seq` is the seq of the last record
//! before the protected recent region (the most recent `keep_recent_steps` model responses and
//! everything after the first of them). Order of sacrifice, each class oldest first unless stated:
//!   1. `DropReasoning` on model responses;
//!   2. stub `ToolClass::Nav` results;
//!   3. stub `ToolClass::Read` results, largest first;
//!   4. stub every other unpinned tool result and agent report, largest first;
//!   5. only when `allow_text_eviction`: `Drop` assistant text.
//! Results already stubbed are skipped. Returns `None` when nothing can be evicted. Stub text comes
//! from [`stub_text`].
//!
//! Tests required: each rendering rule; pairing with missing and out-of-order results; merge rules;
//! determinism (weave twice, compare JSON); reweave application for every action; cumulative
//! re-weaves; pins respected; brief placement; a forked log renders the parent's prefix identically
//! to the parent's own weave of the same records (compare message JSON); plan order and stopping
//! point; plan never touches the recent region or protected items; `request_messages` HUD placement.

use crate::estimate::TokenEstimator;
use crate::event::{Brief, Eviction, Record, Seq, ToolCall, ToolClass, ToolResult, ToolSpec};
use crate::ids::CallId;
use crate::message::{Message, Role};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Rendered for a tool call that has no result in the log.
pub const MISSING_RESULT: &str =
    "[no result recorded: the call was interrupted; its effects are unknown — check before retrying]";

/// Rendered for a tool result evicted with `Drop`.
pub const DROPPED_RESULT: &str = "[evicted from view; the call and its result remain in the session record]";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemState {
    /// Rendered as recorded.
    Live,
    /// Replaced by a stub.
    Stubbed,
    /// Reasoning no longer replayed; the rest is live.
    ReasoningDropped,
    /// Removed from the window.
    Dropped,
}

/// One log record's standing in the window, for inspection (API `/window`) and for planning.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WindowItem {
    pub seq: Seq,
    /// Event kind as on the wire (`tool_result`, `model_response`, …).
    pub kind: String,
    pub role: Role,
    /// Characters this item currently contributes to the request.
    pub chars: usize,
    pub state: ItemState,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub call_id: Option<CallId>,
    #[serde(default)]
    pub class: Option<ToolClass>,
    /// First 160 characters of the rendered content, single line.
    pub preview: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Weave {
    /// The stable request prefix.
    pub messages: Vec<Message>,
    /// The session's tool set (from `session_start`).
    pub tools: Vec<ToolSpec>,
    pub epoch: u32,
    /// One entry per record that renders (or would render if not evicted), in log order.
    pub items: Vec<WindowItem>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReweavePolicy {
    /// Plan a re-weave when the server-reported prompt size exceeds this.
    pub target_tokens: u64,
    /// Evict until the estimate is at or below this.
    pub floor_tokens: u64,
    /// Model responses at the end of the log whose surroundings are never evicted.
    pub keep_recent_steps: u32,
    /// Trailing lines of an evicted `Exec` result kept in its stub.
    pub stub_tail_lines: u32,
}

impl Default for ReweavePolicy {
    fn default() -> Self {
        Self { target_tokens: 400_000, floor_tokens: 180_000, keep_recent_steps: 60, stub_tail_lines: 12 }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReweavePlan {
    pub upto_seq: Seq,
    pub evictions: Vec<Eviction>,
    pub before_tokens_est: u64,
    pub after_tokens_est: u64,
}

/// Render the stable prefix from a session's records.
pub fn weave(records: &[Record]) -> Weave {
    let _ = records;
    todo!("implement per module contract")
}

/// Choose evictions for the next re-weave, or `None` if nothing can be evicted.
pub fn plan_reweave(
    records: &[Record],
    estimator: &TokenEstimator,
    policy: &ReweavePolicy,
    allow_text_eviction: bool,
) -> Option<ReweavePlan> {
    let _ = (records, estimator, policy, allow_text_eviction);
    todo!("implement per module contract")
}

/// The stub that replaces an evicted tool result.
///
/// Line 1 is the first line of `result.text` (the envelope header written at admission), unchanged.
/// For `ToolClass::Exec`, the last `stub_tail_lines` lines of `result.text` follow under the line
/// `[last {n} lines as first shown]`. The final line is:
/// `[evicted from view, not from the record: {lines} lines / {bytes} bytes. Full output: {handle} — read it again with out_read or out_grep before relying on it.]`
/// (`{lines}`/`{bytes}`/`{handle}` from `result.output`; when there is no stored output the final line
/// is `[evicted from view, not from the record. Run it again if the result matters.]`).
pub fn stub_text(call: Option<&ToolCall>, result: &ToolResult, stub_tail_lines: u32) -> String {
    let _ = (call, result, stub_tail_lines);
    todo!("implement per module contract")
}

/// Render a brief as the text a child sees. Fixed field order; absent fields are omitted:
/// `Question: …`, `Hypothesis: …`, `Scope: …`, `Not yours: …`, `Return: …`, `Stop when: …`, `Context: …`,
/// one per paragraph.
pub fn render_brief(brief: &Brief) -> String {
    let _ = brief;
    todo!("implement per module contract")
}

/// The `messages` array for a request: the stable messages in OpenAI form, then — when `hud` is given
/// — one final `user` message `<harness-state>\n{hud}\n</harness-state>`. The HUD is never merged
/// into a stable message, so the stable part is byte-identical with or without it.
pub fn request_messages(weave: &Weave, hud: Option<&str>) -> Vec<Value> {
    let _ = (weave, hud);
    todo!("implement per module contract")
}
