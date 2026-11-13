//! A session's scorecard: what its work took, and how often the harness sent it back. Pure over the
//! log records of one session.
//!
//! CONTRACT.
//!
//! A change to the harness (a prompt, a gate, a tool's shape) is meant to make the model's work cheaper
//! or its results better. Whether it did is a question about runs, and these are the numbers that answer
//! it: the same ones for a scripted run against the mock server (`loom-agent`'s `evalkit`) and for a
//! recorded run of a real model (`loom score`). They are counts of records, not judgements: nothing here
//! reads prose, and nothing here knows whether a result was right. Whether the task was solved is the
//! business of an oracle outside the session (`docs/SECURITY-EVAL.md`).
//!
//! `score(records)` reads the session's *own* records: those from its last `session_start` or `forked`
//! record on (a fork's log begins with a copy of its parent's log, which is the parent's work). With
//! neither record, all of them.
//!
//! - `steps`: `model_request` records with purpose `Step` (a digest request is not a step).
//! - `finished`: a `finish` result with status `Ok` exists. `steps_to_finish`: the steps requested up to
//!   the first such result; `None` without one. A run that did not finish is censored, not fast: `None`
//!   is never to be read as zero, and a mean over runs is a mean over the finished ones only, reported
//!   with how many those are.
//! - `calls`: the tool calls of the session's `model_response` records, complete or not.
//!   `malformed_calls`: those not `complete` (the output limit cut them: they never ran) and the
//!   `tool_result`s with status `Invalid` (arguments that do not fit the tool, a tool that does not
//!   exist: nothing ran). `malformed_call_rate()` is malformed / calls, `None` with no calls.
//! - `finish_calls`: `tool_result`s of `finish`. `finish_refusals`: those whose status is not `Ok`,
//!   whatever held the result back (a quote, the goal not concluded, open ledger items, running work, the
//!   verifier, a fault). `Invalid` ones count here and as malformed.
//! - `quote_refusals`: results with `meta[META_REFUSAL] == REFUSAL_QUOTE`: a `finish` or an `evidence`
//!   whose quote did not check. Each is a step spent on repairing a quote.
//! - `verifier_accepts`: `finish` results with status `Ok` and `meta[META_VERIFIED] == true`.
//!   `verifier_rejections`: `finish` results with `meta[META_REFUSAL] == REFUSAL_VERIFIER`.
//!   `verifier_accept_rate()` is accepts / (accepts + rejections), `None` when no verifier judged a
//!   finish.
//! - `fresh_starts`: `reweave` records whose evictions include a `Remove` (only a fresh start after a
//!   finish that was not accepted plans one).
//! - `unrecorded`: true when a `finish` result with status `Ok` has no `META_VERIFIED`: the log was
//!   written before the harness recorded these facts, so its verifier and quote counts are not zero but
//!   unknown, and the rates are `None`.
//!
//! `add(other)` adds another session's work to a total: every count is summed, `unrecorded` is true if
//! either is, and `finished`/`steps_to_finish` stay as they are (the result of a mission is its lead's,
//! so the lead's card is the one others are added to).
//!
//! `cells()` is the card as a table row under the headings `COLUMNS`, for the two places that print one
//! (`evalkit::table`, `loom score`), so that both say the same thing the same way: `steps`; `to finish`
//! (`-` for a run that did not finish); `calls`; `malformed` as `{n} ({pct}%)`, the rate rounded to a
//! whole per cent, `-` with no calls; `finish refused` as `{refusals} of {finish calls}`; `quote refused`;
//! `verifier` as `{accepts} of {finishes judged}`, `-` when none was judged; `fresh starts`. `quote
//! refused` and `verifier` are `?` on an `unrecorded` card.
//!
//! Tests required: an empty log; each count from records that carry it and not from those that do not; a
//! fork's copied prefix left out; a run that never finished; the rates with and without a denominator; a
//! log without the meta keys; `add`; `cells` for a full card, an empty one and an unrecorded one.

use crate::event::{
    Event, EvictAction, Purpose, Record, ToolStatus, META_REFUSAL, META_VERIFIED, REFUSAL_QUOTE, REFUSAL_VERIFIER,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The counts of one session (or, after [`Scorecard::add`], of several). See the module contract.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scorecard {
    pub steps: u64,
    pub finished: bool,
    pub steps_to_finish: Option<u64>,
    pub calls: u64,
    pub malformed_calls: u64,
    pub finish_calls: u64,
    pub finish_refusals: u64,
    pub quote_refusals: u64,
    pub verifier_accepts: u64,
    pub verifier_rejections: u64,
    pub fresh_starts: u64,
    pub unrecorded: bool,
}

impl Scorecard {
    /// Malformed calls per call made; `None` when the session made no call.
    pub fn malformed_call_rate(&self) -> Option<f64> {
        ratio(self.malformed_calls, self.calls)
    }

    /// Finishes a verifier accepted per finish a verifier judged; `None` when none was judged, or when
    /// the log does not record verdicts.
    pub fn verifier_accept_rate(&self) -> Option<f64> {
        if self.unrecorded {
            return None;
        }
        ratio(self.verifier_accepts, self.verifier_accepts.saturating_add(self.verifier_rejections))
    }

    /// Add the work of another session of the same mission (a worker, a verifier) to this one's.
    pub fn add(&mut self, other: &Scorecard) {
        self.steps = self.steps.saturating_add(other.steps);
        self.calls = self.calls.saturating_add(other.calls);
        self.malformed_calls = self.malformed_calls.saturating_add(other.malformed_calls);
        self.finish_calls = self.finish_calls.saturating_add(other.finish_calls);
        self.finish_refusals = self.finish_refusals.saturating_add(other.finish_refusals);
        self.quote_refusals = self.quote_refusals.saturating_add(other.quote_refusals);
        self.verifier_accepts = self.verifier_accepts.saturating_add(other.verifier_accepts);
        self.verifier_rejections = self.verifier_rejections.saturating_add(other.verifier_rejections);
        self.fresh_starts = self.fresh_starts.saturating_add(other.fresh_starts);
        self.unrecorded |= other.unrecorded;
    }

    /// The card as one table row under [`COLUMNS`]. See the module contract.
    pub fn cells(&self) -> [String; 8] {
        let recorded = |known: String| if self.unrecorded { "?".to_string() } else { known };
        let judged = self.verifier_accepts.saturating_add(self.verifier_rejections);
        [
            self.steps.to_string(),
            self.steps_to_finish.map_or_else(|| "-".to_string(), |n| n.to_string()),
            self.calls.to_string(),
            match percent(self.malformed_calls, self.calls) {
                Some(pct) => format!("{} ({pct}%)", self.malformed_calls),
                None => "-".to_string(),
            },
            format!("{} of {}", self.finish_refusals, self.finish_calls),
            recorded(self.quote_refusals.to_string()),
            recorded(if judged == 0 { "-".to_string() } else { format!("{} of {judged}", self.verifier_accepts) }),
            self.fresh_starts.to_string(),
        ]
    }
}

/// The headings of [`Scorecard::cells`], in its order.
pub const COLUMNS: [&str; 8] =
    ["steps", "to finish", "calls", "malformed", "finish refused", "quote refused", "verifier", "fresh starts"];

fn ratio(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| part as f64 / whole as f64)
}

/// `part` of `whole` in whole per cent, rounded to the nearest; `None` when `whole` is zero.
fn percent(part: u64, whole: u64) -> Option<u64> {
    (whole > 0).then(|| part.saturating_mul(100).saturating_add(whole / 2) / whole)
}

/// The scorecard of the session whose log `records` is.
pub fn score(records: &[Record]) -> Scorecard {
    let own_from =
        records.iter().rposition(|r| matches!(r.event, Event::SessionStart(_) | Event::Forked(_))).unwrap_or(0);
    let mut card = Scorecard::default();
    for record in records.get(own_from..).unwrap_or_default() {
        match &record.event {
            Event::ModelRequest(q) if q.purpose == Purpose::Step => card.steps = card.steps.saturating_add(1),
            Event::ModelResponse(resp) => {
                card.calls = card.calls.saturating_add(resp.tool_calls.len() as u64);
                let cut = resp.tool_calls.iter().filter(|c| !c.complete).count() as u64;
                card.malformed_calls = card.malformed_calls.saturating_add(cut);
            }
            Event::ToolResult(t) => {
                if t.status == ToolStatus::Invalid {
                    card.malformed_calls = card.malformed_calls.saturating_add(1);
                }
                let refusal = t.meta.get(META_REFUSAL).and_then(Value::as_str);
                if refusal == Some(REFUSAL_QUOTE) {
                    card.quote_refusals = card.quote_refusals.saturating_add(1);
                }
                if t.name != "finish" {
                    continue;
                }
                card.finish_calls = card.finish_calls.saturating_add(1);
                if t.status != ToolStatus::Ok {
                    card.finish_refusals = card.finish_refusals.saturating_add(1);
                    if refusal == Some(REFUSAL_VERIFIER) {
                        card.verifier_rejections = card.verifier_rejections.saturating_add(1);
                    }
                    continue;
                }
                match t.meta.get(META_VERIFIED).and_then(Value::as_bool) {
                    Some(true) => card.verifier_accepts = card.verifier_accepts.saturating_add(1),
                    Some(false) => {}
                    None => card.unrecorded = true,
                }
                if !card.finished {
                    card.finished = true;
                    card.steps_to_finish = Some(card.steps);
                }
            }
            Event::Reweave(w) if w.evictions.iter().any(|e| e.action == EvictAction::Remove) => {
                card.fresh_starts = card.fresh_starts.saturating_add(1);
            }
            _ => {}
        }
    }
    card
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::event::{
        Author, Brief, Budget, Eviction, FinishReason, Forked, ModelRequest, ModelResponse, Reweave, Termination,
        Timing, ToolCallRequest, ToolClass, ToolResult, Usage,
    };
    use crate::ids::{CallId, SessionId};
    use serde_json::{json, Map};

    fn rec(seq: u64, event: Event) -> Record {
        Record { seq, ts_ms: seq, author: Author::Harness, prev: String::new(), event }
    }

    fn request(purpose: Purpose) -> Event {
        Event::ModelRequest(ModelRequest {
            req_id: "r".into(),
            step: 1,
            epoch: 0,
            purpose,
            n_messages: 1,
            stable_hash: String::new(),
            hud: None,
            est_tokens: 0,
        })
    }

    /// A reply making one call per entry: its name and whether the call is complete.
    fn reply(calls: &[(&str, bool)]) -> Event {
        Event::ModelResponse(ModelResponse {
            req_id: "r".into(),
            text: String::new(),
            reasoning: String::new(),
            tool_calls: calls
                .iter()
                .map(|(name, complete)| ToolCallRequest {
                    call_id: CallId::from("c"),
                    name: (*name).into(),
                    arguments: "{}".into(),
                    complete: *complete,
                })
                .collect(),
            finish: FinishReason::ToolCalls,
            usage: Usage::default(),
            timing: Timing::default(),
            attempts: 1,
        })
    }

    fn result(name: &str, status: ToolStatus, meta: Value) -> Event {
        Event::ToolResult(ToolResult {
            call_id: CallId::from("c"),
            name: name.into(),
            status,
            text: String::new(),
            output: None,
            cut: false,
            class: ToolClass::State,
            meta: meta.as_object().cloned().unwrap_or_else(Map::new),
            duration_ms: 0,
        })
    }

    fn numbered(events: Vec<Event>) -> Vec<Record> {
        events.into_iter().enumerate().map(|(i, e)| rec(i as u64, e)).collect()
    }

    /// One step: a request, a reply with one complete call, its result.
    fn step(name: &str, status: ToolStatus, meta: Value) -> Vec<Event> {
        vec![request(Purpose::Step), reply(&[(name, true)]), result(name, status, meta)]
    }

    #[test]
    fn an_empty_log_scores_nothing_and_has_no_rates() {
        let card = score(&[]);
        assert_eq!(card, Scorecard::default());
        assert_eq!(card.malformed_call_rate(), None);
        assert_eq!(card.verifier_accept_rate(), None);
        assert_eq!(card.steps_to_finish, None);
    }

    #[test]
    fn a_run_is_counted_record_by_record() {
        let mut events = Vec::new();
        events.extend(step("bash", ToolStatus::Ok, json!({})));
        // A call the tool's parameters refuse, and one the output limit cut: neither ran.
        events.extend(step("bash", ToolStatus::Invalid, json!({})));
        events.extend(vec![request(Purpose::Step), reply(&[("bash", true), ("edit", false)])]);
        events.push(result("bash", ToolStatus::Error, json!({})));
        // A quote that did not check, in `evidence` and in `finish`.
        events.extend(step("evidence", ToolStatus::Error, json!({ META_REFUSAL: REFUSAL_QUOTE })));
        events.extend(step("finish", ToolStatus::Error, json!({ META_REFUSAL: REFUSAL_QUOTE })));
        // A finish held for another reason, one its verifier rejected, and the fold that follows.
        events.extend(step("finish", ToolStatus::Error, json!({})));
        events.extend(step("finish", ToolStatus::Error, json!({ META_REFUSAL: REFUSAL_VERIFIER })));
        events.push(Event::Reweave(Reweave {
            epoch: 1,
            upto_seq: 0,
            evictions: vec![Eviction { seq: 3, action: EvictAction::Remove }],
            brief: String::new(),
            digest: None,
            reason: "finish not accepted".into(),
            before_tokens: 0,
            after_tokens_est: 0,
        }));
        // A digest request is not a step; a re-weave for size is not a fresh start.
        events.push(request(Purpose::Digest));
        events.push(Event::Reweave(Reweave {
            epoch: 2,
            upto_seq: 0,
            evictions: vec![Eviction { seq: 1, action: EvictAction::Drop }],
            brief: String::new(),
            digest: None,
            reason: "target".into(),
            before_tokens: 0,
            after_tokens_est: 0,
        }));
        events.extend(step("finish", ToolStatus::Ok, json!({ META_VERIFIED: true })));
        // Work after the result does not move `steps_to_finish`.
        events.extend(step("bash", ToolStatus::Ok, json!({})));
        let card = score(&numbered(events));
        assert_eq!(
            card,
            Scorecard {
                steps: 9,
                finished: true,
                steps_to_finish: Some(8),
                calls: 10,
                malformed_calls: 2,
                finish_calls: 4,
                finish_refusals: 3,
                quote_refusals: 2,
                verifier_accepts: 1,
                verifier_rejections: 1,
                fresh_starts: 1,
                unrecorded: false,
            }
        );
        assert_eq!(card.malformed_call_rate(), Some(0.2));
        assert_eq!(card.verifier_accept_rate(), Some(0.5));
    }

    #[test]
    fn a_run_that_did_not_finish_is_censored_not_fast() {
        let mut events = step("bash", ToolStatus::Ok, json!({}));
        events.extend(step("finish", ToolStatus::Error, json!({})));
        let card = score(&numbered(events));
        assert!(!card.finished);
        assert_eq!((card.steps, card.steps_to_finish), (2, None));
        assert_eq!((card.finish_calls, card.finish_refusals), (1, 1));
        // No verifier judged anything: there is no rate, which is not a rate of zero.
        assert_eq!(card.verifier_accept_rate(), None);
        assert_eq!(card.malformed_call_rate(), Some(0.0));
    }

    #[test]
    fn a_delivery_without_a_verifier_is_no_verdict() {
        let card = score(&numbered(step("finish", ToolStatus::Ok, json!({ META_VERIFIED: false }))));
        assert!(card.finished && !card.unrecorded);
        assert_eq!((card.verifier_accepts, card.verifier_rejections), (0, 0));
        assert_eq!(card.verifier_accept_rate(), None);
    }

    #[test]
    fn a_log_without_the_recorded_facts_says_so() {
        let mut events = step("finish", ToolStatus::Error, json!({}));
        events.extend(step("finish", ToolStatus::Ok, json!({})));
        let card = score(&numbered(events));
        assert!(card.unrecorded && card.finished);
        assert_eq!(card.steps_to_finish, Some(2));
        assert_eq!(card.verifier_accept_rate(), None);
    }

    #[test]
    fn the_copied_prefix_of_a_fork_is_the_parents_work() {
        let mut events = step("bash", ToolStatus::Invalid, json!({}));
        events.extend(step("finish", ToolStatus::Error, json!({ META_REFUSAL: REFUSAL_QUOTE })));
        events.push(Event::Forked(Forked {
            session: SessionId::from("s-child"),
            parent: SessionId::from("s-lead"),
            upto_seq: 5,
            role: "worker".into(),
            termination: Termination::Explicit,
            budget: Budget::default(),
            brief: Brief::default(),
            contract: String::new(),
            allowed_tools: None,
            title: String::new(),
        }));
        events.extend(step("bash", ToolStatus::Ok, json!({})));
        events.extend(step("finish", ToolStatus::Ok, json!({ META_VERIFIED: false })));
        let card = score(&numbered(events));
        assert_eq!((card.steps, card.calls, card.malformed_calls, card.quote_refusals), (2, 2, 0, 0));
        assert_eq!((card.finish_calls, card.finish_refusals, card.steps_to_finish), (1, 0, Some(2)));
    }

    #[test]
    fn adding_a_session_sums_its_work_and_keeps_the_result() {
        let mut lead = Scorecard {
            steps: 6,
            finished: true,
            steps_to_finish: Some(6),
            calls: 6,
            finish_calls: 2,
            finish_refusals: 1,
            verifier_accepts: 1,
            verifier_rejections: 1,
            fresh_starts: 1,
            ..Scorecard::default()
        };
        let worker = Scorecard {
            steps: 4,
            finished: true,
            steps_to_finish: Some(4),
            calls: 5,
            malformed_calls: 1,
            finish_calls: 2,
            finish_refusals: 1,
            quote_refusals: 1,
            ..Scorecard::default()
        };
        lead.add(&worker);
        assert_eq!((lead.steps, lead.calls, lead.malformed_calls), (10, 11, 1));
        assert_eq!((lead.finish_calls, lead.finish_refusals, lead.quote_refusals), (4, 2, 1));
        assert_eq!((lead.verifier_accepts, lead.verifier_rejections, lead.fresh_starts), (1, 1, 1));
        // The result is the lead's.
        assert_eq!((lead.finished, lead.steps_to_finish), (true, Some(6)));
        assert!(!lead.unrecorded);
        lead.add(&Scorecard { unrecorded: true, ..Scorecard::default() });
        assert!(lead.unrecorded && lead.verifier_accept_rate().is_none());
    }

    #[test]
    fn a_card_as_a_table_row() {
        let card = Scorecard {
            steps: 12,
            finished: true,
            steps_to_finish: Some(11),
            calls: 16,
            malformed_calls: 2,
            finish_calls: 3,
            finish_refusals: 2,
            quote_refusals: 4,
            verifier_accepts: 1,
            verifier_rejections: 1,
            fresh_starts: 1,
            unrecorded: false,
        };
        assert_eq!(card.cells(), ["12", "11", "16", "2 (13%)", "2 of 3", "4", "1 of 2", "1"]);
        assert_eq!(COLUMNS.len(), card.cells().len());
        // Nothing done: no rate, no finish to reach, no verdict. None of them reads as a zero.
        assert_eq!(Scorecard::default().cells(), ["0", "-", "0", "-", "0 of 0", "0", "-", "0"]);
        // What an old log does not record is unknown, not zero; what it does record is still shown.
        let old = Scorecard { unrecorded: true, ..card };
        assert_eq!(old.cells(), ["12", "11", "16", "2 (13%)", "2 of 3", "?", "?", "1"]);
        // The rate rounds to the nearest whole per cent.
        let rate = |malformed, calls| {
            Scorecard { malformed_calls: malformed, calls, ..Scorecard::default() }.cells()[3].clone()
        };
        assert_eq!(
            (rate(1, 3), rate(2, 3), rate(1, 200), rate(3, 3)),
            ("1 (33%)".into(), "2 (67%)".into(), "1 (1%)".into(), "3 (100%)".into())
        );
    }
}
