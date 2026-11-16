//! What `security_record` accepts: the exact shape of every operation, how a near miss is read, and
//! the guidance a refused operation gets.
//!
//! CONTRACT.
//!
//! Why: logged missions showed 42% of `security_record` calls refused, almost all for shape rather
//! than substance (a host given as `127.0.0.1:19727`, a `hypothesis: {…}` wrapper, `ops` for
//! `operations`, `priority: "high"`, a free-text blocked_on condition). Each refusal costs a model
//! step. This module reads a near miss where its meaning is unambiguous, says so in a note, and
//! otherwise refuses with the exact shape to send. It never weakens what the core checks: evidence
//! must still exist and be attested, authority is still checked by `authorize` and the core, and
//! secret material is never echoed.
//!
//! ## `read(caller, state, operation)`
//!
//! Reads the tool's `operation` argument into one `SecurityOp` plus notes. Steps, in this order:
//!
//! 1. `operation` must be a JSON object with a string `action`. Otherwise:
//!    "Correct `operation` before retrying: give an object with `action`, one of {ACTIONS joined by
//!    `, `}. Nothing was recorded."
//! 2. For `action == "batch"`: N1, then every element of `operations` is read by steps 3–6 on its
//!    own, with location "operation {i} of the batch" (1-based, in the order given). An element that
//!    is not an object with a string `action` is refused with
//!    "Operation {i} of {n} in the batch: give an object with `action`. Nothing was recorded."
//!    Elements are not expanded (N4d applies to a single operation only). A nested batch element is
//!    passed through unchanged; the core refuses it. The batch itself is decoded from the read
//!    elements; it stays one atomic append.
//!    For a single operation the location is "the operation".
//! 3. Early refusals (before any shape check), each with prefix P (empty for a single operation,
//!    "Operation {i} of {n} in the batch ({action}): " for a batch element) and the suffix
//!    " Nothing was recorded.":
//!    - R1: `action` is not in ACTIONS but is one of `caller.tools` →
//!      P + "`{action}` is a separate tool, not a security_record action; call it directly."
//!    - Unknown action otherwise → P + "Correct `operation` before retrying: `{action}` is not a
//!      security_record action; use one of {ACTIONS joined by `, `}." (the action text cut to 80
//!      characters on a character boundary).
//!    - R4: `hypothesis_verdict` when `caller.standing != Judge` →
//!      P + "Only an independent read-only verifier records a hypothesis verdict. Attach your
//!      evidence with hypothesis_evidence {id, evidence}; the hypothesis stays open until a verifier
//!      reviews it."
//!    - `hypothesis_open` when `caller.standing == Child` →
//!      P + "Only the mission lead may open a hypothesis; send the proposed hypothesis to the lead."
//!    - `hypothesis_priority` when `caller.standing == Child` →
//!      P + "Only the hypothesis's original lead may change its priority; send the proposed change to
//!      that lead."
//! 4. Normalization (N1–N7 below). Every rewrite appends exactly one note, in the order applied. A
//!    note names its location L ("the operation" or "operation {i} of the batch").
//! 5. Refusals that need the normalized value (R2, R5, R6, R7), same P and suffix.
//! 6. Decode with serde (the core types keep `deny_unknown_fields`):
//!    - D1 single operation: "Correct `operation` before retrying: {serde error}. {action} takes
//!      {shape(action)}. Nothing was recorded."
//!    - D2 batch element: "Operation {i} of {n} in the batch ({action}): correct it before retrying:
//!      {serde error}. {action} takes {shape(action)}. Nothing was recorded."
//!
//! Strings quoted back into a note or a refusal are cut to 80 characters on a character boundary
//! (with "…" appended when cut). A locator holding URL user information (`user@` or `user:pass@`)
//! is never rewritten and never quoted; the core refuses it.
//!
//! ### Normalization rules
//!
//! - N1 batch: `operations` absent and exactly one of `ops` / `items` present → renamed.
//!   Note: "In the batch, `{ops|items}` was read as `operations`."
//! - N2 wrapper operations — asset_upsert→`asset`, credential_add→`credential`,
//!   foothold_add→`foothold`, relation_add→`relation`. Inner fields: asset {kind, locator, evidence,
//!   mandatory, parent}; credential {asset, principal, secret_handle, evidence, unlocks, expires_ms,
//!   username, user}; foothold {asset, principal, access, evidence, unlocks, expires_ms, username,
//!   user}; relation {from, to, kind, cost, evidence, expires_ms}.
//!   - N2a: the wrapper key is absent and at least one inner field is at the top level → every
//!     top-level key except `action` moves into a new wrapper object.
//!     Note: "In L, the {asset|credential|foothold|relation} fields were moved into `{key}`."
//!   - N2b: the wrapper is an object without `evidence` and the top level has `evidence` → moved in.
//!     Note: "In L, `evidence` was moved into `{key}`."
//! - N3 credential/foothold (inside the wrapper): `principal` absent and `username` or `user`
//!   present → renamed. Note: "In L, `{username|user}` was read as `principal`."
//! - N4 hypothesis_open:
//!   - N4a: `hypothesis` is an object and `text` is absent → its keys are copied into the operation
//!     where the operation lacks them, then `hypothesis` is removed.
//!     Note: "In L, the fields of `hypothesis` were read as the operation's own."
//!   - N4b: `text` absent and `hypothesis` (a string) or `statement` present → renamed to `text`.
//!     Note: "In L, `{hypothesis|statement}` was read as `text`."
//!   - N4c: `status` present → removed. When it is "open" (any case):
//!     "In L, `status` was dropped: a new hypothesis is always open." Otherwise:
//!     "In L, status `{status}` was not recorded: a new hypothesis is open, and only an independent
//!     read-only verifier records a verdict."
//!   - N4d: `evidence` or `counterevidence` present. For a single operation, when either is a
//!     nonempty array, the operation becomes the batch [hypothesis_open {text, priority},
//!     hypothesis_evidence {id: stable_id("hy", [text.trim()]), evidence, counterevidence}]
//!     (missing lists empty). Note: "In L, the evidence was attached by a hypothesis_evidence
//!     operation recorded in the same atomic append." When both are empty arrays they are removed
//!     silently. Inside a batch a nonempty one is refused (R8).
//! - N5 priority (hypothesis_open, hypothesis_priority): an integer 0–255 is kept. A string, trimmed
//!   and case-insensitive: "low"→1, "medium"/"normal"→3, "high"→5, all ASCII digits with value
//!   0–255→that number. Note: "In L, priority `{given}` was read as {n}." hypothesis_open without
//!   `priority` gets 3. Note: "In L, no priority was given, so it is 3 (1 low to 5 high)." Any other
//!   value is R7.
//! - N6 hypothesis_priority / hypothesis_evidence / hypothesis_verdict:
//!   - N6a: `id` absent and `hypothesis` or `hypothesis_id` (a string) present → renamed.
//!     Note: "In L, `{hypothesis|hypothesis_id}` was read as `id`."
//!   - evidence/verdict: a missing `evidence` or `counterevidence` becomes `[]` (no note).
//!   - N6b verdict: `status` absent and `verdict` present → renamed. Note: "In L, `verdict` was read
//!     as `status`."
//!   - N6c verdict: `status` (string, trimmed, case-insensitive) "confirmed", "verified", "true",
//!     "accepted", "valid" → "supported"; "disproved", "rejected", "false", "invalid" → "refuted"; a
//!     JSON boolean true/false the same. Note: "In L, status `{given}` was read as `{status}`."
//! - N7 asset_upsert locators (after N2; only when `asset.kind` and `asset.locator` are strings;
//!   the locator is trimmed first):
//!   - N7a kind host: a locator that is not an IP address and (i) parses as a URL with a host and no
//!     user information, or (ii) is `name:port` / `[v6]:port` with a decimal port of at most five
//!     digits and a name without `/`, `@`, `:` or whitespace → the host (brackets removed), only when
//!     `canonical_locator(Host, host)` accepts it. Note: "In L, the host was recorded as `{host}`
//!     from `{given}`: a host locator has no scheme, port or path; record the service as kind
//!     service with an absolute URL."
//!   - N7b kind service/endpoint: a leading token GET, POST, PUT, PATCH, DELETE, HEAD or OPTIONS
//!     (any case) followed by whitespace, when the rest starts with `{scheme}://` or with `/` → the
//!     rest. Note: "In L, the HTTP method `{METHOD}` was dropped from the locator: an endpoint is
//!     identified by its URL."
//!   - N7c kind service/endpoint: the locator holds whitespace and its first token parses as an
//!     absolute URL with a host and no user information → the first token. Note: "In L, the text
//!     after the URL was not recorded: `{rest}`; record it as a fact if it matters."
//!   - N7d kind service/endpoint: the locator starts with `/` but not `//`, `asset.parent` is a
//!     string that `state.resolve` resolves to a recorded asset whose locator parses as an absolute
//!     URL with a host → `base.join(locator)`, accepted only when the joined URL keeps the base's
//!     scheme, host and port. Note: "In L, the path `{path}` was joined to its parent's URL as
//!     `{url}`." A parent that does not resolve → P + the resolve error + suffix.
//!
//! ### Refusals after normalization
//!
//! - R2 a condition (an element of `conditions` in condition_unlock / blocked_on, or of `unlocks`
//!   in a credential or foothold) that is not an object, or whose `kind` is not one of auth, cred,
//!   role, leak, offset, key → P + "A condition is a typed prerequisite {kind, value} with kind
//!   auth, cred, role, leak, offset or key, for example {\"kind\": \"cred\", \"value\": \"<asset
//!   ID>\"}; `{given}` is not one." + (when `caller.tools` has report_blocker) " To report that a
//!   target is unreachable or the environment is broken, use report_blocker." `{given}` is the
//!   string itself, or the `kind` value, or the compact JSON of the element.
//! - R5 kind service/endpoint, the locator has no `://`, no whitespace, no `@`, and its part before
//!   the first `/` is `name:port` with a decimal port, or a bare name or IP → P + "Give the scheme as
//!   well, for example `http://{locator}` (or `tcp://{locator}` for a service that is not HTTP)."
//! - R6 kind service/endpoint, the locator starts with `/` and N7d did not apply (no parent, or a
//!   parent whose locator is not an absolute URL) → P + "An endpoint locator is one absolute URL,
//!   such as `http://10.0.0.5:8080/render?name=`; give the full URL, or name its service asset as
//!   `parent` and give only the path."
//! - R7 priority not readable by N5 → P + "Give priority as an integer from 1 (low) to 5 (high), or
//!   low, medium or high."
//! - R8 hypothesis_open inside a batch with a nonempty evidence or counterevidence list → P +
//!   "A hypothesis opens without evidence. Put {\"action\": \"hypothesis_evidence\", \"id\":
//!   \"{id}\", \"evidence\": […]} after it in the batch; `{id}` is the ID of this text." where `{id}`
//!   is `stable_id("hy", [text.trim()])` (quoted in full, never cut).
//!
//! ## `shape(action)` and `ACTIONS`
//!
//! `ACTIONS` lists the 19 `SecurityOp` actions in the order of the enum. `shape` returns exactly:
//!
//! - asset_upsert: `{action:asset_upsert, asset:{kind:host|service|endpoint|file|identity, locator, evidence:[eN], mandatory?:true, parent?:assetID}}; a host locator is a bare name or IP such as 10.0.0.5; a service or endpoint locator is one absolute URL such as http://10.0.0.5:8080/login?next=, without a method or a description`
//! - coverage_set: `{action:coverage_set, asset:assetID, disposition:{status:tested, evidence:[eN]} or {status:deferred, reason}}`
//! - credential_add: `{action:credential_add, credential:{asset:assetID, principal, secret_handle:out handle of the stored secret, evidence:[eN], unlocks?:[condition], expires_ms?}}`
//! - foothold_add: `{action:foothold_add, foothold:{asset:assetID, principal, access, evidence:[eN], unlocks?:[condition], expires_ms?}}`
//! - condition_unlock: `{action:condition_unlock, conditions:[condition], evidence:[eN]}`
//! - blocked_on: `{action:blocked_on, target:ID, conditions:[condition]}`
//! - revisit_acknowledge: `{action:revisit_acknowledge, target:ID}`
//! - crash_record: `{action:crash_record, signature:{sanitizer, frames:[{function, file, line?}], outcome:crash|timeout|oom|no_crash|fuzzer_exit71}, attempt:{vector, summary, evidence:[eN]}}`
//! - hypothesis_open: `{action:hypothesis_open, text, priority?:1 (low) to 5 (high), default 3}`
//! - hypothesis_priority: `{action:hypothesis_priority, id:hypothesisID, priority:1 (low) to 5 (high)}`
//! - hypothesis_evidence: `{action:hypothesis_evidence, id:hypothesisID, evidence:[eN], counterevidence?:[eN]}`
//! - hypothesis_verdict: `{action:hypothesis_verdict, id:hypothesisID, status:supported|refuted, note, evidence:[eN], counterevidence:[eN]}`
//! - relation_add: `{action:relation_add, relation:{from:assetID, to:assetID, kind, cost:1-1000 (smaller is easier), evidence:[eN], expires_ms?}}`
//! - fact_assert: `{action:fact_assert, fact:{predicate, args:[string]}, evidence:[eN]}`
//! - fact_retract: `{action:fact_retract, id:factID, reason}`
//! - rule_install: `{action:rule_install, rule:{name, head:{predicate, args:[?x]}, body:[{atom:{predicate, args:[?x]}, negated?:false}]}}`
//! - rule_retract: `{action:rule_retract, id:ruleID, reason}`
//! - alias_add: `{action:alias_add, alias, target:ID}`
//! - batch: `{action:batch, operations:[operation, …]}; atomic: when one operation is invalid nothing is recorded and the error names it`
//!
//! Any other action → `None`.
//!
//! ## `description(caller)` (the tool description)
//!
//! Lines joined by "\n":
//! 1. "Record typed, evidence-linked security observations in the mission ledger. `operation` is one
//!    object: an action and its fields."
//! 2. One line "- {shape(action)}" per action in ACTIONS order, with batch moved to the end, except:
//!    - Child: hypothesis_open and hypothesis_priority are replaced by the single line
//!      "- hypothesis_open, hypothesis_priority: the mission lead's; send a proposed hypothesis to the
//!      lead." (at hypothesis_open's position).
//!    - Lead and Child: hypothesis_verdict is "- hypothesis_verdict: recorded only by an independent
//!      read-only verifier; attach evidence with hypothesis_evidence and the hypothesis stays open
//!      until one reviews it."
//! 3. "A condition is {kind:auth|cred|role|leak|offset|key, value}: a typed prerequisite that a route
//!    waits on, not a description of a fault." + (when tools has report_blocker) " Report an
//!    unreachable target or a broken environment with report_blocker."
//! 4. "Evidence IDs (eN) must already exist and be attested" + (when tools has evidence) ": attach
//!    the output that shows it with the evidence tool first" + ". An ID may be the exact ID, an
//!    alias, or a unique prefix of at least four characters" + (when tools has security_query)
//!    "; security_query lists them" + "."
//! 5. "Near-miss field names and locators are read where the meaning is unambiguous, and each such
//!    reading is listed under `normalized` in the result. These records never authorize network
//!    access."
//!
//! The description names no tool that is not in `caller.tools`, except security_record itself.
//! It is a pure function of `caller`, so a session's tool schema is stable across steps.
//!
//! ## Tests required
//!
//! - Every N rule: input → decoded op + the exact note text (single operation and batch location).
//! - Every refusal R1, R2 (string, unknown kind; with and without report_blocker in tools), R4 (lead
//!   and plain child; refused before a shape error would be reported), R5, R6 (no parent; parent that
//!   is a host), R7, R8, child open/priority; unknown action; non-object element; D1 and D2 texts
//!   carry the shape.
//! - N7a refuses to rewrite (and never quotes) `http://user:pass@h/` and `user@h:1`; IPv6 literal
//!   `::1` and `[::1]:8080`; a name with a port above 99999 is left unchanged.
//! - N7d: `//evil.test/x` with a parent is not joined; a join keeps scheme, host and port.
//! - Note and refusal quotes are cut on a character boundary (a multi-byte string over 80 chars).
//! - `description`: judge shows the verdict shape, lead and child do not; child has the merged
//!   open/priority line; with tools lacking evidence/report_blocker/security_query none is named.
//! - A regression list of synthetic operations, one per failure class seen in logged missions
//!   (host:port host, URL host, method-prefixed URL, URL + trailing text, scheme-less service,
//!   relative endpoint, `hypothesis:{statement,status,priority:"high",evidence}`, `ops`/`items`,
//!   `hypothesis` as id, missing counterevidence, `verdict` + `confirmed`, flat credential with
//!   `username`, evidence outside the wrapper, string conditions, kind `container_running`,
//!   `claim_update` as an action), each asserting success or its specific refusal. No real
//!   session data in the repository.
//! - `#[ignore]` test `replay_logged_operations`: reads the JSON file named by the environment
//!   variable `LOOM_SECURITY_REPLAY` (an array of `{"standing":"lead"|"child"|"judge",
//!   "tools":[…], "operation":{…}}`), runs `read` against an empty `SecurityState`, then for every
//!   decoded `AssetUpsert` (top level or in a batch) `AssetInput::id()`; prints counts of: read ok,
//!   read ok with notes, each refusal kind (by the first 60 characters of the message with digits
//!   and backticked text masked), and asset locators the core still refuses. Skips when the
//!   variable is unset.

use loom_core::security_state::{SecurityOp, SecurityState};
use serde_json::Value;

/// What the session may do with hypotheses. Decides the early refusals and the tool description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Standing {
    /// No parent: opens hypotheses and sets their priority.
    Lead,
    /// A child that is not a judge.
    Child,
    /// A child with `read_only` and the `verdict` tool: may record verdicts.
    Judge,
}

/// The session facts the rules depend on.
pub(super) struct Caller<'a> {
    pub standing: Standing,
    /// The role's tool names (R1, R2 and the description).
    pub tools: &'a [String],
}

/// An operation as read, with one note per rewrite in the order applied.
#[derive(Debug)]
pub(super) struct Read {
    pub op: SecurityOp,
    pub notes: Vec<String>,
}

/// Every `SecurityOp` action, in the order of the enum.
pub(super) const ACTIONS: [&str; 19] = [
    "batch",
    "asset_upsert",
    "credential_add",
    "foothold_add",
    "condition_unlock",
    "blocked_on",
    "revisit_acknowledge",
    "coverage_set",
    "crash_record",
    "hypothesis_open",
    "hypothesis_priority",
    "hypothesis_evidence",
    "hypothesis_verdict",
    "relation_add",
    "fact_assert",
    "fact_retract",
    "rule_install",
    "rule_retract",
    "alias_add",
];

/// Read the tool's `operation` argument (see the module contract).
pub(super) fn read(caller: &Caller<'_>, state: &SecurityState, operation: &Value) -> Result<Read, String> {
    let _ = (caller, state, operation);
    todo!()
}

/// The exact one-line shape of `action`; `None` for an action that does not exist.
pub(super) fn shape(action: &str) -> Option<&'static str> {
    let _ = action;
    todo!()
}

/// The tool description for this caller.
pub(super) fn description(caller: &Caller<'_>) -> String {
    let _ = caller;
    todo!()
}
