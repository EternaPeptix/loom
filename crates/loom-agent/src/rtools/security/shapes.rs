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
//!    - `hypothesis_open` when `caller.standing != Lead` (a child, judges included) →
//!      P + "Only the mission lead may open a hypothesis; send the proposed hypothesis to the lead."
//!    - `hypothesis_priority` when `caller.standing != Lead` →
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
//! is never rewritten and never quoted; the core refuses it. It holds user information when the
//! authority after any `://` in it contains `@`, or when any whitespace-separated token parses as a URL
//! with a user name or password; that check runs before N7a (kind host) and N7b to N7d.
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
//!   - N4d: first, when the dropped status (N4c) reads as refuted (the N6c words "refuted",
//!     "disproved", "rejected", "false", "invalid", or a JSON false) and `evidence` is a nonempty array
//!     while `counterevidence` is empty or absent, `evidence` is moved into `counterevidence` (the status
//!     says the evidence counts against the hypothesis; attaching it as support would record the
//!     opposite). Note, after the N4c note: "In L, the status said the hypothesis is refuted, so its
//!     `evidence` was attached as counterevidence." Then: `evidence` or `counterevidence` present. For a
//!     single operation, when either is a
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
//!   - N7a kind host: a locator that is not an IP address, holds no user information, and (i) contains
//!     `://` and parses as a URL with a host (a name such as `ftp:21` is not a URL: the URL parser
//!     would read it as an IPv4 address), or (ii) is `name:port` / `[v6]:port` with a decimal port of at most five
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
//!     after the URL was not recorded: `{rest}`; record it as a fact if it matters." The same applies
//!     when the first token is a path (starts with `/` but not `//`), with "the text after the path"
//!     in the note; N7d then joins that path.
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
//!   the first `/` is `name:port` with a decimal port, or a bare name or IP (an IPv6 address bare or in
//!   brackets included) → P + "Give the scheme as well, for example `http://{locator}` (or
//!   `tcp://{locator}` for a service that is not HTTP)." A bare IPv6 address is bracketed in
//!   `{locator}` (`::1/x` gives `[::1]/x`).
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
//! - crash_record: `{action:crash_record, signature:{sanitizer, frames:[{function, file, line?}], outcome:crash}, attempt:{vector, summary, evidence:[eN]}}; only a real crash has a signature: record a timeout, an out-of-memory exit or a run without a crash as a fact with fact_assert`
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
//!    - Child and Judge (every standing but Lead): hypothesis_open and hypothesis_priority are replaced by
//!      the single line
//!      "- hypothesis_open, hypothesis_priority: the mission lead's; send a proposed hypothesis to the
//!      lead." (at hypothesis_open's position).
//!    - Lead and Child: hypothesis_verdict is "- hypothesis_verdict: recorded only by an independent
//!      read-only verifier; attach evidence with hypothesis_evidence and the hypothesis stays open
//!      until one reviews it."
//! 3. "A condition is {kind:auth|cred|role|leak|offset|key, value}: a typed prerequisite that a route
//!    waits on, not a description of a fault." + (when tools has report_blocker) " Report an
//!    unreachable target or a broken environment with report_blocker."
//! 4. "Evidence IDs (eN) must already exist and be attested" + (when tools has evidence) ": attach
//!    the output that shows it with the evidence tool first" + ". Evidence IDs are given exactly; other
//!    IDs (assets, parents, hypotheses, facts, rules, and the asset in a cred or auth condition) may be
//!    the exact ID, an alias, or a unique prefix of at least four characters" + (when tools has
//!    security_query) "; security_query lists them" + "." (Why: evidence IDs are matched exactly, and a
//!    cred or auth condition's asset is resolved by `security_record`, see security.rs.)
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
//! - N7a: `ftp:21` and `http:8080` give `ftp` and `http`; user information after the first URL (host,
//!   service and endpoint) is never rewritten or quoted. N7c/N7d: `GET /render?name= (text)` with a
//!   parent is joined without the text; `/\evil.test/x` with a parent is refused (R6). R5: `::1`.
//! - `description`: judge shows the verdict shape, lead and child do not; child and judge have the merged
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

use loom_core::security_state::{canonical_locator, stable_id, AssetKind, SecurityOp, SecurityState};
use serde_json::{json, Map, Value};

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


const SUFFIX: &str = " Nothing was recorded.";
const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const CONDITION_KINDS: [&str; 6] = ["auth", "cred", "role", "leak", "offset", "key"];
/// How much of a model-supplied string a note or refusal quotes back.
const QUOTE: usize = 80;

/// Where in the call an operation sits: names it in notes and prefixes its refusals.
#[derive(Clone, Copy)]
enum Loc {
    Single,
    Batch { i: usize, n: usize },
}

impl Loc {
    fn name(self) -> String {
        match self {
            Loc::Single => "the operation".to_string(),
            Loc::Batch { i, .. } => format!("operation {i} of the batch"),
        }
    }
    fn prefix(self, action: &str) -> String {
        match self {
            Loc::Single => String::new(),
            Loc::Batch { i, n } => format!("Operation {i} of {n} in the batch ({}): ", cut(action, QUOTE)),
        }
    }
}

/// `s` cut to `max` characters on a character boundary, with "…" appended when it was cut.
fn cut(s: &str, max: usize) -> String {
    let mut chars = s.chars();
    let head: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

fn refuse(p: &str, message: &str) -> String {
    format!("{p}{message}{SUFFIX}")
}

/// A serde error without any string value it would echo (a wrongly placed secret must not come back).
fn sanitize(error: &str) -> String {
    let mut text = error.to_string();
    if let Ok(re) = regex::Regex::new(r#"string "(?:[^"\\]|\\.)*""#) {
        text = re.replace_all(&text, "a string").into_owned();
    }
    if let Ok(re) = regex::Regex::new(r"unknown (variant|field) `([^`]*)`") {
        text = re
            .replace_all(&text, |c: &regex::Captures<'_>| {
                let kind = c.get(1).map_or("", |m| m.as_str());
                let name = c.get(2).map_or("", |m| m.as_str());
                format!("unknown {kind} `{}`", cut(name, 40))
            })
            .into_owned();
    }
    cut(&text, 400)
}

fn decode(value: Value, action: &str, loc: Loc) -> Result<SecurityOp, String> {
    serde_json::from_value::<SecurityOp>(value).map_err(|e| {
        let error = sanitize(&e.to_string());
        let error = error.trim_end_matches('.');
        let shape = shape(action).unwrap_or("");
        match loc {
            Loc::Single => format!("Correct `operation` before retrying: {error}. {action} takes {shape}.{SUFFIX}"),
            Loc::Batch { i, n } => format!(
                "Operation {i} of {n} in the batch ({}): correct it before retrying: {error}. \
                 {action} takes {shape}.{SUFFIX}",
                cut(action, QUOTE)
            ),
        }
    })
}

/// Read the tool's `operation` argument (see the module contract).
pub(super) fn read(caller: &Caller<'_>, state: &SecurityState, operation: &Value) -> Result<Read, String> {
    let object = operation.as_object();
    let action = object.and_then(|o| o.get("action")).and_then(Value::as_str);
    let (Some(object), Some(action)) = (object, action) else {
        return Err(format!(
            "Correct `operation` before retrying: give an object with `action`, one of {}.{SUFFIX}",
            ACTIONS.join(", ")
        ));
    };
    if action != "batch" {
        let (op, notes) = read_one(caller, state, object, action, Loc::Single, false)?;
        return Ok(Read { op, notes });
    }
    let mut object = object.clone();
    let mut notes = Vec::new();
    if !object.contains_key("operations") {
        let key = match (object.contains_key("ops"), object.contains_key("items")) {
            (true, false) => Some("ops"),
            (false, true) => Some("items"),
            _ => None,
        };
        if let Some((key, value)) = key.and_then(|k| object.remove(k).map(|v| (k, v))) {
            object.insert("operations".into(), value);
            notes.push(format!("In the batch, `{key}` was read as `operations`."));
        }
    }
    let items = match object.get("operations") {
        Some(Value::Array(items)) => items.clone(),
        _ => return decode(Value::Object(object), "batch", Loc::Single).map(|op| Read { op, notes }),
    };
    let n = items.len();
    let mut operations = Vec::with_capacity(n);
    for (index, item) in items.iter().enumerate() {
        let i = index.saturating_add(1);
        let loc = Loc::Batch { i, n };
        let element = item.as_object();
        let action = element.and_then(|o| o.get("action")).and_then(Value::as_str);
        let (Some(element), Some(action)) = (element, action) else {
            return Err(format!("Operation {i} of {n} in the batch: give an object with `action`.{SUFFIX}"));
        };
        if action == "batch" {
            operations.push(decode(item.clone(), action, loc)?);
            continue;
        }
        let (op, more) = read_one(caller, state, element, action, loc, true)?;
        operations.push(op);
        notes.extend(more);
    }
    // The batch's own keys are checked by decoding it with no elements (deny_unknown_fields).
    object.insert("operations".into(), Value::Array(Vec::new()));
    decode(Value::Object(object), "batch", Loc::Single)?;
    Ok(Read { op: SecurityOp::Batch { operations }, notes })
}

/// Read one operation (steps 3 to 6). Returns the decoded op (a batch when N4d expanded it) and its notes.
fn read_one(
    caller: &Caller<'_>,
    state: &SecurityState,
    object: &Map<String, Value>,
    action: &str,
    loc: Loc,
    in_batch: bool,
) -> Result<(SecurityOp, Vec<String>), String> {
    let p = loc.prefix(action);
    let shown = cut(action, QUOTE);
    if !ACTIONS.contains(&action) {
        if caller.tools.iter().any(|t| t == action) {
            let message = format!("`{shown}` is a separate tool, not a security_record action; call it directly.");
            return Err(refuse(&p, &message));
        }
        return Err(refuse(
            &p,
            &format!(
                "Correct `operation` before retrying: `{shown}` is not a security_record action; use one of {}.",
                ACTIONS.join(", ")
            ),
        ));
    }
    if action == "hypothesis_verdict" && caller.standing != Standing::Judge {
        return Err(refuse(
            &p,
            "Only an independent read-only verifier records a hypothesis verdict. Attach your evidence with \
             hypothesis_evidence {id, evidence}; the hypothesis stays open until a verifier reviews it.",
        ));
    }
    if action == "hypothesis_open" && caller.standing != Standing::Lead {
        return Err(refuse(
            &p,
            "Only the mission lead may open a hypothesis; send the proposed hypothesis to the lead.",
        ));
    }
    if action == "hypothesis_priority" && caller.standing != Standing::Lead {
        return Err(refuse(
            &p,
            "Only the hypothesis's original lead may change its priority; send the proposed change to that lead.",
        ));
    }
    let l = loc.name();
    let mut m = object.clone();
    let mut notes = Vec::new();
    let mut attach: Option<(Value, Value)> = None;
    match action {
        "asset_upsert" => {
            wrap(&mut m, "asset", &["kind", "locator", "evidence", "mandatory", "parent"], &l, &mut notes);
            locator(&mut m, state, &l, &p, &mut notes)?;
        }
        "credential_add" => {
            wrap(
                &mut m,
                "credential",
                &["asset", "principal", "secret_handle", "evidence", "unlocks", "expires_ms", "username", "user"],
                &l,
                &mut notes,
            );
            principal(&mut m, "credential", &l, &mut notes);
            unlocks(&m, "credential", caller, &p)?;
        }
        "foothold_add" => {
            wrap(
                &mut m,
                "foothold",
                &["asset", "principal", "access", "evidence", "unlocks", "expires_ms", "username", "user"],
                &l,
                &mut notes,
            );
            principal(&mut m, "foothold", &l, &mut notes);
            unlocks(&m, "foothold", caller, &p)?;
        }
        "relation_add" => {
            wrap(&mut m, "relation", &["from", "to", "kind", "cost", "evidence", "expires_ms"], &l, &mut notes);
        }
        "condition_unlock" | "blocked_on" => {
            if let Some(given) = m.get("conditions").and_then(bad_condition) {
                return Err(refuse(&p, &condition_refusal(&given, caller)));
            }
        }
        "hypothesis_open" => {
            attach = open(&mut m, &l, &p, in_batch, &mut notes)?;
        }
        "hypothesis_priority" => {
            rename_id(&mut m, &l, &mut notes);
            if m.contains_key("priority") {
                set_priority(&mut m, &l, &p, &mut notes)?;
            }
        }
        "hypothesis_evidence" | "hypothesis_verdict" => {
            rename_id(&mut m, &l, &mut notes);
            for key in ["evidence", "counterevidence"] {
                if !m.contains_key(key) {
                    m.insert(key.into(), Value::Array(Vec::new()));
                }
            }
            if action == "hypothesis_verdict" {
                verdict(&mut m, &l, &mut notes);
            }
        }
        _ => {}
    }
    m.insert("action".into(), Value::String(action.to_string()));
    let op = decode(Value::Object(m), action, loc)?;
    let Some((evidence, counterevidence)) = attach else { return Ok((op, notes)) };
    let id = match &op {
        SecurityOp::HypothesisOpen { text, .. } => stable_id("hy", &[text.trim()]),
        _ => return Ok((op, notes)),
    };
    let attached = json!({"action": "hypothesis_evidence", "id": id, "evidence": evidence,
        "counterevidence": counterevidence});
    let attached = decode(attached, "hypothesis_evidence", loc)?;
    Ok((SecurityOp::Batch { operations: vec![op, attached] }, notes))
}

/// N2: gather a wrapper operation's fields into its wrapper object, and `evidence` into the wrapper.
fn wrap(m: &mut Map<String, Value>, key: &str, inner: &[&str], l: &str, notes: &mut Vec<String>) {
    if !m.contains_key(key) && inner.iter().any(|f| m.contains_key(*f)) {
        let mut wrapper = Map::new();
        let keys: Vec<String> = m.keys().filter(|k| k.as_str() != "action").cloned().collect();
        for k in keys {
            if let Some(v) = m.remove(&k) {
                wrapper.insert(k, v);
            }
        }
        m.insert(key.into(), Value::Object(wrapper));
        notes.push(format!("In {l}, the {key} fields were moved into `{key}`."));
    }
    let open_wrapper = matches!(m.get(key), Some(Value::Object(w)) if !w.contains_key("evidence"));
    if open_wrapper {
        if let Some(evidence) = m.remove("evidence") {
            if let Some(Value::Object(wrapper)) = m.get_mut(key) {
                wrapper.insert("evidence".into(), evidence);
                notes.push(format!("In {l}, `evidence` was moved into `{key}`."));
            }
        }
    }
}

/// N3: `username` or `user` inside a credential or foothold means `principal`.
fn principal(m: &mut Map<String, Value>, key: &str, l: &str, notes: &mut Vec<String>) {
    let Some(Value::Object(wrapper)) = m.get_mut(key) else { return };
    if wrapper.contains_key("principal") {
        return;
    }
    for name in ["username", "user"] {
        if let Some(value) = wrapper.remove(name) {
            wrapper.insert("principal".into(), value);
            notes.push(format!("In {l}, `{name}` was read as `principal`."));
            return;
        }
    }
}

/// R2 for the `unlocks` of a credential or foothold.
fn unlocks(m: &Map<String, Value>, key: &str, caller: &Caller<'_>, p: &str) -> Result<(), String> {
    match m.get(key).and_then(|w| w.get("unlocks")).and_then(bad_condition) {
        Some(given) => Err(refuse(p, &condition_refusal(&given, caller))),
        None => Ok(()),
    }
}

/// The first element of a `conditions` array that is not a typed condition, as it is quoted back.
fn bad_condition(list: &Value) -> Option<String> {
    for element in list.as_array()? {
        let given = match element {
            Value::Object(o) => match o.get("kind").and_then(Value::as_str) {
                Some(kind) if CONDITION_KINDS.contains(&kind) => continue,
                Some(kind) => kind.to_string(),
                None => element.to_string(),
            },
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        return Some(cut(&given, QUOTE));
    }
    None
}

fn condition_refusal(given: &str, caller: &Caller<'_>) -> String {
    let more = if caller.tools.iter().any(|t| t == "report_blocker") {
        " To report that a target is unreachable or the environment is broken, use report_blocker."
    } else {
        ""
    };
    format!(
        "A condition is a typed prerequisite {{kind, value}} with kind auth, cred, role, leak, offset or key, for \
         example {{\"kind\": \"cred\", \"value\": \"<asset ID>\"}}; `{given}` is not one.{more}"
    )
}

/// N4 and N5 for hypothesis_open. Returns the evidence lists to attach by a second operation (N4d).
fn open(
    m: &mut Map<String, Value>,
    l: &str,
    p: &str,
    in_batch: bool,
    notes: &mut Vec<String>,
) -> Result<Option<(Value, Value)>, String> {
    if !m.contains_key("text") {
        if let Some(Value::Object(inner)) = m.get("hypothesis").cloned() {
            for (k, v) in inner {
                if !m.contains_key(&k) {
                    m.insert(k, v);
                }
            }
            m.remove("hypothesis");
            notes.push(format!("In {l}, the fields of `hypothesis` were read as the operation's own."));
        }
    }
    if !m.contains_key("text") {
        let key = if m.get("hypothesis").is_some_and(Value::is_string) { Some("hypothesis") } else { None };
        let key = key.or(if m.contains_key("statement") { Some("statement") } else { None });
        if let Some((key, value)) = key.and_then(|k| m.remove(k).map(|v| (k, v))) {
            m.insert("text".into(), value);
            notes.push(format!("In {l}, `{key}` was read as `text`."));
        }
    }
    let mut refuted = false;
    if let Some(status) = m.remove("status") {
        let given = match &status {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        refuted = verdict_word(&given) == Some("refuted");
        if given.trim().eq_ignore_ascii_case("open") {
            notes.push(format!("In {l}, `status` was dropped: a new hypothesis is always open."));
        } else {
            notes.push(format!(
                "In {l}, status `{}` was not recorded: a new hypothesis is open, and only an independent read-only \
                 verifier records a verdict.",
                cut(&given, QUOTE)
            ));
        }
    }
    // N4d: evidence given with the hypothesis.
    let mut attach = None;
    let mut refuse_id = None;
    let lists_ok = ["evidence", "counterevidence"].iter().all(|k| m.get(*k).is_none_or(Value::is_array));
    let present = m.contains_key("evidence") || m.contains_key("counterevidence");
    if present && lists_ok {
        let nonempty = ["evidence", "counterevidence"]
            .iter()
            .any(|k| m.get(*k).and_then(Value::as_array).is_some_and(|a| !a.is_empty()));
        let text = m.get("text").and_then(Value::as_str).map(|t| t.trim().to_string());
        // A refuted status says the evidence given counts against the hypothesis (N4d).
        let given_support = m.get("evidence").and_then(Value::as_array).is_some_and(|a| !a.is_empty());
        let given_counter = m.get("counterevidence").and_then(Value::as_array).is_some_and(|a| !a.is_empty());
        if refuted && given_support && !given_counter {
            if let Some(evidence) = m.remove("evidence") {
                m.insert("counterevidence".into(), evidence);
                m.insert("evidence".into(), Value::Array(Vec::new()));
                notes.push(format!(
                    "In {l}, the status said the hypothesis is refuted, so its `evidence` was attached as \
                     counterevidence."
                ));
            }
        }
        match (nonempty, text) {
            (false, _) => {
                m.remove("evidence");
                m.remove("counterevidence");
            }
            (true, Some(text)) if in_batch => refuse_id = Some(stable_id("hy", &[text.as_str()])),
            (true, Some(_)) => {
                let evidence = m.remove("evidence").unwrap_or_else(|| Value::Array(Vec::new()));
                let counter = m.remove("counterevidence").unwrap_or_else(|| Value::Array(Vec::new()));
                attach = Some((evidence, counter));
                notes.push(format!(
                    "In {l}, the evidence was attached by a hypothesis_evidence operation recorded in the same \
                     atomic append."
                ));
            }
            (true, None) => {}
        }
    }
    // N5.
    let bad_priority = if m.contains_key("priority") {
        set_priority(m, l, p, notes).err()
    } else {
        m.insert("priority".into(), json!(3));
        notes.push(format!("In {l}, no priority was given, so it is 3 (1 low to 5 high)."));
        None
    };
    if let Some(e) = bad_priority {
        return Err(e);
    }
    if let Some(id) = refuse_id {
        return Err(refuse(
            p,
            &format!(
                "A hypothesis opens without evidence. Put {{\"action\": \"hypothesis_evidence\", \"id\": \"{id}\", \
                 \"evidence\": […]}} after it in the batch; `{id}` is the ID of this text."
            ),
        ));
    }
    Ok(attach)
}

/// N5 on `m["priority"]`; R7 when it cannot be read.
fn set_priority(m: &mut Map<String, Value>, l: &str, p: &str, notes: &mut Vec<String>) -> Result<(), String> {
    let given = m.get("priority").cloned().unwrap_or(Value::Null);
    let read = match &given {
        Value::Number(n) => n.as_u64().filter(|v| *v <= 255).map(|v| (v, false)),
        Value::String(s) => {
            let t = s.trim().to_ascii_lowercase();
            match t.as_str() {
                "low" => Some((1, true)),
                "medium" | "normal" => Some((3, true)),
                "high" => Some((5, true)),
                digits if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                    digits.parse::<u8>().ok().map(|v| (u64::from(v), true))
                }
                _ => None,
            }
        }
        _ => None,
    };
    let Some((value, rewritten)) = read else {
        return Err(refuse(p, "Give priority as an integer from 1 (low) to 5 (high), or low, medium or high."));
    };
    if rewritten {
        let shown = given.as_str().map(|s| cut(s, QUOTE)).unwrap_or_default();
        notes.push(format!("In {l}, priority `{shown}` was read as {value}."));
        m.insert("priority".into(), json!(value));
    }
    Ok(())
}

/// N6a: `hypothesis` or `hypothesis_id` is the hypothesis `id`.
fn rename_id(m: &mut Map<String, Value>, l: &str, notes: &mut Vec<String>) {
    if m.contains_key("id") {
        return;
    }
    for name in ["hypothesis", "hypothesis_id"] {
        if m.get(name).is_some_and(Value::is_string) {
            if let Some(value) = m.remove(name) {
                m.insert("id".into(), value);
                notes.push(format!("In {l}, `{name}` was read as `id`."));
                return;
            }
        }
    }
}

/// The verdict a status word means (N6c): "supported" or "refuted".
fn verdict_word(word: &str) -> Option<&'static str> {
    match word.trim().to_ascii_lowercase().as_str() {
        "supported" | "confirmed" | "verified" | "true" | "accepted" | "valid" => Some("supported"),
        "refuted" | "disproved" | "rejected" | "false" | "invalid" => Some("refuted"),
        _ => None,
    }
}

/// N6b and N6c for hypothesis_verdict.
fn verdict(m: &mut Map<String, Value>, l: &str, notes: &mut Vec<String>) {
    if !m.contains_key("status") {
        if let Some(value) = m.remove("verdict") {
            m.insert("status".into(), value);
            notes.push(format!("In {l}, `verdict` was read as `status`."));
        }
    }
    let (given, status) = match m.get("status") {
        Some(Value::Bool(b)) => (b.to_string(), if *b { "supported" } else { "refuted" }),
        Some(Value::String(s)) => {
            let Some(status) = verdict_word(s) else { return };
            (s.clone(), status)
        }
        _ => return,
    };
    if given != status {
        notes.push(format!("In {l}, status `{}` was read as `{status}`.", cut(&given, QUOTE)));
    }
    m.insert("status".into(), Value::String(status.to_string()));
}

/// Whether `s` holds URL user information (`user@` or `user:pass@`) anywhere: in the authority after any `://`,
/// or in a whitespace-separated token that parses as a URL with a user name or password.
fn has_userinfo(s: &str) -> bool {
    let after_scheme = s.match_indices("://").any(|(at, _)| {
        let rest = s.get(at.saturating_add(3)..).unwrap_or("");
        let authority = rest.split(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace()).next();
        authority.is_some_and(|a| a.contains('@'))
    });
    after_scheme
        || s.split_whitespace().any(|token| {
            url::Url::parse(token).is_ok_and(|u| !u.username().is_empty() || u.password().is_some())
        })
}

/// The host of `s` when it is `name:port` or `[v6]:port` with a decimal port of at most five digits.
fn host_and_port(s: &str) -> Option<String> {
    let port_ok = |port: &str| !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = s.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        inner.parse::<std::net::Ipv6Addr>().ok()?;
        return port_ok(port).then(|| inner.to_string());
    }
    let (name, port) = s.split_once(':')?;
    let name_ok = !name.is_empty() && !name.chars().any(|c| c.is_whitespace() || matches!(c, '/' | '@' | ':'));
    (name_ok && port_ok(port)).then(|| name.to_string())
}

/// The host of an absolute URL that has one and no user information.
fn url_host(s: &str) -> Option<String> {
    let url = url::Url::parse(s).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    match url.host()? {
        url::Host::Domain(d) => Some(d.to_string()),
        url::Host::Ipv4(a) => Some(a.to_string()),
        url::Host::Ipv6(a) => Some(a.to_string()),
    }
}

/// Whether `s` starts with `scheme://`.
fn has_scheme(s: &str) -> bool {
    match s.split_once("://") {
        Some((scheme, _)) => {
            scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        None => false,
    }
}

/// N7 and R5/R6 for the locator of an asset_upsert's `asset`.
fn locator(
    m: &mut Map<String, Value>,
    state: &SecurityState,
    l: &str,
    p: &str,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    let Some(Value::Object(asset)) = m.get_mut("asset") else { return Ok(()) };
    let (Some(kind), Some(given)) = (
        asset.get("kind").and_then(Value::as_str).map(str::to_string),
        asset.get("locator").and_then(Value::as_str).map(|s| s.trim().to_string()),
    ) else {
        return Ok(());
    };
    let mut loc = given.clone();
    let before = notes.len();
    match kind.as_str() {
        "host" if loc.parse::<std::net::IpAddr>().is_err() && !has_userinfo(&loc) => {
            // A URL is read only with `://`: WHATWG parsing reads `ftp:21` as ftp://0.0.0.21/.
            let host = if loc.contains("://") { url_host(&loc) } else { None }.or_else(|| host_and_port(&loc));
            if let Some(host) = host.filter(|h| canonical_locator(AssetKind::Host, h).is_ok()) {
                notes.push(format!(
                    "In {l}, the host was recorded as `{}` from `{}`: a host locator has no scheme, port or \
                     path; record the service as kind service with an absolute URL.",
                    cut(&host, QUOTE),
                    cut(&given, QUOTE)
                ));
                loc = host;
            }
        }
        "service" | "endpoint" if !has_userinfo(&loc) => {
            if let Some((token, rest)) = loc.clone().split_once(char::is_whitespace) {
                let rest = rest.trim_start();
                if METHODS.contains(&token.to_ascii_uppercase().as_str()) && (has_scheme(rest) || rest.starts_with('/'))
                {
                    notes.push(format!(
                        "In {l}, the HTTP method `{}` was dropped from the locator: an endpoint is identified by \
                         its URL.",
                        token.to_ascii_uppercase()
                    ));
                    loc = rest.to_string();
                }
            }
            if let Some((first, rest)) = loc.clone().split_once(char::is_whitespace) {
                let path = first.starts_with('/') && !first.starts_with("//");
                if (first.contains("://") && url_host(first).is_some()) || path {
                    let what = if path { "path" } else { "URL" };
                    notes.push(format!(
                        "In {l}, the text after the {what} was not recorded: `{}`; record it as a fact if it \
                         matters.",
                        cut(rest.trim(), QUOTE)
                    ));
                    loc = first.to_string();
                }
            }
            if loc.starts_with('/') && !loc.starts_with("//") {
                let parent = asset.get("parent").and_then(Value::as_str);
                if let Some(parent) = parent {
                    let id = state.resolve(parent).map_err(|e| refuse(p, &e))?;
                    let base = state.assets.get(&id).and_then(|a| url::Url::parse(&a.locator).ok());
                    let joined = base.and_then(|b| b.join(&loc).ok().map(|j| (b, j)));
                    let same = |b: &url::Url, j: &url::Url| {
                        b.has_host()
                            && b.scheme() == j.scheme()
                            && b.host() == j.host()
                            && b.port_or_known_default() == j.port_or_known_default()
                    };
                    if let Some(j) = joined.filter(|(b, j)| same(b, j)).map(|(_, j)| j) {
                        notes.push(format!(
                            "In {l}, the path `{}` was joined to its parent's URL as `{}`.",
                            cut(&loc, QUOTE),
                            cut(j.as_str(), QUOTE)
                        ));
                        loc = j.to_string();
                    }
                }
            }
            if loc.starts_with('/') {
                return Err(refuse(
                    p,
                    "An endpoint locator is one absolute URL, such as `http://10.0.0.5:8080/render?name=`; give the \
                     full URL, or name its service asset as `parent` and give only the path.",
                ));
            }
            let head = loc.split('/').next().unwrap_or("");
            let plain = !loc.contains("://") && !loc.contains('@') && !loc.chars().any(char::is_whitespace);
            let v6 = head.parse::<std::net::Ipv6Addr>().is_ok();
            let bracketed = head
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .is_some_and(|h| h.parse::<std::net::Ipv6Addr>().is_ok());
            if plain && !head.is_empty() && (host_and_port_any(head) || bare_name(head) || v6 || bracketed) {
                // A bare IPv6 address is bracketed in a URL.
                let tail = loc.get(head.len()..).unwrap_or("");
                let shown = if v6 { cut(&format!("[{head}]{tail}"), QUOTE) } else { cut(&loc, QUOTE) };
                return Err(refuse(
                    p,
                    &format!(
                        "Give the scheme as well, for example `http://{shown}` (or `tcp://{shown}` for a service \
                         that is not HTTP)."
                    ),
                ));
            }
        }
        _ => {}
    }
    if notes.len() > before {
        asset.insert("locator".into(), Value::String(loc));
    }
    Ok(())
}

/// `name:port` or `[v6]:port` with any decimal port (R5).
fn host_and_port_any(s: &str) -> bool {
    let digits = |port: &str| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split_once("]:").is_some_and(|(_, port)| digits(port));
    }
    s.split_once(':').is_some_and(|(name, port)| bare_name(name) && digits(port))
}

/// A bare host name or IP address.
fn bare_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// The exact one-line shape of `action`; `None` for an action that does not exist.
pub(super) fn shape(action: &str) -> Option<&'static str> {
    Some(match action {
        "asset_upsert" => "{action:asset_upsert, asset:{kind:host|service|endpoint|file|identity, locator, evidence:[eN], mandatory?:true, parent?:assetID}}; a host locator is a bare name or IP such as 10.0.0.5; a service or endpoint locator is one absolute URL such as http://10.0.0.5:8080/login?next=, without a method or a description",
        "coverage_set" => "{action:coverage_set, asset:assetID, disposition:{status:tested, evidence:[eN]} or {status:deferred, reason}}",
        "credential_add" => "{action:credential_add, credential:{asset:assetID, principal, secret_handle:out handle of the stored secret, evidence:[eN], unlocks?:[condition], expires_ms?}}",
        "foothold_add" => "{action:foothold_add, foothold:{asset:assetID, principal, access, evidence:[eN], unlocks?:[condition], expires_ms?}}",
        "condition_unlock" => "{action:condition_unlock, conditions:[condition], evidence:[eN]}",
        "blocked_on" => "{action:blocked_on, target:ID, conditions:[condition]}",
        "revisit_acknowledge" => "{action:revisit_acknowledge, target:ID}",
        "crash_record" => "{action:crash_record, signature:{sanitizer, frames:[{function, file, line?}], outcome:crash}, attempt:{vector, summary, evidence:[eN]}}; only a real crash has a signature: record a timeout, an out-of-memory exit or a run without a crash as a fact with fact_assert",
        "hypothesis_open" => "{action:hypothesis_open, text, priority?:1 (low) to 5 (high), default 3}",
        "hypothesis_priority" => "{action:hypothesis_priority, id:hypothesisID, priority:1 (low) to 5 (high)}",
        "hypothesis_evidence" => "{action:hypothesis_evidence, id:hypothesisID, evidence:[eN], counterevidence?:[eN]}",
        "hypothesis_verdict" => "{action:hypothesis_verdict, id:hypothesisID, status:supported|refuted, note, evidence:[eN], counterevidence:[eN]}",
        "relation_add" => "{action:relation_add, relation:{from:assetID, to:assetID, kind, cost:1-1000 (smaller is easier), evidence:[eN], expires_ms?}}",
        "fact_assert" => "{action:fact_assert, fact:{predicate, args:[string]}, evidence:[eN]}",
        "fact_retract" => "{action:fact_retract, id:factID, reason}",
        "rule_install" => "{action:rule_install, rule:{name, head:{predicate, args:[?x]}, body:[{atom:{predicate, args:[?x]}, negated?:false}]}}",
        "rule_retract" => "{action:rule_retract, id:ruleID, reason}",
        "alias_add" => "{action:alias_add, alias, target:ID}",
        "batch" => "{action:batch, operations:[operation, …]}; atomic: when one operation is invalid nothing is recorded and the error names it",
        _ => return None,
    })
}

/// The tool description for this caller.
pub(super) fn description(caller: &Caller<'_>) -> String {
    let has = |tool: &str| caller.tools.iter().any(|t| t == tool);
    let mut lines = vec![
        "Record typed, evidence-linked security observations in the mission ledger. `operation` is one object: an \
         action and its fields."
            .to_string(),
    ];
    let mut order: Vec<&str> = ACTIONS.iter().copied().filter(|a| *a != "batch").collect();
    order.push("batch");
    for action in order {
        let line = match (action, caller.standing) {
            ("hypothesis_open", Standing::Child | Standing::Judge) => "- hypothesis_open, hypothesis_priority: the mission lead's; send a \
                 proposed hypothesis to the lead."
                .to_string(),
            ("hypothesis_priority", Standing::Child | Standing::Judge) => continue,
            ("hypothesis_verdict", Standing::Lead | Standing::Child) => "- hypothesis_verdict: recorded only by an \
                 independent read-only verifier; attach evidence with hypothesis_evidence and the hypothesis stays \
                 open until one reviews it."
                .to_string(),
            _ => format!("- {}", shape(action).unwrap_or("")),
        };
        lines.push(line);
    }
    let mut condition = "A condition is {kind:auth|cred|role|leak|offset|key, value}: a typed prerequisite that a route \
                         waits on, not a description of a fault."
        .to_string();
    if has("report_blocker") {
        condition.push_str(" Report an unreachable target or a broken environment with report_blocker.");
    }
    lines.push(condition);
    let mut evidence = "Evidence IDs (eN) must already exist and be attested".to_string();
    if has("evidence") {
        evidence.push_str(": attach the output that shows it with the evidence tool first");
    }
    evidence.push_str(
        ". Evidence IDs are given exactly; other IDs (assets, parents, hypotheses, facts, rules, and the asset in a \
         cred or auth condition) may be the exact ID, an alias, or a unique prefix of at least four characters",
    );
    if has("security_query") {
        evidence.push_str("; security_query lists them");
    }
    evidence.push('.');
    lines.push(evidence);
    lines.push(
        "Near-miss field names and locators are read where the meaning is unambiguous, and each such reading is \
         listed under `normalized` in the result. These records never authorize network access."
            .to_string(),
    );
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::security_state::{Asset, CoverageDisposition};

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }
    fn go_in(state: &SecurityState, standing: Standing, tools: &[&str], op: Value) -> Result<Read, String> {
        let tools = names(tools);
        read(&Caller { standing, tools: &tools }, state, &op)
    }
    fn go(standing: Standing, tools: &[&str], op: Value) -> Result<Read, String> {
        go_in(&SecurityState::default(), standing, tools, op)
    }
    fn lead(op: Value) -> Result<Read, String> {
        go(Standing::Lead, &["report_blocker", "evidence", "security_query"], op)
    }
    fn ok(r: Result<Read, String>) -> Read {
        r.unwrap_or_else(|e| panic!("refused: {e}"))
    }
    fn err(r: Result<Read, String>) -> String {
        match r {
            Ok(r) => panic!("accepted: {:?}", r.op),
            Err(e) => e,
        }
    }
    fn json_of(op: &SecurityOp) -> Value {
        serde_json::to_value(op).unwrap()
    }
    /// The operation `i` (0-based) of a batch read.
    fn element(read: &Read, i: usize) -> Value {
        match &read.op {
            SecurityOp::Batch { operations } => json_of(&operations[i]),
            other => panic!("not a batch: {other:?}"),
        }
    }
    fn batch(ops: Vec<Value>) -> Value {
        json!({"action": "batch", "operations": ops})
    }
    fn asset(kind: &str, locator: &str) -> Value {
        json!({"action": "asset_upsert", "asset": {"kind": kind, "locator": locator, "evidence": ["e1"]}})
    }
    fn locator_of(read: &Read) -> String {
        match &read.op {
            SecurityOp::AssetUpsert { asset } => asset.locator.clone(),
            other => panic!("not an asset: {other:?}"),
        }
    }
    fn state_with(locator: &str, kind: AssetKind) -> (SecurityState, String) {
        let id = stable_id("as", &[&format!("{kind:?}"), locator]);
        let mut state = SecurityState::default();
        state.assets.insert(
            id.clone(),
            Asset {
                id: id.clone(),
                kind,
                locator: locator.into(),
                evidence: vec!["e1".into()],
                mandatory: true,
                parent: None,
                coverage: CoverageDisposition::Untested,
                n: 1,
            },
        );
        (state, id)
    }

    #[test]
    fn shapes_cover_every_action_in_order() {
        for action in ACTIONS {
            assert!(shape(action).is_some_and(|s| s.starts_with(&format!("{{action:{action}"))), "{action}");
        }
        assert!(shape("claim_update").is_none());
        let mut sorted = ACTIONS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 19);
    }

    #[test]
    fn step_one_needs_an_object_with_an_action() {
        for bad in [json!("x"), json!({"text": "t"}), json!({"action": 4}), Value::Null] {
            let e = err(lead(bad));
            assert!(e.starts_with("Correct `operation` before retrying: give an object with `action`, one of batch,"));
            assert!(e.ends_with("Nothing was recorded."), "{e}");
        }
    }

    #[test]
    fn n1_renames_ops_and_items_and_names_the_location() {
        for key in ["ops", "items"] {
            let r = ok(lead(json!({"action": "batch", key: [asset("host", "10.0.0.5")]})));
            assert!(matches!(r.op, SecurityOp::Batch { ref operations } if operations.len() == 1));
            assert_eq!(r.notes, vec![format!("In the batch, `{key}` was read as `operations`.")]);
        }
        // Both given: nothing is guessed.
        let e = err(lead(json!({"action": "batch", "ops": [], "items": []})));
        assert!(e.contains("batch takes {action:batch") && e.contains("`operations`"), "{e}");
        // An unknown key on the batch itself is refused.
        let e = err(lead(json!({"action": "batch", "operations": [], "extra": 1})));
        assert!(e.contains("unknown field `extra`"), "{e}");
    }

    #[test]
    fn batch_elements_are_read_one_by_one_with_their_position() {
        let r = ok(lead(batch(vec![
            asset("host", "10.0.0.5"),
            json!({"action": "hypothesis_open", "statement": "x is injectable"}),
        ])));
        assert_eq!(
            r.notes,
            vec![
                "In operation 2 of the batch, `statement` was read as `text`.",
                "In operation 2 of the batch, no priority was given, so it is 3 (1 low to 5 high)."
            ]
        );
        let e = err(lead(batch(vec![asset("host", "10.0.0.5"), json!("oops")])));
        assert_eq!(e, "Operation 2 of 2 in the batch: give an object with `action`. Nothing was recorded.");
        let e = err(lead(batch(vec![asset("host", "10.0.0.5"), json!({"action": "claim_update"})])));
        assert!(e.starts_with("Operation 2 of 2 in the batch (claim_update): Correct `operation` before retrying:"));
        let e = err(lead(batch(vec![json!({"action": "alias_add", "alias": "a"})])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (alias_add): correct it before retrying: "), "{e}");
        assert!(e.contains("missing field `target`") && e.contains("alias_add takes {action:alias_add"), "{e}");
        // A nested batch is passed through for the core to refuse.
        let r = ok(lead(batch(vec![batch(vec![asset("host", "10.0.0.5")])])));
        assert!(matches!(&r.op, SecurityOp::Batch { operations } if matches!(operations[0], SecurityOp::Batch { .. })));
    }

    #[test]
    fn n2_moves_wrapper_fields_and_evidence() {
        let r = ok(lead(json!({"action": "asset_upsert", "kind": "host", "locator": "10.0.0.5", "evidence": ["e1"]})));
        assert_eq!(r.notes, vec!["In the operation, the asset fields were moved into `asset`."]);
        assert_eq!(locator_of(&r), "10.0.0.5");
        let r = ok(lead(json!({"action": "asset_upsert", "asset": {"kind": "host", "locator": "h"}, "evidence": ["e1"]})));
        assert_eq!(r.notes, vec!["In the operation, `evidence` was moved into `asset`."]);
        let r = ok(lead(json!({"action": "credential_add", "asset": "as-1", "principal": "root",
            "secret_handle": "out:abcdef01", "evidence": ["e1"]})));
        assert_eq!(r.notes, vec!["In the operation, the credential fields were moved into `credential`."]);
        let r = ok(lead(json!({"action": "foothold_add", "asset": "as-1", "user": "www", "access": "shell",
            "evidence": ["e1"]})));
        assert_eq!(
            r.notes,
            vec![
                "In the operation, the foothold fields were moved into `foothold`.",
                "In the operation, `user` was read as `principal`."
            ]
        );
        let r = ok(lead(json!({"action": "relation_add", "from": "as-1", "to": "as-2", "kind": "reaches",
            "cost": 5, "evidence": ["e1"]})));
        assert_eq!(r.notes, vec!["In the operation, the relation fields were moved into `relation`."]);
        // N3 inside a batch, with the credential wrapper and evidence outside it.
        let r = ok(lead(batch(vec![json!({"action": "credential_add", "evidence": ["e1"], "credential":
            {"asset": "as-1", "username": "root", "secret_handle": "out:abcdef01"}})])));
        assert_eq!(
            r.notes,
            vec![
                "In operation 1 of the batch, `evidence` was moved into `credential`.",
                "In operation 1 of the batch, `username` was read as `principal`."
            ]
        );
        assert_eq!(element(&r, 0)["credential"]["principal"], "root");
        // An unknown inner field is still refused with the shape.
        let e = err(lead(json!({"action": "relation_add", "from": "a", "to": "b", "colour": "red"})));
        assert!(e.contains("unknown field `colour`") && e.contains("relation_add takes {action:relation_add"), "{e}");
    }

    #[test]
    fn n4_reads_hypothesis_open_near_misses() {
        let r = ok(lead(json!({"action": "hypothesis_open", "hypothesis": {"statement": "s", "status": "verified",
            "priority": "high"}})));
        assert_eq!(
            r.notes,
            vec![
                "In the operation, the fields of `hypothesis` were read as the operation's own.",
                "In the operation, `statement` was read as `text`.",
                "In the operation, status `verified` was not recorded: a new hypothesis is open, and only an \
                 independent read-only verifier records a verdict.",
                "In the operation, priority `high` was read as 5."
            ]
        );
        assert_eq!(json_of(&r.op), json!({"action": "hypothesis_open", "text": "s", "priority": 5}));
        let r = ok(lead(json!({"action": "hypothesis_open", "hypothesis": "s", "status": "Open", "priority": 2})));
        assert_eq!(
            r.notes,
            vec![
                "In the operation, `hypothesis` was read as `text`.",
                "In the operation, `status` was dropped: a new hypothesis is always open."
            ]
        );
        let r = ok(lead(json!({"action": "hypothesis_open", "text": "s"})));
        assert_eq!(r.notes, vec!["In the operation, no priority was given, so it is 3 (1 low to 5 high)."]);
        assert_eq!(json_of(&r.op)["priority"], 3);
    }

    #[test]
    fn n4d_expands_a_single_open_with_evidence_into_one_atomic_batch() {
        let r = ok(lead(json!({"action": "hypothesis_open", "text": " s ", "priority": 4, "evidence": ["e1"],
            "counterevidence": []})));
        assert_eq!(
            r.notes,
            vec!["In the operation, the evidence was attached by a hypothesis_evidence operation recorded in the \
                  same atomic append."]
        );
        let id = stable_id("hy", &["s"]);
        assert_eq!(element(&r, 0), json!({"action": "hypothesis_open", "text": " s ", "priority": 4}));
        assert_eq!(
            element(&r, 1),
            json!({"action": "hypothesis_evidence", "id": id, "evidence": ["e1"], "counterevidence": []})
        );
        // Only counterevidence also expands; empty lists vanish silently.
        let r = ok(lead(json!({"action": "hypothesis_open", "text": "s", "priority": 4, "counterevidence": ["e2"]})));
        assert_eq!(element(&r, 1)["evidence"], json!([]));
        assert_eq!(element(&r, 1)["counterevidence"], json!(["e2"]));
        let r = ok(lead(json!({"action": "hypothesis_open", "text": "s", "priority": 4, "evidence": [],
            "counterevidence": []})));
        assert!(matches!(r.op, SecurityOp::HypothesisOpen { .. }));
        assert_eq!(r.notes, Vec::<String>::new());
        // The wrapper form of the logged near miss reads in one go.
        let r = ok(lead(json!({"hypothesis": {"statement": "s", "status": "verified", "priority": "high",
            "evidence": ["e1"]}, "action": "hypothesis_open"})));
        assert_eq!(r.notes.len(), 5, "{:?}", r.notes);
        assert_eq!(element(&r, 0)["priority"], 5);
    }

    #[test]
    fn n4d_reads_evidence_given_with_a_refuted_status_as_counterevidence() {
        let id = stable_id("hy", &["s"]);
        for status in [json!("refuted"), json!(" Disproved "), json!(false)] {
            let r = ok(lead(json!({"action": "hypothesis_open", "hypothesis": {"statement": "s", "status": status,
                "evidence": ["e5"]}})));
            assert_eq!(
                element(&r, 1),
                json!({"action": "hypothesis_evidence", "id": id, "evidence": [], "counterevidence": ["e5"]})
            );
            assert!(
                r.notes.contains(
                    &"In the operation, the status said the hypothesis is refuted, so its `evidence` was attached as \
                      counterevidence."
                        .to_string()
                ),
                "{:?}",
                r.notes
            );
        }
        // Evidence given on both sides is kept as given, and a supported status moves nothing.
        let r = ok(lead(json!({"action": "hypothesis_open", "text": "s", "status": "refuted", "evidence": ["e1"],
            "counterevidence": ["e2"]})));
        assert_eq!(element(&r, 1)["evidence"], json!(["e1"]));
        let r = ok(lead(json!({"action": "hypothesis_open", "text": "s", "status": "verified", "evidence": ["e1"]})));
        assert_eq!(element(&r, 1)["evidence"], json!(["e1"]));
    }

    #[test]
    fn r8_refuses_evidence_on_an_open_inside_a_batch() {
        let id = stable_id("hy", &["s"]);
        let e = err(lead(batch(vec![
            asset("host", "10.0.0.5"),
            json!({"action": "hypothesis_open", "text": " s", "priority": 3, "evidence": ["e1"]}),
        ])));
        assert_eq!(
            e,
            format!(
                "Operation 2 of 2 in the batch (hypothesis_open): A hypothesis opens without evidence. Put \
                 {{\"action\": \"hypothesis_evidence\", \"id\": \"{id}\", \"evidence\": […]}} after it in the batch; \
                 `{id}` is the ID of this text. Nothing was recorded."
            )
        );
        // Empty lists inside a batch are removed silently.
        let r = ok(lead(batch(vec![json!({"action": "hypothesis_open", "text": "s", "priority": 3,
            "evidence": [], "counterevidence": []})])));
        assert!(r.notes.is_empty());
    }

    #[test]
    fn n5_reads_priorities_and_r7_refuses_the_rest() {
        let prio = |v: Value| lead(json!({"action": "hypothesis_open", "text": "s", "priority": v}));
        for (given, want) in [(json!("low"), 1), (json!(" Medium "), 3), (json!("normal"), 3), (json!("HIGH"), 5),
            (json!("4"), 4), (json!("255"), 255)] {
            let r = ok(prio(given.clone()));
            assert_eq!(json_of(&r.op)["priority"], want);
            let shown = given.as_str().unwrap_or("");
            assert_eq!(r.notes, vec![format!("In the operation, priority `{shown}` was read as {want}.")]);
        }
        for kept in [json!(0), json!(7), json!(255)] {
            assert!(ok(prio(kept)).notes.is_empty());
        }
        for bad in [json!("urgent"), json!("256"), json!(256), json!(-1), json!(2.5), json!(null), json!(true), json!("")] {
            let e = err(prio(bad.clone()));
            assert_eq!(
                e,
                "Give priority as an integer from 1 (low) to 5 (high), or low, medium or high. Nothing was recorded.",
                "{bad}"
            );
        }
        let r = ok(lead(json!({"action": "hypothesis_priority", "hypothesis": "hy-1", "priority": "high"})));
        assert_eq!(
            r.notes,
            vec!["In the operation, `hypothesis` was read as `id`.", "In the operation, priority `high` was read as 5."]
        );
        let e = err(lead(json!({"action": "hypothesis_priority", "id": "hy-1", "priority": "soon"})));
        assert!(e.starts_with("Give priority as an integer"), "{e}");
    }

    #[test]
    fn n6_reads_evidence_and_verdict_near_misses() {
        let judge = |op: Value| go(Standing::Judge, &[], op);
        let r = ok(judge(json!({"action": "hypothesis_evidence", "hypothesis_id": "hy-1", "evidence": ["e1"]})));
        assert_eq!(r.notes, vec!["In the operation, `hypothesis_id` was read as `id`."]);
        assert_eq!(json_of(&r.op)["counterevidence"], json!([]));
        let r = ok(judge(json!({"action": "hypothesis_verdict", "id": "hy-1", "verdict": "supported", "note": "n"})));
        assert_eq!(r.notes, vec!["In the operation, `verdict` was read as `status`."]);
        let r = ok(judge(json!({"action": "hypothesis_verdict", "id": "hy-1", "status": "Confirmed", "note": "n",
            "evidence": ["e1"]})));
        assert_eq!(r.notes, vec!["In the operation, status `Confirmed` was read as `supported`."]);
        for (given, want) in [(json!("verified"), "supported"), (json!("true"), "supported"), (json!("accepted"), "supported"),
            (json!("valid"), "supported"), (json!("disproved"), "refuted"), (json!("rejected"), "refuted"),
            (json!("false"), "refuted"), (json!("invalid"), "refuted"), (json!(true), "supported"), (json!(false), "refuted")] {
            let r = ok(judge(json!({"action": "hypothesis_verdict", "id": "hy-1", "status": given, "note": "n"})));
            assert_eq!(json_of(&r.op)["status"], want);
            assert_eq!(r.notes.len(), 1, "{given}");
        }
        let e = err(judge(json!({"action": "hypothesis_verdict", "id": "hy-1", "status": "maybe", "note": "n"})));
        assert!(e.contains("unknown variant `maybe`") && e.contains("hypothesis_verdict takes"), "{e}");
    }

    #[test]
    fn n7a_reduces_a_host_locator_to_the_host() {
        let host = |loc: &str| lead(asset("host", loc));
        for (given, want) in [("127.0.0.1:19727", "127.0.0.1"), ("http://127.0.0.1:19750", "127.0.0.1"),
            ("https://Example.test/a/b?x=1", "example.test"), ("db.internal:5432", "db.internal"), ("[::1]:8080", "::1"),
            ("http://[::1]:8080/x", "::1"), ("  10.0.0.5:80 ", "10.0.0.5"), ("ftp:21", "ftp"), ("http:8080", "http"),
            ("https:443", "https"), ("ws:80", "ws")] {
            let r = ok(host(given));
            assert_eq!(locator_of(&r), want, "{given}");
            assert_eq!(
                r.notes,
                vec![format!(
                    "In the operation, the host was recorded as `{want}` from `{}`: a host locator has no scheme, \
                     port or path; record the service as kind service with an absolute URL.",
                    given.trim()
                )]
            );
        }
        for same in ["::1", "10.0.0.5", "example.test", "db:123456", "db:99999x", "x/y:80"] {
            let r = ok(host(same));
            assert_eq!(locator_of(&r), same);
            assert!(r.notes.is_empty(), "{same}");
        }
        // User information is never rewritten and never quoted; the core refuses it.
        for secret in ["http://user:pass@h/", "user@h:1", "http://:pw@h", "http://10.0.0.5/ http://admin:pw@10.0.0.5/",
            "http://10.0.0.5/?next=http://admin:pw@x"] {
            let r = ok(host(secret));
            assert_eq!(locator_of(&r), secret);
            assert!(r.notes.is_empty());
        }
    }

    #[test]
    fn n7_reads_service_and_endpoint_locators() {
        let r = ok(lead(asset("service", "POST http://127.0.0.1:19761/expense")));
        assert_eq!(locator_of(&r), "http://127.0.0.1:19761/expense");
        assert_eq!(
            r.notes,
            vec!["In the operation, the HTTP method `POST` was dropped from the locator: an endpoint is identified \
                  by its URL."]
        );
        let e = err(lead(asset("endpoint", "get   /x")));
        assert!(e.starts_with("An endpoint locator is one absolute URL"), "{e}");
        let r = ok(lead(asset("service", "http://127.0.0.1:19752 acme-sso Flask/Werkzeug 3.1.9")));
        assert_eq!(locator_of(&r), "http://127.0.0.1:19752");
        assert_eq!(
            r.notes,
            vec!["In the operation, the text after the URL was not recorded: `acme-sso Flask/Werkzeug 3.1.9`; record \
                  it as a fact if it matters."]
        );
        let r = ok(lead(asset("endpoint", "PUT https://h.test/a b c")));
        assert_eq!((locator_of(&r).as_str(), r.notes.len()), ("https://h.test/a", 2));
        // User information keeps the whole locator for the core to refuse.
        let r = ok(lead(asset("service", "POST http://u:p@h.test/a")));
        assert_eq!(locator_of(&r), "POST http://u:p@h.test/a");
        assert!(r.notes.is_empty());
        // User information anywhere in the locator is never rewritten and never quoted.
        for secret in ["http://10.0.0.5:8080/login (try http://admin:admin@10.0.0.5:8080/)",
            "http://10.0.0.5:8080 admin via http://admin:hunter2@10.0.0.5:8080/",
            "POST http://10.0.0.5:8080/a?next=http://u:p@x/"] {
            let r = ok(lead(asset("service", secret)));
            assert_eq!(locator_of(&r), secret);
            assert!(r.notes.is_empty(), "{secret}");
        }
        // A locator that is a URL already is untouched.
        assert!(ok(lead(asset("endpoint", "http://10.0.0.5:8080/login?next="))).notes.is_empty());
        assert!(ok(lead(asset("file", "/etc/passwd x"))).notes.is_empty());
    }

    #[test]
    fn n7d_joins_a_path_to_its_parent_and_nothing_else() {
        let (state, id) = state_with("http://10.0.0.5:8080/app/", AssetKind::Service);
        let with_parent = |loc: &str, parent: &str| {
            go_in(
                &state,
                Standing::Lead,
                &[],
                json!({"action": "asset_upsert", "asset": {"kind": "endpoint", "locator": loc, "evidence": ["e1"],
                    "parent": parent}}),
            )
        };
        for parent in [id.as_str(), &id[..12]] {
            let r = ok(with_parent("/render?name=", parent));
            assert_eq!(locator_of(&r), "http://10.0.0.5:8080/render?name=");
            assert_eq!(
                r.notes,
                vec!["In the operation, the path `/render?name=` was joined to its parent's URL as \
                      `http://10.0.0.5:8080/render?name=`."]
            );
        }
        let r = ok(with_parent("GET /a/../b", &id));
        assert_eq!(locator_of(&r), "http://10.0.0.5:8080/b");
        assert_eq!(r.notes.len(), 2);
        // A description after a path is cut, as it is after a URL, before the path is joined.
        let r = ok(with_parent("GET /render?name= (Jinja2 SSTI)", &id));
        assert_eq!(locator_of(&r), "http://10.0.0.5:8080/render?name=");
        assert_eq!(
            r.notes[1],
            "In the operation, the text after the path was not recorded: `(Jinja2 SSTI)`; record it as a fact if it \
             matters."
        );
        assert_eq!(r.notes.len(), 3);
        // A backslash is a slash in a special scheme, so this join would change the host: it is refused.
        for evil in ["/\\evil.test/x", "/\\\\evil.test/x"] {
            let e = err(with_parent(evil, &id));
            assert!(e.starts_with("An endpoint locator is one absolute URL"), "{evil}: {e}");
        }
        // A protocol-relative locator is never joined, so it cannot change the host.
        let e = err(with_parent("//evil.test/x", &id));
        assert!(e.starts_with("An endpoint locator is one absolute URL"), "{e}");
        // A parent that does not resolve names the resolve error.
        let e = err(with_parent("/x", "as-nonexistent"));
        assert_eq!(e, "No security record matches `as-nonexistent`; query the current records before choosing an ID. Nothing was recorded.");
        // In a batch the refusal carries the position.
        let e = err(go_in(&state, Standing::Lead, &[], batch(vec![asset("host", "h"), asset("endpoint", "/x")])));
        assert!(e.starts_with("Operation 2 of 2 in the batch (asset_upsert): An endpoint locator"), "{e}");
    }

    #[test]
    fn r5_and_r6_refuse_a_locator_the_core_cannot_use() {
        for (loc, shown) in [("172.17.0.3:8080", "172.17.0.3:8080"), ("localhost", "localhost"),
            ("app.test:8080/login", "app.test:8080/login"), ("[::1]:80", "[::1]:80")] {
            let e = err(lead(asset("service", loc)));
            assert_eq!(
                e,
                format!(
                    "Give the scheme as well, for example `http://{shown}` (or `tcp://{shown}` for a service that is \
                     not HTTP). Nothing was recorded."
                )
            );
        }
        // A bare IPv6 address needs a scheme, and the suggestion brackets it.
        for (loc, shown) in [("::1", "[::1]"), ("fe80::1", "[fe80::1]"), ("[::1]", "[::1]"), ("::1/x", "[::1]/x")] {
            let e = err(lead(asset("endpoint", loc)));
            assert_eq!(
                e,
                format!(
                    "Give the scheme as well, for example `http://{shown}` (or `tcp://{shown}` for a service that is \
                     not HTTP). Nothing was recorded."
                ),
                "{loc}"
            );
        }
        // Not a bare host: left for the core.
        for loc in ["a b", "x@y:80", "mailto:me", "http://h", "file:///x"] {
            assert!(lead(asset("service", loc)).is_ok(), "{loc}");
        }
        // R6: no parent, or a parent that is a host.
        let (state, id) = state_with("10.0.0.5", AssetKind::Host);
        let e = err(lead(asset("endpoint", "/render?name=")));
        assert!(e.contains("such as `http://10.0.0.5:8080/render?name=`") && e.ends_with("Nothing was recorded."), "{e}");
        let e = err(go_in(
            &state,
            Standing::Lead,
            &[],
            json!({"action": "asset_upsert", "asset": {"kind": "endpoint", "locator": "/x", "parent": id}}),
        ));
        assert!(e.starts_with("An endpoint locator is one absolute URL"), "{e}");
    }

    #[test]
    fn r2_refuses_conditions_that_are_not_typed() {
        let tools_with = ["report_blocker"];
        let blocked = |conditions: Value, tools: &[&str]| {
            go(Standing::Lead, tools, json!({"action": "blocked_on", "target": "c1", "conditions": conditions}))
        };
        let head = "A condition is a typed prerequisite {kind, value} with kind auth, cred, role, leak, offset or key, \
                    for example {\"kind\": \"cred\", \"value\": \"<asset ID>\"}; ";
        let more = " To report that a target is unreachable or the environment is broken, use report_blocker.";
        let e = err(blocked(json!(["Target returns 502"]), &tools_with));
        assert_eq!(e, format!("{head}`Target returns 502` is not one.{more} Nothing was recorded."));
        let e = err(blocked(json!([{"kind": "container_running", "value": "x"}]), &[]));
        assert_eq!(e, format!("{head}`container_running` is not one. Nothing was recorded."));
        let e = err(blocked(json!([{"value": "x"}]), &[]));
        assert!(e.contains("`{\"value\":\"x\"}` is not one."), "{e}");
        let e = err(blocked(json!([{"kind": "cred", "value": "x"}, 5]), &[]));
        assert!(e.contains("`5` is not one."), "{e}");
        assert!(blocked(json!([{"kind": "cred", "value": "x"}]), &[]).is_ok());
        let e = err(go(Standing::Lead, &[], json!({"action": "condition_unlock", "conditions": ["x"], "evidence": []})));
        assert!(e.starts_with(head), "{e}");
        let e = err(lead(json!({"action": "credential_add", "credential": {"asset": "as-1", "principal": "p",
            "secret_handle": "out:abcdef01", "evidence": ["e1"], "unlocks": ["admin"]}})));
        assert!(e.contains("`admin` is not one."), "{e}");
        let e = err(lead(batch(vec![json!({"action": "foothold_add", "foothold": {"asset": "as-1", "principal": "p",
            "access": "a", "evidence": ["e1"], "unlocks": [{"kind": "root", "value": "v"}]}})])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (foothold_add): A condition is"), "{e}");
    }

    #[test]
    fn early_refusals_come_before_any_shape_check() {
        let verdict_without_anything = json!({"action": "hypothesis_verdict", "verdict": "confirmed"});
        for standing in [Standing::Lead, Standing::Child] {
            let e = err(go(standing, &[], verdict_without_anything.clone()));
            assert_eq!(
                e,
                "Only an independent read-only verifier records a hypothesis verdict. Attach your evidence with \
                 hypothesis_evidence {id, evidence}; the hypothesis stays open until a verifier reviews it. Nothing \
                 was recorded."
            );
        }
        assert!(go(Standing::Judge, &[], verdict_without_anything.clone()).is_err());
        let e = err(lead(batch(vec![verdict_without_anything])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (hypothesis_verdict): Only an independent"), "{e}");
        let e = err(go(Standing::Child, &[], json!({"action": "hypothesis_open"})));
        assert_eq!(
            e,
            "Only the mission lead may open a hypothesis; send the proposed hypothesis to the lead. Nothing was recorded."
        );
        let e = err(go(Standing::Child, &[], json!({"action": "hypothesis_priority"})));
        assert_eq!(
            e,
            "Only the hypothesis's original lead may change its priority; send the proposed change to that lead. \
             Nothing was recorded."
        );
        for action in ["hypothesis_open", "hypothesis_priority"] {
            let e = err(go(Standing::Judge, &[], json!({"action": action, "text": "t"})));
            assert!(e.starts_with("Only the "), "{action}: {e}");
        }
        assert!(go(Standing::Lead, &[], json!({"action": "hypothesis_open", "text": "t"})).is_ok());
    }

    #[test]
    fn r1_names_a_separate_tool_and_unknown_actions_list_the_valid_ones() {
        let e = err(go(Standing::Lead, &["claim_update", "evidence"], json!({"action": "claim_update", "id": "c1"})));
        assert_eq!(e, "`claim_update` is a separate tool, not a security_record action; call it directly. Nothing was recorded.");
        let e = err(lead(json!({"action": "claim_update", "id": "c1"})));
        assert!(e.starts_with("Correct `operation` before retrying: `claim_update` is not a security_record action; use one of batch, asset_upsert,"), "{e}");
        assert!(e.ends_with("alias_add. Nothing was recorded."), "{e}");
        let e = err(go(Standing::Lead, &[], batch(vec![json!({"action": "evidence"})])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (evidence): Correct `operation`"), "{e}");
        let e = err(go(Standing::Lead, &["evidence"], batch(vec![json!({"action": "evidence"})])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (evidence): `evidence` is a separate tool"), "{e}");
    }

    #[test]
    fn d1_and_d2_carry_the_shape_and_never_echo_a_string_value() {
        let e = err(lead(json!({"action": "hypothesis_open", "priority": 3})));
        assert_eq!(
            e,
            format!(
                "Correct `operation` before retrying: missing field `text`. hypothesis_open takes {}. Nothing was recorded.",
                shape("hypothesis_open").unwrap()
            )
        );
        let e = err(lead(json!({"action": "credential_add", "credential": {"asset": "as-1", "principal": "p",
            "secret_handle": "out:abcdef01", "evidence": ["e1"], "unlocks": "hunter2-the-password"}})));
        assert!(!e.contains("hunter2"), "{e}");
        assert!(e.contains("credential_add takes {action:credential_add"), "{e}");
        let e = err(lead(batch(vec![json!({"action": "fact_retract", "id": "ft-1", "reason": 5})])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (fact_retract): correct it before retrying: invalid type"), "{e}");
    }

    #[test]
    fn quotes_are_cut_on_character_boundaries() {
        let long: String = "é世".repeat(60);
        assert_eq!(long.chars().count(), 120);
        let cut_text: String = long.chars().take(80).collect();
        let r = ok(lead(json!({"action": "hypothesis_open", "text": "s", "status": long.clone()})));
        assert_eq!(r.notes.len(), 2);
        assert!(r.notes[0].contains(&format!("status `{cut_text}…` was not recorded")), "{}", r.notes[0]);
        let e = err(lead(json!({"action": long.clone()})));
        assert!(e.contains(&format!("`{cut_text}…` is not a security_record action")), "{e}");
        let r = ok(lead(asset("service", &format!("http://h.test/ {long}"))));
        assert!(r.notes[0].contains(&format!("`{cut_text}…`")), "{}", r.notes[0]);
        let e = err(lead(json!({"action": "blocked_on", "target": "c1", "conditions": [long.clone()]})));
        assert!(e.contains(&format!("`{cut_text}…` is not one")), "{e}");
        assert_eq!(cut("abc", 3), "abc");
        assert_eq!(cut("abcd", 3), "abc…");
    }

    #[test]
    fn descriptions_depend_only_on_the_caller() {
        let all = names(&["evidence", "report_blocker", "security_query"]);
        let d = |standing: Standing, tools: &[String]| description(&Caller { standing, tools });
        let judge = d(Standing::Judge, &all);
        let lead_d = d(Standing::Lead, &all);
        let child = d(Standing::Child, &all);
        assert!(judge.contains("- {action:hypothesis_verdict, id:hypothesisID, status:supported|refuted"));
        for text in [&lead_d, &child] {
            assert!(!text.contains("status:supported|refuted"));
            assert!(text.contains(
                "- hypothesis_verdict: recorded only by an independent read-only verifier; attach evidence with \
                 hypothesis_evidence and the hypothesis stays open until one reviews it."
            ));
        }
        assert!(lead_d.contains("- {action:hypothesis_open,") && lead_d.contains("- {action:hypothesis_priority,"));
        assert!(!child.contains("{action:hypothesis_open") && !child.contains("{action:hypothesis_priority"));
        // A judge is a child too: it never sees the lead's hypothesis shapes.
        assert!(!judge.contains("{action:hypothesis_open") && !judge.contains("{action:hypothesis_priority"));
        assert!(judge.contains("- hypothesis_open, hypothesis_priority: the mission lead's;"));
        assert!(!judge.contains("outcome:timeout") && !lead_d.contains("fuzzer_exit71"));
        assert!(lead_d.contains("outcome:crash}") && lead_d.contains("record a timeout, an out-of-memory exit"));
        assert!(child.contains(
            "- hypothesis_open, hypothesis_priority: the mission lead's; send a proposed hypothesis to the lead."
        ));
        assert!(lead_d.starts_with("Record typed, evidence-linked security observations in the mission ledger."));
        assert!(lead_d.contains("Report an unreachable target or a broken environment with report_blocker."));
        assert!(lead_d.contains(
            "Evidence IDs (eN) must already exist and be attested: attach the output that shows it with the evidence \
             tool first. Evidence IDs are given exactly; other IDs (assets, parents, hypotheses, facts, rules, and \
             the asset in a cred or auth condition) may be the exact ID, an alias, or a unique prefix of at least \
             four characters; security_query lists them."
        ));
        assert!(lead_d.ends_with("These records never authorize network access."));
        assert_eq!(lead_d, d(Standing::Lead, &all));
        let bare = d(Standing::Lead, &[]);
        assert!(!bare.contains("report_blocker") && !bare.contains("security_query") && !bare.contains("evidence tool"));
        assert!(bare.contains("Evidence IDs (eN) must already exist and be attested. Evidence IDs are given exactly;"));
        // The batch is the last action line, the shapes are listed in the enum order.
        let lines: Vec<&str> = lead_d.lines().collect();
        assert!(lines.iter().position(|l| l.starts_with("- {action:batch")).is_some_and(|i| i == lines.len() - 4));
        assert_eq!(lines.iter().filter(|l| l.starts_with("- ")).count(), 19);
        assert_eq!(child.lines().filter(|l| l.starts_with("- ")).count(), 18);
    }

    #[test]
    fn logged_failure_classes_succeed_or_refuse_specifically() {
        // host:port and URL hosts, method-prefixed and described service locators, scheme-less services.
        assert_eq!(locator_of(&ok(lead(asset("host", "127.0.0.1:19727")))), "127.0.0.1");
        assert_eq!(locator_of(&ok(lead(asset("host", "http://127.0.0.1:19750")))), "127.0.0.1");
        assert_eq!(locator_of(&ok(lead(asset("endpoint", "POST http://127.0.0.1:19761/expense")))), "http://127.0.0.1:19761/expense");
        assert_eq!(locator_of(&ok(lead(asset("service", "http://127.0.0.1:19752 acme-sso Flask/Werkzeug 3.1.9")))), "http://127.0.0.1:19752");
        assert!(err(lead(asset("service", "172.17.0.3:8080"))).starts_with("Give the scheme as well"));
        assert!(err(lead(asset("endpoint", "GET /render?name="))).starts_with("An endpoint locator is one absolute URL"));
        // hypotheses
        let r = ok(lead(json!({"action": "hypothesis_open", "hypothesis": {"statement": "s", "status": "verified",
            "priority": "high", "evidence": ["e1"]}})));
        assert!(matches!(&r.op, SecurityOp::Batch { operations } if operations.len() == 2));
        let r = ok(lead(json!({"action": "hypothesis_open", "text": "s"})));
        assert_eq!(json_of(&r.op)["priority"], 3);
        let r = ok(lead(json!({"action": "hypothesis_evidence", "hypothesis": "hy-1", "evidence": ["e1"]})));
        assert_eq!(json_of(&r.op)["counterevidence"], json!([]));
        assert!(err(lead(json!({"action": "hypothesis_verdict", "verdict": "supported"}))).starts_with("Only an independent"));
        assert!(err(lead(json!({"action": "hypothesis_verdict", "status": "confirmed"}))).starts_with("Only an independent"));
        // batch spellings
        assert!(ok(lead(json!({"action": "batch", "ops": [asset("host", "h")]}))).notes.len() == 1);
        assert!(ok(lead(json!({"action": "batch", "items": [asset("host", "h")]}))).notes.len() == 1);
        // credentials
        let r = ok(lead(json!({"action": "credential_add", "asset": "as-1", "principal": "root",
            "secret_handle": "out:abcdef01", "evidence": ["e1"]})));
        assert!(matches!(r.op, SecurityOp::CredentialAdd { .. }));
        let r = ok(lead(json!({"action": "credential_add", "credential": {"asset": "as-1", "username": "root",
            "secret_handle": "out:abcdef01"}, "evidence": ["e1"]})));
        assert_eq!(r.notes.len(), 2);
        // blocked_on
        assert!(err(lead(json!({"action": "blocked_on", "conditions": ["Target returns 502"]}))).contains("report_blocker"));
        assert!(err(lead(json!({"action": "blocked_on", "target": "c1",
            "conditions": [{"kind": "container_running", "value": "x"}]}))).contains("`container_running`"));
        assert!(err(lead(json!({"action": "claim_update", "id": "c1"}))).contains("not a security_record action"));
    }

    /// Replays logged operations (a JSON array of {"standing", "tools", "operation"}) named by the
    /// environment variable LOOM_SECURITY_REPLAY and prints how each was read.
    #[test]
    #[ignore = "reads the file named by LOOM_SECURITY_REPLAY"]
    fn replay_logged_operations() {
        let Ok(path) = std::env::var("LOOM_SECURITY_REPLAY") else { return };
        let text = std::fs::read_to_string(&path).unwrap();
        let entries: Vec<Value> = serde_json::from_str(&text).unwrap();
        let state = SecurityState::default();
        let (mut ok_count, mut with_notes) = (0usize, 0usize);
        let mut refusals: std::collections::BTreeMap<String, usize> = Default::default();
        let mut core_refused: std::collections::BTreeMap<String, usize> = Default::default();
        let mask = regex::Regex::new(r"`[^`]*`|\d").unwrap();
        for entry in &entries {
            let standing = match entry["standing"].as_str() {
                Some("child") => Standing::Child,
                Some("judge") => Standing::Judge,
                _ => Standing::Lead,
            };
            let tools: Vec<String> =
                entry["tools"].as_array().map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect()).unwrap_or_default();
            match read(&Caller { standing, tools: &tools }, &state, &entry["operation"]) {
                Ok(read) => {
                    ok_count += 1;
                    if !read.notes.is_empty() {
                        with_notes += 1;
                    }
                    let ops = match &read.op {
                        SecurityOp::Batch { operations } => operations.iter().collect::<Vec<_>>(),
                        one => vec![one],
                    };
                    for op in ops {
                        if let SecurityOp::AssetUpsert { asset } = op {
                            if let Err(e) = asset.id() {
                                *core_refused.entry(cut(&mask.replace_all(&e, "_"), 60)).or_default() += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    *refusals.entry(cut(&mask.replace_all(&e, "_"), 60)).or_default() += 1;
                }
            }
        }
        println!("read ok: {ok_count}\nread ok with notes: {with_notes}");
        for (kind, count) in &refusals {
            println!("refused {count:>5}  {kind}");
        }
        for (kind, count) in &core_refused {
            println!("core still refuses {count:>5}  {kind}");
        }
    }
}
