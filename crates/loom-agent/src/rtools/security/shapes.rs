//! What `security_record` accepts: the exact shape of every operation, how a near miss is read, and
//! the guidance a refused operation gets.
//!
//! CONTRACT.
//!
//! Why: logged missions showed 42% of `security_record` calls refused, almost all for shape rather
//! than substance (a host given as `127.0.0.1:19727`, `ops` for
//! `operations`, a free-text blocked_on condition). Each refusal costs a model
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
//!    A nested batch element is
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
//!    - R4: `hypothesis_open`, `hypothesis_priority`, `hypothesis_evidence`, `hypothesis_verdict`,
//!      `rule_install` and `rule_retract` (the removed operations, checked first of all, so a batch
//!      element naming one is refused too) → P + `REMOVED_OP_REFUSAL`: "Hypotheses are not recorded in
//!      the security state any more: write the idea as a note (`note` with kind `decision`) or test
//!      it and record what the run showed."
//! 4. Normalization (N1–N7 below). Every rewrite appends exactly one note, in the order applied. A
//!    note names its location L ("the operation" or "operation {i} of the batch").
//! 5. Refusals that need the normalized value (R2, R6), same P and suffix.
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
//! - evidence/counterevidence: across operations and wrappers that take them (`asset`, `credential`,
//!   `foothold`, `relation`, `condition_unlock`, `coverage_set` when `status` is `tested`,
//!   `crash_record.attempt`, `fact_assert`), an omitted
//!   `evidence` or `counterevidence` defaults quietly to `[]`.
//! - N6 blocked_on / condition_unlock: see `normalize_conditions_action`; a `reason` given
//!   alongside `conditions` is dropped with a note.
//! - N7 asset_upsert locators (after N2; only when `asset.kind` and `asset.locator` are strings;
//!   the locator is trimmed first):
//!   - N7a kind host: a locator that is not an IP address and (i) contains
//!     `://` and parses as a URL with a host (a name such as `ftp:21` is not a URL: the URL parser
//!     would read it as an IPv4 address), or (ii) is `name:port` / `[v6]:port` with a decimal port of at most five
//!     digits, or otherwise carries a path or user information → the host (brackets removed), only when
//!     `canonical_locator(Host, host)` accepts it. Note: "In L, the host was recorded as `{host}`
//!     from `{given}`: a host locator has no scheme, port, path or credentials; record the
//!     service as kind service with an absolute URL." A value that holds user information is never quoted.
//!   - N7b kind service/endpoint: a leading token GET, POST, PUT, PATCH, DELETE, HEAD or OPTIONS
//!     (any case) followed by whitespace, when the rest starts with `{scheme}://` or with `/` → the
//!     rest. Note: "In L, the HTTP method `{METHOD}` was dropped from the locator: an endpoint is
//!     identified by its URL."
//!   - N7c kind service/endpoint: the locator holds whitespace and its first token parses as an
//!     absolute URL with a host and no user information → the first token. Note: "In L, the text
//!     after the URL was not recorded: `{rest}`; record it as a fact if it matters." The same applies
//!     when the first token is a path (starts with `/` but not `//`), with "the text after the path"
//!     in the note; N7d then joins that path.
//!   - N7d kind service/endpoint: the locator starts with `/` but not `//`. If `asset.parent` is a
//!     nonblank string, `state.resolve` resolves it to a recorded asset whose locator parses as an
//!     absolute URL with a host → `base.join(locator)`, accepted only when the joined URL keeps the
//!     base's scheme, host and port. Note: "In L, the path `{path}` was joined to its parent's URL as
//!     `{url}`." A parent that does not resolve → P + the resolve error + suffix. If `asset.parent` is
//!     absent or blank and `state.assets` contains exactly one asset whose locator parses as an
//!     absolute URL with a host, that asset is inferred as `parent` (unless the joined locator
//!     canonicalizes to that asset itself) and joined the same way. Note: "In L, `parent` was inferred
//!     as `{id}` and the path `{path}` was joined to its URL as `{url}`."
//!
//!   - N7e kind service/endpoint: the locator has no `://`, no whitespace and no `@`, and its part before
//!     the first `/` is `name:port` with a decimal port, or a bare name or IP (an IPv6 address bare or in
//!     brackets included) → the locator with `https://` in front when the port is 443 and `http://`
//!     otherwise (a bare IPv6 address is bracketed: `::1/x` gives `http://[::1]/x`), only when
//!     `canonical_locator` accepts the result. Note: "In L, `{given}` had no scheme, so it was recorded
//!     as `{repaired}`: https for port 443 and http otherwise; give tcp:// yourself for a service that
//!     is not HTTP."
//! - N8 batch spelling: an object with no `action` and an array under `ops`, `items` or `operations` is
//!   a batch. Note: "In the operation, no `action` was given; it holds a list of operations, so it was
//!   read as a batch."
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
//! - R6 kind service/endpoint, the locator starts with `/` and N7d did not apply (no parent, or a
//!   parent whose locator is not an absolute URL) → P + "An endpoint locator is one absolute URL,
//!   such as `http://10.0.0.5:8080/render?name=`; give the full URL, or name its service asset as
//!   `parent` and give only the path."
//!
//! ## `shape(action)` and `ACTIONS`
//!
//! `ACTIONS` lists the 13 `SecurityOp` actions that are still recorded, in the order of the enum. `shape` returns exactly:
//!
//! - asset_upsert: `{action:asset_upsert, asset:{kind:host|service|endpoint|file|identity, locator, evidence:[eN], mandatory?:true, parent?:assetID}}; a host locator is a bare name or IP such as 10.0.0.5; a service or endpoint locator is one absolute URL such as http://10.0.0.5:8080/login?next=, without a method or a description`
//! - coverage_set: `{action:coverage_set, asset:assetID, disposition:{status:tested, evidence:[eN]} or {status:deferred, reason}}`
//! - credential_add: `{action:credential_add, credential:{asset:assetID, principal, secret_handle:out handle of the stored secret, evidence:[eN], unlocks?:[condition], expires_ms?}}`
//! - foothold_add: `{action:foothold_add, foothold:{asset:assetID, principal, access, evidence:[eN], unlocks?:[condition], expires_ms?}}`
//! - condition_unlock: `{action:condition_unlock, conditions:[condition], evidence:[eN]}`
//! - blocked_on: `{action:blocked_on, target:ID, conditions:[condition]}`
//! - revisit_acknowledge: `{action:revisit_acknowledge, target:ID}`
//! - crash_record: `{action:crash_record, signature:{sanitizer, frames:[{function, file, line?}], outcome:crash}, attempt:{vector, summary, evidence:[eN]}}; only a real crash has a signature: record a timeout, an out-of-memory exit or a run without a crash as a fact with fact_assert`
//! - relation_add: `{action:relation_add, relation:{from:assetID, to:assetID, kind, cost:1-1000 (smaller is easier), evidence:[eN], expires_ms?}}`
//! - fact_assert: `{action:fact_assert, fact:{predicate, args:[string]}, evidence:[eN]}`
//! - fact_retract: `{action:fact_retract, id:factID, reason}`
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
//! 2. One line "- {shape(action)}" per action in ACTIONS order, with batch moved to the end.
//! 3. "A condition is {kind:auth|cred|role|leak|offset|key, value}: a typed prerequisite that a route
//!    waits on, not a description of a fault." + (when tools has report_blocker) " Report an
//!    unreachable target or a broken environment with report_blocker."
//! 4. "Evidence IDs (eN) must already exist and be attested" + (when tools has evidence) ": attach
//!    the output that shows it with the evidence tool first" + ". Evidence IDs are given exactly; other
//!    IDs (assets, parents, facts, and the asset in a cred or auth condition) may be
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
//! - Every refusal R1, R2 (string, unknown kind; with and without report_blocker in tools), R4 (every
//!   removed action, alone and inside a batch, refused before a shape error would be reported), R6 (no
//!   parent; parent that is a host); unknown action; non-object element; D1 and D2 texts
//!   carry the shape.
//! - N7a reduces `http://user:pass@h/` and `user@h:1` to `h` and never quotes the credentials; IPv6 literal
//!   `::1` and `[::1]:8080`; a name with a port above 99999 is left unchanged.
//! - N7d: `//evil.test/x` with a parent is not joined; a join keeps scheme, host and port.
//! - Note and refusal quotes are cut on a character boundary (a multi-byte string over 80 chars).
//! - N7a: `ftp:21` and `http:8080` give `ftp` and `http`; user information after the first URL (host,
//!   service and endpoint) is never rewritten or quoted. N7c/N7d: `GET /render?name= (text)` with a
//!   parent is joined without the text; `/\evil.test/x` with a parent is refused (R6). N7e: `::1`, `host:443`.
//! - `description`: with tools lacking evidence/report_blocker/security_query none is named.
//! - A regression list of synthetic operations, one per failure class seen in logged missions
//!   (host:port host, URL host, method-prefixed URL, URL + trailing text, scheme-less service,
//!   relative endpoint, `ops`/`items`/`ops` without an action,
//!   missing counterevidence, flat credential with
//!   `username`, evidence outside the wrapper, string conditions, kind `container_running`,
//!   `claim_update` as an action), each asserting success or its specific refusal. No real
//!   session data in the repository.
//! - `#[ignore]` test `replay_logged_operations`: reads the JSON file named by the environment
//!   variable `LOOM_SECURITY_REPLAY` (an array of `{"tools":[…], "operation":{…}}`), runs `read` against an empty `SecurityState`, then for every
//!   decoded `AssetUpsert` (top level or in a batch) `AssetInput::id()`; prints counts of: read ok,
//!   read ok with notes, each refusal kind (by the first 60 characters of the message with digits
//!   and backticked text masked), and asset locators the core still refuses. Skips when the
//!   variable is unset.

use loom_core::security_state::{
    canonical_locator, stable_id, AssetKind, SecurityOp, SecurityState, REMOVED_OP_REFUSAL,
};
use serde_json::{Map, Value};

/// The session facts the rules depend on.
pub(super) struct Caller<'a> {
    /// The role's tool names (R1, R2 and the description).
    pub tools: &'a [String],
}

/// An operation as read, with one note per rewrite in the order applied.
#[derive(Debug)]
pub(super) struct Read {
    pub op: SecurityOp,
    pub notes: Vec<String>,
}

/// Every `SecurityOp` action `security_record` offers, in the order of the enum.
pub(super) const ACTIONS: [&str; 13] = [
    "batch",
    "asset_upsert",
    "credential_add",
    "foothold_add",
    "condition_unlock",
    "blocked_on",
    "revisit_acknowledge",
    "coverage_set",
    "crash_record",
    "relation_add",
    "fact_assert",
    "fact_retract",
    "alias_add",
];

/// Actions that older logs hold and that are refused now (hypotheses and the rule engine).
pub(super) const REMOVED_ACTIONS: [&str; 6] = [
    "hypothesis_open",
    "hypothesis_priority",
    "hypothesis_evidence",
    "hypothesis_verdict",
    "rule_install",
    "rule_retract",
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
    // An object with `ops`, `items` or `operations` and no action is a batch.
    let implied = object.is_some_and(|o| {
        action.is_none() && ["ops", "items", "operations"].iter().any(|k| o.get(*k).is_some_and(Value::is_array))
    });
    let action = if implied { Some("batch") } else { action };
    let (Some(object), Some(action)) = (object, action) else {
        return Err(format!(
            "Correct `operation` before retrying: give an object with `action`, one of {}.{SUFFIX}",
            ACTIONS.join(", ")
        ));
    };
    if action != "batch" {
        let (op, notes) = read_one(caller, state, object, action, Loc::Single)?;
        return Ok(Read { op, notes });
    }
    let mut object = object.clone();
    let mut notes = Vec::new();
    if implied {
        object.insert("action".into(), Value::String("batch".into()));
        notes.push(
            "In the operation, no `action` was given; it holds a list of operations, so it was read as a batch.".into(),
        );
    }
    // `ops` or `items` stand for `operations` when it is absent, or present but empty.
    let operations_empty = object.get("operations").and_then(Value::as_array).is_some_and(Vec::is_empty);
    if operations_empty && object.get("ops").and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
        object.remove("operations");
    }
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
        let (op, more) = read_one(caller, state, element, action, loc)?;
        operations.push(op);
        notes.extend(more);
    }
    // The batch's own keys are checked by decoding it with no elements (deny_unknown_fields).
    object.insert("operations".into(), Value::Array(Vec::new()));
    decode(Value::Object(object), "batch", Loc::Single)?;
    Ok(Read { op: SecurityOp::Batch { operations }, notes })
}

/// Read one operation (steps 3 to 6). Returns the decoded op and its notes.
fn read_one(
    caller: &Caller<'_>,
    state: &SecurityState,
    object: &Map<String, Value>,
    action: &str,
    loc: Loc,
) -> Result<(SecurityOp, Vec<String>), String> {
    let p = loc.prefix(action);
    let shown = cut(action, QUOTE);
    if REMOVED_ACTIONS.contains(&action) {
        return Err(refuse(&p, REMOVED_OP_REFUSAL));
    }
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
    let l = loc.name();
    let mut m = object.clone();
    let mut notes = Vec::new();
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
            normalize_conditions_action(&mut m, action, &l, &p, caller, &mut notes)?;
        }
        _ => {}
    }
    default_omitted_evidence(&mut m, action);
    m.insert("action".into(), Value::String(action.to_string()));
    let op = decode(Value::Object(m), action, loc)?;
    Ok((op, notes))
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

fn ensure_array(m: &mut Map<String, Value>, key: &str) {
    if !m.contains_key(key) {
        m.insert(key.into(), Value::Array(Vec::new()));
    }
}

/// Default omitted `evidence` and `counterevidence` to `[]` across all actions/wrappers that take them.
fn default_omitted_evidence(m: &mut Map<String, Value>, action: &str) {
    match action {
        "asset_upsert" => {
            if let Some(Value::Object(w)) = m.get_mut("asset") {
                ensure_array(w, "evidence");
            }
        }
        "credential_add" => {
            if let Some(Value::Object(w)) = m.get_mut("credential") {
                ensure_array(w, "evidence");
            }
        }
        "foothold_add" => {
            if let Some(Value::Object(w)) = m.get_mut("foothold") {
                ensure_array(w, "evidence");
            }
        }
        "relation_add" => {
            if let Some(Value::Object(w)) = m.get_mut("relation") {
                ensure_array(w, "evidence");
            }
        }
        "condition_unlock" | "fact_assert" => ensure_array(m, "evidence"),
        "coverage_set" => {
            if let Some(Value::Object(d)) = m.get_mut("disposition") {
                if d.get("status").and_then(Value::as_str) == Some("tested") {
                    ensure_array(d, "evidence");
                }
            }
        }
        "crash_record" => {
            if let Some(Value::Object(a)) = m.get_mut("attempt") {
                ensure_array(a, "evidence");
            }
        }
        _ => {}
    }
}

/// Adopt `val` as `conditions` when it is an array or single condition object; otherwise check it with R2.
fn adopt_conditions(
    m: &mut Map<String, Value>,
    key: &str,
    val: Value,
    l: &str,
    p: &str,
    caller: &Caller<'_>,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    match val {
        Value::Array(_) => {
            m.insert("conditions".into(), val);
            notes.push(format!("In {l}, `{key}` was read as `conditions`."));
        }
        Value::Object(_) => {
            m.insert("conditions".into(), Value::Array(vec![val]));
            notes.push(format!("In {l}, `{key}` was read as `conditions`."));
        }
        other => {
            if let Some(given) = bad_condition(&Value::Array(vec![other])) {
                return Err(refuse(p, &condition_refusal(&given, caller)));
            }
        }
    }
    Ok(())
}

/// N6d and R2 for `condition_unlock` and `blocked_on`.
fn normalize_conditions_action(
    m: &mut Map<String, Value>,
    action: &str,
    l: &str,
    p: &str,
    caller: &Caller<'_>,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    if action == "blocked_on" {
        if !m.contains_key("target") {
            let mut candidates: Vec<&str> = ["asset", "endpoint", "service", "claim", "dead_end", "id"]
                .into_iter()
                .filter(|k| m.contains_key(*k))
                .collect();
            if m.contains_key("conditions") && m.get("blocked").is_some_and(Value::is_string) {
                candidates.push("blocked");
            }
            if candidates.len() == 1 {
                let key = candidates[0];
                if let Some(val) = m.remove(key) {
                    m.insert("target".into(), val);
                    notes.push(format!("In {l}, `{key}` was read as `target`."));
                }
            }
        }
        if !m.contains_key("conditions") {
            let has_cond = m.contains_key("condition");
            let has_blocked = m.contains_key("blocked");
            match (has_cond, has_blocked) {
                (true, false) => {
                    if let Some(val) = m.remove("condition") {
                        adopt_conditions(m, "condition", val, l, p, caller, notes)?;
                    }
                }
                (false, true) => {
                    if let Some(val) = m.remove("blocked") {
                        adopt_conditions(m, "blocked", val, l, p, caller, notes)?;
                    }
                }
                (false, false) => {
                    if let Some(reason) = m.get("reason") {
                        let check = if reason.is_array() { reason.clone() } else { Value::Array(vec![reason.clone()]) };
                        if let Some(given) = bad_condition(&check) {
                            return Err(refuse(p, &condition_refusal(&given, caller)));
                        }
                    }
                }
                (true, true) => {}
            }
        }
    } else if !m.contains_key("conditions") {
        let candidates: Vec<&str> =
            ["condition", "unlocked", "unlocks"].into_iter().filter(|k| m.contains_key(*k)).collect();
        if candidates.len() == 1 {
            let key = candidates[0];
            if let Some(val) = m.remove(key) {
                adopt_conditions(m, key, val, l, p, caller, notes)?;
            }
        }
    }
    if m.get("conditions").is_some_and(Value::is_object) {
        if let Some(obj) = m.remove("conditions") {
            m.insert("conditions".into(), Value::Array(vec![obj]));
            notes.push(format!("In {l}, `conditions` was wrapped in an array."));
        }
    }
    if let Some(given) = m.get("conditions").and_then(bad_condition) {
        return Err(refuse(p, &condition_refusal(&given, caller)));
    }
    if action == "blocked_on" && m.contains_key("conditions") && m.get("reason").is_some_and(Value::is_string) {
        m.remove("reason");
        notes.push(format!(
            "In {l}, `reason` was not recorded: blocked_on records only `target` and typed `conditions`."
        ));
    }
    Ok(())
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

/// Whether `s` holds URL user information (`user@` or `user:pass@`) anywhere: in the authority after any `://`,
/// or in a whitespace-separated token that parses as a URL with a user name or password.
fn has_userinfo(s: &str) -> bool {
    let after_scheme = s.match_indices("://").any(|(at, _)| {
        let rest = s.get(at.saturating_add(3)..).unwrap_or("");
        let authority = rest.split(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace()).next();
        authority.is_some_and(|a| a.contains('@'))
    });
    after_scheme
        || s.split_whitespace()
            .any(|token| url::Url::parse(token).is_ok_and(|u| !u.username().is_empty() || u.password().is_some()))
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

/// Join `path` to `base` only when `base` has a host and joining preserves scheme, host, and port.
fn join_same_origin(base: &url::Url, path: &str) -> Option<url::Url> {
    if !base.has_host() {
        return None;
    }
    let joined = base.join(path).ok()?;
    (base.scheme() == joined.scheme()
        && base.host() == joined.host()
        && base.port_or_known_default() == joined.port_or_known_default())
    .then_some(joined)
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
        "host" if loc.parse::<std::net::IpAddr>().is_err() => {
            if let Some(host) = reduce_host(&loc).filter(|h| canonical_locator(AssetKind::Host, h).is_ok()) {
                notes.push(format!(
                    "In {l}, the host was recorded as `{}` from {}: a host locator has no scheme, port, path or \
                     credentials; record the service as kind service with an absolute URL.",
                    cut(&host, QUOTE),
                    shown(&given)
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
                let explicit_parent = match asset.get("parent") {
                    Some(Value::String(parent)) if !parent.trim().is_empty() => Some(Some(parent.as_str())),
                    None | Some(Value::Null) => None,
                    Some(Value::String(_)) => None,
                    Some(_) => Some(None),
                };
                match explicit_parent {
                    Some(Some(parent)) => {
                        let id = state.resolve(parent).map_err(|e| refuse(p, &e))?;
                        let base = state.assets.get(&id).and_then(|a| url::Url::parse(&a.locator).ok());
                        if let Some(j) = base.as_ref().and_then(|b| join_same_origin(b, &loc)) {
                            notes.push(format!(
                                "In {l}, the path `{}` was joined to its parent's URL as `{}`.",
                                cut(&loc, QUOTE),
                                cut(j.as_str(), QUOTE)
                            ));
                            loc = j.to_string();
                        }
                    }
                    None => {
                        let mut url_assets = state.assets.values().filter_map(|a| {
                            url::Url::parse(&a.locator).ok().filter(|u| u.has_host()).map(|u| (a.id.clone(), u))
                        });
                        if let Some((sole_id, base)) = url_assets.next().filter(|_| url_assets.next().is_none()) {
                            if let Some(j) = join_same_origin(&base, &loc) {
                                let kind_enum =
                                    if kind == "service" { AssetKind::Service } else { AssetKind::Endpoint };
                                let joined_id = canonical_locator(kind_enum, j.as_str())
                                    .ok()
                                    .map(|cl| stable_id("as", &[&format!("{kind_enum:?}"), &cl]));
                                if joined_id.as_deref() == Some(sole_id.as_str()) {
                                    asset.remove("parent");
                                    notes.push(format!(
                                        "In {l}, the path `{}` was joined to `{}` as `{}`.",
                                        cut(&loc, QUOTE),
                                        cut(&sole_id, QUOTE),
                                        cut(j.as_str(), QUOTE)
                                    ));
                                } else {
                                    asset.insert("parent".into(), Value::String(sole_id.clone()));
                                    notes.push(format!(
                                        "In {l}, `parent` was inferred as `{}` and the path `{}` was joined to its \
                                         URL as `{}`.",
                                        cut(&sole_id, QUOTE),
                                        cut(&loc, QUOTE),
                                        cut(j.as_str(), QUOTE)
                                    ));
                                }
                                loc = j.to_string();
                            }
                        }
                    }
                    Some(None) => {}
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
                // A bare IPv6 address is bracketed in a URL; port 443 reads as https, anything else as http.
                let tail = loc.get(head.len()..).unwrap_or("");
                let authority = if v6 { format!("[{head}]") } else { head.to_string() };
                let port = authority.rsplit_once(':').filter(|(h, _)| !v6 && !h.ends_with(':')).map(|(_, p)| p);
                let scheme = if port == Some("443") { "https" } else { "http" };
                let repaired = format!("{scheme}://{authority}{tail}");
                if canonical_locator(AssetKind::Service, &repaired).is_ok() {
                    notes.push(format!(
                        "In {l}, `{}` had no scheme, so it was recorded as `{}`: https for port 443 and http \
                         otherwise; give tcp:// yourself for a service that is not HTTP.",
                        cut(&loc, QUOTE),
                        cut(&repaired, QUOTE)
                    ));
                    loc = repaired;
                }
            }
        }
        _ => {}
    }
    if notes.len() > before {
        asset.insert("locator".into(), Value::String(loc));
    }
    Ok(())
}

/// What a note may quote of a given locator: never a value that holds user information.
fn shown(s: &str) -> String {
    if s.contains('@') {
        "a value with credentials, not shown".to_string()
    } else {
        format!("`{}`", cut(s, QUOTE))
    }
}

/// The host of a host locator that carries a scheme, port, path or credentials; `None` when it has none.
fn reduce_host(given: &str) -> Option<String> {
    let token = given.split_whitespace().next()?;
    let text = if token.contains("://") { token.to_string() } else { format!("tcp://{token}") };
    let url = url::Url::parse(&text).ok()?;
    let host = match url.host()? {
        url::Host::Domain(d) => d.to_string(),
        url::Host::Ipv4(a) => a.to_string(),
        url::Host::Ipv6(a) => a.to_string(),
    };
    (host != given).then_some(host)
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
        "relation_add" => "{action:relation_add, relation:{from:assetID, to:assetID, kind, cost:1-1000 (smaller is easier), evidence:[eN], expires_ms?}}",
        "fact_assert" => "{action:fact_assert, fact:{predicate, args:[string]}, evidence:[eN]}",
        "fact_retract" => "{action:fact_retract, id:factID, reason}",
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
        let line = format!("- {}", shape(action).unwrap_or(""));
        lines.push(line);
    }
    let mut condition =
        "A condition is {kind:auth|cred|role|leak|offset|key, value}: a typed prerequisite that a route \
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
        ". Evidence IDs are given exactly; other IDs (assets, parents, facts, and the asset in a \
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
    use serde_json::json;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }
    fn go_in(state: &SecurityState, tools: &[&str], op: Value) -> Result<Read, String> {
        let tools = names(tools);
        read(&Caller { tools: &tools }, state, &op)
    }
    fn go(tools: &[&str], op: Value) -> Result<Read, String> {
        go_in(&SecurityState::default(), tools, op)
    }
    fn lead(op: Value) -> Result<Read, String> {
        go(&["report_blocker", "evidence", "security_query"], op)
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
        assert_eq!(sorted.len(), 13);
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
            json!({"action": "relation_add", "from": "as-1", "to": "as-2", "kind": "reaches", "cost": 5,
                "evidence": ["e1"]}),
        ])));
        assert_eq!(r.notes, vec!["In operation 2 of the batch, the relation fields were moved into `relation`."]);
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
        let r =
            ok(lead(json!({"action": "asset_upsert", "asset": {"kind": "host", "locator": "h"}, "evidence": ["e1"]})));
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
    fn n7a_reduces_a_host_locator_to_the_host() {
        let host = |loc: &str| lead(asset("host", loc));
        for (given, want) in [
            ("127.0.0.1:19727", "127.0.0.1"),
            ("http://127.0.0.1:19750", "127.0.0.1"),
            ("https://Example.test/a/b?x=1", "example.test"),
            ("db.internal:5432", "db.internal"),
            ("[::1]:8080", "::1"),
            ("http://[::1]:8080/x", "::1"),
            ("  10.0.0.5:80 ", "10.0.0.5"),
            ("ftp:21", "ftp"),
            ("http:8080", "http"),
            ("https:443", "https"),
            ("ws:80", "ws"),
            ("x/y:80", "x"),
        ] {
            let r = ok(host(given));
            assert_eq!(locator_of(&r), want, "{given}");
            assert_eq!(
                r.notes,
                vec![format!(
                    "In the operation, the host was recorded as `{want}` from `{}`: a host locator has no scheme, \
                     port, path or credentials; record the service as kind service with an absolute URL.",
                    given.trim()
                )]
            );
        }
        for same in ["::1", "10.0.0.5", "example.test", "db:123456", "db:99999x"] {
            let r = ok(host(same));
            assert_eq!(locator_of(&r), same);
            assert!(r.notes.is_empty(), "{same}");
        }
        // Credentials are dropped with the rest and never quoted.
        for (secret, want) in [
            ("http://user:pass@h/", "h"),
            ("user@h:1", "h"),
            ("http://:pw@h", "h"),
            ("http://10.0.0.5/ http://admin:pw@10.0.0.5/", "10.0.0.5"),
            ("http://10.0.0.5/?next=http://admin:pw@x", "10.0.0.5"),
        ] {
            let r = ok(host(secret));
            assert_eq!(locator_of(&r), want, "{secret}");
            assert_eq!(r.notes.len(), 1);
            assert!(!r.notes[0].contains("pw") && !r.notes[0].contains("pass") && !r.notes[0].contains("admin"));
        }
    }

    #[test]
    fn n7_reads_service_and_endpoint_locators() {
        let r = ok(lead(asset("service", "POST http://127.0.0.1:19761/expense")));
        assert_eq!(locator_of(&r), "http://127.0.0.1:19761/expense");
        assert_eq!(
            r.notes,
            vec![
                "In the operation, the HTTP method `POST` was dropped from the locator: an endpoint is identified \
                  by its URL."
            ]
        );
        let e = err(lead(asset("endpoint", "get   /x")));
        assert!(e.starts_with("An endpoint locator is one absolute URL"), "{e}");
        let r = ok(lead(asset("service", "http://127.0.0.1:19752 acme-sso Flask/Werkzeug 3.1.9")));
        assert_eq!(locator_of(&r), "http://127.0.0.1:19752");
        assert_eq!(
            r.notes,
            vec![
                "In the operation, the text after the URL was not recorded: `acme-sso Flask/Werkzeug 3.1.9`; record \
                  it as a fact if it matters."
            ]
        );
        let r = ok(lead(asset("endpoint", "PUT https://h.test/a b c")));
        assert_eq!((locator_of(&r).as_str(), r.notes.len()), ("https://h.test/a", 2));
        // User information keeps the whole locator for the core to refuse.
        let r = ok(lead(asset("service", "POST http://u:p@h.test/a")));
        assert_eq!(locator_of(&r), "POST http://u:p@h.test/a");
        assert!(r.notes.is_empty());
        // User information anywhere in the locator is never rewritten and never quoted.
        for secret in [
            "http://10.0.0.5:8080/login (try http://admin:admin@10.0.0.5:8080/)",
            "http://10.0.0.5:8080 admin via http://admin:hunter2@10.0.0.5:8080/",
            "POST http://10.0.0.5:8080/a?next=http://u:p@x/",
        ] {
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
                vec![
                    "In the operation, the path `/render?name=` was joined to its parent's URL as \
                      `http://10.0.0.5:8080/render?name=`."
                ]
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
        // When exactly one URL asset exists and parent is absent, it inherits the sole service parent.
        let r = ok(go_in(&state, &[], batch(vec![asset("host", "h"), asset("endpoint", "/x")])));
        assert_eq!(element(&r, 1)["asset"]["locator"], "http://10.0.0.5:8080/x");
        assert_eq!(element(&r, 1)["asset"]["parent"], id);
        // In a batch with no service parent to inherit, the refusal carries the position.
        let e = err(go_in(&SecurityState::default(), &[], batch(vec![asset("host", "h"), asset("endpoint", "/x")])));
        assert!(e.starts_with("Operation 2 of 2 in the batch (asset_upsert): An endpoint locator"), "{e}");
    }

    #[test]
    fn r5_and_r6_refuse_a_locator_the_core_cannot_use() {
        for (loc, want) in [
            ("172.17.0.3:8080", "http://172.17.0.3:8080"),
            ("localhost", "http://localhost"),
            ("app.test:8080/login", "http://app.test:8080/login"),
            ("[::1]:80", "http://[::1]:80"),
            ("app.test:443", "https://app.test:443"),
        ] {
            let r = ok(lead(asset("service", loc)));
            assert_eq!(locator_of(&r), want, "{loc}");
            assert_eq!(r.notes.len(), 1, "{loc}");
            assert!(r.notes[0].contains("had no scheme"), "{}", r.notes[0]);
        }
        // A bare IPv6 address is bracketed in the repaired URL.
        for (loc, want) in [
            ("::1", "http://[::1]"),
            ("fe80::1", "http://[fe80::1]"),
            ("[::1]", "http://[::1]"),
            ("::1/x", "http://[::1]/x"),
        ] {
            assert_eq!(locator_of(&ok(lead(asset("endpoint", loc)))), want, "{loc}");
        }
        // Not a bare host: left for the core.
        for loc in ["a b", "x@y:80", "mailto:me", "http://h", "file:///x"] {
            assert!(lead(asset("service", loc)).is_ok(), "{loc}");
        }
        // R6: no parent, or a parent that is a host.
        let (state, id) = state_with("10.0.0.5", AssetKind::Host);
        let e = err(lead(asset("endpoint", "/render?name=")));
        assert!(
            e.contains("such as `http://10.0.0.5:8080/render?name=`") && e.ends_with("Nothing was recorded."),
            "{e}"
        );
        let e = err(go_in(
            &state,
            &[],
            json!({"action": "asset_upsert", "asset": {"kind": "endpoint", "locator": "/x", "parent": id}}),
        ));
        assert!(e.starts_with("An endpoint locator is one absolute URL"), "{e}");
    }

    #[test]
    fn r2_refuses_conditions_that_are_not_typed() {
        let tools_with = ["report_blocker"];
        let blocked = |conditions: Value, tools: &[&str]| {
            go(tools, json!({"action": "blocked_on", "target": "c1", "conditions": conditions}))
        };
        let head =
            "A condition is a typed prerequisite {kind, value} with kind auth, cred, role, leak, offset or key, \
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
        let e = err(go(&[], json!({"action": "condition_unlock", "conditions": ["x"], "evidence": []})));
        assert!(e.starts_with(head), "{e}");
        let e = err(lead(json!({"action": "credential_add", "credential": {"asset": "as-1", "principal": "p",
            "secret_handle": "out:abcdef01", "evidence": ["e1"], "unlocks": ["admin"]}})));
        assert!(e.contains("`admin` is not one."), "{e}");
        let e =
            err(lead(batch(vec![json!({"action": "foothold_add", "foothold": {"asset": "as-1", "principal": "p",
            "access": "a", "evidence": ["e1"], "unlocks": [{"kind": "root", "value": "v"}]}})])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (foothold_add): A condition is"), "{e}");
    }

    #[test]
    fn r1_names_a_separate_tool_and_unknown_actions_list_the_valid_ones() {
        let e = err(go(&["claim_update", "evidence"], json!({"action": "claim_update", "id": "c1"})));
        assert_eq!(
            e,
            "`claim_update` is a separate tool, not a security_record action; call it directly. Nothing was recorded."
        );
        let e = err(lead(json!({"action": "claim_update", "id": "c1"})));
        assert!(e.starts_with("Correct `operation` before retrying: `claim_update` is not a security_record action; use one of batch, asset_upsert,"), "{e}");
        assert!(e.ends_with("alias_add. Nothing was recorded."), "{e}");
        let e = err(go(&[], batch(vec![json!({"action": "evidence"})])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (evidence): Correct `operation`"), "{e}");
        let e = err(go(&["evidence"], batch(vec![json!({"action": "evidence"})])));
        assert!(e.starts_with("Operation 1 of 1 in the batch (evidence): `evidence` is a separate tool"), "{e}");
    }

    #[test]
    fn d1_and_d2_carry_the_shape_and_never_echo_a_string_value() {
        let e = err(lead(json!({"action": "relation_add", "relation": {"from": "as-1"}})));
        assert!(e.contains(&format!("relation_add takes {}", shape("relation_add").unwrap())), "{e}");
        let e = err(lead(json!({"action": "credential_add", "credential": {"asset": "as-1", "principal": "p",
            "secret_handle": "out:abcdef01", "evidence": ["e1"], "unlocks": "hunter2-the-password"}})));
        assert!(!e.contains("hunter2"), "{e}");
        assert!(e.contains("credential_add takes {action:credential_add"), "{e}");
        let e = err(lead(batch(vec![json!({"action": "fact_retract", "id": "ft-1", "reason": 5})])));
        assert!(
            e.starts_with("Operation 1 of 1 in the batch (fact_retract): correct it before retrying: invalid type"),
            "{e}"
        );
    }

    #[test]
    fn quotes_are_cut_on_character_boundaries() {
        let long: String = "é世".repeat(60);
        assert_eq!(long.chars().count(), 120);
        let cut_text: String = long.chars().take(80).collect();
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
    fn logged_failure_classes_succeed_or_refuse_specifically() {
        // host:port and URL hosts, method-prefixed and described service locators, scheme-less services.
        assert_eq!(locator_of(&ok(lead(asset("host", "127.0.0.1:19727")))), "127.0.0.1");
        assert_eq!(locator_of(&ok(lead(asset("host", "http://127.0.0.1:19750")))), "127.0.0.1");
        assert_eq!(
            locator_of(&ok(lead(asset("endpoint", "POST http://127.0.0.1:19761/expense")))),
            "http://127.0.0.1:19761/expense"
        );
        assert_eq!(
            locator_of(&ok(lead(asset("service", "http://127.0.0.1:19752 acme-sso Flask/Werkzeug 3.1.9")))),
            "http://127.0.0.1:19752"
        );
        let r = ok(lead(asset("service", "172.17.0.3:8080")));
        assert_eq!(locator_of(&r), "http://172.17.0.3:8080");
        assert_eq!(locator_of(&ok(lead(asset("service", "10.0.0.5:443")))), "https://10.0.0.5:443");
        assert!(
            err(lead(asset("endpoint", "GET /render?name="))).starts_with("An endpoint locator is one absolute URL")
        );
        // removed operations are refused, never read
        for a in ["hypothesis_open", "hypothesis_evidence", "hypothesis_verdict", "rule_install"] {
            assert!(err(lead(json!({"action": a, "text": "s"}))).starts_with("Hypotheses are not recorded"), "{a}");
        }
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
        assert!(
            err(lead(json!({"action": "blocked_on", "conditions": ["Target returns 502"]}))).contains("report_blocker")
        );
        assert!(err(lead(json!({"action": "blocked_on", "target": "c1",
            "conditions": [{"kind": "container_running", "value": "x"}]})))
        .contains("`container_running`"));
        assert!(err(lead(json!({"action": "claim_update", "id": "c1"}))).contains("not a security_record action"));
    }

    #[test]
    fn omitted_evidence_and_counterevidence_default_to_empty_arrays() {
        let cases = [
            json!({"action": "asset_upsert", "asset": {"kind": "host", "locator": "10.0.0.5"}}),
            json!({"action": "credential_add", "credential": {"asset": "as-1", "principal": "root", "secret_handle": "out:abcdef01"}}),
            json!({"action": "foothold_add", "foothold": {"asset": "as-1", "principal": "www", "access": "shell"}}),
            json!({"action": "relation_add", "relation": {"from": "as-1", "to": "as-2", "kind": "reaches", "cost": 1}}),
            json!({"action": "condition_unlock", "conditions": [{"kind": "cred", "value": "as-1"}]}),
            json!({"action": "coverage_set", "asset": "as-1", "disposition": {"status": "tested"}}),
            json!({"action": "crash_record", "signature": {"sanitizer": "asan", "frames": [{"function": "f", "file": "a.c"}], "outcome": "crash"}, "attempt": {"vector": "v", "summary": "s"}}),
            json!({"action": "fact_assert", "fact": {"predicate": "seen", "args": ["a"]}}),
        ];
        for op in cases {
            let r = ok(lead(op.clone()));
            assert!(r.notes.is_empty(), "{op}: {:?}", r.notes);
        }
        // Deferred coverage does not get an invalid `evidence` field injected.
        let r = ok(lead(
            json!({"action": "coverage_set", "asset": "as-1", "disposition": {"status": "deferred", "reason": "oob"}}),
        ));
        assert!(matches!(r.op, SecurityOp::CoverageSet { .. }));
    }

    #[test]
    fn n7d_sole_service_path_inheritance_infers_parent_only_when_unique() {
        let (mut state, service_id) = state_with("http://10.0.0.5:8080/app/", AssetKind::Service);
        // Adding a host does not introduce ambiguity since hosts do not parse as URLs.
        let host_id = stable_id("as", &["Host", "10.0.0.5"]);
        state.assets.insert(
            host_id.clone(),
            Asset {
                id: host_id,
                kind: AssetKind::Host,
                locator: "10.0.0.5".into(),
                evidence: vec!["e1".into()],
                mandatory: true,
                parent: None,
                coverage: CoverageDisposition::Untested,
                n: 2,
            },
        );
        // Absent and blank parents infer the sole service asset.
        for op in [
            json!({"action": "asset_upsert", "asset": {"kind": "endpoint", "locator": "/login", "evidence": ["e1"]}}),
            json!({"action": "asset_upsert", "asset": {"kind": "service", "locator": "GET /api/v1", "evidence": ["e1"], "parent": "  "}}),
        ] {
            let r = ok(go_in(&state, &[], op));
            let v = json_of(&r.op);
            assert_eq!(v["asset"]["parent"], service_id);
            assert!(v["asset"]["locator"].as_str().unwrap().starts_with("http://10.0.0.5:8080/"));
            assert!(r.notes.iter().any(|n| n.contains("`parent` was inferred as")), "{:?}", r.notes);
        }
        // Joining `/` to the sole service itself does not assign itself as parent.
        let r = ok(go_in(
            &state,
            &[],
            json!({"action": "asset_upsert", "asset": {"kind": "service", "locator": "/app/", "evidence": ["e1"], "parent": ""}}),
        ));
        let v = json_of(&r.op);
        assert_eq!(v["asset"]["locator"], "http://10.0.0.5:8080/app/");
        assert_eq!(v["asset"]["parent"], Value::Null);
        // Traversal out of origin still hits R6.
        let e = err(go_in(
            &state,
            &[],
            json!({"action": "asset_upsert", "asset": {"kind": "endpoint", "locator": "/\\evil.test/x", "evidence": ["e1"]}}),
        ));
        assert!(e.starts_with("An endpoint locator is one absolute URL"), "{e}");
        // Two URL assets -> ambiguous, keeps R6 error intact.
        let second_id = stable_id("as", &["Service", "http://10.0.0.5:9090/"]);
        state.assets.insert(
            second_id.clone(),
            Asset {
                id: second_id,
                kind: AssetKind::Service,
                locator: "http://10.0.0.5:9090/".into(),
                evidence: vec!["e1".into()],
                mandatory: true,
                parent: None,
                coverage: CoverageDisposition::Untested,
                n: 3,
            },
        );
        let e = err(go_in(&state, &[], asset("endpoint", "/login")));
        assert!(e.starts_with("An endpoint locator is one absolute URL"), "{e}");
    }

    #[test]
    fn blocked_on_and_condition_unlock_synonyms_preserve_r2() {
        for key in ["asset", "endpoint", "service", "claim", "dead_end", "id"] {
            let r = ok(lead(json!({
                "action": "blocked_on",
                key: "c1",
                "conditions": [{"kind": "cred", "value": "as-1"}]
            })));
            assert_eq!(json_of(&r.op)["target"], "c1");
            assert_eq!(r.notes, vec![format!("In the operation, `{key}` was read as `target`.")]);
        }
        // `blocked` as target when `conditions` is present.
        let r = ok(lead(json!({
            "action": "blocked_on",
            "blocked": "c1",
            "conditions": [{"kind": "auth", "value": "as-1"}]
        })));
        assert_eq!(json_of(&r.op)["target"], "c1");
        assert_eq!(r.notes, vec!["In the operation, `blocked` was read as `target`."]);
        // `blocked` as conditions array, and `condition` singular / single object.
        let r = ok(lead(json!({
            "action": "blocked_on",
            "target": "c1",
            "blocked": [{"kind": "cred", "value": "as-1"}]
        })));
        assert_eq!(json_of(&r.op)["conditions"][0]["kind"], "cred");
        let r = ok(lead(json!({
            "action": "blocked_on",
            "target": "c1",
            "condition": {"kind": "key", "value": "k1"}
        })));
        assert_eq!(json_of(&r.op)["conditions"][0]["kind"], "key");
        let r = ok(lead(json!({
            "action": "blocked_on",
            "target": "c1",
            "conditions": {"kind": "role", "value": "admin"},
            "reason": "needs admin role"
        })));
        assert_eq!(json_of(&r.op)["conditions"][0]["kind"], "role");
        assert_eq!(r.notes.len(), 2);
        // `condition_unlock` aliases.
        let r = ok(lead(json!({
            "action": "condition_unlock",
            "unlocked": {"kind": "leak", "value": "libc-base"},
            "evidence": ["e1"]
        })));
        assert_eq!(json_of(&r.op)["conditions"][0]["kind"], "leak");
        let r = ok(lead(json!({
            "action": "condition_unlock",
            "unlocks": [{"kind": "offset", "value": "0x10"}]
        })));
        assert_eq!(json_of(&r.op)["evidence"], json!([]));
        // R2 is never relaxed: prose `reason` or `blocked` when `conditions` is absent still refuses via R2.
        for op in [
            json!({"action": "blocked_on", "target": "c1", "reason": "Target returns 502"}),
            json!({"action": "blocked_on", "target": "c1", "blocked": "Target returns 502"}),
            json!({"action": "blocked_on", "target": "c1", "blocked": [{"kind": "container_running", "value": "x"}]}),
            json!({"action": "condition_unlock", "condition": "admin login works", "evidence": ["e1"]}),
        ] {
            let e = err(lead(op.clone()));
            assert!(e.starts_with("A condition is a typed prerequisite"), "{op}: {e}");
        }
        assert!(err(lead(json!({"action": "blocked_on", "target": "c1", "reason": "502"}))).contains("report_blocker"));
    }

    /// Replays logged operations (a JSON array of {"tools", "operation"}) named by the
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
            let tools: Vec<String> = entry["tools"]
                .as_array()
                .map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect())
                .unwrap_or_default();
            match read(&Caller { tools: &tools }, &state, &entry["operation"]) {
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
