//! ferret-tools: running a tool call and turning what it produced into the record the model sees.
//!
//! The path from "the model asked for a call" to "a `tool_result` record" is [`execute`], and every
//! tool goes through it, so the rules of `docs/DESIGN.md` §2 (3, 11, 12) are applied in one place:
//!
//! 1. the tool is looked up, the arguments parsed and checked against the tool's schema — a call
//!    that fails here does not run, and the result says exactly what was wrong;
//! 2. the tool runs (a panic inside it becomes an error result);
//! 3. raw output is normalised without changing its line count, stored whole, and admitted — the
//!    result records which stored lines its text shows.
//!
//! No result's text may exceed what admission allows (DESIGN §2, principle 3): a result in the recent
//! region cannot be folded out of view, so one oversized result would make every later request
//! overflow. Views bound themselves with `ctx.view_chars` (see `view`, `outview`, `fstools`), and
//! [`finalize`] is the backstop, with
//! `budget = max(ctx.view_chars, admission.policy.view_chars(admission.estimator))` (`ctx` being the
//! context the call ran with: a call started early sized its view before the estimator was calibrated by
//! the reply that holds it, and is not cut for that):
//! - a `View` or `ProducedView` whose text is longer than `budget` characters keeps its text up to and
//!   including the last `\n` at or before character `budget` (cut on a character boundary at `budget`
//!   when there is none), followed by the line `[cut by harness: this view is {n} characters, more than
//!   one result may show ({budget}); the rest is not shown. Nothing was discarded: ask for fewer lines
//!   (start/end, or a narrower pattern) of {handle}.]` where `{handle}` is the `out:` handle of the
//!   viewed blob. Its `meta[META_SHOWN]` becomes `[]` (what a cut view showed is not claimed) and `cut`
//!   is true;
//! - a `Message` longer than `budget` characters is stored and admitted exactly as `Raw` of its UTF-8
//!   bytes would be (handle, line count, cut marker), so it is cut explicitly with a handle;
//! - anything within `budget` is unchanged, byte for byte.
//!
//! Step 1 goes through [`dialect::adapt`] (`docs/TOOL-SHAPES.md`): the call's name and arguments are
//! converted into ferret's internal shape first, its notes lead `notes`, and a refusal lists the tool's
//! parameters (and names them in its problem lines) as the session's `ToolsCfg::dialect` presents them.
//! `adapt` can answer without a tool (`think` -> an ok result "Noted.", returned as the `Err` record),
//! refuse, or return a batch: a Codex `apply_patch` over several files is several checked steps in one
//! [`Prepared`]. All steps are checked before any runs (one failure refuses all, naming each file),
//! then they run in order, stopping at the first that does not succeed; the one result joins the
//! steps' texts under `` `tool` path `` lines, its status is the worst step's, and a batch is never
//! started early ([`Prepared::speculative`]).
//!
//! The three steps are also public on their own ([`prepare`], [`Prepared::run`], [`Ran::finish`]), so
//! that a call of a [`Tool::speculative`] tool can run before its turn and be finished — stored and
//! admitted with the admission of that moment — only when the session claims it.
//!
//! Modules:
//! - [`schema`]  argument checking with unambiguous coercions
//! - [`sandbox`] the OS sandbox profile and the same policy for in-process file access
//! - [`proc`]    spawning a command in its own process group, with one merged output stream
//! - [`jobs`]    background jobs
//! - [`files`]   what a session has read, for refusing writes over unseen changes
//! - [`view`]    numbered line views of stored output
//! - [`outputs`] opening a stored output by handle, only among the outputs of the session's mission
//! - [`workcopy`] a child's own copy of the workspace, and bringing one child's changes back
//! - [`boxctl`], [`boxfs`] the remote Docker box: container life, egress, files in and out
//! - [`bash`], [`fstools`], [`search`], [`outview`], [`web`]: the built-in tools
//! - [`cve`]: the vulnerability-database lookups; [`depscan`]: the OWASP dep-scan wrapper

pub mod bash;
pub mod binary;
pub mod boxctl;
pub mod boxfs;
pub mod capabilities;
pub mod codec;
pub mod cve;
pub mod depscan;
pub mod dialect;
pub mod files;
pub mod fstools;
pub mod http;
pub mod jobs;
pub mod mail;
pub mod mcp;
pub mod oast;
pub mod oracle;
pub mod outputs;
pub mod outview;
pub mod params;
pub mod proc;
pub mod procinfo;
pub mod pty;
pub mod sandbox;
pub mod schema;
pub mod search;
pub mod traffic;
pub mod view;
pub mod web;
pub mod workcopy;

use async_trait::async_trait;
use ferret_core::admit::{admit, envelope_plain, normalize, AdmitPolicy, Facts};
use ferret_core::config::ToolsCfg;
use ferret_core::estimate::TokenEstimator;
use ferret_core::event::{
    ToolClass, ToolResult, ToolSpec, ToolStatus, META_OF_BLOB, META_RAW_BLOB, META_REPAIRED, META_SHOWN,
};
use ferret_core::{BlobId, BlobStore, CallId, SessionId};
use futures_util::FutureExt;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Everything a tool may use while it runs one call.
#[derive(Clone)]
pub struct ToolCtx {
    pub session: SessionId,
    pub call_id: CallId,
    /// Working directory for commands and the base for relative paths. Canonical.
    pub workspace: PathBuf,
    /// The session's scratch directory. Canonical.
    pub tmp_dir: PathBuf,
    pub blobs: BlobStore,
    /// Which stored outputs this session may open (`outputs::open`).
    pub outputs: Arc<dyn outputs::OutputScope>,
    pub cfg: Arc<ToolsCfg>,
    pub sandbox: Arc<sandbox::Sandbox>,
    /// Environment variables added to every command (proxy settings and the like).
    pub env: Arc<BTreeMap<String, String>>,
    /// Reference-only proxy capability, deliberately absent from subprocess environments.
    pub reference_proxy: Option<ferret_net::ReferenceGrant>,
    pub files: Arc<files::FileTracker>,
    pub jobs: Arc<jobs::JobTable>,
    pub cancel: CancellationToken,
    /// Session-local PTY/HTTP state. Cloned contexts share it; children start with fresh state.
    pub capabilities: Arc<capabilities::SessionTools>,
    /// The most characters the text of a view (`read`, `out_read`, `out_grep`, other numbered views)
    /// may hold: `AdmitPolicy::view_chars` of the session's admission when the call was started.
    pub view_chars: usize,
    /// The session's shell directory: where `bash` runs when it is given no `cwd`. Clones of the context
    /// share it; a child agent or fork starts with its own, empty one.
    pub shell: Arc<bash::ShellState>,
}

/// Reserved meta key: the exchanges a tool made itself (`Vec<ferret_core::event::Exchange>`). `finalize` moves
/// them to `ToolResult::exchanges`; they never reach the record's meta.
pub const META_EXCHANGES: &str = "\u{0}exchanges";

/// Reserved `ToolOutput::meta` key that carries a tool's images to `finalize`; never written to a record.
pub const META_IMAGES: &str = "\u{0}images";

/// Meta `complete`: `false` when the result did not cover everything it was asked about; absent otherwise.
pub const META_COMPLETE: &str = "complete";
/// Meta `limits`: the short words (`cut`, `timeout`, `idle stop`, `output limit`, `net denied`,
/// `unreadable skipped`, `search cap`, `child incomplete`) that say how. A tool may put its own words here;
/// [`finalize`] adds the ones it can tell from the result and sets `complete`.
pub const META_LIMITS: &str = "limits";
/// Meta `net_denied`: how many proxy connections were denied during a `bash`/`box_exec` call.
pub const META_NET_DENIED: &str = "net_denied";

/// Add `word` to the `limits` of `meta` (once) and mark the result `complete: false`.
pub fn add_limit(meta: &mut Map<String, Value>, word: &str) {
    let mut list: Vec<Value> = match meta.remove(META_LIMITS) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    if !list.iter().any(|v| v.as_str() == Some(word)) {
        list.push(json!(word));
    }
    meta.insert(META_LIMITS.into(), Value::Array(list));
    meta.insert(META_COMPLETE.into(), json!(false));
}

/// The limits recorded in a result's meta.
pub fn limits_of(meta: &Map<String, Value>) -> Vec<String> {
    match meta.get(META_LIMITS) {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    }
}

/// What a tool hands back.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolOutput {
    pub status: ToolStatus,
    /// The outcome in a few words (`exit 0`, `ok`, `error`, …). Shown first and last.
    pub outcome: String,
    /// Further header facts, in order.
    pub more: Vec<String>,
    pub body: Body,
    /// Tool-specific facts for the record (`META_*` keys).
    pub meta: Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    /// Bytes the tool produced. They are normalised, stored whole and admitted.
    Raw(Vec<u8>),
    /// Lines of an output that is already stored: the text to show and exactly which of its lines
    /// that text contains (1-based, inclusive).
    View { of: BlobId, text: String, shown: Vec<(u64, u64)> },
    /// A newly produced complete normalized output, with only these numbered lines displayed.
    /// Unlike View, this records the producing tool and retains the complete output as its own blob.
    ProducedView { blob: ferret_core::BlobRef, text: String, shown: Vec<(u64, u64)> },
    /// A short message with nothing behind it (a refusal, a confirmation).
    Message(String),
}

impl ToolOutput {
    pub fn ok(outcome: impl Into<String>, body: Body) -> ToolOutput {
        ToolOutput { status: ToolStatus::Ok, outcome: outcome.into(), more: Vec::new(), body, meta: Map::new() }
    }

    /// An error with a message that tells the model what to do next.
    pub fn error(message: impl Into<String>) -> ToolOutput {
        ToolOutput {
            status: ToolStatus::Error,
            outcome: "error".into(),
            more: Vec::new(),
            body: Body::Message(message.into()),
            meta: Map::new(),
        }
    }

    pub fn denied(message: impl Into<String>) -> ToolOutput {
        ToolOutput {
            status: ToolStatus::Denied,
            outcome: "denied".into(),
            more: Vec::new(),
            body: Body::Message(message.into()),
            meta: Map::new(),
        }
    }

    pub fn with_more(mut self, fact: impl Into<String>) -> ToolOutput {
        self.more.push(fact.into());
        self
    }

    pub fn with_meta(mut self, key: &str, value: Value) -> ToolOutput {
        self.meta.insert(key.to_string(), value);
        self
    }

    /// Say that this result did not cover everything, by one of the words of [`META_LIMITS`].
    pub fn with_limit(mut self, word: &str) -> ToolOutput {
        add_limit(&mut self.meta, word);
        self
    }

    /// Images the result carries (already stored in the blob store). `finalize` moves them out of `meta`
    /// (the reserved key [`META_IMAGES`]) into `ToolResult::images`, so they never reach the record's meta.
    /// Attach the exchanges this call made (C3). The tool stored the messages as blobs already.
    pub fn with_exchanges(mut self, exchanges: &[ferret_core::event::Exchange]) -> ToolOutput {
        if !exchanges.is_empty() {
            self.meta.insert(META_EXCHANGES.to_string(), json!(exchanges));
        }
        self
    }

    pub fn with_images(mut self, images: &[ferret_core::ImageRef]) -> ToolOutput {
        if !images.is_empty() {
            self.meta.insert(META_IMAGES.to_string(), json!(images));
        }
        self
    }
}

#[async_trait]
pub trait Tool: Send + Sync {
    /// Name, description, argument schema and class. Must return the same value every time.
    fn spec(&self) -> ToolSpec;

    /// True when a call may be started while the reply that holds it is still streaming, before it
    /// is certain the finished reply holds it: the tool only reads local state, has no effect outside
    /// the harness, and records what it saw only through `ctx.files` (which the caller may stage).
    /// Nothing that runs commands, writes, reaches the network or belongs to the runtime says yes.
    fn speculative(&self) -> bool {
        false
    }

    /// Run one call. `args` has passed [`schema::check`] against `spec().parameters`.
    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput;
}

/// The tools a session can call, in a fixed order.
#[derive(Clone, Default)]
pub struct Registry {
    tools: Vec<Arc<dyn Tool>>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry::default()
    }

    /// Every built-in tool, in the order they are presented to the model.
    pub fn builtin() -> Registry {
        let mut r = Registry::new();
        r.add(Arc::new(bash::Bash));
        r.add(Arc::new(bash::JobWait));
        r.add(Arc::new(bash::JobKill));
        r.add(Arc::new(bash::JobList));
        r.add(Arc::new(pty::PtyOpen));
        r.add(Arc::new(pty::PtyExec));
        r.add(Arc::new(pty::PtyClose));
        r.add(Arc::new(http::HttpSend));
        r.add(Arc::new(http::HttpRepeat));
        r.add(Arc::new(http::HttpAuthzMatrix));
        r.add(Arc::new(oast::OastMint));
        r.add(Arc::new(oast::OastPoll));
        r.add(Arc::new(codec::CodecCalc));
        r.add(Arc::new(binary::BinSurvey));
        r.add(Arc::new(binary::BinDecompile));
        r.add(Arc::new(binary::BinXrefs));
        r.add(Arc::new(binary::GdbProbe));
        r.add(Arc::new(oracle::OracleCheck));
        r.add(Arc::new(fstools::Read));
        r.add(Arc::new(fstools::Write));
        r.add(Arc::new(fstools::Edit));
        r.add(Arc::new(search::Glob));
        r.add(Arc::new(search::Grep));
        r.add(Arc::new(outview::OutRead));
        r.add(Arc::new(outview::OutGrep));
        r.add(Arc::new(web::WebFetch));
        r.add(Arc::new(cve::CveLookup));
        r.add(Arc::new(cve::CveSearch));
        r.add(Arc::new(cve::AdvisoryLookup));
        r.add(Arc::new(depscan::DepScan));
        r
    }

    /// Add a tool. A tool with the same name as an earlier one replaces it in place.
    pub fn add(&mut self, tool: Arc<dyn Tool>) {
        let name = tool.spec().name;
        match self.tools.iter().position(|t| t.spec().name == name) {
            Some(i) => self.tools[i] = tool,
            None => self.tools.push(tool),
        }
    }

    /// Keep only the named tools (unknown names are ignored), preserving order.
    pub fn retain(&mut self, names: &[String]) {
        self.tools.retain(|t| names.contains(&t.spec().name));
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Tool>> {
        self.tools.iter().find(|t| t.spec().name == name).cloned()
    }

    /// Resolve a tool call name, falling back to [`canonical_tool_alias`] ONLY when that canonical
    /// tool is registered in `self`. Returns `(tool, Some(canonical))` when resolved via alias.
    pub fn resolve(&self, name: &str) -> Option<(Arc<dyn Tool>, Option<&'static str>)> {
        if let Some(tool) = self.get(name) {
            return Some((tool, None));
        }
        let canon = canonical_tool_alias(name)?;
        self.get(canon).map(|tool| (tool, Some(canon)))
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.spec()).collect()
    }

    pub fn names(&self) -> Vec<String> {
        self.tools.iter().map(|t| t.spec().name).collect()
    }
}

/// Map a tool-call name that is not a ferret tool name to the ferret tool it stands for (the table is
/// `dialect`'s, `docs/TOOL-SHAPES.md` section 2). Callers must still verify the tool is in the [`Registry`].
pub fn canonical_tool_alias(name: &str) -> Option<&'static str> {
    dialect::alias_tool(name)
}

/// The class of the tool a call runs, as [`prepare`] adapts it (`dialect::adapt` against `registry`): a name in
/// another case or with `-` for `_` runs the tool it folds to, `shell` with a Codex `apply_patch` argv runs `write` or
/// `edit`, an editor's `view` runs `read`. The class of the first step of a batch (every step writes). `None` when
/// nothing would run: an unknown name, a refusal, arguments that are not JSON.
pub fn run_class(
    registry: &Registry,
    name: &str,
    arguments: &str,
    dialect: ferret_core::config::Dialect,
) -> Option<ToolClass> {
    let parsed: Value = serde_json::from_str(if arguments.trim().is_empty() { "{}" } else { arguments }).ok()?;
    let class_of = |tool: &str| registry.get(tool).map(|t| t.spec().class);
    match dialect::adapt(name, parsed, dialect, &|t| registry.get(t).is_some()) {
        dialect::Adapt::Run(call) => class_of(&call.tool),
        dialect::Adapt::Batch(calls) => calls.first().and_then(|c| class_of(&c.tool)),
        dialect::Adapt::Noop(_) | dialect::Adapt::Refuse(_) | dialect::Adapt::Unknown => None,
    }
}

/// How output is admitted for this call.
pub struct Admission<'a> {
    pub policy: &'a AdmitPolicy,
    pub estimator: &'a TokenEstimator,
}

/// Outcome text of a call that was refused before it ran.
pub const NOT_RUN: &str = "not run";

/// Run one tool call from the model's raw arguments text and produce its `tool_result` record.
/// Never fails: every problem becomes a result the model can read.
pub async fn execute(
    registry: &Registry,
    ctx: &ToolCtx,
    name: &str,
    arguments: &str,
    admission: &Admission<'_>,
) -> ToolResult {
    match prepare(registry, ctx, name, arguments) {
        Ok(call) => call.run(ctx).await.finish(ctx, admission),
        Err(refusal) => *refusal,
    }
}

/// One checked call inside a [`Prepared`].
struct Step {
    tool: Arc<dyn Tool>,
    spec: ToolSpec,
    checked: schema::Checked,
}

/// A call whose tool was found and whose arguments passed checking: [`execute`] up to running it.
/// It holds one step, or several when one model call stands for many (a Codex `apply_patch` over
/// several files): every step was checked before any runs, the steps run in order, and the result is
/// one combined result ([`Prepared::run`]).
pub struct Prepared {
    steps: Vec<Step>,
    started: Instant,
}

/// What a prepared call produced, before it is stored and admitted ([`Ran::finish`]).
pub struct Ran {
    spec: ToolSpec,
    output: ToolOutput,
    /// From the call's preparation to the end of its run.
    pub took: Duration,
}

/// Look the tool up and check the arguments: the first part of [`execute`]. `Err` is the record of
/// the refused call (or of a call that needs no tool, such as `think`), exactly as `execute` returns it.
pub fn prepare(registry: &Registry, ctx: &ToolCtx, name: &str, arguments: &str) -> Result<Prepared, Box<ToolResult>> {
    use dialect::Adapt;
    let started = Instant::now();
    let dialect = ctx.cfg.dialect;
    let parsed: Value = match serde_json::from_str(if arguments.trim().is_empty() { "{}" } else { arguments }) {
        Ok(v) => v,
        Err(e) => {
            // The tool the name stands for, when there is one, gives the refusal its class and wording.
            let tool = registry.resolve(name).map(|(t, _)| t);
            let (shown, class) = tool.map_or((name.to_string(), ToolClass::State), |t| {
                let s = t.spec();
                (s.name, s.class)
            });
            return Err(Box::new(refused(ctx, name, class, not_json_message(&shown, &e, arguments), started)));
        }
    };
    match dialect::adapt(name, parsed, dialect, &|t| registry.get(t).is_some()) {
        Adapt::Unknown => {
            let message = unknown_tool_message(name, &registry.names());
            Err(Box::new(refused(ctx, name, ToolClass::State, message, started)))
        }
        Adapt::Refuse(message) => Err(Box::new(refused(ctx, name, ToolClass::State, message, started))),
        Adapt::Noop(text) => {
            let facts = Facts { tool: name.to_string(), outcome: "ok".into(), more: Vec::new(), notes: None };
            Err(Box::new(ToolResult {
                call_id: ctx.call_id.clone(),
                name: name.to_string(),
                status: ToolStatus::Ok,
                text: envelope_plain(&facts, &text),
                output: None,
                cut: false,
                class: ToolClass::State,
                meta: Map::new(),
                duration_ms: started.elapsed().as_millis() as u64,
                images: Vec::new(),
                exchanges: Vec::new(),
            }))
        }
        Adapt::Run(call) => {
            let step = check_step(registry, call, dialect)
                .map_err(|(class, msg)| Box::new(refused(ctx, name, class, msg, started)))?;
            Ok(Prepared { steps: vec![step], started })
        }
        Adapt::Batch(calls) => {
            let mut steps = Vec::new();
            let mut class = ToolClass::State;
            let mut problems = Vec::new();
            for call in calls {
                let label = batch_label(&call);
                match check_step(registry, call, dialect) {
                    Ok(step) => steps.push(step),
                    Err((c, msg)) => {
                        class = c;
                        problems.push(format!("{label}: {msg}"));
                    }
                }
            }
            if !problems.is_empty() {
                let message = format!(
                    "This call changes several files and one of them cannot be applied, so none was changed.\n{}",
                    problems.join("\n")
                );
                return Err(Box::new(refused(ctx, name, class, message, started)));
            }
            Ok(Prepared { steps, started })
        }
    }
}

/// The file a batch entry is about, for the lines that name it.
fn batch_label(call: &dialect::Adapted) -> String {
    let path = call.args.get("path").and_then(Value::as_str).unwrap_or("?");
    format!("`{}` {path}", call.tool)
}

/// Normalise and check one adapted call against its tool. `Err` is the class and refusal message.
fn check_step(
    registry: &Registry,
    call: dialect::Adapted,
    dialect: ferret_core::config::Dialect,
) -> Result<Step, (ToolClass, String)> {
    let Some(tool) = registry.get(&call.tool) else {
        return Err((ToolClass::State, unknown_tool_message(&call.tool, &registry.names())));
    };
    let spec = tool.spec();
    match check_value(&spec, call.args, dialect) {
        Ok(mut checked) => {
            checked.notes.splice(0..0, call.notes);
            Ok(Step { tool, spec, checked })
        }
        Err(msg) => Err((spec.class, msg)),
    }
}

impl Prepared {
    /// See [`Tool::speculative`]. A call of several steps is never started early.
    pub fn speculative(&self) -> bool {
        matches!(self.steps.as_slice(), [only] if only.tool.speculative())
    }

    /// Run the tool. A panic inside it becomes an error output. Several steps run in order and stop at
    /// the first that does not succeed; their results are joined under the file each is about, the
    /// status is the worst one, and the steps after a failure are named as not run.
    pub async fn run(self, ctx: &ToolCtx) -> Ran {
        let Prepared { steps, started } = self;
        if steps.len() == 1 {
            let Some(step) = steps.into_iter().next() else { unreachable!("one step") };
            let (spec, output) = run_step(ctx, step).await;
            return Ran { spec, output, took: started.elapsed() };
        }
        let total = steps.len();
        let mut spec = None;
        let mut parts: Vec<String> = Vec::new();
        let mut worst = ToolStatus::Ok;
        let mut done = 0;
        let mut failed = false;
        for step in steps {
            let path = step.checked.args.get("path").and_then(Value::as_str).unwrap_or("?").to_string();
            let label = format!("`{}` {path}", step.spec.name);
            if failed {
                parts.push(format!("{label}: not run (an earlier file failed)."));
                continue;
            }
            let (s, output) = run_step(ctx, step).await;
            spec.get_or_insert(s);
            if output.status == ToolStatus::Ok {
                done += 1;
            } else {
                failed = true;
            }
            if status_rank(output.status) > status_rank(worst) {
                worst = output.status;
            }
            let body = match &output.body {
                Body::Message(t) => t.clone(),
                Body::Raw(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                Body::View { text, .. } | Body::ProducedView { text, .. } => text.clone(),
            };
            let head = if output.more.is_empty() {
                output.outcome.clone()
            } else {
                format!("{} ({})", output.outcome, output.more.join(", "))
            };
            parts.push(format!("{label}: {head}\n{}", body.trim_end()));
        }
        let Some(spec) = spec else { unreachable!("several steps ran at least one") };
        let outcome = if failed {
            format!("{done} of {total} applied, then stopped")
        } else {
            format!("{done} of {total} applied")
        };
        let output = ToolOutput {
            status: worst,
            outcome,
            more: Vec::new(),
            body: Body::Message(parts.join("\n\n")),
            meta: Map::new(),
        };
        Ran { spec, output, took: started.elapsed() }
    }
}

fn status_rank(s: ToolStatus) -> u8 {
    match s {
        ToolStatus::Ok => 0,
        ToolStatus::Error => 1,
        ToolStatus::Invalid => 2,
        ToolStatus::Denied => 3,
        ToolStatus::Timeout => 4,
        ToolStatus::Interrupted => 5,
    }
}

async fn run_step(ctx: &ToolCtx, step: Step) -> (ToolSpec, ToolOutput) {
    let Step { tool, spec, checked } = step;
    let ran = std::panic::AssertUnwindSafe(tool.run(ctx, &checked.args)).catch_unwind().await;
    let mut output = match ran {
        Ok(o) => o,
        Err(_) => ToolOutput::error(format!(
            "The `{}` tool failed internally while handling this call (a harness fault, not a problem with the arguments). Its effects, if any, are unknown — check the state it would have changed before repeating the call.",
            spec.name
        )),
    };
    if !checked.notes.is_empty() {
        output.meta.insert(META_REPAIRED.into(), json!(true));
        output.more.extend(checked.notes);
    }
    (spec, output)
}

impl Ran {
    /// Store and admit the output: the last part of [`execute`]. The record's duration is the run's.
    pub fn finish(self, ctx: &ToolCtx, admission: &Admission<'_>) -> ToolResult {
        let started = Instant::now().checked_sub(self.took).unwrap_or_else(Instant::now);
        finalize(ctx, &self.spec, self.output, admission, started)
    }
}

fn not_json_message(name: &str, e: &serde_json::Error, arguments: &str) -> String {
    format!(
        "The arguments were not valid JSON ({e}).\nWhat was received:\n{}\nNothing was executed. Call `{name}` again with a JSON object as arguments.",
        preview(arguments, 600)
    )
}

/// Parse a call's raw arguments text and check it against the tool's parameters. The error is the
/// complete refusal message for the model. Public so that runtime-owned tools share the same path.
/// Arguments are checked as given (no dialect): runtime tools are shown in their own names.
pub fn check_arguments(spec: &ToolSpec, arguments: &str) -> Result<schema::Checked, String> {
    let name = &spec.name;
    let parsed: Value = match serde_json::from_str(if arguments.trim().is_empty() { "{}" } else { arguments }) {
        Ok(v) => v,
        Err(e) => return Err(not_json_message(name, &e, arguments)),
    };
    check_value(spec, parsed, ferret_core::config::Dialect::Ferret)
}

/// Normalise and check parsed arguments against `spec`. When the model is shown the `dialect`'s
/// presentation of the tool, the refusal lists the parameters as the model was shown them.
fn check_value(
    spec: &ToolSpec,
    mut parsed: Value,
    dialect: ferret_core::config::Dialect,
) -> Result<schema::Checked, String> {
    let name = &spec.name;
    let mut notes = schema::normalize_for_tool(name, &mut parsed);
    notes.extend(schema::prepare_for_spec(&spec.parameters, &mut parsed));
    let checker = if name.starts_with("mcp__") { schema::check_mcp } else { schema::check };
    let mut checked = checker(&spec.parameters, &parsed).map_err(|problems| {
        let mut msg = String::from("The arguments do not fit this tool:\n");
        let internal: Vec<&str> = spec
            .parameters
            .get("properties")
            .and_then(Value::as_object)
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        for p in &problems {
            let mut line = p.clone();
            for key in &internal {
                let shown = dialect::presented_arg(name, key, dialect);
                if shown != *key {
                    line = line.replace(&format!("`{key}`"), &format!("`{shown}`"));
                }
            }
            msg.push_str("- ");
            msg.push_str(&line);
            msg.push('\n');
        }
        let shown = dialect::present(spec, dialect);
        msg.push_str(&format!(
            "Nothing was executed. Call `{name}` again with corrected arguments. Its parameters are:\n{}",
            schema::describe(&shown.parameters)
        ));
        msg
    })?;
    if !notes.is_empty() {
        notes.extend(checked.notes);
        checked.notes = notes;
    }
    Ok(checked)
}

/// Turn a tool's output into the record. Public so that runtime-owned tools share the same path.
///
/// When the session has secrets (CONTRACTS-TRAFFIC-TARGETS S5) every value in them is replaced by
/// `[redacted]` in the result's text and meta and in every output that is stored for it: bytes before they
/// are stored, and the blob a view or a produced view points at is re-stored redacted when it held one.
/// Without secrets nothing is copied.
pub fn finalize(
    ctx: &ToolCtx,
    spec: &ToolSpec,
    mut output: ToolOutput,
    admission: &Admission<'_>,
    started: Instant,
) -> ToolResult {
    let Some(secrets) = ctx.capabilities.secrets.get().filter(|s| !s.is_empty()) else {
        return finalize_plain(ctx, spec, output, admission, started);
    };
    redact_output(ctx, secrets, &mut output);
    let mut result = finalize_plain(ctx, spec, output, admission, started);
    if let std::borrow::Cow::Owned(t) = secrets.redact(&result.text) {
        result.text = t;
    }
    redact_meta(secrets, &mut result.meta);
    result
}

fn redact_string(secrets: &ferret_core::creds::Secrets, s: &mut String) {
    if let std::borrow::Cow::Owned(t) = secrets.redact(s) {
        *s = t;
    }
}

fn redact_meta(secrets: &ferret_core::creds::Secrets, meta: &mut Map<String, Value>) {
    fn walk(secrets: &ferret_core::creds::Secrets, v: &mut Value) {
        match v {
            Value::String(s) => redact_string(secrets, s),
            Value::Array(a) => a.iter_mut().for_each(|x| walk(secrets, x)),
            Value::Object(o) => o.values_mut().for_each(|x| walk(secrets, x)),
            _ => {}
        }
    }
    meta.values_mut().for_each(|v| walk(secrets, v));
}

/// A stored blob with the secrets taken out: `None` when it held none (or cannot be read, which the
/// caller's own read will report), else the new, redacted blob.
fn redacted_blob(ctx: &ToolCtx, secrets: &ferret_core::creds::Secrets, id: &BlobId) -> Option<ferret_core::BlobRef> {
    let bytes = ctx.blobs.read_all(id).ok()?;
    match secrets.redact_bytes(&bytes) {
        std::borrow::Cow::Owned(clean) => ctx.blobs.put_bytes(&clean).ok(),
        std::borrow::Cow::Borrowed(_) => None,
    }
}

fn redact_output(ctx: &ToolCtx, secrets: &ferret_core::creds::Secrets, output: &mut ToolOutput) {
    redact_string(secrets, &mut output.outcome);
    output.more.iter_mut().for_each(|m| redact_string(secrets, m));
    redact_meta(secrets, &mut output.meta);
    match &mut output.body {
        Body::Raw(bytes) => {
            if let std::borrow::Cow::Owned(clean) = secrets.redact_bytes(bytes) {
                *bytes = clean;
            }
        }
        Body::Message(text) => redact_string(secrets, text),
        Body::View { of, text, .. } => {
            redact_string(secrets, text);
            if let Some(clean) = redacted_blob(ctx, secrets, of) {
                *of = clean.id;
            }
        }
        Body::ProducedView { blob, text, .. } => {
            redact_string(secrets, text);
            if let Some(clean) = redacted_blob(ctx, secrets, &blob.id) {
                *blob = clean;
            }
        }
    }
}

fn finalize_plain(
    ctx: &ToolCtx,
    spec: &ToolSpec,
    output: ToolOutput,
    admission: &Admission<'_>,
    started: Instant,
) -> ToolResult {
    let ToolOutput { status, outcome, more, body, mut meta } = output;
    let outcome_text = outcome.clone();
    let mut facts = Facts { tool: spec.name.clone(), outcome, more, notes: None };
    let duration_ms = started.elapsed().as_millis() as u64;
    let exchanges: Vec<ferret_core::event::Exchange> =
        meta.remove(META_EXCHANGES).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
    let images: Vec<ferret_core::ImageRef> =
        meta.remove(META_IMAGES).and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();
    let derived: Vec<&str> = {
        let mut d = Vec::new();
        if status == ToolStatus::Timeout {
            d.push(if outcome_text.contains("no output during idle") { "idle stop" } else { "timeout" });
        }
        if outcome_text.starts_with("stopped: output passed") {
            d.push("output limit");
        }
        d
    };
    let base = |status, text, output, cut: bool, mut meta: Map<String, Value>| {
        for word in &derived {
            add_limit(&mut meta, word);
        }
        if cut {
            add_limit(&mut meta, "cut");
        }
        ToolResult {
            call_id: ctx.call_id.clone(),
            name: spec.name.clone(),
            status,
            text,
            output,
            cut,
            class: spec.class,
            meta,
            duration_ms,
            images: images.clone(),
            exchanges: exchanges.clone(),
        }
    };
    // A view sized for the bound the call ran with is not cut for a lower one that came after it.
    let budget = ctx.view_chars.max(admission.policy.view_chars(admission.estimator));
    // A message longer than one result may show is stored and admitted like raw output.
    let body = match body {
        Body::Message(text) if text.chars().count() > budget => Body::Raw(text.into_bytes()),
        other => other,
    };
    match body {
        Body::Message(text) => base(status, envelope_plain(&facts, &text), None, false, meta),
        Body::View { of, text, shown } => {
            meta.insert(META_OF_BLOB.into(), json!(of.as_str()));
            match cut_view(&text, budget, &handle_of(of.as_str())) {
                Some(cut) => {
                    meta.insert(META_SHOWN.into(), ranges_json(&[]));
                    base(status, envelope_plain(&facts, &cut), None, true, meta)
                }
                None => {
                    meta.insert(META_SHOWN.into(), ranges_json(&shown));
                    base(status, envelope_plain(&facts, &text), None, false, meta)
                }
            }
        }
        Body::ProducedView { blob, text, shown } => {
            meta.insert(META_OF_BLOB.into(), json!(blob.id.as_str()));
            match cut_view(&text, budget, &blob.handle()) {
                Some(cut) => {
                    meta.insert(META_SHOWN.into(), ranges_json(&[]));
                    base(status, envelope_plain(&facts, &cut), Some(blob), true, meta)
                }
                None => {
                    let cut = blob.lines > 0 && !(shown.len() == 1 && shown.first() == Some(&(1, blob.lines)));
                    meta.insert(META_SHOWN.into(), ranges_json(&shown));
                    base(status, envelope_plain(&facts, &text), Some(blob), cut, meta)
                }
            }
        }
        Body::Raw(bytes) => {
            let normalized = normalize(&bytes);
            facts.notes = normalized.notes();
            let stored = match ctx.blobs.put_bytes(normalized.text.as_bytes()) {
                Ok(b) => b,
                Err(e) => {
                    return base(ToolStatus::Error, storage_failure(&facts, &normalized.text, &e), None, true, meta);
                }
            };
            if normalized.changed {
                if let Ok(raw) = ctx.blobs.put_bytes(&bytes) {
                    meta.insert(META_RAW_BLOB.into(), json!(raw.id.as_str()));
                }
            }
            match admit(&ctx.blobs, &stored, &facts, admission.policy, admission.estimator) {
                Ok(admitted) => {
                    meta.insert(META_SHOWN.into(), ranges_json(&admitted.shown));
                    base(status, admitted.text, Some(stored), admitted.cut, meta)
                }
                Err(e) => {
                    base(ToolStatus::Error, storage_failure(&facts, &normalized.text, &e), Some(stored), true, meta)
                }
            }
        }
    }
}

/// The handle (`out:` and the first 16 characters) of a blob id.
fn handle_of(id: &str) -> String {
    format!("out:{}", id.chars().take(16).collect::<String>())
}

/// `text` cut to at most `budget` characters at a line end, with the line that says so, or `None` when
/// it is within `budget`.
fn cut_view(text: &str, budget: usize, handle: &str) -> Option<String> {
    let total = text.chars().count();
    if total <= budget {
        return None;
    }
    let end = text.char_indices().nth(budget).map_or(text.len(), |(i, _)| i);
    let head = text.get(..end).unwrap_or("");
    let kept = match head.rfind('\n') {
        Some(i) => head.get(..=i).unwrap_or(head),
        None => head,
    };
    let mut out = kept.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!(
        "[cut by harness: this view is {total} characters, more than one result may show ({budget}); the rest is not shown. Nothing was discarded: ask for fewer lines (start/end, or a narrower pattern) of {handle}.]"
    ));
    Some(out)
}

/// The record of a call that was refused before it ran (status `Invalid`). Public so that
/// runtime-owned tools refuse in exactly the same words.
pub fn refused(ctx: &ToolCtx, name: &str, class: ToolClass, message: String, started: Instant) -> ToolResult {
    let facts = Facts { tool: name.to_string(), outcome: NOT_RUN.into(), more: Vec::new(), notes: None };
    ToolResult {
        call_id: ctx.call_id.clone(),
        name: name.to_string(),
        status: ToolStatus::Invalid,
        text: envelope_plain(&facts, &message),
        output: None,
        cut: false,
        class,
        meta: Map::new(),
        duration_ms: started.elapsed().as_millis() as u64,
        images: Vec::new(),
        exchanges: Vec::new(),
    }
}

/// The harness could not store or re-read an output. The model still gets the start of it, and is
/// told that this view is partial and why.
fn storage_failure(facts: &Facts, text: &str, error: &std::io::Error) -> String {
    let shown = preview(text, 8_000);
    let body = format!(
        "[harness fault: the output of this call could not be stored ({error}). What follows is only its first {} characters of {}; the rest is not available. The call itself ran — do not assume it failed.]\n{shown}",
        shown.chars().count(),
        text.chars().count()
    );
    envelope_plain(facts, &body)
}

/// The sentence for a call to a tool that does not exist, naming the closest tools that do.
pub fn unknown_tool_message(name: &str, names: &[String]) -> String {
    let mut near: Vec<(usize, &String)> = names.iter().map(|n| (schema::distance(name, n), n)).collect();
    near.sort();
    let close: Vec<&str> = near
        .iter()
        .filter(|(d, n)| *d <= 3 || n.contains(name) || name.contains(n.as_str()))
        .take(3)
        .map(|(_, n)| n.as_str())
        .collect();
    let mut msg = format!("There is no tool named `{name}`.");
    if !close.is_empty() {
        msg.push_str(&format!(" Closest names: {}.", close.join(", ")));
    }
    msg.push_str(&format!("\nNothing was executed. The tools you can call are: {}.", names.join(", ")));
    msg
}

/// The first `max` characters of `text`, with a marker when it is longer.
pub fn preview(text: &str, max: usize) -> String {
    let mut out: String = text.chars().take(max).collect();
    let total = text.chars().count();
    if total > max {
        out.push_str(&format!("…[+{} chars]", total - max));
    }
    out
}

pub fn ranges_json(ranges: &[(u64, u64)]) -> Value {
    Value::Array(ranges.iter().map(|(a, b)| json!([a, b])).collect())
}

/// A complete tool context over a temporary directory, for tests (this crate's, and other crates'
/// through the `testutil` feature).
#[cfg(any(test, feature = "testutil"))]
#[allow(clippy::expect_used)]
pub mod testutil {
    use super::*;
    use ferret_core::config::{SandboxCfg, SandboxMode};
    use tokio::sync::mpsc::UnboundedReceiver;

    pub struct TestEnv {
        pub dir: tempfile::TempDir,
        pub ctx: ToolCtx,
        pub job_events: UnboundedReceiver<jobs::JobEvent>,
        pub policy: AdmitPolicy,
        pub estimator: TokenEstimator,
        pub registry: Registry,
    }

    /// Workspace `<dir>/ws`, temp `<dir>/tmp`, ferret home `<dir>/home`; sandbox mode `none`.
    pub fn env() -> TestEnv {
        env_with(
            ToolsCfg { dialect: ferret_core::config::Dialect::Ferret, ..ToolsCfg::default() },
            SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() },
        )
    }

    pub fn env_with(cfg: ToolsCfg, sandbox_cfg: SandboxCfg) -> TestEnv {
        make_env(cfg, sandbox_cfg, false)
    }

    /// `env_with` in the production layout: the session temp dir is `<dir>/home/sessions/s1/tmp`, inside the ferret
    /// home, and the job output files are in `<dir>/home/sessions/s1/jobs`, which the sandbox is told of.
    pub fn env_prod(cfg: ToolsCfg, sandbox_cfg: SandboxCfg) -> TestEnv {
        make_env(cfg, sandbox_cfg, true)
    }

    fn make_env(cfg: ToolsCfg, sandbox_cfg: SandboxCfg, prod: bool) -> TestEnv {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical tempdir");
        let (ws, home) = (root.join("ws"), root.join("home"));
        let (tmp, jobs_dir) = if prod {
            (home.join("sessions/s1/tmp"), home.join("sessions/s1/jobs"))
        } else {
            (root.join("tmp"), home.join("jobs"))
        };
        for d in [&ws, &tmp, &home] {
            std::fs::create_dir_all(d).expect("create test dirs");
        }
        let blobs = BlobStore::open(home.join("blobs")).expect("blob store");
        let mut sandbox = sandbox::Sandbox::new(&sandbox_cfg, &ws, &tmp, &home, None).expect("sandbox");
        if prod {
            sandbox = sandbox.with_jobs_dir(&jobs_dir).expect("jobs dir");
        }
        let (tx, job_events) = tokio::sync::mpsc::unbounded_channel();
        let jobs = jobs::JobTable::new(jobs_dir, blobs.clone(), tx, cfg.max_output_bytes);
        let ctx = ToolCtx {
            session: SessionId::from("s-test"),
            call_id: CallId::from("call-1"),
            workspace: ws,
            tmp_dir: tmp,
            blobs,
            outputs: Arc::new(outputs::AnyStored),
            cfg: Arc::new(cfg),
            sandbox: Arc::new(sandbox),
            env: Arc::new(BTreeMap::new()),
            reference_proxy: None,
            files: Arc::new(files::FileTracker::new()),
            jobs: Arc::new(jobs),
            cancel: CancellationToken::new(),
            capabilities: Arc::new(capabilities::SessionTools::default()),
            view_chars: AdmitPolicy::default().view_chars(&TokenEstimator::default()),
            shell: Arc::new(bash::ShellState::default()),
        };
        TestEnv {
            dir,
            ctx,
            job_events,
            policy: AdmitPolicy::default(),
            estimator: TokenEstimator::default(),
            registry: Registry::builtin(),
        }
    }

    impl TestEnv {
        /// Run a call the way the runtime does: through `execute`, arguments as JSON text.
        pub async fn call(&self, name: &str, args: Value) -> ToolResult {
            let admission = Admission { policy: &self.policy, estimator: &self.estimator };
            execute(&self.registry, &self.ctx, name, &args.to_string(), &admission).await
        }

        /// The complete stored output of a result.
        pub fn stored(&self, result: &ToolResult) -> String {
            let blob = result.output.as_ref().expect("result has stored output");
            String::from_utf8(self.ctx.blobs.read_all(&blob.id).expect("read blob")).expect("utf-8")
        }
    }
}

#[cfg(test)]
mod creds_tests;

#[cfg(test)]
mod tls_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_cuts_on_characters() {
        assert_eq!(preview("héllo", 10), "héllo");
        assert_eq!(preview("héllo wörld", 4), "héll…[+7 chars]");
    }

    #[test]
    fn ranges_serialise_as_pairs() {
        assert_eq!(ranges_json(&[(1, 3), (9, 9)]).to_string(), "[[1,3],[9,9]]");
    }

    #[test]
    fn exactly_the_local_read_only_tools_may_start_early() {
        let r = Registry::builtin();
        let early: Vec<String> = r.names().into_iter().filter(|n| r.get(n).is_some_and(|t| t.speculative())).collect();
        assert_eq!(early, ["read", "glob", "grep", "out_read", "out_grep"]);
    }

    #[tokio::test]
    async fn a_call_prepared_run_and_finished_apart_makes_the_usual_record() {
        let e = testutil::env();
        std::fs::write(e.ctx.workspace.join("a.txt"), "one\ntwo\n").unwrap();
        let admission = Admission { policy: &e.policy, estimator: &e.estimator };
        let prepared = prepare(&e.registry, &e.ctx, "read", r#"{"path": "a.txt"}"#).map_err(|r| r.text).unwrap();
        let r = prepared.run(&e.ctx).await.finish(&e.ctx, &admission);
        assert_eq!((r.status, r.name.as_str(), &r.call_id), (ToolStatus::Ok, "read", &e.ctx.call_id));
        // The header ends with the handle of what was shown, which evidence can cite.
        let (head, body) = r.text.split_once('\n').unwrap_or_default();
        assert!(head.starts_with("[read · ok · a.txt · lines 1-2 of 2 · out:") && head.ends_with(']'), "{head}");
        assert_eq!(body, "1\tone\n2\ttwo\n[end of read output · ok]");
        assert_eq!(r.meta.get(META_SHOWN), Some(&json!([[1, 2]])));
        for (name, args, says) in [
            ("reed", "{}", "There is no tool named `reed`."),
            ("read", "{}", "The arguments do not fit this tool:"),
            ("read", "{nope", "The arguments were not valid JSON"),
        ] {
            let refused = prepare(&e.registry, &e.ctx, name, args).err().unwrap();
            assert_eq!(refused.status, ToolStatus::Invalid);
            assert!(refused.text.starts_with(&format!("[{name} · not run]\n{says}")), "{}", refused.text);
        }
    }

    fn small_admission() -> (AdmitPolicy, TokenEstimator) {
        (AdmitPolicy { max_inline_tokens: 25, ..AdmitPolicy::default() }, TokenEstimator::default())
    }

    fn spec_of(e: &testutil::TestEnv, name: &str) -> ToolSpec {
        e.registry.get(name).map(|t| t.spec()).unwrap_or_else(|| panic!("no tool {name}"))
    }

    fn body_of(text: &str) -> &str {
        let after = text.split_once('\n').map_or("", |(_, b)| b);
        after.rsplit_once('\n').map_or("", |(b, _)| b)
    }

    #[test]
    fn a_view_over_the_budget_is_cut_at_a_line_with_the_handle() {
        let mut e = testutil::env();
        let (policy, estimator) = small_admission();
        e.ctx.view_chars = policy.view_chars(&estimator);
        let admission = Admission { policy: &policy, estimator: &estimator };
        let budget = policy.view_chars(&estimator);
        let stored = e.ctx.blobs.put_bytes(b"x\n").unwrap();
        let text: String = (1..=200).map(|i| format!("{i}\tsome line of text\n")).collect();
        let out = ToolOutput::ok("ok", Body::View { of: stored.id.clone(), text: text.clone(), shown: vec![(1, 200)] });
        let r = finalize(&e.ctx, &spec_of(&e, "out_read"), out, &admission, Instant::now());
        let body = body_of(&r.text);
        let (kept, marker) = body.rsplit_once('\n').unwrap();
        assert!(kept.chars().count() <= budget, "{} > {budget}", kept.chars().count());
        assert!(text.starts_with(kept) && text.get(kept.len()..).unwrap().starts_with('\n'));
        assert!(marker.starts_with("[cut by harness: this view is "), "{marker}");
        assert!(marker.contains(&format!("({budget})")) && marker.contains(&stored.handle()), "{marker}");
        assert!(r.cut && r.output.is_none());
        assert_eq!(r.meta.get(META_SHOWN), Some(&json!([])));
        assert_eq!(r.meta.get(META_OF_BLOB), Some(&json!(stored.id.as_str())));
    }

    #[test]
    fn a_view_sized_for_the_calls_own_bound_is_not_cut_by_a_lower_admission() {
        let mut e = testutil::env();
        let (policy, estimator) = small_admission();
        let admission = Admission { policy: &policy, estimator: &estimator };
        let budget = policy.view_chars(&estimator);
        e.ctx.view_chars = budget * 2;
        let stored = e.ctx.blobs.put_bytes(b"x\n").unwrap();
        let line = "some line of text\n";
        let text: String = line.repeat(budget * 3 / 2 / line.len() + 1);
        assert!(text.chars().count() > budget && text.chars().count() <= budget * 2);
        let out = ToolOutput::ok("ok", Body::View { of: stored.id.clone(), text: text.clone(), shown: vec![(1, 1)] });
        let r = finalize(&e.ctx, &spec_of(&e, "out_read"), out, &admission, Instant::now());
        assert!(!r.cut && !r.text.contains("[cut by harness"), "{}", r.text);
        // Over the call's own bound it is still cut.
        let long = line.repeat(budget * 3 / line.len() + 1);
        let out = ToolOutput::ok("ok", Body::View { of: stored.id.clone(), text: long, shown: vec![(1, 1)] });
        let r = finalize(&e.ctx, &spec_of(&e, "out_read"), out, &admission, Instant::now());
        assert!(r.cut && r.text.contains("[cut by harness"), "{}", r.text);
    }

    #[test]
    fn a_view_with_no_line_end_is_cut_on_a_character_boundary() {
        let mut e = testutil::env();
        let (policy, estimator) = small_admission();
        e.ctx.view_chars = policy.view_chars(&estimator);
        let admission = Admission { policy: &policy, estimator: &estimator };
        let budget = policy.view_chars(&estimator);
        let stored = e.ctx.blobs.put_bytes(b"x\n").unwrap();
        let text = "é✓".repeat(budget);
        let out = ToolOutput::ok("ok", Body::View { of: stored.id.clone(), text, shown: vec![(1, 1)] });
        let r = finalize(&e.ctx, &spec_of(&e, "out_read"), out, &admission, Instant::now());
        let (kept, marker) = body_of(&r.text).rsplit_once('\n').unwrap();
        assert_eq!(kept.chars().count(), budget);
        assert!(marker.starts_with("[cut by harness"), "{marker}");
    }

    #[test]
    fn a_produced_view_over_the_budget_keeps_its_blob_and_is_cut() {
        let mut e = testutil::env();
        let (policy, estimator) = small_admission();
        e.ctx.view_chars = policy.view_chars(&estimator);
        let admission = Admission { policy: &policy, estimator: &estimator };
        let full: String = (1..=300).map(|i| format!("{i}\tdecompiled\n")).collect();
        let blob = e.ctx.blobs.put_bytes(full.as_bytes()).unwrap();
        let out = ToolOutput::ok(
            "ok",
            Body::ProducedView { blob: blob.clone(), text: full.clone(), shown: vec![(1, blob.lines)] },
        );
        let r = finalize(&e.ctx, &spec_of(&e, "bin_decompile"), out, &admission, Instant::now());
        assert!(r.cut);
        assert_eq!(r.output.as_ref().map(|b| b.id.clone()), Some(blob.id.clone()));
        assert_eq!(r.meta.get(META_SHOWN), Some(&json!([])));
        assert!(r.text.contains("[cut by harness") && r.text.contains(&blob.handle()), "{}", r.text);
        assert!(r.text.chars().count() < full.chars().count());
    }

    #[test]
    fn a_message_over_the_budget_is_admitted_with_a_handle() {
        let mut e = testutil::env();
        let (policy, estimator) = small_admission();
        e.ctx.view_chars = policy.view_chars(&estimator);
        let admission = Admission { policy: &policy, estimator: &estimator };
        let text: String = (1..=500).map(|i| format!("message line {i}\n")).collect();
        let out = ToolOutput::ok("ok", Body::Message(text.clone()));
        let r = finalize(&e.ctx, &spec_of(&e, "bash"), out, &admission, Instant::now());
        let stored = r.output.as_ref().expect("a handle");
        assert_eq!(e.ctx.blobs.read_all(&stored.id).unwrap(), text.as_bytes());
        assert!(r.cut && r.text.contains(&stored.handle()), "{}", r.text);
        assert!(r.text.chars().count() < text.chars().count());
    }

    #[test]
    fn views_and_messages_within_the_budget_are_unchanged() {
        let mut e = testutil::env();
        let (policy, estimator) = small_admission();
        e.ctx.view_chars = policy.view_chars(&estimator);
        let admission = Admission { policy: &policy, estimator: &estimator };
        let budget = policy.view_chars(&estimator);
        let stored = e.ctx.blobs.put_bytes(b"x\n").unwrap();
        let text = "a".repeat(budget);
        let out = ToolOutput::ok("ok", Body::View { of: stored.id.clone(), text: text.clone(), shown: vec![(1, 1)] });
        let r = finalize(&e.ctx, &spec_of(&e, "out_read"), out, &admission, Instant::now());
        assert_eq!(body_of(&r.text), text);
        assert!(!r.cut);
        assert_eq!(r.meta.get(META_SHOWN), Some(&json!([[1, 1]])));
        let out = ToolOutput::ok("ok", Body::Message(text.clone()));
        let r = finalize(&e.ctx, &spec_of(&e, "bash"), out, &admission, Instant::now());
        assert_eq!(body_of(&r.text), text);
        assert!(r.output.is_none() && !r.cut);
    }

    #[test]
    fn a_call_has_the_class_of_the_tool_it_runs_not_of_the_name_it_was_sent_under() {
        let r = Registry::builtin();
        let d = ferret_core::config::Dialect::default();
        let class = |name: &str, args: Value| run_class(&r, name, &args.to_string(), d);
        // Not in the alias table: the case and the dash fold to the registered name, which `Registry::resolve` misses.
        assert!(r.resolve("Pty-Exec").is_none());
        assert_eq!(class("Pty-Exec", json!({"pty": "1", "command": "id"})), Some(ToolClass::Exec));
        assert_eq!(class("OUT_READ", json!({"handle": "out:x"})), Some(ToolClass::Read));
        let patch = "*** Begin Patch\n*** Add File: Makefile\n+all:\n*** End Patch";
        assert_eq!(class("shell", json!({"command": ["apply_patch", patch]})), Some(ToolClass::Write));
        assert_eq!(class("text_editor", json!({"command": "view", "path": "a.txt"})), Some(ToolClass::Read));
        assert_eq!(class("bash", json!({"command": "ls"})), Some(ToolClass::Exec));
        assert_eq!(class("no_such_tool", json!({})), None);
        assert_eq!(run_class(&r, "bash", "{not json", d), None);
    }

    #[test]
    fn canonical_tool_alias_table() {
        for (alias, canon) in [
            ("read_file", "read"),
            ("view_file", "read"),
            ("open_file", "read"),
            ("write_file", "write"),
            ("create_file", "write"),
            ("edit_file", "edit"),
            ("str_replace", "edit"),
            ("str_replace_editor", "edit"),
            ("replace_in_file", "edit"),
            ("apply_patch", "edit"),
            ("shell", "bash"),
            ("run_command", "bash"),
            ("execute_command", "bash"),
            ("exec", "bash"),
            ("terminal", "bash"),
            ("search_files", "grep"),
            ("ripgrep", "grep"),
            ("rg", "grep"),
            ("grep_search", "grep"),
            ("find_files", "glob"),
            ("list_files", "glob"),
            ("list_dir", "glob"),
            ("todo_write", "plan"),
            ("update_plan", "plan"),
            ("task", "agent_spawn"),
            ("subagent", "agent_spawn"),
            ("spawn_agent", "agent_spawn"),
        ] {
            assert_eq!(canonical_tool_alias(alias), Some(canon), "{alias}");
        }
        assert_eq!(canonical_tool_alias("read"), None);
        assert_eq!(canonical_tool_alias("unknown_tool"), None);
    }

    #[tokio::test]
    async fn tool_alias_and_normalization_mark_repaired_and_respect_registry() {
        let e = testutil::env();
        std::fs::write(e.ctx.workspace.join("a.txt"), "one\ntwo\nthree\n").unwrap();

        // Registered canonical target via alias runs canonical tool and marks repaired.
        let r = e.call("read_file", json!({"file_path": "a.txt", "offset": 2, "limit": 1})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert_eq!(r.meta.get("repaired"), Some(&json!(true)));
        assert!(r.text.contains("tool alias: called `read_file`, ran `read`"), "{}", r.text);
        assert!(r.text.contains("2\ttwo") && !r.text.contains("3\tthree"), "{}", r.text);

        // Clean canonical call sets no repaired meta.
        let clean = e.call("read", json!({"path": "a.txt", "start": 1, "end": 1})).await;
        assert_eq!(clean.status, ToolStatus::Ok, "{}", clean.text);
        assert!(clean.meta.get("repaired").is_none(), "{:?}", clean.meta);

        // Unregistered canonical target is never granted through alias; keeps unknown_tool_message.
        let registered: Vec<String> = e.registry.specs().into_iter().map(|s| s.name).collect();
        let unregistered = e.call("todo_write", json!({"action": "list"})).await;
        assert_eq!(unregistered.status, ToolStatus::Invalid);
        assert!(unregistered.meta.get("repaired").is_none());
        assert_eq!(body_of(&unregistered.text), "`todo_write` runs `plan`, which this role does not have.");

        let unknown = e.call("reed", json!({})).await;
        assert_eq!(unknown.status, ToolStatus::Invalid);
        assert_eq!(body_of(&unknown.text), unknown_tool_message("reed", &registered));
    }
}
