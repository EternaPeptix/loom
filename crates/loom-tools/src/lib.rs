//! loom-tools: running a tool call and turning what it produced into the record the model sees.
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
pub mod files;
pub mod fstools;
pub mod http;
pub mod jobs;
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
pub mod view;
pub mod web;
pub mod workcopy;

use async_trait::async_trait;
use futures_util::FutureExt;
use loom_core::admit::{admit, envelope_plain, normalize, AdmitPolicy, Facts};
use loom_core::config::ToolsCfg;
use loom_core::estimate::TokenEstimator;
use loom_core::event::{ToolClass, ToolResult, ToolSpec, ToolStatus, META_OF_BLOB, META_RAW_BLOB, META_SHOWN};
use loom_core::{BlobId, BlobStore, CallId, SessionId};
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
    pub reference_proxy: Option<loom_net::ReferenceGrant>,
    pub files: Arc<files::FileTracker>,
    pub jobs: Arc<jobs::JobTable>,
    pub cancel: CancellationToken,
    /// Session-local PTY/HTTP state. Cloned contexts share it; children start with fresh state.
    pub capabilities: Arc<capabilities::SessionTools>,
    /// The most characters the text of a view (`read`, `out_read`, `out_grep`, other numbered views)
    /// may hold: `AdmitPolicy::view_chars` of the session's admission when the call was started.
    pub view_chars: usize,
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
    ProducedView { blob: loom_core::BlobRef, text: String, shown: Vec<(u64, u64)> },
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

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.iter().map(|t| t.spec()).collect()
    }

    pub fn names(&self) -> Vec<String> {
        self.tools.iter().map(|t| t.spec().name).collect()
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

/// A call whose tool was found and whose arguments passed checking: [`execute`] up to running it.
pub struct Prepared {
    tool: Arc<dyn Tool>,
    spec: ToolSpec,
    checked: schema::Checked,
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
/// the refused call, exactly as `execute` returns it.
pub fn prepare(registry: &Registry, ctx: &ToolCtx, name: &str, arguments: &str) -> Result<Prepared, Box<ToolResult>> {
    let started = Instant::now();
    let Some(tool) = registry.get(name) else {
        let message = unknown_tool_message(name, &registry.names());
        return Err(Box::new(refused(ctx, name, ToolClass::State, message, started)));
    };
    let spec = tool.spec();
    match check_arguments(&spec, arguments) {
        Ok(checked) => Ok(Prepared { tool, spec, checked, started }),
        Err(msg) => Err(Box::new(refused(ctx, name, spec.class, msg, started))),
    }
}

impl Prepared {
    /// See [`Tool::speculative`].
    pub fn speculative(&self) -> bool {
        self.tool.speculative()
    }

    /// Run the tool. A panic inside it becomes an error output.
    pub async fn run(self, ctx: &ToolCtx) -> Ran {
        let Prepared { tool, spec, checked, started } = self;
        let ran = std::panic::AssertUnwindSafe(tool.run(ctx, &checked.args)).catch_unwind().await;
        let mut output = match ran {
            Ok(o) => o,
            Err(_) => ToolOutput::error(format!(
                "The `{}` tool failed internally while handling this call (a harness fault, not a problem with the arguments). Its effects, if any, are unknown — check the state it would have changed before repeating the call.",
                spec.name
            )),
        };
        for note in checked.notes {
            output.more.push(note);
        }
        Ran { spec, output, took: started.elapsed() }
    }
}

impl Ran {
    /// Store and admit the output: the last part of [`execute`]. The record's duration is the run's.
    pub fn finish(self, ctx: &ToolCtx, admission: &Admission<'_>) -> ToolResult {
        let started = Instant::now().checked_sub(self.took).unwrap_or_else(Instant::now);
        finalize(ctx, &self.spec, self.output, admission, started)
    }
}

/// Parse a call's raw arguments text and check it against the tool's parameters. The error is the
/// complete refusal message for the model. Public so that runtime-owned tools share the same path.
pub fn check_arguments(spec: &ToolSpec, arguments: &str) -> Result<schema::Checked, String> {
    let name = &spec.name;
    let parsed: Value = match serde_json::from_str(if arguments.trim().is_empty() { "{}" } else { arguments }) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "The arguments were not valid JSON ({e}).\nWhat was received:\n{}\nNothing was executed. Call `{name}` again with a JSON object as arguments.",
                preview(arguments, 600)
            ));
        }
    };
    schema::check(&spec.parameters, &parsed).map_err(|problems| {
        let mut msg = String::from("The arguments do not fit this tool:\n");
        for p in &problems {
            msg.push_str("- ");
            msg.push_str(p);
            msg.push('\n');
        }
        msg.push_str(&format!(
            "Nothing was executed. Call `{name}` again with corrected arguments. Its parameters are:\n{}",
            schema::describe(&spec.parameters)
        ));
        msg
    })
}

/// Turn a tool's output into the record. Public so that runtime-owned tools share the same path.
pub fn finalize(
    ctx: &ToolCtx,
    spec: &ToolSpec,
    output: ToolOutput,
    admission: &Admission<'_>,
    started: Instant,
) -> ToolResult {
    let ToolOutput { status, outcome, more, body, mut meta } = output;
    let mut facts = Facts { tool: spec.name.clone(), outcome, more, notes: None };
    let duration_ms = started.elapsed().as_millis() as u64;
    let base = |status, text, output, cut, meta| ToolResult {
        call_id: ctx.call_id.clone(),
        name: spec.name.clone(),
        status,
        text,
        output,
        cut,
        class: spec.class,
        meta,
        duration_ms,
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
                    return base(ToolStatus::Error, storage_failure(&facts, &normalized.text, &e), None, true, meta)
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
    use loom_core::config::{SandboxCfg, SandboxMode};
    use tokio::sync::mpsc::UnboundedReceiver;

    pub struct TestEnv {
        pub dir: tempfile::TempDir,
        pub ctx: ToolCtx,
        pub job_events: UnboundedReceiver<jobs::JobEvent>,
        pub policy: AdmitPolicy,
        pub estimator: TokenEstimator,
        pub registry: Registry,
    }

    /// Workspace `<dir>/ws`, temp `<dir>/tmp`, loom home `<dir>/home`; sandbox mode `none`.
    pub fn env() -> TestEnv {
        env_with(ToolsCfg::default(), SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() })
    }

    pub fn env_with(cfg: ToolsCfg, sandbox_cfg: SandboxCfg) -> TestEnv {
        make_env(cfg, sandbox_cfg, false)
    }

    /// `env_with` in the production layout: the session temp dir is `<dir>/home/sessions/s1/tmp`, inside the loom
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
}
