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
//! Modules:
//! - [`schema`]  argument checking with unambiguous coercions
//! - [`sandbox`] the OS sandbox profile and the same policy for in-process file access
//! - [`proc`]    spawning a command in its own process group, with one merged output stream
//! - [`jobs`]    background jobs
//! - [`files`]   what a session has read, for refusing writes over unseen changes
//! - [`view`]    numbered line views of stored output
//! - [`bash`], [`fstools`], [`search`], [`outview`], [`web`]: the built-in tools

pub mod bash;
pub mod cve;
pub mod files;
pub mod fstools;
pub mod jobs;
pub mod outview;
pub mod params;
pub mod proc;
pub mod sandbox;
pub mod schema;
pub mod search;
pub mod view;
pub mod web;

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
use std::time::Instant;
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
    pub cfg: Arc<ToolsCfg>,
    pub sandbox: Arc<sandbox::Sandbox>,
    /// Environment variables added to every command (proxy settings and the like).
    pub env: Arc<BTreeMap<String, String>>,
    pub files: Arc<files::FileTracker>,
    pub jobs: Arc<jobs::JobTable>,
    pub cancel: CancellationToken,
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
    let started = Instant::now();
    let Some(tool) = registry.get(name) else {
        return refused(ctx, name, ToolClass::State, unknown_tool_message(name, &registry.names()), started);
    };
    let spec = tool.spec();
    let checked = match check_arguments(&spec, arguments) {
        Ok(c) => c,
        Err(msg) => return refused(ctx, name, spec.class, msg, started),
    };

    let ran = std::panic::AssertUnwindSafe(tool.run(ctx, &checked.args)).catch_unwind().await;
    let mut output = match ran {
        Ok(o) => o,
        Err(_) => ToolOutput::error(format!(
            "The `{name}` tool failed internally while handling this call (a harness fault, not a problem with the arguments). Its effects, if any, are unknown — check the state it would have changed before repeating the call."
        )),
    };
    for note in checked.notes {
        output.more.push(note);
    }
    finalize(ctx, &spec, output, admission, started)
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
    match body {
        Body::Message(text) => base(status, envelope_plain(&facts, &text), None, false, meta),
        Body::View { of, text, shown } => {
            meta.insert(META_OF_BLOB.into(), json!(of.as_str()));
            meta.insert(META_SHOWN.into(), ranges_json(&shown));
            base(status, envelope_plain(&facts, &text), None, false, meta)
        }
        Body::Raw(bytes) => {
            let normalized = normalize(&bytes);
            facts.notes = normalized.notes();
            let stored = match ctx.blobs.put_bytes(normalized.text.as_bytes()) {
                Ok(b) => b,
                Err(e) => return base(ToolStatus::Error, storage_failure(&facts, &normalized.text, &e), None, true, meta),
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
                Err(e) => base(ToolStatus::Error, storage_failure(&facts, &normalized.text, &e), Some(stored), true, meta),
            }
        }
    }
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
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical tempdir");
        let (ws, tmp, home) = (root.join("ws"), root.join("tmp"), root.join("home"));
        for d in [&ws, &tmp, &home] {
            std::fs::create_dir_all(d).expect("create test dirs");
        }
        let blobs = BlobStore::open(home.join("blobs")).expect("blob store");
        let sandbox = sandbox::Sandbox::new(&sandbox_cfg, &ws, &tmp, &home, None).expect("sandbox");
        let (tx, job_events) = tokio::sync::mpsc::unbounded_channel();
        let jobs = jobs::JobTable::new(home.join("jobs"), blobs.clone(), tx, cfg.max_output_bytes);
        let ctx = ToolCtx {
            session: SessionId::from("s-test"),
            call_id: CallId::from("call-1"),
            workspace: ws,
            tmp_dir: tmp,
            blobs,
            cfg: Arc::new(cfg),
            sandbox: Arc::new(sandbox),
            env: Arc::new(BTreeMap::new()),
            files: Arc::new(files::FileTracker::new()),
            jobs: Arc::new(jobs),
            cancel: CancellationToken::new(),
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
}
