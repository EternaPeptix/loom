//! `bash` and the job tools.
//!
//! CONTRACT (bodies of `run` are placeholders for the implementer; `spec` is fixed).
//!
//! ## `bash`
//! 1. `cwd`: `ctx.sandbox.resolve`, must be an existing directory (else an error sentence); default
//!    `ctx.workspace`.
//! 2. `ctx.jobs.allocate()`, then `proc::spawn` with the script exactly as given, environment
//!    `ctx.sandbox.env(<this process's environment>)` overlaid with `ctx.env`.
//! 3. `background: true` → `ctx.jobs.register(...)` and return at once: outcome
//!    `started as job {id}`, body `(running in the background — job_wait("{id}") returns its output)`,
//!    meta `META_JOB`.
//! 4. Otherwise wait (`Running::wait`) with deadline = `timeout_s` if given, else
//!    `cfg.bash_foreground_s`, and `cfg.max_output_bytes`:
//!    - ended → outcome `Ended::outcome()`, fact `{seconds:.1}s`, `Body::Raw(whole output)`, meta
//!      `META_EXIT_CODE` or `META_SIGNAL`. Status `Ok` for exit 0, `Error` otherwise. The output and
//!      status files are deleted.
//!    - `timeout_s` was given and elapsed → `terminate(cfg.kill_grace_s)`; status `Timeout`, outcome
//!      `stopped after {n}s (timeout_s)`, the output so far as `Body::Raw`.
//!    - no `timeout_s` and the foreground limit elapsed → register as a job; status `Ok`, outcome
//!      `still running after {n}s — now job {id}`, `Body::Raw(output so far)`, meta `META_JOB`. The
//!      job's read position starts after what was just shown.
//!    - cancelled → `terminate`; status `Interrupted`, outcome `interrupted`, output so far.
//!    - too much output → `terminate`; status `Error`, outcome
//!      `stopped: output passed {limit} bytes`, the output so far.
//!    - spawn failure → error sentence with the OS error.
//! 5. When the exit status is not 0, the sandbox is in seatbelt mode and the output contains
//!    `Operation not permitted`, add the fact `sandboxed: writes only under the workspace and temp
//!    dir; network only via proxy` — a reminder, not a diagnosis.
//!
//! ## `job_wait` / `job_kill` / `job_list`
//! `job_wait`: `ctx.jobs.wait(job, timeout_s or cfg.job_wait_s, ctx.cancel)`. Outcome: the state's
//! outcome (`running`, `exit 0`, …); facts: `job {id}`, `{bytes} new bytes` and, while running,
//! `{elapsed}s so far`; `Body::Raw(new_output)`, or `Body::Message("(no new output)")` when there is
//! none. Status `Ok` unless the job ended with a non-zero status (`Error`).
//! `job_kill`: `ctx.jobs.kill`, same rendering, outcome prefixed by what happened.
//! `job_list`: one line per job: `{id}  {state}  {elapsed}s  {output_bytes} bytes  {command (≤ 120
//! chars)}`, or `(no jobs)`.
//! An unknown job id is an error result carrying the table's sentence.
//!
//! Tests required (real processes, sandbox mode `none`, through `crate::execute` so that the
//! envelope and the stored output are exercised): exit 0 / non-zero with the right status, facts and
//! meta; stderr captured in order; `cwd`; bad `cwd`; `timeout_s` stops and reports; foreground limit
//! promotes to a job and `job_wait` then returns only the rest; `background`; cancel; output limit;
//! job tools incl. unknown id; a long output is stored whole and the result is a cut with a handle.

use crate::jobs::{JobState, JobView};
use crate::proc::{self, Ended, Running, Spawn, WaitEnd};
use crate::{params, Body, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::config::SandboxMode;
use loom_core::event::{ToolClass, ToolSpec, ToolStatus, META_EXIT_CODE, META_JOB, META_SIGNAL};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Shown when a command failed under the seatbelt profile with a permission error.
const SANDBOX_REMINDER: &str = "sandboxed: writes only under the workspace and temp dir; network only via proxy";

/// Milliseconds as seconds with one decimal.
fn secs_text(ms: u64) -> String {
    format!("{}.{}", ms / 1000, (ms % 1000) / 100)
}

fn missing_job() -> ToolOutput {
    ToolOutput::error("No job id was given. Call the tool again with `job` set to a job id such as `j1` (job_list shows them).")
}

fn add_ended_meta(out: ToolOutput, ended: &Ended) -> ToolOutput {
    match ended {
        Ended::Exit(n) => out.with_meta(META_EXIT_CODE, json!(n)),
        Ended::Signal(s) => out.with_meta(META_SIGNAL, json!(s)),
        Ended::Unknown | Ended::Failed(_) | Ended::TrackingFailed(_) => out,
    }
}

/// What a job tool returns for a view of a job: its state, how much output there was, the output
/// that is new, and — once the job has settled — where all of it is stored.
fn render(ctx: &ToolCtx, view: JobView, outcome: Option<String>) -> ToolOutput {
    let JobView { info, new_output, from: _ } = view;
    let state_text = info.state.outcome();
    let status = match &info.state {
        JobState::Ended(e) if *e != Ended::Exit(0) => ToolStatus::Error,
        _ => ToolStatus::Ok,
    };
    let body = if new_output.is_empty() { Body::Message("(no new output)".to_string()) } else { Body::Raw(new_output.clone()) };
    let mut out = ToolOutput { status, outcome: outcome.unwrap_or(state_text), more: Vec::new(), body, meta: Map::new() };
    out = out.with_more(format!("job {}", info.id)).with_more(format!("{} new bytes", new_output.len()));
    if info.state == JobState::Running {
        let elapsed = ctx.jobs.elapsed_ms(&info.id).unwrap_or(0);
        out = out.with_more(format!("{}s so far", secs_text(elapsed)));
    }
    out = out.with_more(format!("{} bytes of output in all", info.output_bytes));
    if let Some(blob) = ctx.jobs.output_blob(&info.id) {
        out = out.with_more(format!("complete output stored as {}", blob.handle()));
    }
    out = out.with_meta(META_JOB, json!(info.id));
    match &info.state {
        JobState::Ended(e) => add_ended_meta(out, e),
        JobState::Running | JobState::Killed => out,
    }
}

pub struct Bash;
pub struct JobWait;
pub struct JobKill;
pub struct JobList;

#[async_trait]
impl Tool for Bash {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "bash",
            "Run a shell command with bash and return what it printed. stdout and stderr are captured together, in the order they were written. The complete output is always stored: when it is long you are shown its start and end, with a marker that says exactly which lines are missing and how to read them (out_read, out_grep). The result header gives the exit status. Each call starts a new shell in the workspace directory, so `cd` and variables do not carry over between calls — use `cd dir && command` or absolute paths. A command that is still running after the foreground limit is not stopped: it continues as a background job and the result tells you its job id.",
            ToolClass::Exec,
            &[
                params::req("command", "string", "The command line to run."),
                params::opt("timeout_s", "integer", "Stop the command if it has not finished after this many seconds. Leave it out to let the command run as long as it needs.").min(1),
                params::opt("background", "boolean", "Start the command as a background job and return immediately (default false). Use for servers and long runs; read its output with job_wait."),
                params::opt("cwd", "string", "Directory to run in (default: the workspace)."),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        run_bash(ctx, args).await
    }
}

#[async_trait]
impl Tool for JobWait {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "job_wait",
            "Wait for a background job to finish, or for the given time, and return the output it has produced since you last looked at it, together with its state (running, or its exit status).",
            ToolClass::Exec,
            &[
                params::req("job", "string", "The job id, e.g. `j1`."),
                params::opt("timeout_s", "integer", "How long to wait for the job to finish before returning what there is (default 120).").min(0),
            ],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(id) = args.get("job").and_then(Value::as_str) else { return missing_job() };
        let wait = args.get("timeout_s").and_then(Value::as_u64).unwrap_or(ctx.cfg.job_wait_s);
        match ctx.jobs.wait(id, Duration::from_secs(wait), &ctx.cancel).await {
            Ok(view) => render(ctx, view, None),
            Err(sentence) => ToolOutput::error(sentence),
        }
    }
}

#[async_trait]
impl Tool for JobKill {
    fn spec(&self) -> ToolSpec {
        params::spec(
            "job_kill",
            "Stop a background job and everything it started. Returns the output it produced since you last looked.",
            ToolClass::Exec,
            &[params::req("job", "string", "The job id, e.g. `j1`.")],
        )
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let Some(id) = args.get("job").and_then(Value::as_str) else { return missing_job() };
        let was_running = ctx.jobs.list().await.iter().any(|j| j.id == id && j.state == JobState::Running);
        match ctx.jobs.kill(id, Duration::from_secs(ctx.cfg.kill_grace_s)).await {
            Ok(view) => {
                let outcome = match (&view.info.state, was_running) {
                    (JobState::Running, _) => "kill sent, but the job is still running".to_string(),
                    (JobState::Killed, true) => "killed by job_kill".to_string(),
                    (state, true) => format!("had just ended on its own: {}", state.outcome()),
                    (state, false) => format!("already ended: {}", state.outcome()),
                };
                render(ctx, view, Some(outcome))
            }
            Err(sentence) => ToolOutput::error(sentence),
        }
    }
}

#[async_trait]
impl Tool for JobList {
    fn spec(&self) -> ToolSpec {
        params::spec("job_list", "List this session's background jobs with their state.", ToolClass::State, &[])
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = args;
        let jobs = ctx.jobs.list().await;
        if jobs.is_empty() {
            return ToolOutput::ok("0 jobs", Body::Message("(no jobs)".to_string()));
        }
        let lines: Vec<String> = jobs
            .iter()
            .map(|j| {
                let elapsed = secs_text(ctx.jobs.elapsed_ms(&j.id).unwrap_or(0));
                let command = crate::preview(&j.command.replace('\n', "\\n"), 120);
                format!("{}  {}  {}s  {} bytes  {}", j.id, j.state.outcome(), elapsed, j.output_bytes, command)
            })
            .collect();
        ToolOutput::ok(format!("{} jobs", jobs.len()), Body::Message(lines.join("\n")))
    }
}

fn remove_files(running: &Running) {
    let _ = std::fs::remove_file(&running.out_path);
    let _ = std::fs::remove_file(&running.exit_path);
    running.remove_owner();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Everything the command wrote so far. When the file cannot be read the call says so and names the
/// file, which is left in place.
fn read_all(running: &Running) -> Result<Vec<u8>, String> {
    running.read_output(0).map_err(|e| {
        format!(
            "The command ran, but its output could not be read back ({e}). It is in the file {} — read it with `read`, or run the command again.",
            running.out_path.display()
        )
    })
}

/// The script's environment: the sandbox's view of ours, plus what the session adds.
fn command_env(ctx: &ToolCtx) -> BTreeMap<String, String> {
    let parent: BTreeMap<String, String> =
        std::env::vars_os().filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?))).collect();
    let mut env = ctx.sandbox.env(&parent);
    for (k, v) in ctx.env.iter() {
        env.insert(k.clone(), v.clone());
    }
    env
}

/// The result for a command that is over (it ended, or we stopped it).
struct Finish<'a> {
    ctx: &'a ToolCtx,
    status: ToolStatus,
    outcome: String,
    ended: &'a Ended,
    output: Vec<u8>,
    elapsed: Duration,
    facts: Vec<String>,
}

fn finish(f: Finish<'_>) -> ToolOutput {
    let Finish { ctx, status, outcome, ended, mut output, elapsed, facts } = f;
    if let Ended::Failed(text) = ended {
        output.extend_from_slice(format!("\n[the command could not be started: {text}]\n").as_bytes());
    }
    if let Ended::TrackingFailed(text) = ended {
        output.extend_from_slice(format!("\n[process tracking failed: {text}]\n").as_bytes());
    }
    let mut out = ToolOutput { status, outcome, more: Vec::new(), body: Body::Raw(Vec::new()), meta: Map::new() };
    out = out.with_more(format!("{:.1}s", elapsed.as_secs_f64()));
    for fact in facts {
        out = out.with_more(fact);
    }
    if *ended != Ended::Exit(0)
        && ctx.sandbox.mode() == SandboxMode::Seatbelt
        && contains(&output, b"Operation not permitted")
    {
        out = out.with_more(SANDBOX_REMINDER);
    }
    out.body = Body::Raw(output);
    add_ended_meta(out, ended)
}

async fn run_bash(ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
    let Some(command) = args.get("command").and_then(Value::as_str) else {
        return ToolOutput::error("No command was given. Call bash again with `command` set to the command line to run.");
    };
    let timeout_s = args.get("timeout_s").and_then(Value::as_u64);
    let background = args.get("background").and_then(Value::as_bool).unwrap_or(false);
    let cwd = match args.get("cwd").and_then(Value::as_str) {
        Some(given) => ctx.sandbox.resolve(given),
        None => ctx.workspace.clone(),
    };
    if !Path::new(&cwd).is_dir() {
        return ToolOutput::error(format!(
            "The directory `{}` does not exist or is not a directory, so nothing was run. Check the path (relative paths start at the workspace, {}) or leave `cwd` out.",
            cwd.display(),
            ctx.workspace.display()
        ));
    }
    let (id, out_path, exit_path) = match ctx.jobs.allocate().await {
        Ok(a) => a,
        Err(e) => return ToolOutput::error(format!("Nothing was run: the harness could not prepare the output files for the command ({e}). Try the call again.")),
    };
    let spec = Spawn { script: command.to_string(), cwd, env: command_env(ctx), out_path, exit_path };
    let started = Instant::now();
    let mut running = match proc::spawn(&ctx.sandbox, &spec) {
        Ok(r) => r,
        Err(e) => {
            let _ = std::fs::remove_file(&spec.out_path);
            let _ = std::fs::remove_file(&spec.exit_path);
            return ToolOutput::error(format!("The command could not be started ({e}). Nothing ran; try the call again."));
        }
    };

    if background {
        ctx.jobs.register(&id, &ctx.call_id, command, running).await;
        let mut out = ToolOutput::ok(
            format!("started as job {id}"),
            Body::Message(format!("(running in the background — job_wait(\"{id}\") returns its output)")),
        );
        out = out.with_meta(META_JOB, json!(id));
        return out;
    }

    let limit = ctx.cfg.max_output_bytes;
    let allowed = Duration::from_secs(timeout_s.unwrap_or(ctx.cfg.bash_foreground_s));
    let grace = Duration::from_secs(ctx.cfg.kill_grace_s);
    let mut end = running.wait(&ctx.cancel, Some(allowed), limit).await;
    if end == WaitEnd::Deadline {
        // It may have ended in the instant between the deadline and now.
        if let Some(e) = running.poll() {
            end = WaitEnd::Ended(e);
        }
    }
    let elapsed = started.elapsed();

    match end {
        WaitEnd::Ended(ended) => {
            let output = match read_all(&running) {
                Ok(o) => o,
                Err(e) => return ToolOutput::error(e),
            };
            remove_files(&running);
            let status = if ended == Ended::Exit(0) { ToolStatus::Ok } else { ToolStatus::Error };
            finish(Finish { ctx, status, outcome: ended.outcome(), ended: &ended, output, elapsed, facts: Vec::new() })
        }
        WaitEnd::Deadline if timeout_s.is_none() => {
            // Not stopped: the command goes on as a job, and the first job_wait starts after what is shown here.
            let shown = match read_all(&running) {
                Ok(o) => o,
                Err(e) => {
                    ctx.jobs.register(&id, &ctx.call_id, command, running).await;
                    return ToolOutput::error(format!("{e} The command is still running as job {id}; job_wait(\"{id}\") returns its output.")).with_meta(META_JOB, json!(id));
                }
            };
            ctx.jobs.register_from(&id, &ctx.call_id, command, running, shown.len() as u64).await;
            let n = allowed.as_secs();
            ToolOutput {
                status: ToolStatus::Ok,
                outcome: format!("still running after {n}s — now job {id}"),
                more: vec![
                    format!("{:.1}s", elapsed.as_secs_f64()),
                    format!("still running, not finished; follow it with job_wait(\"{id}\"), stop it with job_kill(\"{id}\")"),
                ],
                body: Body::Raw(shown),
                meta: Map::new(),
            }
            .with_meta(META_JOB, json!(id))
        }
        WaitEnd::Deadline | WaitEnd::Cancelled | WaitEnd::TooMuchOutput => {
            let ended = running.terminate(grace).await;
            let output = match read_all(&running) {
                Ok(o) => o,
                Err(e) => return ToolOutput::error(e),
            };
            remove_files(&running);
            let (status, outcome) = match end {
                WaitEnd::Cancelled => (ToolStatus::Interrupted, "interrupted".to_string()),
                WaitEnd::TooMuchOutput => (ToolStatus::Error, format!("stopped: output passed {limit} bytes")),
                _ => (ToolStatus::Timeout, format!("stopped after {}s (timeout_s)", allowed.as_secs())),
            };
            let facts = vec![format!("the command's own status after it was stopped: {}", ended.outcome())];
            finish(Finish { ctx, status, outcome, ended: &ended, output, elapsed, facts })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::jobs::JobEvent;
    use crate::testutil::{env, env_with, TestEnv};
    use loom_core::config::{SandboxCfg, SandboxMode, ToolsCfg};
    use loom_core::event::{ToolResult, ToolStatus, META_EXIT_CODE, META_JOB, META_SIGNAL};
    use serde_json::json;
    use std::time::Duration;

    fn bash_env(cfg: ToolsCfg) -> TestEnv {
        env_with(cfg, SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() })
    }

    fn alive(pid: i32) -> bool {
        // SAFETY: signal 0 only tests for existence.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    async fn pid_from(path: &std::path::Path) -> i32 {
        for _ in 0..200 {
            if let Some(p) = std::fs::read_to_string(path).ok().and_then(|t| t.trim().parse().ok()) {
                return p;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("no pid in {}", path.display());
    }

    fn header(r: &ToolResult) -> &str {
        r.text.lines().next().unwrap_or_default()
    }

    #[tokio::test]
    async fn exit_zero_is_ok_with_status_duration_and_stored_output() {
        let e = env();
        let r = e.call("bash", json!({"command": "echo hello"})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.text.contains("exit 0"), "{}", r.text);
        assert!(r.text.contains("hello"), "{}", r.text);
        assert!(header(&r).contains("s"), "{}", r.text);
        assert_eq!(r.meta.get(META_EXIT_CODE), Some(&json!(0)));
        assert!(r.meta.get(META_SIGNAL).is_none());
        assert_eq!(e.stored(&r), "hello\n");
        // The call's own files are gone.
        let left: Vec<_> = std::fs::read_dir(e.dir.path().join("home/jobs")).expect("jobs dir").collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[tokio::test]
    async fn a_failing_command_is_an_error_with_its_code() {
        let e = env();
        let r = e.call("bash", json!({"command": "echo bad; exit 7"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("exit 7"), "{}", r.text);
        assert_eq!(r.meta.get(META_EXIT_CODE), Some(&json!(7)));
        assert_eq!(e.stored(&r), "bad\n");
    }

    #[tokio::test]
    async fn a_command_killed_by_a_signal_reports_the_signal() {
        let e = env();
        let r = e.call("bash", json!({"command": "echo before; kill -9 $$"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("killed by signal 9 (KILL)"), "{}", r.text);
        assert_eq!(r.meta.get(META_SIGNAL), Some(&json!(9)));
        assert!(r.meta.get(META_EXIT_CODE).is_none());
    }

    #[tokio::test]
    async fn stdout_and_stderr_are_captured_in_the_order_written() {
        let e = env();
        let r = e.call("bash", json!({"command": "echo a; echo b >&2; echo c; echo d >&2"})).await;
        assert_eq!(e.stored(&r), "a\nb\nc\nd\n");
    }

    #[tokio::test]
    async fn cwd_is_resolved_against_the_workspace_and_must_exist() {
        let e = env();
        std::fs::create_dir_all(e.ctx.workspace.join("sub")).expect("mkdir");
        let r = e.call("bash", json!({"command": "pwd", "cwd": "sub"})).await;
        assert_eq!(e.stored(&r).trim(), e.ctx.workspace.join("sub").to_str().expect("utf-8"));
        let r = e.call("bash", json!({"command": "pwd"})).await;
        assert_eq!(e.stored(&r).trim(), e.ctx.workspace.to_str().expect("utf-8"));
        let r = e.call("bash", json!({"command": "pwd", "cwd": "nope"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("does not exist") && r.text.contains("nope"), "{}", r.text);
        std::fs::write(e.ctx.workspace.join("file"), "x").expect("write");
        let r = e.call("bash", json!({"command": "pwd", "cwd": "file"})).await;
        assert_eq!(r.status, ToolStatus::Error);
    }

    #[tokio::test]
    async fn timeout_stops_the_command_and_reports_it() {
        let e = env();
        let pidfile = e.ctx.tmp_dir.join("pid");
        let script = format!("echo start; sleep 300 & echo $! > {}; wait", pidfile.display());
        let t = std::time::Instant::now();
        let r = e.call("bash", json!({"command": script, "timeout_s": 1})).await;
        assert!(t.elapsed() < Duration::from_secs(30));
        assert_eq!(r.status, ToolStatus::Timeout);
        assert!(r.text.contains("stopped after 1s (timeout_s)"), "{}", r.text);
        assert!(r.text.contains("signal"), "{}", r.text);
        assert_eq!(e.stored(&r), "start\n");
        let pid = pid_from(&pidfile).await;
        for _ in 0..100 {
            if !alive(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("a child outlived the timeout");
    }

    #[tokio::test]
    async fn the_foreground_limit_promotes_to_a_job_and_job_wait_returns_only_the_rest() {
        let cfg = ToolsCfg { bash_foreground_s: 1, ..ToolsCfg::default() };
        let mut e = bash_env(cfg);
        let r = e.call("bash", json!({"command": "echo first; sleep 2; echo second; sleep 300"})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.text.contains("still running after 1s — now job j1"), "{}", r.text);
        assert!(r.text.contains("job_wait(\"j1\")"), "{}", r.text);
        assert!(!r.text.contains("exit 0"), "{}", r.text);
        assert_eq!(r.meta.get(META_JOB), Some(&json!("j1")));
        assert_eq!(e.stored(&r), "first\n");
        assert!(matches!(e.job_events.try_recv(), Ok(JobEvent::Registered(_))));

        let w = e.call("job_wait", json!({"job": "j1", "timeout_s": 10})).await;
        assert!(w.text.contains("job j1") && w.text.contains("running"), "{}", w.text);
        let mut seen = String::new();
        if w.output.is_some() {
            seen.push_str(&e.stored(&w));
        }
        assert!(!seen.contains("first"), "{seen}");
        // Whatever arrives later is also new; together with the first view nothing repeats or is missing.
        for _ in 0..40 {
            if seen.contains("second") {
                break;
            }
            let w = e.call("job_wait", json!({"job": "j1", "timeout_s": 1})).await;
            if w.output.is_some() {
                seen.push_str(&e.stored(&w));
            }
        }
        assert_eq!(seen, "second\n");

        let k = e.call("job_kill", json!({"job": "j1"})).await;
        assert!(k.text.contains("killed"), "{}", k.text);
        let settled = tokio::time::timeout(Duration::from_secs(10), e.job_events.recv()).await.expect("event").expect("open");
        let JobEvent::Settled { output, .. } = settled else { panic!("Settled") };
        let whole = e.ctx.blobs.read_all(&output.expect("stored").id).expect("read");
        assert_eq!(whole, b"first\nsecond\n");
    }

    #[tokio::test]
    async fn background_returns_at_once_and_job_wait_gives_the_output() {
        let mut e = env();
        let t = std::time::Instant::now();
        let r = e.call("bash", json!({"command": "echo bg; sleep 1; echo done", "background": true})).await;
        assert!(t.elapsed() < Duration::from_secs(1));
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.text.contains("started as job j1") && r.text.contains("job_wait(\"j1\")"), "{}", r.text);
        assert_eq!(r.meta.get(META_JOB), Some(&json!("j1")));
        let w = e.call("job_wait", json!({"job": "j1", "timeout_s": 30})).await;
        assert_eq!(w.status, ToolStatus::Ok);
        assert!(w.text.contains("exit 0"), "{}", w.text);
        assert!(w.text.contains("complete output stored as out:"), "{}", w.text);
        assert_eq!(w.meta.get(META_EXIT_CODE), Some(&json!(0)));
        assert_eq!(e.stored(&w), "bg\ndone\n");
        assert!(matches!(e.job_events.recv().await, Some(JobEvent::Registered(_))));
        assert!(matches!(e.job_events.recv().await, Some(JobEvent::Settled { .. })));
        // Nothing new now.
        let w = e.call("job_wait", json!({"job": "j1"})).await;
        assert!(w.text.contains("(no new output)") && w.text.contains("0 new bytes"), "{}", w.text);
    }

    #[tokio::test]
    async fn a_failed_job_is_an_error_result() {
        let e = env();
        e.call("bash", json!({"command": "echo no; exit 4", "background": true})).await;
        let w = e.call("job_wait", json!({"job": "j1", "timeout_s": 30})).await;
        assert_eq!(w.status, ToolStatus::Error);
        assert!(w.text.contains("exit 4"), "{}", w.text);
        assert_eq!(w.meta.get(META_EXIT_CODE), Some(&json!(4)));
    }

    #[tokio::test]
    async fn cancel_stops_the_whole_group_and_reports_interrupted() {
        let e = env();
        let pidfile = e.ctx.tmp_dir.join("pid");
        let script = format!("echo partial; sleep 300 & echo $! > {}; wait", pidfile.display());
        let cancel = e.ctx.cancel.clone();
        let canceller = async {
            let _ = pid_from(&pidfile).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            cancel.cancel();
        };
        let (r, ()) = tokio::join!(e.call("bash", json!({"command": script})), canceller);
        assert_eq!(r.status, ToolStatus::Interrupted);
        assert!(r.text.contains("interrupted"), "{}", r.text);
        assert_eq!(e.stored(&r), "partial\n");
        let pid = pid_from(&pidfile).await;
        for _ in 0..100 {
            if !alive(pid) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("a child outlived the cancel");
    }

    #[tokio::test]
    async fn too_much_output_stops_the_command() {
        let cfg = ToolsCfg { max_output_bytes: 2_000, ..ToolsCfg::default() };
        let e = bash_env(cfg);
        let r = e.call("bash", json!({"command": "yes"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("stopped: output passed 2000 bytes"), "{}", r.text);
        assert!(e.stored(&r).len() > 2_000);
    }

    #[tokio::test]
    async fn job_tools_report_unknown_ids_and_list_jobs() {
        let e = env();
        let l = e.call("job_list", json!({})).await;
        assert!(l.text.contains("(no jobs)"), "{}", l.text);
        for tool in ["job_wait", "job_kill"] {
            let r = e.call(tool, json!({"job": "j9"})).await;
            assert_eq!(r.status, ToolStatus::Error);
            assert!(r.text.contains("no job `j9`"), "{}", r.text);
        }
        e.call("bash", json!({"command": "sleep 300", "background": true})).await;
        e.call("bash", json!({"command": "echo x\necho y; exit 2", "background": true})).await;
        let w = e.call("job_wait", json!({"job": "j2", "timeout_s": 30})).await;
        assert!(w.text.contains("exit 2"), "{}", w.text);
        let r = e.call("job_wait", json!({"job": "j9"})).await;
        assert!(r.text.contains("j1, j2"), "{}", r.text);

        let l = e.call("job_list", json!({})).await;
        let lines: Vec<&str> = l.text.lines().filter(|l| l.starts_with('j')).collect();
        assert_eq!(lines.len(), 2, "{}", l.text);
        assert!(lines[0].starts_with("j1  running  ") && lines[0].ends_with("0 bytes  sleep 300"), "{}", lines[0]);
        assert!(lines[1].starts_with("j2  exit 2  ") && lines[1].contains("4 bytes") && lines[1].ends_with("echo x\\necho y; exit 2"), "{}", lines[1]);

        let k = e.call("job_kill", json!({"job": "j1"})).await;
        assert_eq!(k.status, ToolStatus::Ok);
        assert!(k.text.contains("killed by job_kill"), "{}", k.text);
        let k = e.call("job_kill", json!({"job": "j1"})).await;
        assert_eq!(k.status, ToolStatus::Ok);
        assert!(k.text.contains("already ended: killed"), "{}", k.text);
        let k = e.call("job_kill", json!({"job": "j2"})).await;
        assert!(k.text.contains("already ended: exit 2"), "{}", k.text);
        let l = e.call("job_list", json!({})).await;
        assert!(l.text.contains("j1  killed  "), "{}", l.text);
    }

    #[tokio::test]
    async fn long_output_is_stored_whole_and_the_result_is_a_cut_with_a_handle() {
        let e = env();
        let r = e.call("bash", json!({"command": "seq 1 100000"})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.cut);
        assert!(r.text.contains("exit 0") && r.text.contains("out:"), "{}", r.text);
        let whole = e.stored(&r);
        assert_eq!(whole.lines().count(), 100_000);
        assert!(whole.ends_with("99999\n100000\n"));
        assert!(r.text.len() < whole.len() / 4);
    }

    #[tokio::test]
    async fn the_seatbelt_reminder_follows_a_permission_failure() {
        if !std::path::Path::new("/usr/bin/sandbox-exec").exists() {
            return;
        }
        let Some(home) = std::env::var_os("HOME") else { return };
        let Ok(outside) = tempfile::Builder::new().prefix("loom-bash-").tempdir_in(home) else { return };
        let e = env_with(ToolsCfg::default(), SandboxCfg { mode: SandboxMode::Seatbelt, ..SandboxCfg::default() });
        let target = outside.path().join("f");
        let r = e.call("bash", json!({"command": format!("echo x > {}", target.display())})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("sandboxed: writes only under the workspace and temp dir; network only via proxy"), "{}", r.text);
        let r = e.call("bash", json!({"command": "echo fine; echo more > ok.txt"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(!r.text.contains("sandboxed:"));
        let r = e.call("bash", json!({"command": "echo 'Operation not permitted'; exit 1"})).await;
        assert!(r.text.contains("sandboxed:"), "{}", r.text);
        let r = e.call("bash", json!({"command": "echo 'Operation not permitted'"})).await;
        assert!(!r.text.contains("sandboxed:"), "{}", r.text);
    }
}
