//! `bash` and the job tools.
//!
//! CONTRACT.
//!
//! ## `bash`
//! Pack-enabled command guards reject known interactive/unbounded patterns before a spawn. They
//! are hygiene checks rather than shell containment; arbitrary scripts remain subject to sandbox,
//! output, cancellation and time limits. Optional idle_timeout_s terminates a silent foreground call.
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
//!    - `timeout_s` was given and elapsed → `terminate_within(cfg.kill_grace_s, cfg.max_output_bytes)`
//!      (the grace period ends early when the output passes the limit); status `Timeout`, outcome
//!      `stopped after {n}s (timeout_s)`, the output so far as `Body::Raw`.
//!    - no `timeout_s` and the foreground limit elapsed → register as a job; status `Ok`, outcome
//!      `still running after {n}s — now job {id}`, `Body::Raw(output so far)`, meta `META_JOB`. The
//!      job's read position starts after what was just shown.
//!    - cancelled → `terminate`; status `Interrupted`, outcome `interrupted`, output so far.
//!    - too much output → the group is SIGKILLed at once (a command that ignores TERM would keep
//!      writing through a grace period); status `Error`, outcome `stopped: output passed {limit}
//!      bytes`, the first `{limit}` bytes of the output (a fact gives the file's true size). No output
//!      is ever read back beyond `max_output_bytes`.
//!    - ended while other processes of its group still run, and they are still there after a short
//!      settle window (`GROUP_SETTLE`, for helpers bash does not wait for) → the leader's status in
//!      the outcome and the output so far, and the rest continues as a job (fact with the job id,
//!      `job_wait`, `job_kill`). Meta is `META_JOB` only, as for the foreground limit: a result that
//!      also carried `META_EXIT_CODE` or `META_SIGNAL` would tell the session that the end of this job
//!      has already been shown, and its settlement would then not be reported.
//!    - spawn failure → error sentence with the OS error.
//! 5. When the exit status is not 0, the sandbox is in seatbelt mode and the output contains
//!    `Operation not permitted`, add the fact `sandboxed: writes only under the workspace and temp
//!    dir; network only via proxy` — a reminder, not a diagnosis.
//! 6. `wake_on` (a regular expression) makes whatever job the call leaves behind a watched one
//!    (`jobs`, "Watched output"): `Watch::new(wake_on, wake_every_s or cfg.job_wake_gap_s,
//!    cfg.job_wake_max)`, whose refusal is the error result, before anything is spawned. Every
//!    registration above passes it on (`register_watched`), so the watch starts after the output the
//!    result showed. The result of a call that leaves a watched job carries the fact `watched: you
//!    are told, and resumed if you are waiting, when its output has a line matching /{pattern}/`
//!    (for `background` the body ends with that sentence instead). `wake_on` on a command that ends
//!    in the foreground does nothing, and `wake_every_s` without `wake_on` is ignored.
//!
//! ## `job_wait` / `job_kill` / `job_list`
//! `job_wait`: `ctx.jobs.wait(job, timeout_s or cfg.job_wait_s, ctx.cancel)`. Outcome: the state's
//! outcome (`running`, `exit 0`, …); facts: `job {id}`, `{bytes} new bytes` and, while running,
//! `{elapsed}s so far`; `Body::Raw(new_output)`, or `Body::Message("(no new output)")` when there is
//! none. Status `Ok` unless the job ended with a non-zero status (`Error`). While a job runs on after
//! its own command has exited, a fact gives that command's status. Once the job has settled a fact
//! names the stored output: `complete output stored as …`, or, when the job wrote more than
//! `max_output_bytes`, `the first {limit} bytes of output are stored as …`; and the settled job's
//! `detail`, when it has one, is a fact too (stopped for the output limit, the rest of the output
//! discarded, storage failure).
//! `job_kill`: `ctx.jobs.kill`, same rendering, outcome prefixed by what happened.
//! `job_list`: one line per job: `{id}  {state}  {elapsed}s  {output_bytes} bytes  {command (≤ 120
//! chars)}`, or `(no jobs)`; the state of a job that runs on after its own command has exited is
//! `running (the command itself has exited: {status})`, and a job whose watch can still report has
//! `, watched for /{pattern}/` after `running`.
//! An unknown job id is an error result carrying the table's sentence.
//!
//! Tests required (real processes, sandbox mode `none`, through `crate::execute` so that the
//! envelope and the stored output are exercised): exit 0 / non-zero with the right status, facts and
//! meta; stderr captured in order; `cwd`; bad `cwd`; `timeout_s` stops and reports; foreground limit
//! promotes to a job and `job_wait` then returns only the rest; `background`; cancel; output limit;
//! job tools incl. unknown id; a long output is stored whole and the result is a cut with a handle;
//! `wake_on` on a background call and on a promoted one (the watch starts after what was shown), a
//! refused pattern runs nothing, `job_list` names the watch.

use crate::jobs::{JobState, JobView, Watch};
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

/// How long a foreground command's process group gets to empty after its leader has exited before
/// what is left of it is handed over as a job.
const GROUP_SETTLE: Duration = Duration::from_millis(200);

/// Milliseconds as seconds with one decimal.
fn secs_text(ms: u64) -> String {
    format!("{}.{}", ms / 1000, (ms % 1000) / 100)
}

fn missing_job() -> ToolOutput {
    ToolOutput::error(
        "No job id was given. Call the tool again with `job` set to a job id such as `j1` (job_list shows them).",
    )
}

fn add_ended_meta(out: ToolOutput, ended: &Ended) -> ToolOutput {
    match ended {
        Ended::Exit(n) => out.with_meta(META_EXIT_CODE, json!(n)),
        Ended::Signal(s) => out.with_meta(META_SIGNAL, json!(s)),
        Ended::Unknown | Ended::Failed(_) => out,
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
    let body = if new_output.is_empty() {
        Body::Message("(no new output)".to_string())
    } else {
        Body::Raw(new_output.clone())
    };
    let mut out =
        ToolOutput { status, outcome: outcome.unwrap_or(state_text), more: Vec::new(), body, meta: Map::new() };
    out = out.with_more(format!("job {}", info.id)).with_more(format!("{} new bytes", new_output.len()));
    if info.state == JobState::Running {
        let elapsed = ctx.jobs.elapsed_ms(&info.id).unwrap_or(0);
        out = out.with_more(format!("{}s so far", secs_text(elapsed)));
        if let Some(leader) = ctx.jobs.leader_status(&info.id) {
            out = out.with_more(format!(
                "the command itself has exited: {}; other processes it started are still running",
                leader.outcome()
            ));
        }
    }
    out = out.with_more(format!("{} bytes of output in all", info.output_bytes));
    if let Some(blob) = ctx.jobs.output_blob(&info.id) {
        let limit = ctx.cfg.max_output_bytes;
        out = out.with_more(if info.output_bytes > limit {
            // The detail below says that the rest was discarded.
            format!("the first {limit} bytes of output are stored as {}", blob.handle())
        } else {
            format!("complete output stored as {}", blob.handle())
        });
    }
    // Why it ended, when that needs saying: stopped for its output, output discarded, storage failure.
    if let Some(detail) = ctx.jobs.detail(&info.id) {
        out = out.with_more(detail);
    }
    out = out.with_meta(META_JOB, json!(info.id));
    match &info.state {
        JobState::Ended(e) => {
            let out = match e.fact() {
                Some(fact) => out.with_more(fact),
                None => out,
            };
            add_ended_meta(out, e)
        }
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
                params::opt("idle_timeout_s", "integer", "Stop a foreground command after this many seconds without output. Silent computation can also trigger it; omitted means no idle watchdog.").min(1).max(300),
                params::opt("wake_on", "string", "For a background job: a regular expression. When a line of the job's output matches it you are told at once, with the matching lines and the handle of that part of the output, and if you had ended your turn with `wait` you are resumed, as when a job ends. Use it for a fuzzer, cracker, scan or listener that runs for hours and matters only when it finds something, e.g. `(?i)crash|panic|FOUND`. Rust regex syntax, matched line by line."),
                params::opt("wake_every_s", "integer", "With `wake_on`: tell you at most once in this many seconds; lines that match in between come with the next notice (default 30).").min(1).max(3600),
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
        // Its own command had already exited and only what that left running is there to stop.
        let leftovers_only = was_running && ctx.jobs.leader_status(id).is_some();
        match ctx.jobs.kill(id, Duration::from_secs(ctx.cfg.kill_grace_s)).await {
            Ok(view) => {
                let outcome = match (&view.info.state, was_running) {
                    (JobState::Running, _) => "kill sent, but the job is still running".to_string(),
                    (JobState::Killed, true) => "killed by job_kill".to_string(),
                    (state, true) if leftovers_only => {
                        format!("stopped by job_kill; the command itself had already exited: {}", state.outcome())
                    }
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
                let state = match ctx.jobs.leader_status(&j.id).filter(|_| j.state == JobState::Running) {
                    Some(leader) => format!("running (the command itself has exited: {})", leader.outcome()),
                    None => j.state.outcome(),
                };
                let watched = match ctx.jobs.watching(&j.id) {
                    Some(pattern) => format!(", watched for /{}/", crate::preview(&pattern, 60)),
                    None => String::new(),
                };
                format!("{}  {}{}  {}s  {} bytes  {}", j.id, state, watched, elapsed, j.output_bytes, command)
            })
            .collect();
        ToolOutput::ok(format!("{} jobs", jobs.len()), Body::Message(lines.join("\n")))
    }
}

fn remove_files(running: &Running) {
    let _ = std::fs::remove_file(&running.out_path);
    remove_records(running);
}

/// Removes the status file and the pid record of a command that is over, and leaves its output file:
/// a record left behind would make the next daemon start take the command for a crashed one.
fn remove_records(running: &Running) {
    let _ = std::fs::remove_file(&running.exit_path);
    let _ = std::fs::remove_file(proc::pid_path(&running.out_path));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// What the command wrote so far, but at most `limit` bytes, and a note when the file was longer.
/// When the file cannot be read the call says so and names the file, which is left in place.
fn read_all(running: &Running, limit: u64) -> Result<(Vec<u8>, Option<String>), String> {
    let (bytes, size) = running.read_output_capped(limit).map_err(|e| {
        format!(
            "The command ran, but its output could not be read back ({e}). It is in the file {} — read it with `read`, or run the command again.",
            running.out_path.display()
        )
    })?;
    let note = (size > bytes.len() as u64).then(|| {
        format!(
            "the command wrote {size} bytes in all; only the first {} bytes were kept and the rest was discarded",
            bytes.len()
        )
    });
    Ok((bytes, note))
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
    /// The job that the rest of the command's process group continues as, when it left one running.
    job: Option<&'a str>,
}

fn finish(f: Finish<'_>) -> ToolOutput {
    let Finish { ctx, status, outcome, ended, mut output, elapsed, facts, job } = f;
    if let Ended::Failed(text) = ended {
        output.extend_from_slice(format!("\n[the command could not be started: {text}]\n").as_bytes());
    }
    let mut out = ToolOutput { status, outcome, more: Vec::new(), body: Body::Raw(Vec::new()), meta: Map::new() };
    out = out.with_more(format!("{:.1}s", elapsed.as_secs_f64()));
    for fact in facts {
        out = out.with_more(fact);
    }
    if let Some(fact) = ended.fact() {
        out = out.with_more(fact);
    }
    if *ended != Ended::Exit(0)
        && ctx.sandbox.mode() == SandboxMode::Seatbelt
        && contains(&output, b"Operation not permitted")
    {
        out = out.with_more(SANDBOX_REMINDER);
    }
    out.body = Body::Raw(output);
    match job {
        // No exit meta beside the job id: that pair means "the end of this job has been shown", and
        // the session would then not report the job when it settles.
        Some(id) => out.with_meta(META_JOB, json!(id)),
        None => add_ended_meta(out, ended),
    }
}

/// What the result of a call says about the watch on the job it leaves behind.
fn watched_fact(watch: &Watch) -> String {
    format!(
        "watched: you are told, and resumed if you are waiting, when its output has a line matching /{}/",
        crate::preview(watch.pattern(), 120)
    )
}

async fn run_bash(ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
    let Some(command) = args.get("command").and_then(Value::as_str) else {
        return ToolOutput::error(
            "No command was given. Call bash again with `command` set to the command line to run.",
        );
    };
    let timeout_s = args.get("timeout_s").and_then(Value::as_u64);
    if ctx.capabilities.command_guard {
        if let Err(e) = crate::capabilities::guard_script(command) {
            return ToolOutput::denied(e);
        }
    }
    let background = args.get("background").and_then(Value::as_bool).unwrap_or(false);
    let watch = match args.get("wake_on").and_then(Value::as_str) {
        Some(pattern) => {
            let gap = args.get("wake_every_s").and_then(Value::as_u64).unwrap_or(ctx.cfg.job_wake_gap_s);
            match Watch::new(pattern, Duration::from_secs(gap), ctx.cfg.job_wake_max) {
                Ok(watch) => Some(watch),
                Err(sentence) => return ToolOutput::error(format!("{sentence} Nothing was run.")),
            }
        }
        None => None,
    };
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
            return ToolOutput::error(format!(
                "The command could not be started ({e}). Nothing ran; try the call again."
            ));
        }
    };

    if background {
        let watched = watch.as_ref().map(|w| format!("; {}", watched_fact(w))).unwrap_or_default();
        ctx.jobs.register_watched(&id, &ctx.call_id, command, running, 0, watch).await;
        let mut out = ToolOutput::ok(
            format!("started as job {id}"),
            Body::Message(format!("(running in the background — job_wait(\"{id}\") returns its output{watched})")),
        );
        out = out.with_meta(META_JOB, json!(id));
        return out;
    }

    let limit = ctx.cfg.max_output_bytes;
    let allowed = Duration::from_secs(timeout_s.unwrap_or(ctx.cfg.bash_foreground_s));
    let grace = Duration::from_secs(ctx.cfg.kill_grace_s);
    let mut idle_stopped = false;
    let mut end = if let Some(idle) = args.get("idle_timeout_s").and_then(Value::as_u64) {
        let mut last = Instant::now();
        let mut size = running.output_len();
        loop {
            let left = allowed.saturating_sub(started.elapsed());
            if left.is_zero() {
                break WaitEnd::Deadline;
            }
            let end = running.wait(&ctx.cancel, Some(left.min(Duration::from_millis(100))), limit).await;
            if end != WaitEnd::Deadline {
                break end;
            }
            let now_size = running.output_len();
            if now_size != size {
                size = now_size;
                last = Instant::now();
            }
            if last.elapsed() >= Duration::from_secs(idle.clamp(1, 300)) {
                idle_stopped = true;
                break WaitEnd::Deadline;
            }
        }
    } else {
        running.wait(&ctx.cancel, Some(allowed), limit).await
    };
    if idle_stopped {
        let ended = running.terminate_within(grace, limit).await;
        let (output, note) = match read_all(&running, limit) {
            Ok(v) => v,
            Err(e) => {
                remove_records(&running);
                return ToolOutput::error(format!("Idle watchdog stopped the process group. {e}"));
            }
        };
        remove_files(&running);
        return finish(Finish { ctx, status: ToolStatus::Timeout, outcome: "stopped: no output during idle timeout".into(), ended: &ended, output, elapsed: started.elapsed(), facts: note.into_iter().chain(["Silent computation can trigger this watchdog. Use batch flags for interactive tools, pty_open for interactive input, or omit idle_timeout_s for silent work.".into()]).collect(), job: None });
    }
    if end == WaitEnd::Deadline {
        // It may have ended in the instant between the deadline and now.
        if let Some(e) = running.poll() {
            end = WaitEnd::Ended(e);
        }
    }
    let elapsed = started.elapsed();

    match end {
        WaitEnd::Ended(ended) => {
            // What bash does not wait for (a process substitution, a helper that takes milliseconds) gets
            // a moment to finish: only a group that is still there afterwards goes on as a job, and the
            // output read below includes what those processes were still writing.
            if running.group_alive() {
                let _ = running.wait_group(&ctx.cancel, Some(GROUP_SETTLE), limit).await;
            }
            // Asked before the read so that the output shown is final when no process is left.
            let group_runs = running.group_alive();
            let (output, note) = match read_all(&running, limit) {
                Ok(o) => o,
                Err(e) if group_runs => {
                    // Not dropped, which would kill them unannounced: what is left goes on as a job.
                    ctx.jobs.register_watched(&id, &ctx.call_id, command, running, 0, watch).await;
                    return ToolOutput::error(format!(
                        "{e} The command itself has ended ({}); other processes it started are still running as job {id}: job_wait(\"{id}\") returns their output, job_kill(\"{id}\") stops them.",
                        ended.outcome()
                    ))
                    .with_meta(META_JOB, json!(id));
                }
                Err(e) => {
                    // The message names the output file, which stays.
                    remove_records(&running);
                    return ToolOutput::error(e);
                }
            };
            let status = if ended == Ended::Exit(0) { ToolStatus::Ok } else { ToolStatus::Error };
            let mut facts: Vec<String> = note.into_iter().collect();
            if group_runs {
                // The leader is over, the rest of its group is not: it goes on as a job, from after what is shown.
                facts.extend(watch.as_ref().map(watched_fact));
                ctx.jobs.register_watched(&id, &ctx.call_id, command, running, output.len() as u64, watch).await;
                facts.push(format!(
                    "other processes it started are still running, not finished — now job {id}; follow them with job_wait(\"{id}\"), stop them with job_kill(\"{id}\")"
                ));
                return finish(Finish {
                    ctx,
                    status,
                    outcome: ended.outcome(),
                    ended: &ended,
                    output,
                    elapsed,
                    facts,
                    job: Some(&id),
                });
            }
            remove_files(&running);
            finish(Finish { ctx, status, outcome: ended.outcome(), ended: &ended, output, elapsed, facts, job: None })
        }
        WaitEnd::Deadline if timeout_s.is_none() => {
            // Not stopped: the command goes on as a job, and the first job_wait starts after what is shown here.
            let (shown, note) = match read_all(&running, limit) {
                Ok(o) => o,
                Err(e) => {
                    ctx.jobs.register_watched(&id, &ctx.call_id, command, running, 0, watch).await;
                    return ToolOutput::error(format!(
                        "{e} The command is still running as job {id}; job_wait(\"{id}\") returns its output."
                    ))
                    .with_meta(META_JOB, json!(id));
                }
            };
            let watched = watch.as_ref().map(watched_fact);
            ctx.jobs.register_watched(&id, &ctx.call_id, command, running, shown.len() as u64, watch).await;
            let n = allowed.as_secs();
            ToolOutput {
                status: ToolStatus::Ok,
                outcome: format!("still running after {n}s — now job {id}"),
                more: [
                    Some(format!("{:.1}s", elapsed.as_secs_f64())),
                    Some(format!("still running, not finished; follow it with job_wait(\"{id}\"), stop it with job_kill(\"{id}\")")),
                    watched,
                    note,
                ]
                .into_iter()
                .flatten()
                .collect(),
                body: Body::Raw(shown),
                meta: Map::new(),
            }
            .with_meta(META_JOB, json!(id))
        }
        WaitEnd::Deadline | WaitEnd::Cancelled | WaitEnd::TooMuchOutput => {
            // Past the output limit the group is killed outright: a command that ignores TERM would go on
            // writing for the whole grace period. The same holds when it passes the limit during the grace.
            let ended = if end == WaitEnd::TooMuchOutput {
                running.kill().await
            } else {
                running.terminate_within(grace, limit).await
            };
            let (output, note) = match read_all(&running, limit) {
                Ok(o) => o,
                Err(e) => {
                    remove_records(&running);
                    return ToolOutput::error(e);
                }
            };
            remove_files(&running);
            let (status, outcome) = match end {
                WaitEnd::Cancelled => (ToolStatus::Interrupted, "interrupted".to_string()),
                WaitEnd::TooMuchOutput => (ToolStatus::Error, format!("stopped: output passed {limit} bytes")),
                _ => (ToolStatus::Timeout, format!("stopped after {}s (timeout_s)", allowed.as_secs())),
            };
            let mut facts = vec![format!("the command's own status after it was stopped: {}", ended.outcome())];
            facts.extend(note);
            finish(Finish { ctx, status, outcome, ended: &ended, output, elapsed, facts, job: None })
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::jobs::{JobEvent, JobState};
    use crate::proc::{self, Ended, Spawn, WaitEnd};
    use crate::testutil::{env, env_with, TestEnv};
    use loom_core::config::{SandboxCfg, SandboxMode, ToolsCfg};
    use loom_core::event::{ToolResult, ToolStatus, META_EXIT_CODE, META_JOB, META_SIGNAL};
    use serde_json::json;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

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
        let r = e.call("bash", json!({"command": "echo before; kill -9 $PPID"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("killed by signal 9 (KILL)"), "{}", r.text);
        assert_eq!(r.meta.get(META_SIGNAL), Some(&json!(9)));
        assert!(r.meta.get(META_EXIT_CODE).is_none());
    }

    #[tokio::test]
    async fn exit_codes_above_127_are_exit_codes_with_a_fact_about_signals() {
        let e = env();
        for (command, code) in [("exit 128", 128), ("exit 255", 255), ("kill -9 $$", 137)] {
            let r = e.call("bash", json!({"command": command})).await;
            assert_eq!(r.status, ToolStatus::Error);
            assert!(r.text.contains(&format!("exit {code}")), "{}", r.text);
            assert_eq!(r.meta.get(META_EXIT_CODE), Some(&json!(code)));
            assert!(r.meta.get(META_SIGNAL).is_none());
            assert_eq!(r.text.contains("128+N conventionally means"), code > 128, "{}", r.text);
        }
        let r = e.call("bash", json!({"command": "kill -9 $$"})).await;
        assert!(r.text.contains("signal 9 (KILL)"), "{}", r.text);
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
    async fn a_command_that_leaves_its_group_running_continues_as_a_job() {
        let mut e = env();
        let pidfile = e.ctx.tmp_dir.join("pid");
        let script = format!("echo leader; sleep 300 & echo $! > {}", pidfile.display());
        let t = std::time::Instant::now();
        let r = e.call("bash", json!({"command": script})).await;
        assert!(t.elapsed() < Duration::from_secs(10));
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(r.text.contains("exit 0"), "{}", r.text);
        assert!(
            r.text.contains("now job j1") && r.text.contains("job_wait(\"j1\")") && r.text.contains("job_kill(\"j1\")"),
            "{}",
            r.text
        );
        // The job id only: exit meta beside it would tell the session that the job's end was already shown.
        assert_eq!(r.meta.get(META_JOB), Some(&json!("j1")));
        assert!(r.meta.get(META_EXIT_CODE).is_none() && r.meta.get(META_SIGNAL).is_none(), "{:?}", r.meta);
        assert_eq!(e.stored(&r), "leader\n");
        assert!(matches!(e.job_events.try_recv(), Ok(JobEvent::Registered(_))));
        let child = pid_from(&pidfile).await;
        assert!(alive(child));

        let l = e.call("job_list", json!({})).await;
        assert!(l.text.contains("j1  running (the command itself has exited: exit 0)  "), "{}", l.text);
        let k = e.call("job_kill", json!({"job": "j1"})).await;
        assert!(k.text.contains("stopped by job_kill; the command itself had already exited: exit 0"), "{}", k.text);
        for _ in 0..100 {
            if !alive(child) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(!alive(child), "the child outlived job_kill");

        // A second one is left to the table going away.
        let script = format!("sleep 300 & echo $! > {}", pidfile.display());
        std::fs::remove_file(&pidfile).expect("remove");
        let r = e.call("bash", json!({"command": script})).await;
        assert!(r.text.contains("now job j2"), "{}", r.text);
        let child = pid_from(&pidfile).await;
        assert!(alive(child));
        drop(e);
        for _ in 0..100 {
            if !alive(child) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the child outlived the table");
    }

    #[tokio::test]
    async fn a_job_left_behind_by_a_command_settles_with_the_commands_status() {
        let mut e = env();
        let r = e.call("bash", json!({"command": "echo leader; (sleep 1; echo late) & exit 3"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("exit 3") && r.text.contains("now job j1"), "{}", r.text);
        // Nothing in the result says how the job ended, so its settlement is news for the session.
        assert_eq!(r.meta.get(META_JOB), Some(&json!("j1")));
        assert!(r.meta.get(META_EXIT_CODE).is_none() && r.meta.get(META_SIGNAL).is_none(), "{:?}", r.meta);
        assert!(matches!(e.job_events.recv().await, Some(JobEvent::Registered(_))));
        let settled =
            tokio::time::timeout(Duration::from_secs(20), e.job_events.recv()).await.expect("event").expect("open");
        let JobEvent::Settled { info, output, detail } = settled else { panic!("Settled") };
        assert_eq!(info.state, JobState::Ended(Ended::Exit(3)));
        assert_eq!(detail, "");
        assert_eq!(e.ctx.blobs.read_all(&output.expect("stored").id).expect("read"), b"leader\nlate\n");
        let w = e.call("job_wait", json!({"job": "j1"})).await;
        assert!(w.text.contains("exit 3") && w.text.contains("late"), "{}", w.text);
    }

    #[tokio::test]
    async fn a_helper_that_ends_just_after_the_command_is_waited_for_and_is_no_job() {
        let e = env();
        // The helper ends when the harness has seen the command end and waits for the rest of its group:
        // only then does the pid record gain `member` lines. It runs shell builtins alone, so no sleep or
        // program start has to fit into the settle window.
        let record = e.dir.path().join("home/jobs/j1.pid");
        let helper = format!(
            "while :; do while read -r kind _; do [ \"$kind\" = member ] && break 2; done < {}; done 2>/dev/null; echo helper",
            record.display()
        );
        let r = e.call("bash", json!({"command": format!("echo first; ({helper}) &")})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert!(!r.text.contains("now job"), "{}", r.text);
        assert!(r.meta.get(META_JOB).is_none());
        assert_eq!(r.meta.get(META_EXIT_CODE), Some(&json!(0)));
        assert_eq!(e.stored(&r), "first\nhelper\n");
        let left: Vec<_> = std::fs::read_dir(e.dir.path().join("home/jobs")).expect("jobs dir").collect();
        assert!(left.is_empty(), "{left:?}");
    }

    #[tokio::test]
    async fn processes_left_running_become_a_job_even_when_the_output_cannot_be_read() {
        let e = env();
        let pidfile = e.ctx.tmp_dir.join("pid");
        let out = e.dir.path().join("home/jobs/j1.out");
        let script = format!("rm {}; sleep 300 & echo $! > {}", out.display(), pidfile.display());
        let r = e.call("bash", json!({"command": script})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("could not be read back") && r.text.contains("still running as job j1"), "{}", r.text);
        assert_eq!(r.meta.get(META_JOB), Some(&json!("j1")));
        let child = pid_from(&pidfile).await;
        assert!(alive(child), "the processes it left were stopped unannounced");
        let k = e.call("job_kill", json!({"job": "j1"})).await;
        assert!(k.text.contains("stopped by job_kill"), "{}", k.text);
        for _ in 0..100 {
            if !alive(child) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the child outlived job_kill");
    }

    #[tokio::test]
    async fn an_output_that_cannot_be_read_leaves_the_output_file_and_no_records() {
        let e = env();
        let jobs = e.dir.path().canonicalize().expect("canonical").join("home/jobs");
        // A directory in place of the output file cannot be read as one; the command goes on writing to
        // the file it was given, which is gone from the directory. Once when it ends, once when stopped.
        let replace = |id: &str| format!("rm {0} && mkdir {0}; echo gone", jobs.join(format!("{id}.out")).display());
        let calls = [
            ("j1", json!({"command": replace("j1")})),
            ("j2", json!({"command": format!("{}; sleep 300", replace("j2")), "timeout_s": 1})),
        ];
        for (id, args) in calls {
            let out = jobs.join(format!("{id}.out"));
            let r = e.call("bash", args).await;
            assert_eq!(r.status, ToolStatus::Error, "{}", r.text);
            assert!(
                r.text.contains("could not be read back") && r.text.contains(&out.display().to_string()),
                "{}",
                r.text
            );
            // The output file the message names stays; the status file and the pid record, which would
            // make the next daemon start take the command for a crashed one, are gone.
            assert!(out.is_dir(), "{id}");
            for left in ["pid", "status"] {
                assert!(!jobs.join(format!("{id}.{left}")).exists(), "{id}.{left} is left behind");
            }
        }
    }

    #[tokio::test]
    async fn wake_on_watches_a_background_job_and_job_list_names_the_watch() {
        let mut e = env();
        let r = e
            .call("bash", json!({"command": "echo warming up; echo CRASH at 0x41; sleep 300", "background": true, "wake_on": "CRASH", "wake_every_s": 1}))
            .await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(
            r.text.contains("(running in the background — job_wait(\"j1\") returns its output; watched: you are told, and resumed if you are waiting, when its output has a line matching /CRASH/)"),
            "{}",
            r.text
        );
        assert!(matches!(e.job_events.recv().await, Some(JobEvent::Registered(_))));
        let l = e.call("job_list", json!({})).await;
        assert!(l.text.contains("j1  running, watched for /CRASH/  "), "{}", l.text);
        let report = tokio::time::timeout(Duration::from_secs(20), e.job_events.recv()).await.expect("in time");
        let Some(JobEvent::Matched(m)) = report else { panic!("a match, not {report:?}") };
        assert_eq!(m.lines, [(2, "CRASH at 0x41".to_string())]);
        assert!(m.running);
        // What the watch reported is still new to job_wait.
        let w = e.call("job_wait", json!({"job": "j1", "timeout_s": 0})).await;
        assert_eq!(e.stored(&w), "warming up\nCRASH at 0x41\n");
        e.call("job_kill", json!({"job": "j1"})).await;
        let l = e.call("job_list", json!({})).await;
        assert!(l.text.contains("j1  killed  "), "{}", l.text);
    }

    #[tokio::test]
    async fn wake_on_a_promoted_job_starts_after_what_was_shown_and_a_bad_pattern_runs_nothing() {
        let cfg = ToolsCfg { bash_foreground_s: 1, ..ToolsCfg::default() };
        let mut e = bash_env(cfg);
        let marker = e.ctx.tmp_dir.join("ran");
        let r = e.call("bash", json!({"command": format!("touch {}", marker.display()), "wake_on": "(unclosed"})).await;
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("`wake_on` is not a regular expression that can be used"), "{}", r.text);
        assert!(r.text.contains("Nothing was run."), "{}", r.text);
        assert!(!marker.exists());

        // The first "hit" is in the result the model was shown; only the second is reported.
        let r = e
            .call("bash", json!({"command": "echo hit one; sleep 2; echo hit two; sleep 300", "wake_on": "^hit"}))
            .await;
        assert!(r.text.contains("still running after 1s — now job j1"), "{}", r.text);
        assert!(
            r.text.contains(
                "watched: you are told, and resumed if you are waiting, when its output has a line matching /^hit/"
            ),
            "{}",
            r.text
        );
        assert_eq!(e.stored(&r), "hit one\n");
        assert!(matches!(e.job_events.recv().await, Some(JobEvent::Registered(_))));
        let report = tokio::time::timeout(Duration::from_secs(20), e.job_events.recv()).await.expect("in time");
        let Some(JobEvent::Matched(m)) = report else { panic!("a match, not {report:?}") };
        assert_eq!(m.lines, [(1, "hit two".to_string())]);
        assert_eq!(m.from, "hit one\n".len() as u64);
        e.call("job_kill", json!({"job": "j1"})).await;
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
        let settled =
            tokio::time::timeout(Duration::from_secs(10), e.job_events.recv()).await.expect("event").expect("open");
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
        // Only the first max_output_bytes are kept; the result says how much was written.
        assert_eq!(e.stored(&r).len(), 2_000);
        assert!(r.text.contains("only the first 2000 bytes were kept"), "{}", r.text);
    }

    #[tokio::test]
    async fn a_term_ignoring_writer_is_stopped_at_once_and_the_stored_output_is_bounded() {
        let cfg = ToolsCfg { max_output_bytes: 2_000, kill_grace_s: 30, ..ToolsCfg::default() };
        let e = bash_env(cfg);
        let t = std::time::Instant::now();
        let r = e.call("bash", json!({"command": "trap '' TERM; yes"})).await;
        // The 30 s grace period is not waited out.
        assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
        assert_eq!(r.status, ToolStatus::Error);
        assert!(r.text.contains("stopped: output passed 2000 bytes"), "{}", r.text);
        assert!(r.text.contains("only the first 2000 bytes were kept and the rest was discarded"), "{}", r.text);
        assert_eq!(e.stored(&r).len(), 2_000);
    }

    #[tokio::test]
    async fn job_results_say_when_only_the_first_bytes_of_the_output_were_kept() {
        let cfg = ToolsCfg { max_output_bytes: 2_000, ..ToolsCfg::default() };
        let e = bash_env(cfg);
        // Stopped by the harness for its output.
        e.call("bash", json!({"command": "yes", "background": true})).await;
        let w = e.call("job_wait", json!({"job": "j1", "timeout_s": 30})).await;
        assert!(w.text.contains("killed"), "{}", w.text);
        assert!(w.text.contains("stopped by the harness: the output passed the limit of 2000 bytes"), "{}", w.text);
        assert!(w.text.contains("only the first 2000 bytes were stored and the rest was discarded"), "{}", w.text);
        assert!(w.text.contains("the first 2000 bytes of output are stored as out:"), "{}", w.text);
        assert!(!w.text.contains("complete output"), "{}", w.text);

        // Past the limit in one burst, and over before anything could stop it.
        let (id, out_path, exit_path) = e.ctx.jobs.allocate().await.expect("allocate");
        let vars = [("PATH".to_string(), "/usr/bin:/bin".to_string())].into_iter().collect();
        let script = "printf '%05000d' 0; exit 3".to_string();
        let spec = Spawn { script, cwd: e.ctx.workspace.clone(), env: vars, out_path, exit_path };
        let mut running = proc::spawn(&e.ctx.sandbox, &spec).expect("spawn");
        let end = running.wait(&CancellationToken::new(), Some(Duration::from_secs(20)), u64::MAX).await;
        assert_eq!(end, WaitEnd::Ended(Ended::Exit(3)));
        e.ctx.jobs.register(&id, &e.ctx.call_id, "printf", running).await;
        let w = e.call("job_wait", json!({"job": id, "timeout_s": 30})).await;
        assert!(w.text.contains("exit 3") && w.text.contains("5000 bytes of output in all"), "{}", w.text);
        assert!(
            w.text.contains(
                "the output was 5000 bytes; only the first 2000 bytes were stored and the rest was discarded"
            ),
            "{}",
            w.text
        );
        assert!(w.text.contains("the first 2000 bytes of output are stored as out:"), "{}", w.text);
        assert!(!w.text.contains("complete output"), "{}", w.text);
    }

    #[tokio::test]
    async fn a_stale_output_file_is_not_part_of_a_new_calls_output() {
        let e = env();
        let jobs = e.dir.path().join("home/jobs");
        std::fs::create_dir_all(&jobs).expect("mkdir");
        std::fs::write(jobs.join("j1.out"), "left by a crashed daemon\n").expect("write");
        std::fs::write(jobs.join("j1.status"), "9\n").expect("write");
        let r = e.call("bash", json!({"command": "echo fresh"})).await;
        assert_eq!(r.status, ToolStatus::Ok);
        assert_eq!(e.stored(&r), "fresh\n");
        assert_eq!(r.meta.get(META_EXIT_CODE), Some(&json!(0)));
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
        assert!(
            lines[1].starts_with("j2  exit 2  ")
                && lines[1].contains("4 bytes")
                && lines[1].ends_with("echo x\\necho y; exit 2"),
            "{}",
            lines[1]
        );

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
        assert!(
            r.text.contains("sandboxed: writes only under the workspace and temp dir; network only via proxy"),
            "{}",
            r.text
        );
        let r = e.call("bash", json!({"command": "echo fine; echo more > ok.txt"})).await;
        assert_eq!(r.status, ToolStatus::Ok, "{}", r.text);
        assert!(!r.text.contains("sandboxed:"));
        let r = e.call("bash", json!({"command": "echo 'Operation not permitted'; exit 1"})).await;
        assert!(r.text.contains("sandboxed:"), "{}", r.text);
        let r = e.call("bash", json!({"command": "echo 'Operation not permitted'"})).await;
        assert!(!r.text.contains("sandboxed:"), "{}", r.text);
    }
}
