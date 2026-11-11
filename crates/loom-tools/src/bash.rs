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

use crate::{params, Tool, ToolCtx, ToolOutput};
use async_trait::async_trait;
use loom_core::event::{ToolClass, ToolSpec};
use serde_json::{Map, Value};

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
        let _ = (ctx, args);
        todo!("implement per module contract")
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
        let _ = (ctx, args);
        todo!("implement per module contract")
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
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}

#[async_trait]
impl Tool for JobList {
    fn spec(&self) -> ToolSpec {
        params::spec("job_list", "List this session's background jobs with their state.", ToolClass::State, &[])
    }

    async fn run(&self, ctx: &ToolCtx, args: &Map<String, Value>) -> ToolOutput {
        let _ = (ctx, args);
        todo!("implement per module contract")
    }
}
