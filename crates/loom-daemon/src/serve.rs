//! Running the daemon, and starting it in the background.
//!
//! CONTRACT (bodies are placeholders for the implementer; public signatures are fixed).
//!
//! ## `run(paths)` — the body of `loom daemon`
//! 0. Raise the soft limit on open files to the smaller of the hard limit and 16384
//!    (`libc::getrlimit` / `setrlimit` with `RLIMIT_NOFILE`; a failure is ignored). A process
//!    started by launchd or over ssh gets 256, and every running session holds a log, pipes for
//!    its commands and sockets to the model server, so a busy daemon would otherwise start failing
//!    with "Too many open files" in the middle of missions.
//! 1. Create `paths.home` (0700) and `paths.logs_dir()`. `Config::load(paths.config_file())`, then
//!    `check()`; an error is returned as `{path}: {error}`.
//! 2. If `daemon.json` exists and its `pid` is alive (`libc::kill(pid, 0)` succeeds or fails with
//!    `EPERM`) and `GET http://{bind}/healthz` answers within 2 s: return `A loom daemon is already
//!    running for {home} (pid {pid}, {bind}).` A stale file is removed.
//! 3. `auth::load_or_create_token(paths.token_file())`.
//! 4. Bind `config.daemon.bind` (`TcpListener`; `SO_REUSEADDR`). A failure is `Cannot listen on
//!    {bind}: {error}.` The port actually bound is the port used everywhere below (so port 0
//!    works, for tests).
//! 5. `Runtime::start(config, paths)`.
//! 6. Write `daemon.json` (`DaemonFile`, atomically). Log one line at info level with the address.
//! 7. Serve `api::router` until SIGINT, SIGTERM, or the state's `shutdown` token (graceful
//!    shutdown: stop accepting, give open requests 3 s — event streams are simply dropped).
//! 8. `runtime.shutdown().await`, remove `daemon.json`, return `Ok(())`.
//!
//! Logging: `tracing_subscriber` to stderr, level from `LOOM_LOG` (default `info`), installed once
//! (`try_init`, an error ignored). Nothing is ever logged that contains the token.
//!
//! `run_until(paths, stop)` is `run` with one more reason to stop (for tests): `stop` cancelled.
//! It calls `ready(bind)` once, after step 6.
//!
//! ## `spawn_background(paths)` — the body of `loom up`
//! If the daemon already answers (`healthz` on the configured bind): `Ok(Already)`. Otherwise start
//! `std::env::current_exe()` with the single argument `daemon`, `LOOM_HOME` set to `paths.home`,
//! stdin `/dev/null`, stdout and stderr appended to `{logs}/loomd.log`, in its own session
//! (`pre_exec` + `libc::setsid`) so it outlives the terminal. Then poll `healthz` every 100 ms for
//! up to 20 s. If the child exits first or the time runs out: `Err` with `The daemon did not come
//! up. Last lines of {log}:` followed by the log's last 15 lines.
//!
//! ## `launch_agent_plist(exe, home)` — for `loom service install` (macOS)
//! A LaunchAgent property list with `Label` [`SERVICE_LABEL`], `ProgramArguments` `[exe, "daemon"]`,
//! `EnvironmentVariables` `{LOOM_HOME: home, PATH: /usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin}`,
//! `RunAtLoad` true, `KeepAlive` `{SuccessfulExit: false}`, `ProcessType` `Background`,
//! `SoftResourceLimits` `{NumberOfFiles: 16384}`,
//! `StandardOutPath` and `StandardErrorPath` `{home}/logs/loomd.log`. Every inserted string is
//! XML-escaped (`&`, `<`, `>`).
//!
//! Tests required: `run_until` over a temporary home with port 0 and a `MockServer`-backed config:
//! `ready` fires, `daemon.json` exists and names the bound port, `/healthz` answers, the token file
//! is 0600; cancelling `stop` returns `Ok` and removes `daemon.json`; a second `run` against a live
//! first one is refused with the sentence above; a stale `daemon.json` is replaced; an invalid
//! config is reported with its path; the plist (escaping, both paths present).

use loom_core::config::Paths;
use std::path::Path;
use tokio_util::sync::CancellationToken;

/// launchd label of the daemon's LaunchAgent.
pub const SERVICE_LABEL: &str = "dev.loom.daemon";

/// How `spawn_background` found or left things.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spawned {
    /// A daemon was already answering.
    Already,
    Started,
}

/// Run the daemon until it is told to stop.
pub async fn run(paths: Paths) -> Result<(), String> {
    run_until(paths, CancellationToken::new(), |_| {}).await
}

/// `run`, also stopping when `stop` is cancelled; `ready` is called with the bound address.
pub async fn run_until(
    paths: Paths,
    stop: CancellationToken,
    ready: impl FnOnce(&str) + Send,
) -> Result<(), String> {
    let _ = (paths, stop, ready);
    todo!("implement per module contract")
}

/// Start the daemon in the background and wait until it answers.
pub async fn spawn_background(paths: &Paths) -> Result<Spawned, String> {
    let _ = paths;
    todo!("implement per module contract")
}

pub fn launch_agent_plist(exe: &Path, home: &Path) -> String {
    let _ = (exe, home);
    todo!("implement per module contract")
}
