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
//! 1. Create `paths.home` (0700). Take an exclusive, non-blocking lock on `<home>/daemon.lock` and hold it
//!    until `run` returns (the process exits): when it is taken, another daemon drives this home and the
//!    answer is the "already running" sentence below (pid and address from `daemon.json` when readable).
//!    Create `paths.logs_dir()`. `Config::load(paths.config_file())`, then
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

use crate::api::{self, ApiState};
use crate::auth;
use crate::wire::DaemonFile;
use loom_agent::runtime::Runtime;
use loom_core::config::{Config, ConfigError, Paths};
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// The soft limit on open files the daemon asks for.
const NOFILE_TARGET: libc::rlim_t = 16_384;
/// What macOS accepts as a soft limit when the hard limit is unlimited.
const NOFILE_MACOS_CAP: libc::rlim_t = 10_240;
/// How long open requests get to finish after a stop is asked for.
const GRACE: Duration = Duration::from_secs(3);
/// How long an existing daemon has to answer `/healthz`.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long `spawn_background` waits for the new daemon.
const UP_TIMEOUT: Duration = Duration::from_secs(20);
const UP_POLL: Duration = Duration::from_millis(100);
const LOG_TAIL_LINES: usize = 15;
const DAEMON_FILE: &str = "daemon.json";
const LOCK_FILE: &str = "daemon.lock";

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
    raise_open_files_limit();
    init_logging();

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&paths.home)
        .map_err(|e| format!("Cannot create {}: {e}.", paths.home.display()))?;
    let _home_lock = take_home_lock(&paths)?;
    std::fs::create_dir_all(paths.logs_dir()).map_err(|e| format!("Cannot create {}: {e}.", paths.logs_dir().display()))?;
    let config = load_config(&paths)?;
    loom_tools::sandbox::preflight(&config.sandbox)?;

    if let Some(file) = read_daemon_file(&paths) {
        if pid_alive(file.pid) && healthy(&file.bind, PROBE_TIMEOUT).await {
            return Err(format!(
                "A loom daemon is already running for {} (pid {}, {}).",
                paths.home.display(),
                file.pid,
                file.bind
            ));
        }
        // The process that wrote it is gone, or it no longer serves.
        let _ = std::fs::remove_file(daemon_file_path(&paths));
    }

    let token = auth::load_or_create_token(&paths.token_file())
        .map_err(|e| format!("{}: {e}", paths.token_file().display()))?;

    let listener = bind_listener(&config.daemon.bind).await?;
    let local = listener.local_addr().map_err(|e| format!("Cannot listen on {}: {e}.", config.daemon.bind))?;
    let bind = local.to_string();
    let port = local.port();

    let runtime = Runtime::start(config, paths.clone()).await?;

    let started_ms = loom_core::now_ms();
    let file = DaemonFile { pid: std::process::id(), bind: bind.clone(), started_ms };
    if let Err(e) = write_daemon_file(&paths, &file) {
        runtime.shutdown().await;
        return Err(format!("Cannot write {}: {e}.", daemon_file_path(&paths).display()));
    }
    tracing::info!("loom daemon listening on http://{bind} (home {})", paths.home.display());
    ready(&bind);

    let shutdown = CancellationToken::new();
    let state = ApiState {
        runtime: runtime.clone(),
        token: Arc::new(token),
        bind,
        port,
        started_ms,
        shutdown: shutdown.clone(),
        logins: Arc::new(auth::Logins::new()),
    };
    let begin = CancellationToken::new();
    let server = axum::serve(listener, api::router(state)).with_graceful_shutdown({
        let begin = begin.clone();
        async move { begin.cancelled().await }
    });
    let mut server = Box::pin(server.into_future());
    let stopping = async {
        tokio::select! {
            _ = stop.cancelled() => {}
            _ = shutdown.cancelled() => {}
            _ = os_signal() => {}
        }
        // Streams end on the token; the server stops accepting and waits for the rest.
        shutdown.cancel();
        begin.cancel();
        tokio::time::sleep(GRACE).await;
    };
    tokio::select! {
        result = &mut server => {
            if let Err(e) = result {
                tracing::error!("the HTTP server stopped: {e}");
            }
        }
        _ = stopping => tracing::info!("open requests did not finish within {} s; dropping them", GRACE.as_secs()),
    }
    drop(server);

    runtime.shutdown().await;
    let _ = std::fs::remove_file(daemon_file_path(&paths));
    tracing::info!("loom daemon stopped");
    Ok(())
}

/// Start the daemon in the background and wait until it answers.
pub async fn spawn_background(paths: &Paths) -> Result<Spawned, String> {
    let config = load_config(paths)?;
    if answering(paths, &config).await {
        return Ok(Spawned::Already);
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(paths.logs_dir())
        .map_err(|e| format!("Cannot create {}: {e}.", paths.logs_dir().display()))?;
    let log = paths.logs_dir().join("loomd.log");
    let out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log)
        .map_err(|e| format!("Cannot open {}: {e}.", log.display()))?;
    let err = out.try_clone().map_err(|e| format!("Cannot open {}: {e}.", log.display()))?;
    let exe = std::env::current_exe().map_err(|e| format!("Cannot find the loom program to start: {e}."))?;
    let mut command = std::process::Command::new(&exe);
    command.arg("daemon").env("LOOM_HOME", &paths.home).stdin(Stdio::null()).stdout(out).stderr(err);
    // SAFETY: the closure only calls `setsid`, which is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = command.spawn().map_err(|e| format!("Cannot start {}: {e}.", exe.display()))?;

    let deadline = Instant::now() + UP_TIMEOUT;
    loop {
        if let Some(file) = read_daemon_file(paths) {
            if file.pid == child.id() && healthy(&file.bind, PROBE_TIMEOUT).await {
                return Ok(Spawned::Started);
            }
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                // It may have lost a race with another daemon that is now up.
                if answering(paths, &config).await {
                    return Ok(Spawned::Already);
                }
                return Err(did_not_come_up(&log));
            }
            Ok(None) => {}
            Err(_) => return Err(did_not_come_up(&log)),
        }
        if Instant::now() >= deadline {
            return Err(did_not_come_up(&log));
        }
        tokio::time::sleep(UP_POLL).await;
    }
}

pub fn launch_agent_plist(exe: &Path, home: &Path) -> String {
    let logs = home.join("logs").join("loomd.log");
    let string = |s: &str| format!("<string>{}</string>", xml_escape(s));
    let key = |k: &str| format!("<key>{}</key>", xml_escape(k));
    let exe = exe.to_string_lossy();
    let home_text = home.to_string_lossy();
    let logs = logs.to_string_lossy();
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    out.push_str("<plist version=\"1.0\">\n<dict>\n");
    out.push_str(&format!("  {}\n  {}\n", key("Label"), string(SERVICE_LABEL)));
    out.push_str(&format!(
        "  {}\n  <array>\n    {}\n    {}\n  </array>\n",
        key("ProgramArguments"),
        string(&exe),
        string("daemon")
    ));
    out.push_str(&format!(
        "  {}\n  <dict>\n    {}\n    {}\n    {}\n    {}\n  </dict>\n",
        key("EnvironmentVariables"),
        key("LOOM_HOME"),
        string(&home_text),
        key("PATH"),
        string("/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    ));
    out.push_str(&format!("  {}\n  <true/>\n", key("RunAtLoad")));
    out.push_str(&format!("  {}\n  <dict>\n    {}\n    <false/>\n  </dict>\n", key("KeepAlive"), key("SuccessfulExit")));
    out.push_str(&format!("  {}\n  {}\n", key("ProcessType"), string("Background")));
    out.push_str(&format!(
        "  {}\n  <dict>\n    {}\n    <integer>{NOFILE_TARGET}</integer>\n  </dict>\n",
        key("SoftResourceLimits"),
        key("NumberOfFiles")
    ));
    out.push_str(&format!("  {}\n  {}\n", key("StandardOutPath"), string(&logs)));
    out.push_str(&format!("  {}\n  {}\n", key("StandardErrorPath"), string(&logs)));
    out.push_str("</dict>\n</plist>\n");
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

// ---------------------------------------------------------------------------------------------
// Helpers

/// Ask for a bigger soft limit on open files; a failure is ignored.
fn raise_open_files_limit() {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid, writable `rlimit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return;
    }
    let want: libc::rlim_t = limit.rlim_max.min(NOFILE_TARGET);
    if limit.rlim_cur >= want {
        return;
    }
    for target in [want, want.min(NOFILE_MACOS_CAP)] {
        let new = libc::rlimit { rlim_cur: target, rlim_max: limit.rlim_max };
        // SAFETY: `new` is a valid `rlimit`.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) } == 0 {
            return;
        }
    }
}

/// Log to stderr, level from `LOOM_LOG` (default `info`). Installed once; an error is ignored.
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("LOOM_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

fn load_config(paths: &Paths) -> Result<Config, String> {
    let path = paths.config_file();
    let describe = |e: ConfigError| match e {
        // Already begins with the path.
        ConfigError::Parse { .. } => e.to_string(),
        other => format!("{}: {other}", path.display()),
    };
    let config = Config::load(&path).map_err(describe)?;
    config.check().map_err(describe)?;
    Ok(config)
}

fn daemon_file_path(paths: &Paths) -> PathBuf {
    paths.home.join(DAEMON_FILE)
}

fn read_daemon_file(paths: &Paths) -> Option<DaemonFile> {
    let text = std::fs::read_to_string(daemon_file_path(paths)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Write `daemon.json` by writing a sibling file and renaming it over.
fn write_daemon_file(paths: &Paths, file: &DaemonFile) -> std::io::Result<()> {
    use std::io::Write;
    let text = serde_json::to_string_pretty(file).map_err(std::io::Error::other)?;
    let target = daemon_file_path(paths);
    let tmp = paths.home.join(format!(".{DAEMON_FILE}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        std::fs::rename(&tmp, &target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// True when a process with this pid exists (it may belong to someone else).
fn pid_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else { return false };
    if pid <= 0 {
        return false;
    }
    // SAFETY: signal 0 only checks that the process exists.
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// True when `GET http://{bind}/healthz` is answered with a success within `timeout`.
async fn healthy(bind: &str, timeout: Duration) -> bool {
    let Ok(client) = reqwest::Client::builder().no_proxy().timeout(timeout).build() else { return false };
    match client.get(format!("http://{bind}/healthz")).send().await {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

/// True when a daemon for this home answers: at the address in `daemon.json`, or the configured one.
async fn answering(paths: &Paths, config: &Config) -> bool {
    if let Some(file) = read_daemon_file(paths) {
        if pid_alive(file.pid) && healthy(&file.bind, PROBE_TIMEOUT).await {
            return true;
        }
    }
    healthy(&config.daemon.bind, PROBE_TIMEOUT).await
}

/// Take the exclusive lock on `<home>/daemon.lock`; the returned file holds it until it is dropped. A lock that
/// another daemon holds is answered with the "already running" sentence.
fn take_home_lock(paths: &Paths) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    let path = paths.home.join(LOCK_FILE);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("Cannot open {}: {e}.", path.display()))?;
    // SAFETY: flock on a descriptor this function owns.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(file);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
        return Err(format!("Cannot lock {}: {err}.", path.display()));
    }
    Err(match read_daemon_file(paths) {
        Some(f) => format!("A loom daemon is already running for {} (pid {}, {}).", paths.home.display(), f.pid, f.bind),
        None => format!(
            "A loom daemon is already running for {} (it is starting; its address is not written yet).",
            paths.home.display()
        ),
    })
}

/// The address to bind among those `bind` resolved to: a loopback one, IPv4 preferred. When none is loopback the
/// answer names the first address the name resolved to.
fn pick_loopback(bind: &str, addrs: &[SocketAddr]) -> Result<SocketAddr, String> {
    let loopback = |a: &&SocketAddr| a.ip().is_loopback();
    addrs.iter().filter(loopback).find(|a| a.is_ipv4()).or_else(|| addrs.iter().find(loopback)).copied().ok_or_else(|| {
        match addrs.first() {
            Some(a) => format!(
                "Cannot listen on {bind}: it resolves to {}, which is not a loopback address. Set [daemon] bind to \
                 127.0.0.1:<port> (or [::1]:<port>); the API must not be reachable from other machines.",
                a.ip()
            ),
            None => format!("Cannot listen on {bind}: the address does not resolve."),
        }
    })
}

/// Bind with `SO_REUSEADDR`, preferring an IPv4 address when the name has several. Only loopback addresses are
/// bound, whatever name was configured.
async fn bind_listener(bind: &str) -> Result<tokio::net::TcpListener, String> {
    let fail = |why: &dyn std::fmt::Display| format!("Cannot listen on {bind}: {why}.");
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(bind).await.map_err(|e| fail(&e))?.collect();
    let addr = pick_loopback(bind, &addrs)?;
    let socket = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4() } else { tokio::net::TcpSocket::new_v6() }
        .map_err(|e| fail(&e))?;
    socket.set_reuseaddr(true).map_err(|e| fail(&e))?;
    socket.bind(addr).map_err(|e| fail(&e))?;
    socket.listen(1024).map_err(|e| fail(&e))
}

/// Resolves on SIGINT or SIGTERM.
async fn os_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let term = async {
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    let int = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        _ = term => {}
        _ = int => {}
    }
}

fn did_not_come_up(log: &Path) -> String {
    let text = std::fs::read(log).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let mut lines: Vec<&str> = text.lines().rev().take(LOG_TAIL_LINES).collect();
    lines.reverse();
    format!("The daemon did not come up. Last lines of {}:\n{}", log.display(), lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_model::mock::{MockServer, Reply, Script};
    use std::os::unix::fs::PermissionsExt;

    struct Home {
        dir: tempfile::TempDir,
        paths: Paths,
        _server: MockServer,
    }

    async fn home_with(extra: &str) -> Home {
        let dir = tempfile::tempdir().unwrap();
        let server = MockServer::start(Script::new(|_, _| Reply::text("hi").into())).await.unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        let config = format!(
            "default_model = \"mock\"\n[daemon]\nbind = \"127.0.0.1:0\"\n[sandbox]\nmode = \"none\"\n[network]\nmode = \"deny_all\"\n[models.mock]\nbase_url = \"{}\"\nmodel = \"mock\"\ncontext_window = 1000000\n{extra}",
            server.base_url()
        );
        std::fs::write(home.join("config.toml"), config).unwrap();
        Home { paths: Paths::at(home), dir, _server: server }
    }

    type Running = (tokio::task::JoinHandle<Result<(), String>>, CancellationToken, String);

    async fn start(paths: &Paths) -> Running {
        let stop = CancellationToken::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        let task = tokio::spawn(run_until(paths.clone(), stop.clone(), move |bind: &str| {
            let _ = tx.send(bind.to_string());
        }));
        let bind = tokio::time::timeout(Duration::from_secs(30), rx).await.unwrap().unwrap();
        (task, stop, bind)
    }

    async fn stop_and_join((task, stop, _): Running) {
        stop.cancel();
        let result = tokio::time::timeout(Duration::from_secs(30), task).await.unwrap().unwrap();
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn run_until_serves_writes_files_and_cleans_up() {
        let h = home_with("").await;
        let running = start(&h.paths).await;
        let bind = running.2.clone();
        let port: u16 = bind.rsplit_once(':').unwrap().1.parse().unwrap();
        assert_ne!(port, 0);

        let file: DaemonFile = serde_json::from_str(&std::fs::read_to_string(h.paths.home.join("daemon.json")).unwrap()).unwrap();
        assert_eq!(file.bind, bind);
        assert_eq!(file.pid, std::process::id());
        let mode = std::fs::metadata(h.paths.token_file()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!h.paths.home.read_dir().unwrap().any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));

        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let ok = http.get(format!("http://{bind}/healthz")).send().await.unwrap();
        assert_eq!(ok.status(), 200);
        assert_eq!(ok.text().await.unwrap(), "ok");
        let token = std::fs::read_to_string(h.paths.token_file()).unwrap();
        let status: serde_json::Value = http
            .get(format!("http://{bind}/api/status"))
            .bearer_auth(token.trim())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(status["bind"], bind.as_str());

        stop_and_join(running).await;
        assert!(!h.paths.home.join("daemon.json").exists());
        assert!(http.get(format!("http://{bind}/healthz")).send().await.is_err());
    }

    #[tokio::test]
    async fn a_second_daemon_for_the_same_home_is_refused() {
        let h = home_with("").await;
        let running = start(&h.paths).await;
        let err = run_until(h.paths.clone(), CancellationToken::new(), |_| {}).await.unwrap_err();
        assert_eq!(
            err,
            format!(
                "A loom daemon is already running for {} (pid {}, {}).",
                h.paths.home.display(),
                std::process::id(),
                running.2
            )
        );
        // The first one is untouched.
        assert!(h.paths.home.join("daemon.json").exists());
        assert_eq!(spawn_background(&h.paths).await, Ok(Spawned::Already));
        stop_and_join(running).await;
    }

    #[tokio::test]
    async fn a_stale_daemon_file_is_replaced() {
        let h = home_with("").await;
        let write = |pid: u32, bind: &str| {
            let file = DaemonFile { pid, bind: bind.to_string(), started_ms: 1 };
            std::fs::write(h.paths.home.join("daemon.json"), serde_json::to_string(&file).unwrap()).unwrap();
        };
        // A pid nobody has.
        write(2_000_000_000, "127.0.0.1:1");
        let running = start(&h.paths).await;
        let file = read_daemon_file(&h.paths).unwrap();
        assert_eq!((file.pid, file.bind.as_str()), (std::process::id(), running.2.as_str()));
        stop_and_join(running).await;

        // A live pid (this process) that serves nothing at the recorded address.
        write(std::process::id(), "127.0.0.1:1");
        let running = start(&h.paths).await;
        assert_eq!(read_daemon_file(&h.paths).unwrap().bind, running.2);
        stop_and_join(running).await;
    }

    #[tokio::test]
    async fn an_invalid_config_is_reported_with_its_path() {
        let h = home_with("").await;
        let file = h.paths.config_file();
        std::fs::write(&file, "bogus_key = 1\n").unwrap();
        let err = run_until(h.paths.clone(), CancellationToken::new(), |_| {}).await.unwrap_err();
        assert!(err.starts_with(&file.display().to_string()), "{err}");

        std::fs::write(&file, "default_model = \"nope\"\n[models.a]\nmodel = \"a\"\n").unwrap();
        let err = run_until(h.paths.clone(), CancellationToken::new(), |_| {}).await.unwrap_err();
        assert!(err.starts_with(&format!("{}: ", file.display())) && err.contains("nope"), "{err}");

        std::fs::write(&file, "[daemon]\nbind = \"0.0.0.0:0\"\n").unwrap();
        let err = spawn_background(&h.paths).await.unwrap_err();
        assert!(err.starts_with(&file.display().to_string()) && err.contains("loopback"), "{err}");
        assert!(!h.paths.home.join("daemon.json").exists());
        let _ = &h.dir;
    }

    #[tokio::test]
    async fn an_address_in_use_is_reported() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let h = home_with("").await;
        let config = std::fs::read_to_string(h.paths.config_file()).unwrap().replace("127.0.0.1:0", &addr.to_string());
        std::fs::write(h.paths.config_file(), config).unwrap();
        let err = run_until(h.paths.clone(), CancellationToken::new(), |_| {}).await.unwrap_err();
        assert!(err.starts_with(&format!("Cannot listen on {addr}: ")) && err.ends_with('.'), "{err}");
    }

    #[test]
    fn the_home_lock_is_exclusive_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path());
        let first = take_home_lock(&paths).unwrap();
        let err = take_home_lock(&paths).unwrap_err();
        assert!(err.starts_with(&format!("A loom daemon is already running for {}", paths.home.display())), "{err}");
        let file = DaemonFile { pid: 4242, bind: "127.0.0.1:9".to_string(), started_ms: 1 };
        write_daemon_file(&paths, &file).unwrap();
        assert_eq!(
            take_home_lock(&paths).unwrap_err(),
            format!("A loom daemon is already running for {} (pid 4242, 127.0.0.1:9).", paths.home.display())
        );
        drop(first);
        assert!(take_home_lock(&paths).is_ok());
    }

    #[test]
    fn only_loopback_addresses_are_bound() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(pick_loopback("localhost:1", &[a("[::1]:1"), a("127.0.0.1:1")]), Ok(a("127.0.0.1:1")));
        assert_eq!(pick_loopback("localhost:1", &[a("[::1]:1")]), Ok(a("[::1]:1")));
        let err = pick_loopback("evil.example:1", &[a("10.1.2.3:1"), a("127.0.0.1:1")]).unwrap();
        assert_eq!(err, a("127.0.0.1:1"));
        let err = pick_loopback("evil.example:1", &[a("10.1.2.3:1")]).unwrap_err();
        assert!(err.contains("evil.example:1") && err.contains("10.1.2.3") && err.contains("not a loopback address"), "{err}");
        assert!(pick_loopback("x:1", &[]).unwrap_err().contains("does not resolve"));
    }

    #[tokio::test]
    async fn bind_listener_refuses_an_address_that_is_not_loopback() {
        let err = bind_listener("0.0.0.0:0").await.unwrap_err();
        assert!(err.contains("0.0.0.0") && err.contains("not a loopback address"), "{err}");
        assert!(bind_listener("127.0.0.1:0").await.is_ok());
    }

    #[test]
    fn the_plist_escapes_and_names_both_paths() {
        let plist = launch_agent_plist(Path::new("/opt/a&b/<loom>"), Path::new("/Users/x&y/.loom"));
        assert!(plist.contains(&format!("<string>{SERVICE_LABEL}</string>")));
        assert!(plist.contains("<string>/opt/a&amp;b/&lt;loom&gt;</string>"));
        assert!(plist.contains("<key>LOOM_HOME</key>\n    <string>/Users/x&amp;y/.loom</string>"));
        assert_eq!(plist.matches("<string>/Users/x&amp;y/.loom/logs/loomd.log</string>").count(), 2);
        assert!(plist.contains("<key>StandardOutPath</key>") && plist.contains("<key>StandardErrorPath</key>"));
        assert!(plist.contains("/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"));
        assert!(plist.contains("<key>NumberOfFiles</key>\n    <integer>16384</integer>"));
        assert!(plist.contains("<key>SuccessfulExit</key>\n    <false/>"));
        assert!(plist.contains("<string>daemon</string>") && plist.contains("<string>Background</string>"));
        assert!(!plist.contains("a&b"));
    }

    #[test]
    fn the_log_tail_is_the_last_fifteen_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("loomd.log");
        let text: String = (1..=20).map(|n| format!("line {n}\n")).collect();
        std::fs::write(&log, text).unwrap();
        let msg = did_not_come_up(&log);
        assert!(msg.starts_with("The daemon did not come up. Last lines of "));
        assert!(msg.contains("\nline 6\n") && msg.ends_with("line 20") && !msg.contains("line 5\n"));
    }
}
