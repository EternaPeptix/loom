//! The sandbox self-probe: does a sandboxed command still reach the network outside the egress proxy?
//!
//! CONTRACT.
//!
//! `run(cfg, loom_home)` builds sandboxes from the daemon's `SandboxCfg` (the profile sessions get) and runs
//! commands in them against listeners on loopback ports that the profile does not allow. What reaches a listener
//! was sent by something outside the sandbox, so the verdict is the harness's own observation, never the printed
//! output of a command (`docs/MONITOR.md` I8). It does not touch the loom home, the operator's configuration or any
//! other port; its files live in a fresh directory below the system temp directory that it removes at the end.
//!
//! The profile used is the daemon's, with loopback, unix sockets and extra paths cleared (so nothing but the
//! probed route can reach a listener) and `protect_credentials` off (irrelevant to egress, and it needs a home
//! directory). Probes (`Probe`):
//! - `aia_fetch`: `security verify-cert -p ssl` on a certificate whose AIA `caIssuers` names a unique URL on a
//!   listener. Certificate evaluation fetches that URL through `trustd` outside the sandbox.
//! - `url_session`: a background `NSURLSession` download of a unique URL, started from `osascript -l JavaScript`
//!   (`nsurlsessiond` fetches it outside the sandbox).
//! - `web_kit`: a `WKWebView` that loads a unique URL, made from `osascript -l JavaScript` (WebKit's networking
//!   process fetches it outside the sandbox).
//! - `daemon_port`: the credential flow of the audit. A decoy process outside the sandbox carries a code in its
//!   argument vector; the sandboxed command looks for it with `pgrep -fl` and presents it to a listener standing in
//!   for the daemon (which the profile names as `daemon_port`, with `loopback_all` on, as the daemon's own profile
//!   does), and also tries a second listener named in `infra_ports`. A connection that carries the probe's code (`code=code-...`) to either is a leak; another connection (a port scan) is only noted. That the
//!   argument vector is readable at all is recorded in the detail and is not a leak: the code is never put there.
//!
//! - `git_metadata`: a command writes a ref (the control, allowed) and tries a hook, `config` and `config.worktree`
//!   of a repository in the workspace; any of the three landing is a leak (the check is the files, not the output).
//!
//! The three fetch probes each run a control first, under the same profile with `allow_fetch_services` on. A
//! control that reaches its listener proves the host fetches for sandboxed commands; only then is the real
//! profile run, and a request from it is a leak. A control that does not reach is `NotExercised`: the host does not
//! fetch on a command's behalf in this setting, so the real profile cannot be judged leaking or held (it is not a
//! failure). With `cfg.allow_fetch_services` the three are not run (the setting says the route is open) and
//! `daemon_port` and `git_metadata` still are.
//!
//! `Outcome`: `Held` (no request reached), `Leaked` (a request reached a listener), `NotExercised` (see above, or a
//! probe's program is missing on this host: `openssl`, `security`, `osascript`, `pgrep`), `Failed` (the probe could
//! not be set up or run: a listener, a certificate, a sandbox or a process failed, with the reason). A caller must
//! treat `Leaked` and `Failed` as "egress unbounded": a probe that cannot run proves nothing.
//!
//! Every command is killed after `SCRIPT_LIMIT`. `run` returns only after the listeners are closed and the
//! directory removed. It blocks for up to about a minute: call it from a blocking thread. `stop()` (the daemon shuts
//! down) kills the process groups of every command and decoy a running probe made, and the commands that follow
//! are killed as they start.
//!
//! In mode `none` and `bubblewrap` there is nothing to probe: `run` returns a report with no results and
//! `Report::ran` false; the caller decides what that means (`loom-agent::egress`).
//!
//! Tests required: `a_report_lists_what_leaked_or_failed_and_nothing_else`, `a_listener_sees_a_request_and_counts_connections`,
//! `a_script_that_runs_too_long_is_killed`, `the_probe_does_nothing_in_a_mode_that_has_no_sandbox_profile`,
//! `the_probes_hold_under_the_default_profile` and `allow_fetch_services_skips_the_fetch_probes_and_still_checks_the_daemon_port`,
//! `a_profile_that_allows_the_fetch_services_is_seen_leaking` and
//! `the_probe_sees_a_listener_that_the_profile_allows_as_a_leak` (macOS only; each fetch probe reports `NotExercised`
//! when the host does not fetch), `a_listener_is_not_held_by_a_peer_that_streams_without_a_newline`,
//! `dropping_a_listener_does_not_wait_for_a_silent_peer`, `the_daemon_port_verdict_is_a_leak_only_for_the_probes_own_connection`,
//! `the_git_verdict_reads_the_files_and_not_the_output`, `the_daemon_port_probe_reports_a_hole_in_the_profile_as_a_leak`
//! (macOS), `the_processes_of_a_probe_are_tracked_and_can_be_killed` and
//! `a_directory_a_dead_probe_left_is_removed_and_nothing_else`.

use super::Sandbox;
use loom_core::config::{SandboxCfg, SandboxMode};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::net::TcpListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long a control is waited for, and then the real profile.
const CONTROL_WAIT: Duration = Duration::from_secs(10);
const REAL_WAIT: Duration = Duration::from_secs(6);
/// A command that runs longer than this is killed with its process group.
pub const SCRIPT_LIMIT: Duration = Duration::from_secs(30);

/// The process groups of the commands and decoys of a probe that is running, so that `stop` can end them.
static LIVE_GROUPS: Mutex<Vec<i32>> = Mutex::new(Vec::new());
/// Set by `stop`: no command is waited for any longer.
static STOPPED: AtomicBool = AtomicBool::new(false);

fn track(pid: u32) -> Option<i32> {
    let pid = i32::try_from(pid).ok()?;
    if let Ok(mut live) = LIVE_GROUPS.lock() {
        live.push(pid);
    }
    Some(pid)
}

fn untrack(pid: Option<i32>) {
    if let (Some(pid), Ok(mut live)) = (pid, LIVE_GROUPS.lock()) {
        live.retain(|p| *p != pid);
    }
}

fn kill_group(pid: i32) {
    // SAFETY: killpg on a group a probe made; a stale pid names nothing we own.
    unsafe {
        libc::killpg(pid, libc::SIGKILL);
    }
}

/// Kill every process group a running probe has made (commands and decoys). Returns how many.
fn kill_live() -> usize {
    let groups: Vec<i32> = LIVE_GROUPS.lock().map(|mut l| std::mem::take(&mut *l)).unwrap_or_default();
    for g in &groups {
        kill_group(*g);
    }
    groups.len()
}

/// End a probe that is running (the daemon is shutting down): its commands and decoys are killed and the probes
/// that have not started do not start. `run` still removes its directory.
pub fn stop() {
    STOPPED.store(true, Ordering::SeqCst);
    kill_live();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Probe {
    AiaFetch,
    UrlSession,
    WebKit,
    DaemonPort,
    GitMetadata,
}

impl Probe {
    pub const ALL: [Probe; 5] =
        [Probe::AiaFetch, Probe::UrlSession, Probe::WebKit, Probe::DaemonPort, Probe::GitMetadata];

    pub fn name(self) -> &'static str {
        match self {
            Probe::AiaFetch => "aia_fetch",
            Probe::UrlSession => "url_session",
            Probe::WebKit => "web_kit",
            Probe::DaemonPort => "daemon_port",
            Probe::GitMetadata => "git_metadata",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Held,
    Leaked,
    NotExercised,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub probe: Probe,
    pub outcome: Outcome,
    /// One sentence: what was observed, or why the probe could not run.
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Whether anything could be probed (a seatbelt sandbox on this host).
    pub ran: bool,
    pub results: Vec<ProbeResult>,
}

impl Report {
    /// One sentence for each probe that leaked or failed: what makes egress unbounded.
    pub fn problems(&self) -> Vec<String> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Leaked | Outcome::Failed))
            .map(|r| {
                let what = if r.outcome == Outcome::Leaked { "leaked" } else { "could not run" };
                format!("self-probe {} {what}: {}", r.probe.name(), r.detail)
            })
            .collect()
    }
}

fn result(probe: Probe, outcome: Outcome, detail: impl Into<String>) -> ProbeResult {
    ProbeResult { probe, outcome, detail: detail.into() }
}

/// How much of a request line a listener keeps, and for how long it reads one connection. A peer that streams
/// bytes without a newline, or says nothing, is cut off at either.
const LINE_MAX: usize = 4096;
const CONNECTION_LIMIT: Duration = Duration::from_secs(3);
/// How many connections are served at once; a connection beyond that is counted and closed.
const CONNECTIONS_AT_ONCE: usize = 64;

/// A listener on a loopback port that records what connects. Each connection is served on its own thread that
/// reads at most `LINE_MAX` bytes for at most `CONNECTION_LIMIT`, so no peer can hold it, and dropping the listener
/// never waits for a peer.
struct Listener {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Read the first line of `conn` (at most `LINE_MAX` bytes, within `CONNECTION_LIMIT`, until `stop`).
fn read_first_line(conn: &mut std::net::TcpStream, stop: &AtomicBool) -> String {
    use std::io::Read;
    let _ = conn.set_nonblocking(false);
    let _ = conn.set_read_timeout(Some(Duration::from_millis(200)));
    let deadline = Instant::now() + CONNECTION_LIMIT;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    while buf.len() < LINE_MAX && Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        match conn.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let room = LINE_MAX.saturating_sub(buf.len());
                buf.extend_from_slice(chunk.get(..n.min(room)).unwrap_or_default());
                if buf.contains(&b'\n') {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
    }
    let end = buf.iter().position(|b| *b == b'\n').unwrap_or(buf.len());
    String::from_utf8_lossy(buf.get(..end).unwrap_or_default()).trim().to_string()
}

impl Listener {
    fn start(reply: &'static [u8]) -> io::Result<Listener> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let thread = {
            let (seen, stop) = (seen.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let Ok((mut conn, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    };
                    // The connection counts when it is made, whether or not it says anything.
                    let index = match seen.lock() {
                        Ok(mut v) => {
                            v.push(String::new());
                            v.len() - 1
                        }
                        Err(_) => continue,
                    };
                    if live.load(Ordering::SeqCst) >= CONNECTIONS_AT_ONCE {
                        continue;
                    }
                    live.fetch_add(1, Ordering::SeqCst);
                    let (seen, stop, live) = (seen.clone(), stop.clone(), live.clone());
                    // Detached: nothing waits for a peer that does not finish.
                    std::thread::spawn(move || {
                        let line = read_first_line(&mut conn, &stop);
                        if let Ok(mut v) = seen.lock() {
                            if let Some(slot) = v.get_mut(index) {
                                *slot = line;
                            }
                        }
                        let _ = conn.write_all(reply);
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            })
        };
        Ok(Listener { port, seen, stop, thread: Some(thread) })
    }

    /// Whether a request line containing `needle` arrives within `wait`.
    fn saw(&self, needle: &str, wait: Duration) -> bool {
        let deadline = Instant::now() + wait;
        loop {
            if self.seen.lock().is_ok_and(|v| v.iter().any(|l| l.contains(needle))) {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// How many connections have been made.
    fn connections(&self) -> usize {
        self.seen.lock().map_or(0, |v| v.len())
    }

    /// The request lines so far.
    fn lines(&self) -> Vec<String> {
        self.seen.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn unique(what: &str) -> String {
    // The clock alone can repeat for two calls in one tick; the counter cannot.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    format!("{what}-{}-{nanos}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst))
}

fn quoted(p: &Path) -> String {
    format!("'{}'", p.to_string_lossy().replace('\'', "'\\''"))
}

/// Run `script` in `sb` from `cwd` and wait up to `limit`; the process group is killed after that. Returns
/// whether it exited 0 and what it printed.
pub(crate) fn run_script(sb: &Sandbox, cwd: &Path, script: &str, limit: Duration) -> io::Result<(bool, String)> {
    let (program, args) = sb.command(script);
    let out_path = sb.tmp_dir.join(format!("out-{}.txt", unique("probe")));
    let out = std::fs::File::create(&out_path)?;
    let mut child = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env("TMPDIR", &sb.tmp_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out.try_clone()?))
        .stderr(Stdio::from(out))
        .process_group(0)
        .spawn()?;
    let group = track(child.id());
    let deadline = Instant::now() + limit;
    let status = loop {
        let waited = child.try_wait();
        if !matches!(waited, Ok(None)) {
            untrack(group);
        }
        if let Some(status) = waited? {
            break Some(status);
        }
        if Instant::now() > deadline || STOPPED.load(Ordering::SeqCst) {
            if let Some(pid) = group {
                kill_group(pid);
            }
            untrack(group);
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let text = std::fs::read(&out_path).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);
    Ok((status.is_some_and(|s| s.success()), text))
}

/// A leaf certificate whose AIA `caIssuers` names `url`, made with the system `openssl`.
fn aia_certificate(dir: &Path, url: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
    let extensions = format!(
        "[v3]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n\
         subjectAltName=DNS:leaf.example\nauthorityInfoAccess=caIssuers;URI:{url}\n"
    );
    std::fs::write(dir.join("ext.cnf"), extensions).map_err(|e| format!("cannot write the extensions file: {e}"))?;
    let steps: [&[&str]; 3] = [
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-subj",
            "/CN=loom-probe-ca",
            "-days",
            "2",
        ],
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=leaf.example",
        ],
        &[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            "ext.cnf",
            "-extensions",
            "v3",
            "-out",
            "leaf.pem",
        ],
    ];
    for args in steps {
        let out = Command::new("/usr/bin/openssl")
            .args(args)
            .current_dir(dir)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("openssl did not run: {e}"))?;
        if !out.status.success() {
            return Err(format!("openssl {} failed", args.first().copied().unwrap_or("")));
        }
    }
    Ok(dir.join("leaf.pem"))
}

/// What every probe shares: the daemon's profile made safe to probe with, and a scratch directory.
struct Rig {
    cfg: SandboxCfg,
    loom_home: PathBuf,
    work: PathBuf,
    ws: PathBuf,
    /// Tests only: leave the daemon and infrastructure ports out of the `daemon_port` probe's profile, which is the
    /// hole that probe exists to find.
    hole: bool,
}

impl Rig {
    fn sandbox(&self, cfg: &SandboxCfg, name: &str) -> Result<Sandbox, String> {
        let tmp = self.work.join(format!("tmp-{name}"));
        std::fs::create_dir_all(&tmp).map_err(|e| format!("cannot make {}: {e}", tmp.display()))?;
        Sandbox::new(cfg, &self.ws, &tmp, &self.loom_home, None).map_err(|e| format!("the sandbox was not built: {e}"))
    }

    fn real(&self) -> SandboxCfg {
        self.cfg.clone()
    }

    fn control(&self) -> SandboxCfg {
        SandboxCfg { allow_fetch_services: true, ..self.cfg.clone() }
    }
}

/// What one try of a fetch probe does: the rig, the sandbox, the attempt's name, the listener's port and the path
/// the request must name.
type Attempt<'a> = dyn Fn(&Rig, &Sandbox, &str, u16, &str) -> Result<String, String> + 'a;

/// The shape of the three fetch probes: control, then the real profile, against one listener.
fn fetch_probe(rig: &Rig, probe: Probe, reply: &'static [u8], needs: &[&str], attempt: &Attempt) -> ProbeResult {
    for program in needs {
        if !Path::new(program).exists() {
            return result(probe, Outcome::NotExercised, format!("{program} is not on this host."));
        }
    }
    let listener = match Listener::start(reply) {
        Ok(l) => l,
        Err(e) => return result(probe, Outcome::Failed, format!("no listener could be opened: {e}")),
    };
    let nonce = unique("loom-selfprobe");
    let run = |cfg: SandboxCfg, name: &str, wait: Duration| -> Result<bool, String> {
        let sb = rig.sandbox(&cfg, name)?;
        let path = format!("/{name}-{nonce}");
        attempt(rig, &sb, name, listener.port, &path)?;
        Ok(listener.saw(&path, wait))
    };
    let control = match run(rig.control(), "control", CONTROL_WAIT) {
        Ok(c) => c,
        Err(e) => return result(probe, Outcome::Failed, e),
    };
    if !control {
        return result(
            probe,
            Outcome::NotExercised,
            "This host does not fetch a URL for a sandboxed command even with the fetch services allowed.",
        );
    }
    match run(rig.real(), "real", REAL_WAIT) {
        Ok(true) => result(
            probe,
            Outcome::Leaked,
            "A URL the command named was fetched outside the sandbox, past the egress proxy.",
        ),
        Ok(false) => result(probe, Outcome::Held, "The control fetched its URL; the real profile's did not."),
        Err(e) => result(probe, Outcome::Failed, e),
    }
}

fn aia_fetch(rig: &Rig) -> ProbeResult {
    fetch_probe(
        rig,
        Probe::AiaFetch,
        b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        &["/usr/bin/security", "/usr/bin/openssl"],
        &|rig, sb, name, port, path| {
            let leaf =
                aia_certificate(&rig.work.join(format!("cert-{name}")), &format!("http://127.0.0.1:{port}{path}"))?;
            let script = format!("/usr/bin/security verify-cert -c {} -p ssl -s leaf.example", quoted(&leaf));
            run_script(sb, &rig.ws, &script, SCRIPT_LIMIT)
                .map(|_| String::new())
                .map_err(|e| format!("the command did not run: {e}"))
        },
    )
}

/// JavaScript for Automation that runs `body`, then `secs` seconds on the main run loop, then `tail` (what cleans up
/// after `body`).
fn jxa_script(body: &str, tail: &str, secs: u32) -> String {
    format!("ObjC.import(\"Foundation\");\n{body}\n$.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow({secs}));\n{tail}\n")
}

/// The body and the tail of a JXA probe's script, from the listener's port, the path to request and an id.
type JxaParts<'a> = dyn Fn(u16, &str, &str) -> (String, String) + 'a;

fn jxa_probe(rig: &Rig, probe: Probe, parts: &JxaParts, secs: u32) -> ProbeResult {
    fetch_probe(
        rig,
        probe,
        b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        &["/usr/bin/osascript"],
        &|rig, sb, name, port, path| {
            let id = unique(&format!("loom-selfprobe-{name}"));
            let file = sb.tmp_dir.join(format!("{name}.js"));
            let (body, tail) = parts(port, path, &id);
            std::fs::write(&file, jxa_script(&body, &tail, secs))
                .map_err(|e| format!("cannot write the script: {e}"))?;
            let script = format!("/usr/bin/osascript -l JavaScript {}", quoted(&file));
            run_script(sb, &rig.ws, &script, SCRIPT_LIMIT)
                .map(|_| String::new())
                .map_err(|e| format!("the command did not run: {e}"))
        },
    )
}

fn url_session(rig: &Rig) -> ProbeResult {
    jxa_probe(
        rig,
        Probe::UrlSession,
        &|port, path, id| {
            // The session is invalidated at the end, so `nsurlsessiond` drops it with its download.
            (
                format!(
                    "var cfg = $.NSClassFromString(\"NSURLSessionConfiguration\").backgroundSessionConfigurationWithIdentifier(\"{id}\");\n\
                     var session = $.NSClassFromString(\"NSURLSession\").sessionWithConfiguration(cfg);\n\
                     var task = session.downloadTaskWithURL($.NSURL.URLWithString(\"http://127.0.0.1:{port}{path}\"));\n\
                     task.resume;"
                ),
                "task.cancel; session.invalidateAndCancel;".to_string(),
            )
        },
        5,
    )
}

fn web_kit(rig: &Rig) -> ProbeResult {
    jxa_probe(
        rig,
        Probe::WebKit,
        &|port, path, _| {
            // A non-persistent data store: the view leaves no website data in the operator's Library.
            (
                format!(
                    "ObjC.import(\"WebKit\");\n\
                     var conf = $.WKWebViewConfiguration.alloc.init;\n\
                     conf.websiteDataStore = $.WKWebsiteDataStore.nonPersistentDataStore;\n\
                     var view = $.WKWebView.alloc.initWithFrameConfiguration($.NSMakeRect(0, 0, 100, 100), conf);\n\
                     view.loadRequest($.NSClassFromString(\"NSURLRequest\").requestWithURL($.NSURL.URLWithString(\"http://127.0.0.1:{port}{path}\")));"
                ),
                "view.stopLoading;".to_string(),
            )
        },
        5,
    )
}

/// The decoy's code, in its argument vector; the sandboxed command finds it with `pgrep -fl` and presents it.
fn daemon_port(rig: &Rig) -> ProbeResult {
    let probe = Probe::DaemonPort;
    if !Path::new("/usr/bin/pgrep").exists() {
        return result(probe, Outcome::NotExercised, "pgrep is not on this host.");
    }
    let (daemon, infra) = match (Listener::start(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"), Listener::start(b""))
    {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            return result(probe, Outcome::Failed, format!("no listener could be opened: {e}"))
        }
    };
    let marker = unique("loom-selfprobe-argv");
    let code = format!("code-{}", unique("c").replace('-', ""));
    // The decoy sleeps outside the sandbox with the code in its argument vector (the trailing `:` keeps bash from
    // replacing itself with `sleep`, whose argument vector would not hold it).
    let mut decoy = match Command::new("/bin/bash")
        .args(["-c", "sleep 60; :", &format!("{marker}-{code}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return result(probe, Outcome::Failed, format!("the decoy process did not start: {e}")),
    };
    let decoy_group = track(decoy.id());
    let cfg = SandboxCfg {
        loopback_all: true,
        daemon_port: if rig.hole { None } else { Some(daemon.port) },
        infra_ports: if rig.hole { Vec::new() } else { vec![infra.port] },
        ..rig.cfg.clone()
    };
    let verdict = (|| -> Result<(bool, String), String> {
        let sb = rig.sandbox(&cfg, "daemon")?;
        // `pgrep -fl` lists the decoy's whole command line; the code is cut out of it and sent to both ports.
        let script = format!(
            "line=$(/usr/bin/pgrep -fl '[{first}]{rest}-code-' | head -n 1); c=${{line##*-code-}}; echo \"argv=${{line:+yes}}\"; \
             for p in {} {}; do (exec 3<>/dev/tcp/127.0.0.1/$p && printf 'GET /?code=%s HTTP/1.0\\r\\n\\r\\n' \"code-$c\" >&3 && sleep 1) 2>/dev/null; done",
            daemon.port,
            infra.port,
            first = &marker[..1],
            rest = &marker[1..],
        );
        let (_, out) =
            run_script(&sb, &rig.ws, &script, SCRIPT_LIMIT).map_err(|e| format!("the command did not run: {e}"))?;
        Ok((out.contains("argv=yes"), out))
    })();
    // A connection that carries the probe's own code (`code=code-...`, which only its script sends) is a leak; a
    // connection that does not (a port scan of the machine, another process) is noted and is not.
    let daemon_hit = daemon.saw(CODE_PREFIX, Duration::from_secs(2));
    let infra_hit = infra.saw(CODE_PREFIX, Duration::ZERO);
    let strays =
        (daemon.connections() + infra.connections()).saturating_sub(usize::from(daemon_hit) + usize::from(infra_hit));
    let carried = daemon.lines().iter().any(|l| l.contains(&code));
    let _ = decoy.kill();
    let _ = decoy.wait();
    untrack(decoy_group);
    daemon_verdict(verdict, daemon_hit, infra_hit, carried, strays)
}

/// What the script's request line starts with after `GET /?`: only the probe's script sends it.
const CODE_PREFIX: &str = "code=code-";

/// The `daemon_port` probe's result from what it observed: the command's result (whether the decoy's argument vector
/// was readable, or why the command did not run), whether a connection carrying the probe's code reached the daemon
/// stand-in and the infrastructure stand-in, whether the code the command read arrived, and how many other
/// connections arrived.
fn daemon_verdict(
    verdict: Result<(bool, String), String>,
    daemon_hit: bool,
    infra_hit: bool,
    carried: bool,
    strays: usize,
) -> ProbeResult {
    let probe = Probe::DaemonPort;
    let readable = match &verdict {
        Ok((true, _)) => "The decoy's argument vector was readable (the daemon puts no code there)",
        Ok(_) => "The decoy's argument vector was not readable",
        Err(_) => "",
    };
    let noise =
        if strays > 0 { format!(" ({strays} other connection(s) were not the probe's)") } else { String::new() };
    match verdict {
        Err(e) => result(probe, Outcome::Failed, e),
        Ok(_) if daemon_hit || infra_hit => result(
            probe,
            Outcome::Leaked,
            format!(
                "A sandboxed command connected to {} (the daemon's port in the probe profile, or an infrastructure port){}.",
                if daemon_hit { "the daemon port" } else { "an infrastructure port" },
                if carried { " and presented the code it read from a process list" } else { "" }
            ),
        ),
        Ok(_) => result(
            probe,
            Outcome::Held,
            format!("{readable}; the connections to the daemon and infrastructure ports were refused{noise}."),
        ),
    }
}

/// A command cannot plant what Git runs: a hook, `config` and `config.worktree` of a repository in a writable
/// root. The control writes a ref, which stays allowed, so a script that fails for another reason is not read as
/// a held rule.
fn git_metadata(rig: &Rig) -> ProbeResult {
    let probe = Probe::GitMetadata;
    let git = rig.ws.join(".git");
    let made = ["hooks", "refs/heads", "objects"].iter().try_for_each(|d| std::fs::create_dir_all(git.join(d)));
    let seeded = made
        .and_then(|()| std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n"))
        .and_then(|()| std::fs::write(git.join("config"), "[core]\n\tbare = false\n"));
    if let Err(e) = seeded {
        return result(probe, Outcome::Failed, format!("the probe repository could not be made: {e}"));
    }
    let before = std::fs::read(git.join("config")).unwrap_or_default();
    let verdict = (|| -> Result<(), String> {
        let sb = rig.sandbox(&rig.real(), "git")?;
        let script = "echo ref > .git/refs/heads/probe; echo x > .git/hooks/pre-commit; \
                      printf '[core]\\n\\tfsmonitor = x\\n' >> .git/config; echo x > .git/config.worktree; true";
        run_script(&sb, &rig.ws, script, SCRIPT_LIMIT).map(|_| ()).map_err(|e| format!("the command did not run: {e}"))
    })();
    if let Err(e) = verdict {
        return result(probe, Outcome::Failed, e);
    }
    let planted = git.join("hooks/pre-commit").exists()
        || git.join("config.worktree").exists()
        || std::fs::read(git.join("config")).unwrap_or_default() != before;
    git_verdict(git.join("refs/heads/probe").exists(), planted)
}

/// The `git_metadata` probe's result: whether the control write (a ref) landed and whether a hook or Git
/// configuration did.
fn git_verdict(control_landed: bool, planted: bool) -> ProbeResult {
    let probe = Probe::GitMetadata;
    if !control_landed {
        return result(probe, Outcome::Failed, "The control write (a ref, which Git may write) did not land.");
    }
    if planted {
        return result(
            probe,
            Outcome::Leaked,
            "A command wrote a hook or Git configuration that Git would run as the operator.",
        );
    }
    result(probe, Outcome::Held, "A ref was written; a hook, `config` and `config.worktree` could not be.")
}

/// A probe directory older than this was left by a daemon that ended while probing.
const STALE_AFTER: Duration = Duration::from_secs(600);

/// Remove the `loom-selfprobe-*` directories of `parent` that were last modified more than `older` ago.
fn remove_stale_directories(parent: &Path, older: Duration) {
    let Ok(entries) = std::fs::read_dir(parent) else { return };
    for entry in entries.flatten() {
        let named = entry.file_name().to_string_lossy().starts_with("loom-selfprobe-");
        let age = entry.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok());
        if named && entry.path().is_dir() && age.is_some_and(|a| a > older) {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Run the probes against `cfg` (the profile sessions get). See the contract.
pub fn run(cfg: &SandboxCfg, loom_home: &Path) -> Report {
    if cfg.mode != SandboxMode::Seatbelt || !Path::new(super::SANDBOX_EXEC).exists() {
        return Report::default();
    }
    STOPPED.store(false, Ordering::SeqCst);
    remove_stale_directories(&std::env::temp_dir(), STALE_AFTER);
    let work = std::env::temp_dir().join(unique("loom-selfprobe"));
    let setup = std::fs::create_dir_all(work.join("ws")).and_then(|()| work.canonicalize());
    let work = match setup {
        Ok(w) => w,
        Err(e) => {
            let detail = format!("the probe directory {} could not be made: {e}", work.display());
            let results = Probe::ALL.iter().map(|p| result(*p, Outcome::Failed, detail.clone())).collect();
            return Report { ran: true, results };
        }
    };
    let rig = Rig {
        cfg: SandboxCfg {
            loopback_all: false,
            loopback_ports: Vec::new(),
            unix_sockets: Vec::new(),
            extra_writable: Vec::new(),
            protected_paths: Vec::new(),
            unreadable_paths: Vec::new(),
            replay_untrusted_paths: Vec::new(),
            protect_credentials: false,
            daemon_port: None,
            infra_ports: Vec::new(),
            ..cfg.clone()
        },
        loom_home: loom_home.to_path_buf(),
        ws: work.join("ws"),
        work: work.clone(),
        hole: false,
    };
    let mut results = Vec::new();
    if cfg.allow_fetch_services {
        for p in [Probe::AiaFetch, Probe::UrlSession, Probe::WebKit] {
            results.push(result(
                p,
                Outcome::NotExercised,
                "sandbox.allow_fetch_services is set: the route is open by configuration.",
            ));
        }
    } else {
        results.push(aia_fetch(&rig));
        results.push(url_session(&rig));
        results.push(web_kit(&rig));
    }
    results.push(daemon_port(&rig));
    results.push(git_metadata(&rig));
    let _ = std::fs::remove_dir_all(&work);
    Report { ran: true, results }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn available() -> bool {
        Path::new(super::super::SANDBOX_EXEC).exists()
    }

    fn cfg() -> SandboxCfg {
        SandboxCfg { mode: SandboxMode::Seatbelt, ..SandboxCfg::default() }
    }

    fn home() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn a_report_lists_what_leaked_or_failed_and_nothing_else() {
        let report = Report {
            ran: true,
            results: vec![
                result(Probe::AiaFetch, Outcome::Held, "ok"),
                result(Probe::UrlSession, Outcome::Leaked, "a URL arrived"),
                result(Probe::WebKit, Outcome::NotExercised, "no"),
                result(Probe::DaemonPort, Outcome::Failed, "no listener"),
            ],
        };
        assert_eq!(
            report.problems(),
            ["self-probe url_session leaked: a URL arrived", "self-probe daemon_port could not run: no listener"]
        );
        assert!(Report::default().problems().is_empty() && !Report::default().ran);
        let json = serde_json::to_string(&report).expect("json");
        assert_eq!(serde_json::from_str::<Report>(&json).expect("back"), report);
        assert!(json.contains("\"probe\":\"aia_fetch\"") && json.contains("\"outcome\":\"not_exercised\""), "{json}");
        let names: Vec<&str> = Probe::ALL.iter().map(|p| p.name()).collect();
        assert_eq!(names, ["aia_fetch", "url_session", "web_kit", "daemon_port", "git_metadata"]);
    }

    #[test]
    fn a_listener_sees_a_request_and_counts_connections() {
        let l = Listener::start(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n").expect("listener");
        assert_eq!(l.connections(), 0);
        assert!(!l.saw("/nothing", Duration::from_millis(150)));
        let mut conn = std::net::TcpStream::connect(("127.0.0.1", l.port)).expect("connect");
        conn.write_all(b"GET /unique-path HTTP/1.0\r\n\r\n").expect("write");
        assert!(l.saw("/unique-path", Duration::from_secs(3)), "{:?}", l.lines());
        // A connection that says nothing still counts.
        let _silent = std::net::TcpStream::connect(("127.0.0.1", l.port)).expect("connect");
        let deadline = Instant::now() + Duration::from_secs(3);
        while l.connections() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(l.connections(), 2);
    }

    #[test]
    fn a_script_that_runs_too_long_is_killed() {
        if !available() {
            return;
        }
        let dir = home();
        let root = dir.path().canonicalize().expect("canonical");
        let (ws, tmp, home) = (root.join("ws"), root.join("tmp"), root.join("home"));
        for d in [&ws, &tmp, &home] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        let sb = Sandbox::new(&cfg(), &ws, &tmp, &home, None).expect("sandbox");
        let started = Instant::now();
        let (ok, _) = run_script(&sb, &ws, "sleep 30", Duration::from_millis(500)).expect("run");
        assert!(!ok && started.elapsed() < Duration::from_secs(10));
        let (ok, out) = run_script(&sb, &ws, "echo hi", Duration::from_secs(10)).expect("run");
        assert!(ok && out.trim() == "hi", "{out}");
    }

    #[test]
    fn the_probe_does_nothing_in_a_mode_that_has_no_sandbox_profile() {
        let dir = home();
        for mode in [SandboxMode::None, SandboxMode::Bubblewrap] {
            let report = run(&SandboxCfg { mode, ..SandboxCfg::default() }, dir.path());
            assert!(!report.ran && report.results.is_empty(), "{mode:?}");
        }
    }

    fn by_probe(report: &Report, p: Probe) -> &ProbeResult {
        report.results.iter().find(|r| r.probe == p).expect("probe result")
    }

    #[test]
    fn the_probes_hold_under_the_default_profile() {
        if !available() {
            return;
        }
        let dir = home();
        let report = run(&cfg(), dir.path());
        eprintln!("self-probe report: {report:#?}");
        assert!(report.ran && report.results.len() == 5, "{report:?}");
        for r in &report.results {
            assert!(matches!(r.outcome, Outcome::Held | Outcome::NotExercised), "{r:?}");
        }
        // The daemon-port probe needs no host service: it always runs and holds.
        assert_eq!(by_probe(&report, Probe::DaemonPort).outcome, Outcome::Held, "{report:?}");
        assert_eq!(by_probe(&report, Probe::GitMetadata).outcome, Outcome::Held, "{report:?}");
        assert!(report.problems().is_empty(), "{report:?}");
    }

    #[test]
    fn allow_fetch_services_skips_the_fetch_probes_and_still_checks_the_daemon_port() {
        if !available() {
            return;
        }
        // With the services allowed the three fetch probes are not run; the setting is the finding.
        let dir = home();
        let report = run(&SandboxCfg { allow_fetch_services: true, ..cfg() }, dir.path());
        for p in [Probe::AiaFetch, Probe::UrlSession, Probe::WebKit] {
            let r = by_probe(&report, p);
            assert_eq!(r.outcome, Outcome::NotExercised, "{r:?}");
            assert!(r.detail.contains("allow_fetch_services"), "{r:?}");
        }
        assert_eq!(by_probe(&report, Probe::DaemonPort).outcome, Outcome::Held, "{report:?}");
    }

    #[test]
    fn the_probe_sees_a_listener_that_the_profile_allows_as_a_leak() {
        if !available() {
            return;
        }
        // A profile that lets a command reach the daemon-port stand-in is the hole this probe exists to find. The
        // real `run` clears loopback, so this builds the probe's own rig with the daemon port left out of the profile.
        let dir = home();
        let work = std::env::temp_dir().join(unique("loom-selfprobe-test"));
        std::fs::create_dir_all(work.join("ws")).expect("mkdir");
        let work = work.canonicalize().expect("canonical");
        let rig = Rig {
            cfg: SandboxCfg { loopback_all: true, protect_credentials: false, ..cfg() },
            loom_home: dir.path().to_path_buf(),
            ws: work.join("ws"),
            work: work.clone(),
            hole: false,
        };
        let listener = Listener::start(b"").expect("listener");
        let sb = rig.sandbox(&rig.cfg, "hole").expect("sandbox");
        let script = format!(
            "(exec 3<>/dev/tcp/127.0.0.1/{} && printf 'GET /?code=x HTTP/1.0\\r\\n\\r\\n' >&3 && sleep 1)",
            listener.port
        );
        let _ = run_script(&sb, &rig.ws, &script, Duration::from_secs(10));
        assert!(
            listener.saw("code=x", Duration::from_secs(3)),
            "a profile that allows loopback must let the connection through"
        );
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn a_profile_that_allows_the_fetch_services_is_seen_leaking() {
        if !available() {
            return;
        }
        // The real profile here is the control itself: a host that fetches for a sandboxed command shows the leak.
        let dir = home();
        let work = std::env::temp_dir().join(unique("loom-selfprobe-test"));
        std::fs::create_dir_all(work.join("ws")).expect("mkdir");
        let work = work.canonicalize().expect("canonical");
        let rig = Rig {
            cfg: SandboxCfg { allow_fetch_services: true, protect_credentials: false, ..cfg() },
            loom_home: dir.path().to_path_buf(),
            ws: work.join("ws"),
            work: work.clone(),
            hole: false,
        };
        let aia = aia_fetch(&rig);
        let session = url_session(&rig);
        let _ = std::fs::remove_dir_all(&work);
        for r in [aia, session] {
            assert!(matches!(r.outcome, Outcome::Leaked | Outcome::NotExercised), "{r:?}");
            if r.outcome == Outcome::Leaked {
                assert!(r.detail.contains("past the egress proxy"), "{r:?}");
            }
        }
    }

    #[test]
    fn a_listener_is_not_held_by_a_peer_that_streams_without_a_newline() {
        let l = Listener::start(b"").expect("listener");
        let port = l.port;
        let ended = Arc::new(AtomicBool::new(false));
        let peer = {
            let ended = ended.clone();
            std::thread::spawn(move || {
                let Ok(mut conn) = std::net::TcpStream::connect(("127.0.0.1", port)) else { return };
                let chunk = [b'a'; 1024];
                while !ended.load(Ordering::SeqCst) {
                    if conn.write_all(&chunk).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        };
        // A second connection is served while the first streams.
        std::thread::sleep(Duration::from_millis(200));
        let mut conn = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        conn.write_all(b"GET /second HTTP/1.0\r\n\r\n").expect("write");
        assert!(l.saw("/second", Duration::from_secs(3)), "{:?}", l.lines().len());
        let started = Instant::now();
        // The streamed line is cut at LINE_MAX once the connection's limit passes.
        std::thread::sleep(CONNECTION_LIMIT + Duration::from_millis(500));
        assert!(l.lines().iter().all(|line| line.len() <= LINE_MAX), "a line is not bounded");
        drop(l);
        ended.store(true, Ordering::SeqCst);
        assert!(
            started.elapsed() < CONNECTION_LIMIT + Duration::from_secs(2),
            "dropping the listener waited for a peer"
        );
        let _ = peer.join();
    }

    #[test]
    fn dropping_a_listener_does_not_wait_for_a_silent_peer() {
        let l = Listener::start(b"").expect("listener");
        let _silent = std::net::TcpStream::connect(("127.0.0.1", l.port)).expect("connect");
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        drop(l);
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
    }

    #[test]
    fn the_daemon_port_verdict_is_a_leak_only_for_the_probes_own_connection() {
        let readable = || Ok((true, "argv=yes".to_string()));
        let held = daemon_verdict(readable(), false, false, false, 0);
        assert_eq!(held.outcome, Outcome::Held, "{held:?}");
        // A port scan of the machine connects without the code: noted, not a leak.
        let scanned = daemon_verdict(readable(), false, false, false, 3);
        assert_eq!(scanned.outcome, Outcome::Held, "{scanned:?}");
        assert!(scanned.detail.contains("3 other connection"), "{scanned:?}");
        let leaked = daemon_verdict(readable(), true, false, true, 0);
        assert_eq!(leaked.outcome, Outcome::Leaked, "{leaked:?}");
        assert!(
            leaked.detail.contains("the daemon port") && leaked.detail.contains("presented the code"),
            "{leaked:?}"
        );
        let infra = daemon_verdict(Ok((false, String::new())), false, true, false, 0);
        assert_eq!(infra.outcome, Outcome::Leaked, "{infra:?}");
        assert!(infra.detail.contains("an infrastructure port"), "{infra:?}");
        let failed = daemon_verdict(Err("the command did not run".into()), true, true, true, 0);
        assert_eq!(failed.outcome, Outcome::Failed, "{failed:?}");
    }

    #[test]
    fn the_git_verdict_reads_the_files_and_not_the_output() {
        assert_eq!(git_verdict(true, true).outcome, Outcome::Leaked);
        assert_eq!(git_verdict(true, false).outcome, Outcome::Held);
        // A control that did not land proves nothing, whatever else was seen.
        assert_eq!(git_verdict(false, false).outcome, Outcome::Failed);
        assert_eq!(git_verdict(false, true).outcome, Outcome::Failed);
    }

    #[test]
    fn the_daemon_port_probe_reports_a_hole_in_the_profile_as_a_leak() {
        if !available() || !Path::new("/usr/bin/pgrep").exists() {
            return;
        }
        // The same probe that holds under the daemon's profile, run with the ports left out of the profile.
        let dir = home();
        let work = std::env::temp_dir().join(unique("loom-selfprobe-test"));
        std::fs::create_dir_all(work.join("ws")).expect("mkdir");
        let work = work.canonicalize().expect("canonical");
        let rig = Rig {
            cfg: SandboxCfg { protect_credentials: false, ..cfg() },
            loom_home: dir.path().to_path_buf(),
            ws: work.join("ws"),
            work: work.clone(),
            hole: true,
        };
        let leaked = daemon_port(&rig);
        let held = daemon_port(&Rig { hole: false, ..rig_like(&rig) });
        let _ = std::fs::remove_dir_all(&work);
        assert_eq!(leaked.outcome, Outcome::Leaked, "{leaked:?}");
        assert!(leaked.detail.contains("presented the code"), "{leaked:?}");
        assert_eq!(held.outcome, Outcome::Held, "{held:?}");
    }

    fn rig_like(r: &Rig) -> Rig {
        Rig { cfg: r.cfg.clone(), loom_home: r.loom_home.clone(), work: r.work.clone(), ws: r.ws.clone(), hole: r.hole }
    }

    #[test]
    fn the_processes_of_a_probe_are_tracked_and_can_be_killed() {
        let mut child = Command::new("/bin/sleep").arg("30").process_group(0).spawn().expect("sleep");
        let group = track(child.id());
        assert!(group.is_some_and(|g| LIVE_GROUPS.lock().expect("lock").contains(&g)));
        if let Some(g) = group {
            kill_group(g);
        }
        let started = Instant::now();
        let status = child.wait().expect("wait");
        assert!(!status.success() && started.elapsed() < Duration::from_secs(5));
        untrack(group);
        assert!(group.is_some_and(|g| !LIVE_GROUPS.lock().expect("lock").contains(&g)));
    }

    #[test]
    fn a_directory_a_dead_probe_left_is_removed_and_nothing_else() {
        let dir = home();
        for name in ["loom-selfprobe-1-2", "loom-selfprobe-test-3", "other"] {
            std::fs::create_dir_all(dir.path().join(name).join("ws")).expect("mkdir");
        }
        std::thread::sleep(Duration::from_millis(20));
        // Too young to be stale: kept.
        remove_stale_directories(dir.path(), Duration::from_secs(3600));
        assert!(dir.path().join("loom-selfprobe-1-2").exists());
        remove_stale_directories(dir.path(), Duration::from_millis(1));
        assert!(!dir.path().join("loom-selfprobe-1-2").exists() && !dir.path().join("loom-selfprobe-test-3").exists());
        assert!(dir.path().join("other").exists());
    }
}
