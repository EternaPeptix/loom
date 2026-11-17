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
//!   does), and also tries a second listener named in `infra_ports`. Any connection to either is a leak. That the
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
//! directory removed. It blocks for up to about a minute: call it from a blocking thread.
//!
//! In mode `none` and `bubblewrap` there is nothing to probe: `run` returns a report with no results and
//! `Report::ran` false; the caller decides what that means (`loom-agent::egress`).
//!
//! Tests required: `a_report_lists_what_leaked_or_failed_and_nothing_else`, `a_listener_sees_a_request_and_counts_connections`,
//! `a_script_that_runs_too_long_is_killed`, `the_probe_does_nothing_in_a_mode_that_has_no_sandbox_profile`,
//! `the_probes_hold_under_the_default_profile` and `allow_fetch_services_skips_the_fetch_probes_and_still_checks_the_daemon_port`,
//! `a_profile_that_allows_the_fetch_services_is_seen_leaking` and
//! `the_probe_sees_a_listener_that_the_profile_allows_as_a_leak` (macOS only; each fetch probe reports `NotExercised`
//! when the host does not fetch).

use super::Sandbox;
use loom_core::config::{SandboxCfg, SandboxMode};
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Write};
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

/// A listener on a loopback port that records what connects.
struct Listener {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Listener {
    fn start(reply: &'static [u8]) -> io::Result<Listener> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
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
                    let _ = conn.set_nonblocking(false);
                    let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut line = String::new();
                    if BufReader::new(&conn).read_line(&mut line).is_ok() {
                        if let Ok(mut v) = seen.lock() {
                            if let Some(slot) = v.get_mut(index) {
                                *slot = line.trim().to_string();
                            }
                        }
                    }
                    let _ = conn.write_all(reply);
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
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    format!("{what}-{}-{nanos}", std::process::id())
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
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() > deadline {
            if let Ok(pid) = i32::try_from(child.id()) {
                // SAFETY: killpg on the group this function made; a stale pid names nothing we own.
                unsafe {
                    libc::killpg(pid, libc::SIGKILL);
                }
            }
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

/// JavaScript for Automation that runs for `secs` seconds on the main run loop.
fn jxa_script(body: &str, secs: u32) -> String {
    format!("ObjC.import(\"Foundation\");\n{body}\n$.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow({secs}));\n")
}

fn jxa_probe(rig: &Rig, probe: Probe, body: &dyn Fn(u16, &str, &str) -> String, secs: u32) -> ProbeResult {
    fetch_probe(
        rig,
        probe,
        b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        &["/usr/bin/osascript"],
        &|rig, sb, name, port, path| {
            let id = unique(&format!("loom-selfprobe-{name}"));
            let file = sb.tmp_dir.join(format!("{name}.js"));
            std::fs::write(&file, jxa_script(&body(port, path, &id), secs))
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
            format!(
                "var cfg = $.NSClassFromString(\"NSURLSessionConfiguration\").backgroundSessionConfigurationWithIdentifier(\"{id}\");\n\
                 var session = $.NSClassFromString(\"NSURLSession\").sessionWithConfiguration(cfg);\n\
                 var task = session.downloadTaskWithURL($.NSURL.URLWithString(\"http://127.0.0.1:{port}{path}\"));\n\
                 task.resume;"
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
            format!(
                "ObjC.import(\"WebKit\");\n\
                 var view = $.WKWebView.alloc.initWithFrameConfiguration($.NSMakeRect(0, 0, 100, 100), $.WKWebViewConfiguration.alloc.init);\n\
                 view.loadRequest($.NSClassFromString(\"NSURLRequest\").requestWithURL($.NSURL.URLWithString(\"http://127.0.0.1:{port}{path}\")));"
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
    let cfg = SandboxCfg {
        loopback_all: true,
        daemon_port: Some(daemon.port),
        infra_ports: vec![infra.port],
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
    // A connection that carries the code is the worst case; any connection is a hole in the profile.
    let waited = daemon.saw("code=", Duration::from_secs(2)) || infra.connections() > 0 || daemon.connections() > 0;
    let _ = decoy.kill();
    let _ = decoy.wait();
    let readable = match &verdict {
        Ok((true, _)) => "The decoy's argument vector was readable (the daemon puts no code there)",
        Ok(_) => "The decoy's argument vector was not readable",
        Err(_) => "",
    };
    let carried = daemon.lines().iter().any(|l| l.contains(&code));
    match verdict {
        Err(e) => result(probe, Outcome::Failed, e),
        Ok(_) if waited => result(
            probe,
            Outcome::Leaked,
            format!(
                "A sandboxed command connected to {} (the daemon's port in the probe profile, or an infrastructure port){}.",
                if daemon.connections() > 0 { "the daemon port" } else { "an infrastructure port" },
                if carried { " and presented the code it read from a process list" } else { "" }
            ),
        ),
        Ok(_) => result(probe, Outcome::Held, format!("{readable}; the connections to the daemon and infrastructure ports were refused.")),
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
    if !git.join("refs/heads/probe").exists() {
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

/// Run the probes against `cfg` (the profile sessions get). See the contract.
pub fn run(cfg: &SandboxCfg, loom_home: &Path) -> Report {
    if cfg.mode != SandboxMode::Seatbelt || !Path::new(super::SANDBOX_EXEC).exists() {
        return Report::default();
    }
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
}
