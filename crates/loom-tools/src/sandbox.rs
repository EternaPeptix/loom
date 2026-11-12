//! The sandbox: one policy, applied to commands by the OS and to in-process file access by us.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! ## Policy
//! - writable roots: the workspace, the session temp dir, `cfg.extra_writable`, and the system temp
//!   locations commands need (`/private/tmp`, `/private/var/folders`, `/dev`);
//! - never writable, even inside a writable root: `<workspace>/.loom`, the loom home directory, and
//!   `cfg.protected_paths` (relative entries are relative to the workspace). One exception: the
//!   session temp dir lies inside the loom home (`<loom home>/sessions/<id>/tmp`) and what is in it
//!   is writable all the same — but not the directory entry itself (it cannot be removed, renamed
//!   or replaced by a link), and not a protected path that is the temp dir or lies inside it. A temp
//!   dir that is `/`, or is or contains the loom home, is refused at construction;
//! - not readable: `<loom home>/token`, `<loom home>/keys`, `cfg.unreadable_paths` (`~` expands to
//!   the home directory) and, unless `cfg.protect_credentials` is off, the user's credential stores
//!   (`CREDENTIAL_PATHS` under the home directory). A credential store that is or contains the
//!   workspace is skipped, so the workspace stays readable; when the home directory is not known the
//!   stores cannot be located and construction is refused;
//! - starting something outside the sandbox is denied: LaunchServices opens, Apple Events, launchd
//!   jobs;
//! - network: denied, except loopback connections to the egress proxy port (when there is one), to
//!   `cfg.loopback_ports` — or to every loopback port when `cfg.loopback_all` — and to
//!   `cfg.unix_sockets`. Listening on loopback is allowed.
//!
//! All paths are made canonical when the sandbox is built (macOS: `/tmp` is `/private/tmp`); a
//! configured path that does not exist is kept as written after resolving its deepest existing
//! ancestor. On macOS, where volumes are case-insensitive by default, the rules that refuse (never
//! writable, not readable) are compared without regard to case; the rules that allow are compared
//! exactly, as they are everywhere else.
//!
//! ## `profile()`
//! The seatbelt profile text, `None` in mode `none`. This form is verified on macOS 27 — keep its
//! structure (later rules win):
//!
//! ```text
//! (version 1)
//! (allow default)
//! (deny signal)
//! (allow signal (target same-sandbox))
//! (deny file-write*)
//! (allow file-write* (subpath "<writable root>") …)
//! (deny file-write* (subpath "<protected>") …)
//! (allow file-write* (subpath "<session temp dir>"))
//! (deny file-write* (literal "<session temp dir>"))
//! (deny file-write* (subpath "<protected, at or inside the temp dir>") …)
//! (deny file-read* (subpath "<unreadable or credential store>") …)
//! (deny lsopen)
//! (deny appleevent-send)
//! (deny job-creation)
//! (deny network*)
//! (allow network-outbound (remote ip "localhost:<port>")) …      ; or "localhost:*" for loopback_all
//! (allow network-outbound (remote unix-socket (path-literal "<socket>"))) …
//! (allow network-bind (local ip "localhost:*"))
//! (allow network-inbound (local ip "localhost:*"))
//! ```
//!
//! A sandboxed process can signal itself and the other processes of its sandbox, and nothing else:
//! not the harness, not other sessions, not any other process of the same user.
//!
//! Paths are written as SBPL string literals: `\` and `"` are backslash-escaped; a path containing a
//! control character is an error at construction.
//!
//! ## `command(script)`
//! The program and arguments that run `script` with `/bin/bash -c`: in seatbelt mode
//! `/usr/bin/sandbox-exec -p <profile> /bin/bash -c <script>`; in mode `none`, `/bin/bash -c <script>`.
//!
//! ## `check_read(path)` / `check_write(path)`
//! The same policy for the file tools, which run in this process. `path` must be absolute. The path
//! is resolved through symlinks (canonicalise the deepest existing ancestor, then append the rest;
//! `..` components that remain are an error) and the *resolved* path is tested, so a symlink inside
//! the workspace that points outside it does not grant access. Returns the resolved path, or a
//! sentence: which path, which rule refused it, and what is allowed (for writes, the writable roots).
//! `check_write` tests the session temp dir before the never-writable rules, as the profile does.
//! In mode `none` only the never-writable and not-readable rules apply.
//!
//! ## `resolve(given)`
//! A path as the model wrote it → absolute: `~`/`~/x` expand to the home directory, a relative path
//! is joined to the workspace. No file-system access.
//!
//! ## `env(parent)`
//! The environment for commands: `parent` (the daemon's own variables) without any whose name
//! (case-insensitive) contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `CREDENTIAL`,
//! `AUTH_TOKEN`, `COOKIE` or `SESSION_KEY`, ends in `_PAT`, `_DSN` or `_PWD` (`PWD` and `OLDPWD`
//! stay), is `DATABASE_URL` or `SSH_AUTH_SOCK`, or starts with `LOOM_`, unless listed in
//! `cfg.env_pass`; plus `TERM=dumb`, `NO_COLOR=1`, `PAGER=cat`, `GIT_PAGER=cat`,
//! `GIT_TERMINAL_PROMPT=0`, `TMPDIR=<session temp dir>`.
//!
//! ## `describe()`
//! Two or three plain sentences for the system prompt: where commands may write, what they may not
//! read (credential stores included, when protected), how network access works. Deterministic. In
//! mode `none` it says commands are not confined and what the file tools still refuse.
//!
//! ## `preflight(cfg)`
//! Whether the configured mode can work on this host: seatbelt needs macOS and an executable
//! `/usr/bin/sandbox-exec`. The error is a sentence naming the problem and the alternatives; the
//! daemon refuses to start with it.
//!
//! Tests required: profile text for a representative config (exact string); escaping; canonical
//! paths; `check_write`/`check_read` accept and refuse per rule, including a symlink escape, a
//! not-yet-existing file in a writable dir, `..`, and the protected directory inside the workspace;
//! mode `none`; `resolve`; `env` scrubbing and `env_pass`. Tests that execute `sandbox-exec` are
//! welcome when `/usr/bin/sandbox-exec` exists (skip otherwise): a write inside the workspace
//! succeeds, a write outside fails, a read of an unreadable path fails.

use loom_core::config::{SandboxCfg, SandboxMode};
use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Device files commands may write to (redirections and pipes need these).
const DEVICE_LITERALS: [&str; 3] = ["/dev/null", "/dev/tty", "/dev/dtracehelper"];

/// System temp locations that commands need.
const SYSTEM_WRITABLE: [&str; 2] = ["/private/tmp", "/private/var/folders"];

const SECRET_WORDS: [&str; 9] =
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH_TOKEN", "COOKIE", "SESSION_KEY"];
const SECRET_SUFFIXES: [&str; 3] = ["_PAT", "_DSN", "_PWD"];
const SECRET_NAMES: [&str; 2] = ["DATABASE_URL", "SSH_AUTH_SOCK"];

/// Credential stores, relative to the user's home directory, that commands and file tools may not read.
const CREDENTIAL_PATHS: [&str; 22] = [
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gh",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".docker/config.json",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".git-credentials",
    ".config/git/credentials",
    ".password-store",
    ".config/op",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox",
    "Library/Safari",
];

#[derive(Clone, Debug)]
pub struct Sandbox {
    mode: SandboxMode,
    workspace: PathBuf,
    tmp_dir: PathBuf,
    home: Option<PathBuf>,
    writable: Vec<PathBuf>,
    protected: Vec<PathBuf>,
    unreadable: Vec<PathBuf>,
    credentials: Vec<PathBuf>,
    loopback_ports: Vec<u16>,
    loopback_all: bool,
    unix_sockets: Vec<PathBuf>,
    env_pass: Vec<String>,
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

/// Resolves symlinks in the deepest existing ancestor of `path` and appends the rest. A `..` in the
/// part that does not exist is an error when `lenient` is false and is applied lexically otherwise.
fn resolve_path(path: &Path, lenient: bool) -> Result<PathBuf, String> {
    let comps: Vec<Component> = path.components().collect();
    let mut base: Option<(PathBuf, usize)> = None;
    for n in (1..=comps.len()).rev() {
        let prefix: PathBuf = comps.iter().take(n).collect();
        if std::fs::symlink_metadata(&prefix).is_err() {
            continue;
        }
        match prefix.canonicalize() {
            Ok(c) => {
                base = Some((c, n));
                break;
            }
            Err(_) if lenient => {
                base = Some((prefix, n));
                break;
            }
            Err(e) => {
                return Err(format!(
                    "{} cannot be resolved ({e}); it may be a symlink that points nowhere. Use a path whose links all resolve.",
                    prefix.display()
                ))
            }
        }
    }
    let (mut out, used) = base.unwrap_or_default();
    for c in comps.iter().skip(used) {
        match c {
            Component::ParentDir => {
                if !lenient {
                    return Err(format!(
                        "{} contains `..` after a component that does not exist, so it cannot be resolved. Write the path without `..`.",
                        path.display()
                    ));
                }
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

/// A path as an SBPL string literal body; refuses what cannot be written safely.
fn sbpl(path: &Path) -> io::Result<String> {
    let s = path
        .to_str()
        .ok_or_else(|| invalid(format!("sandbox path {} is not valid UTF-8; use a path made of plain text.", path.display())))?;
    if s.chars().any(char::is_control) {
        return Err(invalid(format!("sandbox path {s:?} contains a control character; remove it from the configuration.")));
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn expand_home(given: &str, home: Option<&Path>) -> Option<PathBuf> {
    let home = home?;
    if given == "~" {
        Some(home.to_path_buf())
    } else {
        given.strip_prefix("~/").map(|rest| home.join(rest))
    }
}

/// Whether `path` is `rule` or lies under it, for a rule that refuses. Volumes on macOS are
/// case-insensitive by default, so there the comparison ignores case (over-blocking is acceptable);
/// elsewhere it is bytewise. Rules that allow are compared with `Path::starts_with` everywhere.
fn under(path: &Path, rule: &Path) -> bool {
    if !cfg!(target_os = "macos") {
        return path.starts_with(rule);
    }
    // Compared a character at a time: nothing is allocated for names that are valid UTF-8.
    let same = |a: Component, b: Component| {
        let (a, b) = (a.as_os_str().to_string_lossy(), b.as_os_str().to_string_lossy());
        a.chars().flat_map(char::to_lowercase).eq(b.chars().flat_map(char::to_lowercase))
    };
    let mut p = path.components();
    rule.components().all(|r| p.next().is_some_and(|c| c == r || same(c, r)))
}

/// Why `mode` cannot work on this host, if it cannot (`exec` is the seatbelt launcher).
fn preflight_at(mode: SandboxMode, exec: &Path, macos: bool) -> Result<(), String> {
    if mode != SandboxMode::Seatbelt {
        return Ok(());
    }
    let runnable = exec.metadata().map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.is_file() && m.permissions().mode() & 0o111 != 0
    });
    if macos && runnable.unwrap_or(false) {
        return Ok(());
    }
    let why = if macos {
        format!("{} is missing or not executable", exec.display())
    } else {
        "this host is not macOS".to_string()
    };
    Err(format!(
        "[sandbox] mode = \"seatbelt\" cannot work here: {why}. Run the daemon on macOS, or set [sandbox] mode = \"none\" \
         in the configuration knowing that commands are then not confined and can read and write anything this user can."
    ))
}

/// Checks that the configured sandbox mode can work on this host; the daemon refuses to start otherwise.
pub fn preflight(cfg: &SandboxCfg) -> Result<(), String> {
    preflight_at(cfg.mode, Path::new(SANDBOX_EXEC), cfg!(target_os = "macos"))
}

/// Whether the environment variable `name` looks like it holds a secret and is withheld from commands.
fn secret_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.starts_with("LOOM_")
        || SECRET_NAMES.contains(&upper.as_str())
        || SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s))
        || SECRET_WORDS.iter().any(|w| upper.contains(w))
}

fn join_list(paths: &[PathBuf]) -> String {
    paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
}

impl Sandbox {
    /// `proxy_port` is the session's egress proxy on loopback, when there is one.
    pub fn new(
        cfg: &SandboxCfg,
        workspace: &Path,
        tmp_dir: &Path,
        loom_home: &Path,
        proxy_port: Option<u16>,
    ) -> io::Result<Sandbox> {
        let home = match std::env::var_os("HOME") {
            Some(h) if !h.is_empty() => Some(PathBuf::from(h)),
            _ => None,
        };
        Self::with_home(cfg, workspace, tmp_dir, loom_home, proxy_port, home)
    }

    /// `new` with the user's home directory given instead of read from `HOME`.
    fn with_home(
        cfg: &SandboxCfg,
        workspace: &Path,
        tmp_dir: &Path,
        loom_home: &Path,
        proxy_port: Option<u16>,
        home: Option<PathBuf>,
    ) -> io::Result<Sandbox> {
        let canon = |p: &Path| resolve_path(p, true).map_err(invalid);
        let workspace = canon(workspace)?;
        let tmp_dir = canon(tmp_dir)?;
        let loom_home = canon(loom_home)?;
        // Everything in the temp dir is writable, so it cannot be a directory that holds anything else.
        if tmp_dir.parent().is_none() || under(&loom_home, &tmp_dir) {
            return Err(invalid(format!(
                "the session temp dir {} is the root directory, or is or contains the loom home {}; everything in the \
                 temp dir is writable, so give the session a directory of its own.",
                tmp_dir.display(),
                loom_home.display()
            )));
        }
        let home = match home {
            Some(h) => Some(canon(&h)?),
            None => None,
        };
        // A configured path: `~` expanded, relative ones taken from the workspace, then canonical.
        let anchored = |given: &str| -> io::Result<PathBuf> {
            let p = match expand_home(given, home.as_deref()) {
                Some(p) => p,
                None if given == "~" || given.starts_with("~/") => {
                    return Err(invalid(format!(
                        "the sandbox path {given:?} needs the home directory, but HOME is not set; write the path in full."
                    )))
                }
                None => PathBuf::from(given),
            };
            canon(&workspace.join(p))
        };

        let mut writable = vec![workspace.clone(), tmp_dir.clone()];
        for p in &cfg.extra_writable {
            push_unique(&mut writable, anchored(p)?);
        }
        for p in SYSTEM_WRITABLE {
            push_unique(&mut writable, canon(Path::new(p))?);
        }

        let mut protected = vec![canon(&workspace.join(".loom"))?, loom_home.clone()];
        for p in &cfg.protected_paths {
            push_unique(&mut protected, anchored(p)?);
        }

        let mut unreadable = vec![loom_home.join("token"), loom_home.join("keys")];
        for p in &cfg.unreadable_paths {
            push_unique(&mut unreadable, anchored(p)?);
        }

        // The workspace stays readable: a credential path that is or contains it is skipped.
        let mut credentials = Vec::new();
        if cfg.protect_credentials {
            let Some(h) = &home else {
                return Err(invalid(
                    "sandbox.protect_credentials is on, but the home directory is not known (HOME is not set), so the \
                     credential stores cannot be located. Start the daemon with HOME set, or set [sandbox] \
                     protect_credentials = false knowing that commands and file tools can then read them."
                        .to_string(),
                ));
            };
            for rel in CREDENTIAL_PATHS {
                let p = canon(&h.join(rel))?;
                if !workspace.starts_with(&p) {
                    push_unique(&mut credentials, p);
                }
            }
        }

        let mut loopback_ports = Vec::new();
        if let Some(p) = proxy_port {
            loopback_ports.push(p);
        }
        for p in &cfg.loopback_ports {
            push_unique(&mut loopback_ports, *p);
        }

        let mut unix_sockets = Vec::new();
        for p in &cfg.unix_sockets {
            push_unique(&mut unix_sockets, anchored(p)?);
        }

        // Every path that can reach a profile must be writable as a literal, whatever the mode.
        for p in writable.iter().chain(&protected).chain(&unreadable).chain(&credentials).chain(&unix_sockets) {
            sbpl(p)?;
        }
        Ok(Sandbox {
            mode: cfg.mode,
            workspace,
            tmp_dir,
            home,
            writable,
            protected,
            unreadable,
            credentials,
            loopback_ports,
            loopback_all: cfg.loopback_all,
            unix_sockets,
            env_pass: cfg.env_pass.clone(),
        })
    }

    pub fn mode(&self) -> SandboxMode {
        self.mode
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn tmp_dir(&self) -> &Path {
        &self.tmp_dir
    }

    pub fn profile(&self) -> Option<String> {
        if self.mode == SandboxMode::None {
            return None;
        }
        // Paths were validated in `new`; one that fails here is left out rather than half written.
        let subpaths = |v: &[PathBuf]| {
            v.iter().filter_map(|p| sbpl(p).ok()).map(|s| format!(" (subpath \"{s}\")")).collect::<String>()
        };
        let mut out = String::from(
            "(version 1)\n(allow default)\n(deny signal)\n(allow signal (target same-sandbox))\n(deny file-write*)\n",
        );
        let literals: String = DEVICE_LITERALS.iter().map(|d| format!(" (literal \"{d}\")")).collect();
        out.push_str(&format!("(allow file-write*{}{literals})\n", subpaths(&self.writable)));
        if !self.protected.is_empty() {
            out.push_str(&format!("(deny file-write*{})\n", subpaths(&self.protected)));
        }
        // The session temp dir may lie inside a protected directory; this later rule wins. The directory
        // entry itself stays unwritable, so it cannot be removed, renamed or replaced by a link that the
        // next activation of the session would follow.
        if let Ok(t) = sbpl(&self.tmp_dir) {
            out.push_str(&format!("(allow file-write* (subpath \"{t}\"))\n(deny file-write* (literal \"{t}\"))\n"));
        }
        let inside_tmp = self.inside_tmp_protected();
        if !inside_tmp.is_empty() {
            out.push_str(&format!("(deny file-write*{})\n", subpaths(&inside_tmp)));
        }
        let unreadable: Vec<PathBuf> = self.unreadable.iter().chain(&self.credentials).cloned().collect();
        if !unreadable.is_empty() {
            out.push_str(&format!("(deny file-read*{})\n", subpaths(&unreadable)));
        }
        // Opening an application or URL through LaunchServices, driving one with Apple Events, or handing
        // launchd a job, runs code outside the sandbox.
        out.push_str("(deny lsopen)\n(deny appleevent-send)\n(deny job-creation)\n");
        out.push_str("(deny network*)\n");
        if self.loopback_all {
            out.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
        } else {
            for p in &self.loopback_ports {
                out.push_str(&format!("(allow network-outbound (remote ip \"localhost:{p}\"))\n"));
            }
        }
        for s in self.unix_sockets.iter().filter_map(|p| sbpl(p).ok()) {
            out.push_str(&format!("(allow network-outbound (remote unix-socket (path-literal \"{s}\")))\n"));
        }
        out.push_str("(allow network-bind (local ip \"localhost:*\"))\n");
        out.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
        Some(out)
    }

    /// Protected paths that are the session temp dir or lie inside it; they stay protected.
    fn inside_tmp_protected(&self) -> Vec<PathBuf> {
        self.protected.iter().filter(|p| under(p, &self.tmp_dir)).cloned().collect()
    }

    pub fn command(&self, script: &str) -> (String, Vec<String>) {
        match self.profile() {
            Some(profile) => (
                SANDBOX_EXEC.to_string(),
                vec!["-p".into(), profile, "/bin/bash".into(), "-c".into(), script.to_string()],
            ),
            None => ("/bin/bash".to_string(), vec!["-c".into(), script.to_string()]),
        }
    }

    fn resolved(&self, path: &Path) -> Result<PathBuf, String> {
        if !path.is_absolute() {
            return Err(format!(
                "{} is not an absolute path; give the full path (relative paths are taken from the workspace {}).",
                path.display(),
                self.workspace.display()
            ));
        }
        resolve_path(path, false)
    }

    pub fn check_read(&self, path: &Path) -> Result<PathBuf, String> {
        let r = self.resolved(path)?;
        if let Some(rule) = self.unreadable.iter().find(|u| under(&r, u)) {
            return Err(format!(
                "{} is not readable: {} is off limits to commands and file tools. Read something else, or ask the user to change `sandbox.unreadable_paths` if this is wrong.",
                r.display(),
                rule.display()
            ));
        }
        if let Some(rule) = self.credentials.iter().find(|u| under(&r, u)) {
            return Err(format!(
                "{} is not readable: {} is a credential store, off limits to commands and file tools. Read something else, or ask the user to set `sandbox.protect_credentials = false` if this is wrong.",
                r.display(),
                rule.display()
            ));
        }
        Ok(r)
    }

    pub fn check_write(&self, path: &Path) -> Result<PathBuf, String> {
        let r = self.resolved(path)?;
        // The session temp dir is writable even when it lies inside a protected directory.
        if r.starts_with(&self.tmp_dir) && !self.inside_tmp_protected().iter().any(|p| under(&r, p)) {
            return Ok(r);
        }
        if let Some(rule) = self.protected.iter().find(|p| under(&r, p)) {
            return Err(format!(
                "{} is protected: nothing under {} can be written by commands or file tools. Write elsewhere in the workspace.",
                r.display(),
                rule.display()
            ));
        }
        if self.mode == SandboxMode::Seatbelt {
            let device = DEVICE_LITERALS.iter().any(|d| r == Path::new(d));
            if !device && !self.writable.iter().any(|w| r.starts_with(w)) {
                let shown = if r == path { String::new() } else { format!(" (resolved from {})", path.display()) };
                return Err(format!(
                    "{}{shown} is outside the writable areas. Writes are allowed only under: {}. Choose a path under one of them.",
                    r.display(),
                    join_list(&self.writable)
                ));
            }
        }
        Ok(r)
    }

    pub fn resolve(&self, given: &str) -> PathBuf {
        match expand_home(given, self.home.as_deref()) {
            Some(p) => p,
            None => self.workspace.join(given),
        }
    }

    pub fn env(&self, parent: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let mut out: BTreeMap<String, String> = parent
            .iter()
            .filter(|(name, _)| {
                self.env_pass.iter().any(|p| p == *name) || !secret_name(name)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in [("TERM", "dumb"), ("NO_COLOR", "1"), ("PAGER", "cat"), ("GIT_PAGER", "cat"), ("GIT_TERMINAL_PROMPT", "0")] {
            out.insert(k.to_string(), v.to_string());
        }
        out.insert("TMPDIR".to_string(), self.tmp_dir.display().to_string());
        out
    }

    pub fn describe(&self) -> String {
        let protected = join_list(&self.protected);
        let unreadable = join_list(&self.unreadable);
        // In mode `none` nothing confines commands, so the credential rule is stated as the file tools' own.
        let credentials = match (self.credentials.is_empty(), self.mode) {
            (true, _) => "",
            (false, SandboxMode::None) => {
                " They also refuse to read credential directories (~/.ssh, ~/.aws, ~/.gnupg, keychains, browser \
                 profiles and similar)."
            }
            (false, SandboxMode::Seatbelt) => {
                " Credential directories (~/.ssh, ~/.aws, ~/.gnupg, keychains, browser profiles and similar) are \
                 off limits to read."
            }
        };
        if self.mode == SandboxMode::None {
            return format!(
                "Commands are not confined by an operating-system sandbox: they can read and write anything this user can. \
                 File tools still refuse to write under {protected} and to read {unreadable}.{credentials}"
            );
        }
        let ports = if self.loopback_all {
            "any loopback port".to_string()
        } else if self.loopback_ports.is_empty() {
            "no loopback port".to_string()
        } else {
            format!("loopback ports {}", self.loopback_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))
        };
        let sockets = if self.unix_sockets.is_empty() {
            String::new()
        } else {
            format!(" and the unix sockets {}", join_list(&self.unix_sockets))
        };
        format!(
            "Commands and file tools may write only under {}; writes under {protected} are refused even there. \
             {unreadable} cannot be read.{credentials} \
             Direct network access is blocked except connections to {ports}{sockets}; reach other hosts through the proxy named in the environment, if there is one.",
            join_list(&self.writable)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    struct Fx {
        _dir: tempfile::TempDir,
        root: PathBuf,
        ws: PathBuf,
        tmp: PathBuf,
        home: PathBuf,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical");
        let (ws, tmp, home) = (root.join("ws"), root.join("tmp"), root.join("home"));
        for d in [&ws, &tmp, &home, &ws.join(".loom"), &home.join("keys")] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::write(home.join("token"), "t0ken").expect("write");
        std::fs::write(home.join("other"), "visible").expect("write");
        std::fs::write(home.join("keys").join("k"), "k").expect("write");
        Fx { _dir: dir, root, ws, tmp, home }
    }

    /// The production layout: the session temp dir lies inside the loom home.
    fn fx_prod() -> Fx {
        let mut f = fx();
        f.tmp = f.home.join("sessions").join("s1").join("tmp");
        std::fs::create_dir_all(&f.tmp).expect("mkdir");
        std::fs::write(f.home.join("sessions/s1/log.jsonl"), "{}").expect("write");
        f
    }

    /// A sandbox whose user home directory is `fake_home` instead of the real one.
    fn build_home(f: &Fx, c: &SandboxCfg, fake_home: &Path) -> Sandbox {
        Sandbox::with_home(c, &f.ws, &f.tmp, &f.home, None, Some(fake_home.to_path_buf())).expect("sandbox")
    }

    fn cfg(mode: SandboxMode) -> SandboxCfg {
        SandboxCfg { mode, ..SandboxCfg::default() }
    }

    fn build(f: &Fx, c: &SandboxCfg, proxy: Option<u16>) -> Sandbox {
        Sandbox::new(c, &f.ws, &f.tmp, &f.home, proxy).expect("sandbox")
    }

    fn s(p: &Path) -> &str {
        p.to_str().expect("utf-8 path")
    }

    #[test]
    fn profile_has_the_verified_shape() {
        let f = fx();
        let c = SandboxCfg {
            extra_writable: vec![format!("{}/extra", s(&f.root))],
            protected_paths: vec!["secrets".into()],
            unreadable_paths: vec![format!("{}/hidden", s(&f.root))],
            loopback_ports: vec![9000, 8080],
            unix_sockets: vec![format!("{}/run.sock", s(&f.root))],
            protect_credentials: false,
            ..cfg(SandboxMode::Seatbelt)
        };
        let sb = build(&f, &c, Some(8080));
        let r = s(&f.root);
        let expected = format!(
            "(version 1)\n(allow default)\n(deny signal)\n(allow signal (target same-sandbox))\n(deny file-write*)\n\
             (allow file-write* (subpath \"{r}/ws\") (subpath \"{r}/tmp\") (subpath \"{r}/extra\") (subpath \"/private/tmp\") (subpath \"/private/var/folders\") (literal \"/dev/null\") (literal \"/dev/tty\") (literal \"/dev/dtracehelper\"))\n\
             (deny file-write* (subpath \"{r}/ws/.loom\") (subpath \"{r}/home\") (subpath \"{r}/ws/secrets\"))\n\
             (allow file-write* (subpath \"{r}/tmp\"))\n\
             (deny file-write* (literal \"{r}/tmp\"))\n\
             (deny file-read* (subpath \"{r}/home/token\") (subpath \"{r}/home/keys\") (subpath \"{r}/hidden\"))\n\
             (deny lsopen)\n(deny appleevent-send)\n(deny job-creation)\n\
             (deny network*)\n\
             (allow network-outbound (remote ip \"localhost:8080\"))\n\
             (allow network-outbound (remote ip \"localhost:9000\"))\n\
             (allow network-outbound (remote unix-socket (path-literal \"{r}/run.sock\")))\n\
             (allow network-bind (local ip \"localhost:*\"))\n\
             (allow network-inbound (local ip \"localhost:*\"))\n"
        );
        assert_eq!(sb.profile().expect("profile"), expected);
        let (prog, args) = sb.command("echo hi");
        assert_eq!(prog, "/usr/bin/sandbox-exec");
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], expected);
        assert_eq!(&args[2..], ["/bin/bash", "-c", "echo hi"]);
    }

    #[test]
    fn profile_denies_launch_services_apple_events_and_launchd_jobs() {
        let f = fx();
        let p = build(&f, &cfg(SandboxMode::Seatbelt), None).profile().expect("profile");
        for rule in ["(deny lsopen)\n", "(deny appleevent-send)\n", "(deny job-creation)\n"] {
            assert!(p.contains(rule), "{rule} is missing: {p}");
        }
    }

    #[test]
    fn temp_dir_inside_the_loom_home_is_writable_but_nothing_else_there() {
        let f = fx_prod();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let p = sb.profile().expect("profile");
        let deny = p.find("(deny file-write* (subpath \"").expect("protected deny");
        let allow = p.rfind(&format!("(allow file-write* (subpath \"{}\"))\n", s(&f.tmp))).expect("tmp allow");
        assert!(allow > deny, "the temp-dir allow must come after the protected deny: {p}");
        let entry = p.rfind(&format!("(deny file-write* (literal \"{}\"))\n", s(&f.tmp))).expect("tmp entry deny");
        assert!(entry > allow, "the deny for the temp dir entry must come after its allow: {p}");
        for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
            let sb = build(&f, &cfg(mode), None);
            assert!(sb.check_write(&f.tmp.join("x")).is_ok());
            assert!(sb.check_write(&f.tmp.join("new/dir/x")).is_ok());
            assert!(sb.check_write(&f.home.join("sessions/s1/log.jsonl")).is_err());
            assert!(sb.check_write(&f.home.join("sessions/s1/tmpx")).is_err());
            assert!(sb.check_write(&f.home.join("sessions/s1/x")).is_err());
            assert!(sb.check_write(&f.home.join("other")).is_err());
        }
    }

    #[test]
    fn protected_path_inside_the_temp_dir_stays_protected() {
        let f = fx();
        // A temp dir that is the workspace itself must not unprotect `.loom`.
        let sb = Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &f.ws, &f.home, None).expect("sandbox");
        assert!(sb.check_write(&f.ws.join("a")).is_ok());
        assert!(sb.check_write(&f.ws.join(".loom/x")).is_err());
        let p = sb.profile().expect("profile");
        let last_allow = p.rfind("(allow file-write*").expect("allow");
        let last_deny = p.rfind(&format!("(deny file-write* (subpath \"{}/.loom\"))", s(&f.ws))).expect("deny");
        assert!(last_deny > last_allow, "{p}");
        // Nor does a temp dir that is itself a protected directory become writable.
        let dot = f.ws.join(".loom");
        let sb = Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &dot, &f.home, None).expect("sandbox");
        assert!(sb.check_write(&dot.join("x")).is_err());
        let p = sb.profile().expect("profile");
        let last_allow = p.rfind("(allow file-write*").expect("allow");
        let last_deny = p.rfind(&format!("(deny file-write* (subpath \"{}\"))", s(&dot))).expect("deny");
        assert!(last_deny > last_allow, "{p}");
        let none = Sandbox::new(&cfg(SandboxMode::None), &f.ws, &dot, &f.home, None).expect("sandbox");
        assert!(none.check_write(&dot.join("x")).is_err());
    }

    #[test]
    fn a_temp_dir_that_holds_the_loom_home_is_refused() {
        let f = fx();
        for tmp in [f.home.as_path(), f.root.as_path(), Path::new("/")] {
            for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
                let e = Sandbox::new(&cfg(mode), &f.ws, tmp, &f.home, None).expect_err("temp dir over the loom home");
                assert!(e.to_string().contains("session temp dir") && e.to_string().contains(s(&f.home)), "{e}");
            }
        }
        // A directory of its own inside the loom home is where it belongs.
        let inside = f.home.join("sessions/s1/tmp");
        assert!(Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &inside, &f.home, None).is_ok());
    }

    #[test]
    fn credentials_are_unreadable_by_default() {
        let f = fx();
        let fake = f.root.join("fakehome");
        std::fs::create_dir_all(fake.join(".ssh")).expect("mkdir");
        std::fs::write(fake.join(".ssh/id"), "private").expect("write");
        std::fs::write(fake.join(".netrc"), "machine x").expect("write");
        std::fs::write(fake.join("notes"), "fine").expect("write");
        let sb = build_home(&f, &cfg(SandboxMode::Seatbelt), &fake);
        // The refusal names the setting that governs it, which is not `unreadable_paths`.
        let e = sb.check_read(&fake.join(".ssh/id")).expect_err("ssh");
        assert!(e.contains("not readable") && e.contains("credential store"), "{e}");
        assert!(e.contains("`sandbox.protect_credentials = false`") && !e.contains("unreadable_paths"), "{e}");
        assert!(sb.check_read(&fake.join(".netrc")).is_err());
        assert!(sb.check_read(&fake.join(".aws/credentials")).is_err());
        assert!(sb.check_read(&fake.join("Library/Keychains/login.keychain-db")).is_err());
        assert!(sb.check_read(&fake.join("notes")).is_ok());
        let p = sb.profile().expect("profile");
        assert!(p.contains(&format!("(subpath \"{}/.ssh\")", s(&fake))), "{p}");
        assert!(sb.describe().contains("Credential directories"), "{}", sb.describe());
        // Mode none keeps the read rule for the file tools, and says that it is theirs alone.
        let none = build_home(&f, &cfg(SandboxMode::None), &fake);
        assert!(none.check_read(&fake.join(".ssh/id")).is_err());
        let d = none.describe();
        assert!(d.contains("They also refuse to read credential directories") && !d.contains("off limits"), "{d}");
        // Switched off, nothing is added.
        let off = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        let sb = build_home(&f, &off, &fake);
        assert!(sb.check_read(&fake.join(".ssh/id")).is_ok());
        assert!(!sb.profile().expect("profile").contains(".ssh"));
        assert!(!sb.describe().contains("Credential directories"));
    }

    #[test]
    fn a_workspace_inside_a_credential_directory_stays_readable() {
        let f = fx();
        let fake = f.root.join("fakehome2");
        let ws = fake.join(".config/gh/project");
        std::fs::create_dir_all(&ws).expect("mkdir");
        std::fs::create_dir_all(fake.join(".ssh")).expect("mkdir");
        let sb = Sandbox::with_home(&cfg(SandboxMode::Seatbelt), &ws, &f.tmp, &f.home, None, Some(fake.clone()))
            .expect("sandbox");
        assert!(sb.check_read(&ws.join("src.rs")).is_ok());
        assert!(sb.check_read(&fake.join(".config/gh/hosts.yml")).is_ok());
        assert!(sb.check_read(&fake.join(".ssh/id")).is_err());
        assert!(!sb.profile().expect("profile").contains(&format!("(subpath \"{}/.config/gh\")", s(&fake))));
    }

    #[test]
    fn credential_protection_needs_a_home_directory() {
        let f = fx();
        // Without a home directory the stores cannot be located; protecting nothing in silence is not an option.
        for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
            let e = Sandbox::with_home(&cfg(mode), &f.ws, &f.tmp, &f.home, None, None).expect_err("no home directory");
            let e = e.to_string();
            assert!(e.contains("HOME") && e.contains("protect_credentials = false"), "{e}");
        }
        let off = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        let sb = Sandbox::with_home(&off, &f.ws, &f.tmp, &f.home, None, None).expect("sandbox");
        assert!(!sb.describe().contains("redential"), "{}", sb.describe());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn protected_and_unreadable_rules_ignore_case_on_macos() {
        let f = fx();
        // A workspace with no `.loom` yet, and configured paths that do not exist: `realpath` restores the
        // spelling of what is on disk, so only for a missing path does the comparison itself decide.
        let (ws, fake) = (f.root.join("bare"), f.root.join("fakehome3"));
        for d in [&ws, &fake] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        let c = SandboxCfg {
            protected_paths: vec!["secrets".into()],
            unreadable_paths: vec![format!("{}/hidden", s(&f.root))],
            ..cfg(SandboxMode::Seatbelt)
        };
        let sb = Sandbox::with_home(&c, &ws, &f.tmp, &f.home, None, Some(fake.clone())).expect("sandbox");
        assert!(sb.check_write(&ws.join(".LOOM/x")).is_err());
        assert!(sb.check_write(&ws.join(".Loom")).is_err());
        assert!(sb.check_write(&ws.join("SECRETS/x")).is_err());
        assert!(sb.check_write(&ws.join(".loomy")).is_ok());
        assert!(sb.check_write(&ws.join("Secret")).is_ok());
        assert!(sb.check_read(&f.root.join("HIDDEN/x")).is_err());
        assert!(sb.check_read(&f.root.join("Hidden")).is_err());
        assert!(sb.check_read(&fake.join(".SSH/id")).is_err());
        assert!(sb.check_read(&f.root.join("hidden2")).is_ok());
        assert!(!ws.join(".loom").exists() && !ws.join("secrets").exists() && !f.root.join("hidden").exists());
        // Letters outside ASCII fold too, and a longer name is not a match.
        let rule = Path::new("/a/école");
        assert!(under(Path::new("/A/ÉCOLE/x"), rule) && under(Path::new("/a/École"), rule));
        assert!(!under(Path::new("/a/écoles"), rule) && !under(Path::new("/a"), rule));
    }

    #[test]
    fn loopback_all_replaces_port_rules() {
        let f = fx();
        let c = SandboxCfg { loopback_all: true, loopback_ports: vec![9000], ..cfg(SandboxMode::Seatbelt) };
        let p = build(&f, &c, Some(8080)).profile().expect("profile");
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:*\"))\n"));
        assert!(!p.contains("localhost:9000"));
    }

    #[test]
    fn special_characters_are_escaped_and_control_characters_refused() {
        let f = fx();
        let odd = f.root.join("a\"b\\c");
        std::fs::create_dir_all(&odd).expect("mkdir");
        let sb = Sandbox::new(&cfg(SandboxMode::Seatbelt), &odd, &f.tmp, &f.home, None).expect("sandbox");
        let p = sb.profile().expect("profile");
        assert!(p.contains(&format!("(subpath \"{}/a\\\"b\\\\c\")", s(&f.root))), "{p}");

        let bad = f.root.join("new\nline");
        std::fs::create_dir_all(&bad).expect("mkdir");
        let err = Sandbox::new(&cfg(SandboxMode::Seatbelt), &bad, &f.tmp, &f.home, None).expect_err("control char");
        assert!(err.to_string().contains("control character"), "{err}");
    }

    #[test]
    fn paths_are_canonical() {
        let f = fx();
        let link = f.root.join("link");
        symlink(&f.ws, &link).expect("symlink");
        let c = SandboxCfg { extra_writable: vec![format!("{}/newdir", s(&link))], ..cfg(SandboxMode::Seatbelt) };
        let sb = Sandbox::new(&c, &link, &f.tmp, &f.home, None).expect("sandbox");
        assert_eq!(sb.workspace(), f.ws);
        assert_eq!(sb.tmp_dir(), f.tmp);
        let p = sb.profile().expect("profile");
        assert!(p.contains(&format!("(subpath \"{}/newdir\")", s(&f.ws))), "{p}");
        assert!(!p.contains("link"), "{p}");
        // `..` in a configured path that does not exist is applied lexically.
        let c = SandboxCfg { extra_writable: vec!["/usr/local/loomtest/a/../b".into()], ..cfg(SandboxMode::Seatbelt) };
        let p = build(&f, &c, None).profile().expect("profile");
        assert!(p.contains("(subpath \"/usr/local/loomtest/b\")"), "{p}");
    }

    #[test]
    fn check_write_follows_the_policy() {
        let f = fx();
        let c = SandboxCfg {
            extra_writable: vec!["/usr/local/loomtest".into()],
            protected_paths: vec!["/usr/local/loomtest/p".into(), "ws-protected".into()],
            ..cfg(SandboxMode::Seatbelt)
        };
        let sb = build(&f, &c, None);
        // Accepted: existing file, a file that does not exist yet (in a directory that does not
        // exist either), the session temp dir, an extra root, a device.
        assert_eq!(sb.check_write(&f.ws.join("a.txt")), Ok(f.ws.join("a.txt")));
        assert_eq!(sb.check_write(&f.ws.join("new/dir/a.txt")), Ok(f.ws.join("new/dir/a.txt")));
        assert!(sb.check_write(&f.tmp.join("x")).is_ok());
        assert!(sb.check_write(Path::new("/usr/local/loomtest/a/b")).is_ok());
        assert!(sb.check_write(Path::new("/dev/null")).is_ok());
        // Refused: outside, the protected directory, the loom home, configured protected paths.
        let e = sb.check_write(Path::new("/usr/bin/x")).expect_err("outside");
        assert!(e.contains("/usr/bin/x") && e.contains("outside the writable areas") && e.contains(s(&f.ws)), "{e}");
        let e = sb.check_write(&f.ws.join(".loom/events")).expect_err("protected");
        assert!(e.contains("protected") && e.contains(".loom"), "{e}");
        assert!(sb.check_write(&f.ws.join(".loom")).is_err());
        assert!(sb.check_write(&f.home.join("anything")).is_err());
        assert!(sb.check_write(Path::new("/usr/local/loomtest/p/q")).is_err());
        assert!(sb.check_write(&f.ws.join("ws-protected/q")).is_err());
        // A sibling whose name merely starts like a protected one is fine.
        assert!(sb.check_write(&f.ws.join(".loomy")).is_ok());
        // A writable root is matched exactly, on every platform: only the rules that refuse ignore case.
        assert!(sb.check_write(Path::new("/usr/local/LOOMTEST/a")).is_err());
        // Relative paths and `..` that cannot be resolved.
        assert!(sb.check_write(Path::new("rel/x")).expect_err("relative").contains("absolute"));
        let e = sb.check_write(&f.ws.join("nothere/../x")).expect_err("dotdot");
        assert!(e.contains(".."), "{e}");
        // `..` through existing directories is resolved, and the resolved path is judged.
        std::fs::create_dir_all(f.ws.join("sub")).expect("mkdir");
        assert!(sb.check_write(&f.ws.join("sub/../ok")).is_ok());
        assert!(sb.check_write(&f.ws.join("sub/../.loom/x")).is_err());
        let up = f.ws.join("sub/../../../../../../../../usr/bin/x");
        assert!(sb.check_write(&up).is_err());
    }

    #[test]
    fn check_write_resolves_symlinks() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        symlink("/usr/bin", f.ws.join("esc")).expect("symlink");
        let e = sb.check_write(&f.ws.join("esc/newfile")).expect_err("escape");
        assert!(e.contains("/usr/bin/newfile") && e.contains("resolved from"), "{e}");
        // A link to the protected directory is the protected directory.
        symlink(f.ws.join(".loom"), f.ws.join("sneaky")).expect("symlink");
        assert!(sb.check_write(&f.ws.join("sneaky/x")).is_err());
        // A link that stays inside is fine.
        std::fs::create_dir_all(f.ws.join("sub")).expect("mkdir");
        symlink(f.ws.join("sub"), f.ws.join("inside")).expect("symlink");
        assert_eq!(sb.check_write(&f.ws.join("inside/x")), Ok(f.ws.join("sub/x")));
        // A dangling link cannot be judged and is refused with advice.
        symlink("/nonexistent-loom-target", f.ws.join("dangling")).expect("symlink");
        let e = sb.check_write(&f.ws.join("dangling")).expect_err("dangling");
        assert!(e.contains("points nowhere"), "{e}");
    }

    #[test]
    fn check_read_refuses_credentials_and_configured_paths() {
        let f = fx();
        let c = SandboxCfg { unreadable_paths: vec![format!("{}/hidden", s(&f.root)), "~/.loomtest-ssh".into()], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, None);
        assert!(sb.check_read(&f.home.join("token")).expect_err("token").contains("not readable"));
        assert!(sb.check_read(&f.home.join("keys/k")).is_err());
        let e = sb.check_read(&f.root.join("hidden/x")).expect_err("configured");
        assert!(e.contains("`sandbox.unreadable_paths`") && !e.contains("protect_credentials"), "{e}");
        assert!(sb.check_read(&f.home.join("other")).is_ok());
        assert!(sb.check_read(&f.ws.join("anything")).is_ok());
        assert!(sb.check_read(Path::new("/usr/bin/env")).is_ok());
        // A link cannot be used to read around the rule.
        symlink(f.home.join("token"), f.ws.join("tok")).expect("symlink");
        assert!(sb.check_read(&f.ws.join("tok")).is_err());
        if let Some(h) = &sb.home {
            assert!(sb.check_read(&h.join(".loomtest-ssh/id")).is_err());
        }
    }

    #[test]
    fn mode_none_has_no_profile_and_only_the_two_rules() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::None), None);
        assert_eq!(sb.mode(), SandboxMode::None);
        assert!(sb.profile().is_none());
        assert_eq!(sb.command("ls -l"), ("/bin/bash".to_string(), vec!["-c".to_string(), "ls -l".to_string()]));
        assert!(sb.check_write(Path::new("/usr/bin/x")).is_ok());
        assert!(sb.check_write(&f.ws.join(".loom/x")).is_err());
        assert!(sb.check_write(&f.home.join("x")).is_err());
        assert!(sb.check_read(&f.home.join("token")).is_err());
        assert!(sb.check_read(Path::new("/usr/bin/env")).is_ok());
        assert!(sb.describe().contains("not confined"));
    }

    #[test]
    fn preflight_checks_the_launcher_and_the_platform() {
        let f = fx();
        let missing = f.root.join("no-sandbox-exec");
        let e = preflight_at(SandboxMode::Seatbelt, &missing, true).expect_err("missing");
        assert!(e.contains("missing or not executable") && e.contains("macOS") && e.contains("mode = \"none\""), "{e}");
        let plain = f.root.join("plain-file");
        std::fs::write(&plain, "x").expect("write");
        assert!(preflight_at(SandboxMode::Seatbelt, &plain, true).is_err());
        let e = preflight_at(SandboxMode::Seatbelt, Path::new("/bin/sh"), false).expect_err("not macOS");
        assert!(e.contains("not macOS") && e.contains("mode = \"none\""), "{e}");
        assert!(preflight_at(SandboxMode::None, &missing, false).is_ok());
        assert!(preflight_at(SandboxMode::Seatbelt, Path::new("/bin/sh"), true).is_ok());
        if available() {
            assert!(preflight(&cfg(SandboxMode::Seatbelt)).is_ok());
        }
    }

    #[test]
    fn resolve_expands_home_and_joins_relative_paths() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::None), None);
        assert_eq!(sb.resolve("a/b.txt"), f.ws.join("a/b.txt"));
        assert_eq!(sb.resolve("/etc/hosts"), PathBuf::from("/etc/hosts"));
        assert_eq!(sb.resolve("../up"), f.ws.join("../up"));
        if let Some(h) = sb.home.clone() {
            assert_eq!(sb.resolve("~"), h);
            assert_eq!(sb.resolve("~/x/y"), h.join("x/y"));
        }
        assert_eq!(sb.resolve("~other/x"), f.ws.join("~other/x"));
    }

    #[test]
    fn env_scrubs_secrets_and_sets_fixed_variables() {
        let f = fx();
        let c = SandboxCfg { env_pass: vec!["MY_API_KEY".into()], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, None);
        let parent: BTreeMap<String, String> = [
            ("PATH", "/usr/bin"),
            ("HOME", "/h"),
            ("OPENAI_API_KEY", "x"),
            ("MY_API_KEY", "kept"),
            ("github_token", "x"),
            ("DB_PASSWORD", "x"),
            ("PASSWD_FILE", "x"),
            ("AWS_SECRET_ACCESS_KEY", "x"),
            ("SOME_CREDENTIALS", "x"),
            ("LOOM_HOME", "x"),
            ("loom_x", "x"),
            ("TERM", "xterm"),
            ("PAGER", "less"),
            ("GH_PAT", "x"),
            ("SENTRY_DSN", "x"),
            ("MYSQL_PWD", "x"),
            ("PWD", "/w"),
            ("OLDPWD", "/o"),
            ("DATABASE_URL", "x"),
            ("SSH_AUTH_SOCK", "x"),
            ("GITHUB_AUTH_TOKEN_X", "x"),
            ("SESSION_COOKIE_JAR", "x"),
            ("MY_SESSION_KEY_V", "x"),
            ("DATABASE_HOST", "kept-host"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let env = sb.env(&parent);
        let keys: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "DATABASE_HOST",
                "GIT_PAGER",
                "GIT_TERMINAL_PROMPT",
                "HOME",
                "MY_API_KEY",
                "NO_COLOR",
                "OLDPWD",
                "PAGER",
                "PATH",
                "PWD",
                "TERM",
                "TMPDIR"
            ]
        );
        assert_eq!(env["MY_API_KEY"], "kept");
        // `env_pass` overrides the new rules too.
        let c = SandboxCfg { env_pass: vec!["GH_PAT".into(), "SSH_AUTH_SOCK".into()], ..cfg(SandboxMode::Seatbelt) };
        let passed = build(&f, &c, None).env(&parent);
        assert_eq!((passed["GH_PAT"].as_str(), passed["SSH_AUTH_SOCK"].as_str()), ("x", "x"));
        assert_eq!(env["TERM"], "dumb");
        assert_eq!(env["PAGER"], "cat");
        assert_eq!(env["GIT_TERMINAL_PROMPT"], "0");
        assert_eq!(env["NO_COLOR"], "1");
        assert_eq!(env["TMPDIR"], s(&f.tmp));
    }

    #[test]
    fn describe_is_deterministic_and_states_the_policy() {
        let f = fx();
        let c = SandboxCfg { loopback_ports: vec![9000], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, Some(8080));
        let d = sb.describe();
        assert_eq!(d, sb.describe());
        assert!(d.contains(s(&f.ws)) && d.contains(".loom") && d.contains("token") && d.contains("8080, 9000"), "{d}");
        let all = SandboxCfg { loopback_all: true, ..cfg(SandboxMode::Seatbelt) };
        assert!(build(&f, &all, None).describe().contains("any loopback port"));
    }

    #[test]
    fn test_environment_builds() {
        let e = crate::testutil::env();
        assert_eq!(e.ctx.sandbox.mode(), SandboxMode::None);
    }

    // ---- tests that run commands under the generated profile ----

    fn available() -> bool {
        Path::new(SANDBOX_EXEC).exists()
    }

    /// (succeeded, stdout + stderr)
    fn run(sb: &Sandbox, cwd: &Path, script: &str) -> (bool, String) {
        let (prog, args) = sb.command(script);
        let out = Command::new(prog).args(args).current_dir(cwd).output().expect("run");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    /// A directory that is not under any writable root (the home directory of the user running the tests).
    fn outside() -> Option<tempfile::TempDir> {
        let home = std::env::var_os("HOME")?;
        tempfile::Builder::new().prefix("loom-sbx-").tempdir_in(home).ok()
    }

    #[test]
    fn commands_write_only_where_allowed() {
        if !available() {
            return;
        }
        let Some(out) = outside() else { return };
        let out_dir = out.path().canonicalize().expect("canonical");
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (ws, tmp, od) = (s(&f.ws), s(&f.tmp), s(&out_dir));

        assert!(run(&sb, &f.ws, &format!("echo x > {ws}/ok.txt")).0);
        assert_eq!(std::fs::read_to_string(f.ws.join("ok.txt")).expect("read"), "x\n");
        assert!(run(&sb, &f.ws, &format!("echo x > {tmp}/ok.txt")).0);
        assert!(run(&sb, &f.ws, "mktemp \"${TMPDIR:-/private/tmp}/loom.XXXXXX\" >/dev/null && echo x > rel.txt").0);

        // Outside every root.
        let (ok, text) = run(&sb, &f.ws, &format!("echo x > {od}/no.txt"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(!out_dir.join("no.txt").exists());

        // The protected directory: no writes, no rename.
        let (ok, text) = run(&sb, &f.ws, &format!("echo x > {ws}/.loom/events"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(!f.ws.join(".loom/events").exists());
        let (ok, text) = run(&sb, &f.ws, &format!("mv {ws}/.loom {ws}/moved"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(f.ws.join(".loom").is_dir() && !f.ws.join("moved").exists());
        assert!(!run(&sb, &f.ws, &format!("echo x > {}/h.txt", s(&f.home))).0);

        // Through a symlink that points outside.
        symlink(&out_dir, f.ws.join("esc")).expect("symlink");
        let (ok, text) = run(&sb, &f.ws, &format!("echo x > {ws}/esc/via.txt"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(!out_dir.join("via.txt").exists());
    }

    #[test]
    fn commands_write_to_a_temp_dir_inside_the_loom_home() {
        if !available() {
            return;
        }
        let f = fx_prod();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let env = sb.env(&BTreeMap::new());
        assert_eq!(env["TMPDIR"], s(&f.tmp));
        let (ok, text) = run(&sb, &f.ws, &format!("echo x > {}/t.txt && mktemp {}/m.XXXXXX", s(&f.tmp), s(&f.tmp)));
        assert!(ok, "{text}");
        assert!(f.tmp.join("t.txt").exists());
        // Nothing else in the loom home became writable.
        let log = f.home.join("sessions/s1/log.jsonl");
        let (ok, text) = run(&sb, &f.ws, &format!("echo x >> {}", s(&log)));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert_eq!(std::fs::read_to_string(&log).expect("read"), "{}");
        assert!(!run(&sb, &f.ws, &format!("echo x > {}/sessions/s1/new", s(&f.home))).0);
    }

    #[test]
    fn commands_cannot_replace_the_temp_dir_itself() {
        if !available() {
            return;
        }
        let f = fx_prod();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (tmp, ws) = (s(&f.tmp), s(&f.ws));
        // A link in its place would be followed when the session is next activated.
        let (ok, text) = run(&sb, &f.ws, &format!("rmdir {tmp}"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        let (ok, text) = run(&sb, &f.ws, &format!("mv {tmp} {ws}/moved"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        let (_, text) = run(&sb, &f.ws, &format!("rm -rf {tmp}; ln -s {ws} {tmp}"));
        assert!(text.contains("Operation not permitted"), "{text}");
        assert!(std::fs::symlink_metadata(&f.tmp).expect("temp dir").file_type().is_dir(), "the temp dir was replaced");
        assert!(!f.ws.join("moved").exists());
        // What is in it can still be created, renamed and removed.
        let inside = format!(
            "d=$(mktemp -d {tmp}/d.XXXXXX) && echo x > $d/f && mkdir -p {tmp}/a/b && mv $d {tmp}/a/b/d && rm -r {tmp}/a"
        );
        let (ok, text) = run(&sb, &f.ws, &inside);
        assert!(ok, "{text}");
    }

    #[test]
    fn commands_cannot_read_credentials_unless_protection_is_off() {
        if !available() {
            return;
        }
        let f = fx();
        let fake = f.root.join("fakehome4");
        std::fs::create_dir_all(fake.join(".ssh")).expect("mkdir");
        std::fs::write(fake.join(".ssh/id"), "private-key").expect("write");
        let sb = build_home(&f, &cfg(SandboxMode::Seatbelt), &fake);
        let id = format!("{}/.ssh/id", s(&fake));
        let (ok, text) = run(&sb, &f.ws, &format!("cat {id}"));
        assert!(!ok && text.contains("Operation not permitted") && !text.contains("private-key"), "{text}");
        assert!(!run(&sb, &f.ws, &format!("ls {}/.ssh", s(&fake))).0);
        let off = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        let (ok, text) = run(&build_home(&f, &off, &fake), &f.ws, &format!("cat {id}"));
        assert!(ok && text == "private-key", "{text}");
    }

    /// Says on the test run's own stderr, which is not captured, that a test could compare nothing on this host.
    fn skipped(test: &str, why: &str) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "sandbox test `{test}` skipped: {why}");
    }

    /// Whether this process is in a GUI login session. In any other (over ssh, say) LaunchServices opens
    /// nothing and launchd takes no jobs, sandbox or not, so a refusal there says nothing about the profile.
    fn gui_session() -> bool {
        let name = Command::new("/bin/launchctl").arg("managername").output();
        name.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "Aqua")
    }

    #[test]
    fn launch_services_open_is_refused_under_the_profile() {
        if !available() || !Path::new("/usr/bin/open").exists() {
            return;
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        // The profile compiles with the launch rules and bash runs under it.
        assert!(run(&sb, &f.ws, "true").0);
        if !gui_session() {
            let why = "not a GUI session, where `open` fails with or without the sandbox; \
                       the profile text is the evidence";
            return skipped("launch_services_open_is_refused_under_the_profile", why);
        }
        // Terminal runs an executable `.command` file that LaunchServices opens. There is no control run
        // outside the sandbox: it would really open Terminal.
        let script = f.ws.join("opened.command");
        std::fs::write(&script, format!("#!/bin/sh\ntouch {}/ran\n", s(&f.ws))).expect("write");
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).expect("chmod");
        let (ok, text) = run(&sb, &f.ws, &format!("/usr/bin/open -g {}", s(&script)));
        assert!(!ok, "{text}");
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(!f.ws.join("ran").exists(), "the script ran outside the sandbox");
    }

    #[test]
    fn launchd_jobs_are_refused_under_the_profile() {
        if !available() || !Path::new("/bin/launchctl").exists() {
            return;
        }
        if !gui_session() {
            let why = "not a GUI session, where launchd refuses a submitted job with or without the sandbox; \
                       the profile text is the evidence";
            return skipped("launchd_jobs_are_refused_under_the_profile", why);
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        // A job that launchd accepted would run outside the sandbox. There is no control run (it would
        // register a real job on this host), and the label is removed whatever happened.
        let label = format!("loom.sandbox-test.{}", std::process::id());
        let escaped = f.ws.join("escaped");
        let submit = format!("/bin/launchctl submit -l {label} -- /usr/bin/touch {}", s(&escaped));
        let (ok, text) = run(&sb, &f.ws, &submit);
        std::thread::sleep(std::time::Duration::from_millis(500));
        let ran = escaped.exists();
        let _ = Command::new("/bin/launchctl").args(["remove", &label]).output();
        assert!(!ok, "launchd accepted a job from inside the sandbox: {text}");
        assert!(!ran, "the job ran outside the sandbox");
    }

    #[test]
    fn commands_cannot_read_denied_paths() {
        if !available() {
            return;
        }
        let f = fx();
        let hidden = f.root.join("hidden");
        std::fs::create_dir_all(&hidden).expect("mkdir");
        std::fs::write(hidden.join("f"), "secret").expect("write");
        let c = SandboxCfg { unreadable_paths: vec![s(&hidden).to_string()], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, None);
        let h = s(&f.home);
        let (ok, text) = run(&sb, &f.ws, &format!("cat {h}/token"));
        assert!(!ok && text.contains("Operation not permitted") && !text.contains("t0ken"), "{text}");
        assert!(!run(&sb, &f.ws, &format!("ls {h}/keys")).0);
        assert!(!run(&sb, &f.ws, &format!("cat {}/f", s(&hidden))).0);
        assert!(!run(&sb, &f.ws, &format!("ls {}", s(&hidden))).0);
        let (ok, text) = run(&sb, &f.ws, &format!("cat {h}/other"));
        assert!(ok && text == "visible", "{text}");
    }

    #[test]
    fn devices_and_pipes_work() {
        if !available() {
            return;
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (ok, text) = run(&sb, &f.ws, "echo hidden > /dev/null; echo abc | tr a-c A-C | cat; ls /nonexistent-dir 2>/dev/null; true");
        assert!(ok && text == "ABC\n", "{text}");
    }

    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    }

    fn connects(sb: &Sandbox, cwd: &Path, host: &str, port: u16) -> bool {
        run(sb, cwd, &format!("/usr/bin/nc -z -w 2 {host} {port}")).0
    }

    #[test]
    fn network_is_limited_to_the_listed_loopback_ports() {
        if !available() {
            return;
        }
        let f = fx();
        let allowed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let other = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let (pa, po) = (allowed.local_addr().expect("addr").port(), other.local_addr().expect("addr").port());
        let c = SandboxCfg { loopback_ports: vec![pa], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, None);
        assert!(connects(&sb, &f.ws, "127.0.0.1", pa));
        assert!(!connects(&sb, &f.ws, "127.0.0.1", po));
        // Outside the sandbox both are reachable, so the refusal above is the profile's doing.
        let none = build(&f, &cfg(SandboxMode::None), None);
        assert!(connects(&none, &f.ws, "127.0.0.1", po));
        // The proxy port counts as an allowed port, and loopback_all opens every loopback port.
        let via_proxy = build(&f, &cfg(SandboxMode::Seatbelt), Some(po));
        assert!(connects(&via_proxy, &f.ws, "127.0.0.1", po));
        assert!(!connects(&via_proxy, &f.ws, "127.0.0.1", pa));
        let all = build(&f, &SandboxCfg { loopback_all: true, ..cfg(SandboxMode::Seatbelt) }, None);
        assert!(connects(&all, &f.ws, "127.0.0.1", pa) && connects(&all, &f.ws, "127.0.0.1", po));
    }

    /// An address of this host that is not loopback, found without sending anything.
    fn host_address() -> Option<std::net::IpAddr> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect("192.0.2.1:9").ok()?;
        let ip = sock.local_addr().ok()?.ip();
        (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
    }

    #[test]
    fn non_loopback_addresses_are_refused_under_seatbelt() {
        if !available() {
            return;
        }
        let test = "non_loopback_addresses_are_refused_under_seatbelt";
        let Some(ip) = host_address() else { return skipped(test, "this host has no address besides loopback") };
        let Ok(listener) = std::net::TcpListener::bind((ip, 0)) else {
            return skipped(test, &format!("cannot listen on {ip}"));
        };
        let port = listener.local_addr().expect("addr").port();
        let f = fx();
        let host = ip.to_string();
        // Control: outside the sandbox the host's own address is reachable.
        let none = build(&f, &cfg(SandboxMode::None), None);
        if !connects(&none, &f.ws, &host, port) {
            return skipped(test, &format!("{host}:{port} cannot be reached even outside the sandbox"));
        }
        // (With `loopback_all` the host's own address counts as localhost to the profile; that is not tested.)
        assert!(!connects(&build(&f, &cfg(SandboxMode::Seatbelt), None), &f.ws, &host, port));
    }

    #[test]
    fn names_that_resolve_outside_the_sandbox_do_not_resolve_under_seatbelt() {
        if !available() {
            return;
        }
        let f = fx();
        let resolves = |mode: SandboxMode, name: &str| {
            let script = format!("/usr/bin/dscacheutil -q host -a name {name}");
            run(&build(&f, &cfg(mode), None), &f.ws, &script).1.contains("ip_address")
        };
        // A name in /etc/hosts is answered from that file by the process itself, sandbox or not, so it
        // proves nothing; the name has to be one that only the resolver daemon knows.
        let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default().to_lowercase();
        let in_hosts = |name: &str| {
            let (name, entries) = (name.to_lowercase(), hosts.lines().map(|l| l.split('#').next().unwrap_or_default()));
            entries.flat_map(|l| l.split_whitespace().skip(1)).any(|n| n == name)
        };
        // This host's own names: `hostname` in full and in short.
        let mut own = [&[][..], &["-s"][..]].into_iter().filter_map(|args: &[&str]| {
            let out = Command::new("/bin/hostname").args(args).output().ok()?;
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let plain = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
            plain.then_some(name)
        });
        let Some(name) = own.find(|n| !in_hosts(n) && resolves(SandboxMode::None, n)) else {
            return skipped(
                "names_that_resolve_outside_the_sandbox_do_not_resolve_under_seatbelt",
                "no name of this host resolves through the resolver daemon",
            );
        };
        assert!(!resolves(SandboxMode::Seatbelt, &name), "{name} resolved under seatbelt");
    }

    #[test]
    fn commands_may_listen_on_loopback_but_need_permission_to_connect_to_themselves() {
        if !available() {
            return;
        }
        let f = fx();
        let port = free_port();
        let listen = format!("(/usr/bin/nc -l 127.0.0.1 {port} </dev/null >/dev/null 2>&1 &); sleep 1; ");
        let connect = format!("/usr/bin/nc -z -w 2 127.0.0.1 {port}");
        let with = build(&f, &SandboxCfg { loopback_ports: vec![port], ..cfg(SandboxMode::Seatbelt) }, None);
        assert!(run(&with, &f.ws, &format!("{listen}{connect}")).0);
        let without = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (ok, _) = run(&without, &f.ws, &format!("{listen}{connect}"));
        assert!(!ok);
        // Clean up the listener the second run left behind.
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    }

    fn pid_alive(pid: i32) -> bool {
        // SAFETY: signal 0 only tests for existence.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[test]
    fn commands_may_signal_their_own_processes() {
        if !available() {
            return;
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let script = "sleep 300 & c=$!; kill -0 $c || exit 11; kill $c || exit 12; wait $c 2>/dev/null; \
                      if kill -0 $c 2>/dev/null; then exit 13; fi; echo killed";
        let (ok, text) = run(&sb, &f.ws, script);
        assert!(ok && text.trim() == "killed", "{text}");
    }

    #[test]
    fn commands_cannot_signal_processes_outside_the_sandbox() {
        if !available() {
            return;
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let mut outside = std::process::Command::new("/bin/sleep").arg("300").spawn().expect("spawn sleep");
        let pid = i32::try_from(outside.id()).expect("pid");
        let (ok, text) = run(&sb, &f.ws, &format!("kill -9 {pid}"));
        let still_alive = pid_alive(pid);
        let _ = outside.kill();
        let _ = outside.wait();
        assert!(!ok, "kill should have failed: {text}");
        assert!(text.contains("Operation not permitted"), "{text}");
        assert!(still_alive, "the process outside the sandbox was signalled");
        // The same signal from outside the sandbox works, so the refusal above is the profile's doing.
        let mut other = std::process::Command::new("/bin/sleep").arg("300").spawn().expect("spawn sleep");
        let pid = i32::try_from(other.id()).expect("pid");
        let (ok, text) = run(&build(&f, &cfg(SandboxMode::None), None), &f.ws, &format!("kill -9 {pid}"));
        assert!(ok, "{text}");
        let _ = other.wait();
    }
}
