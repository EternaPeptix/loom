//! The sandbox: one policy, applied to commands by the OS and to in-process file access by us.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! ## Policy
//! - writable roots: the workspace, the session temp dir, `cfg.extra_writable`, and the system temp
//!   locations commands need (`/private/tmp`, `/private/var/folders`, `/dev`);
//! - never writable, even inside a writable root: `<workspace>/.loom`, the loom home directory, and
//!   `cfg.protected_paths` (relative entries are relative to the workspace);
//! - not readable: `<loom home>/token`, `<loom home>/keys`, and `cfg.unreadable_paths` (`~` expands
//!   to the home directory);
//! - network: denied, except loopback connections to the egress proxy port (when there is one), to
//!   `cfg.loopback_ports` — or to every loopback port when `cfg.loopback_all` — and to
//!   `cfg.unix_sockets`. Listening on loopback is allowed.
//! All paths are made canonical when the sandbox is built (macOS: `/tmp` is `/private/tmp`); a
//! configured path that does not exist is kept as written after resolving its deepest existing
//! ancestor.
//!
//! ## `profile()`
//! The seatbelt profile text, `None` in mode `none`. This form is verified on macOS 27 — keep its
//! structure (later rules win):
//!
//! ```text
//! (version 1)
//! (allow default)
//! (deny file-write*)
//! (allow file-write* (subpath "<writable root>") …)
//! (deny file-write* (subpath "<protected>") …)
//! (deny file-read* (subpath "<unreadable>") …)
//! (deny network*)
//! (allow network-outbound (remote ip "localhost:<port>")) …      ; or "localhost:*" for loopback_all
//! (allow network-outbound (remote unix-socket (path-literal "<socket>"))) …
//! (allow network-bind (local ip "localhost:*"))
//! (allow network-inbound (local ip "localhost:*"))
//! ```
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
//! In mode `none` only the never-writable and not-readable rules apply.
//!
//! ## `resolve(given)`
//! A path as the model wrote it → absolute: `~`/`~/x` expand to the home directory, a relative path
//! is joined to the workspace. No file-system access.
//!
//! ## `env(parent)`
//! The environment for commands: `parent` (the daemon's own variables) without any whose name
//! contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD` or `CREDENTIAL` (case-insensitive) or
//! starts with `LOOM_`, unless listed in `cfg.env_pass`; plus `TERM=dumb`, `NO_COLOR=1`, `PAGER=cat`,
//! `GIT_PAGER=cat`, `GIT_TERMINAL_PROMPT=0`, `TMPDIR=<session temp dir>`.
//!
//! ## `describe()`
//! Two or three plain sentences for the system prompt: where commands may write, what they may not
//! read, how network access works. Deterministic. In mode `none` it says commands are not confined.
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
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Sandbox {
    mode: SandboxMode,
    workspace: PathBuf,
    tmp_dir: PathBuf,
    home: Option<PathBuf>,
    writable: Vec<PathBuf>,
    protected: Vec<PathBuf>,
    unreadable: Vec<PathBuf>,
    loopback_ports: Vec<u16>,
    loopback_all: bool,
    unix_sockets: Vec<PathBuf>,
    env_pass: Vec<String>,
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
        let _ = (cfg, workspace, tmp_dir, loom_home, proxy_port);
        todo!("implement per module contract")
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
        todo!("implement per module contract")
    }

    pub fn command(&self, script: &str) -> (String, Vec<String>) {
        let _ = script;
        todo!("implement per module contract")
    }

    pub fn check_read(&self, path: &Path) -> Result<PathBuf, String> {
        let _ = path;
        todo!("implement per module contract")
    }

    pub fn check_write(&self, path: &Path) -> Result<PathBuf, String> {
        let _ = path;
        todo!("implement per module contract")
    }

    pub fn resolve(&self, given: &str) -> PathBuf {
        let _ = (given, &self.home);
        todo!("implement per module contract")
    }

    pub fn env(&self, parent: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let _ = (parent, &self.env_pass);
        todo!("implement per module contract")
    }

    pub fn describe(&self) -> String {
        let _ = (&self.writable, &self.protected, &self.unreadable, &self.loopback_ports, self.loopback_all, &self.unix_sockets);
        todo!("implement per module contract")
    }
}
