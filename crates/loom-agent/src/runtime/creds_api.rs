//! Credential profiles in the runtime (CONTRACTS-TRAFFIC-TARGETS S2, S7, S11): the operator's routes over a
//! target's profiles, login recordings through the proxy, and the items a mission's sessions carry.
//!
//! CONTRACT
//!
//! - Operator routes (S7). `creds_list`, `creds_show`, `creds_set` and `creds_remove` act on
//!   `CredsStore::new(paths.targets_dir(), paths.creds_key())` for a target that exists (`There is no target
//!   {name}.` otherwise, a 404 by its first words) and a valid profile name (`valid_profile_name`; the
//!   sentence names the rule). `creds_set` checks every item's host against the target's current scope with
//!   `CredsStore::set_items` (a host outside it is refused, nothing written). `creds_remove` of a profile
//!   that does not exist is `No profile {profile} for target {name}.` (404). No answer of these carries a
//!   value: `ProfileSummary` and `ItemView` have none.
//! - Recording (S2). `creds_record_start(target, profile)`:
//!   - refuses while a recording of the same target and profile is live (one sentence naming its handle);
//!   - loads the CA (`loom_net::tls::Ca::load_or_create(paths.ca_dir())`) and the target's scope;
//!   - grants a pseudo-session `creds-rec-{16 hex}` with `Policy::new(&config.network)` in `open` mode
//!     joined with the target's scope and exclude (`Policy::with_target`), through
//!     `Proxy::grant_with_capture` with a `CaptureGrant { intercept: true, intercept_scope: Some(scope),
//!     passthrough: the daemon's and the target's lists, upstream_insecure: the target's, max_bytes:
//!     RECORD_MAX_BYTES }` and a sink of its own (never `capture_tx`: a recording is no session and writes
//!     no log);
//!   - spawns one task that reads that sink: for each `Captured`, `Recorder::observe(host, request,
//!     response)` and appends the returned lines to the recording's lines; it ends the recording itself
//!     after `RECORD_MAX_MS`, as a stop does;
//!   - returns `RecordStarted` with `proxy` = `http://127.0.0.1:{port}`, the grant's user and password,
//!     the CA file and its SHA-256 fingerprint (as `ca_show` gives them).
//! - `creds_record_lines(target, handle, after)` returns the lines from index `after` on, `next` = the
//!   number of lines so far, and `done` once the recording ended. An unknown handle (or one of another
//!   target) is `No recording {handle} for target {name}.`.
//! - `creds_record_stop(target, handle)` (and the timeout) revokes the grant, then: when the recorder
//!   collected nothing, `Err("The recording collected nothing in scope of target {name}; no profile was
//!   written.")`; else `Recorder::finish(now_ms())` is written with `CredsStore::put` and its summary
//!   returned. A recording that ended on its timeout keeps its result for a later stop: `stop` of a done
//!   recording returns what was written (or the same nothing sentence); the entry goes away on that stop
//!   or 10 minutes after it ended. A daemon shutdown ends every recording as a stop does.
//! - Missions (S11). `mission_creds(meta)`: `None` when `meta.creds` is `None`. Otherwise the mission's
//!   live `(Arc<Inject>, Arc<Secrets>)` from `Inner::mission_creds` when both are still held by a session;
//!   else read the profile through `CredsStore::get(target, profile)`, apply `effective` with the scope of
//!   `meta.target` (`Scope::parse(&t.scope, &t.exclude)`), build `Inject::new(items)` and
//!   `Secrets::for_items(&items)`, store `Weak`s of both and return them. A profile that is gone or does
//!   not open: `tracing::warn` naming target and profile (never a value), `None`, and the mission goes on
//!   without items. `start_creds(target_ref, name)` is what a lead's start runs: it refuses per S11 and
//!   returns the `CredsRef` (summary with `summary_line`, `dropped` = S6's count) to record.

// Scaffolding: the implementer of S2/S11 removes this once everything here is used.
#![allow(dead_code)]

use super::*;
use loom_core::creds::{Item, ItemView, ProfileSummary, Secrets};
use loom_core::event::{CredsRef, TargetRef};
use loom_net::Inject;

/// How many bytes of each exchange a recording keeps: its request and response heads are all it reads.
pub const RECORD_MAX_BYTES: u64 = 64 * 1024;
/// A recording ends by itself after this long (S2).
pub const RECORD_MAX_MS: u64 = 30 * 60 * 1000;

/// `POST /api/targets/{name}/creds`: exactly one of the three.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredsBody {
    pub record: Option<RecordBody>,
    /// A recording's handle to end.
    pub stop: Option<String>,
    pub set: Option<SetBody>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecordBody {
    /// `default` when left out.
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SetBody {
    /// `default` when left out.
    pub profile: Option<String>,
    pub items: Vec<Item>,
}

/// A recording that was opened: where the operator's browser goes and what it trusts.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordStarted {
    pub handle: String,
    pub profile: String,
    /// `http://127.0.0.1:{port}`
    pub proxy: String,
    pub user: String,
    pub password: String,
    pub ca_path: String,
    pub ca_sha256: String,
    /// When it ends by itself.
    pub ends_ms: u64,
}

impl std::fmt::Debug for RecordStarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordStarted").field("handle", &self.handle).field("proxy", &self.proxy).finish()
    }
}

/// `GET /api/targets/{name}/creds/record/{handle}?after={n}`: name lines only.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RecordLines {
    pub lines: Vec<String>,
    pub next: usize,
    pub done: bool,
}

/// `GET /api/targets/{name}/creds/{profile}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProfileShow {
    pub summary: ProfileSummary,
    pub items: Vec<ItemView>,
}

/// A login recording in progress or just ended (S2). Owned by `Inner::recordings`.
pub(super) struct Recording {
    pub target: String,
    pub profile: String,
    pub session: SessionId,
    pub started_ms: u64,
    pub lines: Mutex<Vec<String>>,
    pub recorder: Mutex<loom_core::creds::Recorder>,
    /// Set when it ended (stop, timeout or shutdown), with what was written: the summary, or the sentence.
    pub ended: Mutex<Option<(u64, Result<ProfileSummary, String>)>>,
    pub task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// The items of a mission while one of its sessions holds them (S11).
pub(super) type MissionCreds = (Weak<Inject>, Weak<Secrets>);

impl Runtime {
    pub fn creds_list(&self, target: &str) -> Result<Vec<ProfileSummary>, String> {
        let _ = target;
        todo!("S7")
    }

    pub fn creds_show(&self, target: &str, profile: &str) -> Result<ProfileShow, String> {
        let _ = (target, profile);
        todo!("S7")
    }

    pub fn creds_set(&self, target: &str, profile: &str, items: Vec<Item>) -> Result<ProfileSummary, String> {
        let _ = (target, profile, items);
        todo!("S2, S7")
    }

    pub fn creds_remove(&self, target: &str, profile: &str) -> Result<(), String> {
        let _ = (target, profile);
        todo!("S7")
    }

    pub async fn creds_record_start(&self, target: &str, profile: &str) -> Result<RecordStarted, String> {
        let _ = (target, profile);
        todo!("S2")
    }

    pub fn creds_record_lines(&self, target: &str, handle: &str, after: usize) -> Result<RecordLines, String> {
        let _ = (target, handle, after);
        todo!("S2")
    }

    pub async fn creds_record_stop(&self, target: &str, handle: &str) -> Result<ProfileSummary, String> {
        let _ = (target, handle);
        todo!("S2")
    }
}

impl Inner {
    /// What a lead's start records for `creds` (S11): refused without a target, for a name that is not
    /// valid, a profile that does not exist or does not open.
    pub(super) fn start_creds(
        &self,
        target: Option<&TargetRef>,
        name: Option<&str>,
    ) -> Result<Option<CredsRef>, String> {
        let _ = (target, name);
        todo!("S11")
    }

    /// The items of the mission of `meta`, shared by its sessions (S11). `None` without `creds` or when the
    /// profile cannot be read now.
    pub(super) fn mission_creds(&self, meta: &SessionMeta) -> Option<(Arc<Inject>, Arc<Secrets>)> {
        let _ = meta;
        todo!("S11")
    }

    /// End every live recording as a stop does (daemon shutdown).
    pub(super) fn stop_recordings(&self) {
        todo!("S2")
    }
}
