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
//!   - loads the CA (`ferret_net::tls::Ca::load_or_create(paths.ca_dir())`) and the target's scope;
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

use super::*;
use ferret_core::creds::{Item, ItemView, ProfileSummary, Secrets};
use ferret_core::event::{CredsRef, TargetRef};
use ferret_core::target::Scope;
use ferret_net::Inject;

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
    pub lines: Mutex<Vec<String>>,
    /// Taken when the recording is written.
    pub recorder: Mutex<Option<ferret_core::creds::Recorder>>,
    /// Asks the task to end the recording (a stop).
    pub cancel: CancellationToken,
    /// Set when it ended (stop, timeout or shutdown), with what was written: the summary, or the sentence.
    pub ended: Mutex<Option<(u64, Result<ProfileSummary, String>)>>,
    pub task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Mounted credential profiles for a mission: default profile name & injector, all named profile
/// injectors (`as_profile` / `http_authz_matrix`), and the union secret redaction set across all of them.
pub(super) struct MountedCreds {
    pub default_name: String,
    pub default_inject: Arc<Inject>,
    pub profiles: BTreeMap<String, Arc<Inject>>,
    pub secrets: Arc<Secrets>,
}

/// The items of a mission while one of its sessions holds them (S11).
pub(super) struct MissionCreds {
    pub default_name: String,
    pub default_inject: Weak<Inject>,
    pub profiles: BTreeMap<String, Weak<Inject>>,
    pub secrets: Weak<Secrets>,
}

const KEEP_ENDED_MS: u64 = 10 * 60 * 1000;
/// How long a stop waits for an exchange that was in flight when the grant was revoked.
const DRAIN_MS: u64 = 150;

fn profile_or_default(profile: &str) -> &str {
    if profile.trim().is_empty() {
        "default"
    } else {
        profile.trim()
    }
}

fn check_profile_name(profile: &str) -> Result<(), String> {
    if ferret_core::creds::valid_profile_name(profile) {
        Ok(())
    } else {
        Err(format!(
            "`{profile}` is not a profile name: use 1 to 64 characters from a-z, 0-9, `-` and `_`, starting with a letter or digit."
        ))
    }
}

fn nothing_sentence(target: &str) -> String {
    format!("The recording collected nothing in scope of target {target}; no profile was written.")
}

/// Feed one captured exchange to the recording and keep the name lines it gives.
fn observe(rec: &Recording, c: &ferret_net::Captured) {
    let new = match lock(&rec.recorder).as_mut() {
        Some(r) => r.observe(&c.host, &c.request, c.response.as_deref()),
        None => return,
    };
    lock(&rec.lines).extend(new);
}

impl Inner {
    fn creds_store(&self) -> ferret_core::creds::CredsStore {
        ferret_core::creds::CredsStore::new(self.paths.targets_dir(), self.paths.creds_key())
    }

    /// The target's settings, or the 404 sentence.
    fn creds_target(&self, target: &str) -> Result<ferret_core::target::TargetCfg, String> {
        let store = self.target_store();
        if !store.exists(target) {
            return Err(format!("There is no target {target}."));
        }
        store.get(target)
    }

    fn recording(&self, target: &str, handle: &str) -> Result<Arc<Recording>, String> {
        let mut map = lock(&self.recordings);
        let now = now_ms();
        map.retain(|_, r| match &*lock(&r.ended) {
            Some((at, _)) => now.saturating_sub(*at) < KEEP_ENDED_MS,
            None => true,
        });
        match map.get(handle) {
            Some(r) if r.target == target => Ok(r.clone()),
            _ => Err(format!("No recording {handle} for target {target}.")),
        }
    }

    /// End `rec` once: revoke its grant, write what it collected and keep the outcome. Later calls change
    /// nothing.
    fn finish_recording(&self, rec: &Recording) {
        let mut ended = lock(&rec.ended);
        if ended.is_some() {
            return;
        }
        self.proxy.revoke(&rec.session);
        // The proxy's egress audit needs a directory for the pseudo-session; it holds nothing else.
        let _ = std::fs::remove_dir_all(self.paths.session_dir(&rec.session));
        let now = now_ms();
        let result = match lock(&rec.recorder).take() {
            Some(r) if !r.is_empty() => {
                let store = self.creds_store();
                store
                    .put(&rec.target, &rec.profile, &r.finish(now))
                    .and_then(|()| store.show(&rec.target, &rec.profile))
                    .map(|(summary, _)| summary)
            }
            _ => Err(nothing_sentence(&rec.target)),
        };
        *ended = Some((now, result));
    }

    /// End every live recording as a stop does (daemon shutdown).
    pub(super) fn stop_recordings(&self) {
        let live: Vec<Arc<Recording>> = lock(&self.recordings).values().cloned().collect();
        for rec in live {
            rec.cancel.cancel();
            if let Some(t) = lock(&rec.task).take() {
                t.abort();
            }
            self.finish_recording(&rec);
        }
    }

    /// What a lead's start records for `creds` and `creds_profiles` (S11 + Wave B multi-principal):
    /// refused without a target, for a name that is not valid, or for any profile that does not exist
    /// or does not open. Names are trimmed and deduplicated preserving order, with `default_name`
    /// first if set, else the first entry of `extra`.
    pub(super) fn start_creds_profiles(
        &self,
        target: Option<&TargetRef>,
        default_name: Option<&str>,
        extra: &[String],
    ) -> Result<(Option<CredsRef>, Vec<CredsRef>), String> {
        let mut names: Vec<String> = Vec::new();
        let mut push_unique = |raw: &str| {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && !names.iter().any(|existing| existing == trimmed) {
                names.push(trimmed.to_string());
            }
        };
        if let Some(d) = default_name {
            push_unique(d);
        }
        let had_extra = extra.iter().any(|s| !s.trim().is_empty());
        for p in extra {
            push_unique(p);
        }
        if names.is_empty() {
            return Ok((None, Vec::new()));
        }
        let Some(t) = target else {
            return Err(format!(
                "A credential profile belongs to a target: give the mission a target as well as the profile {}.",
                names[0]
            ));
        };
        let scope = Scope::parse(&t.scope, &t.exclude)?;
        let store = self.creds_store();
        let mut refs: Vec<CredsRef> = Vec::with_capacity(names.len());
        for name in &names {
            check_profile_name(name)?;
            let profile = store.get(&t.name, name).map_err(|e| {
                if e.starts_with("There is no credential profile") {
                    format!(
                        "There is no profile {name} for target {}; list them with `ferret creds list --target {}`.",
                        t.name, t.name
                    )
                } else {
                    e
                }
            })?;
            let (kept, dropped) = ferret_core::creds::effective(&profile.items, &scope);
            refs.push(CredsRef {
                profile: name.clone(),
                summary: ferret_core::creds::summary_line(name, &kept, dropped),
                dropped,
            });
        }
        let primary = refs.first().cloned();
        // Keep single-profile `new.creds` serialization 100% backward-compatible when `creds_profiles` was not supplied.
        let list = if had_extra || refs.len() > 1 { refs } else { Vec::new() };
        Ok((primary, list))
    }

    /// The items of the mission of `meta`, shared by its sessions (S11 + multi-principal). `None` when no
    /// profiles are configured or none can be read now.
    pub(super) fn mission_creds(&self, meta: &SessionMeta) -> Option<MountedCreds> {
        let mut names: Vec<String> = Vec::new();
        let mut push_unique = |name: &str| {
            let trimmed = name.trim();
            if !trimmed.is_empty() && !names.iter().any(|n| n == trimmed) {
                names.push(trimmed.to_string());
            }
        };
        if let Some(c) = meta.creds.as_ref() {
            push_unique(&c.profile);
        }
        for c in &meta.creds_profiles {
            push_unique(&c.profile);
        }
        if names.is_empty() {
            return None;
        }
        let mut map = lock(&self.mission_creds);
        map.retain(|_, c| c.default_inject.strong_count() > 0 && c.secrets.strong_count() > 0);
        if let Some(cached) = map.get(&meta.mission) {
            if let (Some(default_inject), Some(secrets)) = (cached.default_inject.upgrade(), cached.secrets.upgrade()) {
                let mut profiles = BTreeMap::new();
                let mut all_ok = !cached.profiles.is_empty();
                for (name, w) in &cached.profiles {
                    if let Some(inj) = w.upgrade() {
                        profiles.insert(name.clone(), inj);
                    } else {
                        all_ok = false;
                        break;
                    }
                }
                if all_ok {
                    return Some(MountedCreds {
                        default_name: cached.default_name.clone(),
                        default_inject,
                        profiles,
                        secrets,
                    });
                }
            }
        }
        let Some(t) = meta.target.as_ref() else {
            tracing::warn!(session = %meta.id, profile = %names[0], "a mission with credentials has no target; none attached");
            return None;
        };
        let scope = match Scope::parse(&t.scope, &t.exclude) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(target_name = %t.name, "credential profiles not attached because target scope failed to parse: {e}");
                return None;
            }
        };
        let store = self.creds_store();
        let mut profiles: BTreeMap<String, Arc<Inject>> = BTreeMap::new();
        let mut secret_sets: Vec<Secrets> = Vec::new();
        let mut default_name: Option<String> = None;
        for name in &names {
            match store.get(&t.name, name) {
                Ok(p) => {
                    let kept = ferret_core::creds::effective(&p.items, &scope).0;
                    secret_sets.push(Secrets::for_items(&kept));
                    profiles.insert(name.clone(), Arc::new(Inject::new(kept)));
                    if default_name.is_none() {
                        default_name = Some(name.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(target_name = %t.name, profile = %name, "credential profile not attached: {e}");
                }
            }
        }
        let default_name = default_name?;
        let default_inject = profiles.get(&default_name)?.clone();
        let secret_refs: Vec<&Secrets> = secret_sets.iter().collect();
        let secrets = Arc::new(Secrets::union(&secret_refs));
        let weak_profiles = profiles.iter().map(|(k, v)| (k.clone(), Arc::downgrade(v))).collect();
        map.insert(
            meta.mission.clone(),
            MissionCreds {
                default_name: default_name.clone(),
                default_inject: Arc::downgrade(&default_inject),
                profiles: weak_profiles,
                secrets: Arc::downgrade(&secrets),
            },
        );
        Some(MountedCreds { default_name, default_inject, profiles, secrets })
    }
}

impl Runtime {
    pub fn creds_list(&self, target: &str) -> Result<Vec<ProfileSummary>, String> {
        self.inner.creds_target(target)?;
        self.inner.creds_store().list(target)
    }

    pub fn creds_show(&self, target: &str, profile: &str) -> Result<ProfileShow, String> {
        self.inner.creds_target(target)?;
        check_profile_name(profile)?;
        let (summary, items) = self.inner.creds_store().show(target, profile)?;
        Ok(ProfileShow { summary, items })
    }

    pub fn creds_set(&self, target: &str, profile: &str, items: Vec<Item>) -> Result<ProfileSummary, String> {
        let cfg = self.inner.creds_target(target)?;
        let profile = profile_or_default(profile);
        check_profile_name(profile)?;
        if items.is_empty() {
            return Err("Give at least one item to store: a cookie or a header with its host.".to_string());
        }
        let scope = Scope::parse(&cfg.scope, &cfg.exclude)?;
        self.inner.creds_store().set_items(target, profile, items, &scope, now_ms())
    }

    pub fn creds_remove(&self, target: &str, profile: &str) -> Result<(), String> {
        self.inner.creds_target(target)?;
        check_profile_name(profile)?;
        if self.inner.creds_store().remove(target, profile)? {
            Ok(())
        } else {
            Err(format!("No profile {profile} for target {target}."))
        }
    }

    pub async fn creds_record_start(&self, target: &str, profile: &str) -> Result<RecordStarted, String> {
        let inner = &self.inner;
        inner.check_open()?;
        let cfg = inner.creds_target(target)?;
        let profile = profile_or_default(profile).to_string();
        check_profile_name(&profile)?;
        let scope = Scope::parse(&cfg.scope, &cfg.exclude)?;
        if scope.is_empty() {
            return Err(format!(
                "Target {target} has an empty scope, so nothing could be recorded for it; add a host with `ferret target scope`."
            ));
        }
        let running = lock(&inner.recordings)
            .iter()
            .find(|(_, r)| r.target == target && r.profile == profile && lock(&r.ended).is_none())
            .map(|(h, _)| h.clone());
        if let Some(h) = running {
            return Err(format!(
                "A recording of {target}/{profile} is already running (handle {h}); stop it with `ferret creds record --target {target} --stop {h}`."
            ));
        }
        let ca = ferret_net::tls::Ca::load_or_create(&inner.paths.ca_dir())
            .map_err(|e| format!("The interception CA cannot be loaded for the recording: {e}"))?;
        let mut net = inner.config.network.clone();
        net.mode = ferret_core::config::NetworkMode::Open;
        let policy = Policy::new(&net)?.with_target(&cfg.scope, &cfg.exclude)?;
        let handle = format!("{:016x}", rand::random::<u64>());
        let session = SessionId::from(format!("creds-rec-{handle}"));
        std::fs::create_dir_all(inner.paths.session_dir(&session))
            .map_err(|e| format!("The recording's audit folder cannot be created: {e}"))?;
        let (tx, mut rx) = unbounded_channel::<(SessionId, ferret_net::Captured)>();
        let capture = ferret_net::CaptureGrant {
            max_bytes: RECORD_MAX_BYTES,
            intercept: true,
            passthrough: inner
                .config
                .network
                .intercept_passthrough
                .iter()
                .chain(cfg.intercept_passthrough.iter())
                .cloned()
                .collect(),
            upstream_insecure: cfg.upstream_insecure.clone(),
            intercept_scope: Some(scope.clone()),
        };
        let grant = inner
            .proxy
            .grant_with_capture(&session, policy, capture, tx, Some(ca.clone()))
            .map_err(|e| format!("The egress proxy cannot open a port for the recording: {e}"))?;
        let started = now_ms();
        let rec = Arc::new(Recording {
            target: target.to_string(),
            profile: profile.clone(),
            session,
            lines: Mutex::new(Vec::new()),
            recorder: Mutex::new(Some(ferret_core::creds::Recorder::new(scope))),
            cancel: CancellationToken::new(),
            ended: Mutex::new(None),
            task: Mutex::new(None),
        });
        let weak = inner.me.clone();
        let task_rec = rec.clone();
        let task = tokio::spawn(async move {
            let deadline = tokio::time::sleep(Duration::from_millis(RECORD_MAX_MS));
            tokio::pin!(deadline);
            loop {
                tokio::select! {
                    _ = &mut deadline => break,
                    _ = task_rec.cancel.cancelled() => break,
                    got = rx.recv() => match got {
                        Some((_, c)) => observe(&task_rec, &c),
                        None => break,
                    }
                }
            }
            if let Some(inner) = weak.upgrade() {
                // The grant goes first; exchanges that were already on their way are still read.
                inner.proxy.revoke(&task_rec.session);
                while let Ok(Some((_, c))) = tokio::time::timeout(Duration::from_millis(DRAIN_MS), rx.recv()).await {
                    observe(&task_rec, &c);
                }
                inner.finish_recording(&task_rec);
            }
        });
        *lock(&rec.task) = Some(task);
        lock(&inner.recordings).insert(handle.clone(), rec);
        Ok(RecordStarted {
            handle,
            profile,
            proxy: format!("http://127.0.0.1:{}", grant.port),
            user: grant.user.clone(),
            password: grant.password.clone(),
            ca_path: inner.paths.ca_dir().join("ferret-ca.pem").display().to_string(),
            ca_sha256: ca.fingerprint_sha256.clone(),
            ends_ms: started.saturating_add(RECORD_MAX_MS),
        })
    }

    pub fn creds_record_lines(&self, target: &str, handle: &str, after: usize) -> Result<RecordLines, String> {
        let rec = self.inner.recording(target, handle)?;
        let lines = lock(&rec.lines);
        let next = lines.len();
        let done = lock(&rec.ended).is_some();
        Ok(RecordLines { lines: lines.iter().skip(after).cloned().collect(), next, done })
    }

    pub async fn creds_record_stop(&self, target: &str, handle: &str) -> Result<ProfileSummary, String> {
        let rec = self.inner.recording(target, handle)?;
        rec.cancel.cancel();
        let task = lock(&rec.task).take();
        if let Some(t) = task {
            let _ = t.await;
        }
        // A task that was aborted or never ran leaves the entry open; end it here.
        self.inner.finish_recording(&rec);
        lock(&self.inner.recordings).remove(handle);
        let ended = lock(&rec.ended).clone();
        match ended {
            Some((_, r)) => r,
            None => Err(nothing_sentence(target)),
        }
    }
}
