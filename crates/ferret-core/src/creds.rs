//! Credential profiles of a target and the session secret set. `docs/CONTRACTS-TRAFFIC-TARGETS.md` part S is
//! normative.
//!
//! CONTRACT
//!
//! - [`Item`], [`ItemKind`], [`Profile`], [`ProfileSummary`], [`ItemView`] and [`CredsKey`] are final types.
//!   `Item`'s and `CredsKey`'s `Debug` never print a value or key byte; [`ItemView`] and [`ProfileSummary`]
//!   carry no value, so anything serialized from them is safe to show.
//! - [`valid_profile_name`]: `[a-z0-9][a-z0-9_-]{0,63}` (S1).
//! - [`load_or_create_key`]: `~/.ferret/keys/creds.key`, 32 random bytes stored raw, file `0600`, parent dir
//!   `0700`, created on first need with `journal::publish_new_file` so two creators agree on one key (S4).
//!   An existing file that is not exactly 32 bytes is an error sentence naming the path, never replaced.
//! - [`seal`] / [`open`]: file bytes `b"v1" || nonce (12) || ciphertext || tag (16)` under `ring::aead`
//!   `CHACHA20_POLY1305`, random nonce per seal, AAD = `"{target}/{profile}"`; the plaintext is the
//!   profile as JSON. `open` of a file with another AAD, another key, a cut or changed byte, or another
//!   version prefix fails with one sentence that names `target/profile` and never says which of these it
//!   was (an AEAD failure is not more specific than that).
//! - [`CredsStore`]: files at `{targets_root}/{target}/creds/{profile}.enc`, the `creds` dir `0700`, each
//!   file written `0600` through a temporary file and a rename. Every method refuses an invalid target name
//!   (`target::valid_target_name`) or profile name with a sentence, and a target that does not exist
//!   (`{targets_root}/{target}/target.toml` missing). `list` decrypts each profile to count; a profile that
//!   fails to open is listed with `error` set instead of counts, never dropped silently. `set_items` merges
//!   into the profile (an item with the same kind, name — case-insensitive for headers — and host is
//!   replaced; a missing profile is created) and refuses an item whose host the given scope does not contain
//!   or excludes, naming the host and the scope. `remove` returns whether a file was removed.
//! - [`effective`] (S6): keeps an item only when the scope contains its host and does not exclude it; returns
//!   the kept items in their order and the number dropped.
//! - [`Recorder`] (S2): collects from captured exchanges per the collection rules of S2: only hosts the scope
//!   contains and does not exclude; per (host, kind, name) the latest value, request before response within
//!   one exchange; `Set-Cookie` with an empty value or `Max-Age` <= 0 removes. `observe` returns the name
//!   lines that are new since the last call (`{host} · cookie {name}` / `{host} · header {name}`), each line
//!   once for the recording's life even when its value changes; a removal emits nothing. `finish` gives the
//!   profile with items ordered by host, then kind (cookie first), then name.
//! - [`summary_line`]: S10, exactly.
//! - [`Secrets`] (S5): values shorter than [`Secrets::MIN_LEN`] bytes are not kept; duplicates are kept once;
//!   replacement is longest value first so a value that contains another is replaced whole. `redact` and
//!   `redact_bytes` return `Cow::Borrowed` when nothing matched. [`Secrets::for_items`] adds every item value
//!   and, for a `header` value `<scheme> <token>` (one space, token without spaces), the token too.
//!
//! Tests required: the S list in the contract for this module (round trip, wrong AAD swapped between
//! profiles and between targets, other key, cut file, bad version; key file mode and dir mode; list with a
//! damaged file; set_items merge and out-of-scope refusal; effective with exclude; recorder ordering,
//! Set-Cookie override, Max-Age=0 removal, out-of-scope dropped, lines emitted once; summary_line shapes
//! incl. 0 counts left out, `and k more`, dropped suffix; Secrets min length, longest-first, bytes path,
//! Borrowed when untouched; `format!("{:?}", item)` holds no value).

use crate::target::Scope;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

const VERSION: &[u8; 2] = b"v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// The text a secret value is replaced with.
pub const REDACTED: &str = "[redacted]";

/// What an item adds to a request (S1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    /// One `name=value` pair merged into the request's `Cookie` header.
    Cookie,
    /// A whole header (`name: value`), set when the request does not send it.
    Header,
}

/// One stored credential: a cookie pair or a header, for exactly one host (S1).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub kind: ItemKind,
    pub name: String,
    /// The secret. Never in `Debug`, a view, a record, a prompt or an API answer.
    pub value: String,
    /// One host name or IP, lower-case, no port, never a glob.
    pub host: String,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("value", &REDACTED)
            .field("host", &self.host)
            .finish()
    }
}

/// The decrypted content of a profile file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub items: Vec<Item>,
    /// When it was written (ms since the epoch).
    pub recorded_ms: u64,
}

/// An item without its value, for `ferret creds show` and the API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemView {
    pub kind: ItemKind,
    pub name: String,
    pub host: String,
}

impl From<&Item> for ItemView {
    fn from(i: &Item) -> ItemView {
        ItemView { kind: i.kind, name: i.name.clone(), host: i.host.clone() }
    }
}

/// One profile as listed: counts and hosts, no values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub profile: String,
    pub cookies: usize,
    pub headers: usize,
    /// Distinct hosts, sorted.
    pub hosts: Vec<String>,
    pub recorded_ms: u64,
    /// Set when the file could not be opened; the counts are then 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The daemon key profiles are sealed with (S4).
#[derive(Clone, PartialEq, Eq)]
pub struct CredsKey(pub [u8; 32]);

impl std::fmt::Debug for CredsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredsKey([redacted])")
    }
}

/// `[a-z0-9][a-z0-9_-]{0,63}`.
pub fn valid_profile_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

/// Read the key at `path`, creating it (32 random bytes, 0600, parent 0700) when missing.
pub fn load_or_create_key(path: &Path) -> Result<CredsKey, String> {
    let read = || -> Result<Option<CredsKey>, String> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    format!(
                        "The credentials key {} is not exactly 32 bytes, so it was left alone; \
                         restore it from a backup or move it away to start a new key (existing profiles will not open).",
                        path.display()
                    )
                })?;
                Ok(Some(CredsKey(arr)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Could not read the credentials key {}: {e}.", path.display())),
        }
    };
    if let Some(k) = read()? {
        return Ok(k);
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(parent)
            .map_err(|e| format!("Could not create the credentials key directory {}: {e}.", parent.display()))?;
    }
    let mut key = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key)
        .map_err(|_| "Could not get random bytes for the credentials key.".to_string())?;
    crate::journal::publish_new_file(path, &key)
        .map_err(|e| format!("Could not write the credentials key {}: {e}.", path.display()))?;
    read()?.ok_or_else(|| format!("The credentials key {} disappeared right after it was written.", path.display()))
}

fn aead_key(key: &CredsKey) -> Result<ring::aead::LessSafeKey, String> {
    let unbound = ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key.0)
        .map_err(|_| "The credentials key is unusable.".to_string())?;
    Ok(ring::aead::LessSafeKey::new(unbound))
}

fn aad(target: &str, name: &str) -> String {
    format!("{target}/{name}")
}

/// Encrypt `profile` for `target/name`.
pub fn seal(key: &CredsKey, target: &str, name: &str, profile: &Profile) -> Result<Vec<u8>, String> {
    let id = aad(target, name);
    let mut buf =
        serde_json::to_vec(profile).map_err(|_| format!("Could not encode credential profile {id} for storage."))?;
    let mut nonce = [0u8; NONCE_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
        .map_err(|_| format!("Could not get random bytes to seal credential profile {id}."))?;
    aead_key(key)?
        .seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(id.as_bytes()),
            &mut buf,
        )
        .map_err(|_| format!("Could not seal credential profile {id}."))?;
    let mut out = Vec::with_capacity(VERSION.len() + NONCE_LEN + buf.len());
    out.extend_from_slice(VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Decrypt a profile file sealed for `target/name`.
pub fn open(key: &CredsKey, target: &str, name: &str, bytes: &[u8]) -> Result<Profile, String> {
    let id = aad(target, name);
    let fail = || {
        format!(
            "Could not open credential profile {id}: the file is damaged, belongs to another profile or target, \
             or was sealed with another key."
        )
    };
    if bytes.len() < VERSION.len() + NONCE_LEN + TAG_LEN || bytes.get(..VERSION.len()) != Some(&VERSION[..]) {
        return Err(fail());
    }
    let rest = bytes.get(VERSION.len()..).ok_or_else(fail)?;
    let (nonce_bytes, ct) = rest.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| fail())?;
    let mut buf = ct.to_vec();
    let plain = aead_key(key)?
        .open_in_place(ring::aead::Nonce::assume_unique_for_key(nonce), ring::aead::Aad::from(id.as_bytes()), &mut buf)
        .map_err(|_| fail())?;
    serde_json::from_slice(plain).map_err(|_| fail())
}

/// The profiles of every target, on disk.
#[derive(Clone, Debug)]
pub struct CredsStore {
    targets_root: PathBuf,
    key_path: PathBuf,
}

impl CredsStore {
    /// `targets_root` = `Paths::targets_dir()`, `key_path` = `Paths::creds_key()`.
    pub fn new(targets_root: PathBuf, key_path: PathBuf) -> CredsStore {
        CredsStore { targets_root, key_path }
    }

    /// `{targets_root}/{target}/creds/{profile}.enc`, after checking both names.
    pub fn path(&self, target: &str, profile: &str) -> Result<PathBuf, String> {
        check_names(target, profile)?;
        Ok(self.dir(target).join(format!("{profile}.enc")))
    }

    fn dir(&self, target: &str) -> PathBuf {
        self.targets_root.join(target).join("creds")
    }

    fn check_target(&self, target: &str) -> Result<(), String> {
        if !crate::target::valid_target_name(target) {
            return Err(format!(
                "{target:?} is not a valid target name: use lower-case letters, digits, '-' and '_', at most 64."
            ));
        }
        if !self.targets_root.join(target).join("target.toml").is_file() {
            return Err(format!("There is no target named {target}; create it before storing credentials for it."));
        }
        Ok(())
    }

    /// Path after checking both names and that the target exists.
    fn checked_path(&self, target: &str, profile: &str) -> Result<PathBuf, String> {
        let p = self.path(target, profile)?;
        self.check_target(target)?;
        Ok(p)
    }

    fn read_profile(&self, key: &CredsKey, target: &str, profile: &str, path: &Path) -> Result<Profile, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("Could not read credential profile {target}/{profile} at {}: {e}.", path.display()))?;
        open(key, target, profile, &bytes)
    }

    /// Every profile of `target`, sorted by name.
    pub fn list(&self, target: &str) -> Result<Vec<ProfileSummary>, String> {
        check_names(target, "default")?;
        self.check_target(target)?;
        let dir = self.dir(target);
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(format!("Could not read the credentials of target {target} at {}: {e}.", dir.display()))
            }
        };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".enc")).map(str::to_string))
            .filter(|n| valid_profile_name(n))
            .collect();
        names.sort();
        let mut key: Option<CredsKey> = None;
        let mut out = Vec::new();
        for name in names {
            let path = dir.join(format!("{name}.enc"));
            if key.is_none() {
                key = Some(load_or_create_key(&self.key_path)?);
            }
            let Some(k) = key.as_ref() else { continue };
            out.push(match self.read_profile(k, target, &name, &path) {
                Ok(p) => summarize(&name, &p, None),
                Err(e) => summarize(&name, &Profile::default(), Some(e)),
            });
        }
        Ok(out)
    }

    /// One profile's summary and items without values.
    pub fn show(&self, target: &str, profile: &str) -> Result<(ProfileSummary, Vec<ItemView>), String> {
        let p = self.get(target, profile)?;
        Ok((summarize(profile, &p, None), p.items.iter().map(ItemView::from).collect()))
    }

    /// The decrypted profile.
    pub fn get(&self, target: &str, profile: &str) -> Result<Profile, String> {
        let path = self.checked_path(target, profile)?;
        if !path.is_file() {
            return Err(format!("There is no credential profile {target}/{profile}."));
        }
        let key = load_or_create_key(&self.key_path)?;
        self.read_profile(&key, target, profile, &path)
    }

    /// Write (replace) a profile.
    pub fn put(&self, target: &str, profile: &str, p: &Profile) -> Result<(), String> {
        let path = self.checked_path(target, profile)?;
        let key = load_or_create_key(&self.key_path)?;
        let sealed = seal(&key, target, profile, p)?;
        let dir = self.dir(target);
        let werr = |e: std::io::Error| {
            format!("Could not write credential profile {target}/{profile} at {}: {e}.", path.display())
        };
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
        b.create(&dir).map_err(werr)?;
        #[cfg(unix)]
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).map_err(werr)?;
        let mut attempt = 0u8;
        let (tmp, mut file) = loop {
            let tmp = dir.join(format!(".{profile}.{}.tmp", hex::encode(rand::random::<u64>().to_le_bytes())));
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
            match o.open(&tmp) {
                Ok(f) => break (tmp, f),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 8 => attempt += 1,
                Err(e) => return Err(werr(e)),
            }
        };
        let done = file.write_all(&sealed).and_then(|()| file.sync_all());
        drop(file);
        let done = done.and_then(|()| std::fs::rename(&tmp, &path));
        if let Err(e) = done {
            let _ = std::fs::remove_file(&tmp);
            return Err(werr(e));
        }
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Merge items into a profile (the scripted `ferret creds set`), refusing any host outside `scope`.
    pub fn set_items(
        &self,
        target: &str,
        profile: &str,
        items: Vec<Item>,
        scope: &Scope,
        now_ms: u64,
    ) -> Result<ProfileSummary, String> {
        self.checked_path(target, profile)?;
        let mut items = items;
        for it in &mut items {
            it.host = it.host.trim().to_ascii_lowercase();
            if it.name.trim().is_empty() {
                return Err(format!("A credential item for {target}/{profile} has an empty name."));
            }
            if !scope.contains(&it.host) {
                let why = if scope.excluded(&it.host) { "excludes it" } else { "does not include it" };
                return Err(format!(
                    "Host {} is outside the scope of target {target} (the scope {why}), so nothing was stored for {target}/{profile}.",
                    it.host
                ));
            }
        }
        let mut p = if self.path(target, profile)?.is_file() { self.get(target, profile)? } else { Profile::default() };
        for it in items {
            match p.items.iter_mut().find(|e| same_item(e, &it)) {
                Some(slot) => *slot = it,
                None => p.items.push(it),
            }
        }
        p.recorded_ms = now_ms;
        self.put(target, profile, &p)?;
        Ok(summarize(profile, &p, None))
    }

    /// Delete a profile. `Ok(false)` when there was none.
    pub fn remove(&self, target: &str, profile: &str) -> Result<bool, String> {
        let path = self.checked_path(target, profile)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => {
                Err(format!("Could not remove credential profile {target}/{profile} at {}: {e}.", path.display()))
            }
        }
    }
}

fn check_names(target: &str, profile: &str) -> Result<(), String> {
    if !crate::target::valid_target_name(target) {
        return Err(format!(
            "{target:?} is not a valid target name: use lower-case letters, digits, '-' and '_', at most 64."
        ));
    }
    if !valid_profile_name(profile) {
        return Err(format!(
            "{profile:?} is not a valid profile name: use lower-case letters, digits, '-' and '_', at most 64."
        ));
    }
    Ok(())
}

fn summarize(name: &str, p: &Profile, error: Option<String>) -> ProfileSummary {
    let mut hosts: Vec<String> = p.items.iter().map(|i| i.host.clone()).collect();
    hosts.sort();
    hosts.dedup();
    ProfileSummary {
        profile: name.to_string(),
        cookies: p.items.iter().filter(|i| i.kind == ItemKind::Cookie).count(),
        headers: p.items.iter().filter(|i| i.kind == ItemKind::Header).count(),
        hosts,
        recorded_ms: p.recorded_ms,
        error,
    }
}

fn same_item(a: &Item, b: &Item) -> bool {
    a.kind == b.kind
        && a.host == b.host
        && match a.kind {
            ItemKind::Cookie => a.name == b.name,
            ItemKind::Header => a.name.eq_ignore_ascii_case(&b.name),
        }
}

/// The items to attach under `scope` and the number dropped (S6).
pub fn effective(items: &[Item], scope: &Scope) -> (Vec<Item>, usize) {
    let kept: Vec<Item> = items.iter().filter(|i| scope.contains(&i.host)).cloned().collect();
    let dropped = items.len() - kept.len();
    (kept, dropped)
}

/// The redaction-safe one-line summary of S10. `dropped` is the count [`effective`] returned.
pub fn summary_line(profile: &str, items: &[Item], dropped: usize) -> String {
    let n = items.iter().filter(|i| i.kind == ItemKind::Cookie).count();
    let m = items.len() - n;
    let mut parts = Vec::new();
    if n > 0 {
        parts.push(format!("{n} cookie{}", if n == 1 { "" } else { "s" }));
    }
    if m > 0 {
        parts.push(format!("{m} header{}", if m == 1 { "" } else { "s" }));
    }
    if parts.is_empty() {
        parts.push("no items".to_string());
    }
    let mut hosts: Vec<&str> = items.iter().map(|i| i.host.as_str()).collect();
    hosts.sort();
    hosts.dedup();
    let mut line = format!("{profile} · {}", parts.join(", "));
    if !hosts.is_empty() {
        let shown = hosts.iter().take(3).copied().collect::<Vec<_>>().join(", ");
        line.push_str(" · ");
        line.push_str(&shown);
        if hosts.len() > 3 {
            line.push_str(&format!(" and {} more", hosts.len() - 3));
        }
    }
    if dropped > 0 {
        line.push_str(&format!(" · {dropped} out of scope, not attached"));
    }
    line
}

/// Collects a profile from captured exchanges while the operator logs in (S2).
#[derive(Debug)]
pub struct Recorder {
    scope: Scope,
    /// (host, kind, name — lower-cased for headers) to the item as first named and last valued.
    items: BTreeMap<(String, ItemKind, String), Item>,
    announced: HashSet<String>,
}

impl Recorder {
    pub fn new(scope: Scope) -> Recorder {
        Recorder { scope, items: BTreeMap::new(), announced: HashSet::new() }
    }

    /// Read one exchange with `host`: the request head (and body, ignored) and the response head when there
    /// was one. Returns the name lines that are new.
    pub fn observe(&mut self, host: &str, request: &[u8], response: Option<&[u8]>) -> Vec<String> {
        let host = host.trim().to_ascii_lowercase();
        let mut lines = Vec::new();
        if !self.scope.contains(&host) {
            return lines;
        }
        for (name, value) in head_fields(request) {
            if name.eq_ignore_ascii_case("cookie") {
                for pair in value.split(';') {
                    if let Some((n, v)) = pair.trim().split_once('=') {
                        if !n.trim().is_empty() && !v.trim().is_empty() {
                            self.set(&host, ItemKind::Cookie, n.trim(), v.trim(), &mut lines);
                        }
                    }
                }
            } else if (name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-api-key"))
                && !value.is_empty()
            {
                self.set(&host, ItemKind::Header, &name, &value, &mut lines);
            }
        }
        if let Some(resp) = response {
            for (name, value) in head_fields(resp) {
                if !name.eq_ignore_ascii_case("set-cookie") {
                    continue;
                }
                let mut parts = value.split(';');
                let Some((n, v)) = parts.next().and_then(|first| first.trim().split_once('=')) else { continue };
                let (n, v) = (n.trim(), v.trim());
                if n.is_empty() {
                    continue;
                }
                let expired = parts.any(|a| {
                    a.trim().split_once('=').is_some_and(|(k, val)| {
                        k.trim().eq_ignore_ascii_case("max-age") && val.trim().parse::<i64>().is_ok_and(|s| s <= 0)
                    })
                });
                if v.is_empty() || expired {
                    self.items.remove(&(host.clone(), ItemKind::Cookie, n.to_string()));
                } else {
                    self.set(&host, ItemKind::Cookie, n, v, &mut lines);
                }
            }
        }
        lines
    }

    fn set(&mut self, host: &str, kind: ItemKind, name: &str, value: &str, lines: &mut Vec<String>) {
        let key_name = if kind == ItemKind::Header { name.to_ascii_lowercase() } else { name.to_string() };
        let key = (host.to_string(), kind, key_name.clone());
        match self.items.get_mut(&key) {
            Some(existing) => existing.value = value.to_string(),
            None => {
                self.items.insert(
                    key,
                    Item { kind, name: name.to_string(), value: value.to_string(), host: host.to_string() },
                );
            }
        }
        let what = if kind == ItemKind::Cookie { "cookie" } else { "header" };
        if self.announced.insert(format!("{host} · {what} {key_name}")) {
            lines.push(format!("{host} · {what} {name}"));
        }
    }

    /// Whether nothing is collected (a recording that ends so writes nothing).
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The collected profile.
    pub fn finish(self, now_ms: u64) -> Profile {
        Profile { items: self.items.into_values().collect(), recorded_ms: now_ms }
    }
}

/// The session secret set (S5).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secrets {
    /// Longest first.
    values: Vec<String>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secrets({} values)", self.values.len())
    }
}

impl Secrets {
    /// Shorter values are not kept: replacing them everywhere would destroy ordinary text.
    pub const MIN_LEN: usize = 8;

    pub fn new<I: IntoIterator<Item = String>>(values: I) -> Secrets {
        let mut v: Vec<String> = values.into_iter().filter(|s| s.len() >= Self::MIN_LEN).collect();
        v.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        v.dedup();
        Secrets { values: v }
    }

    /// The set for injected items: each value, and the token of a `<scheme> <token>` header value.
    pub fn for_items(items: &[Item]) -> Secrets {
        Self::for_many_items(items)
    }

    /// The unified secret set across multiple credential profiles' items: each value and, for a
    /// `header` value `<scheme> <token>` (one space, token without spaces), the token too.
    pub fn for_many_items<'a>(items: impl IntoIterator<Item = &'a Item>) -> Secrets {
        let mut all = Vec::new();
        for i in items {
            all.push(i.value.clone());
            if i.kind == ItemKind::Header && i.value.matches(' ').count() == 1 {
                if let Some((_, token)) = i.value.split_once(' ') {
                    all.push(token.to_string());
                }
            }
        }
        Secrets::new(all)
    }

    /// Combine multiple [`Secrets`] sets into one unified longest-first, deduplicated redactor.
    pub fn union(sets: &[&Secrets]) -> Secrets {
        let mut all = Vec::new();
        for set in sets {
            all.extend(set.values.iter().cloned());
        }
        Secrets::new(all)
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        match self.replace(text.as_bytes()) {
            // Matches are whole values at their own character boundaries, so the result stays UTF-8.
            Some(out) => match String::from_utf8(out) {
                Ok(s) => Cow::Owned(s),
                Err(_) => Cow::Borrowed(text),
            },
            None => Cow::Borrowed(text),
        }
    }

    pub fn redact_bytes<'a>(&self, bytes: &'a [u8]) -> Cow<'a, [u8]> {
        match self.replace(bytes) {
            Some(out) => Cow::Owned(out),
            None => Cow::Borrowed(bytes),
        }
    }

    /// One left-to-right pass; at each position the longest value that starts there wins, and replaced text is
    /// never scanned again. `None` when nothing matched.
    fn replace(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if self.values.is_empty() {
            return None;
        }
        let mut out: Option<Vec<u8>> = None;
        let mut copied = 0;
        let mut i = 0;
        while i < bytes.len() {
            let rest = bytes.get(i..).unwrap_or(&[]);
            if let Some(v) = self.values.iter().find(|v| rest.starts_with(v.as_bytes())) {
                let o = out.get_or_insert_with(Vec::new);
                o.extend_from_slice(bytes.get(copied..i).unwrap_or(&[]));
                o.extend_from_slice(REDACTED.as_bytes());
                i += v.len();
                copied = i;
            } else {
                i += 1;
            }
        }
        out.map(|mut o| {
            o.extend_from_slice(bytes.get(copied..).unwrap_or(&[]));
            o
        })
    }
}

/// The `name: value` fields of an HTTP head (everything before the blank line; the first line is skipped).
fn head_fields(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for line in text.split('\n').skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((n, v)) = line.split_once(':') {
            let n = n.trim();
            if !n.is_empty() {
                out.push((n.to_string(), v.trim().to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: ItemKind, name: &str, value: &str, host: &str) -> Item {
        Item { kind, name: name.into(), value: value.into(), host: host.into() }
    }
    fn scope(inc: &[&str], exc: &[&str]) -> Scope {
        let f = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Scope::parse(&f(inc), &f(exc)).unwrap()
    }
    fn key(b: u8) -> CredsKey {
        CredsKey([b; 32])
    }
    fn prof() -> Profile {
        Profile { items: vec![item(ItemKind::Cookie, "sid", "abcdef123456", "acme.test")], recorded_ms: 7 }
    }
    fn store() -> (tempfile::TempDir, CredsStore) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("targets");
        for t in ["acme", "other"] {
            std::fs::create_dir_all(root.join(t)).unwrap();
            std::fs::write(root.join(t).join("target.toml"), "").unwrap();
        }
        let s = CredsStore::new(root, d.path().join("keys").join("creds.key"));
        (d, s)
    }

    #[test]
    fn profile_names() {
        assert!(valid_profile_name("default") && valid_profile_name("a_b-1"));
        assert!(!valid_profile_name("") && !valid_profile_name("-a") && !valid_profile_name("A"));
        assert!(!valid_profile_name("a/b") && !valid_profile_name(&"a".repeat(65)));
        assert!(valid_profile_name(&"a".repeat(64)));
    }

    #[test]
    fn seal_round_trip_and_rejections() {
        let sealed = seal(&key(1), "acme", "default", &prof()).unwrap();
        assert_eq!(&sealed[..2], b"v1");
        assert_eq!(open(&key(1), "acme", "default", &sealed).unwrap(), prof());
        assert_ne!(sealed, seal(&key(1), "acme", "default", &prof()).unwrap());
        for e in [
            open(&key(1), "acme", "other", &sealed).unwrap_err(),
            open(&key(1), "other", "default", &sealed).unwrap_err(),
            open(&key(2), "acme", "default", &sealed).unwrap_err(),
            open(&key(1), "acme", "default", &sealed[..sealed.len() - 1]).unwrap_err(),
            open(&key(1), "acme", "default", &sealed[..10]).unwrap_err(),
        ] {
            assert!((e.contains("acme/") || e.contains("other/")) && !e.contains("abcdef123456"), "{e}");
        }
        let mut bad = sealed.clone();
        bad[0] = b'x';
        assert!(open(&key(1), "acme", "default", &bad).is_err());
        let mut bad = sealed.clone();
        bad[20] ^= 1;
        assert!(open(&key(1), "acme", "default", &bad).is_err());
    }

    #[test]
    fn key_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("keys").join("creds.key");
        let k = load_or_create_key(&p).unwrap();
        assert_eq!(std::fs::read(&p).unwrap().len(), 32);
        assert_eq!(load_or_create_key(&p).unwrap(), k);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(p.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        std::fs::write(&p, b"short").unwrap();
        let e = load_or_create_key(&p).unwrap_err();
        assert!(e.contains("creds.key"));
        assert_eq!(std::fs::read(&p).unwrap(), b"short");
        assert_eq!(format!("{k:?}"), "CredsKey([redacted])");
    }

    #[test]
    fn store_put_get_list_remove_and_modes() {
        let (_d, s) = store();
        assert!(s.list("acme").unwrap().is_empty());
        s.put("acme", "b", &prof()).unwrap();
        s.put("acme", "a", &prof()).unwrap();
        assert_eq!(s.get("acme", "a").unwrap(), prof());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let p = s.path("acme", "a").unwrap();
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(std::fs::metadata(p.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let l = s.list("acme").unwrap();
        assert_eq!(l.iter().map(|x| x.profile.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!((l[0].cookies, l[0].headers, l[0].hosts.clone()), (1, 0, vec!["acme.test".to_string()]));
        let (sum, views) = s.show("acme", "a").unwrap();
        assert_eq!((sum.cookies, views.len()), (1, 1));
        assert!(s.remove("acme", "a").unwrap());
        assert!(!s.remove("acme", "a").unwrap());
        assert!(s.get("acme", "a").is_err());
    }

    #[test]
    fn store_refuses_bad_names_and_missing_target() {
        let (_d, s) = store();
        assert!(s.path("../x", "a").is_err() && s.path("acme", "A").is_err());
        assert!(s.get("nope", "a").unwrap_err().contains("nope"));
        assert!(s.put("nope", "a", &prof()).is_err());
        assert!(s.list("nope").is_err());
        assert!(s.remove("acme", "../x").is_err());
    }

    #[test]
    fn list_with_damaged_file_and_moved_file() {
        let (_d, s) = store();
        s.put("acme", "good", &prof()).unwrap();
        s.put("acme", "bad", &prof()).unwrap();
        let bad = s.path("acme", "bad").unwrap();
        let mut b = std::fs::read(&bad).unwrap();
        let n = b.len();
        b[n - 1] ^= 1;
        std::fs::write(&bad, b).unwrap();
        std::fs::copy(s.path("acme", "good").unwrap(), s.path("acme", "moved").unwrap()).unwrap();
        let l = s.list("acme").unwrap();
        assert_eq!(l.len(), 3);
        let by = |n: &str| l.iter().find(|x| x.profile == n).unwrap().clone();
        assert!(by("good").error.is_none() && by("good").cookies == 1);
        for n in ["bad", "moved"] {
            let x = by(n);
            assert!(x.error.as_deref().unwrap().contains(&format!("acme/{n}")));
            assert_eq!((x.cookies, x.headers), (0, 0));
        }
        assert!(s.show("acme", "bad").is_err());
    }

    #[test]
    fn set_items_merges_and_refuses_out_of_scope() {
        let (_d, s) = store();
        let sc = scope(&["acme.test", "*.acme.test"], &["admin.acme.test"]);
        let a = s
            .set_items(
                "acme",
                "default",
                vec![
                    item(ItemKind::Cookie, "sid", "one-one-one", "acme.test"),
                    item(ItemKind::Header, "Authorization", "Bearer aaaaaaaa", "api.acme.test"),
                ],
                &sc,
                5,
            )
            .unwrap();
        assert_eq!((a.cookies, a.headers, a.recorded_ms), (1, 1, 5));
        let b = s
            .set_items(
                "acme",
                "default",
                vec![
                    item(ItemKind::Header, "authorization", "Bearer bbbbbbbb", "api.acme.test"),
                    item(ItemKind::Cookie, "sid", "two-two-two", "acme.test"),
                    item(ItemKind::Cookie, "sid", "three-three", "www.acme.test"),
                ],
                &sc,
                9,
            )
            .unwrap();
        assert_eq!((b.cookies, b.headers, b.recorded_ms), (2, 1, 9));
        let p = s.get("acme", "default").unwrap();
        assert!(p.items.iter().any(|i| i.value == "two-two-two") && !p.items.iter().any(|i| i.value == "one-one-one"));
        assert!(p.items.iter().any(|i| i.value == "Bearer bbbbbbbb"));
        let e = s
            .set_items("acme", "default", vec![item(ItemKind::Cookie, "x", "yyyyyyyy", "evil.test")], &sc, 1)
            .unwrap_err();
        assert!(e.contains("evil.test") && e.contains("acme") && !e.contains("yyyyyyyy"), "{e}");
        let e = s
            .set_items("acme", "default", vec![item(ItemKind::Cookie, "x", "yyyyyyyy", "admin.acme.test")], &sc, 1)
            .unwrap_err();
        assert!(e.contains("admin.acme.test"));
        assert_eq!(s.get("acme", "default").unwrap(), p);
    }

    #[test]
    fn effective_with_exclude() {
        let sc = scope(&["*.acme.test", "acme.test"], &["admin.acme.test"]);
        let items = vec![
            item(ItemKind::Cookie, "a", "11111111", "acme.test"),
            item(ItemKind::Cookie, "b", "22222222", "admin.acme.test"),
            item(ItemKind::Header, "c", "33333333", "evil.test"),
            item(ItemKind::Header, "d", "44444444", "api.acme.test"),
        ];
        let (kept, dropped) = effective(&items, &sc);
        assert_eq!(dropped, 2);
        assert_eq!(kept.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["a", "d"]);
    }

    #[test]
    fn recorder_collects() {
        let mut r = Recorder::new(scope(&["acme.test", "*.acme.test"], &["admin.acme.test"]));
        assert!(r.is_empty());
        let req =
            b"GET / HTTP/1.1\r\nHost: acme.test\r\ncookie: b=2; a=1\r\nAuthorization: Bearer tok-tok-tok\r\n\r\nbody";
        let resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: a=9; Path=/; HttpOnly\r\nSet-Cookie: c=3\r\n\r\n";
        let lines = r.observe("acme.test", req, Some(resp));
        assert_eq!(
            lines,
            [
                "acme.test · cookie b",
                "acme.test · cookie a",
                "acme.test · header Authorization",
                "acme.test · cookie c"
            ]
        );
        assert!(r.observe("ACME.test", req, None).is_empty());
        assert!(r.observe("evil.test", req, Some(resp)).is_empty());
        assert!(r.observe("admin.acme.test", req, Some(resp)).is_empty());
        let l = r.observe("api.acme.test", b"GET / HTTP/1.1\r\nX-Api-Key: kkkkkkkk\r\n\r\n", None);
        assert_eq!(l, ["api.acme.test · header X-Api-Key"]);
        assert!(!r.is_empty());
        let p = r.finish(42);
        assert_eq!(p.recorded_ms, 42);
        let got: Vec<(&str, ItemKind, &str, &str)> =
            p.items.iter().map(|i| (i.host.as_str(), i.kind, i.name.as_str(), i.value.as_str())).collect();
        assert_eq!(
            got,
            [
                ("acme.test", ItemKind::Cookie, "a", "1"),
                ("acme.test", ItemKind::Cookie, "b", "2"),
                ("acme.test", ItemKind::Cookie, "c", "3"),
                ("acme.test", ItemKind::Header, "Authorization", "Bearer tok-tok-tok"),
                ("api.acme.test", ItemKind::Header, "X-Api-Key", "kkkkkkkk"),
            ]
        );
    }

    #[test]
    fn recorder_removal_and_lines_once() {
        let mut r = Recorder::new(scope(&["acme.test"], &[]));
        let req = |c: &str| format!("GET / HTTP/1.1\r\nCookie: {c}\r\n\r\n");
        assert_eq!(r.observe("acme.test", req("s=1").as_bytes(), None).len(), 1);
        assert!(r.observe("acme.test", req("s=2").as_bytes(), None).is_empty());
        let del = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=; Path=/\r\n\r\n";
        assert!(r.observe("acme.test", b"GET / HTTP/1.1\r\n\r\n", Some(del)).is_empty());
        assert!(r.is_empty());
        // Back again: the line was already shown.
        assert!(r.observe("acme.test", req("s=3").as_bytes(), None).is_empty());
        assert!(!r.is_empty());
        let age0 = b"HTTP/1.1 200 OK\r\nset-cookie: s=zzz; max-age=0\r\n\r\n";
        r.observe("acme.test", b"GET / HTTP/1.1\r\n\r\n", Some(age0));
        assert!(r.is_empty());
        let neg = b"HTTP/1.1 200 OK\r\nSet-Cookie: t=1; Max-Age=-5\r\n\r\n";
        r.observe("acme.test", b"GET / HTTP/1.1\r\n\r\n", Some(neg));
        assert!(r.is_empty());
        // Request first, response second: the response value wins.
        let resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: s=new\r\n\r\n";
        r.observe("acme.test", req("s=old").as_bytes(), Some(resp));
        assert_eq!(r.finish(1).items[0].value, "new");
    }

    #[test]
    fn summary_shapes() {
        let c = |n: &str, h: &str| item(ItemKind::Cookie, n, "vvvvvvvv", h);
        let hd = |n: &str, h: &str| item(ItemKind::Header, n, "vvvvvvvv", h);
        assert_eq!(
            summary_line("default", &[c("a", "acme.test"), c("b", "acme.test")], 0),
            "default · 2 cookies · acme.test"
        );
        assert_eq!(
            summary_line("p", &[c("a", "b.test"), hd("x", "a.test")], 0),
            "p · 1 cookie, 1 header · a.test, b.test"
        );
        let many = [c("a", "d.test"), c("a", "c.test"), c("a", "b.test"), c("a", "a.test"), c("a", "e.test")];
        assert_eq!(summary_line("p", &many, 0), "p · 5 cookies · a.test, b.test, c.test and 2 more");
        assert_eq!(summary_line("p", &[hd("x", "a.test")], 2), "p · 1 header · a.test · 2 out of scope, not attached");
        assert_eq!(summary_line("p", &[], 1), "p · no items · 1 out of scope, not attached");
    }

    #[test]
    fn secrets_behaviour() {
        let s = Secrets::new(["short".to_string(), "abcdefgh".into(), "abcdefgh".into(), "abcdefghij".into()]);
        assert_eq!(s.values.len(), 2);
        assert!(Secrets::new(["tiny".to_string()]).is_empty());
        assert_eq!(s.redact("x abcdefghij y abcdefgh z short"), "x [redacted] y [redacted] z short");
        assert!(matches!(s.redact("nothing here"), Cow::Borrowed(_)));
        assert_eq!(&*s.redact_bytes(b"\xff abcdefgh \x00"), b"\xff [redacted] \x00");
        assert!(matches!(s.redact_bytes(b"nothing"), Cow::Borrowed(_)));
        assert!(matches!(Secrets::default().redact("abcdefgh"), Cow::Borrowed(_)));
        assert_eq!(format!("{s:?}"), "Secrets(2 values)");
        let r = Secrets::new(["redacted".to_string()]);
        assert_eq!(r.redact("redacted"), "[redacted]");
    }

    #[test]
    fn secrets_for_items_and_debug() {
        let items = [
            item(ItemKind::Header, "Authorization", "Bearer tok-tok-tok", "a.test"),
            item(ItemKind::Header, "X", "two words here", "a.test"),
            item(ItemKind::Cookie, "sid", "cookie-value", "a.test"),
        ];
        let s = Secrets::for_items(&items);
        assert_eq!(s.redact("Bearer tok-tok-tok | tok-tok-tok | cookie-value"), "[redacted] | [redacted] | [redacted]");
        assert!(matches!(s.redact("two"), Cow::Borrowed(_)));
        let d = format!("{:?}", items[0]);
        assert!(!d.contains("tok-tok-tok") && d.contains("[redacted]"));
        assert!(!format!("{:?}", prof()).contains("abcdef123456"));
    }

    #[test]
    fn secrets_for_many_items_and_union_redact_longest_first_across_principals() {
        let user_a = [
            item(ItemKind::Cookie, "sid", "user-a-session", "a.test"),
            item(ItemKind::Header, "Authorization", "Bearer shared-token", "a.test"),
        ];
        let admin = [
            item(ItemKind::Cookie, "sid", "user-a-session-extended-admin", "a.test"),
            item(ItemKind::Header, "Authorization", "Bearer shared-token-admin-99", "a.test"),
            item(ItemKind::Cookie, "short", "tiny", "a.test"),
        ];

        let many = Secrets::for_many_items(user_a.iter().chain(admin.iter()));
        let text = "a=user-a-session b=user-a-session-extended-admin c=Bearer shared-token-admin-99 d=shared-token e=tiny";
        assert_eq!(many.redact(text), "a=[redacted] b=[redacted] c=[redacted] d=[redacted] e=tiny");

        let s_a = Secrets::for_items(&user_a);
        let s_admin = Secrets::for_items(&admin);
        let merged = Secrets::union(&[&s_a, &s_admin]);
        assert_eq!(merged, many);
        assert_eq!(merged.redact(text), "a=[redacted] b=[redacted] c=[redacted] d=[redacted] e=tiny");
        assert!(Secrets::union(&[]).is_empty());
        assert!(!format!("{merged:?}").contains("shared-token"));
    }
}
