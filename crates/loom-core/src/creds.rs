//! Credential profiles of a target and the session secret set. `docs/CONTRACTS-TRAFFIC-TARGETS.md` part S is
//! normative.
//!
//! CONTRACT
//!
//! - [`Item`], [`ItemKind`], [`Profile`], [`ProfileSummary`], [`ItemView`] and [`CredsKey`] are final types.
//!   `Item`'s and `CredsKey`'s `Debug` never print a value or key byte; [`ItemView`] and [`ProfileSummary`]
//!   carry no value, so anything serialized from them is safe to show.
//! - [`valid_profile_name`]: `[a-z0-9][a-z0-9_-]{0,63}` (S1).
//! - [`load_or_create_key`]: `~/.loom/keys/creds.key`, 32 random bytes stored raw, file `0600`, parent dir
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
use std::path::{Path, PathBuf};

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

/// An item without its value, for `loom creds show` and the API.
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
    let _ = name;
    todo!("S1")
}

/// Read the key at `path`, creating it (32 random bytes, 0600, parent 0700) when missing.
pub fn load_or_create_key(path: &Path) -> Result<CredsKey, String> {
    let _ = path;
    todo!("S4")
}

/// Encrypt `profile` for `target/name`.
pub fn seal(key: &CredsKey, target: &str, name: &str, profile: &Profile) -> Result<Vec<u8>, String> {
    let _ = (key, target, name, profile);
    todo!("S4")
}

/// Decrypt a profile file sealed for `target/name`.
pub fn open(key: &CredsKey, target: &str, name: &str, bytes: &[u8]) -> Result<Profile, String> {
    let _ = (key, target, name, bytes);
    todo!("S4")
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
        let _ = (&self.targets_root, &self.key_path, target, profile);
        todo!("S1")
    }

    /// Every profile of `target`, sorted by name.
    pub fn list(&self, target: &str) -> Result<Vec<ProfileSummary>, String> {
        let _ = target;
        todo!("S7")
    }

    /// One profile's summary and items without values.
    pub fn show(&self, target: &str, profile: &str) -> Result<(ProfileSummary, Vec<ItemView>), String> {
        let _ = (target, profile);
        todo!("S7")
    }

    /// The decrypted profile.
    pub fn get(&self, target: &str, profile: &str) -> Result<Profile, String> {
        let _ = (target, profile);
        todo!("S4")
    }

    /// Write (replace) a profile.
    pub fn put(&self, target: &str, profile: &str, p: &Profile) -> Result<(), String> {
        let _ = (target, profile, p);
        todo!("S4")
    }

    /// Merge items into a profile (the scripted `loom creds set`), refusing any host outside `scope`.
    pub fn set_items(
        &self,
        target: &str,
        profile: &str,
        items: Vec<Item>,
        scope: &Scope,
        now_ms: u64,
    ) -> Result<ProfileSummary, String> {
        let _ = (target, profile, items, scope, now_ms);
        todo!("S2")
    }

    /// Delete a profile. `Ok(false)` when there was none.
    pub fn remove(&self, target: &str, profile: &str) -> Result<bool, String> {
        let _ = (target, profile);
        todo!("S7")
    }
}

/// The items to attach under `scope` and the number dropped (S6).
pub fn effective(items: &[Item], scope: &Scope) -> (Vec<Item>, usize) {
    let _ = (items, scope);
    todo!("S6")
}

/// The redaction-safe one-line summary of S10. `dropped` is the count [`effective`] returned.
pub fn summary_line(profile: &str, items: &[Item], dropped: usize) -> String {
    let _ = (profile, items, dropped);
    todo!("S10")
}

/// Collects a profile from captured exchanges while the operator logs in (S2).
#[derive(Debug)]
pub struct Recorder {
    scope: Scope,
}

impl Recorder {
    pub fn new(scope: Scope) -> Recorder {
        Recorder { scope }
    }

    /// Read one exchange with `host`: the request head (and body, ignored) and the response head when there
    /// was one. Returns the name lines that are new.
    pub fn observe(&mut self, host: &str, request: &[u8], response: Option<&[u8]>) -> Vec<String> {
        let _ = (&self.scope, host, request, response);
        todo!("S2")
    }

    /// Whether nothing is collected (a recording that ends so writes nothing).
    pub fn is_empty(&self) -> bool {
        todo!("S2")
    }

    /// The collected profile.
    pub fn finish(self, now_ms: u64) -> Profile {
        let _ = now_ms;
        todo!("S2")
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
        let _ = values.into_iter();
        todo!("S5")
    }

    /// The set for injected items: each value, and the token of a `<scheme> <token>` header value.
    pub fn for_items(items: &[Item]) -> Secrets {
        let _ = items;
        todo!("S5")
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn redact<'a>(&self, text: &'a str) -> Cow<'a, str> {
        let _ = text;
        todo!("S5")
    }

    pub fn redact_bytes<'a>(&self, bytes: &'a [u8]) -> Cow<'a, [u8]> {
        let _ = bytes;
        todo!("S5")
    }
}
