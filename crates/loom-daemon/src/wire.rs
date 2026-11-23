//! JSON bodies of the API that are not runtime types. Field names are the wire format.
//!
//! Everything else on the wire is the serde form of a type from `loom_agent::runtime`
//! (`SessionInfo`, `NewSession`, `InboxEntry`, `WindowView`, `LedgerView`, `MissionInfo`, `NetEntry`,
//! `ModelHealth`, `RuleReceipt`, `ScopeReceipt`, `BusEvent`) or `loom_core` (`Record`, `BlobRef`).

use loom_agent::runtime::{ModelHealth, SessionInfo};
use loom_core::event::{Record, Seq};
use loom_core::log::record_from_value;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

/// `GET /api/status`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatusView {
    pub version: String,
    pub pid: u32,
    pub started_ms: u64,
    /// Address the API listens on, `127.0.0.1:7878`.
    pub bind: String,
    pub proxy_port: u16,
    /// The loom home directory.
    pub home: String,
    /// The command sandbox mode: `seatbelt`, `bubblewrap` or `none` (unconfined).
    #[serde(default)]
    pub sandbox: String,
    /// The egress network mode for tools: `deny_all`, `allowlist` or `open`.
    #[serde(default)]
    pub network: String,
    /// Space on the volume that holds the loom home; `null` when it cannot be read.
    #[serde(default)]
    pub disk: Option<DiskSpace>,
    pub models: Vec<ModelHealth>,
    pub sessions_total: usize,
    /// Sessions a task is driving.
    pub sessions_active: usize,
    /// Sessions in the middle of a turn.
    pub sessions_running: usize,
    pub inbox_open: usize,
}

/// Free space below which `loom status` warns that sessions will soon fail to write: 5 GiB, or 5 percent of the
/// volume. The runtime raises its low-disk notification at the same point.
pub use loom_agent::runtime::{LOW_DISK_BYTES, LOW_DISK_PERCENT};

/// Space on a volume, in bytes: what the daemon's user can still write (`free_bytes`), and the volume's size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskSpace {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

impl DiskSpace {
    /// Less than `LOW_DISK_BYTES`, or less than `LOW_DISK_PERCENT` of the volume, is free (the runtime's rule).
    pub fn is_low(&self) -> bool {
        loom_agent::runtime::disk_is_low(self.free_bytes, self.total_bytes)
    }
}

/// `POST /api/sessions` answers `201` with this: the session, as `GET /api/sessions` lists it, and whether the
/// request made the workspace folder (`create_workspace`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreatedSession {
    #[serde(flatten)]
    pub info: SessionInfo,
    #[serde(default)]
    pub created: bool,
}

/// `GET /api/fs/dirs`: the folders inside one folder of the daemon's machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirsView {
    /// The folder, absolute, symlinks resolved.
    pub path: String,
    /// Its parent; `null` for `/`.
    pub parent: Option<String>,
    /// The daemon user's home directory; `null` when it is not known.
    pub home: Option<String>,
    /// Folders only, sorted case-insensitively, at most [`FS_MAX_ENTRIES`].
    pub entries: Vec<DirEntryView>,
    /// Folders that were left out because of the cap.
    #[serde(default)]
    pub more: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntryView {
    pub name: String,
    /// Absolute; for a symlink to a folder, the folder it resolves to.
    pub path: String,
    /// The name starts with a dot.
    pub hidden: bool,
    /// A symlink to a folder.
    #[serde(default)]
    pub link: bool,
}

/// Entries one listing returns at most (`GET /api/fs/dirs`, `GET /api/sessions/{id}/files`).
pub const FS_MAX_ENTRIES: usize = 2_000;

/// `GET /api/sessions/{id}/files`: one folder of the session's workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesView {
    /// The canonical workspace.
    pub root: String,
    /// The folder, relative to the root, `/`-separated; empty for the root.
    pub path: String,
    /// Folders first, then the rest; each group sorted case-insensitively; at most [`FS_MAX_ENTRIES`].
    pub entries: Vec<FileEntryView>,
    /// Entries that were left out because of the cap.
    #[serde(default)]
    pub more: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntryView {
    pub name: String,
    /// `dir`, `file`, `link` (a symlink, never followed by the listing) or `other` (socket, FIFO, device).
    pub kind: String,
    /// Bytes (of the link itself for a `link`); 0 when it could not be read.
    pub size: u64,
    /// Modification time, milliseconds since the epoch; 0 when it could not be read.
    pub mtime_ms: u64,
    /// The name starts with a dot.
    pub hidden: bool,
    /// Present when the entry is shown but cannot be opened (`.loom`: harness files are not shown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Present when the entry could not be examined: why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `GET /api/sessions/{id}/files/lines`: lines of one file of the session's workspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileLinesView {
    /// As asked, normalised: relative to the workspace, `/`-separated.
    pub path: String,
    /// As [`LinesView`]: the lines `first..=last` (1-based), each with its newline.
    pub text: String,
    pub first: u64,
    pub last: u64,
    /// Lines in the whole file; also sent as `total_lines`.
    pub total: u64,
    pub total_lines: u64,
    pub bytes: u64,
    pub mtime_ms: u64,
    /// The file holds a NUL byte in its first 8 KiB: no lines are sent.
    pub binary: bool,
}

/// `GET /api/sessions/{id}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionDetail {
    #[serde(flatten)]
    pub info: SessionInfo,
    /// The agents this session started, oldest first.
    pub children: Vec<SessionInfo>,
}

/// `GET /api/sessions/{id}/records`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecordsPage {
    /// A record served as stored because the daemon could not read it in full (written by a newer loom)
    /// is read as the log reader reads it: `Event::Unknown` when its header is sound.
    #[serde(deserialize_with = "records_as_stored")]
    pub records: Vec<Record>,
    /// Pass as `after` to get the next page; `null` when this page reached the end of the log.
    pub next_after: Option<Seq>,
    /// With `before`: pass it as `before` to get the page before this one; `null` at the start of the log.
    #[serde(default)]
    pub prev_before: Option<Seq>,
}

fn records_as_stored<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Record>, D::Error> {
    Vec::<serde_json::Value>::deserialize(deserializer)?
        .iter()
        .map(|value| record_from_value(value).ok_or_else(|| D::Error::custom("an entry of `records` is not a record")))
        .collect()
}

/// `GET /api/blobs/{id}/lines`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinesView {
    pub text: String,
    /// 1-based, inclusive.
    pub first: u64,
    pub last: u64,
    pub total: u64,
}

/// Body of `POST /api/sessions/{id}/messages`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageBody {
    /// May be empty when `attachments` is not.
    pub text: String,
    /// Uploads of the session's workspace (`POST /api/uploads`), absolute paths; `docs/UPLOADS.md`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<String>,
    /// `now` (the default): the lead takes it at its next step, or starts a turn when idle. `after_turn`:
    /// held until the lead's turn ends, then sent as the start of the next one (the same as `now` while the
    /// lead is idle). Any other value is a `400`.
    #[serde(default, skip_serializing_if = "MessageWhen::is_now")]
    pub when: MessageWhen,
}

/// When a message is sent (`MessageBody.when`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageWhen {
    #[default]
    Now,
    AfterTurn,
}

impl MessageWhen {
    fn is_now(&self) -> bool {
        *self == MessageWhen::Now
    }
}

/// Body of `PUT /api/sessions/{id}/queued/{qid}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedEditBody {
    pub text: String,
}

/// Answer of `POST /api/sessions/{id}/messages` (`202`) when the message was queued: `{"queued": {id, text,
/// attachments, created_ms}}`. A message sent at once is answered `{}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedReceipt {
    pub queued: loom_agent::session::QueuedMessage,
}

/// Answer of `POST /api/uploads` (`201`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadView {
    /// Absolute path of the stored file, `<workspace>/.loom/uploads/<name>`.
    pub path: String,
    /// The stored name (sanitised, and numbered when the name was taken).
    pub name: String,
    pub bytes: u64,
    pub mime: String,
}

/// Body of `POST /api/sessions/{id}/rules`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBody {
    pub text: String,
}

/// Body of `POST /api/sessions/{id}/approvals`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBody {
    pub text: String,
    /// What the approval covers. Left out or blank, a mission that keeps a ledger records a stock
    /// scope in its place (the answer's `stock`).
    #[serde(default)]
    pub scope: String,
}

/// Body of `POST /api/sessions/{id}/rules/{rule_id}/withdraw`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawBody {
    /// Why the rule is withdrawn. Left out or blank, the runtime records a stock reason in its place.
    #[serde(default)]
    pub reason: String,
}

/// Body of `POST /api/sessions/{id}/scope`: hosts the operator lets the mission's tools reach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeBody {
    /// One host per entry, as the egress rules write them (`api.example.com`, `*.example.com`).
    pub hosts: Vec<String>,
    /// Why, for the ledger. Left out, nothing is recorded with the grant.
    #[serde(default)]
    pub note: Option<String>,
}

/// The answer to `POST /api/sessions/{id}/scope`.
pub use loom_agent::runtime::ScopeReceipt;

/// Body of `POST /api/sessions/{id}/release`: the operator closes the mission without the goal established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBody {
    /// Why the result is accepted short of the goal. Required.
    pub reason: String,
}

/// Body of `POST /api/inbox/{item_id}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerBody {
    pub answer: String,
}

/// Body of `POST /api/sessions/{id}/archive`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveBody {
    pub archived: bool,
}

/// Body of `POST /api/sessions/{id}/rename`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameBody {
    pub title: String,
}

/// Body of `POST /api/sessions/{id}/model`: the model profile to switch the session to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelBody {
    pub profile: String,
}

/// Body of `POST /api/sessions/{id}/role-model`: choose (or clear, `profile` null) the model the
/// mission starts its agents of `role` on; `role` `*` covers every role the lead starts. `now` also moves
/// the mission's running agents of that role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleModelBody {
    pub role: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub now: bool,
}

/// Answer of `GET /api/models`: the live model profiles, as `loom models reload` last read them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModelsView {
    /// The profile a session uses when none is named (empty: none set).
    pub default_model: String,
    pub models: Vec<ModelHealth>,
}

/// Body of `POST /api/gc`. An empty object is a dry run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcBody {
    #[serde(default)]
    pub apply: bool,
}

/// Body of every response whose status is not 2xx.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// A sentence for the operator.
    pub error: String,
}

/// `daemon.json` in the loom home: which process is serving it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonFile {
    pub pid: u32,
    pub bind: String,
    pub started_ms: u64,
}
