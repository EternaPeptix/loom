//! JSON bodies of the API that are not runtime types. Field names are the wire format.
//!
//! Everything else on the wire is the serde form of a type from `loom_agent::runtime`
//! (`SessionInfo`, `NewSession`, `InboxEntry`, `WindowView`, `LedgerView`, `MissionInfo`, `NetEntry`,
//! `ModelHealth`, `RuleReceipt`, `BusEvent`) or `loom_core` (`Record`, `BlobRef`).

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

/// Free space below which `loom status` warns that sessions will soon fail to write: 5 GiB …
pub const LOW_DISK_BYTES: u64 = 5 << 30;

/// … or 5 percent of the volume.
pub const LOW_DISK_PERCENT: u64 = 5;

/// Space on a volume, in bytes: what the daemon's user can still write (`free_bytes`), and the volume's size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskSpace {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

impl DiskSpace {
    /// Less than `LOW_DISK_BYTES`, or less than `LOW_DISK_PERCENT` of the volume, is free.
    pub fn is_low(&self) -> bool {
        self.free_bytes < LOW_DISK_BYTES
            || u128::from(self.free_bytes) * 100 < u128::from(self.total_bytes) * u128::from(LOW_DISK_PERCENT)
    }
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
    pub text: String,
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
