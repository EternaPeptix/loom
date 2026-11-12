//! JSON bodies of the API that are not runtime types. Field names are the wire format.
//!
//! Everything else on the wire is the serde form of a type from `loom_agent::runtime`
//! (`SessionInfo`, `NewSession`, `InboxEntry`, `WindowView`, `LedgerView`, `MissionInfo`, `NetEntry`,
//! `ModelHealth`, `BusEvent`) or `loom_core` (`Record`, `BlobRef`).

use loom_agent::runtime::{ModelHealth, SessionInfo};
use loom_core::event::{Record, Seq};
use serde::{Deserialize, Serialize};

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
    pub models: Vec<ModelHealth>,
    pub sessions_total: usize,
    /// Sessions a task is driving.
    pub sessions_active: usize,
    /// Sessions in the middle of a turn.
    pub sessions_running: usize,
    pub inbox_open: usize,
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
    pub records: Vec<Record>,
    /// Pass as `after` to get the next page; `null` when this page reached the end of the log.
    pub next_after: Option<Seq>,
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
    #[serde(default)]
    pub scope: String,
}

/// Body of `POST /api/sessions/{id}/rules/{rule_id}/withdraw`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawBody {
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
