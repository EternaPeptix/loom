//! ferret-core: the durable record and the pure functions over it.
//!
//! Nothing in this crate is async and nothing talks to a network. See `docs/DESIGN.md`.
//!
//! - [`event`]   the normative event schema (one [`event::Record`] per log line)
//! - [`log`]     append-only, hash-chained session log with damage salvage
//! - [`blob`]    content-addressed store for full tool output, with line paging and search
//! - [`image`]   images a record names: detection, sizes, the sentences about them
//! - [`message`] chat messages as sent to the model
//! - [`weave`]   log → request prefix (deterministic), eviction planning
//! - [`admit`]   what the model sees of a tool output, with explicit cuts
//! - [`estimate`] calibrated token estimation
//! - [`prefix`]  guard that the request prefix only ever grows within an epoch
//! - [`ledger`]  typed mission state (ops and folded state)
//! - [`journal`] sealed append-only journal that stores ledger ops
//! - [`observe`] what the model has been shown: coverage, repetition, staleness, quote checks
//! - [`sarif`]   SARIF 2.1.0 export for structured security findings and surface coverage
//! - [`scorecard`] what a session's work took: steps, malformed calls, refusals, verdicts
//! - [`config`]  configuration file and on-disk layout
//! - [`ingest`]  pure-Rust parsers for bounty scopes, OpenAPI/Swagger, GraphQL introspection, and JS sourcemaps

pub mod admit;
pub mod blob;
pub mod compaction;
pub mod config;
pub mod creds;
pub mod estimate;
pub mod event;
pub mod har;
pub mod ids;
pub mod image;
pub mod ingest;
pub mod journal;
pub mod ledger;
pub mod log;
pub mod message;
pub mod observe;
pub mod prefix;
pub mod sanitize;
pub mod sarif;
pub mod scorecard;
pub mod security_state;
pub mod tagsafe;
pub mod target;
pub mod weave;

pub use blob::{BlobRef, BlobStore};
pub use event::{Author, Event, Record, Seq};
pub use ids::{BlobId, CallId, MissionId, SessionId};
pub use image::ImageRef;
pub use message::{Message, Role};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}
