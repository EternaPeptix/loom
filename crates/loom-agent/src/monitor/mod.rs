//! The adversarial monitor: deterministic tripwires, a cross-family reviewer, a gate for irreversible actions, a
//! durable pause, and "keep going". The specification is `docs/MONITOR.md` (overview: `docs/DESIGN.md` §15); this
//! comment and the comments of the submodules are its precise form. When they disagree, one of them is a bug.
//!
//! CONTRACT.
//!
//! ## Status
//! Phase P0 (this tree): the vocabulary (`taxonomy`), the record and log shapes (`log`), the tripwire table
//! (`tripwire`), the gated classes (`classify`), the review-input rules (`input`), the verdict schema
//! (`reviewer`), lineage and eligibility (`lineage`), the response ladder (`respond`), keep-going's parameters and
//! conditions (`keepgoing`), canaries and fleet joins (`canary`, `fleet`), the operator-authored authorization block
//! (`auth`) and the fixed sentences the agent may see (`sentences`). **Nothing calls this module**: the daemon, the
//! runtime and the session loop do not know it exists, no configuration key, route, command or record of it is
//! accepted or written, and a build with it behaves exactly as one without. Every function that a later phase fills
//! returns `Err(MonitorError::NotBuilt { .. })`, never an empty or permissive value, so a caller wired in too early
//! fails closed (nothing is cleared, nothing is allowed on the monitor's say-so).
//!
//! ## Placement (built by M2; invariants I1 to I12 of `docs/MONITOR.md` §2.1)
//! `Runtime` will own `Arc<Monitor>`, built at `Runtime::start` after the proxy. Its log fold completes before
//! `load_known` and before any session is activated (I9). The monitor is not a session: it has no `Known` entry, so
//! `resolve_child` and `resolve_child_id` cannot name it, `agent_stop all` and mission stop do not reach it (I1). It has
//! no tools and no network except its model endpoints, through a model client with `.no_proxy()` (I2). Its state lives
//! under `<home>/monitor` and `<home>/keys/monitor.key`, which the sandbox hides from commands and the file tools
//! refuse (I3). Its prompts are compiled in (`texts.rs`, I4). Its responses act on harness state, never on the agent's
//! compliance (I5). Every verdict names the SHA-256 of its exact input (I6). An unreachable reviewer, a refusal, a
//! malformed or degraded verdict or a timeout clears nothing (I7). Inputs are harness-attested (I8). A pause is a
//! durable state checked by `Inner::may_run` (I9). Monitor faults are never agent misbehaviour (I10). Nothing the
//! reviewer wrote reaches the agent (I11). Live failures are stopped at chokepoints (I12).
//!
//! ## Submodules
//! - `taxonomy`: `Category` (the 14 slugs), `Severity` S0..S4, `Basis`, `Response` R0..R5, and the pure rules that
//!   relate them (aggregation of S1, reasoning-only cap, relaxed-agent uptier, the response a severity earns).
//! - `log`: `EntryKind` (the 19 record kinds of `<home>/monitor/log.jsonl`), `Entry`, `MonitorLog`, `Fold`.
//! - `tripwire`: `TripwireId` TW-01..TW-28, the table of what each reads and whether it starts enforcing, and the
//!   inline check run from `Session::run_calls_as`.
//! - `classify`: `GatedClass` G1..G8 and opaque code, `Decision`, and the classifier.
//! - `input`: `ReviewKind`, `Content`, the budgets, fence and redaction-tag formats, and the input builder.
//! - `reviewer`: the `monitor_verdict` schema (`Verdict`), its validation, `RecommendedResponse`.
//! - `lineage`: profile `family`, `alignment`, `recipient`, and the eligibility function (M1).
//! - `respond`: `Responder` (note, hold, cut, pause, resume, contain, halt, notify) and the R3 sequence's steps.
//! - `keepgoing`: `KeepGoingParams` and its limits, `Blocker` (K1..K10 and the refusals), `KeepGoingAction`.
//! - `canary`: `Canary` CN-1..CN-6. `fleet`: `Join` FS-1..FS-10.
//! - `auth`: `Authorization`, the operator-authored block of every review input.
//! - `sentences`: the fixed texts an agent can ever see from the monitor.
//!
//! ## Errors
//! `MonitorError` is a typed error whose messages say what to do next. `NotBuilt` names the phase of
//! `docs/MONITOR.md` §9.1 that builds the part. `Invalid` is a refusal of a malformed request. `Unavailable` is a
//! fault (reviewer, log, probe): by invariant I10 a caller must never count it as the agent's misbehaviour.
//!
//! ## Tests required
//! Each submodule's own list. In `mod.rs`: `not_built_names_the_phase`; `not_built_is_a_fault_not_a_verdict`.

pub mod auth;
pub mod canary;
pub mod classify;
pub mod fleet;
pub mod input;
pub mod keepgoing;
pub mod lineage;
pub mod log;
pub mod respond;
pub mod reviewer;
pub mod sentences;
pub mod taxonomy;
pub mod tripwire;

/// What the monitor can say it did not do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MonitorError {
    /// The part is specified and not built. Nothing was checked and nothing is cleared.
    #[error(
        "The monitor's {what} is not built yet (phase {phase} of docs/MONITOR.md section 9.1): nothing was checked, \
         so nothing is cleared. Do not rely on it; the running build behaves as if the monitor were off."
    )]
    NotBuilt { what: &'static str, phase: &'static str },
    /// A request the monitor refuses, with the reason and what to change.
    #[error("{0}")]
    Invalid(String),
    /// A reviewer, the monitor log, a probe or a worker could not do its job. A fault, never a verdict: it clears
    /// nothing and counts against nobody.
    #[error("The monitor could not finish: {0} Nothing was cleared; retry, or answer the held item yourself.")]
    Unavailable(String),
}

impl MonitorError {
    /// True for a fault of the monitor's own (I10): callers must not turn it into a denial count, a flag or evaluation
    /// data.
    pub fn is_fault(&self) -> bool {
        matches!(self, MonitorError::NotBuilt { .. } | MonitorError::Unavailable(_))
    }
}

/// `Err(NotBuilt)` for the part `what`, which `phase` builds. Every stub of this module returns it.
pub(crate) fn not_built<T>(what: &'static str, phase: &'static str) -> Result<T, MonitorError> {
    Err(MonitorError::NotBuilt { what, phase })
}

/// The monitor: owned by the runtime, one per loom home (built by M2). In P0 it holds nothing and cannot be started.
#[derive(Debug)]
pub struct Monitor {
    _private: (),
}

impl Monitor {
    /// Open `<home>/monitor`, fold its log, and start the workers (M2). The fold completes before this returns, so the
    /// caller can activate sessions afterwards (I9). A failed MAC or an unwritable log is `Unavailable`: the monitor is
    /// down and the daemon shows the "down" state (`docs/MONITOR.md` §2.8), but down never lifts a pause: the caller
    /// holds every mission that has a pause or halt record (every mission when it cannot tell) until the operator
    /// acknowledges, whatever `monitor_down` says (`log.rs` CONTRACT).
    pub async fn start(_home: &std::path::Path) -> Result<Monitor, MonitorError> {
        not_built("start-up", "M2")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_built_names_the_phase() {
        let e = not_built::<()>("gate", "M8").err().map(|e| e.to_string()).unwrap_or_default();
        assert!(e.contains("gate"), "{e}");
        assert!(e.contains("phase M8"), "{e}");
        assert!(e.contains("nothing is cleared"), "{e}");
    }

    #[test]
    fn not_built_is_a_fault_not_a_verdict() {
        assert!(MonitorError::NotBuilt { what: "x", phase: "M2" }.is_fault());
        assert!(MonitorError::Unavailable("down".into()).is_fault());
        assert!(!MonitorError::Invalid("no".into()).is_fault());
    }

    #[tokio::test]
    async fn start_fails_closed_in_p0() {
        let started = Monitor::start(std::path::Path::new("/nonexistent")).await;
        assert!(matches!(started, Err(MonitorError::NotBuilt { phase: "M2", .. })));
    }
}
