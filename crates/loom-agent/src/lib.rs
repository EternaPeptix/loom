//! loom-agent: the runtime that turns a model and a set of tools into an agent that can be left
//! alone. See `docs/DESIGN.md` §8 and §9.
//!
//! - [`census`] the process and listener census of the sessions, found by sandbox identity
//! - [`floor`] the proxy's veto, canary users and hosts, and lab-listener identity check
//! - [`pack`]  roles: prompt, tool list, how a role ends
//! - [`frontier`] the honest progress picture read from the ledger
//! - [`prior`] recall of the earlier missions the operator chose for a new one, from their sealed ledgers
//! - [`hud`]   the per-step state block appended to every request (never stored in the prefix)
//! - [`gate`]  what happens when the model stops calling tools, and what `finish` must satisfy
//! - [`rtools`] the tools the runtime owns: ledger, agents, and the tools that end a turn
//! - [`texts`] everything the step loop itself says to the model
//! - [`session`] one session: its log, its step loop, and its reactions to what happens to it
//! - [`runtime`] every session of a loom home: starting, restoring, parents and children, the operator's actions
//! - [`monitor`] the adversarial monitor: tripwires, reviewer, gate, durable pause, keep going (specified in
//!   `docs/MONITOR.md`; phase M2 watches every record in shadow and changes nothing an agent can see)
//! - [`evalkit`] scripted models played against the runtime, and the scorecard of each run

pub mod census;
pub mod completeness;
pub mod continuation;
pub mod egress;
pub mod evalkit;
pub mod floor;
pub mod frontier;
pub mod gate;
pub mod hud;
pub mod infra;
pub mod mcp;
pub mod monitor;
pub mod pack;
pub mod prior;
pub mod rtools;
pub mod runtime;
pub mod session;
pub mod texts;
pub mod traffic;
