//! loom-agent: the runtime that turns a model and a set of tools into an agent that can be left
//! alone. See `docs/DESIGN.md` §8 and §9.
//!
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
//!   `docs/MONITOR.md`; phase P0 has the contracts and vocabulary only, and nothing calls it)
//! - [`evalkit`] scripted models played against the runtime, and the scorecard of each run

pub mod continuation;
pub mod evalkit;
pub mod frontier;
pub mod gate;
pub mod hud;
pub mod infra;
pub mod monitor;
pub mod pack;
pub mod prior;
pub mod rtools;
pub mod runtime;
pub mod session;
pub mod texts;
