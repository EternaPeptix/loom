//! loom-agent: the runtime that turns a model and a set of tools into an agent that can be left
//! alone. See `docs/DESIGN.md` §8 and §9.
//!
//! - [`pack`]  roles: prompt, tool list, how a role ends
//! - [`hud`]   the per-step state block appended to every request (never stored in the prefix)
//! - [`gate`]  what happens when the model stops calling tools, and what `finish` must satisfy
//! - [`rtools`] the tools the runtime owns: ledger, agents, and the tools that end a turn
//! - [`texts`] everything the step loop itself says to the model
//! - [`session`] one session: its log, its step loop, and its reactions to what happens to it

pub mod gate;
pub mod hud;
pub mod pack;
pub mod rtools;
pub mod session;
pub mod texts;
