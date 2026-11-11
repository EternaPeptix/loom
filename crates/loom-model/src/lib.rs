//! loom-model: talking to an OpenAI-compatible chat-completions server.
//!
//! - [`request`]  what a request is and how its body is built (deterministic bytes)
//! - [`assemble`] SSE framing and delta accumulation into a [`Completion`]
//! - [`client`]   [`ModelClient`]: one streamed completion with retry across server restarts
//! - [`limit`]    [`Limiter`]: bounded concurrency with priorities
//! - [`mock`]     a scripted server for tests and behavioural checks
//!
//! See `docs/DESIGN.md` §10.

pub mod assemble;
pub mod client;
pub mod limit;
pub mod mock;
pub mod request;

pub use assemble::{Completion, StreamEvent};
pub use client::{Discovered, ModelClient, ModelError, WindowSource};
pub use limit::{Limiter, Permit, Priority};
pub use request::{ChatRequest, ToolChoice};
