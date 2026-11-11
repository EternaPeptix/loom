//! loom-daemon: the process the operator runs, and the command they type.
//!
//! One binary, `loom`. `loom daemon` is the long-lived process: it owns the
//! [`Runtime`](loom_agent::runtime::Runtime), serves the HTTP API and the web UI on a loopback
//! address, and restores what was running when it starts. Every other `loom` command is a client of
//! that API. See `docs/DESIGN.md` §12.
//!
//! - [`wire`]   the JSON bodies of the API that are not runtime types
//! - [`auth`]   the access token, and the checks every request passes
//! - [`api`]    the HTTP API over a runtime
//! - [`ui`]     the web UI's files, embedded
//! - [`serve`]  running the daemon: start, serve, shut down; starting it in the background
//! - [`client`] the API as typed calls, for the command line
//! - [`render`] records and listings as terminal text
//! - [`cli`]    the `loom` command

pub mod api;
pub mod auth;
pub mod cli;
pub mod client;
pub mod render;
pub mod serve;
pub mod ui;
pub mod wire;
