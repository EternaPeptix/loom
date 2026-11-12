//! loom-net: the only way out for a sandboxed command.
//!
//! A sandboxed process cannot open outbound connections except to this proxy on loopback. The proxy
//! knows which session each connection belongs to (per-session credentials), applies the network
//! policy, resolves names itself, and reports every decision so it lands in that session's log.
//! See `docs/DESIGN.md` §11.

pub mod netlog;
pub mod policy;
pub mod proxy;

pub use policy::{Policy, Verdict};
pub use proxy::{AuditFn, Limits, Proxy, ProxyError, SessionGrant};
