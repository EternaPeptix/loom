//! ferret-net: the only way out for a sandboxed command.
//!
//! A sandboxed process cannot open outbound connections except to this proxy on loopback. The proxy
//! knows which session each connection belongs to (per-session credentials), applies the network
//! policy, resolves names itself, and reports every decision so it lands in that session's log.
//! See `docs/DESIGN.md` §11.

pub mod capture;
pub mod inject;
pub mod netlog;
pub mod pace;
pub mod policy;
pub mod proxy;
pub mod rewrite;
pub mod tls;

pub use capture::{CaptureGrant, CaptureSink, Captured, Transport};
pub use inject::Inject;
pub use pace::{render_noise_profile_prompt, Governor, HostNoise, NoiseProfile};
pub use policy::{Policy, Verdict};
pub use proxy::{
    host_listed, AuditFn, Limits, Proxy, ProxyError, ReferenceGrant, SessionGrant, CHECK_METHOD, RULE_HEADER,
};
pub use rewrite::{
    AssessmentUa, HeaderMatch, RewriteAction, RewriteMatcher, RewritePhase, RewriteRule, RewriteSet, RewriteStore,
    RewrittenHead, RewrittenRawHead,
};
