//! What the proxy captures and how it hands it over (CONTRACTS-TRAFFIC-TARGETS C3, I). The proxy keeps no
//! exchange itself: each one goes to the [`CaptureSink`] with the session it belongs to, and the runtime
//! stores the messages as blobs and records an `Event::Exchange` in that session's log.
//!
//! CONTRACT
//!
//! - A session is captured only when its grant says so ([`CaptureGrant`] given to
//!   [`crate::Proxy::grant_with_capture`]); without one the proxy behaves exactly as before.
//! - `Plain` HTTP requests the proxy forwards are captured whole (head and body) up to `max_bytes` per
//!   body, with the true sizes; `Intercepted` HTTPS likewise when the grant has `intercept`.
//! - Proxy credentials (`Proxy-Authorization` to this proxy) are never in a captured request.
//! - Capture never delays or changes the relayed bytes; a full sink drops the capture, not the traffic.

use loom_core::ids::SessionId;
use tokio::sync::mpsc::UnboundedSender;

/// How a captured exchange travelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// A forwarded `http://` request.
    Plain,
    /// HTTPS decrypted by the proxy (I4).
    Intercepted,
}

/// One request and its response as the proxy saw them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Captured {
    pub ts_ms: u64,
    pub transport: Transport,
    pub method: String,
    pub host: String,
    pub port: u16,
    /// Path and query as sent.
    pub target: String,
    pub status: Option<u16>,
    pub error: Option<String>,
    /// The request head and body as the destination received it, cut at `max_bytes` of body.
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub truncated: bool,
    pub upstream_unverified: bool,
    pub duration_ms: u64,
}

/// Where captures go: the session id and the exchange.
pub type CaptureSink = UnboundedSender<(SessionId, Captured)>;

/// A session's capture settings, given with its grant.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaptureGrant {
    /// Bytes of each body kept.
    pub max_bytes: u64,
    /// Decrypt and capture HTTPS (I4).
    pub intercept: bool,
    /// Host patterns tunneled untouched even when `intercept`.
    pub passthrough: Vec<String>,
    /// Hosts whose upstream certificate is not checked when intercepting.
    pub upstream_insecure: Vec<String>,
    /// When set, only a CONNECT whose host this scope contains (and does not exclude) is intercepted; every
    /// other one is an opaque tunnel and is not captured (the credential recording session, S2). `None` for
    /// a mission: `intercept` and `passthrough` alone decide.
    pub intercept_scope: Option<loom_core::target::Scope>,
}
