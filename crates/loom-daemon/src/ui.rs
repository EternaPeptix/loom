//! The web UI's files, embedded in the binary. `docs/UI.md` is their contract.

pub const INDEX_HTML: &str = include_str!("../../../ui/index.html");
pub const APP_JS: &str = include_str!("../../../ui/app.js");
pub const CORE_JS: &str = include_str!("../../../ui/core.js");
pub const STYLE_CSS: &str = include_str!("../../../ui/style.css");

/// Sent with every UI file. Nothing is loaded from anywhere but the daemon itself, and nothing
/// inline runs: text written by a model or fetched from the network can never become script, and a
/// remote image is never requested.
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
