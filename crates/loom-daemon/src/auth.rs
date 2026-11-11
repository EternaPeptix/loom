//! The access token, and the checks every request passes before it reaches a handler.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures are fixed).
//!
//! The API listens on a loopback address, but a loopback port is reachable by every local process
//! and, through the operator's browser, by every web page. So:
//!
//! - **Token.** `load_or_create_token(path)`: the file's content trimmed, if it is 64 lowercase hex
//!   characters; if the file is missing, 32 random bytes as hex written to it (file mode 0600,
//!   created with that mode — not chmod-ed afterwards; parent directories created 0700). A file
//!   with any other content is an error (`InvalidData`) — never silently replaced.
//! - **`presented_token(authorization, cookie)`**: the token of `Authorization: Bearer <token>`
//!   (scheme case-insensitive, surrounding spaces ignored); else the value of the cookie named
//!   [`COOKIE`] in a `Cookie` header (`a=1; loom_token=…; b=2`); else `None`.
//! - **`token_matches(expected, presented)`**: equal, compared without an early exit (fold the XOR
//!   of the bytes; different lengths are unequal).
//! - **`host_allowed(host, port)`**: the `Host` header must be exactly `127.0.0.1:{port}`,
//!   `localhost:{port}` or `[::1]:{port}` (case-insensitive). Absent or anything else is refused.
//!   This is what stops a web page that points a name of its own at 127.0.0.1 from reading the API.
//! - **`origin_allowed(origin, port)`**: absent is allowed (not a browser). Present: must be
//!   `http://` followed by one of the three allowed hosts. `null` and everything else is refused.
//! - **`session_cookie(token)`**: `loom_token={token}; Path=/; HttpOnly; SameSite=Strict`.
//!
//! Tests required: token created once with mode 0600 and reused; bad content is an error; bearer
//! and cookie parsing (several cookies, odd spacing, wrong scheme); matching; every host and origin
//! case above, including a wrong port and a host with a suffix (`127.0.0.1:7878.evil.example`).

use std::path::Path;

/// Name of the cookie the web UI authenticates with.
pub const COOKIE: &str = "loom_token";

pub fn load_or_create_token(path: &Path) -> std::io::Result<String> {
    let _ = path;
    todo!("implement per module contract")
}

pub fn presented_token(authorization: Option<&str>, cookie: Option<&str>) -> Option<String> {
    let _ = (authorization, cookie);
    todo!("implement per module contract")
}

pub fn token_matches(expected: &str, presented: &str) -> bool {
    let _ = (expected, presented);
    todo!("implement per module contract")
}

pub fn host_allowed(host: Option<&str>, port: u16) -> bool {
    let _ = (host, port);
    todo!("implement per module contract")
}

pub fn origin_allowed(origin: Option<&str>, port: u16) -> bool {
    let _ = (origin, port);
    todo!("implement per module contract")
}

pub fn session_cookie(token: &str) -> String {
    let _ = token;
    todo!("implement per module contract")
}
