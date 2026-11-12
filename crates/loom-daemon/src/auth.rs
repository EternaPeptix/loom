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
//! - **`bearer_token(authorization)`**: the secret of `Authorization: Bearer <secret>` (scheme
//!   case-insensitive, surrounding spaces ignored), else `None`. There are no authentication
//!   cookies: a cookie is sent to every port on the host, including a dev server an agent started.
//! - **`names_legacy_cookie(cookie)`**: whether a `Cookie` header (`a=1; loom_token=…; b=2`) names
//!   [`LEGACY_COOKIE`], in which older daemons kept the API token. Its value is never read; the
//!   index page answers such a browser with [`FORGET_LEGACY_COOKIE`] so it stops sending the token.
//! - **`token_matches(expected, presented)`**: equal, compared without an early exit (fold the XOR
//!   of the bytes; different lengths are unequal).
//! - **`host_allowed(host, port)`**: the `Host` header must be exactly `127.0.0.1:{port}`,
//!   `localhost:{port}` or `[::1]:{port}` (case-insensitive). Absent or anything else is refused.
//!   This is what stops a web page that points a name of its own at 127.0.0.1 from reading the API.
//! - **`origin_allowed(origin, port)`**: absent is allowed (not a browser). Present: must be
//!   `http://` followed by one of the three allowed hosts. `null` and everything else is refused.
//! - **[`Logins`]**: the web UI's way in. `POST /api/login-codes` (API token) mints a single-use code
//!   valid for [`CODE_TTL`]; `POST /api/web-sessions` exchanges it for a web-session secret that the
//!   UI sends as a bearer. Both live in memory only and are bounded ([`MAX_CODES`], [`MAX_SESSIONS`]).
//!
//! Tests required: token created once with mode 0600 and reused; bad content is an error; bearer
//! parsing (odd spacing, wrong scheme); the legacy cookie by name (several cookies, odd spacing,
//! look-alike names); matching; login codes and web sessions; every host and origin case above,
//! including a wrong port and a host with a suffix (`127.0.0.1:7878.evil.example`).

use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt;
use std::collections::VecDeque;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long a login code can be exchanged.
pub const CODE_TTL: Duration = Duration::from_secs(60);
/// Login codes that may be outstanding at once; minting past it drops the oldest.
pub const MAX_CODES: usize = 16;
/// Web-session secrets kept at once; creating past it drops the oldest.
pub const MAX_SESSIONS: usize = 32;
/// The cookie older daemons kept the API token in. It is not a credential.
pub const LEGACY_COOKIE: &str = "loom_token";
/// The `Set-Cookie` value that removes [`LEGACY_COOKIE`] from a browser: the name and path it was
/// set with, no value, already expired.
pub const FORGET_LEGACY_COOKIE: &str = "loom_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict";

/// Length of a token in characters: 32 random bytes as lowercase hex.
const TOKEN_LEN: usize = 64;

fn is_token(text: &str) -> bool {
    text.len() == TOKEN_LEN && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn read_token(path: &Path, content: &str) -> std::io::Result<String> {
    let token = content.trim();
    if is_token(token) {
        Ok(token.to_string())
    } else {
        Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "the token file {} does not hold a 64-character lowercase hex token; if it is not needed, delete it and loom will create a new one",
                path.display()
            ),
        ))
    }
}

/// The access token stored at `path`, created (mode 0600) when the file does not exist.
pub fn load_or_create_token(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => return read_token(path, &content),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    }
    let bytes: [u8; 32] = rand::random();
    // Published atomically; when a concurrent creator got there first, its token is the one read back.
    loom_core::journal::publish_new_file(path, format!("{}\n", hex::encode(bytes)).as_bytes())?;
    read_token(path, &std::fs::read_to_string(path)?)
}

/// The secret a request presents: the value of `Authorization: Bearer <secret>`.
pub fn bearer_token(authorization: Option<&str>) -> Option<String> {
    let (scheme, rest) = authorization?.trim().split_once(char::is_whitespace)?;
    let rest = rest.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !rest.is_empty()).then(|| rest.to_string())
}

/// Whether a `Cookie` header names [`LEGACY_COOKIE`]. Only the name is looked at.
pub fn names_legacy_cookie(cookie: &str) -> bool {
    cookie.split(';').any(|pair| pair.split('=').next().is_some_and(|name| name.trim() == LEGACY_COOKIE))
}

/// Compares two tokens without an early exit. The work depends on the length of `expected` only.
pub fn token_matches(expected: &str, presented: &str) -> bool {
    let a = expected.as_bytes();
    let b = presented.as_bytes();
    let mut diff = usize::from(a.len() != b.len());
    for (i, x) in a.iter().enumerate() {
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    std::hint::black_box(diff) == 0
}

/// True when `authority` (a `Host` header value, or the part of an `Origin` after `http://`) is
/// exactly one of the three loopback spellings with this port.
fn authority_allowed(authority: &str, port: u16) -> bool {
    let authority = authority.to_ascii_lowercase();
    [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")].contains(&authority)
}

/// The `Host` header must name the loopback address the daemon listens on.
pub fn host_allowed(host: Option<&str>, port: u16) -> bool {
    host.is_some_and(|h| authority_allowed(h, port))
}

/// A request without `Origin` is not from a browser; one with it must come from our own origin.
pub fn origin_allowed(origin: Option<&str>, port: u16) -> bool {
    let Some(origin) = origin else { return true };
    // `get` returns `None` when the cut would fall inside a character.
    match origin.get(..7) {
        Some(scheme) if scheme.eq_ignore_ascii_case("http://") => {
            origin.get(7..).is_some_and(|rest| authority_allowed(rest, port))
        }
        _ => false,
    }
}

/// A random 128-bit value as 32 lowercase hex characters.
fn random_hex() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

#[derive(Default)]
struct LoginState {
    codes: VecDeque<(String, Instant)>,
    sessions: VecDeque<String>,
}

/// Login codes and web-session secrets, in memory only (they die with the daemon).
#[derive(Default)]
pub struct Logins {
    state: Mutex<LoginState>,
}

impl Logins {
    pub fn new() -> Logins {
        Logins::default()
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, LoginState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A fresh single-use code, valid for [`CODE_TTL`].
    pub fn mint_code(&self) -> String {
        self.mint_code_at(Instant::now())
    }

    pub fn mint_code_at(&self, now: Instant) -> String {
        let code = random_hex();
        let mut state = self.locked();
        state.codes.retain(|(_, born)| now.saturating_duration_since(*born) < CODE_TTL);
        while state.codes.len() >= MAX_CODES {
            state.codes.pop_front();
        }
        state.codes.push_back((code.clone(), now));
        code
    }

    /// Exchanges a code for a web-session secret. A code works once, and only within [`CODE_TTL`].
    pub fn redeem(&self, code: &str) -> Option<String> {
        self.redeem_at(code, Instant::now())
    }

    pub fn redeem_at(&self, code: &str, now: Instant) -> Option<String> {
        let mut state = self.locked();
        state.codes.retain(|(_, born)| now.saturating_duration_since(*born) < CODE_TTL);
        // Compare against every outstanding code without an early exit.
        let mut found = None;
        for (i, (candidate, _)) in state.codes.iter().enumerate() {
            if token_matches(candidate, code) {
                found = Some(i);
            }
        }
        state.codes.remove(found?)?;
        let secret = random_hex();
        while state.sessions.len() >= MAX_SESSIONS {
            state.sessions.pop_front();
        }
        state.sessions.push_back(secret.clone());
        Some(secret)
    }

    /// Whether `secret` is a live web-session secret.
    pub fn session_ok(&self, secret: &str) -> bool {
        let state = self.locked();
        let mut ok = false;
        for candidate in &state.sessions {
            ok |= token_matches(candidate, secret);
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const T: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn token_is_created_once_with_mode_0600_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/token");
        let first = load_or_create_token(&path).unwrap();
        assert!(is_token(&first));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let parent_mode = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent_mode, 0o700);
        assert_eq!(load_or_create_token(&path).unwrap(), first);
        let other = load_or_create_token(&dir.path().join("token2")).unwrap();
        assert_ne!(other, first);
    }

    #[test]
    fn concurrent_creators_agree_and_a_leftover_temporary_file_is_harmless() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(dir.path().join(".token.tmp"), "junk").unwrap();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || load_or_create_token(&path).unwrap())
            })
            .collect();
        let tokens: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(is_token(&tokens[0]));
        assert!(tokens.iter().all(|t| *t == tokens[0]));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn a_token_file_is_never_seen_partial() {
        let dir = tempfile::tempdir().unwrap();
        for round in 0..200 {
            let path = dir.path().join(format!("t{round}"));
            let reader = {
                let path = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        if let Ok(text) = std::fs::read_to_string(&path) {
                            assert!(is_token(text.trim()), "partial token file: {text:?}");
                        }
                    }
                })
            };
            assert!(is_token(&load_or_create_token(&path).unwrap()));
            reader.join().unwrap();
        }
    }

    #[test]
    fn an_empty_token_file_is_an_error_that_says_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "").unwrap();
        let err = load_or_create_token(&path).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("delete it and loom will create a new one"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn existing_token_is_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, format!("  {T}\n\n")).unwrap();
        assert_eq!(load_or_create_token(&path).unwrap(), T);
    }

    #[test]
    fn bad_content_is_an_error_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let upper = T.to_uppercase();
        let long = format!("{T}0");
        let nonhex = format!("zz{}", &T[2..]);
        for bad in ["", "hello", upper.as_str(), &T[..63], long.as_str(), nonhex.as_str()] {
            std::fs::write(&path, bad).unwrap();
            let err = load_or_create_token(&path).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::InvalidData, "{bad:?}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), bad);
        }
    }

    #[test]
    fn bearer_parsing() {
        let some = |s: &str| Some(s.to_string());
        assert_eq!(bearer_token(Some("Bearer abc")), some("abc"));
        assert_eq!(bearer_token(Some("bearer   abc  ")), some("abc"));
        assert_eq!(bearer_token(Some("  BEARER\tabc")), some("abc"));
        assert_eq!(bearer_token(Some("Basic abc")), None);
        assert_eq!(bearer_token(Some("Bearer")), None);
        assert_eq!(bearer_token(Some("Bearer  ")), None);
        assert_eq!(bearer_token(Some("abc")), None);
        assert_eq!(bearer_token(None), None);
    }

    #[test]
    fn the_legacy_cookie_is_found_by_name_only() {
        assert!(names_legacy_cookie("loom_token=xyz"));
        assert!(names_legacy_cookie("a=1; loom_token=xyz; b=2"));
        assert!(names_legacy_cookie("  a=1 ;loom_token = xyz ;b=2"));
        assert!(names_legacy_cookie("loom_token="));
        assert!(names_legacy_cookie("a=1; loom_token"));
        assert!(!names_legacy_cookie("xloom_token=xyz; loom_tokens=q"));
        assert!(!names_legacy_cookie("a=loom_token; b=loom_token=1"));
        assert!(!names_legacy_cookie("garbage"));
        assert!(!names_legacy_cookie(""));
        // What forgets it is the cookie as it was set, emptied and expired.
        assert_eq!(FORGET_LEGACY_COOKIE, format!("{LEGACY_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"));
    }

    #[test]
    fn matching() {
        assert!(token_matches(T, T));
        assert!(!token_matches(T, &T[..63]));
        assert!(!token_matches(T, &format!("{T}0")));
        assert!(!token_matches(T, ""));
        assert!(!token_matches("", "x"));
        assert!(token_matches("", ""));
        let mut flipped = T.to_string();
        flipped.replace_range(63.., "e");
        assert!(!token_matches(T, &flipped));
        // Padding with the byte the fold substitutes for missing input is still unequal.
        assert!(!token_matches("abc", "abc\0"));
        assert!(!token_matches("ab\0", "ab"));
    }

    #[test]
    fn host_checks() {
        for h in ["127.0.0.1:7878", "localhost:7878", "[::1]:7878", "LOCALHOST:7878", "Localhost:7878"] {
            assert!(host_allowed(Some(h), 7878), "{h}");
        }
        for h in [
            "",
            "127.0.0.1",
            "localhost",
            "127.0.0.1:7879",
            "127.0.0.1:78780",
            "127.0.0.1:07878",
            "127.0.0.1:7878.evil.example",
            "localhost:7878.evil.example",
            "evil.example:7878",
            "evil.example",
            "127.0.0.1.evil.example:7878",
            "xlocalhost:7878",
            "127.0.0.1:7878 ",
            " 127.0.0.1:7878",
            "127.0.0.1:7878/",
            "user@127.0.0.1:7878",
            "[::1]",
            "[::2]:7878",
            "::1:7878",
            "0.0.0.0:7878",
            "localhost.:7878",
        ] {
            assert!(!host_allowed(Some(h), 7878), "{h:?}");
        }
        assert!(!host_allowed(None, 7878));
        assert!(host_allowed(Some("127.0.0.1:0"), 0));
    }

    #[test]
    fn origin_checks() {
        assert!(origin_allowed(None, 7878));
        for o in ["http://127.0.0.1:7878", "http://localhost:7878", "http://[::1]:7878", "HTTP://LocalHost:7878"] {
            assert!(origin_allowed(Some(o), 7878), "{o}");
        }
        for o in [
            "null",
            "",
            "http://",
            "https://127.0.0.1:7878",
            "http://127.0.0.1",
            "http://127.0.0.1:7879",
            "http://127.0.0.1:7878/",
            "http://127.0.0.1:7878.evil.example",
            "http://evil.example",
            "http://evil.example:7878",
            "http://localhost:7878@evil.example",
            "127.0.0.1:7878",
            "//127.0.0.1:7878",
            "ftp://127.0.0.1:7878",
            "http:/127.0.0.1:7878",
            "httpé://127.0.0.1:7878",
            "http://é",
        ] {
            assert!(!origin_allowed(Some(o), 7878), "{o:?}");
        }
    }

    #[test]
    fn a_code_works_once_and_gives_a_session() {
        let logins = Logins::new();
        let code = logins.mint_code();
        assert_eq!(code.len(), 32);
        assert!(logins.redeem(&"0".repeat(32)).is_none());
        let secret = logins.redeem(&code).unwrap();
        assert_ne!(secret, code);
        assert!(logins.session_ok(&secret));
        assert!(!logins.session_ok(&code));
        assert!(logins.redeem(&code).is_none());
        assert!(logins.redeem("").is_none());
    }

    #[test]
    fn a_code_expires_after_the_ttl() {
        let logins = Logins::new();
        let t0 = Instant::now();
        let code = logins.mint_code_at(t0);
        assert!(logins.redeem_at(&code, t0 + CODE_TTL).is_none());
        let code = logins.mint_code_at(t0);
        assert!(logins.redeem_at(&code, t0 + CODE_TTL - Duration::from_secs(1)).is_some());
    }

    #[test]
    fn codes_and_sessions_are_bounded() {
        let logins = Logins::new();
        let now = Instant::now();
        let codes: Vec<String> = (0..=MAX_CODES).map(|_| logins.mint_code_at(now)).collect();
        assert!(logins.redeem_at(&codes[0], now).is_none(), "the oldest code is dropped");
        assert!(logins.redeem_at(&codes[MAX_CODES], now).is_some());
        let secrets: Vec<String> = (0..=MAX_SESSIONS)
            .map(|_| {
                let code = logins.mint_code_at(now);
                logins.redeem_at(&code, now).unwrap()
            })
            .collect();
        assert!(!logins.session_ok(&secrets[0]), "the oldest session is dropped");
        assert!(logins.session_ok(&secrets[1]));
        assert!(logins.session_ok(&secrets[MAX_SESSIONS]));
    }
}
