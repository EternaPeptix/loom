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

use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

/// Name of the cookie the web UI authenticates with.
pub const COOKIE: &str = "loom_token";

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
    let token = hex::encode(bytes);
    let created = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path);
    match created {
        Ok(mut file) => {
            file.write_all(format!("{token}\n").as_bytes())?;
            file.sync_all()?;
            Ok(token)
        }
        // Another process created it between our read and our create: use theirs.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            let content = std::fs::read_to_string(path)?;
            read_token(path, &content)
        }
        Err(e) => Err(e),
    }
}

/// The token a request presents: a bearer token, else the session cookie.
pub fn presented_token(authorization: Option<&str>, cookie: Option<&str>) -> Option<String> {
    if let Some(value) = authorization {
        if let Some((scheme, rest)) = value.trim().split_once(char::is_whitespace) {
            let rest = rest.trim();
            if scheme.eq_ignore_ascii_case("bearer") && !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    cookie?.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        let value = value.trim();
        (name.trim() == COOKIE && !value.is_empty()).then(|| value.to_string())
    })
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

/// The `Set-Cookie` value that carries the token for the web UI.
pub fn session_cookie(token: &str) -> String {
    format!("{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict")
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
    fn bearer_and_cookie_parsing() {
        let some = |s: &str| Some(s.to_string());
        assert_eq!(presented_token(Some("Bearer abc"), None), some("abc"));
        assert_eq!(presented_token(Some("bearer   abc  "), None), some("abc"));
        assert_eq!(presented_token(Some("  BEARER\tabc"), None), some("abc"));
        assert_eq!(presented_token(Some("Basic abc"), None), None);
        assert_eq!(presented_token(Some("Bearer"), None), None);
        assert_eq!(presented_token(Some("Bearer  "), None), None);
        assert_eq!(presented_token(Some("abc"), None), None);
        assert_eq!(presented_token(None, Some("a=1; loom_token=xyz; b=2")), some("xyz"));
        assert_eq!(presented_token(None, Some("loom_token=xyz")), some("xyz"));
        assert_eq!(presented_token(None, Some("  a=1 ;loom_token = xyz ;b=2")), some("xyz"));
        assert_eq!(presented_token(None, Some("xloom_token=xyz; loom_tokens=q")), None);
        assert_eq!(presented_token(None, Some("loom_token=")), None);
        assert_eq!(presented_token(None, Some("garbage")), None);
        assert_eq!(presented_token(None, None), None);
        // A bearer token wins; a wrong scheme falls through to the cookie.
        assert_eq!(presented_token(Some("Bearer abc"), Some("loom_token=xyz")), some("abc"));
        assert_eq!(presented_token(Some("Basic abc"), Some("loom_token=xyz")), some("xyz"));
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
    fn cookie_value() {
        assert_eq!(session_cookie("tok"), "loom_token=tok; Path=/; HttpOnly; SameSite=Strict");
    }
}
