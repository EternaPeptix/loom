//! Attaching a credential profile's items to requests (CONTRACTS-TRAFFIC-TARGETS S3, S6, S8).
//!
//! CONTRACT
//!
//! - Host equality: the destination host and an item's host are compared after lower-casing, removing one
//!   trailing `.` and the brackets of an IPv6 literal; the port is never part of it. No suffix, glob or
//!   registrable-domain match: `acme.test` is not `www.acme.test`.
//! - [`apply`]: for every item whose host equals `host`, in item order:
//!   - `cookie`: when no `Cookie` header of `headers` already has a pair with that name (names compared
//!     exactly, pairs split on `;` and trimmed) and `already` does not hold the name, the pair `name=value`
//!     is appended to the first `Cookie` header (joined with `; `), or a `Cookie` header is added after the
//!     last header when there is none;
//!   - `header`: when no header of `headers` has that name (ASCII case-insensitive), `name: value` is added
//!     after the last header.
//!
//!   [`apply`] returns how many items it added. Nothing else of `headers` changes (order, case, duplicates).
//! - [`apply_head`]: the same on a raw HTTP/1.x request head (request line, header lines ending in CRLF, the
//!   blank line; any bytes after it are not part of the head and are not passed). `None` when nothing was
//!   added or the head does not parse (it is then forwarded untouched); otherwise the new head, the request
//!   line and every header line byte-identical, in place, with added `Cookie` pairs and headers in the
//!   positions [`apply`] gives them.
//! - An item is never attached when its name or value holds a CR, LF or NUL, when its name is empty, when a
//!   `header` name holds `:`, a space or a tab or is a framing or hop header (`Content-Length`,
//!   `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Upgrade`, `TE`, `Trailer`, `Proxy-Authorization`,
//!   `Proxy-Connection`), or when a `cookie` name holds `=` or `;`: it would break the request's framing or
//!   smuggle a header. A head with a bare LF line ending is also left untouched by [`apply_head`].
//! - [`Inject`] holds the effective items of one session (already filtered by S6) and is shared by the proxy
//!   entry of the session, its children's entries and the in-process tools (through `SessionTools::creds`).
//!   `Debug` prints only counts.
//!
//! Tests required: host equality cases (case, trailing dot, IPv6, port ignored, subdomain not matched);
//! request-wins for a cookie of the same name in either of two `Cookie` headers and for a header in another
//! case; `already`; append to an existing `Cookie`; header added when absent; untouched for another host;
//! `apply_head` byte identity outside the additions and `None` on garbage.

use loom_core::creds::{Item, ItemKind};

/// The items one session attaches.
#[derive(Clone, Default)]
pub struct Inject {
    items: Vec<Item>,
}

impl std::fmt::Debug for Inject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Inject({} items)", self.items.len())
    }
}

impl Inject {
    /// `items` = the effective set (`loom_core::creds::effective`).
    pub fn new(items: Vec<Item>) -> Inject {
        Inject { items }
    }

    pub fn items(&self) -> &[Item] {
        &self.items
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether any item is for `host` (host equality above).
    pub fn applies_to(&self, host: &str) -> bool {
        let host = norm_host(host);
        self.items.iter().any(|i| norm_host(&i.host) == host)
    }
}

/// `host` as compared with an item's host.
pub fn norm_host(host: &str) -> String {
    let lower = host.trim().to_ascii_lowercase();
    let no_dot = lower.strip_suffix('.').unwrap_or(&lower);
    no_dot.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(no_dot).to_string()
}

/// Headers that frame the message or hop; never attached from an item.
const NEVER: [&str; 9] = [
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "proxy-connection",
];

/// Whether an item may be attached at all (see the contract).
fn attachable(item: &Item) -> bool {
    let bad = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    if item.name.is_empty() || bad(&item.name) || bad(&item.value) {
        return false;
    }
    match item.kind {
        ItemKind::Cookie => !item.name.contains(['=', ';']),
        ItemKind::Header => {
            !item.name.contains([':', ' ', '\t']) && !NEVER.iter().any(|n| item.name.eq_ignore_ascii_case(n))
        }
    }
}

/// Whether a `Cookie` header of `headers` already has a pair named `name`.
fn has_cookie(headers: &[(String, Vec<u8>)], name: &str) -> bool {
    headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("cookie")).any(|(_, v)| {
        v.split(|b| *b == b';')
            .any(|pair| pair.split(|b| *b == b'=').next().unwrap_or(&[]).trim_ascii() == name.as_bytes())
    })
}

/// Attach the items for `host` to header pairs. `already`: cookie names the client will send anyway (an
/// in-process tool's jar for the URL).
pub fn apply(items: &[Item], host: &str, headers: &mut Vec<(String, Vec<u8>)>, already: &[String]) -> usize {
    let host = norm_host(host);
    let mut added = 0;
    for item in items.iter().filter(|i| norm_host(&i.host) == host && attachable(i)) {
        match item.kind {
            ItemKind::Cookie => {
                if has_cookie(headers, &item.name) || already.iter().any(|a| a == &item.name) {
                    continue;
                }
                let pair = format!("{}={}", item.name, item.value);
                match headers.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case("cookie")) {
                    Some((_, v)) => {
                        if !v.trim_ascii().is_empty() {
                            v.extend_from_slice(b"; ");
                        }
                        v.extend_from_slice(pair.as_bytes());
                    }
                    None => headers.push(("Cookie".to_string(), pair.into_bytes())),
                }
                added += 1;
            }
            ItemKind::Header => {
                if headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(&item.name)) {
                    continue;
                }
                headers.push((item.name.clone(), item.value.clone().into_bytes()));
                added += 1;
            }
        }
    }
    added
}

/// Attach the items for `host` to a raw request head.
pub fn apply_head(items: &[Item], host: &str, head: &[u8]) -> Option<Vec<u8>> {
    let host_norm = norm_host(host);
    if !items.iter().any(|i| norm_host(&i.host) == host_norm) {
        return None;
    }
    let mut slots = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut slots);
    let n = match req.parse(head) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return None,
    };
    let head = head.get(..n)?;
    // The request line and one line per header, each ending in CRLF (a bare LF is not a head to rewrite).
    let mut raw: Vec<&[u8]> = Vec::with_capacity(req.headers.len() + 1);
    for l in head.split(|b| *b == b'\n').take(req.headers.len() + 1) {
        raw.push(l.strip_suffix(b"\r")?);
    }
    let used: usize = raw.iter().map(|l| l.len() + 2).sum();
    if used + 2 != head.len() {
        return None;
    }
    let mut headers: Vec<(String, Vec<u8>)> =
        req.headers.iter().map(|h| (h.name.to_string(), h.value.to_vec())).collect();
    let before: Vec<Vec<u8>> = headers.iter().map(|(_, v)| v.clone()).collect();
    if apply(items, host, &mut headers, &[]) == 0 {
        return None;
    }
    let mut out = Vec::with_capacity(head.len() + 64);
    out.extend_from_slice(raw.first()?);
    out.extend_from_slice(b"\r\n");
    for (i, old) in before.iter().enumerate() {
        out.extend_from_slice(raw.get(i + 1)?);
        let new = &headers.get(i)?.1;
        if new != old {
            // A cookie pair was appended to this header: its original line stays, the addition follows it.
            out.extend_from_slice(new.get(old.len()..)?);
        }
        out.extend_from_slice(b"\r\n");
    }
    for (name, value) in headers.get(before.len()..)? {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie(name: &str, value: &str, host: &str) -> Item {
        Item { kind: ItemKind::Cookie, name: name.into(), value: value.into(), host: host.into() }
    }

    fn header(name: &str, value: &str, host: &str) -> Item {
        Item { kind: ItemKind::Header, name: name.into(), value: value.into(), host: host.into() }
    }

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
        pairs.iter().map(|(n, v)| (n.to_string(), v.as_bytes().to_vec())).collect()
    }

    fn s(headers: &[(String, Vec<u8>)]) -> Vec<(String, String)> {
        headers.iter().map(|(n, v)| (n.clone(), String::from_utf8_lossy(v).to_string())).collect()
    }

    #[test]
    fn host_equality() {
        let inj = Inject::new(vec![cookie("a", "1", "acme.test")]);
        for yes in ["acme.test", "ACME.Test", "acme.test.", "Acme.Test."] {
            assert!(inj.applies_to(yes), "{yes}");
        }
        for no in ["www.acme.test", "acme.test.evil", "xacme.test", "", "acme.test:443"] {
            assert!(!inj.applies_to(no), "{no}");
        }
        assert_eq!(norm_host("[::1]"), "::1");
        assert_eq!(norm_host("[FE80::1]"), "fe80::1");
        assert_eq!(norm_host("127.0.0.1."), "127.0.0.1");
        let v6 = Inject::new(vec![cookie("a", "1", "::1")]);
        assert!(v6.applies_to("[::1]") && v6.applies_to("::1"));
        assert!(!Inject::default().applies_to("acme.test") && Inject::default().is_empty());
        assert_eq!(format!("{inj:?}"), "Inject(1 items)");
    }

    #[test]
    fn a_request_cookie_of_the_same_name_wins_in_either_cookie_header() {
        let items = [cookie("session", "ours", "acme.test"), cookie("csrf", "c", "acme.test")];
        let mut hs = h(&[("Host", "acme.test"), ("Cookie", "a=1"), ("cookie", "x=2; session=theirs")]);
        assert_eq!(apply(&items, "acme.test", &mut hs, &[]), 1);
        assert_eq!(s(&hs)[1].1, "a=1; csrf=c");
        assert_eq!(s(&hs)[2].1, "x=2; session=theirs");
        let mut hs = h(&[("Cookie", "session=theirs")]);
        assert_eq!(apply(&items[..1], "acme.test", &mut hs, &[]), 0);
        // A prefix of a name is not the name.
        let mut hs = h(&[("Cookie", "session2=theirs")]);
        assert_eq!(apply(&items[..1], "acme.test", &mut hs, &[]), 1);
        assert_eq!(s(&hs)[0].1, "session2=theirs; session=ours");
        // Names are case-sensitive.
        let mut hs = h(&[("Cookie", "SESSION=theirs")]);
        assert_eq!(apply(&items[..1], "acme.test", &mut hs, &[]), 1);
    }

    #[test]
    fn already_counts_as_a_cookie_the_request_sends() {
        let items = [cookie("session", "ours", "acme.test"), cookie("b", "2", "acme.test")];
        let mut hs = h(&[("Host", "acme.test")]);
        assert_eq!(apply(&items, "acme.test", &mut hs, &["session".to_string()]), 1);
        assert_eq!(s(&hs), vec![("Host".into(), "acme.test".into()), ("Cookie".into(), "b=2".into())]);
    }

    #[test]
    fn cookies_append_to_the_first_cookie_header_or_add_one_after_the_last_header() {
        let items = [cookie("a", "1", "acme.test"), cookie("b", "2", "acme.test")];
        let mut hs = h(&[("Cookie", "x=9"), ("Accept", "*/*"), ("Cookie", "y=8")]);
        assert_eq!(apply(&items, "acme.test", &mut hs, &[]), 2);
        assert_eq!(s(&hs)[0].1, "x=9; a=1; b=2");
        assert_eq!(hs.len(), 3);
        let mut hs = h(&[("Host", "acme.test"), ("Accept", "*/*")]);
        assert_eq!(apply(&items, "acme.test", &mut hs, &[]), 2);
        assert_eq!(hs.len(), 3);
        assert_eq!(s(&hs)[2], ("Cookie".into(), "a=1; b=2".into()));
    }

    #[test]
    fn a_header_is_added_only_when_the_request_sends_none_of_that_name_in_any_case() {
        let items = [header("Authorization", "Bearer t", "acme.test"), header("X-Api-Key", "k", "acme.test")];
        let mut hs = h(&[("authorization", "Basic x"), ("Host", "acme.test")]);
        assert_eq!(apply(&items, "acme.test", &mut hs, &[]), 1);
        assert_eq!(s(&hs)[2], ("X-Api-Key".into(), "k".into()));
        assert_eq!(s(&hs)[0].1, "Basic x");
        let mut hs = h(&[("Host", "acme.test")]);
        assert_eq!(apply(&items, "acme.test", &mut hs, &[]), 2);
        assert_eq!(s(&hs)[1], ("Authorization".into(), "Bearer t".into()));
    }

    #[test]
    fn another_host_and_unsafe_items_are_untouched() {
        let items = [cookie("a", "1", "acme.test"), header("Authorization", "Bearer t", "acme.test")];
        let mut hs = h(&[("Host", "www.acme.test")]);
        assert_eq!(apply(&items, "www.acme.test", &mut hs, &[]), 0);
        assert_eq!(hs.len(), 1);
        let bad = [
            header("Content-Length", "0", "acme.test"),
            header("X-A", "v\r\nX-B: w", "acme.test"),
            header("X:A", "v", "acme.test"),
            cookie("a=b", "v", "acme.test"),
            cookie("", "v", "acme.test"),
            cookie("n", "v\nw", "acme.test"),
        ];
        let mut hs = h(&[("Host", "acme.test")]);
        assert_eq!(apply(&bad, "acme.test", &mut hs, &[]), 0);
        assert_eq!(hs.len(), 1);
    }

    #[test]
    fn apply_head_changes_only_the_additions() {
        let items = [cookie("session", "ours", "acme.test"), header("Authorization", "Bearer t", "acme.test")];
        let head = b"GET /a?b=c HTTP/1.1\r\nHost: acme.test\r\nx-Odd:   spaced  \r\nCookie: a=1\r\nCookie: z=2\r\nAccept: */*\r\n\r\n";
        let got = apply_head(&items, "acme.test", head).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "GET /a?b=c HTTP/1.1\r\nHost: acme.test\r\nx-Odd:   spaced  \r\nCookie: a=1; session=ours\r\nCookie: z=2\r\n\
             Accept: */*\r\nAuthorization: Bearer t\r\n\r\n"
        );
        // No Cookie header: one is added after the last header; bytes after the head are not passed.
        let head = b"POST /p HTTP/1.1\r\nHost: acme.test\r\nContent-Length: 3\r\n\r\nabc";
        let got = apply_head(&items, "acme.test", head).unwrap();
        assert_eq!(
            String::from_utf8(got).unwrap(),
            "POST /p HTTP/1.1\r\nHost: acme.test\r\nContent-Length: 3\r\nCookie: session=ours\r\nAuthorization: Bearer t\r\n\r\n"
        );
        // Nothing to add: None.
        let head = b"GET / HTTP/1.1\r\nHost: acme.test\r\nCookie: session=x\r\nauthorization: y\r\n\r\n";
        assert_eq!(apply_head(&items, "acme.test", head), None);
        assert_eq!(apply_head(&items, "other.test", b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n"), None);
    }

    #[test]
    fn apply_head_is_none_on_garbage() {
        let items = [cookie("a", "1", "acme.test")];
        for g in [
            &b""[..],
            b"\x16\x03\x01garbage",
            b"GET / HTTP/1.1\r\nHost: acme.test\r\n",
            b"GET / HTTP/1.1\nHost: acme.test\n\n",
            b"NOT HTTP AT ALL\r\n\r\n",
            b"GET / HTTP/1.1\r\nno colon here\r\n\r\n",
        ] {
            assert_eq!(apply_head(&items, "acme.test", g), None, "{g:?}");
        }
    }
}
