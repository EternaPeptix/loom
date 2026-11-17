//! Reading the server name out of a TLS ClientHello (E4c, `docs/MONITOR.md` §2.2).
//!
//! CONTRACT.
//!
//! The proxy binds a `CONNECT` tunnel to the name it was asked for: before relaying a byte upstream it reads the
//! client's first flight and requires the TLS server name (SNI) to be the destination or another name the
//! session's policy allows. This module is the parser and nothing else; it never allocates more than the input and
//! never panics on any input.
//!
//! `parse(buf) -> Hello`, over the bytes the client has sent so far:
//! - `Hello::Empty`: no byte yet.
//! - `Hello::NotTls`: the first byte is not a TLS handshake record (`0x16`) with a `3.x` version, so the stream is
//!   not TLS (an SSH banner, a plain HTTP request, a binary protocol). There is no server name to bind.
//! - `Hello::Incomplete`: a TLS handshake record whose ClientHello is not all there yet (the record, or the
//!   handshake message that spans several records, is cut). The caller reads more and parses again, up to
//!   [`MAX_HELLO`] bytes.
//! - `Hello::Malformed(why)`: a TLS handshake record that does not hold a well-formed ClientHello: the handshake is
//!   not a ClientHello, a length does not fit, the extensions overrun the message, the `server_name` extension
//!   appears twice or holds two host names or a name that is not a host name (letters, digits, `-`, `_` and `.`,
//!   at most 253 bytes, labels of 1 to 63 bytes), or the handshake is split over a record of another type. A
//!   caller refuses it: two parsers that read one hello differently are how a name is hidden.
//! - `Hello::Tls { sni, ech }`: a complete ClientHello. `sni` is the host name in lower case without a trailing
//!   dot, `None` when there is no `server_name` extension (or it lists no host name). `ech` is true when the hello
//!   carries an encrypted-ClientHello extension (types `0xfe08` to `0xfe0d` and the earlier encrypted SNI
//!   `0xffce`): the name the proxy can read is then only the outer one, so the caller refuses it.
//!
//! A ClientHello may be fragmented over consecutive handshake records; they are joined. Anything after the
//! ClientHello's last byte is ignored.
//!
//! Tests required: a plain hello with a name; no extension; an IP-literal hello without a name; a name with upper
//! case and a trailing dot; a hello split over two records and one cut in the middle (Incomplete, then the same
//! after the rest arrives, at every split point); not TLS (HTTP, SSH, a TLS alert); a handshake that is not a
//! ClientHello; a length that overruns; two `server_name` extensions; two host names in one; a name with a NUL, a
//! space, an empty label and a 64-byte label; an ECH extension (both type codes); a fuzz loop of truncations and
//! single-byte corruptions that never panics.

/// The most bytes read for one ClientHello. A hello of a real client is under 2 KiB; one beyond this is refused.
pub const MAX_HELLO: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hello {
    Empty,
    NotTls,
    Incomplete,
    Malformed(&'static str),
    Tls { sni: Option<String>, ech: bool },
}

const HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0;

fn is_ech(ext: u16) -> bool {
    (0xfe08..=0xfe0d).contains(&ext) || ext == 0xffce
}

/// A reader over a byte slice that says `None` instead of going out of bounds.
struct Cur<'a> {
    b: &'a [u8],
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = (self.b.get(..n)?, self.b.get(n..)?);
        self.b = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some((usize::from(*b.first()?) << 16) | (usize::from(*b.get(1)?) << 8) | usize::from(*b.get(2)?))
    }

    fn len8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    fn len16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

/// Reads the ClientHello at the start of `buf`; see the module contract.
pub fn parse(buf: &[u8]) -> Hello {
    let Some(first) = buf.first() else { return Hello::Empty };
    if *first != HANDSHAKE {
        return Hello::NotTls;
    }
    // The handshake message, joined from consecutive handshake records.
    let mut message: Vec<u8> = Vec::new();
    let mut at = 0usize;
    loop {
        let Some(rest) = buf.get(at..) else { return Hello::Incomplete };
        let Some(header) = rest.get(..5) else { return Hello::Incomplete };
        let (kind, major, length) = (
            header.first().copied().unwrap_or(0),
            header.get(1).copied().unwrap_or(0),
            usize::from(u16::from_be_bytes([header.get(3).copied().unwrap_or(0), header.get(4).copied().unwrap_or(0)])),
        );
        if at == 0 && major != 3 {
            return Hello::NotTls;
        }
        if kind != HANDSHAKE || major != 3 {
            return Hello::Malformed("the ClientHello is continued in a record that is not a handshake record");
        }
        if length == 0 || length > 1 << 14 {
            return Hello::Malformed("a TLS record has a length no record can have");
        }
        let Some(body) = rest.get(5..5usize.saturating_add(length)) else { return Hello::Incomplete };
        message.extend_from_slice(body);
        at = at.saturating_add(5).saturating_add(length);
        if message.len() >= 4 {
            let want = message.get(1..4).and_then(|b| Cur { b }.u24());
            let Some(want) = want else { return Hello::Incomplete };
            if want > MAX_HELLO {
                return Hello::Malformed("the ClientHello is larger than a ClientHello can be");
            }
            if message.len() >= want.saturating_add(4) {
                message.truncate(want.saturating_add(4));
                break;
            }
        }
        if at >= MAX_HELLO {
            return Hello::Malformed("the ClientHello is larger than a ClientHello can be");
        }
    }
    hello(&message)
}

/// The handshake message `message` (type, 3-byte length, body) as a ClientHello.
fn hello(message: &[u8]) -> Hello {
    let mut c = Cur { b: message };
    if c.u8() != Some(CLIENT_HELLO) {
        return Hello::Malformed("the first TLS handshake message is not a ClientHello");
    }
    let Some(len) = c.u24() else { return Hello::Malformed("the ClientHello is cut") };
    if len != c.b.len() {
        return Hello::Malformed("the ClientHello's length does not match its record");
    }
    let bad = Hello::Malformed("the ClientHello is not well formed");
    // legacy_version, random, session id, cipher suites, compression methods.
    if c.take(2).is_none() || c.take(32).is_none() || c.len8().is_none() {
        return bad;
    }
    match c.len16() {
        Some(suites) if !suites.is_empty() && suites.len() % 2 == 0 => {}
        _ => return bad,
    }
    if c.len8().is_none() {
        return bad;
    }
    // A hello without extensions has no server name.
    if c.b.is_empty() {
        return Hello::Tls { sni: None, ech: false };
    }
    let Some(extensions) = c.len16() else { return bad };
    if !c.b.is_empty() {
        return Hello::Malformed("the ClientHello has bytes after its extensions");
    }
    let (mut sni, mut seen_name, mut ech) = (None, false, false);
    let mut e = Cur { b: extensions };
    while !e.b.is_empty() {
        let (Some(kind), Some(data)) = (e.u16(), e.len16()) else { return bad };
        if is_ech(kind) {
            ech = true;
        }
        if kind == EXT_SERVER_NAME {
            if seen_name {
                return Hello::Malformed("the ClientHello names a server twice");
            }
            seen_name = true;
            match server_name(data) {
                Ok(name) => sni = name,
                Err(why) => return Hello::Malformed(why),
            }
        }
    }
    Hello::Tls { sni, ech }
}

/// The host name of a `server_name` extension body: `None` when the list holds no host name.
fn server_name(data: &[u8]) -> Result<Option<String>, &'static str> {
    let mut outer = Cur { b: data };
    let list = outer.len16().ok_or("the server_name extension is cut")?;
    if !outer.b.is_empty() {
        return Err("the server_name extension has bytes after its list");
    }
    let mut c = Cur { b: list };
    let mut found: Option<String> = None;
    while !c.b.is_empty() {
        let kind = c.u8().ok_or("the server_name list is cut")?;
        let name = c.len16().ok_or("the server_name list is cut")?;
        if kind != 0 {
            continue;
        }
        if found.is_some() {
            return Err("the server_name extension lists two host names");
        }
        found = Some(host_name(name).ok_or("the server name is not a host name")?);
    }
    Ok(found)
}

/// `name` as a lower-case host name without a trailing dot, when it is one.
fn host_name(name: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(name).ok()?;
    let text = text.strip_suffix('.').unwrap_or(text);
    let ok = !text.is_empty()
        && text.len() <= 253
        && text.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    ok.then(|| text.to_ascii_lowercase())
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// A ClientHello message (handshake header included) with the given extensions.
    pub(crate) fn message(extensions: &[(u16, Vec<u8>)], with_extensions: bool) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7u8; 32]);
        body.push(0); // session id
        body.extend([0, 2, 0x13, 0x01]); // one cipher suite
        body.extend([1, 0]); // null compression
        if with_extensions {
            let mut ext = Vec::new();
            for (kind, data) in extensions {
                ext.extend(kind.to_be_bytes());
                ext.extend((data.len() as u16).to_be_bytes());
                ext.extend(data);
            }
            body.extend((ext.len() as u16).to_be_bytes());
            body.extend(ext);
        }
        let mut m = vec![CLIENT_HELLO, 0, (body.len() >> 8) as u8, body.len() as u8];
        m.extend(body);
        m
    }

    pub(crate) fn sni_ext(names: &[&str]) -> (u16, Vec<u8>) {
        let mut list = Vec::new();
        for n in names {
            list.push(0);
            list.extend((n.len() as u16).to_be_bytes());
            list.extend(n.as_bytes());
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend(list);
        (EXT_SERVER_NAME, data)
    }

    pub(crate) fn record(payload: &[u8]) -> Vec<u8> {
        let mut r = vec![HANDSHAKE, 3, 1];
        r.extend((payload.len() as u16).to_be_bytes());
        r.extend(payload);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn tls(sni: Option<&str>, ech: bool) -> Hello {
        Hello::Tls { sni: sni.map(str::to_string), ech }
    }

    #[test]
    fn a_hello_with_a_name_is_read() {
        let hello = record(&message(&[(10, vec![0, 2, 0, 29]), sni_ext(&["Api.Example.Test."])], true));
        assert_eq!(parse(&hello), tls(Some("api.example.test"), false));
    }

    #[test]
    fn a_hello_without_a_name_or_without_extensions_has_none() {
        assert_eq!(parse(&record(&message(&[(10, vec![0, 2, 0, 29])], true))), tls(None, false));
        assert_eq!(parse(&record(&message(&[], false))), tls(None, false));
        // A server_name extension that lists only a type this parser does not know has no host name.
        let (kind, mut data) = sni_ext(&[]);
        data.clear();
        data.extend([0, 5, 9, 0, 2, 1, 1]);
        assert_eq!(parse(&record(&message(&[(kind, data)], true))), tls(None, false));
    }

    #[test]
    fn a_hello_split_over_records_is_joined_and_a_cut_one_is_incomplete_at_every_point() {
        let msg = message(&[sni_ext(&["a.example.test"])], true);
        let (first, second) = msg.split_at(msg.len() / 2);
        let mut two = record(first);
        two.extend(record(second));
        assert_eq!(parse(&two), tls(Some("a.example.test"), false));
        for cut in 1..two.len() {
            let got = parse(&two[..cut]);
            assert!(matches!(got, Hello::Incomplete), "cut at {cut} gave {got:?}");
        }
        let one = record(&msg);
        for cut in 1..one.len() {
            assert_eq!(parse(&one[..cut]), Hello::Incomplete, "cut at {cut}");
        }
        assert_eq!(parse(&[]), Hello::Empty);
    }

    #[test]
    fn what_is_not_a_hello_is_told_from_what_is_malformed() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), Hello::NotTls);
        assert_eq!(parse(b"SSH-2.0-OpenSSH_9\r\n"), Hello::NotTls);
        // A handshake record of a version that is not 3.x is not TLS either.
        assert_eq!(parse(&[0x16, 2, 0, 0, 5, 1, 2, 3, 4, 5]), Hello::NotTls);
        // A TLS alert is not a handshake.
        assert_eq!(parse(&[0x15, 3, 3, 0, 2, 2, 40]), Hello::NotTls);
        // A handshake that is not a ClientHello.
        let mut other = message(&[], false);
        other[0] = 2;
        assert!(matches!(parse(&record(&other)), Hello::Malformed(_)));
        // A length that does not match.
        let mut long = message(&[], false);
        long[3] = long[3].wrapping_add(1);
        assert!(matches!(parse(&record(&long)), Hello::Incomplete | Hello::Malformed(_)));
        // A zero-length record.
        assert!(matches!(parse(&[0x16, 3, 1, 0, 0]), Hello::Malformed(_)));
        // The continuation of the hello in a record of another type.
        let msg = message(&[sni_ext(&["a.example.test"])], true);
        let (first, second) = msg.split_at(msg.len() / 2);
        let mut mixed = record(first);
        mixed.extend([0x17, 3, 3]);
        mixed.extend((second.len() as u16).to_be_bytes());
        mixed.extend(second);
        assert!(matches!(parse(&mixed), Hello::Malformed(_)));
    }

    #[test]
    fn a_name_that_is_not_a_host_name_or_is_given_twice_is_malformed() {
        let sixty_four = "a".repeat(64);
        for bad in ["a b.test", "a\0b.test", "a..test", ".test", sixty_four.as_str(), "", "é.test"] {
            let got = parse(&record(&message(&[sni_ext(&[bad])], true)));
            assert!(matches!(got, Hello::Malformed(_)), "{bad:?} gave {got:?}");
        }
        let twice = parse(&record(&message(&[sni_ext(&["a.test"]), sni_ext(&["b.test"])], true)));
        assert!(matches!(twice, Hello::Malformed(_)), "{twice:?}");
        let two_names = parse(&record(&message(&[sni_ext(&["a.test", "b.test"])], true)));
        assert!(matches!(two_names, Hello::Malformed(_)), "{two_names:?}");
    }

    #[test]
    fn an_encrypted_client_hello_is_flagged_under_every_type_code() {
        for code in [0xfe0du16, 0xfe08, 0xffce] {
            let got = parse(&record(&message(&[sni_ext(&["public.example.test"]), (code, vec![0, 1, 2])], true)));
            assert_eq!(got, tls(Some("public.example.test"), true), "{code:#x}");
        }
    }

    #[test]
    fn no_truncation_or_corruption_panics() {
        let msg = record(&message(&[sni_ext(&["a.example.test"]), (0xfe0d, vec![1, 2, 3])], true));
        for cut in 0..=msg.len() {
            let _ = parse(&msg[..cut]);
        }
        for at in 0..msg.len() {
            for flip in [0u8, 0xff, 0x80, 0x01] {
                let mut m = msg.clone();
                m[at] ^= flip;
                let _ = parse(&m);
            }
        }
        assert!(matches!(parse(&vec![0x16; MAX_HELLO + 10]), Hello::Malformed(_) | Hello::NotTls));
    }
}
