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
//! - [`Inject`] holds the effective items of one session (already filtered by S6) and is shared by the proxy
//!   entry of the session, its children's entries and the in-process tools (through `SessionTools::creds`).
//!   `Debug` prints only counts.
//!
//! Tests required: host equality cases (case, trailing dot, IPv6, port ignored, subdomain not matched);
//! request-wins for a cookie of the same name in either of two `Cookie` headers and for a header in another
//! case; `already`; append to an existing `Cookie`; header added when absent; untouched for another host;
//! `apply_head` byte identity outside the additions and `None` on garbage.

use loom_core::creds::Item;

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
        let _ = host;
        todo!("S3")
    }
}

/// `host` as compared with an item's host.
pub fn norm_host(host: &str) -> String {
    let _ = host;
    todo!("S3")
}

/// Attach the items for `host` to header pairs. `already`: cookie names the client will send anyway (an
/// in-process tool's jar for the URL).
pub fn apply(items: &[Item], host: &str, headers: &mut Vec<(String, Vec<u8>)>, already: &[String]) -> usize {
    let _ = (items, host, headers, already);
    todo!("S3")
}

/// Attach the items for `host` to a raw request head.
pub fn apply_head(items: &[Item], host: &str, head: &[u8]) -> Option<Vec<u8>> {
    let _ = (items, host, head);
    todo!("S3")
}
