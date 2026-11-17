//! Opening a stored output by its handle, among the outputs the calling session may see.
//!
//! CONTRACT.
//!
//! The blob store under the loom home is shared by every mission and is content-addressed, so a handle
//! (`out:` and at least 8 hex digits of an id) names the same bytes for anyone who learns it: from a file,
//! a page, an operator's message, another mission's report. A session may open only the outputs of its own
//! mission. [`ToolCtx::outputs`](crate::ToolCtx) says which those are, and every tool that takes an output
//! handle from the model opens it with [`open`] — never with `BlobStore::resolve` or `BlobStore::candidates`
//! directly, which look at the whole store. (The operator's own reads, `loom out` and the API, are not
//! scoped.)
//!
//! ## `OutputScope`
//! `#[async_trait] pub trait OutputScope: Send + Sync { async fn holds(&self, blob: &BlobId) -> bool; }`
//! True when `blob` is an output of the session's mission. The runtime's scope is described in
//! `loom_agent::runtime` (*Outputs of a mission*); it costs a map lookup once the mission's logs have been
//! read. Under `cfg(any(test, feature = "testutil"))` only:
//! - `AnyStored`: holds every id (each test environment has its own temporary store, so this is "every
//!   output this test stored"); `testutil` contexts use it.
//! - `OutputSet`: holds the ids put in it (`OutputSet::with(ids)`, `insert(&self, id)`), for tests that
//!   need an output to be outside the scope.
//!
//! ## `open(ctx, handle) -> Result<BlobId, Unopened>`
//! - `handle` is trimmed and an `out:` prefix removed; what is left must be 8 to 64 hex digits (either
//!   case, compared in lower case). Otherwise `Unopened::NotAHandle`.
//! - The candidates are every stored id that starts with it (`BlobStore::candidates` with no limit), and
//!   only those for which `ctx.outputs.holds(id)` is true are kept. None → `Unopened::Unknown`; exactly one
//!   → `Ok(id)`; more than one → `Unopened::Ambiguous`.
//! - So an id outside the scope is never opened, named, counted or reported as making a handle ambiguous:
//!   a handle that names only another mission's output gets exactly the answer of one that names nothing,
//!   and no sentence says whether such an output exists.
//!
//! `Unopened::sentence(&self, handle) -> String`, with `handle` as the model gave it, trimmed and cut to
//! 80 characters (on a character boundary, `…` added when cut):
//! - `NotAHandle`: ``"`{handle}` is not an output handle. Handles look like `out:1a2b3c4d` and appear in the
//!   header of a result; copy one exactly."``
//! - `Unknown`: ``"No output of this mission has the handle `{handle}`. Copy the handle exactly from a result
//!   header in this mission, or run the command again to produce the output."``
//! - `Ambiguous`: ``"The handle `{handle}` matches more than one output of this mission. Give more characters
//!   of it; a result header shows 16."``
//!
//! Tests required: a full id, a 16-character handle and an 8-character prefix open; `out:` optional and
//! upper case accepted; under 8, over 64 and non-hex are `NotAHandle`; an id outside the scope is `Unknown`
//! with the same sentence as an id that is not stored at all; two stored ids sharing a prefix, one outside
//! the scope, open the one inside without `Ambiguous`; two inside are `Ambiguous`; the sentence cuts a long
//! handle to 80 characters.

use crate::ToolCtx;
use async_trait::async_trait;
use loom_core::BlobId;

/// Which stored outputs a session may open.
#[async_trait]
pub trait OutputScope: Send + Sync {
    /// True when `blob` is an output of the session's mission.
    async fn holds(&self, blob: &BlobId) -> bool;
}

/// Holds every id (each test environment has its own temporary store).
#[cfg(any(test, feature = "testutil"))]
pub struct AnyStored;

#[cfg(any(test, feature = "testutil"))]
#[async_trait]
impl OutputScope for AnyStored {
    async fn holds(&self, _blob: &BlobId) -> bool {
        true
    }
}

/// Holds the ids put in it.
#[cfg(any(test, feature = "testutil"))]
#[derive(Default)]
pub struct OutputSet {
    ids: std::sync::Mutex<std::collections::HashSet<BlobId>>,
}

#[cfg(any(test, feature = "testutil"))]
impl OutputSet {
    pub fn with<I: IntoIterator<Item = BlobId>>(ids: I) -> Self {
        Self { ids: std::sync::Mutex::new(ids.into_iter().collect()) }
    }

    pub fn insert(&self, id: BlobId) {
        if let Ok(mut ids) = self.ids.lock() {
            ids.insert(id);
        }
    }
}

#[cfg(any(test, feature = "testutil"))]
#[async_trait]
impl OutputScope for OutputSet {
    async fn holds(&self, blob: &BlobId) -> bool {
        self.ids.lock().map(|ids| ids.contains(blob)).unwrap_or(false)
    }
}

/// Why a handle opened nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unopened {
    NotAHandle,
    Unknown,
    Ambiguous,
}

const MAX_SHOWN_HANDLE: usize = 80;

impl Unopened {
    /// The sentence for the model; `handle` is as the model gave it.
    pub fn sentence(&self, handle: &str) -> String {
        let handle = handle.trim();
        let handle = match handle.char_indices().nth(MAX_SHOWN_HANDLE) {
            Some((cut, _)) => format!("{}…", &handle[..cut]),
            None => handle.to_string(),
        };
        match self {
            Unopened::NotAHandle => format!(
                "`{handle}` is not an output handle. Handles look like `out:1a2b3c4d` and appear in the header of a result; copy one exactly."
            ),
            Unopened::Unknown => format!(
                "No output of this mission has the handle `{handle}`. Copy the handle exactly from a result header in this mission, or run the command again to produce the output."
            ),
            Unopened::Ambiguous => format!(
                "The handle `{handle}` matches more than one output of this mission. Give more characters of it; a result header shows 16."
            ),
        }
    }
}

/// The output of the session's mission a handle names.
pub async fn open(ctx: &ToolCtx, handle: &str) -> Result<BlobId, Unopened> {
    let trimmed = handle.trim();
    let digits = trimmed.strip_prefix("out:").unwrap_or(trimmed);
    if !(8..=64).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Unopened::NotAHandle);
    }
    let mut held = Vec::new();
    for id in ctx.blobs.candidates(digits, usize::MAX) {
        if ctx.outputs.holds(&id).await {
            held.push(id);
        }
    }
    match held.len() {
        0 => Err(Unopened::Unknown),
        1 => held.pop().ok_or(Unopened::Unknown),
        _ => Err(Unopened::Ambiguous),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use std::sync::Arc;

    fn put(ctx: &ToolCtx, text: &str) -> BlobId {
        ctx.blobs.put_bytes(text.as_bytes()).unwrap().id
    }

    /// An empty file named like a stored id: enough for the candidates of a prefix.
    fn fake(ctx: &ToolCtx, id: &str) -> BlobId {
        let dir = ctx.tmp_dir.parent().unwrap().join("home/blobs").join(&id[..2]);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(id), "x\n").unwrap();
        BlobId(id.to_string())
    }

    #[tokio::test]
    async fn full_id_sixteen_and_eight_open() {
        let e = testutil::env();
        let id = put(&e.ctx, "one\n");
        for h in
            [id.0.clone(), format!("out:{}", &id.0[..16]), id.0[..8].to_string(), format!("  out:{}  ", &id.0[..8])]
        {
            assert_eq!(open(&e.ctx, &h).await, Ok(id.clone()), "{h}");
        }
        assert_eq!(open(&e.ctx, &id.0.to_uppercase()).await, Ok(id.clone()));
        assert_eq!(open(&e.ctx, &format!("OUT:{}", &id.0[..8])).await, Err(Unopened::NotAHandle));
    }

    #[tokio::test]
    async fn malformed_handles_are_not_handles() {
        let e = testutil::env();
        let id = put(&e.ctx, "one\n");
        for h in [&id.0[..7], "", "out:", "zzzzzzzzzz", &format!("{}0", id.0)] {
            assert_eq!(open(&e.ctx, h).await, Err(Unopened::NotAHandle), "{h}");
        }
    }

    #[tokio::test]
    async fn outside_the_scope_reads_as_never_stored() {
        let mut e = testutil::env();
        let id = put(&e.ctx, "secret\n");
        e.ctx.outputs = Arc::new(OutputSet::default());
        let missing = format!("out:{}", "0".repeat(16));
        let seen = open(&e.ctx, &format!("out:{}", &id.0[..16])).await;
        assert_eq!(seen, Err(Unopened::Unknown));
        let a = seen.unwrap_err().sentence(&format!("out:{}", &id.0[..16]));
        let b = open(&e.ctx, &missing).await.unwrap_err().sentence(&format!("out:{}", &id.0[..16]));
        assert_eq!(a, b);
        let set = Arc::new(OutputSet::default());
        e.ctx.outputs = set.clone();
        set.insert(id.clone());
        assert_eq!(open(&e.ctx, &id.0).await, Ok(id));
    }

    #[tokio::test]
    async fn a_foreign_sibling_does_not_make_a_handle_ambiguous() {
        let mut e = testutil::env();
        let mine = fake(&e.ctx, &format!("abcdef01{}", "1".repeat(56)));
        let other = fake(&e.ctx, &format!("abcdef01{}", "2".repeat(56)));
        e.ctx.outputs = Arc::new(OutputSet::with([mine.clone()]));
        assert_eq!(open(&e.ctx, "out:abcdef01").await, Ok(mine.clone()));
        e.ctx.outputs = Arc::new(OutputSet::with([mine, other]));
        assert_eq!(open(&e.ctx, "out:abcdef01").await, Err(Unopened::Ambiguous));
    }

    #[test]
    fn sentences_and_cutting() {
        let long = format!("out:{}", "a".repeat(100));
        let s = Unopened::NotAHandle.sentence(&long);
        assert!(s.starts_with(&format!("`out:{}…` is not an output handle.", "a".repeat(76))), "{s}");
        assert_eq!(
            Unopened::Unknown.sentence(" out:ab "),
            "No output of this mission has the handle `out:ab`. Copy the handle exactly from a result header in this mission, or run the command again to produce the output."
        );
        assert_eq!(
            Unopened::Ambiguous.sentence("out:abcdef01"),
            "The handle `out:abcdef01` matches more than one output of this mission. Give more characters of it; a result header shows 16."
        );
        let wide = "é".repeat(90);
        assert_eq!(Unopened::Unknown.sentence(&wide).matches('é').count(), 80);
    }
}
