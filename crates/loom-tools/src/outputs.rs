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
