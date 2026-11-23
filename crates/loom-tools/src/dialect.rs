//! Tool shapes: what the model is shown, and what it may send. `docs/TOOL-SHAPES.md` is the
//! normative table; this module implements it.
//!
//! CONTRACT
//!
//! Models are not fine-tuned for loom. A call in the shape of any widely trained harness (Claude Code,
//! Codex, Gemini CLI, OpenHands, Cline, Cursor) that maps onto a loom tool is run, not refused, and the
//! six file and shell tools are presented in Claude Code's argument names.
//!
//! ## `present(spec, dialect) -> ToolSpec`
//!
//! `Dialect::Loom` returns `spec` unchanged. `Dialect::Trained` rewrites the parameters (and the
//! parameter names inside the description) of exactly `read`, `write`, `edit`, `bash`, `grep`, `glob`
//! per TOOL-SHAPES §1; every other spec is returned unchanged. The tool name never changes. Pure and
//! deterministic: the same input gives byte-identical output (the list is part of the cached prefix).
//! Each presented schema keeps `additionalProperties: false`, marks the same arguments required as the
//! internal one (with the presented names), and gives every argument a description.
//!
//! ## `adapt(name, args, dialect, has) -> Adapt`
//!
//! Called by [`crate::prepare`] before the schema check, with the raw arguments already parsed as JSON
//! (`args` may be any JSON value: Codex sends a bare string to `apply_patch`). `has(tool)` says whether
//! the session's registry has that canonical tool. Steps:
//!
//! 1. Name: an exact registered name is kept. Otherwise match ignoring ASCII case with `-` read as `_`
//!    against registered names, then against the alias table (TOOL-SHAPES §2). `str_replace_editor`,
//!    `str_replace_based_edit_tool` and `text_editor` dispatch on `command`. `apply_patch` may become
//!    several calls (see `Adapt::Batch`). No match → `Adapt::Unknown` (the caller keeps today's
//!    "There is no tool named …" message with nearest names). A match whose tool `has` says is absent →
//!    `Adapt::Refuse("`{name}` runs `{tool}`, which this role does not have.")`.
//! 2. Arguments: convert into the INTERNAL shape (`path`, `start`/`end`, `old`/`new`/`all`, `timeout_s`,
//!    `background`, `ignore_case`, `before`/`after`/`mode`/`max`, `steps`, `question`/`role`, `answer`…).
//!    Keys that are the presented keys of `dialect`, or internal keys, convert silently. Every other
//!    repair adds one note phrased in the PRESENTED names of `dialect`, e.g.
//!    "argument `old_str` read as `old_string`" (trained) or "argument `old_str` read as `old`" (loom);
//!    "called `Read`, ran `read`" for a name that was not exact. Values that are converted say so:
//!    "`timeout` 30 read as 30 seconds (values under 1000 are seconds)", "`offset` 0 read as line 1",
//!    "`requires_approval` is not used here; dropped". Keys this module does not know are left in place
//!    for the schema check to refuse (unknown arguments are never silently dropped). A shape that is
//!    ambiguous (both `old` and `old_string` with different values; `edit_file` with `code_edit`;
//!    `apply_patch` `*** Delete File`; `undo_edit`; `BashOutput` `filter`) → `Adapt::Refuse` with one
//!    sentence naming what to send instead.
//! 3. `think` → `Adapt::Noop("Noted.")`.
//!
//! The existing `schema::normalize_for_tool` aliases stay and run after `adapt`; `adapt` must not
//! duplicate notes that `normalize_for_tool` would add for the same key (convert it here, silently or
//! with a note, and the normalizer then sees the internal key).
//!
//! Internal argument additions this contract relies on (implemented in the owning tools):
//! - `bash`: `description` (string, optional; recorded, shown as the row label, no effect on running).
//! - `grep`: `mode` (`content` | `files` | `count`; default `content` in the loom dialect, and the
//!   presented `output_mode` default is `files_with_matches`), `type` (ripgrep type name), `before`,
//!   `after` (lines), with `context` kept for both; `files_only: true` stays accepted as `mode: files`.
//! - `edit`: `edits` (array of {`old`, `new`, `all`?}); applied in order on the evolving text, all or
//!   none; mutually exclusive with `old`/`new` and with `patch`.
//! - `read` with a `path` that is a stored-output handle (`out:` + hex, as in result headers) runs as
//!   `out_read`; `grep` with such a `path` runs as `out_grep`. `adapt` makes that switch.
//!
//! Tests (in this module): every row of TOOL-SHAPES §2 at least once, through `adapt`, asserting the
//! internal args and the exact note; the Codex argv forms (`["bash","-lc",X]`, `["sh","-c",X]`, plain
//! argv quoted); `apply_patch` with one Update, one Add, two files, Delete (refused), a bare string;
//! Cline SEARCH/REPLACE in both marker styles, two blocks; `str_replace_editor` each `command`;
//! `TodoWrite` and Codex `update_plan` into `steps` with statuses; `timeout` 600 vs 600000; presented
//! keys silent and loom keys silent in both dialects; `present` byte-stable across calls and a golden
//! test of the six presented schemas; a name that maps to a tool the role lacks.

use loom_core::config::Dialect;
use loom_core::event::ToolSpec;
use serde_json::Value;

/// One call in loom's internal shape.
#[derive(Clone, Debug, PartialEq)]
pub struct Adapted {
    /// Canonical registered tool name.
    pub tool: String,
    /// Arguments in the internal shape (still to be normalised and schema-checked).
    pub args: Value,
    /// Repairs, in presented names, for the result header.
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Adapt {
    /// Run this one call.
    Run(Adapted),
    /// Run these calls in order, all-or-none (Codex `apply_patch` over several files). Each entry is
    /// checked before any runs; the caller refuses the whole batch when one entry fails its check.
    Batch(Vec<Adapted>),
    /// Answer `ok` with this text; nothing runs (`think`).
    Noop(String),
    /// Refuse with this sentence; nothing runs.
    Refuse(String),
    /// No tool matches this name.
    Unknown,
}

/// The spec as the model is shown it. See the module contract.
pub fn present(spec: &ToolSpec, dialect: Dialect) -> ToolSpec {
    let _ = (spec, dialect);
    todo!()
}

/// Bring a call into the internal shape. See the module contract.
pub fn adapt(name: &str, args: Value, dialect: Dialect, has: &dyn Fn(&str) -> bool) -> Adapt {
    let _ = (name, args, dialect, has);
    todo!()
}

/// The presented name of an internal argument of `tool` in `dialect` (identity for the loom dialect
/// and for tools whose shape is not rewritten). Used to phrase notes and refusals.
pub fn presented_arg(tool: &str, internal: &str, dialect: Dialect) -> String {
    let _ = (tool, internal, dialect);
    todo!()
}
