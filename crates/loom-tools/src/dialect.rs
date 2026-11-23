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
use serde_json::{json, Map, Value};

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

// ---------------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------------

/// How a call's arguments are converted; chosen by the name the model used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Read,
    Write,
    Edit,
    ReplaceInFile,
    ApplyPatch,
    Editor,
    Bash,
    Grep,
    Glob,
    Ls,
    FileSearch,
    WebFetch,
    Plan,
    JobWait,
    JobKill,
    Agent,
    Ask,
    Finish,
    Plain,
}

/// (name as matched: lowercase, `-` read as `_`; tool it runs; conversion). TOOL-SHAPES §2.
const NAMES: &[(&str, &str, Kind)] = &[
    ("read", "read", Kind::Read),
    ("read_file", "read", Kind::Read),
    ("view_file", "read", Kind::Read),
    ("open_file", "read", Kind::Read),
    ("cat", "read", Kind::Read),
    ("write", "write", Kind::Write),
    ("write_file", "write", Kind::Write),
    ("create_file", "write", Kind::Write),
    ("write_to_file", "write", Kind::Write),
    ("edit", "edit", Kind::Edit),
    ("multiedit", "edit", Kind::Edit),
    ("str_replace", "edit", Kind::Edit),
    ("replace", "edit", Kind::Edit),
    ("edit_file", "edit", Kind::Edit),
    ("replace_in_file", "edit", Kind::ReplaceInFile),
    ("apply_patch", "edit", Kind::ApplyPatch),
    ("str_replace_editor", "edit", Kind::Editor),
    ("str_replace_based_edit_tool", "edit", Kind::Editor),
    ("text_editor", "edit", Kind::Editor),
    ("bash", "bash", Kind::Bash),
    ("shell", "bash", Kind::Bash),
    ("exec_command", "bash", Kind::Bash),
    ("execute_bash", "bash", Kind::Bash),
    ("run_shell_command", "bash", Kind::Bash),
    ("run_terminal_cmd", "bash", Kind::Bash),
    ("execute_command", "bash", Kind::Bash),
    ("run_command", "bash", Kind::Bash),
    ("terminal", "bash", Kind::Bash),
    ("exec", "bash", Kind::Bash),
    ("sh", "bash", Kind::Bash),
    ("grep", "grep", Kind::Grep),
    ("search_file_content", "grep", Kind::Grep),
    ("grep_search", "grep", Kind::Grep),
    ("search_files", "grep", Kind::Grep),
    ("ripgrep", "grep", Kind::Grep),
    ("rg", "grep", Kind::Grep),
    ("search", "grep", Kind::Grep),
    ("glob", "glob", Kind::Glob),
    ("find_files", "glob", Kind::Glob),
    ("glob_file_search", "glob", Kind::Glob),
    ("file_search", "glob", Kind::FileSearch),
    ("ls", "glob", Kind::Ls),
    ("list_dir", "glob", Kind::Ls),
    ("list_directory", "glob", Kind::Ls),
    ("list_files", "glob", Kind::Ls),
    ("web_fetch", "web_fetch", Kind::WebFetch),
    ("webfetch", "web_fetch", Kind::WebFetch),
    ("fetch", "web_fetch", Kind::WebFetch),
    ("fetch_url", "web_fetch", Kind::WebFetch),
    ("plan", "plan", Kind::Plan),
    ("todowrite", "plan", Kind::Plan),
    ("todo_write", "plan", Kind::Plan),
    ("write_todos", "plan", Kind::Plan),
    ("update_plan", "plan", Kind::Plan),
    ("job_wait", "job_wait", Kind::JobWait),
    ("bashoutput", "job_wait", Kind::JobWait),
    ("bash_output", "job_wait", Kind::JobWait),
    ("get_job_output", "job_wait", Kind::JobWait),
    ("job_kill", "job_kill", Kind::JobKill),
    ("killshell", "job_kill", Kind::JobKill),
    ("killbash", "job_kill", Kind::JobKill),
    ("kill_shell", "job_kill", Kind::JobKill),
    ("kill_bash", "job_kill", Kind::JobKill),
    ("kill_job", "job_kill", Kind::JobKill),
    ("agent_spawn", "agent_spawn", Kind::Agent),
    ("task", "agent_spawn", Kind::Agent),
    ("agent", "agent_spawn", Kind::Agent),
    ("subagent", "agent_spawn", Kind::Agent),
    ("spawn_agent", "agent_spawn", Kind::Agent),
    ("dispatch_agent", "agent_spawn", Kind::Agent),
    ("delegate", "agent_spawn", Kind::Agent),
    ("ask_user", "ask_user", Kind::Ask),
    ("askuserquestion", "ask_user", Kind::Ask),
    ("ask_followup_question", "ask_user", Kind::Ask),
    ("ask_user_question", "ask_user", Kind::Ask),
    ("finish", "finish", Kind::Finish),
    ("attempt_completion", "finish", Kind::Finish),
    ("complete_task", "finish", Kind::Finish),
    ("task_complete", "finish", Kind::Finish),
];

fn match_key(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('-', "_")
}

/// The loom tool a foreign name maps to: `None` for loom's own exact names (`read`, not `Read`) and for names that map
/// to nothing. [`crate::canonical_tool_alias`] is this.
pub fn alias_tool(name: &str) -> Option<&'static str> {
    let key = match_key(name);
    NAMES.iter().find(|(k, t, _)| *k == key && *t != name).map(|(_, t, _)| *t)
}

// ---------------------------------------------------------------------------------------------
// Presented names
// ---------------------------------------------------------------------------------------------

/// (tool, internal argument, presented argument) for the trained dialect.
const RENAMES: &[(&str, &str, &str)] = &[
    ("read", "path", "file_path"),
    ("read", "start", "offset"),
    ("read", "end", "limit"),
    ("write", "path", "file_path"),
    ("edit", "path", "file_path"),
    ("edit", "old", "old_string"),
    ("edit", "new", "new_string"),
    ("edit", "all", "replace_all"),
    ("bash", "timeout_s", "timeout"),
    ("bash", "background", "run_in_background"),
    ("grep", "mode", "output_mode"),
    ("grep", "ignore_case", "-i"),
    ("grep", "after", "-A"),
    ("grep", "before", "-B"),
    ("grep", "context", "-C"),
    ("grep", "max", "head_limit"),
];

/// The presented name of an internal argument of `tool` in `dialect` (identity for the loom dialect
/// and for tools whose shape is not rewritten). Used to phrase notes and refusals.
pub fn presented_arg(tool: &str, internal: &str, dialect: Dialect) -> String {
    if dialect == Dialect::Trained {
        if let Some((_, _, p)) = RENAMES.iter().find(|(t, i, _)| *t == tool && *i == internal) {
            return (*p).to_string();
        }
    }
    internal.to_string()
}

// ---------------------------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------------------------

/// One presented property: where it comes from.
enum Src {
    /// The internal property of this name, renamed, with its description in presented names.
    Internal(&'static str),
    /// A property of its own (the unit or the meaning differs from the internal one).
    Own(Value),
}

fn rows(tool: &str) -> Option<Vec<(&'static str, Src)>> {
    use Src::{Internal, Own};
    Some(match tool {
        "read" => vec![
            ("file_path", Internal("path")),
            (
                "offset",
                Own(
                    json!({"type": "integer", "minimum": 1, "description": "The line number to start reading from (1-based, default 1)."}),
                ),
            ),
            (
                "limit",
                Own(
                    json!({"type": "integer", "minimum": 1, "description": "The number of lines to read (default: as many as one call returns)."}),
                ),
            ),
        ],
        "write" => vec![("file_path", Internal("path")), ("content", Internal("content"))],
        "edit" => vec![
            ("file_path", Internal("path")),
            ("old_string", Internal("old")),
            ("new_string", Internal("new")),
            ("replace_all", Internal("all")),
            (
                "edits",
                Own(json!({
                    "type": "array",
                    "description": "Several replacements in one call, applied in order, each to the text the previous one produced; if any one fails the file is left unchanged. Use instead of `old_string`/`new_string` and `patch`.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "old_string": {"type": "string", "description": "The exact text to replace."},
                            "new_string": {"type": "string", "description": "The text to put in its place."},
                            "replace_all": {"type": "boolean", "description": "Replace every occurrence of `old_string` (default false)."}
                        },
                        "required": ["old_string", "new_string"],
                        "additionalProperties": false
                    }
                })),
            ),
            ("patch", Internal("patch")),
        ],
        "bash" => vec![
            ("command", Internal("command")),
            ("description", Internal("description")),
            (
                "timeout",
                Own(
                    json!({"type": "integer", "minimum": 1, "description": "Stop the command if it has not finished after this many milliseconds (a value under 1000 is read as seconds). Leave it out to let the command run as long as it needs."}),
                ),
            ),
            ("run_in_background", Internal("background")),
            ("cwd", Internal("cwd")),
            ("idle_timeout_s", Internal("idle_timeout_s")),
            ("wake_on", Internal("wake_on")),
            ("wake_every_s", Internal("wake_every_s")),
        ],
        "grep" => vec![
            ("pattern", Internal("pattern")),
            ("path", Internal("path")),
            ("glob", Internal("glob")),
            ("type", Internal("type")),
            (
                "output_mode",
                Own(json!({
                    "type": "string",
                    "enum": ["content", "files_with_matches", "count"],
                    "default": "files_with_matches",
                    "description": "`content` shows the matching lines (`path:line:text`), `files_with_matches` shows the paths of the files with matches, `count` shows the number of matching lines per file (default `files_with_matches`)."
                })),
            ),
            ("-i", Internal("ignore_case")),
            (
                "-n",
                Own(
                    json!({"type": "boolean", "description": "Show line numbers (accepted; `content` mode always shows them)."}),
                ),
            ),
            ("-A", Internal("after")),
            ("-B", Internal("before")),
            ("-C", Internal("context")),
            ("head_limit", Internal("max")),
            ("hidden", Internal("hidden")),
            ("no_ignore", Internal("no_ignore")),
        ],
        _ => return None,
    })
}

/// `` `internal` `` read as `` `presented` `` in a description.
fn in_presented_names(tool: &str, text: &str) -> String {
    let mut out = text.to_string();
    for (t, i, p) in RENAMES {
        if *t == tool {
            out = out.replace(&format!("`{i}`"), &format!("`{p}`"));
        }
    }
    out
}

/// The spec as the model is shown it. See the module contract.
pub fn present(spec: &ToolSpec, dialect: Dialect) -> ToolSpec {
    if dialect == Dialect::Loom {
        return spec.clone();
    }
    let Some(rows) = rows(&spec.name) else { return spec.clone() };
    let internal = spec.parameters.get("properties").and_then(Value::as_object);
    let internal_required: Vec<&str> = spec
        .parameters
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut props = Map::new();
    let mut required = Vec::new();
    for (name, src) in rows {
        match src {
            Src::Internal(from) => {
                let Some(Value::Object(p)) = internal.and_then(|m| m.get(from)) else { continue };
                let mut p = p.clone();
                if let Some(Value::String(d)) = p.get("description") {
                    let d = in_presented_names(&spec.name, d);
                    p.insert("description".into(), Value::String(d));
                }
                props.insert(name.to_string(), Value::Object(p));
                if internal_required.contains(&from) {
                    required.push(Value::String(name.to_string()));
                }
            }
            Src::Own(v) => {
                props.insert(name.to_string(), v);
            }
        }
    }
    let mut parameters = spec.parameters.clone();
    if let Value::Object(m) = &mut parameters {
        m.insert("properties".into(), Value::Object(props));
        m.insert("required".into(), Value::Array(required));
    }
    ToolSpec {
        name: spec.name.clone(),
        description: in_presented_names(&spec.name, &spec.description),
        parameters,
        class: spec.class,
    }
}

// ---------------------------------------------------------------------------------------------
// adapt
// ---------------------------------------------------------------------------------------------

/// Keys other harnesses send on calls that carry nothing loom uses.
const UNUSED_KEYS: &[&str] =
    &["requires_approval", "explanation", "security_risk", "with_escalated_permissions", "justification"];

const PATH_KEYS: &[&str] = &["file_path", "absolute_path", "target_file", "filepath", "filename", "file", "path"];
const OLD_KEYS: &[&str] = &["old_string", "old_str", "old_text"];
const NEW_KEYS: &[&str] = &["new_string", "new_str", "new_text"];

/// A refusal sentence.
type Step<T = ()> = Result<T, String>;

/// One call's argument map while it is converted.
struct Conv {
    tool: String,
    dialect: Dialect,
    map: Map<String, Value>,
    notes: Vec<String>,
}

impl Conv {
    fn new(tool: &str, dialect: Dialect, map: Map<String, Value>) -> Conv {
        Conv { tool: tool.to_string(), dialect, map, notes: Vec::new() }
    }

    fn pres(&self, internal: &str) -> String {
        presented_arg(&self.tool, internal, self.dialect)
    }

    fn note(&mut self, text: String) {
        if !self.notes.contains(&text) {
            self.notes.push(text);
        }
    }

    /// Move the first of `keys` that is present to `internal`. A key that is the presented name of
    /// `internal` is taken silently; any other is said. Two different values are a conflict.
    fn alias(&mut self, internal: &str, keys: &[&str]) -> Step {
        for key in keys {
            if *key == internal {
                continue;
            }
            let Some(v) = self.map.remove(*key) else { continue };
            let shown = self.pres(internal);
            match self.map.get(internal) {
                Some(have) if *have != v => {
                    return Err(format!(
                        "Both `{key}` and `{shown}` were sent with different values. Send only `{shown}`. Nothing was executed."
                    ));
                }
                Some(_) => {}
                None => {
                    self.map.insert(internal.to_string(), v);
                }
            }
            if *key != shown {
                self.note(format!("argument `{key}` read as `{shown}`"));
            }
        }
        Ok(())
    }

    /// Remove keys that carry nothing here, and say so.
    fn drop_unused(&mut self, keys: &[&str]) {
        for key in keys {
            if self.map.remove(*key).is_some() {
                self.note(format!("`{key}` is not used here; dropped"));
            }
        }
    }

    /// The numeric value of `key`, removed. `Some(None)` when it was there but is not a number (it is
    /// put back for the schema check).
    fn take_number(&mut self, key: &str) -> Option<Option<f64>> {
        let v = self.map.remove(key)?;
        let n = number(&v);
        if n.is_none() {
            self.map.insert(key.to_string(), v);
        }
        Some(n)
    }

    fn finish(self, tool: &str) -> Adapted {
        Adapted { tool: tool.to_string(), args: Value::Object(self.map), notes: self.notes }
    }
}

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// Bring a call into the internal shape. See the module contract.
pub fn adapt(name: &str, args: Value, dialect: Dialect, has: &dyn Fn(&str) -> bool) -> Adapt {
    let key = match_key(name);
    let entry = NAMES.iter().find(|(k, _, _)| *k == key);
    let (tool, kind): (String, Kind) = if has(name) && entry.is_none_or(|(_, t, _)| *t == name) {
        (name.to_string(), entry.map_or(Kind::Plain, |(_, _, k)| *k))
    } else if let Some((_, t, k)) = entry {
        ((*t).to_string(), *k)
    } else if key == "think" {
        return Adapt::Noop("Noted.".to_string());
    } else if has(&key) {
        (key.clone(), Kind::Plain)
    } else {
        return Adapt::Unknown;
    };
    if !has(&tool) {
        return Adapt::Refuse(format!("`{name}` runs `{tool}`, which this role does not have."));
    }
    let name_note = (name != tool).then(|| format!("tool alias: called `{name}`, ran `{tool}`"));
    match convert(&tool, kind, args, dialect, has) {
        Ok(Adapt::Run(mut a)) => {
            if let Some(n) = name_note {
                a.notes.insert(0, n);
            }
            Adapt::Run(a)
        }
        Ok(Adapt::Batch(mut list)) => {
            if let (Some(n), Some(first)) = (name_note, list.first_mut()) {
                first.notes.insert(0, n);
            }
            Adapt::Batch(list)
        }
        Ok(other) => other,
        Err(sentence) => Adapt::Refuse(sentence),
    }
}

fn convert(tool: &str, kind: Kind, args: Value, dialect: Dialect, has: &dyn Fn(&str) -> bool) -> Step<Adapt> {
    if kind == Kind::ApplyPatch {
        return apply_patch(args, has);
    }
    let map = match args {
        Value::Object(m) => m,
        Value::Null => Map::new(),
        other => return Ok(Adapt::Run(Adapted { tool: tool.to_string(), args: other, notes: Vec::new() })),
    };
    let mut c = Conv::new(tool, dialect, map);
    if matches!(
        kind,
        Kind::Read
            | Kind::Write
            | Kind::Edit
            | Kind::ReplaceInFile
            | Kind::Bash
            | Kind::Grep
            | Kind::Glob
            | Kind::Ls
            | Kind::FileSearch
            | Kind::WebFetch
            | Kind::JobWait
            | Kind::JobKill
    ) {
        c.drop_unused(UNUSED_KEYS);
    }
    let mut target = tool.to_string();
    match kind {
        Kind::Read => read_args(&mut c)?,
        Kind::Write => write_args(&mut c)?,
        Kind::Edit => edit_args(&mut c)?,
        Kind::ReplaceInFile => replace_in_file_args(&mut c)?,
        Kind::Editor => return editor(c, has),
        Kind::Bash => {
            if let Some(patch) = argv_apply_patch(&c.map) {
                return apply_patch(Value::String(patch), has);
            }
            bash_args(&mut c)?;
        }
        Kind::Grep => grep_args(&mut c)?,
        Kind::Glob => glob_args(&mut c)?,
        Kind::Ls => ls_args(&mut c)?,
        Kind::FileSearch => file_search_args(&mut c)?,
        Kind::WebFetch => web_fetch_args(&mut c),
        Kind::Plan => plan_args(&mut c)?,
        Kind::JobWait => job_args(&mut c, true)?,
        Kind::JobKill => job_args(&mut c, false)?,
        Kind::Agent => {
            c.alias("question", &["prompt", "task"])?;
            c.alias("role", &["subagent_type"])?;
            c.alias("title", &["description"])?;
        }
        Kind::Ask => ask_args(&mut c),
        Kind::Finish => c.alias("answer", &["result", "message"])?,
        Kind::Plain | Kind::ApplyPatch => {}
    }
    // A stored output opened through `read` / `grep` runs as `out_read` / `out_grep` where the role has them.
    let handle = c.map.get("path").and_then(Value::as_str).is_some_and(|p| p.starts_with("out:"));
    if handle && (kind == Kind::Read || kind == Kind::Grep) {
        let twin = if kind == Kind::Read { "out_read" } else { "out_grep" };
        if has(twin) {
            if let Some(p) = c.map.remove("path") {
                c.map.insert("handle".into(), p);
            }
            if kind == Kind::Grep {
                c.map.remove("mode");
            }
            target = twin.to_string();
        }
    }
    Ok(Adapt::Run(c.finish(&target)))
}

fn read_args(c: &mut Conv) -> Step {
    c.alias("path", PATH_KEYS)?;
    c.alias("start", &["start_line_one_indexed"])?;
    c.alias("end", &["end_line_one_indexed_inclusive"])?;
    if c.map.remove("should_read_entire_file").is_some() {
        c.note(
            "`should_read_entire_file` is not used here; the file is read from line 1 unless a range is given".into(),
        );
    }
    let offset = c.take_number("offset");
    let limit = c.take_number("limit");
    if offset.is_none() && limit.is_none() {
        return Ok(());
    }
    if c.map.contains_key("start") || c.map.contains_key("end") {
        let (s, e) = (c.pres("start"), c.pres("end"));
        return Err(format!(
            "Both `{s}`/`{e}` and `offset`/`limit` were sent. Send only `{s}` and `{e}`. Nothing was executed."
        ));
    }
    let mut start = 1.0;
    match offset {
        Some(Some(n)) => {
            start = n.max(1.0);
            if n < 1.0 {
                c.note(format!("`offset` {} read as line 1", fmt_num(n)));
            } else if c.pres("start") != "offset" {
                let shown = c.pres("start");
                c.note(format!("argument `offset` read as `{shown}`"));
            }
            c.map.insert("start".into(), json!(start as i64));
        }
        Some(None) => return Err("`offset` must be a line number. Nothing was executed.".into()),
        None => {}
    }
    match limit {
        Some(Some(m)) if m >= 1.0 => {
            let last = (start + m - 1.0) as i64;
            c.map.insert("end".into(), json!(last));
            if c.pres("end") != "limit" {
                let shown = c.pres("end");
                c.note(format!("argument `limit` read as `{shown}` (line {last})"));
            }
        }
        Some(Some(_)) => return Err("`limit` must be at least 1 (a number of lines). Nothing was executed.".into()),
        Some(None) => return Err("`limit` must be a number of lines. Nothing was executed.".into()),
        None => {}
    }
    Ok(())
}

fn write_args(c: &mut Conv) -> Step {
    c.alias("path", PATH_KEYS)?;
    c.alias("content", &["file_text", "contents", "text"])
}

fn edit_args(c: &mut Conv) -> Step {
    if c.map.contains_key("code_edit") {
        return Err("`code_edit` is a sketch with elisions, not a replacement, and cannot be applied. Send `old_string` (the exact text now in the file) and `new_string` (its replacement), or use `write` for a whole file. Nothing was executed.".into());
    }
    c.alias("path", PATH_KEYS)?;
    c.alias("old", OLD_KEYS)?;
    c.alias("new", NEW_KEYS)?;
    c.alias("all", &["replace_all"])?;
    c.drop_unused(&["instruction", "instructions"]);
    if let Some(v) = c.map.remove("expected_replacements") {
        match number(&v) {
            Some(n) if n > 1.0 => {
                let shown = c.pres("all");
                c.map.entry("all".to_string()).or_insert(json!(true));
                c.note(format!("`expected_replacements` {} read as `{shown}` (the count is not checked)", fmt_num(n)));
            }
            Some(_) => c.note("`expected_replacements` 1 is the default; dropped".into()),
            None => {
                c.map.insert("expected_replacements".into(), v);
            }
        }
    }
    if let Some(edits) = c.map.remove("edits") {
        let Value::Array(items) = edits else {
            c.map.insert("edits".into(), edits);
            return Ok(());
        };
        let mut out = Vec::new();
        for item in items {
            match item {
                Value::Object(m) => {
                    let mut ic = Conv::new("edit", c.dialect, m);
                    ic.alias("old", OLD_KEYS)?;
                    ic.alias("new", NEW_KEYS)?;
                    ic.alias("all", &["replace_all"])?;
                    for n in std::mem::take(&mut ic.notes) {
                        c.note(n);
                    }
                    out.push(Value::Object(ic.map));
                }
                other => out.push(other),
            }
        }
        c.map.insert("edits".into(), Value::Array(out));
    }
    Ok(())
}

/// Cline `replace_in_file`: `diff` is SEARCH/REPLACE blocks.
fn replace_in_file_args(c: &mut Conv) -> Step {
    let Some(diff) = c.map.remove("diff") else { return edit_args(c) };
    let Some(text) = diff.as_str() else {
        c.map.insert("diff".into(), diff);
        return Ok(());
    };
    if c.map.contains_key("edits") {
        return Err("Both `diff` and `edits` were sent. Send only `edits`. Nothing was executed.".into());
    }
    let edits = search_replace_blocks(text)?;
    c.map.insert("edits".into(), Value::Array(edits));
    c.note("argument `diff` read as `edits`".into());
    edit_args(c)
}

fn search_replace_blocks(text: &str) -> Step<Vec<Value>> {
    #[derive(PartialEq)]
    enum At {
        Outside,
        Search,
        Replace,
    }
    let (mut at, mut old, mut new, mut out) = (At::Outside, Vec::new(), Vec::new(), Vec::new());
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let marker = line.trim_end();
        match at {
            At::Outside if marker == "<<<<<<< SEARCH" || marker == "------- SEARCH" => {
                at = At::Search;
                old.clear();
                new.clear();
            }
            At::Search if marker == "=======" => at = At::Replace,
            At::Replace if marker == ">>>>>>> REPLACE" || marker == "+++++++ REPLACE" => {
                out.push(json!({"old": old.join("\n"), "new": new.join("\n")}));
                at = At::Outside;
            }
            At::Search => old.push(line.to_string()),
            At::Replace => new.push(line.to_string()),
            At::Outside => {}
        }
    }
    if at != At::Outside {
        return Err("The `diff` ends inside a SEARCH/REPLACE block (a `=======` or the closing REPLACE marker is missing). Nothing was executed.".into());
    }
    if out.is_empty() {
        return Err("The `diff` holds no SEARCH/REPLACE block (`<<<<<<< SEARCH`, `=======`, `>>>>>>> REPLACE`). Nothing was executed.".into());
    }
    Ok(out)
}

/// `str_replace_editor` and its relatives: one call, by `command`.
fn editor(mut c: Conv, has: &dyn Fn(&str) -> bool) -> Step<Adapt> {
    let Some(command) = c.map.remove("command").and_then(|v| v.as_str().map(str::to_string)) else {
        return Err(
            "This editor tool needs a `command`: view, create, str_replace or insert. Nothing was executed.".into()
        );
    };
    c.drop_unused(UNUSED_KEYS);
    c.alias("path", PATH_KEYS)?;
    let wants = |t: &str| -> Step {
        if has(t) {
            Ok(())
        } else {
            Err(format!("`{command}` runs `{t}`, which this role does not have."))
        }
    };
    match command.as_str() {
        "view" => {
            let dir = c.map.get("path").and_then(Value::as_str).is_some_and(|p| p.ends_with('/'));
            if dir {
                wants("glob")?;
                let path = c.map.remove("path");
                c.map.clear();
                c.map.insert("pattern".into(), json!("*"));
                if let Some(p) = path {
                    c.map.insert("path".into(), p);
                }
                c.note("`view` of a directory ran `glob` with pattern `*`".into());
                return Ok(Adapt::Run(c.finish("glob")));
            }
            wants("read")?;
            if let Some(range) = c.map.remove("view_range") {
                let bounds: Option<Vec<f64>> = range.as_array().map(|a| a.iter().filter_map(number).collect());
                match bounds.as_deref() {
                    Some([a, b]) => {
                        c.map.insert("start".into(), json!(a.max(1.0) as i64));
                        if *b >= 0.0 {
                            c.map.insert("end".into(), json!(*b as i64));
                        }
                        c.note(format!("`view_range` [{}, {}] read as a line range", fmt_num(*a), fmt_num(*b)));
                    }
                    _ => return Err("`view_range` must be two numbers, [first line, last line]. Nothing was executed.".into()),
                }
            }
            Ok(Adapt::Run(c.finish("read")))
        }
        "create" => {
            wants("write")?;
            c.alias("content", &["file_text"])?;
            Ok(Adapt::Run(c.finish("write")))
        }
        "str_replace" => {
            wants("edit")?;
            c.alias("old", OLD_KEYS)?;
            c.alias("new", NEW_KEYS)?;
            if !c.map.contains_key("new") && c.map.contains_key("old") {
                c.map.insert("new".into(), json!(""));
                c.note("`new_str` was left out; read as an empty replacement".into());
            }
            Ok(Adapt::Run(c.finish("edit")))
        }
        "insert" => {
            wants("edit")?;
            let line = c.map.remove("insert_line").as_ref().and_then(number);
            let text = ["new_str", "insert_text", "new_string"].iter().find_map(|k| c.map.remove(*k));
            let (Some(line), Some(Value::String(text))) = (line, text) else {
                return Err("`insert` needs `insert_line` (the line to insert after, 0 for the top) and `new_str` (the text). Nothing was executed.".into());
            };
            let line = line.max(0.0) as i64;
            let body = text.strip_suffix('\n').unwrap_or(&text);
            let added: Vec<String> =
                body.split('\n').map(|l| format!("+{}", l.strip_suffix('\r').unwrap_or(l))).collect();
            let patch = format!("@@ -{line},0 +{},{} @@\n{}", line + 1, added.len(), added.join("\n"));
            c.map.insert("patch".into(), Value::String(patch));
            c.note(format!("`insert` after line {line} ran `edit` with a `patch`"));
            Ok(Adapt::Run(c.finish("edit")))
        }
        "undo_edit" => Err("There is no undo. Restore the earlier text with `edit` (or `bash` with git), then send the next call. Nothing was executed.".into()),
        other => Err(format!(
            "`{other}` is not a command this editor tool accepts here (view, create, str_replace, insert). Nothing was executed."
        )),
    }
}

// ----- apply_patch ---------------------------------------------------------------------------

enum Section {
    Update { path: String, body: Vec<String> },
    Add { path: String, lines: Vec<String> },
}

fn patch_sections(text: &str) -> Step<Vec<Section>> {
    let mut out: Vec<Section> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(p) = line.strip_prefix("*** Update File:") {
            out.push(Section::Update { path: p.trim().to_string(), body: Vec::new() });
        } else if let Some(p) = line.strip_prefix("*** Add File:") {
            out.push(Section::Add { path: p.trim().to_string(), lines: Vec::new() });
        } else if let Some(p) = line.strip_prefix("*** Delete File:") {
            let p = p.trim();
            return Err(format!("`apply_patch` `*** Delete File: {p}` is not supported here. Nothing was applied. Delete the file with `bash` (`rm {p}`) and send the rest of the patch again."));
        } else if let Some(p) = line.strip_prefix("*** Move to:") {
            return Err(format!("`apply_patch` `*** Move to: {}` is not supported here. Nothing was applied. Rename the file with `bash` (`mv`) and send the edits for it again.", p.trim()));
        } else if line == "*** End Patch" {
            break;
        } else if line == "*** Begin Patch" {
            continue;
        } else {
            match out.last_mut() {
                Some(Section::Update { body, .. }) => body.push(line.to_string()),
                Some(Section::Add { lines, .. }) => lines.push(line.strip_prefix('+').unwrap_or(line).to_string()),
                None if line.trim().is_empty() => {}
                None => {
                    return Err("The patch has text before its first `*** Update File:` or `*** Add File:` line. Nothing was applied.".into());
                }
            }
        }
    }
    Ok(out)
}

fn apply_patch(args: Value, has: &dyn Fn(&str) -> bool) -> Step<Adapt> {
    const USAGE: &str =
        "`apply_patch` takes the patch text as `input` (`*** Begin Patch` … `*** End Patch`). Nothing was applied.";
    let (text, path) = match &args {
        Value::String(s) => (s.clone(), None),
        Value::Object(m) => {
            let text = ["input", "patch", "diff"].iter().find_map(|k| m.get(*k).and_then(Value::as_str));
            let path = PATH_KEYS.iter().find_map(|k| m.get(*k).and_then(Value::as_str));
            match text {
                Some(t) => (t.to_string(), path.map(str::to_string)),
                None => return Err(USAGE.into()),
            }
        }
        _ => return Err(USAGE.into()),
    };
    let has_header =
        ["*** Update File:", "*** Add File:", "*** Delete File:", "*** Move to:"].iter().any(|h| text.contains(h));
    let sections = if has_header {
        patch_sections(&text)?
    } else if let Some(path) = path {
        // A bare unified diff, for the file named beside it.
        let notes = vec!["`apply_patch` with a `path` ran `edit` with a `patch`".to_string()];
        return Ok(Adapt::Run(Adapted { tool: "edit".into(), args: json!({"path": path, "patch": text}), notes }));
    } else {
        return Err("The patch names no file: it needs `*** Update File: path` or `*** Add File: path` lines between `*** Begin Patch` and `*** End Patch`. Nothing was applied.".into());
    };
    if sections.is_empty() {
        return Err("The patch holds no `*** Update File:` or `*** Add File:` section. Nothing was applied.".into());
    }
    let mut calls = Vec::new();
    for s in sections {
        match s {
            Section::Update { path, body } => {
                if !has("edit") {
                    return Err("`apply_patch` runs `edit`, which this role does not have.".into());
                }
                let patch = format!("*** Begin Patch\n*** Update File: {path}\n{}\n*** End Patch", body.join("\n"));
                calls.push(Adapted {
                    tool: "edit".into(),
                    args: json!({"path": path, "patch": patch}),
                    notes: Vec::new(),
                });
            }
            Section::Add { path, lines } => {
                if !has("write") {
                    return Err(
                        "`apply_patch` with `*** Add File:` runs `write`, which this role does not have.".into()
                    );
                }
                let mut content = lines.join("\n");
                if !lines.is_empty() && !content.ends_with('\n') {
                    content.push('\n');
                }
                calls.push(Adapted {
                    tool: "write".into(),
                    args: json!({"path": path, "content": content}),
                    notes: Vec::new(),
                });
            }
        }
    }
    Ok(match calls.len() {
        1 => calls.pop().map_or(Adapt::Unknown, Adapt::Run),
        _ => Adapt::Batch(calls),
    })
}

/// Codex's `shell` call `["apply_patch", "<patch>"]`.
fn argv_apply_patch(map: &Map<String, Value>) -> Option<String> {
    let argv = map.get("command")?.as_array()?;
    match argv.as_slice() {
        [Value::String(a), Value::String(p)] if a == "apply_patch" || a == "applypatch" => Some(p.clone()),
        _ => None,
    }
}

// ----- bash ----------------------------------------------------------------------------------

fn shell_quote(word: &str) -> String {
    let plain = !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if plain {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// An argv as one command line: `["bash","-lc",X]` is `X`, anything else is quoted and joined.
fn command_line(argv: &[String]) -> String {
    if let [shell, flag, script] = argv {
        let base = shell.rsplit('/').next().unwrap_or(shell);
        if matches!(base, "bash" | "sh" | "zsh") && matches!(flag.as_str(), "-c" | "-lc" | "-ic" | "-ilc") {
            return script.clone();
        }
    }
    argv.iter().map(|w| shell_quote(w)).collect::<Vec<_>>().join(" ")
}

fn bash_args(c: &mut Conv) -> Step {
    c.alias("command", &["cmd"])?;
    if let Some(Value::Array(items)) = c.map.get("command") {
        let argv: Vec<String> = items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        if argv.len() == items.len() && !argv.is_empty() {
            let line = command_line(&argv);
            c.map.insert("command".into(), Value::String(line));
            c.note("argument `command` was a list; joined into one command line".into());
        }
    }
    c.alias("cwd", &["workdir", "directory", "dir", "working_directory"])?;
    c.alias("background", &["run_in_background", "is_background"])?;
    // `timeout` is milliseconds (seconds when under 1000); `timeout_ms` is always milliseconds.
    let shown = c.pres("timeout_s");
    for key in ["timeout", "timeout_ms"] {
        let Some(value) = c.map.remove(key) else { continue };
        let Some(n) = number(&value) else {
            c.map.insert("timeout_s".into(), value);
            continue;
        };
        if c.map.contains_key("timeout_s") {
            return Err(format!("Both `{key}` and `{shown}` were sent. Send only `{shown}`. Nothing was executed."));
        }
        if n <= 0.0 {
            c.note(format!("`{key}` {} means no limit here; dropped", fmt_num(n)));
            continue;
        }
        let ms = key == "timeout_ms" || n >= 1000.0;
        let secs = if ms { (n / 1000.0).ceil() } else { n.ceil() }.max(1.0) as i64;
        c.map.insert("timeout_s".into(), json!(secs));
        if !ms {
            c.note(format!("`{key}` {} read as {secs} seconds (values under 1000 are seconds)", fmt_num(n)));
        } else if key == "timeout_ms" || c.dialect == Dialect::Loom {
            c.note(format!("argument `{key}` read as `{shown}` ({} milliseconds is {secs} seconds)", fmt_num(n)));
        }
    }
    Ok(())
}

// ----- grep / glob ---------------------------------------------------------------------------

fn grep_args(c: &mut Conv) -> Step {
    c.alias("pattern", &["query", "regex"])?;
    c.alias("path", &["dir_path", "directory", "dir", "file_path", "absolute_path"])?;
    c.alias("glob", &["include", "include_pattern", "file_pattern"])?;
    c.alias("ignore_case", &["-i"])?;
    c.alias("after", &["-A"])?;
    c.alias("before", &["-B"])?;
    c.alias("context", &["-C"])?;
    c.alias("max", &["head_limit"])?;
    if let Some(v) = c.map.remove("case_sensitive") {
        match v.as_bool() {
            Some(false) => {
                let shown = c.pres("ignore_case");
                c.map.entry("ignore_case".to_string()).or_insert(json!(true));
                c.note(format!("`case_sensitive` false read as `{shown}`"));
            }
            Some(true) => c.note("`case_sensitive` true is the default; dropped".into()),
            None => {
                c.map.insert("case_sensitive".into(), v);
            }
        }
    }
    if c.map.remove("-n").is_some() && c.dialect == Dialect::Loom {
        c.note("`-n` is not used here (line numbers are always shown); dropped".into());
    }
    let context_given = ["context", "before", "after"].iter().any(|k| c.map.contains_key(*k));
    if let Some(v) = c.map.remove("output_mode") {
        let mode = match v.as_str() {
            Some("content") => "content",
            Some("files_with_matches" | "files") => "files",
            Some("count") => "count",
            _ => {
                return Err(
                    "`output_mode` must be `content`, `files_with_matches` or `count`. Nothing was executed.".into()
                )
            }
        };
        if c.map.get("mode").and_then(Value::as_str).is_some_and(|have| have != mode) {
            return Err("Both `output_mode` and `mode` were sent with different values. Send only `output_mode`. Nothing was executed.".into());
        }
        c.map.insert("mode".into(), json!(mode));
        if c.dialect == Dialect::Loom {
            c.note("argument `output_mode` read as `mode`".into());
        }
    } else if c.dialect == Dialect::Trained
        && !c.map.contains_key("mode")
        && !c.map.contains_key("files_only")
        && !c.map.get("path").and_then(Value::as_str).is_some_and(|p| p.starts_with("out:"))
    {
        // The presented default is `files_with_matches`.
        if context_given {
            c.map.insert("mode".into(), json!("content"));
            c.note("context lines were asked for without `output_mode`; showing the matching lines (`content`)".into());
        } else {
            c.map.insert("mode".into(), json!("files"));
        }
    }
    Ok(())
}

fn glob_args(c: &mut Conv) -> Step {
    c.alias("path", &["dir_path", "directory", "dir", "target_directory"])?;
    c.alias("pattern", &["glob_pattern"])
}

fn ls_args(c: &mut Conv) -> Step {
    c.alias(
        "path",
        &["relative_workspace_path", "dir_path", "directory", "dir", "target_directory", "file_path", "absolute_path"],
    )?;
    let recursive = c.map.remove("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
    if !c.map.contains_key("pattern") {
        let pattern = if recursive { "**/*" } else { "*" };
        c.map.insert("pattern".into(), json!(pattern));
        c.note(format!("a directory listing was read as `glob` with pattern `{pattern}`"));
    }
    Ok(())
}

fn file_search_args(c: &mut Conv) -> Step {
    let Some(q) = c.map.remove("query") else { return glob_args(c) };
    let Some(text) = q.as_str() else {
        c.map.insert("query".into(), q);
        return Ok(());
    };
    let pattern = format!("**/*{text}*");
    c.note(format!("`query` read as `pattern` `{pattern}`"));
    c.map.insert("pattern".into(), json!(pattern));
    Ok(())
}

// ----- the rest ------------------------------------------------------------------------------

fn web_fetch_args(c: &mut Conv) {
    let Some(prompt) = c.map.remove("prompt") else { return };
    if !c.map.contains_key("url") {
        let url = prompt.as_str().and_then(|p| {
            p.split_whitespace()
                .find(|w| w.starts_with("http://") || w.starts_with("https://"))
                .map(|w| w.trim_end_matches([',', ')', '.', ';', '"', '\'']).to_string())
        });
        if let Some(url) = url {
            c.map.insert("url".into(), Value::String(url));
            c.note(
                "`url` was taken from `prompt`; the page itself is returned, and `prompt` is not otherwise used".into(),
            );
            return;
        }
    }
    c.note("`prompt` is not used here (the page itself is returned); dropped".into());
}

fn plan_args(c: &mut Conv) -> Step {
    c.drop_unused(&["explanation"]);
    let from = ["todos", "plan"].iter().find(|k| c.map.contains_key(**k)).copied();
    let Some(from) = from else { return Ok(()) };
    if c.map.contains_key("steps") {
        return Err(format!("Both `{from}` and `steps` were sent. Send only `steps`. Nothing was executed."));
    }
    let Some(Value::Array(items)) = c.map.remove(from) else {
        return Err(format!("`{from}` must be a list of steps. Nothing was executed."));
    };
    let mut steps = Vec::new();
    let mut active_form = false;
    for item in items {
        let Value::Object(m) = item else {
            steps.push(item);
            continue;
        };
        active_form |= m.contains_key("activeForm");
        let text = ["step", "content", "description", "text", "title"]
            .iter()
            .find_map(|k| m.get(*k).and_then(Value::as_str))
            .map(str::to_string);
        let (status, id) = (m.get("status").cloned(), m.get("id").cloned());
        match text {
            Some(t) if status.is_some() || id.is_some() => {
                let mut o = Map::new();
                o.insert("step".into(), json!(t));
                if let Some(s) = status {
                    o.insert("status".into(), s);
                }
                if let Some(i) = id {
                    o.insert("id".into(), i);
                }
                steps.push(Value::Object(o));
            }
            Some(t) => steps.push(json!(t)),
            None => steps.push(Value::Object(m)),
        }
    }
    c.map.insert("steps".into(), Value::Array(steps));
    c.note(format!("argument `{from}` read as `steps`"));
    if active_form {
        c.note("`activeForm` is not used here; dropped".into());
    }
    Ok(())
}

fn job_args(c: &mut Conv, wait: bool) -> Step {
    c.alias("job", &["bash_id", "shell_id", "job_id", "id"])?;
    if wait {
        if c.map.remove("filter").is_some() {
            return Err("`filter` is not supported on a job's output. Read the output without it, then search it with `out_grep`. Nothing was executed.".into());
        }
        c.map.entry("timeout_s".to_string()).or_insert(json!(0));
    }
    Ok(())
}

fn label_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(m) => ["label", "text", "title", "value"]
            .iter()
            .find_map(|k| m.get(*k).and_then(Value::as_str).map(str::to_string)),
        _ => None,
    }
}

fn ask_args(c: &mut Conv) {
    if let Some(Value::Array(qs)) = c.map.remove("questions") {
        let texts: Vec<String> = qs
            .iter()
            .filter_map(|q| q.get("question").and_then(Value::as_str).or_else(|| q.as_str()).map(str::to_string))
            .collect();
        if let ([text], [q]) = (texts.as_slice(), qs.as_slice()) {
            c.map.insert("question".into(), json!(text));
            let labels: Vec<String> = q
                .get("options")
                .and_then(Value::as_array)
                .map(|o| o.iter().filter_map(label_of).collect())
                .unwrap_or_default();
            if !labels.is_empty() {
                c.map.insert("options".into(), json!(labels));
            }
            c.note("argument `questions` read as `question`".into());
        } else if !texts.is_empty() {
            let numbered: Vec<String> = texts.iter().enumerate().map(|(i, t)| format!("{}. {t}", i + 1)).collect();
            c.map.insert("question".into(), json!(numbered.join("\n")));
            c.note("argument `questions` read as one numbered `question` (options dropped)".into());
        }
    }
    if let Some(v) = c.map.remove("follow_up") {
        let labels: Vec<String> = match &v {
            Value::Array(a) => a.iter().filter_map(label_of).collect(),
            Value::String(s) => vec![s.clone()],
            _ => Vec::new(),
        };
        if labels.is_empty() {
            c.map.insert("follow_up".into(), v);
        } else {
            c.map.entry("options".to_string()).or_insert(json!(labels));
            c.note("argument `follow_up` read as `options`".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[&str] = &[
        "read",
        "write",
        "edit",
        "bash",
        "grep",
        "glob",
        "web_fetch",
        "plan",
        "job_wait",
        "job_kill",
        "agent_spawn",
        "ask_user",
        "finish",
        "out_read",
        "out_grep",
    ];

    fn has(t: &str) -> bool {
        ALL.contains(&t)
    }

    fn run(name: &str, args: Value) -> Adapted {
        run_in(name, args, Dialect::Trained)
    }

    fn run_in(name: &str, args: Value, d: Dialect) -> Adapted {
        match adapt(name, args, d, &has) {
            Adapt::Run(a) => a,
            other => panic!("{name}: expected Run, got {other:?}"),
        }
    }

    fn refuse(name: &str, args: Value) -> String {
        match adapt(name, args, Dialect::Trained, &has) {
            Adapt::Refuse(s) => s,
            other => panic!("{name}: expected Refuse, got {other:?}"),
        }
    }

    fn batch(name: &str, args: Value) -> Vec<Adapted> {
        match adapt(name, args, Dialect::Trained, &has) {
            Adapt::Batch(b) => b,
            other => panic!("{name}: expected Batch, got {other:?}"),
        }
    }

    #[test]
    fn names_map_to_loom_tools() {
        let rows: &[(&str, &str)] = &[
            ("Read", "read"),
            ("read_file", "read"),
            ("view-file", "read"),
            ("open_file", "read"),
            ("cat", "read"),
            ("Write", "write"),
            ("write_file", "write"),
            ("create_file", "write"),
            ("write_to_file", "write"),
            ("Edit", "edit"),
            ("MultiEdit", "edit"),
            ("str_replace", "edit"),
            ("replace", "edit"),
            ("edit_file", "edit"),
            ("Bash", "bash"),
            ("shell", "bash"),
            ("exec_command", "bash"),
            ("execute_bash", "bash"),
            ("run_shell_command", "bash"),
            ("run_terminal_cmd", "bash"),
            ("execute_command", "bash"),
            ("run_command", "bash"),
            ("terminal", "bash"),
            ("exec", "bash"),
            ("sh", "bash"),
            ("Grep", "grep"),
            ("search_file_content", "grep"),
            ("grep_search", "grep"),
            ("search_files", "grep"),
            ("ripgrep", "grep"),
            ("rg", "grep"),
            ("search", "grep"),
            ("Glob", "glob"),
            ("find_files", "glob"),
            ("LS", "glob"),
            ("list_dir", "glob"),
            ("list_directory", "glob"),
            ("list_files", "glob"),
            ("WebFetch", "web_fetch"),
            ("fetch", "web_fetch"),
            ("fetch_url", "web_fetch"),
            ("BashOutput", "job_wait"),
            ("get_job_output", "job_wait"),
            ("KillShell", "job_kill"),
            ("KillBash", "job_kill"),
            ("kill_job", "job_kill"),
            ("Task", "agent_spawn"),
            ("Agent", "agent_spawn"),
            ("subagent", "agent_spawn"),
            ("spawn_agent", "agent_spawn"),
            ("dispatch_agent", "agent_spawn"),
            ("delegate", "agent_spawn"),
            ("attempt_completion", "finish"),
            ("complete_task", "finish"),
            ("task_complete", "finish"),
        ];
        for (name, tool) in rows {
            let args = match *tool {
                "read" | "write" | "edit" => {
                    json!({"file_path": "a.txt", "content": "x", "old_string": "a", "new_string": "b"})
                }
                "bash" => json!({"command": "ls"}),
                "grep" | "glob" => json!({"pattern": "x"}),
                "web_fetch" => json!({"url": "https://example.com"}),
                "job_wait" | "job_kill" => json!({"job": "j1"}),
                "agent_spawn" => json!({"question": "q"}),
                _ => json!({"answer": "done"}),
            };
            match adapt(name, args, Dialect::Trained, &has) {
                Adapt::Run(a) => {
                    assert_eq!(a.tool, *tool, "{name}");
                    let note = format!("tool alias: called `{name}`, ran `{tool}`");
                    assert_eq!(a.notes.first(), Some(&note), "{name}");
                }
                other => panic!("{name}: {other:?}"),
            }
        }
        for name in ["TodoWrite", "write_todos", "update_plan", "todo_write"] {
            assert_eq!(run(name, json!({"todos": []})).tool, "plan", "{name}");
        }
        for name in ["AskUserQuestion", "ask_followup_question", "ask_user_question"] {
            assert_eq!(run(name, json!({"question": "q?"})).tool, "ask_user", "{name}");
        }
        assert_eq!(adapt("think", json!({"thought": "hm"}), Dialect::Trained, &has), Adapt::Noop("Noted.".into()));
        assert_eq!(adapt("no_such_tool", json!({}), Dialect::Trained, &has), Adapt::Unknown);
        assert_eq!(alias_tool("Read"), Some("read"));
        assert_eq!(alias_tool("read"), None);
    }

    #[test]
    fn a_tool_the_role_lacks_is_refused_by_name() {
        let only_bash = |t: &str| t == "bash";
        match adapt("Read", json!({"file_path": "a"}), Dialect::Trained, &only_bash) {
            Adapt::Refuse(s) => assert_eq!(s, "`Read` runs `read`, which this role does not have."),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn presented_and_internal_keys_are_silent_in_both_dialects() {
        let a = run_in(
            "edit",
            json!({"file_path": "a", "old_string": "x", "new_string": "y", "replace_all": true}),
            Dialect::Trained,
        );
        assert_eq!(a.args, json!({"path": "a", "old": "x", "new": "y", "all": true}));
        assert!(a.notes.is_empty(), "{:?}", a.notes);
        for d in [Dialect::Trained, Dialect::Loom] {
            let a = run_in("edit", json!({"path": "a", "old": "x", "new": "y", "all": true}), d);
            assert_eq!(a.args, json!({"path": "a", "old": "x", "new": "y", "all": true}), "{d:?}");
            assert!(a.notes.is_empty(), "{d:?} {:?}", a.notes);
        }
        let a = run("read", json!({"file_path": "a.rs", "offset": 10, "limit": 5}));
        assert_eq!(a.args, json!({"path": "a.rs", "start": 10, "end": 14}));
        assert!(a.notes.is_empty(), "{:?}", a.notes);
        let a =
            run("bash", json!({"command": "ls", "timeout": 30000, "run_in_background": true, "description": "list"}));
        assert_eq!(a.args, json!({"command": "ls", "timeout_s": 30, "background": true, "description": "list"}));
        assert!(a.notes.is_empty(), "{:?}", a.notes);
    }

    #[test]
    fn notes_use_the_presented_names_of_the_dialect() {
        let a = run("edit", json!({"file_path": "a", "old_str": "x", "new_str": "y"}));
        assert_eq!(a.args, json!({"path": "a", "old": "x", "new": "y"}));
        assert_eq!(a.notes, vec!["argument `old_str` read as `old_string`", "argument `new_str` read as `new_string`"]);
        let a = run_in("edit", json!({"path": "a", "old_str": "x", "new_str": "y"}), Dialect::Loom);
        assert_eq!(a.notes, vec!["argument `old_str` read as `old`", "argument `new_str` read as `new`"]);
    }

    #[test]
    fn conflicting_spellings_are_refused() {
        let s = refuse("edit", json!({"file_path": "a", "old_string": "x", "old_str": "z", "new_string": "y"}));
        assert!(s.contains("Nothing was executed"), "{s}");
        assert!(refuse("edit_file", json!({"target_file": "a", "code_edit": "// ... existing"})).contains("code_edit"));
        assert!(refuse("BashOutput", json!({"bash_id": "j1", "filter": "x"})).contains("filter"));
    }

    #[test]
    fn timeout_under_1000_is_seconds() {
        let a = run("Bash", json!({"command": "ls", "timeout": 600}));
        assert_eq!(a.args["timeout_s"], json!(600));
        let note = "`timeout` 600 read as 600 seconds (values under 1000 are seconds)";
        assert!(a.notes.iter().any(|n| n == note), "{:?}", a.notes);
        let a = run("Bash", json!({"command": "ls", "timeout": 600000}));
        assert_eq!(a.args["timeout_s"], json!(600));
        assert!(!a.notes.iter().any(|n| n.contains("timeout")), "{:?}", a.notes);
    }

    #[test]
    fn read_offset_and_limit_become_start_and_end() {
        let a = run("Read", json!({"file_path": "a", "offset": 0, "limit": 3}));
        assert_eq!(a.args, json!({"path": "a", "start": 1, "end": 3}));
        assert!(a.notes.iter().any(|n| n == "`offset` 0 read as line 1"), "{:?}", a.notes);
        let a = run("Read", json!({"file_path": "a", "offset": 7}));
        assert_eq!(a.args, json!({"path": "a", "start": 7}));
        let a = run("Read", json!({"file_path": "out:ab12"}));
        assert_eq!(a.tool, "out_read");
        let a = run("Grep", json!({"pattern": "x", "path": "out:ab12"}));
        assert_eq!(a.tool, "out_grep");
    }

    #[test]
    fn grep_arguments_are_converted() {
        let a = run(
            "grep",
            json!({"pattern": "x", "-i": true, "-A": 2, "-B": 1, "type": "rs", "head_limit": 5, "output_mode": "content", "-n": true}),
        );
        assert_eq!(
            a.args,
            json!({"pattern": "x", "ignore_case": true, "after": 2, "before": 1, "type": "rs", "max": 5, "mode": "content"})
        );
        assert!(a.notes.is_empty(), "{:?}", a.notes);
        let a = run("grep", json!({"pattern": "x"}));
        assert_eq!(a.args["mode"], json!("files"));
        let a = run("grep", json!({"pattern": "x", "-C": 3}));
        assert_eq!(a.args["mode"], json!("content"));
        assert_eq!(a.args["context"], json!(3));
        let a = run("grep", json!({"pattern": "x", "output_mode": "count"}));
        assert_eq!(a.args["mode"], json!("count"));
        let a = run_in("grep", json!({"pattern": "x"}), Dialect::Loom);
        assert!(a.args.get("mode").is_none());
    }

    #[test]
    fn multi_edit_and_replacement_counts() {
        let a = run(
            "MultiEdit",
            json!({"file_path": "a", "edits": [{"old_string": "a", "new_string": "b"}, {"old_string": "c", "new_string": "d", "replace_all": true}]}),
        );
        assert_eq!(a.tool, "edit");
        assert_eq!(
            a.args,
            json!({"path": "a", "edits": [{"old": "a", "new": "b"}, {"old": "c", "new": "d", "all": true}]})
        );
        let a =
            run("replace", json!({"file_path": "a", "old_string": "a", "new_string": "b", "expected_replacements": 3}));
        assert_eq!(a.args["all"], json!(true));
    }

    #[test]
    fn codex_argv_forms_become_a_command_line() {
        let a = run("shell", json!({"command": ["bash", "-lc", "cargo test -p x"], "timeout_ms": 5000}));
        assert_eq!(a.args["command"], json!("cargo test -p x"));
        assert_eq!(a.args["timeout_s"], json!(5));
        let a = run("shell", json!({"command": ["sh", "-c", "echo hi"]}));
        assert_eq!(a.args["command"], json!("echo hi"));
        let a = run("shell", json!({"command": ["ls", "-la", "my dir"]}));
        assert_eq!(a.args["command"], json!("ls -la 'my dir'"));
    }

    #[test]
    fn apply_patch_forms() {
        let one = "*** Begin Patch\n*** Update File: a.txt\n@@\n-old\n+new\n*** End Patch";
        let a = run("apply_patch", json!({"input": one}));
        assert_eq!(a.tool, "edit");
        assert_eq!(a.args["path"], json!("a.txt"));
        assert!(a.args["patch"].as_str().unwrap().contains("+new"));

        let add = "*** Begin Patch\n*** Add File: n.txt\n+line1\n+line2\n*** End Patch";
        let a = run("apply_patch", json!({"input": add}));
        assert_eq!(a.tool, "write");
        assert_eq!(a.args, json!({"path": "n.txt", "content": "line1\nline2\n"}));

        let two = "*** Begin Patch\n*** Update File: a.txt\n@@\n-x\n+y\n*** Add File: b.txt\n+z\n*** End Patch";
        let b = batch("apply_patch", Value::String(two.to_string()));
        assert_eq!(b.iter().map(|c| c.tool.as_str()).collect::<Vec<_>>(), ["edit", "write"]);

        let del = "*** Begin Patch\n*** Delete File: a.txt\n*** End Patch";
        assert!(refuse("apply_patch", json!({"input": del})).contains("Delete"));
        assert_eq!(run("apply_patch", Value::String(one.to_string())).tool, "edit");
    }

    #[test]
    fn cline_search_replace_blocks_become_edits() {
        let diff =
            "<<<<<<< SEARCH\nfoo\n=======\nbar\n>>>>>>> REPLACE\n<<<<<<< SEARCH\na\nb\n=======\nc\n>>>>>>> REPLACE";
        let a = run("replace_in_file", json!({"path": "f.rs", "diff": diff}));
        assert_eq!(a.tool, "edit");
        assert_eq!(
            a.args,
            json!({"path": "f.rs", "edits": [{"old": "foo", "new": "bar"}, {"old": "a\nb", "new": "c"}]})
        );
        let diff = "------- SEARCH\nfoo\n=======\nbar\n+++++++ REPLACE";
        let a = run("replace_in_file", json!({"path": "f.rs", "diff": diff}));
        assert_eq!(a.args, json!({"path": "f.rs", "edits": [{"old": "foo", "new": "bar"}]}));
        let bad = refuse("replace_in_file", json!({"path": "f.rs", "diff": "<<<<<<< SEARCH\nfoo\n"}));
        assert!(bad.contains("Nothing was executed"), "{bad}");
    }

    #[test]
    fn str_replace_editor_dispatches_on_command() {
        let a = run("str_replace_editor", json!({"command": "view", "path": "a.rs", "view_range": [2, 4]}));
        assert_eq!((a.tool.as_str(), &a.args), ("read", &json!({"path": "a.rs", "start": 2, "end": 4})));
        let a = run("str_replace_based_edit_tool", json!({"command": "view", "path": "src/"}));
        assert_eq!(a.tool, "glob");
        let a = run("text_editor", json!({"command": "create", "path": "n.rs", "file_text": "x"}));
        assert_eq!((a.tool.as_str(), &a.args), ("write", &json!({"path": "n.rs", "content": "x"})));
        let a =
            run("str_replace_editor", json!({"command": "str_replace", "path": "a", "old_str": "x", "new_str": "y"}));
        assert_eq!((a.tool.as_str(), &a.args), ("edit", &json!({"path": "a", "old": "x", "new": "y"})));
        let a = run("str_replace_editor", json!({"command": "str_replace", "path": "a", "old_str": "x"}));
        assert_eq!(a.args["new"], json!(""));
        let a = run("str_replace_editor", json!({"command": "insert", "path": "a", "insert_line": 1, "new_str": "hi"}));
        assert_eq!(a.tool, "edit");
        assert!(a.args["patch"].is_string());
        assert!(refuse("str_replace_editor", json!({"command": "undo_edit", "path": "a"})).contains("no undo"));
    }

    #[test]
    fn todo_lists_become_steps_with_statuses() {
        let a = run(
            "TodoWrite",
            json!({"todos": [
                {"content": "one", "status": "completed", "activeForm": "Doing one"},
                {"content": "two", "status": "in_progress", "activeForm": "Doing two"},
                {"content": "three", "status": "pending", "activeForm": "Doing three"}]}),
        );
        assert_eq!(a.tool, "plan");
        let steps = a.args["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0]["step"], json!("one"));
        assert_eq!(steps[1]["status"], json!("in_progress"));
        let a = run(
            "update_plan",
            json!({"explanation": "why", "plan": [{"step": "a", "status": "completed"}, {"step": "b", "status": "pending"}]}),
        );
        assert_eq!(a.tool, "plan");
        let steps = a.args["steps"].as_array().unwrap();
        assert_eq!((steps[0]["step"].clone(), steps[0]["status"].clone()), (json!("a"), json!("completed")));
    }

    #[test]
    fn ls_fetch_jobs_and_agents() {
        let a = run("LS", json!({"path": "/w/src"}));
        assert_eq!((a.tool.as_str(), &a.args), ("glob", &json!({"path": "/w/src", "pattern": "*"})));
        let a = run("BashOutput", json!({"bash_id": "j3"}));
        assert_eq!((a.tool.as_str(), a.args["job"].clone()), ("job_wait", json!("j3")));
        let a = run("KillShell", json!({"shell_id": "j3"}));
        assert_eq!((a.tool.as_str(), &a.args), ("job_kill", &json!({"job": "j3"})));
        let a = run("WebFetch", json!({"url": "https://e.com", "prompt": "summarize"}));
        assert_eq!(a.tool, "web_fetch");
        let a = run("Task", json!({"description": "d", "prompt": "find it", "subagent_type": "x"}));
        assert_eq!(a.tool, "agent_spawn");
        assert_eq!(a.args["question"], json!("find it"));
    }

    #[test]
    fn present_is_stable_and_leaves_other_tools_alone() {
        let spec = |name: &str| ToolSpec {
            name: name.to_string(),
            description: format!("Use `path` for {name}."),
            parameters: json!({"type": "object", "properties": {"path": {"type": "string", "description": "p"}}, "required": ["path"], "additionalProperties": false}),
            class: loom_core::event::ToolClass::Read,
        };
        let plan = spec("plan");
        assert_eq!(present(&plan, Dialect::Trained), plan);
        for name in ["read", "write", "edit", "bash", "grep", "glob"] {
            let s = spec(name);
            assert_eq!(present(&s, Dialect::Loom), s);
            let p = present(&s, Dialect::Trained);
            assert_eq!(p.name, name);
            assert_eq!(p, present(&s, Dialect::Trained));
            assert_eq!(p.parameters["additionalProperties"], json!(false));
        }
        assert_eq!(presented_arg("read", "path", Dialect::Trained), "file_path");
        assert_eq!(presented_arg("read", "path", Dialect::Loom), "path");
        assert_eq!(presented_arg("bash", "timeout_s", Dialect::Trained), "timeout");
        assert_eq!(presented_arg("grep", "ignore_case", Dialect::Trained), "-i");
        assert_eq!(presented_arg("plan", "steps", Dialect::Trained), "steps");
    }
}
