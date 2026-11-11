//! Packs: named sets of roles. A role is a prompt, a tool list and the rules for ending.
//!
//! CONTRACT (bodies are placeholders for the implementer; signatures and types are fixed).
//!
//! ## On disk
//! A pack is a directory holding `pack.toml`:
//! ```toml
//! name = "core"                 # required; [a-z0-9-]+
//! description = "…"             # optional
//! default_role = "lead"         # required; must name a role
//! preamble = "harness.md"       # optional file; when absent the built-in preamble is used
//!
//! [roles.lead]
//! description = "…"             # optional
//! prompt = "roles/lead.md"      # required file, relative to the pack directory
//! termination = "explicit"      # "explicit" | "free"; default "explicit"
//! tools = ["bash", "read"]      # required, non-empty, no duplicates; order is the request order
//! may_spawn = ["worker"]        # optional; each must name a role of this pack
//! verify_finish = true          # optional, default false
//! read_only = false             # optional, default false
//! ```
//! Unknown keys are errors. File paths must stay inside the pack directory (no absolute paths, no
//! `..` components). Prompt and preamble files must be valid UTF-8 and are used with trailing
//! whitespace trimmed.
//!
//! ## Loading
//! `Packs::load(dir)`: starts with the built-in `core` pack (embedded in the binary from
//! `packs/core` of this repository via `include_str!`), then loads every sub-directory of `dir`
//! that contains a `pack.toml`, in name order. A directory pack named `core` replaces the built-in
//! one. A missing `dir` is not an error. Any invalid pack is an error naming the pack directory,
//! the key or file, and what is wrong — the daemon refuses to start with a broken pack rather than
//! run without it. `Packs::builtin()` is the built-in pack alone.
//!
//! `Packs::role(pack, role)`: `pack` defaults to `core`; `role` defaults to the pack's
//! `default_role`. An unknown name is an error listing the names that exist.
//!
//! `Packs::check_tools(known)`: every tool name of every role must be in `known`; the error names
//! the pack, role, the unknown tool and the nearest known name.
//!
//! ## The system prompt
//! `system_prompt(role, preamble, env)` is, joined by one blank line:
//! 1. the preamble;
//! 2. the role prompt;
//! 3. `# Environment` followed by the lines: `Workspace: {workspace}`, `Platform: {platform}`,
//!    `Sandbox: {sandbox}`, `Network: {network}` — and nothing that changes from one request to the
//!    next (no date, no time, no counters), because this text is the head of the cached prefix.
//!
//! Tests required: the built-in pack loads, has the roles `lead`, `worker`, `verifier`, `chat`, and
//! every role's prompt is non-empty; a directory pack loads and can replace `core`; each validation
//! failure (missing name, bad name, unknown key, missing prompt file, path escaping the pack,
//! empty/duplicate tools, `default_role`/`may_spawn` naming a missing role, bad termination);
//! defaults; `role` lookup defaults and errors; `check_tools`; `system_prompt` layout and that it is
//! identical for identical inputs.

use loom_core::event::Termination;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleDef {
    pub pack: String,
    pub name: String,
    pub description: String,
    /// The role prompt text (file content, trimmed).
    pub prompt: String,
    pub termination: Termination,
    /// Tool names in request order.
    pub tools: Vec<String>,
    /// Roles this role may start as children.
    pub may_spawn: Vec<String>,
    /// An accepted `finish` by this role is first attacked by an independent verifier.
    pub verify_finish: bool,
    /// The sandbox denies this role every write outside its session temp directory.
    pub read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pack {
    pub name: String,
    pub description: String,
    pub default_role: String,
    /// The shared text that starts every system prompt of this pack.
    pub preamble: String,
    pub roles: BTreeMap<String, RoleDef>,
}

#[derive(Clone, Debug, Default)]
pub struct Packs {
    packs: BTreeMap<String, Pack>,
}

/// What `system_prompt` states about where the session runs. All fixed for the session's life.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptEnv {
    pub workspace: String,
    pub platform: String,
    /// One sentence from `Sandbox::describe`.
    pub sandbox: String,
    /// One sentence describing the network policy.
    pub network: String,
}

impl Packs {
    pub fn builtin() -> Result<Packs, String> {
        todo!("implement per module contract")
    }

    pub fn load(dir: &Path) -> Result<Packs, String> {
        let _ = dir;
        todo!("implement per module contract")
    }

    pub fn names(&self) -> Vec<String> {
        self.packs.keys().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&Pack> {
        self.packs.get(name)
    }

    pub fn role(&self, pack: Option<&str>, role: Option<&str>) -> Result<&RoleDef, String> {
        let _ = (pack, role);
        todo!("implement per module contract")
    }

    pub fn check_tools(&self, known: &[String]) -> Result<(), String> {
        let _ = known;
        todo!("implement per module contract")
    }
}

/// Parse one pack from its directory.
pub fn load_pack(dir: &Path) -> Result<Pack, String> {
    let _ = dir;
    todo!("implement per module contract")
}

pub fn system_prompt(role: &RoleDef, preamble: &str, env: &PromptEnv) -> String {
    let _ = (role, preamble, env);
    todo!("implement per module contract")
}
