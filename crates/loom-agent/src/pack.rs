//! Packs: named sets of roles. A role is a prompt, a tool list and the rules for ending.
//!
//! CONTRACT.
//!
//! ## On disk
//! A pack is a directory holding `pack.toml`:
//! ```toml
//! name = "core"                 # required; [a-z0-9-]+
//! description = "…"             # optional
//! default_role = "lead"         # required; must name a role
//! preamble = "harness.md"       # optional file; when absent the built-in preamble is used
//! command_guard = "off"         # "off" | "offensive" command preflight policy
//! target_concurrency = 2        # positive per-target tool concurrency
//! requires_restricted_network = false  # optional; true = refuse to start sessions while the network mode is open
//! solvable = false              # optional; true = the operator built this mission to be solvable (see below)
//!
//! [roles.lead]
//! description = "…"             # optional
//! prompt = "roles/lead.md"      # required file, relative to the pack directory
//! termination = "explicit"      # "explicit" | "free"; default "explicit"
//! tools = ["bash", "read"]      # required, non-empty, no duplicates; order is the request order
//! may_spawn = ["worker"]        # optional; each must name a role of this pack
//! verify_finish = true          # optional, default false
//! require_oracle = false        # optional, default false; operator-pinned mechanical finish gate
//! requires_credential = false   # optional explicit asset/credential dispatch gate
//! max_steps = 35                # optional hard child epoch slice; zero is rejected
//! verifier = "verifier"         # optional; the role that attacks this role's finish (see below)
//! read_only = false             # optional, default false
//! model = "fast"                 # optional named config profile; absent = inherit
//! escalation_model = "strong"    # optional profile used after a failed/budget-exhausted child
//! alloy_models = ["a", "b"]      # optional fresh-child profile rotation
//! max_exec_calls = 6             # optional admitted Exec starts per assignment/session, 0 denies all
//! require_distinct_verifier_profile = false # require a different named profile, not a family claim
//! flag_regex = "FLAG\\{[^}]+\\}" # optional candidate alert; never verifies success
//! ```
//! `verifier` defaults to the pack's role named `verifier` when it has one. A role with
//! `verify_finish = true`, `require_oracle = true`, or an explicit `verifier` whose verifier is not a role of the same pack that is
//! `read_only` and has the `verdict` tool and `out_read` or `out_grep` is a load error. (A verdict must
//! name evidence the verifier opened, and those two tools are how it opens another session's output.)
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
//! When the pack sets `solvable = true`, `texts::SOLVABLE_PRIOR` is inserted as its own part between the
//! role prompt and `# Environment`. It is a fixed text, so it stays inside the cached head. A pack without
//! the key gets exactly the three parts above, byte for byte. `solvable` is read from `RoleDef::solvable`,
//! which the loader copies from the pack onto every role (so tools and the prompt need no pack lookup); it
//! also makes `conclude` refuse `status: "unreachable"` (see `rtools/terminal.rs`).
//!
//! Tests required: the built-in pack loads, has the roles `lead`, `worker`, `verifier`, `chat`, and
//! every role's prompt is non-empty; a directory pack loads and can replace `core`; each validation
//! failure (missing name, bad name, unknown key, missing prompt file, path escaping the pack,
//! empty/duplicate tools, `default_role`/`may_spawn` naming a missing role, bad termination);
//! defaults; `role` lookup defaults and errors; `check_tools`; `system_prompt` layout and that it is
//! identical for identical inputs; the shipped `packs/vr/workspace/AGENTS.md` (a file the loader never
//! reads) names only tools that a role of `vr` has.

use crate::texts;
use loom_core::event::Termination;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Component, Path};

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
    pub require_oracle: bool,
    /// Dispatch requires explicit evidence-linked asset and credential IDs from this mission.
    pub requires_credential: bool,
    /// Hard child epoch slice; zero is rejected at pack load.
    pub max_steps: Option<u32>,
    /// The role of this pack that attacks this role's finish and answers its `verify` tool; resolved at
    /// load (`verifier` key, else the pack's role named `verifier`). Always `Some` when `verify_finish`.
    pub verifier: Option<String>,
    /// The sandbox denies this role every write outside its session temp directory.
    pub read_only: bool,
    /// Named model profiles. No in-session model switching is performed.
    pub model: Option<String>,
    pub escalation_model: Option<String>,
    pub alloy_models: Vec<String>,
    pub max_exec_calls: Option<u32>,
    pub require_distinct_verifier_profile: bool,
    /// Candidate discovery only; a match is not a verdict.
    pub flag_regex: Option<String>,
    /// Copied from the pack's `solvable` key at load: the operator built this mission to be solved.
    pub solvable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pack {
    pub name: String,
    pub description: String,
    pub default_role: String,
    /// The shared text that starts every system prompt of this pack.
    pub preamble: String,
    /// The pack's text says the network is restricted: sessions of it are refused while the
    /// daemon's network mode is `open`.
    pub requires_restricted_network: bool,
    /// The operator built missions of this pack to be solvable: roles are told so, and `conclude`
    /// refuses `unreachable`.
    pub solvable: bool,
    pub command_guard: bool,
    pub target_concurrency: u32,
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

const CORE_TOML: &str = include_str!("../../../packs/core/pack.toml");
const CORE_PREAMBLE: &str = include_str!("../../../packs/core/harness.md");
const CORE_FILES: [(&str, &str); 4] = [
    ("roles/lead.md", include_str!("../../../packs/core/roles/lead.md")),
    ("roles/worker.md", include_str!("../../../packs/core/roles/worker.md")),
    ("roles/verifier.md", include_str!("../../../packs/core/roles/verifier.md")),
    ("roles/chat.md", include_str!("../../../packs/core/roles/chat.md")),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPack {
    name: Option<String>,
    description: Option<String>,
    default_role: Option<String>,
    preamble: Option<String>,
    #[serde(default)]
    requires_restricted_network: bool,
    #[serde(default)]
    solvable: bool,
    command_guard: Option<String>,
    target_concurrency: Option<u32>,
    #[serde(default)]
    roles: BTreeMap<String, RawRole>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRole {
    description: Option<String>,
    prompt: Option<String>,
    termination: Option<String>,
    tools: Option<Vec<String>>,
    #[serde(default)]
    may_spawn: Vec<String>,
    #[serde(default)]
    verify_finish: bool,
    #[serde(default)]
    require_oracle: bool,
    #[serde(default)]
    requires_credential: bool,
    max_steps: Option<u32>,
    verifier: Option<String>,
    #[serde(default)]
    read_only: bool,
    model: Option<String>,
    escalation_model: Option<String>,
    #[serde(default)]
    alloy_models: Vec<String>,
    max_exec_calls: Option<u32>,
    #[serde(default)]
    require_distinct_verifier_profile: bool,
    flag_regex: Option<String>,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_role_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// A path that stays inside the pack directory by construction.
fn check_rel(label: &str, key: &str, rel: &str) -> Result<(), String> {
    let p = Path::new(rel);
    let ok = !rel.is_empty()
        && p.components().all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        && p.components().any(|c| matches!(c, Component::Normal(_)));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "pack {label}: `{key}` = \"{rel}\" must be a relative path inside the pack directory (no absolute paths, no `..`)"
        ))
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev.get(j).copied().unwrap_or(0) + usize::from(ca != *cb);
            let del = prev.get(j + 1).copied().unwrap_or(0) + 1;
            let ins = cur.get(j).copied().unwrap_or(0) + 1;
            cur.push(sub.min(del).min(ins));
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or(0)
}

/// What a verifier role must be, as the load errors put it.
const VERIFIER_NEEDS: &str =
    "a role with `read_only = true` whose `tools` include `verdict` and `out_read` or `out_grep`";

/// The verifier role of `r`: its `verifier` key, else the pack's role named `verifier`. A role that
/// needs one (`verify_finish`, or an explicit key) must get a read-only role that can give a verdict
/// and open the stored outputs it is pointed at.
fn resolve_verifier(
    at: &str,
    is_verifier: bool,
    r: &RawRole,
    roles: &BTreeMap<String, RawRole>,
    role_list: &str,
) -> Result<Option<String>, String> {
    // The role named `verifier` is not its own default verifier.
    let wanted =
        r.verifier.clone().or_else(|| (roles.contains_key("verifier") && !is_verifier).then(|| "verifier".to_string()));
    let usable = |name: &str| {
        roles.get(name).is_some_and(|v| {
            let has = |tool: &str| v.tools.iter().flatten().any(|t| t == tool);
            v.read_only && has("verdict") && (has("out_read") || has("out_grep"))
        })
    };
    if !(r.verify_finish || r.require_oracle || r.verifier.is_some()) {
        return Ok(wanted.filter(|n| usable(n)));
    }
    let Some(name) = wanted else {
        let gate = if r.require_oracle && !r.verify_finish { "require_oracle" } else { "verify_finish" };
        return Err(format!(
            "{at}: `{gate}` = true needs a verifier role. Add a role named \"verifier\" to this pack, or set `verifier = \"<role>\"`; it must be {VERIFIER_NEEDS} (roles: {role_list})"
        ));
    };
    if !roles.contains_key(&name) {
        return Err(format!(
            "{at}: `verifier` = \"{name}\" is not a role of this pack (roles: {role_list}). Name {VERIFIER_NEEDS}"
        ));
    }
    if !usable(&name) {
        return Err(format!(
            "{at}: the verifier role \"{name}\" must be {VERIFIER_NEEDS}: it gives the verdict, and has to open the evidence it is pointed at without being able to change the workspace. Fix that role, or point `verifier` at another role"
        ));
    }
    Ok(Some(name))
}

/// Validate `pack.toml` text and assemble a pack. `read` returns the text of a file given its
/// pack-relative path; `label` names the pack in errors.
fn parse_pack(
    label: &str,
    toml_text: &str,
    builtin_preamble: &str,
    read: &dyn Fn(&str) -> Result<String, String>,
) -> Result<Pack, String> {
    let raw: RawPack = toml::from_str(toml_text).map_err(|e| format!("pack {label}: pack.toml is invalid: {e}"))?;
    let name = raw.name.ok_or_else(|| format!("pack {label}: pack.toml is missing the required key `name`"))?;
    if !valid_name(&name) {
        return Err(format!("pack {label}: `name` = \"{name}\" is not valid; use only a-z, 0-9 and `-`"));
    }
    let default_role = raw
        .default_role
        .ok_or_else(|| format!("pack {label}: pack.toml is missing the required key `default_role`"))?;
    if raw.roles.is_empty() {
        return Err(format!("pack {label}: pack.toml defines no `[roles.*]` tables"));
    }
    let role_list = raw.roles.keys().cloned().collect::<Vec<_>>().join(", ");
    if !raw.roles.contains_key(&default_role) {
        return Err(format!(
            "pack {label}: `default_role` = \"{default_role}\" does not name a role of this pack (roles: {role_list})"
        ));
    }
    let preamble = match raw.preamble {
        None => builtin_preamble.trim_end().to_string(),
        Some(rel) => {
            check_rel(label, "preamble", &rel)?;
            let text = read(&rel)?;
            let text = text.trim_end();
            if text.is_empty() {
                return Err(format!("pack {label}: preamble file {rel} is empty"));
            }
            text.to_string()
        }
    };
    let mut roles = BTreeMap::new();
    for (rname, r) in &raw.roles {
        if !valid_role_name(rname) {
            return Err(format!("pack {label}: role name \"{rname}\" is not valid; use only a-z, 0-9, `-` and `_`"));
        }
        let at = format!("pack {label}: roles.{rname}");
        let prompt_rel = r.prompt.as_deref().ok_or_else(|| format!("{at} is missing the required key `prompt`"))?;
        check_rel(label, &format!("roles.{rname}.prompt"), prompt_rel)?;
        let prompt = read(prompt_rel)?.trim_end().to_string();
        if prompt.is_empty() {
            return Err(format!("{at}: prompt file {prompt_rel} is empty"));
        }
        let termination = match r.termination.as_deref() {
            None | Some("explicit") => Termination::Explicit,
            Some("free") => Termination::Free,
            Some(other) => {
                return Err(format!("{at}: `termination` = \"{other}\" is not valid; use \"explicit\" or \"free\""))
            }
        };
        let tools = r.tools.clone().ok_or_else(|| format!("{at} is missing the required key `tools`"))?;
        if tools.is_empty() {
            return Err(format!("{at}: `tools` is empty; a role needs at least one tool"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for t in &tools {
            if t.is_empty() {
                return Err(format!("{at}: `tools` contains an empty name"));
            }
            if !seen.insert(t.as_str()) {
                return Err(format!("{at}: `tools` lists \"{t}\" more than once"));
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for m in &r.may_spawn {
            if !raw.roles.contains_key(m) {
                return Err(format!(
                    "{at}: `may_spawn` names \"{m}\", which is not a role of this pack (roles: {role_list})"
                ));
            }
            if !seen.insert(m.as_str()) {
                return Err(format!("{at}: `may_spawn` lists \"{m}\" more than once"));
            }
        }
        for profile in r.model.iter().chain(r.escalation_model.iter()).chain(r.alloy_models.iter()) {
            if profile.trim().is_empty() {
                return Err(format!("{at}: model profiles must be non-empty names from [models] in the config"));
            }
        }
        if let Some(pattern) = &r.flag_regex {
            regex::RegexBuilder::new(pattern)
                .size_limit(1_000_000)
                .build()
                .map_err(|e| format!("{at}: `flag_regex` is invalid: {e}"))?;
        }
        if r.max_steps == Some(0) {
            return Err(format!("{at}: max_steps must be at least one; omit it to inherit the dispatch budget"));
        }
        let verifier = resolve_verifier(&at, rname == "verifier", r, &raw.roles, &role_list)?;
        roles.insert(
            rname.clone(),
            RoleDef {
                pack: name.clone(),
                name: rname.clone(),
                description: r.description.clone().unwrap_or_default(),
                prompt,
                termination,
                tools,
                may_spawn: r.may_spawn.clone(),
                verify_finish: r.verify_finish,
                require_oracle: r.require_oracle,
                requires_credential: r.requires_credential,
                max_steps: r.max_steps,
                verifier,
                read_only: r.read_only,
                model: r.model.clone(),
                escalation_model: r.escalation_model.clone(),
                alloy_models: r.alloy_models.clone(),
                max_exec_calls: r.max_exec_calls,
                require_distinct_verifier_profile: r.require_distinct_verifier_profile,
                flag_regex: r.flag_regex.clone(),
                solvable: raw.solvable,
            },
        );
    }
    let command_guard = match raw.command_guard.as_deref().unwrap_or("off") {
        "off" => false,
        "offensive" => true,
        other => return Err(format!("pack {label}: `command_guard` = \"{other}\" is invalid; use off or offensive")),
    };
    let target_concurrency = raw.target_concurrency.unwrap_or(2);
    if target_concurrency == 0 {
        return Err(format!("pack {label}: `target_concurrency` must be at least 1"));
    }
    Ok(Pack {
        name,
        description: raw.description.unwrap_or_default(),
        default_role,
        preamble,
        requires_restricted_network: raw.requires_restricted_network,
        solvable: raw.solvable,
        command_guard,
        target_concurrency,
        roles,
    })
}

fn builtin_pack() -> Result<Pack, String> {
    let read = |rel: &str| -> Result<String, String> {
        let rel = rel.strip_prefix("./").unwrap_or(rel);
        CORE_FILES
            .iter()
            .find(|(p, _)| *p == rel)
            .map(|(_, t)| (*t).to_string())
            .ok_or_else(|| format!("pack <built-in core>: file {rel} is not embedded in the binary"))
    };
    parse_pack("<built-in core>", CORE_TOML, CORE_PREAMBLE, &read)
}

impl Packs {
    pub fn builtin() -> Result<Packs, String> {
        let core = builtin_pack()?;
        let mut packs = BTreeMap::new();
        packs.insert(core.name.clone(), core);
        Ok(Packs { packs })
    }

    pub fn load(dir: &Path) -> Result<Packs, String> {
        let mut out = Packs::builtin()?;
        if !dir.exists() {
            return Ok(out);
        }
        let rd =
            std::fs::read_dir(dir).map_err(|e| format!("pack directory {}: cannot be read: {e}", dir.display()))?;
        let mut dirs = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| format!("pack directory {}: cannot be listed: {e}", dir.display()))?;
            let path = entry.path();
            if path.is_dir() && path.join("pack.toml").is_file() {
                dirs.push(path);
            }
        }
        dirs.sort();
        let mut loaded: BTreeMap<String, std::path::PathBuf> = BTreeMap::new();
        for path in dirs {
            let pack = load_pack(&path)?;
            if let Some(first) = loaded.get(&pack.name) {
                return Err(format!(
                    "pack {}: name \"{}\" is already used by the pack in {}; names must be unique",
                    path.display(),
                    pack.name,
                    first.display()
                ));
            }
            loaded.insert(pack.name.clone(), path);
            out.packs.insert(pack.name.clone(), pack);
        }
        Ok(out)
    }

    pub fn names(&self) -> Vec<String> {
        self.packs.keys().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&Pack> {
        self.packs.get(name)
    }

    pub fn role(&self, pack: Option<&str>, role: Option<&str>) -> Result<&RoleDef, String> {
        let pname = pack.unwrap_or("core");
        let p = self
            .packs
            .get(pname)
            .ok_or_else(|| format!("unknown pack \"{pname}\"; packs available: {}", self.names().join(", ")))?;
        let rname = role.unwrap_or(&p.default_role);
        p.roles.get(rname).ok_or_else(|| {
            format!(
                "pack \"{pname}\" has no role \"{rname}\"; roles available: {}",
                p.roles.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })
    }

    /// Resolve every configured role profile at daemon start; pack keys never name model ids.
    pub fn check_profiles(&self, models: &BTreeMap<String, loom_core::config::ModelProfile>) -> Result<(), String> {
        for pack in self.packs.values() {
            for role in pack.roles.values() {
                for name in role.model.iter().chain(role.escalation_model.iter()).chain(role.alloy_models.iter()) {
                    if !models.contains_key(name) {
                        return Err(format!("pack {} role {}: model profile \"{}\" is not configured; add [models.{}] or change the role", pack.name, role.name, name, name));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn check_tools(&self, known: &[String]) -> Result<(), String> {
        for pack in self.packs.values() {
            for role in pack.roles.values() {
                for tool in &role.tools {
                    if known.iter().any(|k| k == tool) {
                        continue;
                    }
                    let near = known
                        .iter()
                        .min_by_key(|k| levenshtein(tool, k))
                        .map(|k| format!("; the nearest known tool is \"{k}\""))
                        .unwrap_or_else(|| "; no tools are registered".to_string());
                    return Err(format!(
                        "pack \"{}\", role \"{}\": unknown tool \"{tool}\"{near}",
                        pack.name, role.name
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Parse one pack from its directory.
pub fn load_pack(dir: &Path) -> Result<Pack, String> {
    let label = dir.display().to_string();
    let toml_path = dir.join("pack.toml");
    let text = std::fs::read_to_string(&toml_path)
        .map_err(|e| format!("pack {label}: pack.toml cannot be read as UTF-8 text: {e}"))?;
    let root = std::fs::canonicalize(dir).map_err(|e| format!("pack {label}: directory cannot be resolved: {e}"))?;
    let read = |rel: &str| -> Result<String, String> {
        let path = dir.join(rel);
        // Symlinks must not lead out of the pack directory.
        let real = std::fs::canonicalize(&path).map_err(|e| format!("pack {label}: file {rel} cannot be read: {e}"))?;
        if !real.starts_with(&root) {
            return Err(format!("pack {label}: file {rel} resolves outside the pack directory"));
        }
        std::fs::read_to_string(&real)
            .map_err(|e| format!("pack {label}: file {rel} cannot be read as UTF-8 text: {e}"))
    };
    parse_pack(&label, &text, CORE_PREAMBLE, &read)
}

pub fn system_prompt(role: &RoleDef, preamble: &str, env: &PromptEnv) -> String {
    let prior = if role.solvable { format!("{}\n\n", texts::SOLVABLE_PRIOR) } else { String::new() };
    format!(
        "{}\n\n{}\n\n{prior}# Environment\nWorkspace: {}\nPlatform: {}\nSandbox: {}\nNetwork: {}",
        preamble.trim_end(),
        role.prompt.trim_end(),
        env.workspace,
        env.platform,
        env.sandbox,
        env.network
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const GOOD: &str = "name = \"mine\"\ndefault_role = \"a\"\n[roles.a]\nprompt = \"a.md\"\ntools = [\"bash\"]\nmay_spawn = [\"b\"]\n[roles.b]\nprompt = \"b.md\"\ntools = [\"read\", \"grep\"]\ntermination = \"free\"\n";

    fn mk(toml: &str) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("mine");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("pack.toml"), toml).unwrap();
        fs::write(p.join("a.md"), "Role A.\n\n").unwrap();
        fs::write(p.join("b.md"), "Role B.").unwrap();
        d
    }

    fn err(toml: &str) -> String {
        let d = mk(toml);
        let e = load_pack(&d.path().join("mine")).unwrap_err();
        assert!(e.contains("mine"), "{e}");
        e
    }

    fn env() -> PromptEnv {
        PromptEnv { workspace: "/w".into(), platform: "linux".into(), sandbox: "sb".into(), network: "net".into() }
    }

    #[test]
    fn builtin_loads() {
        let p = Packs::builtin().unwrap();
        let core = p.get("core").unwrap();
        for r in ["lead", "worker", "verifier", "chat"] {
            assert!(!core.roles[r].prompt.is_empty());
        }
        assert!(!core.preamble.is_empty());
        assert_eq!(core.roles["chat"].termination, Termination::Free);
        assert!(core.roles["verifier"].read_only);
        assert!(core.roles["lead"].verify_finish);
        assert_eq!(core.roles["lead"].verifier.as_deref(), Some("verifier"));
        assert_eq!(p.role(None, None).unwrap().name, "lead");
    }

    #[test]
    fn directory_pack_loads_with_defaults() {
        let d = mk(GOOD);
        let p = Packs::load(d.path()).unwrap();
        assert_eq!(p.names(), vec!["core".to_string(), "mine".to_string()]);
        let a = p.role(Some("mine"), None).unwrap();
        assert_eq!(a.prompt, "Role A.");
        assert_eq!(a.termination, Termination::Explicit);
        assert!(!a.verify_finish && !a.read_only);
        assert!(!a.requires_credential && a.max_steps.is_none());
        assert_eq!(a.description, "");
        assert_eq!(a.may_spawn, vec!["b".to_string()]);
        assert_eq!(p.get("mine").unwrap().preamble, p.get("core").unwrap().preamble);
        assert_eq!(p.role(Some("mine"), Some("b")).unwrap().termination, Termination::Free);
    }

    #[test]
    fn requires_restricted_network_is_a_top_level_key_defaulting_to_false() {
        let d = mk(GOOD);
        assert!(!Packs::load(d.path()).unwrap().get("mine").unwrap().requires_restricted_network);
        let d = mk(&format!("requires_restricted_network = true\n{GOOD}"));
        let p = Packs::load(d.path()).unwrap();
        assert!(p.get("mine").unwrap().requires_restricted_network);
        assert!(!p.get("core").unwrap().requires_restricted_network);
        // unknown keys are still rejected
        let e = err(&format!("requires_restricted_networks = true\n{GOOD}"));
        assert!(e.contains("requires_restricted_networks"), "{e}");
    }

    #[test]
    fn the_vr_pack_of_this_repository_requires_a_restricted_network() {
        // Its text tells the model that only authorized hosts are reachable.
        let vr = load_pack(Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../packs/vr"))).unwrap();
        assert_eq!(vr.name, "vr");
        assert!(vr.requires_restricted_network);
    }

    #[test]
    fn missing_dir_is_fine_and_core_can_be_replaced() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(Packs::load(&d.path().join("nope")).unwrap().names(), vec!["core"]);
        let c = d.path().join("c");
        fs::create_dir(&c).unwrap();
        fs::write(
            c.join("pack.toml"),
            "name=\"core\"\ndefault_role=\"x\"\npreamble=\"p.md\"\n[roles.x]\nprompt=\"x.md\"\ntools=[\"bash\"]\n",
        )
        .unwrap();
        fs::write(c.join("x.md"), "X").unwrap();
        fs::write(c.join("p.md"), "Pre\n").unwrap();
        let p = Packs::load(d.path()).unwrap();
        let core = p.get("core").unwrap();
        assert_eq!(core.roles.keys().collect::<Vec<_>>(), vec!["x"]);
        assert_eq!(core.preamble, "Pre");
        // dirs without pack.toml are ignored
        fs::create_dir(d.path().join("empty")).unwrap();
        assert!(Packs::load(d.path()).is_ok());
    }

    #[test]
    fn duplicate_names_rejected() {
        let d = mk(GOOD);
        let q = d.path().join("other");
        fs::create_dir(&q).unwrap();
        for f in ["pack.toml", "a.md", "b.md"] {
            fs::copy(d.path().join("mine").join(f), q.join(f)).unwrap();
        }
        assert!(Packs::load(d.path()).unwrap_err().contains("already used"));
    }

    #[test]
    fn validation_failures() {
        assert!(err(&GOOD.replace("name = \"mine\"\n", "")).contains("`name`"));
        assert!(err(&GOOD.replace("\"mine\"", "\"Bad_Name\"")).contains("Bad_Name"));
        assert!(err(&GOOD.replace("name =", "colour = 1\nname =")).contains("colour"));
        assert!(err(&GOOD.replace("tools = [\"bash\"]", "tools = [\"bash\"]\nbogus = 1")).contains("bogus"));
        assert!(err(&GOOD.replace("a.md", "zzz.md")).contains("zzz.md"));
        assert!(err(&GOOD.replace("a.md", "../x.md")).contains("roles.a.prompt"));
        assert!(err(&GOOD.replace("a.md", "/etc/passwd")).contains("relative"));
        assert!(err(&GOOD.replace("tools = [\"bash\"]", "tools = []")).contains("empty"));
        assert!(err(&GOOD.replace("[\"read\", \"grep\"]", "[\"read\", \"read\"]")).contains("more than once"));
        assert!(err(&GOOD.replace("tools = [\"bash\"]", "")).contains("`tools`"));
        assert!(err(&GOOD.replace("default_role = \"a\"", "default_role = \"q\"")).contains("default_role"));
        assert!(err(&GOOD.replace("[\"b\"]", "[\"q\"]")).contains("may_spawn"));
        assert!(err(&GOOD.replace("\"free\"", "\"never\"")).contains("termination"));
        assert!(err(&GOOD.replace("prompt = \"a.md\"\n", "")).contains("`prompt`"));
        assert!(err("this is not toml").contains("invalid"));
    }

    #[test]
    fn verify_finish_needs_a_resolvable_verifier() {
        let with = |extra: &str| {
            GOOD.replace("tools = [\"bash\"]", &format!("tools = [\"bash\"]\nverify_finish = true\n{extra}"))
        };
        // no role named verifier and no key
        let e = err(&with(""));
        assert!(e.contains("roles.a") && e.contains("needs a verifier role") && e.contains("verifier = "), "{e}");
        // names a missing role
        assert!(err(&with("verifier = \"zz\"")).contains("not a role of this pack"));
        // names a role that is not read-only or has no verdict
        let e = err(&with("verifier = \"b\""));
        assert!(e.contains("read_only = true") && e.contains("verdict"), "{e}");
        // read-only with verdict, but unable to open the evidence a verdict has to name
        let b_as = |tools: &str| {
            with("verifier = \"b\"").replace("[\"read\", \"grep\"]", &format!("{tools}\nread_only = true"))
        };
        let e = err(&b_as("[\"read\", \"verdict\"]"));
        assert!(e.contains("the verifier role \"b\"") && e.contains("`out_read` or `out_grep`"), "{e}");
        for tools in ["[\"out_read\", \"verdict\"]", "[\"verdict\", \"out_grep\"]"] {
            let d = mk(&b_as(tools));
            let p = Packs::load(d.path()).unwrap();
            assert_eq!(p.role(Some("mine"), Some("a")).unwrap().verifier.as_deref(), Some("b"));
        }
        // the default is the role named verifier
        let named = "name = \"mine\"\ndefault_role = \"a\"\n[roles.a]\nprompt = \"a.md\"\ntools = [\"bash\"]\nverify_finish = true\n[roles.verifier]\nprompt = \"b.md\"\ntools = [\"verdict\", \"out_read\"]\nread_only = true\n";
        let d = mk(named);
        let p = Packs::load(d.path()).unwrap();
        assert_eq!(p.role(Some("mine"), Some("a")).unwrap().verifier.as_deref(), Some("verifier"));
        assert_eq!(p.role(Some("mine"), Some("verifier")).unwrap().verifier.as_deref(), None);
    }

    #[test]
    fn shipped_packs_load() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let p = Packs::load(&dir).unwrap();
        assert!(p.names().contains(&"vr".to_string()) && p.names().contains(&"core".to_string()));
        p.check_tools(&crate::rtools::known_tools()).unwrap();
        let vr = p.get("vr").unwrap();
        assert_eq!(vr.roles["researcher"].verifier.as_deref(), Some("judge"));
        assert!(vr.roles["chat"].read_only);
        // A chat session keeps no ledger, so `note` could only fail.
        assert!(
            !vr.roles["chat"].tools.iter().any(|t| t == "note") && vr.roles["chat"].tools.iter().any(|t| t == "pin")
        );
        assert!(vr.roles["scout"].may_spawn.is_empty());
        for pack in ["core", "vr"] {
            let pack = p.get(pack).unwrap();
            for r in pack.roles.values().filter(|r| r.verify_finish) {
                let v = &pack.roles[r.verifier.as_deref().unwrap()];
                assert!(
                    v.read_only && v.tools.iter().any(|t| t == "verdict") && v.tools.iter().any(|t| t == "out_read")
                );
            }
        }
    }

    /// The backticked words of `text` that name a tool in `known`.
    fn tools_named(text: &str, known: &[String]) -> Vec<String> {
        let mut out: Vec<String> =
            text.split('`').skip(1).step_by(2).filter(|w| known.iter().any(|k| k == w)).map(str::to_string).collect();
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn scope_and_conclusion_tools_are_given_to_the_roles_whose_prompts_name_them() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let p = Packs::load(&dir).unwrap();
        let known = crate::rtools::known_tools();
        let has = |pack: &str, role: &str, tool: &str| p.get(pack).unwrap().roles[role].tools.iter().any(|t| t == tool);
        for (pack, role) in [("core", "lead"), ("vr", "researcher"), ("vr", "scout")] {
            assert!(has(pack, role, "request_scope") && has(pack, role, "conclude"), "{pack}/{role}");
        }
        // A read-only chat asks for scope; it concludes nothing.
        for pack in ["core", "vr"] {
            assert!(has(pack, "chat", "request_scope") && !has(pack, "chat", "conclude"), "{pack}/chat");
        }
        for (pack, role) in [("core", "worker"), ("core", "verifier"), ("vr", "judge")] {
            assert!(!has(pack, role, "request_scope") && !has(pack, role, "conclude"), "{pack}/{role}");
        }
        assert!(known.iter().any(|t| t == "request_scope") && known.iter().any(|t| t == "conclude"));
        // Every tool a role prompt names is a tool that role has, and every one is in the registry.
        for pack in ["core", "vr"] {
            for role in p.get(pack).unwrap().roles.values() {
                for tool in tools_named(&role.prompt, &known) {
                    assert!(
                        role.tools.contains(&tool),
                        "{pack}/{}: its prompt names `{tool}`, which it does not have",
                        role.name
                    );
                }
                assert!(role.tools.iter().all(|t| known.contains(t)), "{pack}/{}", role.name);
            }
        }
        // The prompts say what the new tools are for.
        let lead = &p.get("core").unwrap().roles["lead"].prompt;
        assert!(lead.contains("`conclude`") && lead.contains("`request_scope`") && lead.contains("not a finish"));
        let chat = &p.get("vr").unwrap().roles["chat"].prompt;
        assert!(chat.contains("`request_scope`") && !chat.contains("`conclude`"));
        let vr = &p.get("vr").unwrap().preamble;
        assert!(
            vr.contains("`request_scope`")
                && vr.contains("`conclude`")
                && vr.contains("Only the operator grants scope")
        );
    }

    #[test]
    fn the_vr_workspace_standards_name_only_tools_the_pack_has() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let p = Packs::load(&dir).unwrap();
        let known = crate::rtools::known_tools();
        let vr = p.get("vr").unwrap();
        let text = fs::read_to_string(dir.join("vr/workspace/AGENTS.md")).unwrap();
        let named = tools_named(&text, &known);
        for tool in &named {
            assert!(
                vr.roles.values().any(|r| r.tools.contains(tool)),
                "packs/vr/workspace/AGENTS.md names `{tool}`, which no role of the pack has"
            );
        }
        // What it tells the researcher to orchestrate with, the researcher has.
        let researcher = &vr.roles["researcher"];
        for tool in ["agent_spawn", "agent_fanout", "attempt", "agent_adopt", "request_scope", "conclude", "wait"] {
            assert!(named.iter().any(|t| t == tool), "the standards do not mention `{tool}`");
            assert!(researcher.tools.iter().any(|t| t == tool), "the researcher lacks `{tool}`");
        }
        // A scout has tools the researcher lacks, which is why the file says scouts start fresh.
        assert!(vr.roles["scout"].tools.iter().any(|t| !researcher.tools.contains(t)));
        assert!(text.contains("refuses to start a scout as a `fork`"));
    }

    #[test]
    fn the_ctf_prose_names_only_tools_the_pack_has() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let p = Packs::load(&dir).unwrap();
        let known = crate::rtools::known_tools();
        let ctf = p.get("ctf").unwrap();
        // The shared preamble is read by every role, so a tool it names only needs to belong to
        // some role of the pack.
        for tool in tools_named(&ctf.preamble, &known) {
            assert!(
                ctf.roles.values().any(|r| r.tools.contains(&tool)),
                "packs/ctf/harness.md names `{tool}`, which no role of the pack has"
            );
        }
        // A role's own prompt only gets to name tools that role itself has.
        for role in ctf.roles.values() {
            for tool in tools_named(&role.prompt, &known) {
                assert!(
                    role.tools.contains(&tool),
                    "ctf/{}: its prompt names `{tool}`, which it does not have",
                    role.name
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_rejected() {
        let d = mk(GOOD);
        let outside = d.path().join("outside.md");
        fs::write(&outside, "x").unwrap();
        let link = d.path().join("mine/a.md");
        fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(load_pack(&d.path().join("mine")).unwrap_err().contains("outside"));
    }

    #[test]
    fn role_lookup_errors() {
        let p = Packs::builtin().unwrap();
        assert_eq!(p.role(Some("core"), Some("chat")).unwrap().name, "chat");
        let e = p.role(Some("nope"), None).unwrap_err();
        assert!(e.contains("nope") && e.contains("core"));
        let e = p.role(None, Some("boss")).unwrap_err();
        assert!(e.contains("boss") && e.contains("worker"));
    }

    #[test]
    fn check_tools_names_nearest() {
        let p = Packs::builtin().unwrap();
        let mut known: Vec<String> = p.get("core").unwrap().roles.values().flat_map(|r| r.tools.clone()).collect();
        assert!(p.check_tools(&known).is_ok());
        known.retain(|t| t != "grep");
        known.push("grap".into());
        let e = p.check_tools(&known).unwrap_err();
        assert!(e.contains("\"grep\"") && e.contains("\"grap\"") && e.contains("core"), "{e}");
        assert!(p.check_tools(&[]).is_err());
    }

    #[test]
    fn system_prompt_layout_and_stability() {
        let p = Packs::builtin().unwrap();
        let r = p.role(None, Some("worker")).unwrap();
        let pre = &p.get("core").unwrap().preamble;
        let s = system_prompt(r, pre, &env());
        assert_eq!(
            s,
            format!(
                "{pre}\n\n{}\n\n# Environment\nWorkspace: /w\nPlatform: linux\nSandbox: sb\nNetwork: net",
                r.prompt
            )
        );
        assert_eq!(s, system_prompt(r, pre, &env()));
    }
    #[test]
    fn solvable_prior_sits_between_role_prompt_and_environment_only_in_solvable_packs() {
        let p = Packs::builtin().unwrap();
        let mut r = p.role(None, Some("worker")).unwrap().clone();
        let pre = &p.get("core").unwrap().preamble;
        let plain = system_prompt(&r, pre, &env());
        assert!(!plain.contains("solvable"));
        assert_eq!(
            plain,
            format!(
                "{pre}\n\n{}\n\n# Environment\nWorkspace: /w\nPlatform: linux\nSandbox: sb\nNetwork: net",
                r.prompt
            )
        );
        r.solvable = true;
        let s = system_prompt(&r, pre, &env());
        assert_eq!(
            s,
            format!(
                "{pre}\n\n{}\n\n{}\n\n# Environment\nWorkspace: /w\nPlatform: linux\nSandbox: sb\nNetwork: net",
                r.prompt,
                texts::SOLVABLE_PRIOR
            )
        );
        assert_eq!(s, system_prompt(&r, pre, &env()));
    }

    #[test]
    fn solvable_is_a_top_level_key_defaulting_to_false() {
        let d = mk(GOOD);
        let packs = Packs::load(d.path()).unwrap();
        assert!(!packs.get("mine").unwrap().solvable);
        assert!(!packs.role(Some("mine"), Some("a")).unwrap().solvable);
        let d = mk(&format!("solvable = true\n{GOOD}"));
        let packs = Packs::load(d.path()).unwrap();
        assert!(packs.get("mine").unwrap().solvable);
        assert!(packs.get("mine").unwrap().roles.values().all(|r| r.solvable));
        let e = err(&format!("solvable = \"yes\"\n{GOOD}"));
        assert!(e.contains("solvable"), "{e}");
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let packs = Packs::load(&dir).unwrap();
        assert!(packs.get("ctf").unwrap().solvable);
        assert!(packs.get("ctf").unwrap().roles.values().all(|r| r.solvable));
        for name in ["core", "vr", "redteam"] {
            let pack = packs.get(name).unwrap();
            assert!(!pack.solvable && pack.roles.values().all(|r| !r.solvable), "{name}");
        }
    }

    #[test]
    fn runtime_role_controls_load_validate_and_default_without_changing_old_packs() {
        let text = GOOD.replace("[roles.a]", "[roles.a]\nmodel = \"fast\"\nescalation_model = \"strong\"\nalloy_models = [\"fast\", \"other\"]\nmax_exec_calls = 0\nrequire_distinct_verifier_profile = true\nflag_regex = 'FLAG\\{[^}]+\\}'");
        let d = mk(&format!("command_guard = \"offensive\"\ntarget_concurrency = 3\n{text}"));
        let packs = Packs::load(d.path()).unwrap();
        let role = packs.role(Some("mine"), Some("a")).unwrap();
        assert_eq!(role.model.as_deref(), Some("fast"));
        assert_eq!(role.max_exec_calls, Some(0));
        assert_eq!(role.alloy_models, ["fast", "other"]);
        assert!(role.require_distinct_verifier_profile);
        assert!(packs.get("mine").unwrap().command_guard);
        assert_eq!(packs.get("mine").unwrap().target_concurrency, 3);
        let mut models = BTreeMap::new();
        assert!(packs.check_profiles(&models).unwrap_err().contains("fast"));
        for name in ["fast", "strong", "other"] {
            models.insert(name.into(), Default::default());
        }
        packs.check_profiles(&models).unwrap();
        for extra in ["command_guard = \"typo\"", "target_concurrency = 0"] {
            assert!(Packs::load(mk(&format!("{extra}\n{GOOD}")).path()).is_err());
        }
        let bad = GOOD.replace("[roles.a]", "[roles.a]\nflag_regex = '['");
        assert!(Packs::load(mk(&bad).path()).unwrap_err().contains("flag_regex"));
    }

    #[test]
    fn credential_dispatch_and_hard_epoch_slices_are_optional_and_validated() {
        let text = GOOD.replace("[roles.a]", "[roles.a]\nrequires_credential = true\nmax_steps = 35");
        let d = mk(&text);
        let packs = Packs::load(d.path()).unwrap();
        let role = packs.role(Some("mine"), Some("a")).unwrap();
        assert!(role.requires_credential);
        assert_eq!(role.max_steps, Some(35));
        let bad = GOOD.replace("[roles.a]", "[roles.a]\nmax_steps = 0");
        assert!(Packs::load(mk(&bad).path()).unwrap_err().contains("max_steps"));
        let missing_oracle_verifier = GOOD.replace("[roles.a]", "[roles.a]\nrequire_oracle = true");
        assert!(Packs::load(mk(&missing_oracle_verifier).path()).unwrap_err().contains("require_oracle"));
    }

    #[test]
    fn security_packs_have_bounded_tool_surfaces_and_only_lateral_dispatch_requires_credentials() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let packs = Packs::load(&dir).unwrap();
        packs.check_tools(&crate::rtools::known_tools()).unwrap();
        for name in ["ctf", "redteam"] {
            let pack = packs.get(name).unwrap();
            assert!(pack.requires_restricted_network);
            assert!(pack.command_guard);
            let cap = if name == "ctf" { 26 } else { 18 };
            for role in pack.roles.values() {
                assert!(role.tools.len() <= cap, "{name}/{} exposes {} tools", role.name, role.tools.len());
                assert_eq!(role.requires_credential, name == "redteam" && role.name == "lateral_operator");
                if role.name != pack.default_role {
                    assert!(role.max_steps.is_some(), "{name}/{} lacks an epoch cap", role.name);
                }
            }
            assert!(pack.roles.get(&pack.default_role).unwrap().require_oracle);
        }
        assert_eq!(packs.role(Some("ctf"), Some("solver")).unwrap().max_steps, Some(35));
        assert_eq!(packs.role(Some("redteam"), Some("recon_operator")).unwrap().max_steps, Some(25));
        assert_eq!(packs.role(Some("redteam"), Some("lateral_operator")).unwrap().max_steps, Some(30));
    }

    #[test]
    fn ctf_pack_grants_search_wait_edit_and_pty_to_the_roles_that_lacked_them() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let packs = Packs::load(&dir).unwrap();
        let ctf = packs.get("ctf").unwrap();
        let has = |role: &str, tool: &str| ctf.roles.get(role).unwrap().tools.iter().any(|t| t == tool);
        for role in ["solver", "web_solver", "binary_solver", "crypto_solver"] {
            for tool in ["grep", "glob", "wait"] {
                assert!(has(role, tool), "ctf/{role} should have {tool}");
            }
        }
        for role in ["web_solver", "binary_solver", "crypto_solver"] {
            assert!(has(role, "edit"), "ctf/{role} should have edit");
        }
        for role in ["binary_solver", "crypto_solver"] {
            for tool in ["pty_open", "pty_exec", "pty_close"] {
                assert!(has(role, tool), "ctf/{role} should have {tool}");
            }
        }
        assert!(has("web_solver", "job_wait"));
        for tool in ["wait", "attempt", "agent_adopt", "grep", "glob"] {
            assert!(has("dispatcher", tool), "ctf/dispatcher should have {tool}");
        }
        // Being stuck has a door that is not a finish: the dispatcher asks, the solvers hand the work back.
        assert!(has("dispatcher", "ask_for") && !has("dispatcher", "hand_off"));
        for role in ["solver", "web_solver", "binary_solver", "crypto_solver"] {
            assert!(has(role, "hand_off") && !has(role, "ask_for"), "ctf/{role} should have hand_off only");
        }
        assert_eq!(ctf.roles.get("binary_solver").unwrap().tools.len(), 26);
    }

    #[test]
    fn core_and_vr_packs_grant_the_exits_that_are_not_concessions() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packs");
        let packs = Packs::load(&dir).unwrap();
        let has = |pack: &str, role: &str, tool: &str| {
            packs.role(Some(pack), Some(role)).unwrap().tools.iter().any(|t| t == tool)
        };
        for (pack, lead, child) in [("core", "lead", "worker"), ("vr", "researcher", "scout")] {
            assert!(has(pack, lead, "ask_for") && !has(pack, lead, "hand_off"), "{pack}/{lead}");
            assert!(has(pack, child, "hand_off") && !has(pack, child, "ask_for"), "{pack}/{child}");
        }
    }
}
