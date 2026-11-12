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
//! requires_restricted_network = false  # optional; true = refuse to start sessions while the network mode is open
//!
//! [roles.lead]
//! description = "…"             # optional
//! prompt = "roles/lead.md"      # required file, relative to the pack directory
//! termination = "explicit"      # "explicit" | "free"; default "explicit"
//! tools = ["bash", "read"]      # required, non-empty, no duplicates; order is the request order
//! may_spawn = ["worker"]        # optional; each must name a role of this pack
//! verify_finish = true          # optional, default false
//! verifier = "verifier"         # optional; the role that attacks this role's finish (see below)
//! read_only = false             # optional, default false
//! ```
//! `verifier` defaults to the pack's role named `verifier` when it has one. A role with
//! `verify_finish = true` (or an explicit `verifier`) whose verifier is not a role of the same pack that is
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
//! Tests required: the built-in pack loads, has the roles `lead`, `worker`, `verifier`, `chat`, and
//! every role's prompt is non-empty; a directory pack loads and can replace `core`; each validation
//! failure (missing name, bad name, unknown key, missing prompt file, path escaping the pack,
//! empty/duplicate tools, `default_role`/`may_spawn` naming a missing role, bad termination);
//! defaults; `role` lookup defaults and errors; `check_tools`; `system_prompt` layout and that it is
//! identical for identical inputs.

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
    /// The role of this pack that attacks this role's finish and answers its `verify` tool; resolved at
    /// load (`verifier` key, else the pack's role named `verifier`). Always `Some` when `verify_finish`.
    pub verifier: Option<String>,
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
    /// The pack's text says the network is restricted: sessions of it are refused while the
    /// daemon's network mode is `open`.
    pub requires_restricted_network: bool,
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
    verifier: Option<String>,
    #[serde(default)]
    read_only: bool,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
const VERIFIER_NEEDS: &str = "a role with `read_only = true` whose `tools` include `verdict` and `out_read` or `out_grep`";

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
    let wanted = r.verifier.clone().or_else(|| (roles.contains_key("verifier") && !is_verifier).then(|| "verifier".to_string()));
    let usable = |name: &str| {
        roles.get(name).is_some_and(|v| {
            let has = |tool: &str| v.tools.iter().flatten().any(|t| t == tool);
            v.read_only && has("verdict") && (has("out_read") || has("out_grep"))
        })
    };
    if !(r.verify_finish || r.verifier.is_some()) {
        return Ok(wanted.filter(|n| usable(n)));
    }
    let Some(name) = wanted else {
        return Err(format!(
            "{at}: `verify_finish` = true needs a verifier role. Add a role named \"verifier\" to this pack, or set `verifier = \"<role>\"`; it must be {VERIFIER_NEEDS} (roles: {role_list})"
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
    let raw: RawPack =
        toml::from_str(toml_text).map_err(|e| format!("pack {label}: pack.toml is invalid: {e}"))?;
    let name = raw
        .name
        .ok_or_else(|| format!("pack {label}: pack.toml is missing the required key `name`"))?;
    if !valid_name(&name) {
        return Err(format!(
            "pack {label}: `name` = \"{name}\" is not valid; use only a-z, 0-9 and `-`"
        ));
    }
    let default_role = raw.default_role.ok_or_else(|| {
        format!("pack {label}: pack.toml is missing the required key `default_role`")
    })?;
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
        if !valid_name(rname) {
            return Err(format!(
                "pack {label}: role name \"{rname}\" is not valid; use only a-z, 0-9 and `-`"
            ));
        }
        let at = format!("pack {label}: roles.{rname}");
        let prompt_rel = r
            .prompt
            .as_deref()
            .ok_or_else(|| format!("{at} is missing the required key `prompt`"))?;
        check_rel(label, &format!("roles.{rname}.prompt"), prompt_rel)?;
        let prompt = read(prompt_rel)?.trim_end().to_string();
        if prompt.is_empty() {
            return Err(format!("{at}: prompt file {prompt_rel} is empty"));
        }
        let termination = match r.termination.as_deref() {
            None | Some("explicit") => Termination::Explicit,
            Some("free") => Termination::Free,
            Some(other) => {
                return Err(format!(
                    "{at}: `termination` = \"{other}\" is not valid; use \"explicit\" or \"free\""
                ))
            }
        };
        let tools = r
            .tools
            .clone()
            .ok_or_else(|| format!("{at} is missing the required key `tools`"))?;
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
                verifier,
                read_only: r.read_only,
            },
        );
    }
    Ok(Pack {
        name,
        description: raw.description.unwrap_or_default(),
        default_role,
        preamble,
        requires_restricted_network: raw.requires_restricted_network,
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
        let rd = std::fs::read_dir(dir)
            .map_err(|e| format!("pack directory {}: cannot be read: {e}", dir.display()))?;
        let mut dirs = Vec::new();
        for entry in rd {
            let entry = entry
                .map_err(|e| format!("pack directory {}: cannot be listed: {e}", dir.display()))?;
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
        let p = self.packs.get(pname).ok_or_else(|| {
            format!("unknown pack \"{pname}\"; packs available: {}", self.names().join(", "))
        })?;
        let rname = role.unwrap_or(&p.default_role);
        p.roles.get(rname).ok_or_else(|| {
            format!(
                "pack \"{pname}\" has no role \"{rname}\"; roles available: {}",
                p.roles.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })
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
    let root = std::fs::canonicalize(dir)
        .map_err(|e| format!("pack {label}: directory cannot be resolved: {e}"))?;
    let read = |rel: &str| -> Result<String, String> {
        let path = dir.join(rel);
        // Symlinks must not lead out of the pack directory.
        let real = std::fs::canonicalize(&path)
            .map_err(|e| format!("pack {label}: file {rel} cannot be read: {e}"))?;
        if !real.starts_with(&root) {
            return Err(format!("pack {label}: file {rel} resolves outside the pack directory"));
        }
        std::fs::read_to_string(&real)
            .map_err(|e| format!("pack {label}: file {rel} cannot be read as UTF-8 text: {e}"))
    };
    parse_pack(&label, &text, CORE_PREAMBLE, &read)
}

pub fn system_prompt(role: &RoleDef, preamble: &str, env: &PromptEnv) -> String {
    format!(
        "{}\n\n{}\n\n# Environment\nWorkspace: {}\nPlatform: {}\nSandbox: {}\nNetwork: {}",
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
        PromptEnv {
            workspace: "/w".into(),
            platform: "linux".into(),
            sandbox: "sb".into(),
            network: "net".into(),
        }
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
        assert!(!vr.roles["chat"].tools.iter().any(|t| t == "note") && vr.roles["chat"].tools.iter().any(|t| t == "pin"));
        assert!(vr.roles["scout"].may_spawn.is_empty());
        for pack in ["core", "vr"] {
            let pack = p.get(pack).unwrap();
            for r in pack.roles.values().filter(|r| r.verify_finish) {
                let v = &pack.roles[r.verifier.as_deref().unwrap()];
                assert!(v.read_only && v.tools.iter().any(|t| t == "verdict") && v.tools.iter().any(|t| t == "out_read"));
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
        let mut known: Vec<String> =
            p.get("core").unwrap().roles.values().flat_map(|r| r.tools.clone()).collect();
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
}
