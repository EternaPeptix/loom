//! Configuration (`~/.ferret/config.toml`) and the on-disk layout.
//!
//! Every field has a default, so an empty file is a valid config. Unknown keys are rejected so that a
//! typo is an error rather than a silently ignored setting.
//!
//! CONTRACT (model API keys).
//!
//! A model profile names its API key in one of two ways, or not at all; `Config::check` refuses a profile
//! that sets both (`models.{p}: set api_key_file or api_key_env, not both.`).
//! - `api_key_file = "{name}"`: the file `{name}` in `Paths::model_keys_dir()` (`<ferret home>/keys/models`,
//!   which commands cannot read). `check` refuses a name that is empty, longer than 64 characters, starts
//!   with `.`, or holds a character outside `[A-Za-z0-9._-]` (so it can name nothing outside that
//!   directory), with a sentence naming the profile and the rule.
//! - `api_key_env = "{VAR}"`: the variable `{VAR}` of the daemon's environment. Commands are never given it
//!   (`secret_env`), but every process of the user, sandboxed commands included, can read the environment
//!   another process was started with (macOS `KERN_PROCARGS2`), so a key held this way is readable by
//!   commands. It stays supported so that existing configurations keep working.
//!
//! `read_model_key(dir, name) -> Result<String, String>`: the key in `dir/name`. The file is opened
//! without following a link (`O_NOFOLLOW`) and judged by the open descriptor. Refused, each with a
//! sentence that names the path and says how to fix it: a missing file (the sentence gives the commands
//! that make one: `mkdir -p -m 700 {dir}` and `(set -o noclobber; umask 077; cat > {path})`, then the key and Ctrl-D); a link;
//! anything but a regular file; a file another user owns; a file with any group or other permission bit
//! (`chmod 600 {path}`); more than 16 KiB; content that is not UTF-8; content that, with leading and
//! trailing white space removed, is empty or still holds white space or a control character. Returns the
//! trimmed content. Never puts the key in a message.
//!
//! `Config::check_model_keys(dir) -> Result<(), String>`: `read_model_key` for every profile that sets
//! `api_key_file`, in name order; the first refusal as `models.{p}: {sentence}`.
//!
//! `Config::key_env_warnings(dir, is_set) -> Vec<String>`: one sentence per profile that sets `api_key_env`,
//! in name order (`dir` is `Paths::model_keys_dir()`). When `is_set(var)` (the variable is present and not
//! empty in the environment the daemon has or will be started with): the key of `models.{p}` is in the
//! daemon's environment, where every command can read it, and how to move it: write it to `{dir}/{p}`
//! (`mkdir -p -m 700 {dir}`, then `(set -o noclobber; umask 077; printenv {VAR} > {dir}/{p})`, or, when the variable is not
//! set, `(set -o noclobber; umask 077; cat > {dir}/{p})` and the key pasted), replace
//! `api_key_env = "{VAR}"` with `api_key_file = "{p}"` in `[models.{p}]`, and restart the daemon. Otherwise:
//! `{VAR}` is not set, so requests of `models.{p}` carry no key, and the same move. Never the value.
//!
//! Every command these sentences suggest is one a shell runs as written: a path or name that holds a
//! character outside `[A-Za-z0-9/._+:@%=,~-]` is single-quoted (`'` written `'\''`), and every command that
//! writes a key file runs with `set -o noclobber`, so it fails rather than replace a file that is there
//! (another profile's key). The file name they suggest for a profile `{p}` is `{p}` when it passes the
//! `api_key_file` rules, else `{p}` with every character outside `[A-Za-z0-9._-]` replaced by `-`, leading
//! `.`s removed and cut to 64 characters (or `model-key` when nothing is left); in `key_env_warnings` the
//! names suggested are unique within the config, compared without regard to case (as macOS file systems
//! compare them) with each other and with the `api_key_file` names in use, by appending `-2`, `-3`, … (cut
//! to fit 64). A profile name that is not a bare TOML key is written `[models."{p}"]` (with `"` and `\`
//! escaped).
//!
//! Tests required: both forms refused together; each name rule; `read_model_key` returns the trimmed key
//! and refuses a missing file (with the commands), a link, a directory, mode 0640 and 0604, an empty or
//! all-blank file, inner white space, a control character, non-UTF-8 and 16 KiB + 1 bytes, no message
//! holding the key; `check_model_keys` names the profile; `key_env_warnings` for a set and an unset
//! variable, holding the variable's name and the move and never its value; for a profile `gpt 4/o` and a
//! keys directory with a space in its path, the suggested file name passes the rules and the commands
//! quote the path; profiles `gpt 4`, `gpt/4` and `GPT-4` and a profile with `api_key_file = "gpt-4-2"` get
//! four distinct names (case-insensitively); every suggested write uses `noclobber`.

//! CONTRACT (model lineage and `[monitor]`, docs/MONITOR.md section 2.6).
//!
//! A model profile may also set `family` (a list: `["deepseek"]`), `alignment` (`"stock"`, `"relaxed"` or `"unknown"`),
//! `recipient` (`"local"`, `"lan"` or a provider name) and `purpose = "review"`; what unset ones resolve to is
//! `lineage::resolve`. `[monitor]` accepts `reviewers` (profile names, in preference order), `tripwires_only_profiles`,
//! `recipients` (per pack: the recipients the operator consents to), `content.new_recipient_real_targets`
//! (`"features"` default, or `"redacted"`) and `known_families`; M2 adds `enabled` (default true; false keeps only the precision-list, S4 and canary tripwires),
//! `mode` (`"shadow"`, the only value until M4), `fleet_every_s` (default 300, at least 10) and `monitor_down`
//! (`"pause_real_targets"` default, or `"notify"`); later phases add the other keys of the monitor.
//! `Config::check` refuses, each with a sentence that names the key and the fix: an empty `family` list or a family
//! outside `lineage::FAMILIES` and `known_families`; an empty `recipient`; a `reviewers` or `tripwires_only_profiles`
//! entry that is not a configured profile; a profile twice in `reviewers`; a reviewer whose alignment resolves to
//! relaxed; a `recipients` list that names `unknown` or nothing; an empty `known_families` entry; a reserved word
//! (`unknown`, `any`, `none`, `*`) in a `family` list or in `known_families` (it names no family: remove the key and the
//! family stays unknown, which matches every family); a `default_model` that has `purpose = "review"`. Whether a profile has
//! an eligible reviewer is not decided here (it depends on the packs): `ferret_agent::monitor::lineage::check_config`.
//!
//! Tests required: each refusal above with its sentence; an accepted `[monitor]` example; the default config holds no
//! monitor setting.

use crate::admit::AdmitPolicy;
use crate::event::ReasoningReplay;
use crate::ids::{MissionId, SessionId};
use crate::lineage::{is_reserved_family_word, known_family, normalize_name, resolve, Alignment, FAMILIES};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("config: {0}")]
    Invalid(String),
}

/// `[context]`: when the window is compacted (CONTRACTS-COMPACTION K2, K8).
///
/// `compact_at_tokens` is the request size at which a session compacts; `0` means 40% of the profile's
/// context window, never above 400 000 (100 000 when the window is not known). The keys of the re-weave
/// (`target_tokens`, `floor_tokens`, `keep_recent_steps`, `stub_tail_lines`) are still accepted and ignored,
/// with a startup warning ([`ContextCfg::warnings`]); `target_tokens` is read as `compact_at_tokens` when
/// that is absent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContextCfg {
    pub compact_at_tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub floor_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_recent_steps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stub_tail_lines: Option<u32>,
}

/// Most a default `compact_at` can be.
pub const COMPACT_AT_CAP: u64 = 400_000;

impl ContextCfg {
    /// The size at which a session with context window `window` compacts. Never above four fifths of a
    /// known window, so the reply still fits.
    pub fn compact_at(&self, window: Option<u64>) -> u64 {
        let set = if self.compact_at_tokens > 0 { self.compact_at_tokens } else { self.target_tokens.unwrap_or(0) };
        let size = if set > 0 {
            set
        } else {
            match window {
                Some(w) => (w / 5 * 2).min(COMPACT_AT_CAP),
                None => 100_000,
            }
        };
        match window {
            Some(w) => size.min(w / 5 * 4).max(1_000),
            None => size,
        }
    }

    /// One sentence for the old keys that are set and ignored.
    pub fn warnings(&self) -> Vec<String> {
        let mut old: Vec<&str> = Vec::new();
        if self.target_tokens.is_some() {
            old.push("target_tokens");
        }
        if self.floor_tokens.is_some() {
            old.push("floor_tokens");
        }
        if self.keep_recent_steps.is_some() {
            old.push("keep_recent_steps");
        }
        if self.stub_tail_lines.is_some() {
            old.push("stub_tail_lines");
        }
        if old.is_empty() {
            return Vec::new();
        }
        let used = if self.compact_at_tokens == 0 && self.target_tokens.is_some() {
            " target_tokens is read as compact_at_tokens."
        } else {
            ""
        };
        vec![format!(
            "config: [context] {} no longer change anything: the window is compacted at compact_at_tokens (0 = 40% of the model's window).{used}",
            old.join(", "),
        )]
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Name of the profile in `models` used when a session does not name one.
    pub default_model: String,
    pub daemon: DaemonCfg,
    pub models: BTreeMap<String, ModelProfile>,
    pub context: ContextCfg,
    pub admit: AdmitPolicy,
    pub tools: ToolsCfg,
    pub sandbox: SandboxCfg,
    pub network: NetworkCfg,
    pub agents: AgentsCfg,
    pub notify: NotifyCfg,
    /// The remote Docker container the agent runs commands in (`box_exec`). Disabled by default.
    #[serde(rename = "box")]
    pub boxed: BoxCfg,
    /// The adversarial monitor's settings (`docs/MONITOR.md`); M1 accepts the model-policy keys only.
    pub monitor: MonitorCfg,
    /// MCP servers whose tools sessions get (docs/CONTRACTS-MCP.md). Empty by default.
    pub mcp: McpCfg,
    /// Optional operator-scoped read-only email inbox (`inbox_read`) for bug bounty account activation / OTPs.
    pub mail: MailCfg,
    /// Optional two-way Signal bridge via a local `signal-cli daemon --http` for alerts and phone replies.
    pub signal: SignalCfg,
}

/// What a model profile is for. Absent means an agent profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePurpose {
    /// A reviewer profile of the monitor: not an agent's.
    Review,
}

/// What a reviewer in a new-recipient provider receives for a mission that has real targets (decision D9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecipientContent {
    /// Hashes, lengths and classes; no raw target content. Secrets are redacted in every case.
    #[default]
    Features,
    /// The content with secrets redacted.
    Redacted,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorContentCfg {
    pub new_recipient_real_targets: RecipientContent,
}

/// What the monitor does when its own log is unwritable or its fold failed (`docs/MONITOR.md` section 2.8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorDown {
    /// Missions with non-lab grants or relaxed agents are paused (M3 applies it); the default.
    #[default]
    PauseRealTargets,
    /// Only the operator is told.
    Notify,
}

/// The monitor's starting state of its causes (`docs/MONITOR.md` section 4.8). Only `shadow` exists until M4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorMode {
    /// Every cause is recorded and shown as "would have paused", with no effect an agent can see.
    #[default]
    Shadow,
}

/// `[monitor]`: the model policy (M1) and the watcher's own settings (M2). The later phases add keys; until then the
/// daemon rejects them as unknown keys.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorCfg {
    /// Duty W: the tripwires run on every record of every session. `false` keeps only the precision-list, S4 and canary
    /// tripwires, which have no off switch (design 7.1); the monitor still reads, logs and shows its status.
    pub enabled: bool,
    /// The starting state of the causes.
    pub mode: MonitorMode,
    /// Seconds between the fleet joins (FS-1 to FS-10).
    pub fleet_every_s: u64,
    /// What a down monitor does to the missions it can no longer watch.
    pub monitor_down: MonitorDown,
    /// Review profiles in preference order: the first one eligible for a mission reviews it.
    pub reviewers: Vec<String>,
    /// Profiles that have no eligible reviewer on purpose; their missions are shown as "not LLM-reviewed".
    pub tripwires_only_profiles: Vec<String>,
    /// Per pack, the recipients the operator consents to receive that pack's transcripts for review.
    pub recipients: BTreeMap<String, Vec<String>>,
    pub content: MonitorContentCfg,
    /// Family names beyond the ones ferret infers (`lineage::FAMILIES`) that a `family` key may use.
    pub known_families: Vec<String>,
}

impl Default for MonitorCfg {
    fn default() -> Self {
        MonitorCfg {
            enabled: true,
            mode: MonitorMode::Shadow,
            fleet_every_s: 300,
            monitor_down: MonitorDown::PauseRealTargets,
            reviewers: Vec::new(),
            tripwires_only_profiles: Vec::new(),
            recipients: BTreeMap::new(),
            content: MonitorContentCfg::default(),
            known_families: Vec::new(),
        }
    }
}

/// `[mcp]`: MCP servers as tools (docs/CONTRACTS-MCP.md M1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpCfg {
    /// Per role: MCP tool definitions beyond this many estimated tokens are left out (M6).
    pub max_schema_tokens: u64,
    /// A server with no call for this long is closed; it starts again on the next call (M3).
    pub idle_close_s: u64,
    pub servers: BTreeMap<String, McpServerCfg>,
}

impl Default for McpCfg {
    fn default() -> Self {
        Self { max_schema_tokens: 20_000, idle_close_s: 600, servers: BTreeMap::new() }
    }
}

/// One `[mcp.servers.<name>]` entry (M1). Exactly one of `command` (stdio) and `url` (Streamable HTTP).
/// `env` and `headers` values are `"env:NAME"`, `"file:/path"` or a literal; they are resolved when a
/// session starts the server and never written to a record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpServerCfg {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub env: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    /// Working directory of a stdio server, relative to the workspace (default: the workspace).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Hosts added to the session's allowed hosts while the server is configured (M4).
    pub hosts: Vec<String>,
    /// The server's tools a session gets (default: all it lists).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<String>>,
    /// The roles that get this server's tools (default: every role that is not read-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// The operator says no tool of this server changes anything: read-only roles get it too.
    pub read_only: bool,
    /// Per call, seconds.
    pub timeout_s: u64,
}

impl Default for McpServerCfg {
    fn default() -> Self {
        Self {
            command: None,
            url: None,
            env: BTreeMap::new(),
            headers: BTreeMap::new(),
            cwd: None,
            hosts: Vec::new(),
            tools: None,
            roles: None,
            read_only: false,
            timeout_s: 120,
        }
    }
}

impl McpCfg {
    /// M1's rules the types cannot express: a server name matches `[a-z0-9_-]{1,32}`, exactly one of
    /// `command` and `url`, a non-empty `command`, an `http`/`https` `url`, `timeout_s` > 0.
    pub fn check(&self) -> Result<(), String> {
        for (name, s) in &self.servers {
            let ok_name = !name.is_empty()
                && name.len() <= 32
                && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
            if !ok_name {
                return Err(format!("mcp.servers.{name}: a server name must match [a-z0-9_-]{{1,32}}"));
            }
            match (&s.command, &s.url) {
                (Some(_), Some(_)) => {
                    return Err(format!("mcp.servers.{name}: set command or url, not both"));
                }
                (None, None) => {
                    return Err(format!("mcp.servers.{name}: set command (stdio) or url (Streamable HTTP)"));
                }
                (Some(c), None) => {
                    if c.first().is_none_or(|p| p.trim().is_empty()) {
                        return Err(format!("mcp.servers.{name}: command must name a program"));
                    }
                }
                (None, Some(u)) => {
                    let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"));
                    if rest.is_none_or(|r| r.is_empty() || r.starts_with('/')) {
                        return Err(format!("mcp.servers.{name}: url must be an http:// or https:// address"));
                    }
                }
            }
            if s.timeout_s == 0 {
                return Err(format!("mcp.servers.{name}: timeout_s must be at least 1"));
            }
        }
        Ok(())
    }

    /// Startup warnings: a literal (not `env:`/`file:`) value in `env` or `headers` names a secret
    /// written in the config.
    pub fn warnings(&self) -> Vec<String> {
        let literal = |v: &String| !(v.starts_with("env:") || v.starts_with("file:"));
        let mut out = Vec::new();
        for (name, s) in &self.servers {
            for (kind, map) in [("env", &s.env), ("headers", &s.headers)] {
                for (key, value) in map {
                    if literal(value) {
                        out.push(format!(
                            "mcp.servers.{name}.{kind}.{key}: a literal value is written in the config; use \"env:NAME\" or \"file:/path\" so a secret stays out of it"
                        ));
                    }
                }
            }
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonCfg {
    /// Address the API and UI listen on. Must be a loopback address.
    pub bind: String,
    /// Port of the egress proxy on 127.0.0.1 (0 = pick a free one).
    pub proxy_port: u16,
}

impl Default for DaemonCfg {
    fn default() -> Self {
        Self { bind: "127.0.0.1:7878".into(), proxy_port: 0 }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelProfile {
    /// Base URL of an OpenAI-compatible API, including `/v1`.
    pub base_url: String,
    pub model: String,
    /// Name of an environment variable holding the API key, when the server wants one. A key held this
    /// way is in the daemon's environment, which commands can read; prefer `api_key_file` (see *model API
    /// keys* above).
    pub api_key_env: Option<String>,
    /// Name of a file in `<ferret home>/keys/models` holding the API key, when the server wants one. Read
    /// once at daemon start (see *model API keys* above). Set this or `api_key_env`, not both.
    pub api_key_file: Option<String>,
    /// Context window in tokens. When absent it is discovered from the server's model list.
    pub context_window: Option<u64>,
    /// `max_tokens` sent with each request. Absent = not sent (the server's default applies).
    pub max_output_tokens: Option<u64>,
    pub reasoning_replay: ReasoningReplay,
    /// The model takes images (OpenAI `image_url` content parts). Off: an image is named in the text, not sent.
    pub vision: bool,
    /// Fields added to every request body verbatim (`reasoning_effort`, `temperature`, `top_p`, …).
    /// Fixed for the life of a session: some templates render them into the request head.
    pub extra_body: Map<String, Value>,
    /// Concurrent requests this server is given, across all sessions.
    pub max_concurrent: u32,
    /// Abort and retry a stream that delivers nothing for this long.
    pub stall_timeout_s: u64,
    /// How long to keep retrying an unreachable or failing server, in seconds (default 300, long
    /// enough for a server relaunch). 0 = retry until the server comes back. Failures that waiting
    /// cannot cure (a reply that is not HTTP or not an event stream, a stream that ends without a
    /// finish reason, an oversized stream, certificate errors) end the request after 3 attempts in a row whatever this is
    /// set to. Every other failure is retried for the whole window, so with 0 one that never heals
    /// but looks like an outage (a server that hangs up during the TLS handshake, an error object in
    /// every stream) is retried until the request is cancelled. `agents.unavailable_notice_s` tells the
    /// operator about a request that keeps retrying.
    pub retry_window_s: u64,
    /// Longest pause between retries.
    pub retry_max_delay_s: u64,
    /// The model family as a set (`["deepseek"]`; a distill belongs to both of its families). Unset: inferred from the
    /// model id (`lineage`), else unknown, which matches every family.
    pub family: Option<Vec<String>>,
    /// Whether the model's refusals are intact. Unset: `relaxed` when the model id or profile name holds a marker
    /// such as `uncensored`, else `unknown` (an agent profile then counts as relaxed and a reviewer is ineligible).
    pub alignment: Option<Alignment>,
    /// Who receives this profile's traffic: `local`, `lan` (a host the operator owns) or a provider name. Unset: the
    /// host of `base_url`, or `unknown` when that is a loopback address.
    pub recipient: Option<String>,
    /// `review` marks a reviewer profile of the monitor.
    pub purpose: Option<ProfilePurpose>,
    /// Tool calls the model writes into its reply text instead of the tool-call channel, which the
    /// harness then runs (see *text tool calls* in `docs/DESIGN.md`): `"any"` takes every known
    /// format, a named format takes only that one, `"off"` takes none. Whatever the format, only
    /// calls that end the reply are taken, and only in a step of a role that ends by calling a tool.
    pub text_tool_calls: TextToolCalls,
}

/// The text form of tool calls a model is known to write when its server does not parse them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextToolCalls {
    /// Every format below.
    #[default]
    Any,
    /// None: text stays text.
    Off,
    /// `<tool_call>{"name": …, "arguments": …}</tool_call>` (Hermes, Qwen).
    ToolCall,
    /// `<｜DSML｜function_calls>` / `<｜DSML｜invoke name=…>` (DeepSeek).
    Dsml,
    /// `<function_calls>` / `<invoke name=…>` with `<parameter>` children.
    Invoke,
    /// A fenced JSON block holding `{"name": …, "arguments": …}`.
    FencedJson,
}

impl Default for ModelProfile {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8000/v1".into(),
            model: "default".into(),
            api_key_env: None,
            api_key_file: None,
            context_window: None,
            max_output_tokens: None,
            reasoning_replay: ReasoningReplay::All,
            vision: false,
            extra_body: Map::new(),
            max_concurrent: 4,
            stall_timeout_s: 240,
            retry_window_s: 300,
            retry_max_delay_s: 30,
            family: None,
            alignment: None,
            recipient: None,
            purpose: None,
            text_tool_calls: TextToolCalls::Any,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolsCfg {
    /// A foreground command still running after this long continues as a background job.
    pub bash_foreground_s: u64,
    /// Time between TERM and KILL when a command is cancelled.
    pub kill_grace_s: u64,
    /// Most lines one `out_read`/`read` call returns.
    pub read_max_lines: u64,
    /// Most matches `grep`/`glob`/`out_grep` return inline.
    pub search_max_results: usize,
    /// Largest image file `read` attaches (larger ones are described in text only).
    pub max_image_bytes: u64,
    pub web_fetch_timeout_s: u64,
    pub web_fetch_max_bytes: u64,
    /// A command whose output grows past this is stopped, and the result says so.
    pub max_output_bytes: u64,
    /// How long `job_wait` waits when the call gives no time.
    pub job_wait_s: u64,
    /// The least time between two reports of a background job whose output is watched (`bash` with
    /// `wake_on`), when the call gives none.
    pub job_wake_gap_s: u64,
    /// A watched job is reported this many times; after that it is followed with `job_wait`.
    pub job_wake_max: u32,
    /// Start a reply's leading read-only calls (`read`, `glob`, `grep`, `out_read`, `out_grep`) while
    /// the rest of the reply is still streaming. What is recorded and shown is the same either way.
    pub speculate: bool,
    /// The argument names the file and shell tools are shown with (`docs/TOOL-SHAPES.md`). Calls in
    /// either shape, and in other widely trained shapes, are accepted whichever is shown.
    pub dialect: Dialect,
}

/// See `ToolsCfg::dialect`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dialect {
    /// Claude Code's argument names and units for read, write, edit, bash, grep and glob.
    #[default]
    Trained,
    /// ferret's own argument names, as before.
    #[serde(alias = "loom")]
    Ferret,
}

impl Default for ToolsCfg {
    fn default() -> Self {
        Self {
            bash_foreground_s: 300,
            kill_grace_s: 5,
            read_max_lines: 2_000,
            search_max_results: 200,
            max_image_bytes: 5 * 1024 * 1024,
            web_fetch_timeout_s: 60,
            web_fetch_max_bytes: 20 * 1024 * 1024,
            max_output_bytes: 64 * 1024 * 1024,
            job_wait_s: 120,
            job_wake_gap_s: 30,
            job_wake_max: 20,
            speculate: true,
            dialect: Dialect::Trained,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// macOS `sandbox-exec` profile.
    Seatbelt,
    /// Linux bubblewrap with isolated namespaces and no command network access.
    Bubblewrap,
    /// No OS sandbox: commands are unconfined. The daemon logs a warning at start when this is set, and the
    /// system prompt of every session says so.
    None,
}

/// The OS's own sandbox: Bubblewrap on Linux, Seatbelt elsewhere (macOS). A config without `[sandbox]` (as
/// `ferret config init` writes it) then starts on either system.
impl Default for SandboxMode {
    fn default() -> Self {
        if cfg!(target_os = "linux") {
            SandboxMode::Bubblewrap
        } else {
            SandboxMode::Seatbelt
        }
    }
}

impl SandboxMode {
    /// The config spelling, for `ferret status` and other operator-facing text.
    pub fn as_str(&self) -> &'static str {
        match self {
            SandboxMode::Seatbelt => "seatbelt",
            SandboxMode::Bubblewrap => "bubblewrap",
            SandboxMode::None => "none",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxCfg {
    pub mode: SandboxMode,
    /// Extra directories commands may write to (absolute paths).
    pub extra_writable: Vec<String>,
    /// Paths that are never writable, even inside the workspace (absolute, or relative to it).
    pub protected_paths: Vec<String>,
    /// Paths that are not readable (absolute; `~` is expanded).
    pub unreadable_paths: Vec<String>,
    /// Also make the user's credential stores unreadable (`~/.ssh`, `~/.aws`, `~/.gnupg`, keychains,
    /// browser profiles, …). A listed directory that is or contains the workspace stays readable.
    pub protect_credentials: bool,
    /// Loopback TCP ports commands may connect to directly (local test services).
    pub loopback_ports: Vec<u16>,
    /// Allow commands to connect to any loopback port (needed to talk to servers they start).
    pub loopback_all: bool,
    /// Unix sockets commands may connect to (absolute paths), e.g. a container runtime's socket.
    pub unix_sockets: Vec<String>,
    /// Environment variables passed to commands even though their names look like secrets.
    pub env_pass: Vec<String>,
    /// Variable names withheld from commands whatever they are called (the model profiles' `api_key_env`
    /// names). Filled in by the runtime; not a configuration key. `env_pass` still overrides it.
    #[serde(skip)]
    pub secret_env: Vec<String>,
    /// Potential actor write origins retained when read-only roles lose `extra_writable` grants.
    /// Used only to exclude untrusted imports/inputs during isolated replay; not a config key.
    #[serde(skip)]
    pub replay_untrusted_paths: Vec<String>,
    /// The daemon's own TCP port, which no command may connect to whatever else allows it. Set by the daemon
    /// before the runtime starts; not a config key.
    #[serde(skip)]
    pub daemon_port: Option<u16>,
    /// Let commands look up the macOS services that fetch a URL for a process (`trustd`, `nsurlsessiond`, WebKit's
    /// XPC services), which reach the network outside the egress proxy. Off by default, in every network mode.
    /// Setting it marks the daemon's egress "unbounded" and keep-going refuses to turn on.
    pub allow_fetch_services: bool,
    /// Mach services commands may look up besides the built-in list (`MACH_LOOKUP_ALLOW`), for a
    /// tool that fails under the default-deny of `mach-lookup`: exact names, or a name ending in `*` for a prefix.
    /// An entry that would allow a fetch service or a disk-mounting service is refused.
    pub mach_allow: Vec<String>,
    /// How many processes of the user's limit (RLIMIT_NPROC) a sandboxed command leaves unused: a command can
    /// fork until the user has `limit - nproc_headroom` processes, so a fork bomb stops while the daemon can
    /// still start the processes that stop it. 0 sets no limit. Never below the processes that exist plus 64.
    pub nproc_headroom: u32,
    /// Loopback ports of infrastructure (a model endpoint, the Signal bridge's signal-cli or a
    /// `network.infrastructure` entry on this machine) that no command may connect to, whatever else allows
    /// loopback. Set by the runtime; not a config key.
    #[serde(skip)]
    pub infra_ports: Vec<u16>,
}

/// The default of `sandbox.nproc_headroom`.
pub const DEFAULT_NPROC_HEADROOM: u32 = 256;

/// Loopback ports that are never reachable to a command: Chrome DevTools, the Node inspector and the Docker
/// API. `sandbox.loopback_ports` may not list them, and the sandbox refuses them under `loopback_all`.
pub const DENIED_LOOPBACK_PORTS: [u16; 4] = [9222, 9229, 2375, 2376];

/// The macOS services that fetch a URL for a process, outside its sandbox and outside the egress proxy: certificate
/// evaluation (`trustd` fetches the issuer a certificate names), background URL sessions and WebKit.
pub const FETCH_SERVICE_NAMES: [&str; 5] = [
    "com.apple.trustd.agent",
    "com.apple.trustd",
    "com.apple.ocspd",
    "com.apple.nsurlsessiond",
    "com.apple.nsurlsessiond.NSURLSessionProxyService",
];
/// Name prefixes of the same (WebKit's networking and web-content XPC services).
pub const FETCH_SERVICE_PREFIXES: [&str; 1] = ["com.apple.WebKit."];
/// Services that mount a disk image or a volume for a process, outside its sandbox.
pub const DISK_SERVICE_NAMES: [&str; 4] = [
    "com.apple.DiskArbitration.diskarbitrationd",
    "com.apple.diskimagesiod",
    "com.apple.diskimagesiod.ram",
    "com.apple.diskmanagementd",
];
/// The Mach services a command may look up under the default-deny of `mach-lookup`, probed on macOS 27 with a
/// battery of bash, python3, node, git, curl, clang, swiftc, cargo, rustc, make, cmake, ssh, sqlite3, perl, ruby,
/// java, codesign, lldb, osascript and the usual utilities: what they need to start, resolve users, notify and
/// log, check a binary's execution policy, list processes (`pgrep`) and watch files. Everything else fails: the
/// keychain and security daemons, Spotlight (`mdfind`), the pasteboard, audio, analytics, authorization, disk
/// services, Launch Services' writers and every fetch service.
pub const MACH_LOOKUP_ALLOW: [&str; 17] = [
    "com.apple.CoreServices.coreservicesd",
    "com.apple.FSEvents",
    "com.apple.SystemConfiguration.DNSConfiguration",
    "com.apple.SystemConfiguration.configd",
    "com.apple.bsd.dirhelper",
    "com.apple.coreservices.launchservicesd",
    "com.apple.distributed_notifications@Uv3",
    "com.apple.logd",
    "com.apple.lsd.mapdb",
    "com.apple.security.syspolicy.exec",
    "com.apple.sysmond",
    "com.apple.system.logger",
    "com.apple.system.notification_center",
    "com.apple.system.opendirectoryd.libinfo",
    "com.apple.system.opendirectoryd.membership",
    "com.apple.tccd",
    "com.apple.tccd.system",
];

/// Mach service name prefixes a command may look up under the default-deny, besides `MACH_LOOKUP_ALLOW`: the
/// rendezvous servers (`<bundle id>.MachPortRendezvousServer.<pid>`) through which the child processes of a Chromium
/// build (renderer, GPU and utility processes of Playwright, Puppeteer, headless Chrome) find their parent. A
/// process registers its own name and its children look it up, so an exact list cannot name it. Probed on macOS 27
/// with a process that registers such a name and a child that looks it up: refused without the prefix, found with it.
/// Chromium itself was not run. Another build (Edge, Electron) needs `<its bundle id>.MachPortRendezvousServer.*` in
/// `sandbox.mach_allow`. The server checks who asks, which is why a prefix is allowed and no regex is.
pub const MACH_LOOKUP_ALLOW_PREFIXES: [&str; 3] = [
    "org.chromium.Chromium.MachPortRendezvousServer.",
    "com.google.Chrome.MachPortRendezvousServer.",
    "com.google.chrome.for.testing.MachPortRendezvousServer.",
];

/// Whether a `sandbox.mach_allow` entry covers `name`: the same string, or, for an entry ending in `*`, a name that
/// starts with what precedes it.
pub fn mach_entry_covers(entry: &str, name: &str) -> bool {
    match entry.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => entry == name,
    }
}

/// Whether `path` names the socket of a container runtime (Docker, containerd, Podman, CRI-O), which would
/// give a command the Docker host.
pub fn is_container_socket(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    name.contains("docker.sock")
        || name.contains("containerd.sock")
        || name.contains("crio.sock")
        || name.contains("cri-dockerd.sock")
        || (name.ends_with(".sock") && name.contains("podman"))
        || (lower.contains("/podman/") && name.ends_with(".sock"))
}

impl Default for SandboxCfg {
    fn default() -> Self {
        Self {
            mode: SandboxMode::default(),
            extra_writable: Vec::new(),
            protected_paths: Vec::new(),
            unreadable_paths: Vec::new(),
            protect_credentials: true,
            loopback_ports: Vec::new(),
            loopback_all: false,
            unix_sockets: Vec::new(),
            env_pass: Vec::new(),
            secret_env: Vec::new(),
            replay_untrusted_paths: Vec::new(),
            daemon_port: None,
            allow_fetch_services: false,
            mach_allow: Vec::new(),
            nproc_headroom: DEFAULT_NPROC_HEADROOM,
            infra_ports: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Any public destination.
    Open,
    /// Only destinations matching `allow`.
    Allowlist,
    /// Tools reach no host through the egress proxy (model requests to the configured endpoint are not affected); the default.
    #[default]
    DenyAll,
}

impl NetworkMode {
    /// The config spelling, for `ferret status` and other operator-facing text.
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkMode::Open => "open",
            NetworkMode::Allowlist => "allowlist",
            NetworkMode::DenyAll => "deny_all",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkCfg {
    pub mode: NetworkMode,
    /// Host patterns: `example.test`, `*.example.test`, optionally `:port`.
    pub allow: Vec<String>,
    /// Reference-only hosts: in-process GET clients use a separate grant; raw proxy access refuses them.
    pub reference_hosts: Vec<String>,
    /// Host patterns that are always refused.
    pub deny: Vec<String>,
    /// Private, loopback or link-local destinations that are permitted (same pattern syntax, or CIDR).
    pub allow_private: Vec<String>,
    /// Infrastructure no command may reach, whatever its grants say (same syntax as `deny`, CIDR blocks
    /// too): tailnet infrastructure, a desktop app's debugging port. Added to what ferret always refuses
    /// (cloud metadata, DevTools and Docker API ports on this machine, the daemon's port, every model
    /// endpoint, the box's Docker host) and checked before everything else, so a grant cannot lift it.
    pub infrastructure: Vec<String>,
    /// Bytes of each request or response body kept in a captured exchange (CONTRACTS-TRAFFIC-TARGETS C2).
    pub capture_max_bytes: u64,
    /// Exchanges recorded per session; past it traffic is still relayed but not recorded (C2).
    pub capture_max_exchanges: u64,
    /// When HTTPS through the proxy is decrypted and captured (I1).
    pub intercept: InterceptMode,
    /// Host patterns whose HTTPS is tunneled untouched even when interception is on (I4).
    pub intercept_passthrough: Vec<String>,
    /// PEM files of extra roots trusted for upstream TLS when intercepting (I4).
    pub upstream_roots: Vec<String>,
    /// Target noise governor profile (`off` | `quiet` | `balanced` | `aggressive`). Default `off`.
    pub noise_profile: NoiseProfileName,
    /// Default User-Agent attached to requests without an explicit User-Agent when a non-off noise profile is active.
    pub target_user_agent: Option<String>,
    /// Optional origin-scoped assessment User-Agent (`Ferret-Assessment/1.0 (engagement=...)`) for SOC/WAF log correlation.
    pub assessment_ua: Option<AssessmentUaCfg>,
}

/// Target egress noise governor profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseProfileName {
    #[default]
    Off,
    Quiet,
    Balanced,
    Aggressive,
}

impl NoiseProfileName {
    pub fn as_str(self) -> &'static str {
        match self {
            NoiseProfileName::Off => "off",
            NoiseProfileName::Quiet => "quiet",
            NoiseProfileName::Balanced => "balanced",
            NoiseProfileName::Aggressive => "aggressive",
        }
    }
}

/// Origin-scoped assessment identification header configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssessmentUaCfg {
    /// Exact approved HTTP/HTTPS origins (`https://shop.example.test`, `http://app.test:8080`), no wildcards/paths.
    pub origins: Vec<String>,
    /// Optional public engagement reference (1–64 ASCII `[A-Za-z0-9._-]`).
    pub reference: Option<String>,
}

impl AssessmentUaCfg {
    pub fn check(&self) -> Result<(), String> {
        if self.origins.is_empty() {
            return Err("network.assessment_ua.origins must list at least one exact http(s) origin.".into());
        }
        for raw in &self.origins {
            let trimmed = raw.trim();
            let u = url::Url::parse(trimmed).map_err(|_| {
                format!("network.assessment_ua.origins entry `{trimmed}` must be an exact http:// or https:// origin.")
            })?;
            if !matches!(u.scheme(), "http" | "https")
                || u.host_str().is_none()
                || !u.username().is_empty()
                || u.password().is_some()
                || (u.path() != "/" && !u.path().is_empty())
                || trimmed.ends_with('/')
                || u.query().is_some()
                || u.fragment().is_some()
                || u.host_str().is_some_and(|h| h.contains('*'))
            {
                return Err(format!(
                    "network.assessment_ua.origins entry `{trimmed}` must be an exact scheme://host[:port] with no wildcard, path, query, fragment, or credentials."
                ));
            }
        }
        if let Some(r) = self.reference.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            if r.len() > 64 || !r.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
                return Err(format!(
                    "network.assessment_ua.reference `{r}` must be 1 to 64 ASCII letters, digits, dots, underscores, or hyphens."
                ));
            }
        }
        Ok(())
    }
}

/// Backend for the operator-scoped read-only email inbox (`[mail]`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailBackend {
    #[default]
    Imaps,
    Maildir,
}

/// Authentication mechanism for IMAPS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailAuth {
    #[default]
    Login,
    Xoauth2,
}

/// Operator-scoped read-only email inbox configuration (`[mail]`).
/// Disabled by default; when enabled, `allow_senders` MUST be non-empty so the agent can ONLY read
/// emails from explicitly approved bug bounty platforms / target senders (e.g. `*@hackerone.com`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MailCfg {
    pub enabled: bool,
    pub backend: MailBackend,
    /// IMAP host (e.g. `imap.gmail.com`) when `backend = "imaps"`.
    pub host: String,
    /// IMAP TLS port (default 993).
    pub port: u16,
    /// IMAP login username.
    pub username: String,
    /// Path to a private (0600) file holding the IMAP app password or OAuth2 bearer token.
    pub password_file: Option<String>,
    pub auth: MailAuth,
    /// Read-only mailbox folder opened via IMAP `EXAMINE` (default `"INBOX"`).
    pub folder: String,
    /// Local maildir path when `backend = "maildir"`.
    pub maildir_path: Option<String>,
    /// REQUIRED non-empty sender patterns (e.g. `*@hackerone.com`, `*@bugcrowd.com`, `*@*.target.example`).
    pub allow_senders: Vec<String>,
    /// Optional recipient/plus-address patterns (e.g. `me+bb-*@gmail.com`). Empty = any recipient in the mailbox.
    pub allow_recipients: Vec<String>,
    /// When true, require `Authentication-Results` showing `dkim=pass` or `spf=pass`.
    pub require_auth_pass: bool,
    /// Only return messages received within this many minutes (default 120; 0 = unbounded).
    pub max_age_minutes: u64,
    /// Maximum messages returned per read (default 20, capped at 50).
    pub max_messages: usize,
    /// Optional roles allowed to use `inbox_read`. Empty = every non-read-only role.
    pub roles: Vec<String>,
}

impl Default for MailCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: MailBackend::Imaps,
            host: String::new(),
            port: 993,
            username: String::new(),
            password_file: None,
            auth: MailAuth::Login,
            folder: "INBOX".to_string(),
            maildir_path: None,
            allow_senders: Vec::new(),
            allow_recipients: Vec::new(),
            require_auth_pass: false,
            max_age_minutes: 120,
            max_messages: 20,
            roles: Vec::new(),
        }
    }
}

impl MailCfg {
    pub fn check(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.allow_senders.is_empty() || self.allow_senders.iter().any(|s| s.trim().is_empty()) {
            return Err(
                "mail.allow_senders must list at least one allowed sender pattern (for example `*@hackerone.com` or `*@bugcrowd.com`); unrestricted inbox access is refused."
                    .into(),
            );
        }
        for pat in &self.allow_senders {
            let p = pat.trim();
            if p == "*" || p == "*@*" || !p.contains('@') || p.chars().any(char::is_whitespace) {
                return Err(format!(
                    "mail.allow_senders entry `{p}` is too broad or invalid; use a scoped sender pattern like `*@hackerone.com` or `noreply@bugcrowd.com`."
                ));
            }
        }
        for pat in &self.allow_recipients {
            let p = pat.trim();
            if p.is_empty() || !p.contains('@') || p.chars().any(char::is_whitespace) {
                return Err(format!(
                    "mail.allow_recipients entry `{p}` is invalid; use an address or plus-tag pattern like `me+bb-*@gmail.com`."
                ));
            }
        }
        if self.max_messages == 0 || self.max_messages > 50 {
            return Err("mail.max_messages must be between 1 and 50.".into());
        }
        match self.backend {
            MailBackend::Imaps => {
                if self.host.trim().is_empty() || self.host.chars().any(char::is_whitespace) {
                    return Err("mail.host is required for backend = \"imaps\".".into());
                }
                if self.port == 0 {
                    return Err("mail.port must be between 1 and 65535.".into());
                }
                if self.username.trim().is_empty() {
                    return Err("mail.username is required for backend = \"imaps\".".into());
                }
                if self.password_file.as_deref().map(str::trim).unwrap_or("").is_empty() {
                    return Err(
                        "mail.password_file is required for backend = \"imaps\" (store the IMAP app password or OAuth2 token in a 0600 file, never inline in config.toml)."
                            .into(),
                    );
                }
                if self.folder.trim().is_empty() || self.folder.chars().any(char::is_control) {
                    return Err("mail.folder must be a valid IMAP mailbox name without control characters.".into());
                }
            }
            MailBackend::Maildir => {
                if self.maildir_path.as_deref().map(str::trim).unwrap_or("").is_empty() {
                    return Err("mail.maildir_path is required for backend = \"maildir\".".into());
                }
            }
        }
        Ok(())
    }
}

/// Operator two-way Signal bridge configuration (`[signal]`), talking to a local `signal-cli daemon --http`.
/// Disabled by default; when enabled, `allow_from` MUST be non-empty and never `*` (fail closed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignalCfg {
    pub enabled: bool,
    /// Base URL of `signal-cli daemon --http` (e.g. `http://127.0.0.1:1337`).
    pub http_url: String,
    /// Registered `signal-cli` account in E.164 format (e.g. `+15550100`).
    pub account: String,
    /// Outbound destination: an E.164 phone number (`+15550199`), Signal UUID, or `group:<groupId>`.
    pub recipient: String,
    /// Authorized inbound senders (E.164 numbers or Signal UUIDs) allowed to reply or issue commands.
    pub allow_from: Vec<String>,
    /// Optional allowed Signal group IDs for inbound replies (accepts both raw `<groupId>` and
    /// `group:<groupId>`, normalized on load; `recipient` is added automatically if `group:...`).
    #[serde(default, deserialize_with = "deserialize_allow_groups")]
    pub allow_groups: Vec<String>,
    /// Event kinds sent to Signal (default: blocker, question, approval, parked, finished, error).
    pub events: Vec<String>,
    /// Maximum characters of one outbound Signal message body (200..=7500; default 3500).
    pub max_chars: usize,
}

fn deserialize_allow_groups<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    let raw = Vec::<String>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|entry| {
            let trimmed = entry.trim();
            match trimmed.strip_prefix("group:").map(str::trim) {
                Some(rest) if !rest.is_empty() => rest.to_string(),
                _ => trimmed.to_string(),
            }
        })
        .collect())
}

impl Default for SignalCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            http_url: "http://127.0.0.1:1337".to_string(),
            account: String::new(),
            recipient: String::new(),
            allow_from: Vec::new(),
            allow_groups: Vec::new(),
            events: vec![
                "blocker".into(),
                "question".into(),
                "approval".into(),
                "parked".into(),
                "finished".into(),
                "error".into(),
            ],
            max_chars: 3500,
        }
    }
}

pub fn valid_e164(s: &str) -> bool {
    let t = s.trim();
    t.starts_with('+') && (7..=15).contains(&(t.len() - 1)) && t[1..].bytes().all(|b| b.is_ascii_digit())
}

pub fn valid_signal_uuid(s: &str) -> bool {
    let core = SignalCfg::normalize_signal_id(s);
    let parts: Vec<&str> = core.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(parts.iter())
            .all(|(&len, part)| part.len() == len && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl SignalCfg {
    pub const KNOWN_EVENTS: &[&str] = &["blocker", "question", "approval", "parked", "finished", "error", "disk"];

    /// Strip an optional `group:` prefix and trim whitespace from a Signal group ID.
    pub fn normalize_group_id(raw: &str) -> &str {
        let t = raw.trim();
        t.strip_prefix("group:").map(str::trim).unwrap_or(t)
    }

    /// Strip an optional `PNI:` or `u:` prefix (case-insensitive) and trim whitespace from a Signal ID.
    pub fn normalize_signal_id(raw: &str) -> &str {
        let t = raw.trim();
        for prefix in ["PNI:", "pni:", "u:", "U:"] {
            if let Some(rest) = t.strip_prefix(prefix) {
                return rest.trim();
            }
        }
        t
    }

    /// Normalized allowed group IDs (raw group IDs without `group:` prefix), including `recipient`
    /// when configured as `group:<groupId>`.
    pub fn normalized_allow_groups(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut push = |raw: &str| {
            let id = Self::normalize_group_id(raw);
            if !id.is_empty() && !out.iter().any(|existing| existing == id) {
                out.push(id.to_string());
            }
        };
        for g in &self.allow_groups {
            push(g);
        }
        if let Some(rec_gid) = self.recipient.trim().strip_prefix("group:") {
            push(rec_gid);
        }
        out
    }

    pub fn wants_event(&self, kind: &str) -> bool {
        self.events.iter().any(|e| e.trim().eq_ignore_ascii_case(kind))
    }

    pub fn check(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        let u = url::Url::parse(self.http_url.trim())
            .map_err(|_| format!("signal.http_url `{}` must be an http:// or https:// URL.", self.http_url))?;
        if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
            return Err(format!("signal.http_url `{}` must be an http:// or https:// URL with a host.", self.http_url));
        }
        if !valid_e164(&self.account) {
            return Err(format!(
                "signal.account `{}` must be an E.164 phone number (for example `+15550100`).",
                self.account
            ));
        }
        let rec = self.recipient.trim();
        let rec_ok = if let Some(gid) = rec.strip_prefix("group:") {
            !gid.trim().is_empty() && !gid.chars().any(char::is_whitespace)
        } else {
            valid_e164(rec) || valid_signal_uuid(rec)
        };
        if !rec_ok {
            return Err(format!(
                "signal.recipient `{rec}` must be an E.164 phone number (`+15550199`), a Signal UUID, or `group:<groupId>`."
            ));
        }
        if self.allow_from.is_empty() || self.allow_from.iter().any(|s| s.trim().is_empty()) {
            return Err(
                "signal.allow_from must list at least one authorized E.164 sender or Signal UUID; unrestricted inbound replies are refused."
                    .into(),
            );
        }
        for sender in &self.allow_from {
            let s = sender.trim();
            if s == "*" || s.chars().any(char::is_whitespace) || !(valid_e164(s) || valid_signal_uuid(s)) {
                return Err(format!(
                    "signal.allow_from entry `{s}` is invalid; list explicit E.164 phone numbers (for example `+15550199`) or Signal UUIDs."
                ));
            }
        }
        for group in &self.allow_groups {
            let gid = Self::normalize_group_id(group);
            if gid.is_empty() || gid == "*" || gid.chars().any(char::is_whitespace) {
                return Err(format!(
                    "signal.allow_groups entry `{}` is invalid; list explicit Signal group IDs (with or without `group:` prefix).",
                    group.trim()
                ));
            }
        }
        if self.events.is_empty() {
            return Err("signal.events must list at least one event kind.".into());
        }
        for ev in &self.events {
            let e = ev.trim().to_ascii_lowercase();
            if !Self::KNOWN_EVENTS.contains(&e.as_str()) {
                return Err(format!(
                    "signal.events entry `{ev}` is unknown; valid kinds are: {}.",
                    Self::KNOWN_EVENTS.join(", ")
                ));
            }
        }
        if !(200..=7500).contains(&self.max_chars) {
            return Err("signal.max_chars must be between 200 and 7500.".into());
        }
        Ok(())
    }
}

impl Default for NetworkCfg {
    fn default() -> Self {
        NetworkCfg {
            mode: NetworkMode::default(),
            allow: Vec::new(),
            reference_hosts: Vec::new(),
            deny: Vec::new(),
            allow_private: Vec::new(),
            infrastructure: Vec::new(),
            capture_max_bytes: 1 << 20,
            capture_max_exchanges: 100_000,
            intercept: InterceptMode::default(),
            intercept_passthrough: Vec::new(),
            upstream_roots: Vec::new(),
            noise_profile: NoiseProfileName::default(),
            target_user_agent: None,
            assessment_ua: None,
        }
    }
}

/// When the proxy decrypts HTTPS (CONTRACTS-TRAFFIC-TARGETS I1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptMode {
    /// As the mission's pack says (`intercept = true` in ctf, redteam, vr), unless the mission says otherwise.
    #[default]
    Pack,
    Always,
    Never,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentsCfg {
    /// Child sessions running at once within one mission.
    pub max_children: u32,
    /// Default budget for a child that is spawned without one.
    pub child_max_steps: u32,
    pub child_max_minutes: u32,
    /// Stop-gate nudges without progress before the session is parked for the operator.
    pub max_nudges: u32,
    /// Accepted so older configs load; ignored (the stall note was removed).
    pub stall_steps: u32,
    /// Run an independent verifier before a lead's `finish` is accepted.
    pub verify_finish: bool,
    /// When that verifier does not accept a finish, start the lead afresh: reopen the goal and fold its
    /// window, taking the attempt out of view (the records stay). False leaves the rejection in the
    /// window and the goal concluded, as before this option existed.
    pub fresh_start: bool,
    /// Fold a lead session's window after this many child settlements have arrived since the last
    /// compaction (0 = off). Re-anchors the coordinator on the sealed mission ledger, key table and a
    /// fresh note between delegation waves without reopening the goal or dropping attested state. Never
    /// triggers on child sessions, roles that cannot spawn agents, or during budget wrap-up.
    pub lead_fold_every_settlements: u32,
    /// Reserved: accepted so that configs that set it load, but nothing reads it and it has no effect.
    pub invalid_calls_before_forcing: u32,
    /// Outputs with at least this many lines never shown are listed in the HUD.
    pub unviewed_min_lines: u64,
    /// Seconds a model request of a session may keep retrying an unavailable server before the
    /// session tells the operator in a non-blocking inbox item (0 = never). None is opened when the
    /// request's retry window ends first: the request then fails at its next failed attempt.
    pub unavailable_notice_s: u64,
    /// A workspace with more files than this is not copied for an agent that asks for its own copy
    /// (`agent_spawn` with `workspace: "copy"` or `attempts`).
    pub copy_max_files: u64,
    /// Nor is one that holds more than this many MiB of file content (0 = no limit), where a copy
    /// duplicates them. On a file system that clones files (APFS) a copy takes no space until files
    /// are changed, and this limit is not applied.
    pub copy_max_mb: u64,
    /// Use compact tool descriptions and schemas to reduce prompt token overhead.
    pub compact_tools: bool,
    /// Allow explicit-termination sessions to treat a plain reply without open ledger items as implicit finish.
    pub implicit_finish: bool,
    /// Accepted so older configs load; ignored (the idle-goal paragraph was removed).
    pub idle_ledger_nudge: bool,
    /// Put the workspace's `AGENTS.md` and `CLAUDE.md` into the system prompt of each new session.
    pub project_instructions: bool,
}

impl Default for AgentsCfg {
    fn default() -> Self {
        Self {
            max_children: 6,
            child_max_steps: 200,
            child_max_minutes: 120,
            max_nudges: 3,
            stall_steps: 30,
            verify_finish: true,
            fresh_start: true,
            lead_fold_every_settlements: 0,
            invalid_calls_before_forcing: 3,
            unviewed_min_lines: 20,
            unavailable_notice_s: 300,
            copy_max_files: 300_000,
            copy_max_mb: 20_480,
            compact_tools: false,
            implicit_finish: false,
            idle_ledger_nudge: true,
            project_instructions: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyCfg {
    /// Program (and its arguments) run for each notification. It is given `FERRET_KIND`, `FERRET_SESSION`,
    /// `FERRET_TITLE` and `FERRET_TEXT` in its environment (the text cut to 500 characters). When empty the
    /// daemon uses the platform's notifier on macOS and notifies nobody elsewhere.
    pub command: Vec<String>,
    /// Repeat the notification for an unanswered blocking item after this many minutes (0 = never).
    pub repeat_minutes: u32,
}

/// Capabilities `[box] cap_add` may never contain (compared without a `CAP_` prefix, ignoring case).
pub const BOX_FORBIDDEN_CAPS: &[&str] = &[
    "ALL",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "SYS_TIME",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "NET_ADMIN",
    "DAC_READ_SEARCH",
    "BPF",
    "PERFMON",
    "SYSLOG",
];

/// `[box]`: one Docker host, one container per mission (see `ferret_tools::boxctl`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BoxCfg {
    pub enabled: bool,
    /// Forward the Docker socket of this host over SSH (the daemon's own `ssh`, batch mode).
    pub ssh_host: String,
    /// The socket's path on `ssh_host`.
    pub remote_socket: String,
    /// A Docker socket on this machine, instead of `ssh_host` and `remote_socket`.
    pub docker_socket: String,
    /// The docker command line client, resolved on the daemon's PATH at start.
    pub docker_cli: String,
    /// The image of the box: `name@sha256:<64 hex>` or an image ID `sha256:<64 hex>`.
    pub image: String,
    /// The image that edits the egress rules on the Docker host. It must contain `iptables`.
    pub helper_image: String,
    pub cpus: u32,
    pub memory_mb: u64,
    pub pids: u64,
    /// Size of the tmpfs mounted on `/work`.
    pub work_mb: u64,
    /// Size of the tmpfs mounted on `/tmp`.
    pub tmp_mb: u64,
    /// Capabilities added back to the box (everything else is dropped); see [`BOX_FORBIDDEN_CAPS`].
    pub cap_add: Vec<String>,
    /// Most megabytes of changed workspace files copied into `/work` before one `box_exec`.
    pub sync_max_mb: u64,
    /// A workspace file larger than this many megabytes is not copied.
    pub sync_file_max_mb: u64,
    /// Most megabytes one `box_get` brings back.
    pub get_max_mb: u64,
}

impl Default for BoxCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            ssh_host: String::new(),
            remote_socket: String::new(),
            docker_socket: String::new(),
            docker_cli: "docker".into(),
            image: String::new(),
            helper_image: String::new(),
            cpus: 4,
            memory_mb: 8192,
            pids: 512,
            work_mb: 4096,
            tmp_mb: 1024,
            cap_add: Vec::new(),
            sync_max_mb: 64,
            sync_file_max_mb: 16,
            get_max_mb: 64,
        }
    }
}

/// `name@sha256:<64 hex>` or `sha256:<64 hex>`: an image that cannot change under its name.
pub fn pinned_image(image: &str) -> bool {
    let digest = |d: &str| {
        d.strip_prefix("sha256:")
            .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    };
    match image.split_once('@') {
        Some((name, d)) => {
            !name.is_empty()
                && !name.starts_with('-')
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/' | b':'))
                && digest(d)
        }
        None => digest(image),
    }
}

/// The capability name as Docker takes it: upper case, without `CAP_`.
pub fn normalize_cap(cap: &str) -> String {
    let up = cap.trim().to_ascii_uppercase();
    up.strip_prefix("CAP_").unwrap_or(&up).to_string()
}

impl BoxCfg {
    /// The capabilities of `cap_add`, normalised.
    pub fn caps(&self) -> Vec<String> {
        self.cap_add.iter().map(|c| normalize_cap(c)).collect()
    }

    /// Checks that hold whether or not the box is enabled (what is written must never be unsafe), then,
    /// when it is enabled, that it can be used. Every error is a sentence.
    pub fn check(&self) -> Result<(), String> {
        for cap in &self.cap_add {
            let name = normalize_cap(cap);
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
                return Err(format!(
                    "box.cap_add contains \"{cap}\", which is not a capability name. Write names such as SYS_PTRACE or NET_RAW."
                ));
            }
            if BOX_FORBIDDEN_CAPS.contains(&name.as_str()) {
                return Err(format!(
                    "box.cap_add contains {name}, which ferret never gives the box: it would let a command act on the Docker host or undo the box's own limits. Remove it; capabilities such as SYS_PTRACE or NET_RAW are accepted."
                ));
            }
        }
        for (key, image) in [("image", &self.image), ("helper_image", &self.helper_image)] {
            if !image.is_empty() && !pinned_image(image) {
                return Err(format!(
                    "box.{key} \"{image}\" is not pinned. A tag can be moved to a different image after it was checked, so ferret takes only name@sha256:<64 hex digits> or an image ID sha256:<64 hex digits>. Find the ID with `docker image inspect --format '{{{{.Id}}}}' <tag>` on the Docker host."
                ));
            }
        }
        if !self.enabled {
            return Ok(());
        }
        for (key, image) in [("image", &self.image), ("helper_image", &self.helper_image)] {
            if image.is_empty() {
                return Err(format!(
                    "box.enabled is true but box.{key} is not set. Set it to a pinned image (sha256:<64 hex digits>)."
                ));
            }
        }
        let ssh = !self.ssh_host.is_empty() || !self.remote_socket.is_empty();
        let local = !self.docker_socket.is_empty();
        if ssh == local {
            return Err("box.enabled needs exactly one way to reach Docker: either ssh_host with remote_socket, or docker_socket for a socket on this machine.".into());
        }
        if ssh {
            if self.ssh_host.is_empty() || self.remote_socket.is_empty() {
                return Err("box.ssh_host and box.remote_socket must be set together.".into());
            }
            if self.ssh_host.starts_with('-') || self.ssh_host.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(format!(
                    "box.ssh_host \"{}\" must be a host name or an ssh config alias: no spaces, and not starting with `-`.",
                    self.ssh_host
                ));
            }
            if !self.remote_socket.starts_with('/')
                || self.remote_socket.chars().any(|c| c == ':' || c.is_whitespace() || c.is_control())
            {
                return Err(format!(
                    "box.remote_socket \"{}\" must be an absolute path on {} without spaces or `:`.",
                    self.remote_socket, self.ssh_host
                ));
            }
        } else if !self.docker_socket.starts_with('/') {
            return Err("box.docker_socket must be an absolute path.".into());
        }
        if self.docker_cli.trim().is_empty() {
            return Err("box.docker_cli must name the docker command line client.".into());
        }
        for (key, v) in [
            ("cpus", u64::from(self.cpus)),
            ("memory_mb", self.memory_mb),
            ("pids", self.pids),
            ("work_mb", self.work_mb),
            ("tmp_mb", self.tmp_mb),
            ("sync_max_mb", self.sync_max_mb),
            ("sync_file_max_mb", self.sync_file_max_mb),
            ("get_max_mb", self.get_max_mb),
        ] {
            if v == 0 {
                return Err(format!("box.{key} must be at least 1."));
            }
        }
        Ok(())
    }
}

/// `p` with `.` removed and `..` applied, without touching the file system.
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The paths `p` may stand for: itself, and (when it or an ancestor exists) with the links resolved.
fn spellings(p: &Path) -> Vec<PathBuf> {
    let plain = lexical(p);
    let mut all = vec![plain.clone()];
    if let Some(existing) = plain.ancestors().find(|a| a.exists()) {
        if let (Ok(real), Ok(tail)) = (std::fs::canonicalize(existing), plain.strip_prefix(existing)) {
            all.push(real.join(tail));
        }
    }
    all
}

impl Config {
    /// What can only be checked once the ferret home is known: no `sandbox.unix_sockets` entry may be (or be
    /// below) `<ferret home>/keys`, where the box's forwarded Docker socket lives, and none may be the local
    /// `box.docker_socket`. A command that could connect there would control the Docker host.
    pub fn check_box_paths(&self, home: &Path) -> Result<(), String> {
        let keys = spellings(&home.join("keys"));
        let docker = (self.boxed.enabled && !self.boxed.docker_socket.is_empty())
            .then(|| spellings(Path::new(&self.boxed.docker_socket)));
        for entry in &self.sandbox.unix_sockets {
            let mine = spellings(Path::new(entry));
            if mine.iter().any(|m| keys.iter().any(|k| m.starts_with(k))) {
                return Err(format!(
                    "sandbox.unix_sockets lists {entry}, which is inside {}. That directory holds the box's Docker socket and the daemon's keys, and no command may be allowed to connect there. Remove the entry.",
                    home.join("keys").display()
                ));
            }
            if docker.as_ref().is_some_and(|d| mine.iter().any(|m| d.contains(m))) {
                return Err(format!(
                    "sandbox.unix_sockets lists {entry}, which is the Docker socket of the box (box.docker_socket). A command that could connect to it would control the Docker host. Remove the entry."
                ));
            }
        }
        Ok(())
    }

    /// Load a config file. A missing file is the default config.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(source) => return Err(ConfigError::Io { path: path.to_path_buf(), source }),
        };
        let config =
            Config::parse(&text).map_err(|message| ConfigError::Parse { path: path.to_path_buf(), message })?;
        config.check()?;
        Ok(config)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        toml::from_str::<Config>(text).map_err(|e| e.to_string())
    }

    /// Consistency checks that the types cannot express.
    pub fn check(&self) -> Result<(), ConfigError> {
        if !self.models.is_empty() && !self.default_model.is_empty() && !self.models.contains_key(&self.default_model) {
            let names: Vec<&str> = self.models.keys().map(String::as_str).collect();
            return Err(ConfigError::Invalid(format!(
                "default_model \"{}\" is not one of the configured models ({})",
                self.default_model,
                names.join(", ")
            )));
        }
        if let Some(profile) = self.models.get(&self.default_model) {
            if profile.purpose == Some(ProfilePurpose::Review) {
                return Err(ConfigError::Invalid(format!(
                    "default_model \"{}\" has purpose = \"review\": a reviewer profile is not an agent's, and its sessions would run unreviewed. Name an agent profile.",
                    self.default_model
                )));
            }
        }
        let host = self.daemon.bind.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
        if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
            return Err(ConfigError::Invalid(format!(
                "daemon.bind must be a loopback address, got \"{}\"",
                self.daemon.bind
            )));
        }
        for p in &self.sandbox.loopback_ports {
            if DENIED_LOOPBACK_PORTS.contains(p) {
                return Err(ConfigError::Invalid(format!(
                    "sandbox.loopback_ports lists {p}, a DevTools, inspector or Docker API port: no command may connect to it. Remove it from the list."
                )));
            }
        }
        for entry in &self.sandbox.mach_allow {
            let valid = !entry.is_empty()
                && entry.len() <= 128
                && entry.chars().enumerate().all(|(i, c)| {
                    c.is_ascii_alphanumeric()
                        || matches!(c, '.' | '_' | '-' | '@')
                        || (c == '*' && i + 1 == entry.chars().count())
                });
            if !valid {
                return Err(ConfigError::Invalid(format!(
                    "sandbox.mach_allow lists \"{entry}\", which is not a Mach service name: use letters, digits and `.`, `_`, `-`, `@`, with at most one `*` at the end for a prefix. Fix or remove the entry."
                )));
            }
            let fetch = FETCH_SERVICE_NAMES.iter().chain(DISK_SERVICE_NAMES.iter()).copied();
            let covered = fetch.clone().find(|n| mach_entry_covers(entry, n)).or_else(|| {
                FETCH_SERVICE_PREFIXES
                    .iter()
                    .copied()
                    .find(|p| mach_entry_covers(entry, p) || entry.trim_end_matches('*').starts_with(p))
            });
            let broad = entry.strip_suffix('*').is_some_and(|p| p.len() < 8);
            if broad || covered.is_some() {
                let what = covered.map_or_else(
                    || "nearly every service, which defeats the default-deny".to_string(),
                    |n| format!("{n}, a service that fetches URLs or mounts disks outside the sandbox"),
                );
                return Err(ConfigError::Invalid(format!(
                    "sandbox.mach_allow lists \"{entry}\", which would allow {what}. List the exact services the tool needs; for the fetch services the only switch is sandbox.allow_fetch_services, which marks the daemon's egress unbounded."
                )));
            }
        }
        for entry in &self.sandbox.unix_sockets {
            if is_container_socket(entry) {
                return Err(ConfigError::Invalid(format!(
                    "sandbox.unix_sockets lists {entry}, the socket of a container runtime: a command that could connect to it would control the Docker host (a container can mount the whole home). Remove the entry."
                )));
            }
        }
        self.boxed.check().map_err(ConfigError::Invalid)?;
        self.mcp.check().map_err(ConfigError::Invalid)?;
        self.mail.check().map_err(ConfigError::Invalid)?;
        self.signal.check().map_err(ConfigError::Invalid)?;
        if let Some(ua) = self.network.target_user_agent.as_deref() {
            if ua.chars().any(char::is_control) {
                return Err(ConfigError::Invalid(
                    "network.target_user_agent must not contain control characters.".into(),
                ));
            }
        }
        if let Some(aua) = &self.network.assessment_ua {
            aua.check().map_err(ConfigError::Invalid)?;
        }
        if self.boxed.enabled && self.sandbox.mode == SandboxMode::None {
            return Err(ConfigError::Invalid(
                "box.enabled cannot be combined with sandbox.mode = \"none\": without a sandbox the agent's own commands could connect to the Docker socket and the ssh forward that the box uses, and would then control the Docker host. Use the seatbelt or bubblewrap sandbox, or leave the box off.".into(),
            ));
        }
        for (name, profile) in &self.models {
            if profile.max_concurrent == 0 {
                return Err(ConfigError::Invalid(format!("models.{name}.max_concurrent must be at least 1")));
            }
            if profile.api_key_file.is_some() && profile.api_key_env.is_some() {
                return Err(ConfigError::Invalid(format!("models.{name}: set api_key_file or api_key_env, not both.")));
            }
            if let Some(file) = &profile.api_key_file {
                check_key_file_name(file).map_err(|rule| ConfigError::Invalid(format!("models.{name}: {rule}")))?;
            }
            self.check_lineage_keys(name, profile).map_err(ConfigError::Invalid)?;
        }
        self.check_monitor().map_err(ConfigError::Invalid)?;
        Ok(())
    }

    /// The profile's `family` and `recipient` keys.
    fn check_lineage_keys(&self, name: &str, profile: &ModelProfile) -> Result<(), String> {
        if let Some(family) = &profile.family {
            if family.is_empty() {
                return Err(format!(
                    "models.{name}.family is an empty list. List the families of the model (for example family = [\"deepseek\"]; a distill lists two), or remove the key to have ferret infer it from the model id."
                ));
            }
            for f in family {
                if is_reserved_family_word(f) {
                    return Err(format!(
                        "models.{name}.family lists \"{f}\", which names no family. If the family of this model is not known, remove the key: an unknown family matches every family, which is the safe reading. Do not add it to known_families."
                    ));
                }
                if !known_family(f, &self.monitor.known_families) {
                    return Err(format!(
                        "models.{name}.family lists \"{f}\", which is not a family ferret knows ({}). Fix the spelling, or, for a family that is new, add \"{}\" to known_families under [monitor]: a misspelt family would make a reviewer of the same family look unrelated.",
                        FAMILIES.join(", "),
                        normalize_name(f)
                    ));
                }
            }
        }
        if let Some(recipient) = &profile.recipient {
            if normalize_name(recipient).is_empty() {
                return Err(format!(
                    "models.{name}.recipient is empty. Name who receives this profile's traffic: \"local\", \"lan\" (a host you own) or the provider's name, or remove the key."
                ));
            }
        }
        Ok(())
    }

    /// `[monitor]`: every profile it names exists, a reviewer is not relaxed, consents name a recipient.
    fn check_monitor(&self) -> Result<(), String> {
        let m = &self.monitor;
        if m.fleet_every_s < 10 {
            return Err(format!(
                "monitor.fleet_every_s is {}. The fleet joins are not run more often than every 10 seconds: set 10 or more (default 300).",
                m.fleet_every_s
            ));
        }
        let known = |p: &str| -> Result<(), String> {
            self.models.get(p).map(|_| ()).ok_or_else(|| {
                let names: Vec<&str> = self.models.keys().map(String::as_str).collect();
                format!(
                    "{p:?} is not a configured model profile ({}). Add [models.{p}] or fix the name.",
                    names.join(", ")
                )
            })
        };
        let mut seen = HashSet::new();
        for r in &m.reviewers {
            known(r).map_err(|e| format!("monitor.reviewers: {e}"))?;
            if !seen.insert(r.as_str()) {
                return Err(format!(
                    "monitor.reviewers lists \"{r}\" twice. List each profile once, in preference order."
                ));
            }
            if let Some(profile) = self.models.get(r) {
                if resolve(r, profile).alignment == Alignment::Relaxed {
                    return Err(format!(
                        "monitor.reviewers lists \"{r}\", whose refusals are relaxed. A relaxed model is never a reviewer: remove it from the list."
                    ));
                }
            }
        }
        for t in &m.tripwires_only_profiles {
            known(t).map_err(|e| format!("monitor.tripwires_only_profiles: {e}"))?;
        }
        for (pack, list) in &m.recipients {
            if pack.trim().is_empty() {
                return Err("monitor.recipients has a pack name that is empty. Name the pack (for example `ctf = [\"alibaba\"]`).".into());
            }
            for r in list {
                let n = normalize_name(r);
                if n.is_empty() || n == "unknown" {
                    return Err(format!(
                        "monitor.recipients.{pack} lists \"{r}\". Consent names a provider (for example \"alibaba\"); an unknown recipient is never eligible, so a consent to it means nothing."
                    ));
                }
            }
        }
        for f in &m.known_families {
            if normalize_name(f).is_empty() {
                return Err("monitor.known_families lists an empty name. Remove it or write the family.".into());
            }
            if is_reserved_family_word(f) {
                return Err(format!(
                    "monitor.known_families lists \"{f}\", which names no family. Remove it: a model whose family is not known has no family key, and then matches every family; a family called \"{f}\" would be unrelated to all others."
                ));
            }
        }
        Ok(())
    }

    /// Reads every profile's `api_key_file` from `dir` (`Paths::model_keys_dir()`), in name order; the first
    /// refusal is returned as `models.{p}: {sentence}`. The keys are dropped.
    pub fn check_model_keys(&self, dir: &Path) -> Result<(), String> {
        for (name, profile) in &self.models {
            if let Some(file) = &profile.api_key_file {
                read_model_key(dir, file).map_err(|e| format!("models.{name}: {e}"))?;
            }
        }
        Ok(())
    }

    /// One sentence per profile that names its key by `api_key_env`, in name order. `is_set(var)` says whether
    /// the variable is present and not empty in the environment the daemon has or will be started with.
    /// Never holds a value.
    pub fn key_env_warnings(&self, dir: &Path, is_set: impl Fn(&str) -> bool) -> Vec<String> {
        let mut out = Vec::new();
        let files = self.suggested_key_files();
        for (name, profile) in &self.models {
            let Some(var) = &profile.api_key_env else { continue };
            let set = is_set(var);
            let file = files.get(name).cloned().unwrap_or_else(|| suggested_key_file(name));
            // Where the variable is not set, `printenv` would write an empty file: the key is pasted instead.
            let mv = format!("To move it, {}, and restart the daemon.", key_move_steps(dir, name, &file, var, set));
            if set {
                out.push(format!(
                    "The key of models.{name} is in the daemon's environment as {var}, where every command can read it. {mv}"
                ));
            } else {
                out.push(format!("{var} is not set, so requests of models.{name} carry no key. {mv}"));
            }
        }
        out
    }

    /// The key file name to suggest for each profile that names its key by `api_key_env`: unique within the
    /// config, compared without regard to case with each other and with the `api_key_file` names in use, by
    /// appending `-2`, `-3`, … (the name cut to fit 64 characters).
    pub fn suggested_key_files(&self) -> BTreeMap<String, String> {
        let mut used: HashSet<String> =
            self.models.values().filter_map(|p| p.api_key_file.as_ref()).map(|f| f.to_lowercase()).collect();
        let mut out = BTreeMap::new();
        for (name, profile) in &self.models {
            if profile.api_key_env.is_none() {
                continue;
            }
            let base = suggested_key_file(name);
            let mut chosen = base.clone();
            let mut n = 1u32;
            while used.contains(&chosen.to_lowercase()) {
                n += 1;
                let suffix = format!("-{n}");
                let keep = 64usize.saturating_sub(suffix.len());
                chosen = format!("{}{suffix}", base.chars().take(keep).collect::<String>());
            }
            used.insert(chosen.to_lowercase());
            out.insert(name.clone(), chosen);
        }
        out
    }

    /// The profile a session should use: `name` when given, else `default_model`, else the only one.
    pub fn profile(&self, name: Option<&str>) -> Result<(&str, &ModelProfile), ConfigError> {
        resolve_profile(&self.models, &self.default_model, name)
    }
}

/// `s` as one word of a POSIX shell: as it is when it holds only `[A-Za-z0-9/._+:@%=,~-]`, else in single
/// quotes (`'` written `'\''`).
pub fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '+' | ':' | '@' | '%' | '=' | ',' | '~' | '-')
        });
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// The file name to suggest for the key of model profile `profile`: the name itself when it passes the
/// `api_key_file` rules, else the name with every character outside `[A-Za-z0-9._-]` replaced by `-`,
/// leading dots removed and cut to 64 characters (`model-key` when nothing is left).
pub fn suggested_key_file(profile: &str) -> String {
    if check_key_file_name(profile).is_ok() {
        return profile.to_string();
    }
    let cleaned: String = profile
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .skip_while(|c| *c == '.')
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "model-key".to_string()
    } else {
        cleaned
    }
}

/// The TOML table header of model profile `profile`: `[models.{p}]`, with the name quoted when it is not a
/// bare key.
fn models_header(profile: &str) -> String {
    let bare = !profile.is_empty() && profile.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
    if bare {
        format!("[models.{profile}]")
    } else {
        format!("[models.\"{}\"]", profile.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// The steps that move the key of model profile `profile` from `api_key_env = "{var}"` to a file in `dir`,
/// as a clause for a sentence: every command in it runs in a shell as written. `printenv` is used when the
/// variable is set, else the key is pasted. Never holds a value.
/// `file` is the file name to use (see [`Config::suggested_key_files`]). Every write runs with `noclobber`, so
/// it fails rather than replace a file that is there.
pub fn key_move_steps(dir: &Path, profile: &str, file: &str, var: &str, printenv: bool) -> String {
    let path = shell_quote(&dir.join(file).display().to_string());
    let dir = shell_quote(&dir.display().to_string());
    let var_word = shell_quote(var);
    let write = if printenv {
        format!("`(set -o noclobber; umask 077; printenv {var_word} > {path})`")
    } else {
        format!("`(set -o noclobber; umask 077; cat > {path})` and paste the key, then Ctrl-D")
    };
    format!(
        "write the key to {path} (`mkdir -p -m 700 {dir}`, then {write}), replace `api_key_env = \"{var}\"` with `api_key_file = \"{file}\"` in {}",
        models_header(profile)
    )
}

/// Ok when `file` is a plain file name for the model keys directory, else the sentence saying which rule it breaks.
fn check_key_file_name(file: &str) -> Result<(), String> {
    const RULE: &str = "an api_key_file is a file name of at most 64 characters made of letters, digits, '.', '_' and '-', not starting with '.', so that it names nothing outside the model keys directory";
    let ok = !file.is_empty()
        && file.len() <= 64
        && !file.starts_with('.')
        && file.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(format!("api_key_file \"{file}\" is not allowed: {RULE}."))
    }
}

/// Largest key file `read_model_key` accepts.
const MAX_KEY_FILE_BYTES: u64 = 16 * 1024;

/// The key in `dir/name` (a model profile's `api_key_file`), trimmed. See *model API keys* above. The
/// file is opened without following a link and judged by the open descriptor. No message holds the key.
pub fn read_model_key(dir: &Path, name: &str) -> Result<String, String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = dir.join(name);
    let shown = shell_quote(&path.display().to_string());
    // Non-blocking, so that a FIFO put in the key's place is refused below instead of hanging the start.
    let open = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path);
    let file = match open {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "The key file {shown} does not exist. Make it with `mkdir -p -m 700 {dir}` and `(set -o noclobber; umask 077; cat > {shown})`, then type or paste the key and press Ctrl-D.",
                dir = shell_quote(&dir.display().to_string())
            ));
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!(
                "The key file {shown} is a symbolic link, which ferret does not follow. Replace it with a regular file holding the key: `rm {shown}`, then `(set -o noclobber; umask 077; cat > {shown})`."
            ));
        }
        Err(e) => {
            return Err(format!(
                "The key file {shown} cannot be opened: {e}. Fix its permissions or recreate it with `rm {shown}`, then `(set -o noclobber; umask 077; cat > {shown})`."
            ));
        }
    };
    let meta = file.metadata().map_err(|e| format!("The key file {shown} cannot be inspected: {e}."))?;
    if !meta.is_file() {
        return Err(format!(
            "The key file {shown} is not a regular file. Replace it with a regular file holding the key."
        ));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me {
        return Err(format!(
            "The key file {shown} belongs to another user (uid {}), not to you (uid {me}). Recreate it as yourself with `rm {shown}`, then `(set -o noclobber; umask 077; cat > {shown})`.",
            meta.uid()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "The key file {shown} can be read by other users (mode {:04o}). Run `chmod 600 {shown}`.",
            meta.mode() & 0o7777
        ));
    }
    let too_big = format!(
        "The key file {shown} is larger than 16 KiB, which is too big for a key. Replace it with a file holding only the key."
    );
    if meta.len() > MAX_KEY_FILE_BYTES {
        return Err(too_big);
    }
    let mut bytes = Vec::new();
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("The key file {shown} cannot be read: {e}."))?;
    if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(too_big);
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| format!("The key file {shown} is not UTF-8 text. Replace it with a file holding only the key."))?;
    let key = text.trim();
    if key.is_empty() {
        return Err(format!("The key file {shown} is empty. Write the key into it."));
    }
    if key.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "The key file {shown} holds white space or a control character inside the key. It must hold the key and nothing else."
        ));
    }
    Ok(key.to_string())
}

/// [`Config::profile`] over any set of profiles: the daemon keeps a live set that `ferret models reload`
/// replaces, and it resolves names against that set the same way.
pub fn resolve_profile<'a>(
    models: &'a BTreeMap<String, ModelProfile>,
    default_model: &str,
    name: Option<&str>,
) -> Result<(&'a str, &'a ModelProfile), ConfigError> {
    // Name what is configured and how to choose, so the operator is not left guessing.
    let configured = || {
        let mut names: Vec<&str> = models.keys().map(String::as_str).collect();
        names.sort_unstable();
        if names.is_empty() {
            "no model profiles are configured; add a [models.<name>] section".to_string()
        } else {
            format!("configured profiles: {}", names.join(", "))
        }
    };
    let wanted = match name {
        Some(n) if !n.is_empty() => n,
        _ if !default_model.is_empty() => default_model,
        _ if models.len() == 1 => models.keys().next().map(String::as_str).unwrap_or(""),
        _ => {
            return Err(ConfigError::Invalid(format!(
                "no model given and no default_model set. Pass --model <name> or set default_model in the config ({}).",
                configured()
            )));
        }
    };
    models.get_key_value(wanted).map(|(k, v)| (k.as_str(), v)).ok_or_else(|| {
        ConfigError::Invalid(format!(
            "no model profile named \"{wanted}\". Pass --model <name> or set default_model in the config ({}).",
            configured()
        ))
    })
}

/// Directory (inside `sessions/` or `missions/`) that ferret never creates. An id that is not a plain name maps to
/// a name below it, so a lookup for such an id finds nothing.
const UNSAFE_ID_DIR: &str = ".unsafe-ids";

/// The path, relative to the sessions or missions directory, that stands for `id`. Ids of ASCII letters, digits,
/// `-`, `_` and `.` (not starting with `.`, 1 to 128 bytes) are used as they are; any other id (separators,
/// parent references, NUL, empty, ...) maps to `.unsafe-ids/<sha256 of the id>`, which stays inside the tree.
fn id_dir(id: &str) -> PathBuf {
    let plain = !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    if plain {
        PathBuf::from(id)
    } else {
        Path::new(UNSAFE_ID_DIR).join(crate::sha256_hex(id.as_bytes()))
    }
}

/// Create `dir` (and any missing parents) with mode 0700; when it already exists with any group or other
/// permission bit, tighten it to 0700. Every directory the harness creates under the ferret home goes through this.
/// On non-Unix targets it only creates the directory. An empty path (the parent of a bare file name) names the
/// current directory, which is left as it is.
pub fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let meta = std::fs::metadata(dir)?;
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Where everything lives on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    /// `$FERRET_HOME`, else `$HOME/.ferret`.
    pub fn from_env() -> Paths {
        if let Some(home) = std::env::var_os("FERRET_HOME").filter(|v| !v.is_empty()) {
            return Paths { home: PathBuf::from(home) };
        }
        let base = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        Paths { home: base.join(".ferret") }
    }

    pub fn at(home: impl Into<PathBuf>) -> Paths {
        Paths { home: home.into() }
    }

    pub fn config_file(&self) -> PathBuf {
        self.home.join("config.toml")
    }
    pub fn token_file(&self) -> PathBuf {
        self.home.join("token")
    }
    pub fn keys_dir(&self) -> PathBuf {
        self.home.join("keys")
    }
    /// Where model API key files are (`api_key_file`).
    pub fn model_keys_dir(&self) -> PathBuf {
        self.keys_dir().join("models")
    }
    pub fn journal_key(&self) -> PathBuf {
        self.keys_dir().join("journal.key")
    }
    /// The key credential profiles are sealed with (CONTRACTS-TRAFFIC-TARGETS S4).
    pub fn creds_key(&self) -> PathBuf {
        self.keys_dir().join("creds.key")
    }
    pub fn sessions_dir(&self) -> PathBuf {
        self.home.join("sessions")
    }
    /// Where the targets live (`{name}/target.toml`, `{name}/graph.jsonl`).
    pub fn targets_dir(&self) -> PathBuf {
        self.home.join("targets")
    }
    pub fn session_dir(&self, id: &SessionId) -> PathBuf {
        self.sessions_dir().join(id_dir(id.as_str()))
    }
    pub fn session_log(&self, id: &SessionId) -> PathBuf {
        self.session_dir(id).join("log.jsonl")
    }
    /// The interception CA (`ferret-ca.pem`, `ferret-ca.key`; CONTRACTS-TRAFFIC-TARGETS I2). Under the ferret home,
    /// which no command can read.
    pub fn ca_dir(&self) -> PathBuf {
        self.home.join("ca")
    }
    /// Scratch directory a session's commands may write to.
    pub fn session_tmp(&self, id: &SessionId) -> PathBuf {
        self.session_dir(id).join("tmp")
    }
    /// Where agents' own copies of a workspace are made: beside the ferret home, not in it, because
    /// nothing under the home is writable to a session's commands. `~/.ferret` gives `~/.ferret-copies`.
    pub fn copies_dir(&self) -> PathBuf {
        let name = self.home.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "ferret".into());
        self.home.with_file_name(format!("{name}-copies"))
    }
    /// The copies of one mission's agents.
    pub fn mission_copies(&self, id: &MissionId) -> PathBuf {
        self.copies_dir().join(id_dir(id.as_str()))
    }
    /// The working copy of one agent of a mission.
    pub fn agent_copy(&self, mission: &MissionId, agent: &SessionId) -> PathBuf {
        self.mission_copies(mission).join(id_dir(agent.as_str()))
    }
    pub fn blobs_dir(&self) -> PathBuf {
        self.home.join("blobs")
    }
    pub fn missions_dir(&self) -> PathBuf {
        self.home.join("missions")
    }
    pub fn mission_dir(&self, id: &MissionId) -> PathBuf {
        self.missions_dir().join(id_dir(id.as_str()))
    }
    pub fn journal(&self, id: &MissionId) -> PathBuf {
        self.mission_dir(id).join("journal.jsonl")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.home.join("logs")
    }
    pub fn packs_dir(&self) -> PathBuf {
        self.home.join("packs")
    }

    /// Create the home and its top-level directories (keys, sessions, missions, blobs, logs) as private (0700)
    /// directories, tightening any that already exist with group or other access.
    pub fn ensure_private_layout(&self) -> std::io::Result<()> {
        ensure_private_dir(&self.home)?;
        for dir in [self.keys_dir(), self.sessions_dir(), self.missions_dir(), self.blobs_dir(), self.logs_dir()] {
            ensure_private_dir(&dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_sandbox_is_the_one_for_this_os() {
        let want = if cfg!(target_os = "linux") { SandboxMode::Bubblewrap } else { SandboxMode::Seatbelt };
        assert_eq!(SandboxMode::default(), want);
        assert_eq!(SandboxCfg::default().mode, want);
    }

    #[test]
    fn bubblewrap_and_reference_hosts_are_additive_config_options() {
        let c =
            Config::parse("[sandbox]\nmode = 'bubblewrap'\n[network]\nreference_hosts = ['docs.example.test:443']\n")
                .unwrap();
        assert_eq!(c.sandbox.mode, SandboxMode::Bubblewrap);
        assert_eq!(c.network.reference_hosts, ["docs.example.test:443"]);
        assert!(Config::parse("").unwrap().network.reference_hosts.is_empty());
        assert_eq!(Config::parse("[sandbox]\nmode = 'none'\n").unwrap().sandbox.mode, SandboxMode::None);
        assert!(Config::parse("[sandbox]\nreplay_untrusted_paths = ['/actor']\n").is_err());
        let cfg = SandboxCfg { replay_untrusted_paths: vec!["/actor".into()], ..SandboxCfg::default() };
        assert!(serde_json::to_value(cfg).unwrap().get("replay_untrusted_paths").is_none());
    }

    #[test]
    fn empty_file_is_default() {
        let c = Config::parse("").unwrap();
        assert_eq!(c, Config::default());
        c.check().unwrap();
        assert_eq!(c.daemon.bind, "127.0.0.1:7878");
        assert_eq!(c.admit.max_inline_tokens, 60_000);
    }

    #[test]
    fn network_is_closed_by_default() {
        assert_eq!(Config::default().network.mode, NetworkMode::DenyAll);
        assert_eq!(Config::parse("[agents]\nmax_children = 2\n").unwrap().network.mode, NetworkMode::DenyAll);
        assert_eq!(Config::parse("").unwrap().network.mode, NetworkMode::DenyAll);
    }

    #[test]
    fn parses_a_profile_with_extra_body() {
        let c = Config::parse(
            r#"
default_model = "lan"
[models.lan]
base_url = "http://10.0.0.5:8000/v1"
model = "m"
context_window = 1000000
[models.lan.extra_body]
reasoning_effort = "max"
temperature = 0.6
[context]
target_tokens = 300000
floor_tokens = 100000
[network]
mode = "allowlist"
allow = ["*.example.test"]
"#,
        )
        .unwrap();
        c.check().unwrap();
        let (name, p) = c.profile(None).unwrap();
        assert_eq!(name, "lan");
        assert_eq!(p.extra_body["reasoning_effort"], "max");
        assert_eq!(p.reasoning_replay, ReasoningReplay::All);
        // The old `[context]` keys load; `target_tokens` stands in for `compact_at_tokens`.
        assert_eq!(c.context.compact_at(Some(1_000_000)), 300_000);
        assert_eq!(c.context.warnings().len(), 1);
        assert_eq!(c.network.mode, NetworkMode::Allowlist);
    }

    #[test]
    fn speculation_is_on_unless_switched_off() {
        assert!(Config::parse("").unwrap().tools.speculate);
        assert!(!Config::parse("[tools]\nspeculate = false").unwrap().tools.speculate);
        assert_eq!(Config::parse("[tools]\ndialect = \"ferret\"").unwrap().tools.dialect, Dialect::Ferret);
        assert_eq!(Config::parse("[tools]\ndialect = \"loom\"").unwrap().tools.dialect, Dialect::Ferret);
    }

    #[test]
    fn agents_ergonomic_flags_defaults_and_overrides() {
        let def = AgentsCfg::default();
        assert!(!def.compact_tools);
        assert!(!def.implicit_finish);
        assert!(def.idle_ledger_nudge);
        assert!(def.project_instructions);
        assert!(!Config::parse("[agents]\nproject_instructions = false\n").unwrap().agents.project_instructions);

        let empty = Config::parse("").unwrap();
        assert_eq!(empty.agents, def);

        let partial = Config::parse("[agents]\nmax_children = 2\n").unwrap();
        assert!(!partial.agents.compact_tools);
        assert!(!partial.agents.implicit_finish);
        assert!(partial.agents.idle_ledger_nudge);

        let overridden =
            Config::parse("[agents]\ncompact_tools = true\nimplicit_finish = true\nidle_ledger_nudge = false\n")
                .unwrap();
        overridden.check().unwrap();
        assert!(overridden.agents.compact_tools);
        assert!(overridden.agents.implicit_finish);
        assert!(!overridden.agents.idle_ledger_nudge);
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(Config::parse("defualt_model = \"x\"").is_err());
        assert!(Config::parse("[daemon]\nbnd = \"x\"").is_err());
    }

    #[test]
    fn check_rejects_inconsistent_settings() {
        let mut c = Config::default();
        c.daemon.bind = "0.0.0.0:7878".into();
        assert!(c.check().is_err());
        // A window below the compaction size is not an error: a session clamps the size to it.
        let mut c = Config::default();
        c.models.insert("a".into(), ModelProfile { context_window: Some(100_000), ..Default::default() });
        assert!(c.check().is_ok());
        let mut c = Config::default();
        c.models.insert("a".into(), ModelProfile::default());
        c.default_model = "b".into();
        assert!(c.check().is_err());
    }

    #[test]
    fn mcp_check_and_warnings() {
        let ok = |t: &str| Config::parse(t).unwrap().check();
        assert!(ok("[mcp.servers.a-b_1]\ncommand = [\"x\"]").is_ok());
        assert!(ok("[mcp.servers.h]\nurl = \"https://e.com/mcp\"").is_ok());
        assert!(ok("[mcp.servers.A]\ncommand = [\"x\"]").is_err());
        assert!(ok(&format!("[mcp.servers.{}]\ncommand = [\"x\"]", "a".repeat(33))).is_err());
        assert!(ok("[mcp.servers.a]").is_err());
        assert!(ok("[mcp.servers.a]\ncommand = [\"x\"]\nurl = \"http://h\"").is_err());
        assert!(ok("[mcp.servers.a]\ncommand = []").is_err());
        assert!(ok("[mcp.servers.a]\nurl = \"ftp://h\"").is_err());
        assert!(ok("[mcp.servers.a]\ncommand = [\"x\"]\ntimeout_s = 0").is_err());
        assert!(Config::parse("[mcp.servers.a]\ncommand = [\"x\"]\nbogus = 1").is_err());
        let c = Config::parse(
            "[mcp.servers.a]\ncommand = [\"x\"]\nenv = { A = \"env:A\", B = \"lit\", C = \"file:/f\" }\n[mcp.servers.b]\nurl = \"http://h\"\nheaders = { Authorization = \"tok\" }",
        )
        .unwrap();
        let w = c.mcp.warnings();
        assert_eq!(w.len(), 2);
        assert!(w[0].contains("mcp.servers.a.env.B") && !w[0].contains("lit\""));
        assert!(w[1].contains("mcp.servers.b.headers.Authorization") && !w[1].contains("tok\""));
        assert!(Config::default().mcp.warnings().is_empty());
    }

    fn write_key(dir: &Path, name: &str, content: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn both_key_forms_are_refused() {
        let mut c = Config::default();
        c.models.insert(
            "m".into(),
            ModelProfile { api_key_file: Some("m".into()), api_key_env: Some("K".into()), ..Default::default() },
        );
        let e = c.check().unwrap_err().to_string();
        assert!(e.contains("models.m: set api_key_file or api_key_env, not both."), "{e}");
    }

    #[test]
    fn key_file_names_follow_the_rules() {
        for bad in ["", ".hidden", "a/b", "../x", "a b", "naïve", &"a".repeat(65), "a\u{0}b"] {
            let mut c = Config::default();
            c.models.insert("m".into(), ModelProfile { api_key_file: Some(bad.into()), ..Default::default() });
            let e = c.check().unwrap_err().to_string();
            assert!(e.contains("models.m") && e.contains("api_key_file"), "{bad:?}: {e}");
        }
        for good in ["m", "local-1", "a.b_c", &"a".repeat(64)] {
            let mut c = Config::default();
            c.models.insert("m".into(), ModelProfile { api_key_file: Some(good.into()), ..Default::default() });
            c.check().unwrap();
        }
    }

    #[test]
    fn read_model_key_returns_the_trimmed_key() {
        let d = tempfile::tempdir().unwrap();
        write_key(d.path(), "k", b"  sk-secret-123\n", 0o600);
        assert_eq!(read_model_key(d.path(), "k").unwrap(), "sk-secret-123");
        write_key(d.path(), "k400", b"abc", 0o400);
        assert_eq!(read_model_key(d.path(), "k400").unwrap(), "abc");
    }

    #[test]
    fn read_model_key_refusals_name_the_fix_and_never_hold_the_key() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();
        let missing = read_model_key(dir, "nope").unwrap_err();
        assert!(
            missing.contains("mkdir -p -m 700") && missing.contains("set -o noclobber; umask 077; cat >"),
            "{missing}"
        );
        assert!(missing.contains(&dir.join("nope").display().to_string()));
        write_key(dir, "real", b"sk-topsecret", 0o600);
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        let e = read_model_key(dir, "link").unwrap_err();
        assert!(e.contains("symbolic link") && !e.contains("sk-topsecret"), "{e}");
        std::fs::create_dir(dir.join("sub")).unwrap();
        assert!(read_model_key(dir, "sub").unwrap_err().contains("not a regular file"));
        for (mode, name) in [(0o640, "m640"), (0o604, "m604")] {
            write_key(dir, name, b"sk-topsecret", mode);
            let e = read_model_key(dir, name).unwrap_err();
            assert!(e.contains(&format!("chmod 600 {}", dir.join(name).display())), "{e}");
            assert!(!e.contains("sk-topsecret"));
        }
        write_key(dir, "empty", b"", 0o600);
        assert!(read_model_key(dir, "empty").unwrap_err().contains("empty"));
        write_key(dir, "blank", b" \n\t \n", 0o600);
        assert!(read_model_key(dir, "blank").unwrap_err().contains("empty"));
        write_key(dir, "inner", b"sk-topsecret more", 0o600);
        let e = read_model_key(dir, "inner").unwrap_err();
        assert!(e.contains("white space") && !e.contains("sk-topsecret"), "{e}");
        write_key(dir, "ctl", b"sk-top\x07secret", 0o600);
        let e = read_model_key(dir, "ctl").unwrap_err();
        assert!(e.contains("control") && !e.contains("sk-top"), "{e}");
        write_key(dir, "bin", &[0xff, 0xfe, b'a'], 0o600);
        assert!(read_model_key(dir, "bin").unwrap_err().contains("UTF-8"));
        write_key(dir, "big", &vec![b'a'; 16 * 1024 + 1], 0o600);
        let e = read_model_key(dir, "big").unwrap_err();
        assert!(e.contains("16 KiB") && !e.contains("aaaa"), "{e}");
        write_key(dir, "edge", &vec![b'a'; 16 * 1024], 0o600);
        assert_eq!(read_model_key(dir, "edge").unwrap().len(), 16 * 1024);
    }

    #[test]
    fn check_model_keys_names_the_profile() {
        let d = tempfile::tempdir().unwrap();
        let mut c = Config::default();
        c.models.insert("good".into(), ModelProfile { api_key_file: Some("good".into()), ..Default::default() });
        c.models.insert("bad".into(), ModelProfile { api_key_file: Some("bad".into()), ..Default::default() });
        c.models.insert("none".into(), ModelProfile::default());
        write_key(d.path(), "good", b"k", 0o600);
        let e = c.check_model_keys(d.path()).unwrap_err();
        assert!(e.starts_with("models.bad: "), "{e}");
        assert!(e.contains(&d.path().join("bad").display().to_string()));
        write_key(d.path(), "bad", b"k", 0o600);
        c.check_model_keys(d.path()).unwrap();
    }

    #[test]
    fn key_env_warnings_for_a_set_and_an_unset_variable() {
        let dir = Path::new("/h/keys/models");
        let mut c = Config::default();
        c.models.insert("a".into(), ModelProfile { api_key_env: Some("A_KEY".into()), ..Default::default() });
        c.models.insert("b".into(), ModelProfile { api_key_env: Some("B_KEY".into()), ..Default::default() });
        c.models.insert("f".into(), ModelProfile { api_key_file: Some("f".into()), ..Default::default() });
        c.models.insert("n".into(), ModelProfile::default());
        let w = c.key_env_warnings(dir, |v| v == "A_KEY");
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(w[0].contains("models.a") && w[0].contains("A_KEY") && w[0].contains("every command can read it"));
        assert!(w[1].contains("models.b") && w[1].contains("B_KEY is not set"));
        for line in &w {
            assert!(line.contains("api_key_file = ") && line.contains("restart the daemon"), "{line}");
        }
        assert!(w[0].contains("printenv A_KEY > /h/keys/models/a"), "{}", w[0]);
        // An unset variable would give an empty file through printenv: the key is pasted instead.
        assert!(!w[1].contains("printenv") && w[1].contains("cat > /h/keys/models/b"), "{}", w[1]);
        assert!(Config::default().key_env_warnings(dir, |_| true).is_empty());
    }

    #[test]
    fn suggested_key_names_are_unique_and_every_write_is_noclobber() {
        let dir = Path::new("/h/keys/models");
        let mut c = Config::default();
        for name in ["gpt 4", "gpt/4", "GPT-4"] {
            c.models.insert(name.into(), ModelProfile { api_key_env: Some("K".into()), ..Default::default() });
        }
        c.models.insert("taken".into(), ModelProfile { api_key_file: Some("gpt-4-2".into()), ..Default::default() });
        let names = c.suggested_key_files();
        assert_eq!(names.len(), 3, "{names:?}");
        let mut all: Vec<String> = names.values().map(|n| n.to_lowercase()).collect();
        all.push("gpt-4-2".into());
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 4, "{names:?}");
        for n in names.values() {
            assert!(check_key_file_name(n).is_ok(), "{n}");
        }
        // A long name is cut to fit 64 characters with its suffix.
        let mut c = Config::default();
        for name in ["a".repeat(64), format!("{}!", "a".repeat(70))] {
            c.models.insert(name, ModelProfile { api_key_env: Some("K".into()), ..Default::default() });
        }
        let names = c.suggested_key_files();
        assert!(names.values().all(|n| n.len() <= 64), "{names:?}");
        assert_ne!(names.values().next(), names.values().nth(1));
        for set in [true, false] {
            for line in c.key_env_warnings(dir, |_| set) {
                assert!(line.contains("set -o noclobber; umask 077; "), "{line}");
                assert!(!line.contains("(umask"), "{line}");
            }
        }
        let d = tempfile::tempdir().unwrap();
        let e = read_model_key(d.path(), "missing").unwrap_err();
        assert!(e.contains("set -o noclobber; umask 077; cat >") && !e.contains("(umask"), "{e}");
    }

    #[test]
    fn key_commands_are_shell_safe_for_unusual_profile_names_and_paths() {
        assert_eq!(shell_quote("/h/keys/a.b-c_d+e:f@g%h=i,j~k"), "/h/keys/a.b-c_d+e:f@g%h=i,j~k");
        assert_eq!(shell_quote("/h/my keys"), "'/h/my keys'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(suggested_key_file("good-name_1.k"), "good-name_1.k");
        assert_eq!(suggested_key_file("gpt 4/o"), "gpt-4-o");
        assert_eq!(suggested_key_file("..hid"), "hid");
        assert_eq!(suggested_key_file("..."), "model-key");
        assert_eq!(suggested_key_file(&"a".repeat(80)), "a".repeat(64));
        assert_eq!(suggested_key_file("日本"), "--");
        for p in ["gpt 4/o", "..x y", "", "日本", &"b c".repeat(40)] {
            assert!(check_key_file_name(&suggested_key_file(p)).is_ok(), "{p:?}");
        }
        assert_eq!(models_header("m-1_x"), "[models.m-1_x]");
        assert_eq!(models_header("gpt 4/o"), "[models.\"gpt 4/o\"]");
        assert_eq!(models_header("a\"b\\c"), "[models.\"a\\\"b\\\\c\"]");

        let dir = Path::new("/h/my keys/models");
        let mut c = Config::default();
        c.models.insert("gpt 4/o".into(), ModelProfile { api_key_env: Some("A_KEY".into()), ..Default::default() });
        let w = c.key_env_warnings(dir, |_| true);
        let line = &w[0];
        assert!(line.contains("mkdir -p -m 700 '/h/my keys/models'"), "{line}");
        assert!(line.contains("printenv A_KEY > '/h/my keys/models/gpt-4-o'"), "{line}");
        assert!(line.contains("api_key_file = \"gpt-4-o\"") && line.contains("[models.\"gpt 4/o\"]"), "{line}");
        let w = c.key_env_warnings(dir, |_| false);
        assert!(w[0].contains("cat > '/h/my keys/models/gpt-4-o'") && !w[0].contains("printenv"), "{}", w[0]);

        let d = tempfile::tempdir().unwrap();
        let spaced = d.path().join("my keys");
        let e = read_model_key(&spaced, "k").unwrap_err();
        assert!(e.contains(&format!("mkdir -p -m 700 '{}'", spaced.display())), "{e}");
        assert!(e.contains(&format!("cat > '{}'", spaced.join("k").display())), "{e}");
    }

    #[test]
    fn profile_selection() {
        let mut c = Config::default();
        assert!(c.profile(None).is_err());
        c.models.insert("only".into(), ModelProfile::default());
        assert_eq!(c.profile(None).unwrap().0, "only");
        c.models.insert("two".into(), ModelProfile::default());
        assert!(c.profile(None).is_err());
        assert_eq!(c.profile(Some("two")).unwrap().0, "two");
        assert!(c.profile(Some("nope")).is_err());
    }

    #[test]
    fn missing_file_is_default_and_paths_compose() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path());
        assert_eq!(Config::load(&p.config_file()).unwrap(), Config::default());
        let sid = SessionId::from("s-1");
        assert!(p.session_log(&sid).ends_with("sessions/s-1/log.jsonl"));
        assert!(p.journal(&MissionId::from("m-1")).ends_with("missions/m-1/journal.jsonl"));
    }

    #[cfg(unix)]
    #[test]
    fn private_layout_creates_0700_and_tightens_existing_directories() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path().join(".ferret"));
        // The operator made the home and one of its directories first, as `mkdir -p ~/.ferret/packs` would.
        std::fs::create_dir_all(p.packs_dir()).unwrap();
        std::fs::create_dir(p.sessions_dir()).unwrap();
        for d in [&p.home, &p.packs_dir(), &p.sessions_dir()] {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p.ensure_private_layout().unwrap();
        for d in [p.home.clone(), p.keys_dir(), p.sessions_dir(), p.missions_dir(), p.blobs_dir(), p.logs_dir()] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
        }
        // Directories the harness does not create are left as they were.
        assert_eq!(mode(&p.packs_dir()), 0o755);
        // A second call changes nothing and fails nowhere.
        p.ensure_private_layout().unwrap();
    }

    #[test]
    fn an_empty_private_dir_path_is_the_current_directory_and_left_alone() {
        // The parent of a bare file name is empty; it names a directory that exists and is not the harness's.
        assert!(Path::new("log.jsonl").parent().is_some_and(|p| p.as_os_str().is_empty()));
        ensure_private_dir(Path::new("")).unwrap();
    }

    #[test]
    fn ids_never_map_outside_the_tree() {
        let dir = tempfile::tempdir().unwrap();
        let p = Paths::at(dir.path());
        std::fs::create_dir_all(p.session_dir(&SessionId::from("s-real"))).unwrap();
        std::fs::create_dir_all(p.mission_dir(&MissionId::from("m-real"))).unwrap();
        // Ids ferret generates and the importer writes pass unchanged.
        for ok in ["s-0123456789abcdef", "s-dsh0123456789abcdef", "m-x_y.z", &"a".repeat(128)] {
            assert_eq!(p.session_dir(&SessionId::from(ok)), p.sessions_dir().join(ok));
            assert_eq!(p.mission_dir(&MissionId::from(ok)), p.missions_dir().join(ok));
        }
        let generated = SessionId::generate();
        assert_eq!(p.session_dir(&generated), p.sessions_dir().join(generated.as_str()));
        let long = "a".repeat(129);
        for bad in
            ["", ".", "..", "../s-real", "s-real/..", "a/b", "/etc", ".hidden", "s-real\0", "s\0", "a b", "é", &long]
        {
            let s = p.session_dir(&SessionId::from(bad));
            let m = p.mission_dir(&MissionId::from(bad));
            assert!(s.starts_with(p.sessions_dir().join(UNSAFE_ID_DIR)), "{bad:?} -> {}", s.display());
            assert!(m.starts_with(p.missions_dir().join(UNSAFE_ID_DIR)), "{bad:?} -> {}", m.display());
            assert!(!s.exists() && !m.exists(), "{bad:?}");
            assert!(!s.components().any(|c| matches!(c, std::path::Component::ParentDir)));
            assert_eq!(s, p.session_dir(&SessionId::from(bad)), "deterministic");
            assert!(p.session_log(&SessionId::from(bad)).starts_with(p.sessions_dir()));
            assert!(p.journal(&MissionId::from(bad)).starts_with(p.missions_dir()));
        }
        assert_ne!(p.session_dir(&SessionId::from("a/b")), p.session_dir(&SessionId::from("a\\b")));
    }

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn box_cfg(extra: &str) -> Result<Config, String> {
        let text = format!(
            "[box]\nenabled = true\nssh_host = \"ferret-box\"\nremote_socket = \"/var/run/docker.sock\"\nimage = \"{DIGEST}\"\nhelper_image = \"img@{DIGEST}\"\n{extra}"
        );
        let c = Config::parse(&text)?;
        c.check().map_err(|e| e.to_string())?;
        Ok(c)
    }

    #[test]
    fn box_is_off_by_default_and_parses_when_pinned() {
        assert!(!Config::default().boxed.enabled);
        assert!(Config::parse("").unwrap().check().is_ok());
        let c = box_cfg("cap_add = [\"SYS_PTRACE\", \"cap_net_raw\"]").unwrap();
        assert!(c.boxed.enabled);
        assert_eq!(c.boxed.caps(), ["SYS_PTRACE", "NET_RAW"]);
        assert_eq!((c.boxed.cpus, c.boxed.memory_mb, c.boxed.pids), (4, 8192, 512));
        assert!(Config::parse("[box]\nbogus = 1").is_err());
    }

    #[test]
    fn i2_cap_add_rejects_exactly_the_dangerous_capabilities() {
        for cap in BOX_FORBIDDEN_CAPS {
            for spelled in
                [cap.to_string(), cap.to_lowercase(), format!("CAP_{cap}"), format!("cap_{}", cap.to_lowercase())]
            {
                let err = box_cfg(&format!("cap_add = [\"{spelled}\"]")).unwrap_err();
                assert!(err.contains("never gives the box"), "{spelled}: {err}");
            }
        }
        // The rejection holds when the box is not enabled too: nothing unsafe is kept in a config.
        let err = Config::parse("[box]\ncap_add = [\"SYS_ADMIN\"]").unwrap().check().unwrap_err().to_string();
        assert!(err.contains("SYS_ADMIN"), "{err}");
        for ok in ["SYS_PTRACE", "NET_RAW", "CAP_SYS_PTRACE", "NET_BIND_SERVICE", "SYS_CHROOT"] {
            assert!(box_cfg(&format!("cap_add = [\"{ok}\"]")).is_ok(), "{ok}");
        }
        assert!(box_cfg("cap_add = [\"not a cap\"]").unwrap_err().contains("not a capability name"));
    }

    #[test]
    fn i3_image_must_be_pinned_by_digest() {
        for tag in ["ubuntu:24.04", "ubuntu", "ubuntu@sha256:abc", "sha256:ABCDEF", "latest", "x@sha1:0123"] {
            let text = format!(
                "[box]\nenabled = true\nssh_host = \"h\"\nremote_socket = \"/s\"\nimage = \"{tag}\"\nhelper_image = \"{DIGEST}\""
            );
            let err = Config::parse(&text).unwrap().check().unwrap_err().to_string();
            assert!(err.contains("not pinned") && err.contains("A tag can be moved"), "{tag}: {err}");
        }
        assert!(pinned_image(DIGEST));
        assert!(pinned_image(&format!("registry.example:5000/a/b@{DIGEST}")));
        assert!(!pinned_image(&format!("@{DIGEST}")));
        assert!(!pinned_image(&format!("-x@{DIGEST}")));
        // The helper image is pinned the same way.
        let text = format!(
            "[box]\nenabled = true\nssh_host = \"h\"\nremote_socket = \"/s\"\nimage = \"{DIGEST}\"\nhelper_image = \"alpine:3\""
        );
        assert!(Config::parse(&text).unwrap().check().unwrap_err().to_string().contains("box.helper_image"));
    }

    #[test]
    fn box_enabled_needs_one_route_to_docker_and_sane_values() {
        let base = format!("[box]\nenabled = true\nimage = \"{DIGEST}\"\nhelper_image = \"{DIGEST}\"\n");
        let check = |extra: &str| Config::parse(&format!("{base}{extra}")).unwrap().check().map_err(|e| e.to_string());
        assert!(check("").unwrap_err().contains("exactly one way"));
        assert!(check("docker_socket = \"/s\"").is_ok());
        assert!(check("docker_socket = \"/s\"\nssh_host = \"h\"\nremote_socket = \"/r\"")
            .unwrap_err()
            .contains("exactly one way"));
        assert!(check("ssh_host = \"h\"").unwrap_err().contains("together"));
        assert!(check("ssh_host = \"-oProxyCommand=x\"\nremote_socket = \"/r\"").unwrap_err().contains("ssh_host"));
        assert!(check("ssh_host = \"h\"\nremote_socket = \"/r:/etc\"").unwrap_err().contains("remote_socket"));
        assert!(check("docker_socket = \"relative.sock\"").unwrap_err().contains("absolute"));
        assert!(check("docker_socket = \"/s\"\ncpus = 0").unwrap_err().contains("cpus"));
        assert!(Config::parse("[box]\nenabled = true").unwrap().check().unwrap_err().to_string().contains("box.image"));
    }

    #[test]
    fn mach_allow_takes_exact_names_and_prefixes_but_never_a_fetch_or_disk_service() {
        let check = |entries: &str| {
            Config::parse(&format!("[sandbox]\nmach_allow = [{entries}]")).unwrap().check().map_err(|e| e.to_string())
        };
        assert!(check("").is_ok());
        assert!(check("\"com.apple.pasteboard.1\", \"com.apple.system.*\"").is_ok());
        for bad in [
            "\"com.apple.trustd\"",
            "\"com.apple.trustd.*\"",
            "\"com.apple.WebKit.Networking\"",
            "\"com.apple.nsurlsessiond*\"",
            "\"com.apple.diskimagesiod\"",
            "\"com.apple.*\"",
            "\"*\"",
            "\"co*\"",
        ] {
            let err = check(bad).unwrap_err();
            assert!(err.contains("sandbox.mach_allow") && err.contains("allow"), "{bad}: {err}");
        }
        let fetch = check("\"com.apple.ocspd\"").unwrap_err();
        assert!(fetch.contains("com.apple.ocspd") && fetch.contains("sandbox.allow_fetch_services"), "{fetch}");
        for malformed in ["\"\"", "\"a b\"", "\"x*y\"", "\"a\\\"b\""] {
            assert!(check(malformed).unwrap_err().contains("not a Mach service name"), "{malformed}");
        }
        assert!(Config::parse("[sandbox]\nallow_fetch_services = true").unwrap().sandbox.allow_fetch_services);
        assert!(!Config::default().sandbox.allow_fetch_services);
    }

    #[test]
    fn nproc_headroom_defaults_to_256_and_zero_turns_the_limit_off() {
        assert_eq!(Config::default().sandbox.nproc_headroom, 256);
        assert_eq!(Config::parse("[sandbox]\nnproc_headroom = 0").unwrap().sandbox.nproc_headroom, 0);
        assert_eq!(Config::parse("[sandbox]\nnproc_headroom = 1000").unwrap().sandbox.nproc_headroom, 1000);
        assert!(Config::parse("[sandbox]\nnproc_headroom = -1").is_err());
    }

    #[test]
    fn the_built_in_mach_allowlist_has_no_fetch_or_disk_service() {
        for name in MACH_LOOKUP_ALLOW.iter().chain(MACH_LOOKUP_ALLOW_PREFIXES.iter()) {
            assert!(
                !FETCH_SERVICE_NAMES.contains(name)
                    && !DISK_SERVICE_NAMES.contains(name)
                    && !FETCH_SERVICE_PREFIXES.iter().any(|p| name.starts_with(p)),
                "{name}"
            );
        }
    }

    #[test]
    fn r10_the_box_is_refused_with_no_sandbox_and_with_its_socket_in_unix_sockets() {
        // The box with no sandbox: the agent's own commands could reach the socket.
        let err = box_cfg("[sandbox]\nmode = \"none\"").unwrap_err();
        assert!(err.contains("sandbox.mode") && err.contains("Docker socket"), "{err}");
        // Without the box, mode none stays what it was.
        assert!(Config::parse("[sandbox]\nmode = \"none\"").unwrap().check().is_ok());
        let home = Path::new("/home/x/.ferret");
        let with = |sockets: &str, extra: &str| {
            Config::parse(&format!(
                "[sandbox]\nunix_sockets = [{sockets}]\n[box]\nenabled = true\nimage = \"{DIGEST}\"\nhelper_image = \"{DIGEST}\"\n{extra}"
            ))
            .unwrap()
        };
        let ssh = "ssh_host = \"h\"\nremote_socket = \"/r\"";
        for bad in [
            "\"/home/x/.ferret/keys/box.sock\"",
            "\"/home/x/.ferret/keys\"",
            "\"/home/x/.ferret/keys/anything/else\"",
            "\"/home/x/.ferret/./keys/../keys/box.sock\"",
        ] {
            let c = with(bad, ssh);
            assert!(c.check().is_ok(), "the load-time check does not know the home");
            let err = c.check_box_paths(home).unwrap_err();
            assert!(err.contains("inside /home/x/.ferret/keys"), "{bad}: {err}");
        }
        assert!(with("\"/run/other.sock\", \"/home/x/.ferret/keysx/s\"", ssh).check_box_paths(home).is_ok());
        // The local socket of the box is refused as well, and only when the box is enabled.
        let err =
            with("\"/var/run/box.sock\"", "docker_socket = \"/var/run/box.sock\"").check_box_paths(home).unwrap_err();
        assert!(err.contains("box.docker_socket"), "{err}");
        assert!(with("\"/var/run/box.sock\"", ssh).check_box_paths(home).is_ok());
    }

    #[test]
    fn lineage_keys_and_monitor_table_parse() {
        let c = Config::parse(
            r#"
[models.dsv41]
model = "deepseek-v4.1"
family = ["deepseek"]
alignment = "stock"
recipient = "lan"
[models.dsv41_review]
purpose = "review"
[models.qwen4max]
family = ["Qwen"]
recipient = "alibaba"
[monitor]
reviewers = ["dsv41_review", "qwen4max"]
tripwires_only_profiles = ["dsv41"]
known_families = ["acme"]
[monitor.recipients]
ctf = ["alibaba"]
[monitor.content]
new_recipient_real_targets = "redacted"
"#,
        )
        .unwrap();
        c.check().unwrap();
        assert_eq!(c.models["dsv41"].alignment, Some(Alignment::Stock));
        assert_eq!(c.models["dsv41_review"].purpose, Some(ProfilePurpose::Review));
        assert_eq!(c.monitor.content.new_recipient_real_targets, RecipientContent::Redacted);
        assert_eq!(Config::default().monitor, MonitorCfg::default());
        assert_eq!(MonitorCfg::default().content.new_recipient_real_targets, RecipientContent::Features);
        assert!(Config::parse("[models.a]\nalignment = \"uncensored\"\n").is_err(), "alignment is a closed set");
        assert!(Config::parse("[models.a]\npurpose = \"agent\"\n").is_err());
        // A reserved word names no family, in a profile's key and in known_families.
        for w in ["unknown", "Any", "none", "*"] {
            let c = Config::parse(&format!("[models.a]\nfamily = [\"{w}\"]\n[monitor]\nknown_families = [\"{w}\"]\n"))
                .unwrap();
            let e = c.check().unwrap_err().to_string();
            assert!(e.contains("models.a.family") && e.contains("remove the key") && !e.contains("add \""), "{e}");
            let c = Config::parse(&format!("[models.a]\n[monitor]\nknown_families = [\"{w}\"]\n")).unwrap();
            let e = c.check().unwrap_err().to_string();
            assert!(e.contains("monitor.known_families") && e.contains("Remove it"), "{e}");
        }
        // A review profile is not the default agent profile.
        let c = Config::parse("default_model = \"r\"\n[models.r]\npurpose = \"review\"\n").unwrap();
        assert!(c.check().unwrap_err().to_string().contains("default_model \"r\" has purpose = \"review\""));
        assert!(Config::parse("[monitor]\nallow_new_recipient = true\n").is_err(), "there is no global key");
    }

    #[test]
    fn check_refuses_bad_lineage_and_monitor_settings() {
        let with = |text: &str| Config::parse(text).unwrap().check().unwrap_err().to_string();
        let e = with("[models.a]\nfamily = []\n");
        assert!(e.contains("models.a.family") && e.contains("empty list"), "{e}");
        let e = with("[models.a]\nfamily = [\"deepseeq\"]\n");
        assert!(e.contains("\"deepseeq\"") && e.contains("known_families") && e.contains("deepseek"), "{e}");
        assert!(Config::parse("[models.a]\nfamily = [\"acme\"]\n[monitor]\nknown_families = [\"Acme\"]\n")
            .unwrap()
            .check()
            .is_ok());
        let e = with("[models.a]\nrecipient = \" \"\n");
        assert!(e.contains("models.a.recipient is empty"), "{e}");
        let e = with("[models.a]\n[monitor]\nreviewers = [\"b\"]\n");
        assert!(e.contains("monitor.reviewers") && e.contains("\"b\"") && e.contains("[models.b]"), "{e}");
        let e = with("[models.a]\n[monitor]\nreviewers = [\"a\", \"a\"]\n");
        assert!(e.contains("twice"), "{e}");
        let e = with("[models.a]\nalignment = \"relaxed\"\n[monitor]\nreviewers = [\"a\"]\n");
        assert!(e.contains("never a reviewer"), "{e}");
        let e = with("[models.glm_uncensored]\nmodel = \"glm-5\"\n[monitor]\nreviewers = [\"glm_uncensored\"]\n");
        assert!(e.contains("never a reviewer"), "a relaxed marker in the name counts: {e}");
        let e = with("[models.a]\n[monitor]\ntripwires_only_profiles = [\"zzz\"]\n");
        assert!(e.contains("tripwires_only_profiles") && e.contains("zzz"), "{e}");
        let e = with("[monitor.recipients]\nctf = [\"unknown\"]\n");
        assert!(e.contains("monitor.recipients.ctf") && e.contains("never eligible"), "{e}");
        let e = with("[monitor.recipients]\n\"\" = [\"x\"]\n");
        assert!(e.contains("pack name"), "{e}");
        let e = with("[monitor]\nknown_families = [\" \"]\n");
        assert!(e.contains("known_families"), "{e}");
    }

    #[test]
    fn signal_config_validation() {
        assert!(Config::parse("").unwrap().check().is_ok());
        let ok_cfg = r#"
[signal]
enabled = true
http_url = "http://127.0.0.1:1337"
account = "+15550100"
recipient = "+15550199"
allow_from = ["+15550199"]
"#;
        assert!(Config::parse(ok_cfg).unwrap().check().is_ok());

        // Signal Phone Number Privacy users address recipients/senders by ACI/PNI UUID instead of E.164.
        for uuid in [
            "00000000-0000-4000-8000-000000000001",
            "u:00000000-0000-4000-8000-000000000001",
            "PNI:00000000-0000-4000-8000-000000000001",
        ] {
            let uuid_cfg = ok_cfg.replace("\"+15550199\"", &format!("\"{uuid}\""));
            assert!(Config::parse(&uuid_cfg).unwrap().check().is_ok(), "{uuid}");
        }

        // Typos and non-E.164/non-UUID entries in allow_from are refused instead of silently dropping replies.
        for bad in ["*", "15550199", "+1-555-0199", "alice", "+123", "not-a-uuid"] {
            let bad_allow = ok_cfg.replace("allow_from = [\"+15550199\"]", &format!("allow_from = [\"{bad}\"]"));
            assert!(Config::parse(&bad_allow).unwrap().check().is_err(), "{bad}");
        }

        let empty_allow = ok_cfg.replace("[\"+15550199\"]", "[]");
        assert!(Config::parse(&empty_allow).unwrap().check().is_err());

        // allow_groups accepts both raw group IDs and `group:<id>`, normalizing on load.
        let group_cfg = format!("{ok_cfg}allow_groups = [\"group:abc123==\", \"def456==\"]\n");
        let parsed = Config::parse(&group_cfg).unwrap();
        parsed.check().unwrap();
        assert_eq!(parsed.signal.allow_groups, vec!["abc123==", "def456=="]);
        assert_eq!(parsed.signal.normalized_allow_groups(), vec!["abc123==", "def456=="]);

        for bad_group in ["", "group:", "group:   ", "*", "group:*", "a b", "group:a b"] {
            let bad_cfg = format!("{ok_cfg}allow_groups = [\"{bad_group}\"]\n");
            assert!(Config::parse(&bad_cfg).unwrap().check().is_err(), "{bad_group:?}");
        }

        let bad_event = format!("{ok_cfg}events = [\"bogus\"]\n");
        assert!(Config::parse(&bad_event).unwrap().check().is_err());
    }
}
