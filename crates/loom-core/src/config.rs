//! Configuration (`~/.loom/config.toml`) and the on-disk layout.
//!
//! Every field has a default, so an empty file is a valid config. Unknown keys are rejected so that a
//! typo is an error rather than a silently ignored setting.

use crate::admit::AdmitPolicy;
use crate::event::ReasoningReplay;
use crate::ids::{MissionId, SessionId};
use crate::weave::ReweavePolicy;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    #[error("{path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("config: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Name of the profile in `models` used when a session does not name one.
    pub default_model: String,
    pub daemon: DaemonCfg,
    pub models: BTreeMap<String, ModelProfile>,
    pub context: ReweavePolicy,
    pub admit: AdmitPolicy,
    pub tools: ToolsCfg,
    pub sandbox: SandboxCfg,
    pub network: NetworkCfg,
    pub agents: AgentsCfg,
    pub notify: NotifyCfg,
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
    /// Name of an environment variable holding the API key, when the server wants one.
    pub api_key_env: Option<String>,
    /// Context window in tokens. When absent it is discovered from the server's model list.
    pub context_window: Option<u64>,
    /// `max_tokens` sent with each request. Absent = not sent (the server's default applies).
    pub max_output_tokens: Option<u64>,
    pub reasoning_replay: ReasoningReplay,
    /// Fields added to every request body verbatim (`reasoning_effort`, `temperature`, `top_p`, …).
    /// Fixed for the life of a session: some templates render them into the request head.
    pub extra_body: Map<String, Value>,
    /// Concurrent requests this server is given, across all sessions.
    pub max_concurrent: u32,
    /// Abort and retry a stream that delivers nothing for this long.
    pub stall_timeout_s: u64,
    /// How long to keep retrying an unreachable or failing server, in seconds (default 300, long
    /// enough for a server relaunch). 0 = retry until the server comes back. Failures that waiting
    /// cannot cure (a reply that is not an event stream, a stream that ends without a finish reason,
    /// certificate errors) are given up after a few repeats whatever this is set to.
    pub retry_window_s: u64,
    /// Longest pause between retries.
    pub retry_max_delay_s: u64,
}

impl Default for ModelProfile {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8000/v1".into(),
            model: "default".into(),
            api_key_env: None,
            context_window: None,
            max_output_tokens: None,
            reasoning_replay: ReasoningReplay::All,
            extra_body: Map::new(),
            max_concurrent: 4,
            stall_timeout_s: 240,
            retry_window_s: 300,
            retry_max_delay_s: 30,
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
    pub web_fetch_timeout_s: u64,
    pub web_fetch_max_bytes: u64,
    /// A command whose output grows past this is stopped, and the result says so.
    pub max_output_bytes: u64,
    /// How long `job_wait` waits when the call gives no time.
    pub job_wait_s: u64,
}

impl Default for ToolsCfg {
    fn default() -> Self {
        Self {
            bash_foreground_s: 300,
            kill_grace_s: 5,
            read_max_lines: 2_000,
            search_max_results: 200,
            web_fetch_timeout_s: 60,
            web_fetch_max_bytes: 20 * 1024 * 1024,
            max_output_bytes: 64 * 1024 * 1024,
            job_wait_s: 120,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    /// macOS `sandbox-exec` profile.
    #[default]
    Seatbelt,
    /// No OS sandbox. Reported on every session start.
    None,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxCfg {
    pub mode: SandboxMode,
    /// Extra directories commands may write to (absolute paths).
    pub extra_writable: Vec<String>,
    /// Paths that are never writable, even inside the workspace (absolute, or relative to it).
    pub protected_paths: Vec<String>,
    /// Paths that are not readable (absolute; `~` is expanded).
    pub unreadable_paths: Vec<String>,
    /// Loopback TCP ports commands may connect to directly (local test services).
    pub loopback_ports: Vec<u16>,
    /// Allow commands to connect to any loopback port (needed to talk to servers they start).
    pub loopback_all: bool,
    /// Unix sockets commands may connect to (absolute paths), e.g. a container runtime's socket.
    pub unix_sockets: Vec<String>,
    /// Environment variables passed to commands even though their names look like secrets.
    pub env_pass: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Any public destination.
    #[default]
    Open,
    /// Only destinations matching `allow`.
    Allowlist,
    DenyAll,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkCfg {
    pub mode: NetworkMode,
    /// Host patterns: `example.test`, `*.example.test`, optionally `:port`.
    pub allow: Vec<String>,
    /// Host patterns that are always refused.
    pub deny: Vec<String>,
    /// Private, loopback or link-local destinations that are permitted (same pattern syntax, or CIDR).
    pub allow_private: Vec<String>,
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
    /// Steps without a new ledger entry before the harness adds a stall note.
    pub stall_steps: u32,
    /// Run an independent verifier before a lead's `finish` is accepted.
    pub verify_finish: bool,
    /// Consecutive invalid tool calls before the next request forces a tool call.
    pub invalid_calls_before_forcing: u32,
    /// Outputs with at least this many lines never shown are listed in the HUD.
    pub unviewed_min_lines: u64,
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
            invalid_calls_before_forcing: 3,
            unviewed_min_lines: 20,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyCfg {
    /// Program run for each notification with the title and body as its two arguments. When empty
    /// the daemon uses the platform's notification command.
    pub command: Vec<String>,
    /// Repeat the notification for an unanswered blocking item after this many minutes (0 = never).
    pub repeat_minutes: u32,
}

impl Config {
    /// Load a config file. A missing file is the default config.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(source) => return Err(ConfigError::Io { path: path.to_path_buf(), source }),
        };
        let config = Config::parse(&text).map_err(|message| ConfigError::Parse { path: path.to_path_buf(), message })?;
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
        let host = self.daemon.bind.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
        if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") {
            return Err(ConfigError::Invalid(format!("daemon.bind must be a loopback address, got \"{}\"", self.daemon.bind)));
        }
        if self.context.floor_tokens >= self.context.target_tokens {
            return Err(ConfigError::Invalid("context.floor_tokens must be below context.target_tokens".into()));
        }
        for (name, profile) in &self.models {
            if profile.max_concurrent == 0 {
                return Err(ConfigError::Invalid(format!("models.{name}.max_concurrent must be at least 1")));
            }
            if let Some(window) = profile.context_window {
                if self.context.target_tokens >= window {
                    return Err(ConfigError::Invalid(format!(
                        "context.target_tokens ({}) must be below models.{name}.context_window ({window})",
                        self.context.target_tokens
                    )));
                }
            }
        }
        Ok(())
    }

    /// The profile a session should use: `name` when given, else `default_model`, else the only one.
    pub fn profile(&self, name: Option<&str>) -> Result<(&str, &ModelProfile), ConfigError> {
        let wanted = match name {
            Some(n) if !n.is_empty() => n,
            _ if !self.default_model.is_empty() => self.default_model.as_str(),
            _ if self.models.len() == 1 => self.models.keys().next().map(String::as_str).unwrap_or(""),
            _ => return Err(ConfigError::Invalid("no model profile named and no default_model set".into())),
        };
        self.models
            .get_key_value(wanted)
            .map(|(k, v)| (k.as_str(), v))
            .ok_or_else(|| ConfigError::Invalid(format!("no model profile named \"{wanted}\"")))
    }
}

/// Where everything lives on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    pub home: PathBuf,
}

impl Paths {
    /// `$LOOM_HOME`, else `$HOME/.loom`.
    pub fn from_env() -> Paths {
        if let Some(home) = std::env::var_os("LOOM_HOME").filter(|v| !v.is_empty()) {
            return Paths { home: PathBuf::from(home) };
        }
        let base = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        Paths { home: base.join(".loom") }
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
    pub fn journal_key(&self) -> PathBuf {
        self.keys_dir().join("journal.key")
    }
    pub fn sessions_dir(&self) -> PathBuf {
        self.home.join("sessions")
    }
    pub fn session_dir(&self, id: &SessionId) -> PathBuf {
        self.sessions_dir().join(id.as_str())
    }
    pub fn session_log(&self, id: &SessionId) -> PathBuf {
        self.session_dir(id).join("log.jsonl")
    }
    /// Scratch directory a session's commands may write to.
    pub fn session_tmp(&self, id: &SessionId) -> PathBuf {
        self.session_dir(id).join("tmp")
    }
    pub fn blobs_dir(&self) -> PathBuf {
        self.home.join("blobs")
    }
    pub fn missions_dir(&self) -> PathBuf {
        self.home.join("missions")
    }
    pub fn mission_dir(&self, id: &MissionId) -> PathBuf {
        self.missions_dir().join(id.as_str())
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_is_default() {
        let c = Config::parse("").unwrap();
        assert_eq!(c, Config::default());
        c.check().unwrap();
        assert_eq!(c.daemon.bind, "127.0.0.1:7878");
        assert_eq!(c.admit.max_inline_tokens, 60_000);
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
        assert_eq!(c.context.keep_recent_steps, 60);
        assert_eq!(c.network.mode, NetworkMode::Allowlist);
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
        let mut c = Config::default();
        c.context.floor_tokens = c.context.target_tokens;
        assert!(c.check().is_err());
        let mut c = Config::default();
        c.models.insert("a".into(), ModelProfile { context_window: Some(100_000), ..Default::default() });
        assert!(c.check().is_err());
        let mut c = Config::default();
        c.models.insert("a".into(), ModelProfile::default());
        c.default_model = "b".into();
        assert!(c.check().is_err());
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
}
