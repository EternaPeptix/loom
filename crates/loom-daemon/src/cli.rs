//! The `loom` command.
//!
//! CONTRACT.
//! Every command except `daemon`, `up`, `config` and `service` is a client of the daemon
//! (`Client::from_home(&Paths::from_env())`). Errors are printed to stderr as `loom: {sentence}`
//! and the exit code is 1 unless stated. Output goes to stdout; colour only when stdout is a
//! terminal and `NO_COLOR` is not set; width from `COLUMNS`, else `ioctl(TIOCGWINSZ)`, else 100.
//! The global flag `--unverified-daemon` (`client::allow_unverified_daemon`) accepts, with a warning
//! line on stderr, a listener that cannot prove it is this home's daemon (one from an older `loom`).
//!
//! ## Commands
//! - `daemon`: `serve::run`. `up`: `serve::spawn_background`, then print `loom is running on
//!   {bind}` (or `already running`). When it started the daemon, each line of
//!   `config.key_env_warnings(paths.model_keys_dir(), …)` judged against `loom up`'s own environment (which
//!   `daemon_env` passes on) is printed first, on stderr, as `warning: {line}`; a config that cannot be
//!   loaded prints none (`spawn_background` reports it). `down`: `client.shutdown()`, wait until it stops answering
//!   (10 s), then until the old process lets go of `<home>/daemon.lock` (2 × `tools.kill_grace_s` + 30 s;
//!   past that an error names its pid), print `stopped`. When nothing answers, the lock is held and
//!   `daemon.json` names a live pid (a daemon still shutting down), only the second wait.
//! - `status`: `render::status`. Exit 1 when the daemon is not running (with the usual sentence).
//! - `open`: request a login code and open `http://{bind}/#code={code}` (`/usr/bin/open` on macOS,
//!   `xdg-open` elsewhere); `--print` only prints it. The API token is never printed or passed on argv, and
//!   neither is the login code: the opener is given the path of a page file (`<home>/login/login-{random}.html`,
//!   mode 0600 in a private directory, a refresh and `location.replace` to the address, no referrer) and
//!   not the address; pages older than five minutes are removed by the next `open`. A file that cannot be
//!   written, or an opener that fails, is an error that says to use `loom open --print`. The opener gets a
//!   `.html` file, which the desktop opens with whatever handles `.html` (not always a browser), so after a
//!   successful hand-over one line is printed: `OPENED_NOTE`, which says to run `loom open --print` when an
//!   editor opened instead.
//! - `run [options] <message…>`: start a session and follow it. The message is the arguments
//!   joined by spaces; `-` or no message reads standard input to its end. Options → `NewSession`
//!   (`--workspace` defaults to the current directory; `--attended` sets `unattended: false`;
//!   `--max-steps`/`--max-minutes` → budget; each `--agent-model ROLE=PROFILE` → `role_models`, `all`
//!   as `*`; `--create-workspace` → `create_workspace`: the daemon makes the folder when it does not exist, and
//!   `created workspace {path}` goes to stderr before `session {id}` when it did; a `~` or `~/x` workspace is sent
//!   as written, for the daemon to expand; `--prior <mission>`, repeatable, → `prior` in the order
//!   given: earlier missions for this one to recall, `loom_agent::prior`; the same options serve `chat`, which
//!   refuses `--prior` with `--session`: a mission recalls when it starts). A
//!   `--prior` word that starts with `m-` is a mission id, sent as it is; any other word is resolved as a
//!   session (`client.resolve`: an id, a prefix, or `last`) and its `mission` is sent. Prints `session {id}` to stderr first. With
//!   `--detach`, stops there. Otherwise *follows* (below).
//! - `chat [options]`: a `chat`-role session on the terminal: prompt `› `, read a line (an empty
//!   line is ignored, end of input or `/quit` leaves), send it, follow until the turn ends, repeat.
//!   `--session <id>` continues an existing session instead of starting one.
//! - `ls [-a]`: `render::sessions_table` (`-a`: archived too).
//! - `tail <session> [--since <seq>] [--no-follow] [--reasoning] [--full] [--verbose]`: print the
//!   session's records and keep following. `--no-follow` prints what exists and stops.
//! - `send <session> <text…> [--file PATH]…` (`-` = standard input), then follows unless `--detach`. Each
//!   `--file` is read and uploaded (`upload_files`: `client.upload` into the session's workspace, `docs/UPLOADS.md`)
//!   before the message, which carries the returned paths as attachments; with files the text may be empty.
//!   `run` takes `--file` the same way (the workspace must exist: it is uploaded to before the session is made).
//! - `stop <session>`, `resume <session>`, `compact <session>` (alias `reweave`), `archive <session> [--undo]`: the
//!   call, then one line saying what was asked (`stop requested for {id}`).
//! - `rule <session> <text…>` (`-` = standard input): `client.add_rule`; `rule sent to {lead}`.
//!   `rule <session> --withdraw <rule-id> [--reason <text>]`: `client.withdraw_rule`; `withdrawal of
//!   {rule-id} sent to {lead}`. `approve <session> <text…> [--scope <text>]`: `client.approve`;
//!   `approval sent to {lead}`. A child's id reaches its lead, which the line names. The line is
//!   made from the daemon's receipt (`receipt_line`): `sent to` an idle lead, which records it at
//!   once; `queued for` a lead in a turn, which records it at its next step (`… queued for {lead}:
//!   the lead is in a turn and records it at its next step, not while a tool call is running; check
//!   with loom ledger {lead}`). It also names a stock scope or reason that was recorded for a blank
//!   one, and says when the mission keeps no ledger (the rule is then a note without an id).
//! - `scope <session> <host>… [--note <text>]`: `client.grant_scope`, one host per argument (`'*.example.com'`
//!   quoted); the operator's grant of network hosts to the mission, for the session's lifetime. Prints
//!   `scope granted for {lead}: a, b` (`scope_line`, from the daemon's receipt), and says when the mission
//!   keeps no ledger. The command an agent's scope request (`loom inbox`) asks the operator to run.
//! - `scope revoke <mission> --reason <text> <host>`: `client.revoke_scope` (`mission_of`: an `m-` id as it is, or
//!   the mission of a session word); the operator withdraws one granted host, written as it was granted. Prints
//!   `scope revoked for {lead}: {host}; {n} session(s) narrowed, {n} connection(s) cut` (`scope_revoke_line`),
//!   and says when the mission keeps no ledger or the grant was not in the ledger yet. A host that is not
//!   granted is refused with the list of what is. `--reason` is required.
//!   `release <session> <reason…>` (`-` = standard input): `client.release`; the operator closes the mission
//!   without the goal established. Prints `closed by operator, goal not established: release sent to {lead}`
//!   (`release_line`). A blank reason is refused.
//! - `gc [--apply]`: `client.gc`; one line with what was examined, kept and would be (or was) deleted.
//! - `inbox`: `render::inbox_list`. `answer <item> <text…>`: `client.answer`; `answered {item}`.
//! - `ledger <session|mission>`: the ledger's `markdown`, then one line for each of `LedgerView::notices`
//!   (entries written by a newer loom that are not shown, an ignored torn tail, entries past the head record).
//! - `score <session|mission> [--json]`: `client.score` of the mission, as `render::score_table`
//!   followed by `Harness tax: <summary>`; with `--json` the `ScoreView` itself, indented, for a
//!   script that compares runs.
//! - `window <session>`: `render::window_table`. `net <session> [-n <limit>]`: `render::net_table`, then
//!   `render::granted_hosts_line` from the mission's ledger (left out when the ledger cannot be read).
//! - `out <handle> [--lines <a>:<b>]`: the stored output's lines (all of it, paged 5 000 lines at a
//!   time, without `--lines`), passed through `render::clean`.
//! - `config path` prints the config file's path; `config check` loads and checks it, reads every
//!   `api_key_file` (`check_model_keys`) and runs the daemon's other start-up checks (sandbox preflight, box
//!   paths, the infrastructure deny: `loom_agent::runtime::check_infrastructure`): the error (naming the file
//!   when it is the file's) and exit 1 for any of them. Then it checks the model policy against the packs
//!   (`loom_agent::monitor::lineage::check_config`): one line per profile with its resolved family, alignment and
//!   recipient and where each came from (stdout), each note on stderr as `note: {line}`, and, when a problem is found
//!   (an agent profile with no eligible reviewer that is not in `[monitor] tripwires_only_profiles`, an unknown
//!   family or recipient, a reviewer whose family, alignment or recipient is not declared, a policy that cannot be
//!   evaluated), the error `The model policy is not settled (n to fix):`
//!   with each problem and the exact lines to add, exit 1; else `ok: {path}`, and each line of `key_env_warnings` judged
//!   against this shell's environment on stderr as `warning: {line}`. `config init` writes [`DEFAULT_CONFIG`] if no
//!   file exists (refuses to overwrite: `{path} already exists.`). `DEFAULT_CONFIG` leaves `tripwires_only_profiles`
//!   commented out, so a first `config check` fails and lays out the three choices: not LLM-reviewed is a choice the
//!   operator makes, never a default.
//! - `models list`: `render::models_table` of `GET /api/models`. `models reload`: `POST
//!   /api/models/reload`, `render::models_reload` of the report. `models set <session> <profile>`:
//!   resolves the session, `POST /api/sessions/{id}/model`, `render::model_switch_line`. `models show
//!   <session>`: `render::mission_models_table` of `GET /api/sessions/{id}/models`. `models role
//!   <session> <role> <profile> [--now]` / `--clear`: `POST /api/sessions/{id}/role-model` (`all` sent
//!   as `*`), `render::role_model_receipt`. None needs a restart; the daemon refuses with its sentence
//!   (an unknown profile names the configured ones). `models lineage [profile]` prints the lines of `config check`
//!   with, for each agent profile and pack, who reviews it (`lineage::show_lines`); it reads the configuration
//!   and the packs and needs no daemon.
//! - `monitor [status]`: `client.monitor_status`; the monitor's state (`shadow`, `degraded`, `down` with its reason), what it
//!   has read, its open flags, the faults of its sources and one row per tripwire with its hits by severity
//!   (`monitor_status_lines`; every line goes through `render::clean` and has no line break, since a tripwire's detail and key carry strings an agent chose). `monitor log <mission|session> [--json] [--since 90m|12h|7d|<ms>] [--all] [-n N]`:
//!   `client.monitor_log` (`mission_of` resolves the word), paged until N entries; one line per entry in words
//!   (`monitor_entry_line`), or the stored JSON per line with `--json`; `--all` includes `cursor` and `heartbeat`.
//!   `monitor replay [--since …] [--positives FILE] [--home DIR] [--no-journal-key] [--json]`: runs
//!   `loom_agent::monitor::replay::run` in this process over the home (the current one, or a copy), read-only and with
//!   no daemon; reads `keys/journal.key` unless `--no-journal-key`; prints the report as a table with notes, or as JSON.
//!   A `--since` that is not `90m`, `12h`, `7d` or milliseconds is an error that says so (`parse_since`).
//! - `service install|uninstall|status` (macOS; elsewhere `This command is for macOS (launchd).`):
//!   `install` first loads the config and refuses (nothing written) a profile that sets `api_key_env`: a
//!   launchd agent does not have the shell's variables, so its requests would carry no key, and putting
//!   the key in the plist would write it to disk and the daemon's environment; the sentence names the
//!   profile and the variable and gives the move of `key_env_warnings`. It also refuses what
//!   `check_model_keys` refuses. Then it prepares the home (`serve::prepare_home`), creates `{logs}/loomd.log` (0600) if it is missing,
//!   writes `serve::launch_agent_plist` to `~/Library/LaunchAgents/{SERVICE_LABEL}.plist`
//!   and runs `launchctl bootstrap gui/{uid} {plist}`; `uninstall` runs `launchctl bootout
//!   gui/{uid}/{SERVICE_LABEL}` and removes the file; `status` runs `launchctl print` and says
//!   whether it is loaded.
//!
//! `<session>` is resolved with `client.resolve` (an id, the beginning of one, or `last`).
//!
//! ## Following a session
//! `client.stream(id, after)`; each `Record` event → `render::record` → stdout. On a terminal,
//! `Delta` events are shown live as they arrive (reasoning dim, text plain) on the lines below the
//! last record and are erased (`\r\x1b[J` after moving up) when the `model_response` record that
//! contains them arrives; not on a terminal, deltas are ignored. `Lagged` → re-open the stream
//! after the last record seq printed. A lost connection → re-open, up to 5 times one second apart,
//! then the error.
//! Following ends when a `turn_end` record arrives with a reason other than `Waiting`, or a
//! `session_end`. Exit code: 0 after `Finished` or `Yielded`; 2 after `Asked`, `Blocked` or
//! `Parked` (the operator is needed — the inbox item was printed); 1 after `Stopped`,
//! `BudgetExhausted` or `Error`.
//! Ctrl-C while following stops following, not the session: it prints `still running — loom tail
//! {id} to watch, loom stop {id} to stop it` and exits 130.
//!
//! Tests required (`clap` parsing and the pure parts; the calls themselves are covered by the
//! client's tests): every command parses with its options and rejects a missing argument; `run`
//! and `send` message joining and `-`; `--lines` parsing (`10:20`, `10:`, `:20`, bad forms);
//! `--create-workspace` parsing and its `NewSession`; `follow_exit_code` for every turn end; `DEFAULT_CONFIG` parses with `Config::parse` and passes
//! `check()`; `open_url`; `open` hands the address to the browser and writes it only with `--print`;
//! the service-install key check refuses a profile with `api_key_env` (naming it and the variable) and a
//! missing key file, and passes a config whose profiles use `api_key_file` or no key.

use crate::client::{self, Client};
use crate::render::{self, RecordOpts, Style};
use clap::{Args, Parser, Subcommand};
use loom_agent::runtime::{BusEvent, Delta, NewSession, RuleReceipt, ScopeReceipt, ScopeRevokeReceipt, ANY_ROLE};
use loom_agent::session::Phase;
use loom_core::config::{Config, ConfigError, Paths};
use loom_core::event::{Budget, Event, Record, Seq, SessionOutcome, TurnEndReason};
use loom_core::{MissionId, SessionId};
use std::future::Future;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A config file that works against a model server on this machine, with every setting that
/// matters named. Written by `loom config init`.
pub const DEFAULT_CONFIG: &str = r#"# loom configuration. Every setting has a default; this file names the ones worth knowing.

default_model = "local"

[daemon]
bind = "127.0.0.1:7878"

# One table per model server. `base_url` is an OpenAI-compatible endpoint.
[models.local]
base_url = "http://127.0.0.1:8000/v1"
model = "default"
# context_window = 1000000   # only needed when the server does not report it; the context bounds below are clamped to it automatically
max_concurrent = 4           # requests in flight at once (lead, agents and votes together)
retry_window_s = 300         # keep retrying an unreachable server this long; 0 = until it returns

[context]
# The window is compacted (the model writes a note, old output stays readable by key, nothing is lost) when a
# request reaches compact_at_tokens. 0 = 40% of the model's window, never above 400000; a session clamps it to a
# smaller model window automatically, so a small context_window needs no change here.
compact_at_tokens = 0

[sandbox]
# The OS sandbox every command runs in. Left out, it is the one for this system: "bubblewrap" on Linux
# (needs the bwrap binary), "seatbelt" on macOS. "none" runs commands unconfined and is said at start.
# mode = "bubblewrap"

[network]
# deny_all (the default): tools reach no host through the egress proxy.
# To let them reach chosen hosts, use:  mode = "allowlist"  with  allow = ["*.example.com"]
#   (allowlist: only hosts matching `allow` are reachable.)
# To let them reach any public host, use:  mode = "open"   (open: every public destination is reachable.)
# Private and local addresses are refused unless listed in allow_private.
mode = "deny_all"
allow_private = []

[agents]
max_children = 6
verify_finish = true
unavailable_notice_s = 300   # tell you (inbox item, notification) when a request has retried this long; 0 = never

[monitor]
# Who may review whose missions is a model-policy choice (docs/MONITOR.md). A profile with no reviewer must be named here
# on purpose; its missions are then watched by the deterministic tripwires only. `loom config check` says what to add
# (a reviewer, or this line), and `loom models lineage` shows who reviews what. Uncommenting the line is that choice:
# tripwires_only_profiles = ["local"]
"#;

#[derive(Parser, Debug)]
#[command(name = "loom", version, about = "An agent harness for long, unattended work on a local model")]
pub struct Cli {
    /// Talk to a daemon that cannot prove it is this home's (one started by an older loom); the token is sent anyway
    #[arg(long, global = true)]
    pub unverified_daemon: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the daemon in the foreground
    Daemon,
    /// Start the daemon in the background if it is not running
    Up,
    /// Stop the daemon (sessions resume when it starts again)
    Down,
    /// Show the daemon, its models and what is running
    Status,
    /// Open the web UI
    Open(OpenArgs),
    /// Start a session with a message and follow it
    Run(RunArgs),
    /// Talk to a chat session on the terminal
    Chat(ChatArgs),
    /// List sessions
    Ls(LsArgs),
    /// Print a session's record and follow it
    Tail(TailArgs),
    /// Send a message to a session
    Send(SendArgs),
    /// Stop a session's current turn, its jobs and its agents
    Stop(SessionArg),
    /// Let a stopped session carry on
    Resume(SessionArg),
    /// Fold old tool output out of a session's context now
    #[command(alias = "reweave")]
    Compact(SessionArg),
    /// Hide a finished session (or bring it back with --undo)
    Archive(ArchiveArgs),
    /// Rename a mission (set its lead session's title)
    Rename(RenameArgs),
    /// Set a standing rule for a mission (or withdraw one with --withdraw)
    Rule(RuleArgs),
    /// Record an approval for a mission
    Approve(ApproveArgs),
    /// Let a mission's tools reach hosts (the operator's grant; ends with the session)
    Scope(ScopeArgs),
    /// Close a mission without the goal established, giving the reason
    Release(ReleaseArgs),
    /// Delete stored tool outputs that no session or mission refers to any more (dry run unless --apply)
    ///
    /// Collects stored outputs older than one hour whose id or `out:` handle appears in no file under the
    /// sessions and missions directories. Removing a session's directory is what makes its outputs
    /// collectable; an output that another session or a mission still names is kept.
    Gc(GcArgs),
    /// List what is waiting for you
    Inbox,
    /// Answer an inbox item
    Answer(AnswerArgs),
    /// Print a mission's ledger
    Ledger(SessionArg),
    /// Count what a mission's work took: steps, refused finishes, malformed calls, verdicts
    ///
    /// One row per session of the mission and a total. The counts are of the records in the logs:
    /// they say what the work cost and how often the harness sent it back, not whether the result
    /// is right.
    Score(ScoreArgs),
    /// Show what is in a session's context
    Window(SessionArg),
    /// Show a session's network requests and how each was decided
    Net(NetArgs),
    /// Print a stored tool output
    Out(OutArgs),
    /// Targets: named scopes that missions share, with a graph of what they found
    Target {
        #[command(subcommand)]
        action: TargetAction,
    },
    /// The interception CA (CONTRACTS-TRAFFIC-TARGETS I2)
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// The configuration file
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// The adversarial monitor in shadow: its state, its log, a replay over history
    Monitor(MonitorArgs),
    /// The model profiles: list them, reload them from the config, switch a session's model, and who reviews them
    Models {
        #[command(subcommand)]
        action: ModelsAction,
    },
    /// MCP servers: the configured ones, and a start-and-list check of one
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// Run the daemon as a login service (macOS)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum McpAction {
    /// The configured servers with their transport and roles (read from the configuration file)
    List,
    /// Start a configured server in a scratch sandbox, list its tools and close it
    Check(McpCheckArgs),
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct McpCheckArgs {
    /// The server's name in [mcp.servers]
    pub server: String,
    /// The workspace to run it for (default: the current directory)
    #[arg(long)]
    pub workspace: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct OpenArgs {
    /// Print the address instead of opening a browser
    #[arg(long)]
    pub print: bool,
}

#[derive(Args, Debug, Default)]
pub struct StartOpts {
    /// Directory the session works in (default: the current directory)
    #[arg(short, long)]
    pub workspace: Option<PathBuf>,
    #[arg(long)]
    pub pack: Option<String>,
    #[arg(long)]
    pub role: Option<String>,
    /// Model profile from the configuration
    #[arg(short, long)]
    pub model: Option<String>,
    /// Model profile for the mission's agents of a role, as ROLE=PROFILE; repeatable; `all=PROFILE` for every role
    #[arg(long = "agent-model", value_name = "ROLE=PROFILE", value_parser = parse_agent_model)]
    pub agent_models: Vec<(String, String)>,
    #[arg(short, long)]
    pub title: Option<String>,
    /// Do not resume by itself after a restart
    #[arg(long)]
    pub attended: bool,
    #[arg(long, default_value_t = 0)]
    pub max_steps: u32,
    #[arg(long, default_value_t = 0)]
    pub max_minutes: u32,
    /// An earlier mission for this one to recall: a mission id (m-…), or a session id, prefix or `last`
    /// (its mission). Repeat for more
    #[arg(long, value_name = "MISSION")]
    pub prior: Vec<String>,
    /// Make the workspace folder (and the folders above it) when it does not exist
    #[arg(long)]
    pub create_workspace: bool,
    /// A target (`loom target add`) for the mission to work on: its scope joins the network rules and its
    /// graph is shared with the other missions of the target
    #[arg(long, value_name = "NAME")]
    pub target: Option<String>,
    /// Do not decrypt HTTPS for this mission, whatever its pack says (`[network] intercept = "pack"` only)
    #[arg(long)]
    pub no_intercept: bool,
}

#[derive(Args, Debug)]
pub struct ShowOpts {
    /// Print reasoning in full
    #[arg(long)]
    pub reasoning: bool,
    /// Never cut arguments or output
    #[arg(long)]
    pub full: bool,
    #[arg(short, long)]
    pub verbose: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub start: StartOpts,
    #[command(flatten)]
    pub show: ShowOpts,
    /// Start it and return
    #[arg(short, long)]
    pub detach: bool,
    /// Attach a file (uploaded to the workspace first, which must exist); repeatable. The task may then be empty
    #[arg(long = "file", value_name = "PATH")]
    pub files: Vec<PathBuf>,
    /// The task ("-" or nothing: read standard input)
    pub message: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ChatArgs {
    #[command(flatten)]
    pub start: StartOpts,
    #[command(flatten)]
    pub show: ShowOpts,
    /// Continue this session instead of starting one
    #[arg(long)]
    pub session: Option<String>,
}

#[derive(Args, Debug)]
pub struct LsArgs {
    /// Include archived sessions
    #[arg(short, long)]
    pub all: bool,
}

#[derive(Args, Debug)]
pub struct TailArgs {
    pub session: String,
    /// Start after this record number
    #[arg(long)]
    pub since: Option<u64>,
    #[arg(long)]
    pub no_follow: bool,
    #[command(flatten)]
    pub show: ShowOpts,
}

#[derive(Args, Debug)]
pub struct SendArgs {
    pub session: String,
    #[command(flatten)]
    pub show: ShowOpts,
    #[arg(short, long)]
    pub detach: bool,
    /// While the lead is in a turn, hold the message until the turn ends instead of giving it to the lead at its
    /// next step. An idle lead takes it at once, as without the flag
    #[arg(long)]
    pub after_turn: bool,
    /// Attach a file (uploaded to the session's workspace first); repeatable. The message may then be empty
    #[arg(long = "file", value_name = "PATH")]
    pub files: Vec<PathBuf>,
    /// The message ("-" or nothing: read standard input)
    pub text: Vec<String>,
}

#[derive(Args, Debug)]
pub struct SessionArg {
    /// A session id, the beginning of one, or `last`
    pub session: String,
}

#[derive(Args, Debug)]
pub struct ArchiveArgs {
    /// A session id, the beginning of one, or `last`
    pub session: String,
    /// Bring an archived session back instead of hiding it
    #[arg(long)]
    pub undo: bool,
}

#[derive(Args, Debug)]
pub struct RenameArgs {
    /// A session id, the beginning of one, or `last` (the mission's lead)
    pub session: String,
    /// The new title (quote it if it has spaces); the words are joined with a space
    #[arg(required = true)]
    pub title: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ScoreArgs {
    /// A session id, the beginning of one, `last`, or a mission id
    pub session: String,
    /// Print the counts as JSON, for a script that compares runs
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GcArgs {
    /// Delete them (the default only reports what would be deleted)
    #[arg(long)]
    pub apply: bool,
}

#[derive(Args, Debug)]
pub struct AnswerArgs {
    pub item: String,
    pub text: Vec<String>,
}

#[derive(Args, Debug)]
pub struct RuleArgs {
    /// A session id, the beginning of one, or `last`
    pub session: String,
    /// Withdraw the rule with this id (such as k1) instead of setting one; say why with --reason
    #[arg(long, value_name = "RULE_ID", conflicts_with = "text")]
    pub withdraw: Option<String>,
    /// Why the rule is withdrawn (left out: recorded as "no reason given")
    #[arg(long, requires = "withdraw")]
    pub reason: Option<String>,
    /// The rule ("-": read standard input)
    pub text: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ApproveArgs {
    /// A session id, the beginning of one, or `last`
    pub session: String,
    /// What the approval covers (left out: a ledger records "only what the approval says")
    #[arg(long)]
    pub scope: Option<String>,
    /// What is approved ("-": read standard input)
    pub text: Vec<String>,
}

#[derive(Args, Debug)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct ScopeArgs {
    #[command(subcommand)]
    pub action: Option<ScopeAction>,
    /// A session id, the beginning of one, or `last`
    #[arg(required = true)]
    pub session: Option<String>,
    /// Why the hosts are granted (kept in the ledger)
    #[arg(long)]
    pub note: Option<String>,
    /// The hosts, one per argument, such as api.example.com or '*.example.com'
    #[arg(required = true)]
    pub hosts: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum ScopeAction {
    /// Withdraw a granted host from a mission: its open connections are cut and new ones refused
    Revoke(ScopeRevokeArgs),
}

#[derive(Args, Debug)]
pub struct ScopeRevokeArgs {
    /// A mission id (`m-…`), or a session id, the beginning of one, or `last`
    pub mission: String,
    /// The host exactly as it was granted
    pub host: String,
    /// Why (kept in the ledger and shown to the lead)
    #[arg(long)]
    pub reason: String,
}

#[derive(Args, Debug)]
pub struct MonitorArgs {
    #[command(subcommand)]
    pub action: Option<MonitorAction>,
}

#[derive(Subcommand, Debug)]
pub enum MonitorAction {
    /// The monitor's state, its open flags and what each tripwire has fired (the default)
    Status,
    /// The monitor-log entries about a mission
    Log(MonitorLogArgs),
    /// Run the tripwires over the history of a loom home, read-only, and report per tripwire
    Replay(MonitorReplayArgs),
}

#[derive(Args, Debug)]
pub struct MonitorLogArgs {
    /// A mission id (`m-…`), or a session id, the beginning of one, or `last`
    pub target: String,
    /// One JSON object per line, as stored
    #[arg(long)]
    pub json: bool,
    /// Only entries newer than this: `90m`, `12h`, `7d`, or a time in milliseconds since the epoch
    #[arg(long)]
    pub since: Option<String>,
    /// Include the housekeeping entries (`cursor`, `heartbeat`)
    #[arg(long)]
    pub all: bool,
    /// At most this many entries
    #[arg(short = 'n', long, default_value_t = 200)]
    pub limit: usize,
}

#[derive(Args, Debug)]
pub struct MonitorReplayArgs {
    /// Only hits newer than this: `90m`, `12h`, `7d`, or a time in milliseconds since the epoch
    #[arg(long)]
    pub since: Option<String>,
    /// The report as JSON
    #[arg(long)]
    pub json: bool,
    /// A file of mission ids, one per line, known to be positives: precision and recall are reported against them
    #[arg(long)]
    pub positives: Option<PathBuf>,
    /// Replay this loom home instead of the current one (a copy of one; it is only read)
    #[arg(long)]
    pub home: Option<PathBuf>,
    /// Do not read `keys/journal.key`: the ledgers are read unverified
    #[arg(long)]
    pub no_journal_key: bool,
}

#[derive(Args, Debug)]
pub struct ReleaseArgs {
    /// A session id, the beginning of one, or `last`
    pub session: String,
    /// Why the result is accepted without the goal established ("-": read standard input)
    pub reason: Vec<String>,
}

#[derive(Args, Debug)]
pub struct NetArgs {
    pub session: String,
    #[arg(short = 'n', long, default_value_t = 200)]
    pub limit: usize,
}

#[derive(Args, Debug)]
pub struct OutArgs {
    /// A handle such as out:7f3a9c1e
    pub handle: String,
    /// A line range: 10:20, 10: or :20
    #[arg(long)]
    pub lines: Option<String>,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum TargetAction {
    /// List the targets with how many nodes have each status
    List,
    /// Create a target
    Add(TargetAddArgs),
    /// Show a target: its scope and settings, and its nodes by status
    Show(TargetShowArgs),
    /// Change what a target covers: add or remove scope and exclude entries
    Scope(TargetScopeArgs),
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct TargetAddArgs {
    /// The name: a-z, 0-9, `-` and `_`
    pub name: String,
    /// A scope entry (host, `*.domain`, IP or CIDR); repeatable
    #[arg(long, value_name = "ENTRY")]
    pub scope: Vec<String>,
    /// An entry that is never reachable, whatever else allows it; repeatable
    #[arg(long, value_name = "ENTRY")]
    pub exclude: Vec<String>,
    #[arg(long)]
    pub notes: Option<String>,
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct TargetShowArgs {
    pub name: String,
    /// Print the nodes too
    #[arg(long)]
    pub nodes: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct TargetScopeArgs {
    pub name: String,
    /// Scope entries to add; repeatable
    #[arg(long, value_name = "ENTRY")]
    pub add: Vec<String>,
    /// Scope entries to remove; repeatable
    #[arg(long, value_name = "ENTRY")]
    pub remove: Vec<String>,
    /// Exclude entries to add; repeatable
    #[arg(long, value_name = "ENTRY")]
    pub exclude: Vec<String>,
    /// Exclude entries to remove; repeatable
    #[arg(long, value_name = "ENTRY")]
    pub unexclude: Vec<String>,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaAction {
    /// Print the CA's fingerprint and the file of its certificate (made when missing)
    Show,
    /// Replace the CA with a new one
    Rotate,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigAction {
    /// Print the path of the configuration file
    Path,
    /// Validate the configuration — parse, sandbox preflight and box paths — and name the file checked
    Check,
    /// Write a starting configuration file (refuses to overwrite an existing one)
    Init,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ModelsAction {
    /// List the model profiles in use, with each server's state (the default one is marked)
    List,
    /// Read [models] and default_model from the config again and use them now, without a restart
    Reload,
    /// Switch a session to another model profile, from its next step, without a restart
    Set(ModelsSetArgs),
    /// A mission's models: its lead's, the one chosen for each role of its agents, the agents running now
    Show(ModelsShowArgs),
    /// Choose the model a mission starts its agents of a role on (`all` for every role), or clear it
    Role(ModelsRoleArgs),
    /// Each profile's family, alignment and recipient (and where each came from), and who reviews its missions
    /// (reads the configuration and the packs; needs no daemon)
    Lineage {
        /// Only this profile
        profile: Option<String>,
    },
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct ModelsShowArgs {
    /// A session id, the beginning of one, or `last` (any session of the mission)
    pub session: String,
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct ModelsRoleArgs {
    /// A session id, the beginning of one, or `last` (any session of the mission)
    pub session: String,
    /// The agents' role (`loom models show` lists them), or `all` for every role the lead starts
    pub role: String,
    /// The model profile (`loom models list`); left out with --clear
    #[arg(required_unless_present = "clear", conflicts_with = "clear")]
    pub profile: Option<String>,
    /// Remove the choice: the pack chooses again for agents started later
    #[arg(long)]
    pub clear: bool,
    /// Also move the mission's running agents of that role now (not forked ones)
    #[arg(long, conflicts_with = "clear")]
    pub now: bool,
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct ModelsSetArgs {
    /// A session id, the beginning of one, or `last`
    pub session: String,
    /// The model profile to switch it to (`loom models list` shows them)
    pub profile: String,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    /// Install and start the login service so the daemon runs at login (macOS launchd)
    Install,
    /// Stop and remove the login service
    Uninstall,
    /// Show whether the login service is installed and loaded
    Status,
}
/// Run one command; the result is the process's exit code.
pub async fn run(cli: Cli) -> i32 {
    if cli.unverified_daemon {
        client::allow_unverified_daemon();
    }
    match dispatch(cli.command).await {
        Ok(code) => code,
        Err(e) => {
            // An empty sentence means the output was closed (`loom tail | head`): nothing to say.
            if !e.is_empty() {
                errln(&format!("loom: {e}"));
            }
            1
        }
    }
}

/// The words of a message argument joined by spaces; `None` when standard input should be read
/// (no words, or the single word `-`).
pub fn message_from_args(words: &[String]) -> Option<String> {
    match words {
        [] => None,
        [one] if one == "-" => None,
        _ => Some(words.join(" ")),
    }
}

/// `10:20` → `(10, Some(20))`, `10:` → `(10, None)`, `:20` → `(1, Some(20))`. Lines are 1-based;
/// `0`, a reversed range and anything else is an error sentence.
pub fn parse_lines(text: &str) -> Result<(u64, Option<u64>), String> {
    let bad = || format!("`{text}` is not a line range. Use 10:20, 10: or :20 (lines count from 1).");
    let (a, b) = text.trim().split_once(':').ok_or_else(bad)?;
    let (a, b) = (a.trim(), b.trim());
    if a.is_empty() && b.is_empty() {
        return Err(bad());
    }
    let start = if a.is_empty() { 1 } else { a.parse::<u64>().map_err(|_| bad())? };
    let end = if b.is_empty() { None } else { Some(b.parse::<u64>().map_err(|_| bad())?) };
    if start == 0 || end == Some(0) {
        return Err(format!("`{text}` names line 0; lines count from 1."));
    }
    if end.is_some_and(|e| e < start) {
        return Err(format!("`{text}` is a reversed range; write the smaller line number first."));
    }
    Ok((start, end))
}

/// Exit code of a followed session whose turn ended with `reason`; `None` = keep following.
pub fn follow_exit_code(reason: TurnEndReason) -> Option<i32> {
    match reason {
        TurnEndReason::Waiting => None,
        TurnEndReason::Yielded | TurnEndReason::Finished => Some(0),
        TurnEndReason::Asked | TurnEndReason::Blocked | TurnEndReason::Parked => Some(2),
        TurnEndReason::Stopped | TurnEndReason::BudgetExhausted | TurnEndReason::Error => Some(1),
    }
}

/// `http://{bind}/#code={code}`: the fragment is never sent to a server or kept in a log.
pub fn open_url(bind: &str, code: &str) -> String {
    format!("http://{bind}/#code={code}")
}

// ---------------------------------------------------------------------------------------------
// Output

fn errln(text: &str) {
    let _ = writeln!(std::io::stderr(), "{text}");
}

/// Write to standard output and flush; a closed output is the empty error.
fn put(out: &mut dyn Write, text: &str) -> Result<(), String> {
    out.write_all(text.as_bytes()).and_then(|_| out.flush()).map_err(|_| String::new())
}

/// Standard output, locked only for the length of one write so nothing is held across an await.
struct StdoutSink;

impl Write for StdoutSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::stdout().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stdout().flush()
    }
}

/// A line on standard output.
fn outln(text: &str) -> Result<(), String> {
    put(&mut StdoutSink, &format!("{text}\n"))
}

/// Text from `render` (which may or may not end in a newline) on standard output.
fn block(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Ok(());
    }
    if text.ends_with('\n') {
        put(&mut StdoutSink, text)
    } else {
        outln(text)
    }
}

fn format_score_text(view: &loom_agent::runtime::ScoreView, style: &Style) -> String {
    let mut text = render::score_table(view, style);
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("Harness tax: {}\n", view.total.harness_tax_summary()));
    text
}

fn terminal_width() -> usize {
    if let Some(n) = std::env::var("COLUMNS").ok().and_then(|v| v.trim().parse::<usize>().ok()).filter(|&n| n > 0) {
        return n;
    }
    let mut ws = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // SAFETY: TIOCGWINSZ only writes a `winsize` through the pointer, which points at a live local;
    // on a descriptor that is not a terminal the call fails and `ws` stays zero.
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 && ws.ws_col > 0 {
        usize::from(ws.ws_col)
    } else {
        100
    }
}

/// Colour only on a terminal and without `NO_COLOR`.
fn style() -> Style {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    Style { color: std::io::stdout().is_terminal() && !no_color, width: terminal_width() }
}

// ---------------------------------------------------------------------------------------------
// Arguments

fn read_stdin() -> Result<String, String> {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).map_err(|e| format!("Cannot read standard input ({e})."))?;
    String::from_utf8(bytes).map_err(|_| "Standard input is not valid text (UTF-8).".to_string())
}

/// The text of `run`, `send`, `rule` and `approve`: the words, or standard input for `-`. Reading
/// from a terminal happens only when asked for with `-`; with no words at all it is an error, never
/// a silent wait. `noun` is what the text is (`message`, `rule`, `approval`), for the refusals.
fn read_message(words: &[String], noun: &str) -> Result<String, String> {
    let text = match message_from_args(words) {
        Some(t) => t,
        None => {
            if words.is_empty() && std::io::stdin().is_terminal() {
                return Err(format!(
                    "There is no {noun}. Put it after the command, pipe it in, or give `-` to type it (end with Ctrl-D)."
                ));
            }
            read_stdin()?
        }
    };
    if text.trim().is_empty() {
        return Err(format!("The {noun} is empty."));
    }
    Ok(text)
}

/// The line printed once the daemon accepted a rule, an approval or a withdrawal. `what` names it
/// (`rule`, `withdrawal of k1`) and `stock_of` what a stock text stands in for (`scope`, `reason`;
/// a rule has neither). It says whether the lead records it at once (`sent to` an idle lead) or has
/// it only in its queue.
fn receipt_line(what: &str, stock_of: &str, r: &RuleReceipt) -> String {
    let lead = r.lead.as_str();
    let mut parts = vec![if r.queued {
        format!(
            "{what} queued for {lead}: the lead is in a turn and records it at its next step, not while a tool call is running"
        )
    } else {
        format!("{what} sent to {lead}")
    }];
    if let Some(stock) = &r.stock {
        parts.push(format!("{stock_of} recorded as \"{stock}\""));
    }
    if !r.ledger {
        parts.push("this mission keeps no ledger, so it is a note in the lead's window without an id".to_string());
    } else if r.queued {
        parts.push(format!("check with loom ledger {lead}"));
    }
    parts.join("; ")
}

/// The line printed once the daemon accepted a scope grant.
fn scope_line(r: &ScopeReceipt) -> String {
    let mut line = format!("scope granted for {}: {}", r.lead.as_str(), r.hosts.join(", "));
    if !r.ledger {
        line.push_str("; this mission keeps no ledger, so the grant is not listed");
    }
    line
}

/// The line printed once the daemon accepted a scope revoke.
fn scope_revoke_line(r: &ScopeRevokeReceipt) -> String {
    let mut line = format!(
        "scope revoked for {}: {}; {} session(s) narrowed, {} connection(s) cut",
        r.lead.as_str(),
        r.host,
        r.sessions,
        r.cut
    );
    if !r.ledger {
        line.push_str("; this mission keeps no ledger, so the revoke is not listed and a restart does not keep it");
    } else if !r.recorded {
        line.push_str("; the grant was not in the ledger yet, so the revoke is not recorded there: run it again once `loom ledger` lists the grant");
    }
    line
}

/// The line printed once the daemon accepted a release: the outcome in words, then what the lead was sent.
fn release_line(r: &RuleReceipt) -> String {
    let sent = receipt_line("release", "", r);
    format!("closed by operator, goal not established: {sent}")
}

/// The hosts the operator granted the mission of `session`, or `None` when its ledger cannot be read.
async fn granted_hosts_of(c: &Client, session: &str) -> Option<Vec<String>> {
    let mission = c.mission_of(session).await.ok()?;
    Some(c.ledger(&mission).await.ok()?.state.granted_hosts())
}

fn non_zero(n: u32) -> Option<u32> {
    (n > 0).then_some(n)
}

/// The missions `--prior` names, in the order given: a word starting with `m-` is a mission id and is sent as
/// it is; any other word goes to `resolve` (a session id, prefix or `last`), which gives its mission.
async fn prior_missions<F, Fut>(words: &[String], resolve: F) -> Result<Vec<MissionId>, String>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<MissionId, String>>,
{
    let mut out = Vec::new();
    for word in words {
        let word = word.trim();
        if word.is_empty() {
            continue;
        }
        out.push(if word.starts_with("m-") { MissionId::from(word) } else { resolve(word.to_string()).await? });
    }
    Ok(out)
}

/// The request `loom run` and `loom chat` make; `cwd` is the default workspace; `prior` the missions to recall.
fn new_session(opts: &StartOpts, message: Option<String>, cwd: &Path, prior: Vec<MissionId>) -> NewSession {
    let workspace = opts.workspace.clone().unwrap_or_else(|| cwd.to_path_buf());
    // `~` and `~/x` reach the daemon as they are: it expands them to its user's home.
    let tilde = workspace.to_str().is_some_and(|w| w == "~" || w.starts_with("~/"));
    NewSession {
        workspace: if tilde { workspace } else { std::path::absolute(&workspace).unwrap_or(workspace) },
        pack: opts.pack.clone(),
        role: opts.role.clone(),
        model: opts.model.clone(),
        title: opts.title.clone(),
        unattended: opts.attended.then_some(false),
        budget: Budget { max_steps: non_zero(opts.max_steps), max_minutes: non_zero(opts.max_minutes) },
        message,
        prior,
        role_models: opts.agent_models.iter().cloned().collect(),
        create_workspace: opts.create_workspace,
        attachments: Vec::new(),
        target: opts.target.clone().filter(|t| !t.trim().is_empty()),
        intercept: opts.no_intercept.then_some(false),
    }
}

/// The role a model choice names on the command line: `all` (or a quoted `*`) is every role the lead
/// starts. `*` alone is globbed by shells, and zsh refuses `*=x` when nothing matches.
fn cli_role(role: &str) -> String {
    match role.trim() {
        "all" | ANY_ROLE => ANY_ROLE.to_string(),
        other => other.to_string(),
    }
}

/// `--agent-model ROLE=PROFILE`.
fn parse_agent_model(text: &str) -> Result<(String, String), String> {
    let Some((role, profile)) = text.split_once('=') else {
        return Err(format!("`{text}` is not ROLE=PROFILE (for example worker=fast, or all=fast for every role)"));
    };
    let (role, profile) = (role.trim(), profile.trim());
    if role.is_empty() || profile.is_empty() {
        return Err(format!("`{text}` needs both a role and a profile, as ROLE=PROFILE"));
    }
    Ok((cli_role(role), profile.to_string()))
}

fn record_opts(show: &ShowOpts) -> RecordOpts {
    RecordOpts { reasoning: show.reasoning, full: show.full, verbose: show.verbose, ..RecordOpts::default() }
}

// ---------------------------------------------------------------------------------------------
// Following a session

const MAX_RETRIES: u32 = 5;
/// Rows of a half-written reply shown below the last record.
const LIVE_ROWS: usize = 6;

/// How a follow renders and behaves.
struct FollowCfg<'a> {
    render: &'a dyn Fn(&Record) -> String,
    /// Passes stored text through `render::clean`.
    clean: &'a dyn Fn(&str) -> String,
    /// Show the reply being written (a terminal only).
    deltas: bool,
    color: bool,
    width: usize,
    retry_delay: Duration,
    /// Turn and session ends at or below this seq are history, not the end of what is followed.
    stop_floor: Option<Seq>,
}

#[derive(Debug, PartialEq, Eq)]
struct FollowEnd {
    code: i32,
    /// The session itself ended (a chat has nothing more to say to it).
    ended: bool,
}

/// The reply being written, drawn below the last record and erased when the record arrives.
#[derive(Default)]
struct Live {
    reasoning: String,
    text: String,
    /// Rows between the cursor and the first row of what is drawn.
    up: usize,
    drawn: bool,
}

impl Live {
    fn push(&mut self, delta: &Delta) {
        match delta {
            Delta::Text { text } => self.text.push_str(text),
            Delta::Reasoning { text } => self.reasoning.push_str(text),
            Delta::AttemptStart { .. } | Delta::Retrying { .. } => self.clear(),
            Delta::ToolCallStart { .. } | Delta::ToolCallArgs { .. } => {}
        }
    }

    fn clear(&mut self) {
        self.reasoning.clear();
        self.text.clear();
    }

    /// Escape sequence that removes what is drawn.
    fn erase(&mut self) -> String {
        if !self.drawn {
            return String::new();
        }
        let mut s = String::new();
        if self.up > 0 {
            s.push_str(&format!("\x1b[{}A", self.up));
        }
        s.push_str("\r\x1b[J");
        self.drawn = false;
        self.up = 0;
        s
    }

    /// Erase, then draw the last few rows of the reply (reasoning dim); the cursor stays at the end
    /// of the last row.
    fn draw(&mut self, width: usize, color: bool, clean: &dyn Fn(&str) -> String) -> String {
        let mut s = self.erase();
        let w = width.saturating_sub(1).max(10);
        let mut rows: Vec<(bool, String)> = Vec::new();
        for (dim, text) in [(true, &self.reasoning), (false, &self.text)] {
            for line in clean(text).lines() {
                let chars: Vec<char> = line.chars().collect();
                if chars.is_empty() {
                    rows.push((dim, String::new()));
                }
                for chunk in chars.chunks(w) {
                    rows.push((dim, chunk.iter().collect()));
                }
            }
        }
        let skip = rows.len().saturating_sub(LIVE_ROWS);
        let shown: Vec<String> = rows
            .into_iter()
            .skip(skip)
            .map(|(dim, row)| if dim && color { format!("\x1b[2m{row}\x1b[0m") } else { row })
            .collect();
        if shown.is_empty() {
            return s;
        }
        self.up = shown.len().saturating_sub(1);
        self.drawn = true;
        s.push_str(&shown.join("\n"));
        s
    }
}

fn outcome_code(outcome: SessionOutcome) -> i32 {
    match outcome {
        SessionOutcome::Done => 0,
        SessionOutcome::Stopped | SessionOutcome::Failed | SessionOutcome::BudgetExhausted => 1,
    }
}

/// Print `id`'s records as they arrive, once each, until its turn ends.
///
/// `after` is the last seq already seen. A broken or closed stream is re-opened after the last seq
/// printed, up to [`MAX_RETRIES`] times in a row (progress resets the count); a stream that falls
/// behind is re-opened the same way. Ctrl-C leaves the session running and ends with 130.
async fn follow(
    c: &Client,
    id: &SessionId,
    after: Option<Seq>,
    cfg: &FollowCfg<'_>,
    out: &mut dyn Write,
) -> Result<FollowEnd, String> {
    let mut last = after;
    let mut live = Live::default();
    let mut failures = 0u32;
    let mut connected = false;
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    'open: loop {
        let mut stream = match c.stream(id, last).await {
            Ok(s) => s,
            // The first connection failing is the operator's to fix (no daemon, no such session);
            // later ones are a daemon that is restarting.
            Err(e) if !connected => return Err(e),
            Err(e) => {
                failures += 1;
                if failures > MAX_RETRIES {
                    return Err(e);
                }
                tokio::time::sleep(cfg.retry_delay).await;
                continue 'open;
            }
        };
        connected = true;
        loop {
            let next = tokio::select! {
                ev = stream.next() => ev,
                _ = &mut interrupt => {
                    put(out, &live.erase())?;
                    errln(&format!("still running — loom tail {id} to watch, loom stop {id} to stop it"));
                    return Ok(FollowEnd { code: 130, ended: false });
                }
            };
            let event = match next {
                Some(Ok(event)) => event,
                Some(Err(_)) | None => {
                    failures += 1;
                    if failures > MAX_RETRIES {
                        let from = last.map(|l| format!(" --since {l}")).unwrap_or_default();
                        return Err(format!(
                            "The connection to the daemon kept breaking. Carry on with `loom tail {id}{from}`."
                        ));
                    }
                    tokio::time::sleep(cfg.retry_delay).await;
                    continue 'open;
                }
            };
            match event {
                BusEvent::Record { session, record } => {
                    if session != *id || last.is_some_and(|l| record.seq <= l) {
                        continue;
                    }
                    last = Some(record.seq);
                    failures = 0;
                    let mut text = live.erase();
                    if matches!(record.event, Event::ModelResponse(_)) {
                        live.clear();
                    }
                    text.push_str(&(cfg.render)(&record));
                    put(out, &text)?;
                    if cfg.stop_floor.is_some_and(|f| record.seq <= f) {
                        continue;
                    }
                    match &record.event {
                        Event::TurnEnd { reason } => {
                            if let Some(code) = follow_exit_code(*reason) {
                                return Ok(FollowEnd { code, ended: false });
                            }
                        }
                        Event::SessionEnd { outcome, .. } => {
                            return Ok(FollowEnd { code: outcome_code(*outcome), ended: true });
                        }
                        _ => {}
                    }
                }
                BusEvent::Delta { session, delta, .. } => {
                    if cfg.deltas && session == *id {
                        live.push(&delta);
                        put(out, &live.draw(cfg.width, cfg.color, cfg.clean))?;
                    }
                }
                BusEvent::Lagged { .. } => {
                    put(out, &live.erase())?;
                    continue 'open;
                }
                BusEvent::Error { session, message } => {
                    if session.as_ref().is_none_or(|s| s == id) {
                        put(out, &live.erase())?;
                        errln(&format!("! {message}"));
                    }
                }
                BusEvent::Session { .. }
                | BusEvent::Status { .. }
                | BusEvent::Net { .. }
                | BusEvent::Queued { .. }
                | BusEvent::Target { .. }
                | BusEvent::Settled { .. } => {}
            }
        }
    }
}

/// [`follow`] on the terminal.
async fn follow_stdout(
    c: &Client,
    id: &SessionId,
    after: Option<Seq>,
    floor: Option<Seq>,
    show: &ShowOpts,
) -> Result<FollowEnd, String> {
    let style = style();
    let opts = record_opts(show);
    let render_record = |r: &Record| render::record(r, &style, &opts);
    let cfg = FollowCfg {
        render: &render_record,
        clean: &render::clean,
        deltas: std::io::stdout().is_terminal(),
        color: style.color,
        width: style.width,
        retry_delay: Duration::from_secs(1),
        stop_floor: floor,
    };
    follow(c, id, after, &cfg, &mut StdoutSink).await
}

/// The seq of the newest record of a session, found with a doubling probe and a bisection over
/// `records?after=…&limit=1` so a long log is never downloaded.
async fn last_seq(c: &Client, id: &SessionId) -> Result<Option<Seq>, String> {
    async fn has_after(c: &Client, id: &SessionId, n: Seq) -> Result<bool, String> {
        Ok(!c.records(id, Some(n), 1).await?.records.is_empty())
    }
    if c.records(id, None, 1).await?.records.is_empty() {
        return Ok(None);
    }
    let mut lo: Seq = 0;
    let mut hi: Seq = 1;
    while has_after(c, id, hi).await? {
        lo = hi.saturating_add(1);
        hi = hi.checked_mul(2).ok_or_else(|| "The record numbers of this session do not make sense.".to_string())?;
    }
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if has_after(c, id, mid).await? {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(Some(lo))
}

/// Print the records after `after` that exist now, in pages.
async fn print_records(
    c: &Client,
    id: &SessionId,
    mut after: Option<Seq>,
    render_record: &dyn Fn(&Record) -> String,
    out: &mut dyn Write,
) -> Result<(), String> {
    loop {
        let page = c.records(id, after, 500).await?;
        for record in &page.records {
            put(out, &render_record(record))?;
        }
        match page.next_after {
            Some(next) if after.is_none_or(|a| next > a) => after = Some(next),
            _ => return Ok(()),
        }
    }
}

fn rest_code(status: &loom_agent::session::Status) -> Option<i32> {
    match status.phase {
        Phase::Ended => Some(status.outcome.map(outcome_code).unwrap_or(0)),
        Phase::Idle => status.last_end.and_then(follow_exit_code),
        Phase::Running => None,
    }
}

/// `tail`: what exists, then what arrives, until the turn that is running (or the next one) ends. A
/// session at rest — ended, or idle after a turn that ended — has nothing to wait for: its records
/// are printed and the code is that of its last turn.
async fn tail_with(c: &Client, a: &TailArgs, cfg: &FollowCfg<'_>, out: &mut dyn Write) -> Result<i32, String> {
    let id = c.resolve(&a.session).await?;
    let status = c.session(&id).await?.info.status;
    let at_rest_code = rest_code(&status);
    if a.no_follow || at_rest_code.is_some() {
        print_records(c, &id, a.since, cfg.render, out).await?;
        return Ok(if a.no_follow { 0 } else { at_rest_code.unwrap_or(0) });
    }
    let floor = last_seq(c, &id).await?;
    // Re-check after computing `floor`: if the running turn finished before `floor` was read,
    // `floor` already includes its `TurnEnd`/`SessionEnd` and `follow` would wait forever.
    let status = c.session(&id).await?.info.status;
    if let Some(code) = rest_code(&status) {
        print_records(c, &id, a.since, cfg.render, out).await?;
        return Ok(code);
    }
    let cfg = FollowCfg { stop_floor: floor, ..*cfg };
    Ok(follow(c, &id, a.since, &cfg, out).await?.code)
}

/// Read each file and upload it to `workspace`; the stored paths, in order. A file that cannot be read stops
/// the command before anything is sent.
async fn upload_files(c: &Client, workspace: &str, files: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut stored = Vec::with_capacity(files.len());
    for file in files {
        let shown = file.display();
        let bytes = std::fs::read(file).map_err(|e| format!("Cannot read {shown} to attach it ({e})."))?;
        let name = file.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            format!("Cannot attach {shown}: it has no file name. Give a path that ends in the file's name.")
        })?;
        let up = c.upload(workspace, name, bytes).await.map_err(|e| format!("Cannot attach {shown}: {e}"))?;
        stored.push(up.path);
    }
    Ok(stored)
}

/// `send`: the message, then what follows it.
async fn send_with(
    c: &Client,
    id: &SessionId,
    text: &str,
    detach: bool,
    cfg: &FollowCfg<'_>,
    out: &mut dyn Write,
) -> Result<FollowEnd, String> {
    send_with_files(c, id, text, (&[], false), detach, cfg, out).await
}

/// [`send_with`] with uploaded `files` attached.
async fn send_with_files(
    c: &Client,
    id: &SessionId,
    text: &str,
    (files, after_turn): (&[String], bool),
    detach: bool,
    cfg: &FollowCfg<'_>,
    out: &mut dyn Write,
) -> Result<FollowEnd, String> {
    let baseline = last_seq(c, id).await?;
    if after_turn {
        if let Some(queued) = c.send_after_turn(id, text, files).await? {
            put(out, &format!("queued for {id} ({}); it is sent when the turn ends\n", queued.id))?;
            return Ok(FollowEnd { code: 0, ended: false });
        }
    } else {
        c.send_with_files(id, text, files).await?;
    }
    if detach {
        put(out, &format!("sent to {id}\n"))?;
        return Ok(FollowEnd { code: 0, ended: false });
    }
    follow(c, id, baseline, cfg, out).await
}

/// `out`: the lines of a stored output, 5 000 at a time, through `clean`.
async fn print_blob(
    c: &Client,
    handle: &str,
    range: Option<(u64, Option<u64>)>,
    clean: &dyn Fn(&str) -> String,
    out: &mut dyn Write,
) -> Result<(), String> {
    const PAGE: u64 = 5_000;
    let (mut next, limit) = match range {
        Some((start, end)) => (start, end.unwrap_or(u64::MAX)),
        None => (1, u64::MAX),
    };
    loop {
        let end = next.saturating_add(PAGE - 1).min(limit);
        let view = c.blob_lines(handle, next, end).await?;
        if !view.text.is_empty() {
            let mut text = clean(&view.text);
            if !text.ends_with('\n') {
                text.push('\n');
            }
            put(out, &text)?;
        }
        if view.last >= limit || view.last >= view.total || view.last < next {
            return Ok(());
        }
        next = view.last.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------------------------
// Commands

fn client_of(paths: &Paths) -> Result<Client, String> {
    Client::from_home(paths)
}

async fn dispatch(command: Command) -> Result<i32, String> {
    let paths = Paths::from_env();
    match command {
        Command::Daemon => crate::serve::run(paths).await.map(|()| 0),
        Command::Up => cmd_up(&paths).await,
        Command::Down => cmd_down(&paths).await,
        Command::Config { action } => cmd_config(&paths, action),
        Command::Models { action } => cmd_models(&paths, action).await,
        Command::Mcp { action } => cmd_mcp(&paths, action).await,
        Command::Monitor(a) => cmd_monitor(&paths, a).await,
        Command::Service { action } => cmd_service(&paths, action),
        Command::Status => {
            let view = client_of(&paths)?.status().await?;
            block(&render::status(&view, &style())).map(|()| 0)
        }
        Command::Open(a) => cmd_open(&paths, &a).await,
        Command::Run(a) => cmd_run(&paths, a).await,
        Command::Chat(a) => cmd_chat(&paths, a).await,
        Command::Ls(a) => {
            let list = client_of(&paths)?.sessions(a.all).await?;
            block(&render::sessions_table(&list, loom_core::now_ms(), &style())).map(|()| 0)
        }
        Command::Tail(a) => {
            let c = client_of(&paths)?;
            let style = style();
            let opts = record_opts(&a.show);
            let render_record = |r: &Record| render::record(r, &style, &opts);
            let cfg = terminal_cfg(&render_record, &style, None);
            tail_with(&c, &a, &cfg, &mut StdoutSink).await
        }
        Command::Send(a) => {
            let text = if a.files.is_empty() || !a.text.is_empty() {
                read_message(&a.text, "message")?
            } else {
                String::new()
            };
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            let attached = if a.files.is_empty() {
                Vec::new()
            } else {
                let workspace = c.session(&id).await?.info.meta.workspace;
                upload_files(&c, &workspace, &a.files).await?
            };
            let style = style();
            let opts = record_opts(&a.show);
            let render_record = |r: &Record| render::record(r, &style, &opts);
            let cfg = terminal_cfg(&render_record, &style, None);
            Ok(send_with_files(&c, &id, &text, (&attached, a.after_turn), a.detach, &cfg, &mut StdoutSink).await?.code)
        }
        Command::Stop(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            c.stop(&id).await?;
            outln(&format!("stop requested for {id}")).map(|()| 0)
        }
        Command::Resume(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            c.resume(&id).await?;
            outln(&format!("resume requested for {id}")).map(|()| 0)
        }
        Command::Compact(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            c.compact(&id).await?;
            outln(&format!("compaction requested for {id}")).map(|()| 0)
        }
        Command::Archive(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            c.archive(&id, !a.undo).await?;
            outln(&format!("{} {id}", if a.undo { "restored" } else { "archived" })).map(|()| 0)
        }
        Command::Rename(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            let title = a.title.join(" ");
            c.rename(&id, &title).await?;
            outln(&format!("renamed {id} to {title:?}")).map(|()| 0)
        }
        Command::Rule(a) => {
            let c = client_of(&paths)?;
            if let Some(rule) = &a.withdraw {
                let id = c.resolve(&a.session).await?;
                let receipt = c.withdraw_rule(&id, rule, a.reason.as_deref().unwrap_or("")).await?;
                let what = format!("withdrawal of {}", rule.trim());
                return outln(&receipt_line(&what, "reason", &receipt)).map(|()| 0);
            }
            let text = read_message(&a.text, "rule")?;
            let id = c.resolve(&a.session).await?;
            let receipt = c.add_rule(&id, &text).await?;
            outln(&receipt_line("rule", "", &receipt)).map(|()| 0)
        }
        Command::Approve(a) => {
            let text = read_message(&a.text, "approval")?;
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            let receipt = c.approve(&id, &text, a.scope.as_deref().unwrap_or("")).await?;
            outln(&receipt_line("approval", "scope", &receipt)).map(|()| 0)
        }
        Command::Scope(ScopeArgs { action: Some(ScopeAction::Revoke(a)), .. }) => {
            let c = client_of(&paths)?;
            let mission = c.mission_of(&a.mission).await?;
            let receipt = c.revoke_scope(&mission, &a.host, &a.reason).await?;
            outln(&scope_revoke_line(&receipt)).map(|()| 0)
        }
        Command::Scope(a) => {
            let c = client_of(&paths)?;
            let word =
                a.session.as_deref().ok_or("Name the session to grant the hosts to: loom scope <session> <host>…")?;
            let id = c.resolve(word).await?;
            let receipt = c.grant_scope(&id, &a.hosts, a.note.as_deref()).await?;
            outln(&scope_line(&receipt)).map(|()| 0)
        }
        Command::Release(a) => {
            let reason = read_message(&a.reason, "reason")?;
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            let receipt = c.release(&id, &reason).await?;
            outln(&release_line(&receipt)).map(|()| 0)
        }
        Command::Gc(a) => {
            let r = client_of(&paths)?.gc(a.apply).await?;
            let (verb, hint) =
                if a.apply { ("deleted", "") } else { ("would delete", "\nRun `loom gc --apply` to delete them.") };
            outln(&format!(
                "examined {} stored outputs ({} bytes); kept {} ({} bytes); {verb} {} ({} bytes).{hint}",
                r.examined, r.examined_bytes, r.kept, r.kept_bytes, r.collected, r.collected_bytes
            ))
            .map(|()| 0)
        }
        Command::Inbox => {
            let list = client_of(&paths)?.inbox().await?;
            block(&render::inbox_list(&list, loom_core::now_ms(), &style())).map(|()| 0)
        }
        Command::Answer(a) => {
            // No words is an empty answer, which dismisses a non-blocking item; `-` reads stdin.
            let answer = match message_from_args(&a.text) {
                Some(t) => t,
                None if a.text.is_empty() => String::new(),
                None => read_stdin()?,
            };
            client_of(&paths)?.answer(&a.item, &answer).await?;
            outln(&format!("answered {}", a.item)).map(|()| 0)
        }
        Command::Ledger(a) => {
            let c = client_of(&paths)?;
            let mission = c.mission_of(&a.session).await?;
            let view = c.ledger(&mission).await?;
            let mut text = view.markdown.clone();
            for notice in view.notices() {
                text.push_str(&format!("\n{notice}"));
            }
            block(&text).map(|()| 0)
        }
        Command::Score(a) => {
            let c = client_of(&paths)?;
            let mission = c.mission_of(&a.session).await?;
            let view = c.score(&mission).await?;
            let text = if a.json {
                serde_json::to_string_pretty(&view).map_err(|e| format!("The score could not be written: {e}"))?
            } else {
                format_score_text(&view, &style())
            };
            block(&text).map(|()| 0)
        }
        Command::Window(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            let view = c.window(&id).await?;
            block(&render::window_table(&view, &style())).map(|()| 0)
        }
        Command::Net(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            let entries = c.net(&id, a.limit).await?;
            let mut text = render::net_table(&entries, &style());
            if let Some(hosts) = granted_hosts_of(&c, &a.session).await {
                text.push_str(&format!("{}\n", render::granted_hosts_line(&hosts)));
            }
            block(&text).map(|()| 0)
        }
        Command::Target { action } => cmd_target(&paths, action).await,
        Command::Ca { action } => {
            let (fp, file) = match action {
                CaAction::Show => loom_agent::runtime::ca_show(&paths.home)?,
                CaAction::Rotate => loom_agent::runtime::ca_rotate(&paths.home)?,
            };
            let verb = if action == CaAction::Rotate { "rotated; new " } else { "" };
            outln(&format!("{verb}fingerprint sha256 {fp}\ncertificate {}", file.display())).map(|()| 0)
        }
        Command::Out(a) => {
            let range = a.lines.as_deref().map(parse_lines).transpose()?;
            let c = client_of(&paths)?;
            print_blob(&c, &a.handle, range, &render::clean, &mut StdoutSink).await.map(|()| 0)
        }
    }
}

fn terminal_cfg<'a>(render_record: &'a dyn Fn(&Record) -> String, style: &Style, floor: Option<Seq>) -> FollowCfg<'a> {
    FollowCfg {
        render: render_record,
        clean: &render::clean,
        deltas: std::io::stdout().is_terminal(),
        color: style.color,
        width: style.width,
        retry_delay: Duration::from_secs(1),
        stop_floor: floor,
    }
}

/// Whether the variable is present and not empty in this process's environment.
fn env_var_is_set(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| !v.is_empty())
}

/// What `loom service install` refuses before it writes anything: a profile that sets `api_key_env` (a launchd
/// agent does not have the shell's variables, and the key must not be written into the service file) and what
/// `Config::check_model_keys` refuses.
fn service_key_check(config: &Config, keys_dir: &Path) -> Result<(), String> {
    for (name, profile) in &config.models {
        if let Some(var) = &profile.api_key_env {
            let file = config.suggested_key_files().get(name).cloned().unwrap_or_else(|| name.clone());
            let steps = loom_core::config::key_move_steps(keys_dir, name, &file, var, true);
            return Err(format!(
                "models.{name} sets api_key_env = \"{var}\", but a launchd service does not have your shell's variables, so its requests would carry no key, and putting the key in the service file would write it to disk and into the daemon's environment. Move the key to a file: {steps}, and run `loom service install` again."
            ));
        }
    }
    config.check_model_keys(keys_dir)
}

async fn cmd_up(paths: &Paths) -> Result<i32, String> {
    let spawned = crate::serve::spawn_background(paths).await?;
    if matches!(spawned, crate::serve::Spawned::Started) {
        // `spawn_background` has already reported a config that cannot be loaded.
        if let Ok(config) = Config::load(&paths.config_file()) {
            for line in config.key_env_warnings(&paths.model_keys_dir(), env_var_is_set) {
                errln(&format!("warning: {line}"));
            }
        }
    }
    let bind = client::bind_from_home(paths)?;
    let line = match spawned {
        crate::serve::Spawned::Started => format!("loom is running on {bind}"),
        crate::serve::Spawned::Already => format!("loom is already running on {bind}"),
    };
    outln(&line).map(|()| 0)
}

async fn cmd_down(paths: &Paths) -> Result<i32, String> {
    // A shutdown gives running commands the TERM-to-KILL grace twice (those of turns, then the sessions'
    // jobs); the 30 s more cover the HTTP grace, tasks that have to be aborted and the proxy's connections.
    let grace = Config::load(&paths.config_file()).unwrap_or_default().tools.kill_grace_s;
    down(paths, Duration::from_secs(grace.saturating_mul(2).saturating_add(30))).await
}

/// `loom down`, waiting up to `within` for the old process to let go of the home once it no longer answers.
async fn down(paths: &Paths, within: Duration) -> Result<i32, String> {
    let c = client_of(paths)?;
    if let Err(e) = c.shutdown().await {
        // Nothing answers. A daemon still shutting down (an earlier `loom down` stopped waiting for it) is
        // named, alive, in `daemon.json` and holds the home until it exits: that is waited for below. A
        // daemon that is starting has not written `daemon.json` yet, or answers once it has.
        let shutting_down = !crate::serve::home_lock_free(paths) && crate::serve::live_daemon_pid(paths).is_some();
        if c.alive().await {
            return Err(e); // it answered but the shutdown itself errored: keep the real reason
        }
        if !shutting_down {
            // For `down`, the generic "start it with `loom up`" is the wrong next step.
            return Err("The loom daemon is not running, so there is nothing to stop.".to_string());
        }
    } else {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while c.alive().await {
            if std::time::Instant::now() >= deadline {
                return Err(format!(
                    "The daemon was asked to stop but still answers after 10 seconds. See {}.",
                    paths.logs_dir().join("loomd.log").display()
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    // /healthz stops first; the old process keeps the home's lock until its shutdown is done.
    if !crate::serve::wait_home_lock_free(paths, within).await {
        let who = crate::serve::live_daemon_pid(paths).map_or("it".to_string(), |pid| format!("process {pid}"));
        return Err(format!(
            "The loom daemon for {} no longer answers but is still shutting down after {} seconds, so `loom up` would be refused until {who} exits. Run `loom down` again to keep waiting, then `loom up`; see {}.",
            paths.home.display(),
            within.as_secs(),
            paths.logs_dir().join("loomd.log").display()
        ));
    }
    outln("stopped").map(|()| 0)
}

/// The address that logs a browser in: a fresh single-use code; the API token is not in it.
async fn login_url(c: &Client) -> Result<String, String> {
    let bind = c.base().strip_prefix("http://").unwrap_or(c.base());
    Ok(open_url(bind, &c.login_code().await?))
}

/// `open` against a daemon that answers: the address goes to the browser through `launch` and
/// nothing is written; with `--print` it is written to `out` and nothing is started.
async fn open_with(
    c: &Client,
    a: &OpenArgs,
    out: &mut dyn Write,
    launch: impl FnOnce(&str) -> Result<(), String>,
) -> Result<i32, String> {
    let url = login_url(c).await?;
    if a.print {
        put(out, &format!("{url}\n"))?;
    } else {
        launch(&url)?;
        put(out, OPENED_NOTE)?;
    }
    Ok(0)
}

/// Printed after the login page was handed to the desktop's opener.
const OPENED_NOTE: &str = "Opened the loom login page. If an editor opened instead of a browser (your .html files open there), run `loom open --print` and open the address in a browser.\n";

/// How long a login page stays on disk before the next `open` removes it (its code is dead long before).
const LOGIN_PAGE_KEEP: Duration = Duration::from_secs(300);

/// The page that sends the browser to `url` (which holds the login code in its fragment), as a file in
/// `dir` (a private directory under the loom home) that only this user can read. The opener is given the
/// path of this file and never the address, so the code is not in any process's arguments, where another
/// local process could read it while the opener runs. Pages older than [`LOGIN_PAGE_KEEP`] are removed.
fn write_login_page(dir: &Path, url: &str) -> Result<PathBuf, String> {
    loom_core::config::ensure_private_dir(dir).map_err(|e| {
        format!(
            "Cannot create {} ({e}). Run `loom open --print` and open the address in a browser yourself.",
            dir.display()
        )
    })?;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > LOGIN_PAGE_KEEP);
            if old && entry.file_name().to_string_lossy().starts_with("login-") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let escaped = url.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;");
    let script = serde_json::to_string(url).map_err(|e| format!("The address cannot be encoded ({e})."))?;
    let page = format!(
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><title>loom</title>\n\
         <meta http-equiv=\"refresh\" content=\"0;url={escaped}\">\n\
         <script>location.replace({script});</script>\n\
         <p>Opening loom. If nothing happens, <a href=\"{escaped}\">continue</a>.</p>\n"
    );
    let path = dir.join(format!("login-{}.html", hex::encode(rand::random::<[u8; 16]>())));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&path).map_err(|e| {
        format!(
            "Cannot write {} ({e}). Run `loom open --print` and open the address in a browser yourself.",
            path.display()
        )
    })?;
    file.write_all(page.as_bytes()).map_err(|e| {
        format!(
            "Cannot write {} ({e}). Run `loom open --print` and open the address in a browser yourself.",
            path.display()
        )
    })?;
    Ok(path)
}

/// Hand `url` to the desktop's opener, through a page file in `dir` so that the address (with its login
/// code) is not on the opener's command line. `run(program, page)` starts the opener.
fn launch_browser_with(
    dir: &Path,
    url: &str,
    run: impl FnOnce(&str, &Path) -> std::io::Result<bool>,
) -> Result<(), String> {
    let program = if cfg!(target_os = "macos") { "/usr/bin/open" } else { "xdg-open" };
    let page = write_login_page(dir, url)?;
    match run(program, &page) {
        Ok(true) => Ok(()),
        Ok(false) => {
            let _ = std::fs::remove_file(&page);
            Err(format!(
                "{program} could not open the address. Run `loom open --print` and open it in a browser yourself."
            ))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&page);
            Err(format!(
                "Cannot start {program} ({e}). Run `loom open --print` and open the address in a browser yourself."
            ))
        }
    }
}

/// Hand `url` to the desktop's opener (see [`launch_browser_with`]).
fn launch_browser(dir: &Path, url: &str) -> Result<(), String> {
    launch_browser_with(dir, url, |program, page| {
        std::process::Command::new(program)
            .arg(page)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
    })
}

async fn cmd_open(paths: &Paths, a: &OpenArgs) -> Result<i32, String> {
    let c = client_of(paths)?;
    // Say "not running" here rather than hand the browser an address nothing answers on.
    c.status().await?;
    let dir = paths.home.join("login");
    open_with(&c, a, &mut StdoutSink, |url| launch_browser(&dir, url)).await
}

async fn cmd_run(paths: &Paths, a: RunArgs) -> Result<i32, String> {
    let message =
        if a.files.is_empty() || !a.message.is_empty() { read_message(&a.message, "message")? } else { String::new() };
    let c = client_of(paths)?;
    let cwd =
        std::env::current_dir().map_err(|e| format!("Cannot find the current directory ({e}). Pass --workspace."))?;
    let client = &c;
    let prior = prior_missions(&a.start.prior, |word| async move { client.mission_of(&word).await }).await?;
    let mut new = new_session(&a.start, Some(message).filter(|m| !m.is_empty()), &cwd, prior);
    if !a.files.is_empty() {
        new.attachments = upload_files(&c, &new.workspace.to_string_lossy(), &a.files).await?;
    }
    let made = c.create_receipt(&new).await?;
    let id = made.info.meta.id;
    if made.created {
        errln(&format!("created workspace {}", made.info.meta.workspace));
    }
    errln(&format!("session {id}"));
    if a.detach {
        outln(id.as_str())?;
        return Ok(0);
    }
    Ok(follow_stdout(&c, &id, None, None, &a.show).await?.code)
}

async fn cmd_chat(paths: &Paths, a: ChatArgs) -> Result<i32, String> {
    let c = client_of(paths)?;
    let id = match &a.session {
        Some(_) if !a.start.prior.is_empty() => {
            return Err("Earlier missions are recalled when a mission starts. Drop --session to start a new chat \
that recalls them, or drop --prior to continue this one."
                .to_string());
        }
        Some(word) => c.resolve(word).await?,
        None => {
            let cwd = std::env::current_dir()
                .map_err(|e| format!("Cannot find the current directory ({e}). Pass --workspace."))?;
            let client = &c;
            let prior = prior_missions(&a.start.prior, |word| async move { client.mission_of(&word).await }).await?;
            let mut new = new_session(&a.start, None, &cwd, prior);
            if new.role.is_none() {
                new.role = Some("chat".to_string());
            }
            let made = c.create_receipt(&new).await?;
            let id = made.info.meta.id;
            if made.created {
                errln(&format!("created workspace {}", made.info.meta.workspace));
            }
            errln(&format!("session {id}"));
            id
        }
    };
    let tty = std::io::stdin().is_terminal();
    if tty {
        // A first-time operator has no way to know how to leave or that the prompt means "your turn".
        errln("type a message and press Enter · /quit or Ctrl-D to leave");
    }
    let style = style();
    let opts = record_opts(&a.show);
    let render_record = |r: &Record| render::record(r, &style, &opts);
    let cfg = terminal_cfg(&render_record, &style, None);
    let stdin = std::io::stdin();
    loop {
        if tty {
            put(&mut StdoutSink, "› ")?;
        }
        let mut line = String::new();
        let n = stdin.read_line(&mut line).map_err(|e| format!("Cannot read standard input ({e})."))?;
        let text = line.trim();
        if n == 0 || text == "/quit" {
            return Ok(0);
        }
        if text.is_empty() {
            continue;
        }
        let end = send_with(&c, &id, text, false, &cfg, &mut StdoutSink).await?;
        if end.code == 130 || end.ended {
            return Ok(end.code);
        }
    }
}

async fn cmd_mcp(paths: &Paths, action: McpAction) -> Result<i32, String> {
    match action {
        McpAction::List => {
            let file = paths.config_file();
            let cfg = Config::load(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            block(&render::mcp_list(&loom_agent::mcp::configured(&cfg.mcp))).map(|()| 0)
        }
        McpAction::Check(a) => {
            let c = client_of(paths)?;
            let ws = match a.workspace {
                Some(w) => w,
                None => std::env::current_dir()
                    .map_err(|e| format!("Cannot find the current directory ({e}). Pass --workspace."))?,
            };
            let ws = if ws.to_str().is_some_and(|w| w == "~" || w.starts_with("~/")) {
                ws
            } else {
                std::path::absolute(&ws).unwrap_or(ws)
            };
            let view = c.mcp_check(&a.server, &ws.display().to_string()).await?;
            block(&render::mcp_check(&view))?;
            Ok(if view.error.is_some() { 1 } else { 0 })
        }
    }
}

async fn cmd_models(paths: &Paths, action: ModelsAction) -> Result<i32, String> {
    match action {
        // Read from the configuration and the packs, so it works with no daemon running.
        ModelsAction::Lineage { profile } => cmd_models_lineage(paths, profile.as_deref()),
        ModelsAction::List => {
            let c = client_of(paths)?;
            block(&render::models_table(&c.models().await?, &style())).map(|()| 0)
        }
        ModelsAction::Reload => {
            let c = client_of(paths)?;
            block(&render::models_reload(&c.reload_models().await?)).map(|()| 0)
        }
        ModelsAction::Set(a) => {
            let c = client_of(paths)?;
            let id = c.resolve(&a.session).await?;
            let receipt = c.set_model(&id, &a.profile).await?;
            outln(&render::model_switch_line(&receipt)).map(|()| 0)
        }
        ModelsAction::Show(a) => {
            let c = client_of(paths)?;
            let id = c.resolve(&a.session).await?;
            block(&render::mission_models_table(&c.mission_models(&id).await?, &style())).map(|()| 0)
        }
        ModelsAction::Role(a) => {
            let c = client_of(paths)?;
            let id = c.resolve(&a.session).await?;
            let role = cli_role(&a.role);
            let receipt = c.set_role_model(&id, &role, a.profile.as_deref(), a.now).await?;
            block(&render::role_model_receipt(&receipt, &role, a.profile.as_deref(), &style())).map(|()| 0)
        }
    }
}

/// `loom target list|add|show|scope`: the daemon holds the targets, so these go through its API.
async fn cmd_target(paths: &Paths, action: TargetAction) -> Result<i32, String> {
    let c = client_of(paths)?;
    match action {
        TargetAction::List => {
            let list = c.targets().await?;
            if list.is_empty() {
                return outln("No targets yet. Create one with `loom target add NAME --scope HOST`.").map(|()| 0);
            }
            block(&render::target_list(&list)).map(|()| 0)
        }
        TargetAction::Add(a) => {
            let body = loom_agent::runtime::TargetBody {
                name: Some(a.name),
                scope: Some(a.scope),
                exclude: Some(a.exclude),
                notes: a.notes,
                ..Default::default()
            };
            let v = c.target_create(&body).await?;
            outln(&format!("created target {} with {} scope entries", v.name, v.scope.len())).map(|()| 0)
        }
        TargetAction::Show(a) => {
            let v = c.target(&a.name).await?;
            let mut text = render::target_show(&v);
            if a.nodes {
                let g = c.target_graph(&a.name).await?;
                text.push_str(&render::target_nodes(&g));
            }
            block(&text).map(|()| 0)
        }
        TargetAction::Scope(a) => {
            let v = c.target(&a.name).await?;
            let edit = |mut cur: Vec<String>, add: &[String], remove: &[String]| {
                cur.retain(|e| !remove.iter().any(|r| r.eq_ignore_ascii_case(e)));
                for e in add {
                    if !cur.iter().any(|x| x.eq_ignore_ascii_case(e)) {
                        cur.push(e.clone());
                    }
                }
                cur
            };
            let body = loom_agent::runtime::TargetBody {
                scope: Some(edit(v.scope, &a.add, &a.remove)),
                exclude: Some(edit(v.exclude, &a.exclude, &a.unexclude)),
                ..Default::default()
            };
            let v = c.target_update(&a.name, &body).await?;
            outln(&format!("target {}: scope {}; exclude {}", v.name, v.scope.join(", "), v.exclude.join(", ")))
                .map(|()| 0)
        }
    }
}

fn cmd_config(paths: &Paths, action: ConfigAction) -> Result<i32, String> {
    let file = paths.config_file();
    match action {
        ConfigAction::Path => outln(&file.display().to_string()).map(|()| 0),
        ConfigAction::Check => {
            // Name the file on error, as the daemon does, so the operator knows which one to edit.
            let describe = |e: ConfigError| match e {
                ConfigError::Parse { .. } => e.to_string(), // already begins with the path
                other => format!("{}: {other}", file.display()),
            };
            let cfg = Config::load(&file).map_err(describe)?;
            // Run the same deterministic checks the daemon runs at startup, so `check` no longer prints
            // `ok` for a config that `up` then refuses (a key file it cannot use, a missing sandbox, a box
            // path inside the home).
            cfg.check_model_keys(&paths.model_keys_dir())?;
            loom_tools::sandbox::preflight(&cfg.sandbox).map_err(|e| e.to_string())?;
            cfg.check_box_paths(&paths.home).map_err(|e| e.to_string())?;
            loom_agent::runtime::check_infrastructure(&cfg)?;
            // Then the model policy, which the daemon does not refuse to start on: who reviews each profile.
            let packs = loom_agent::pack::Packs::load(&paths.packs_dir())?;
            let report = loom_agent::monitor::lineage::check_config(&cfg, &packs);
            for line in &report.table {
                outln(line)?;
            }
            for note in &report.notes {
                errln(&format!("note: {note}"));
            }
            if !report.problems.is_empty() {
                return Err(format!(
                    "The model policy is not settled ({} to fix):\n\n{}",
                    report.problems.len(),
                    report.problems.join("\n\n")
                ));
            }
            outln(&format!("ok: {}", file.display()))?;
            for line in cfg.key_env_warnings(&paths.model_keys_dir(), env_var_is_set) {
                errln(&format!("warning: {line}"));
            }
            Ok(0)
        }
        ConfigAction::Init => {
            use std::os::unix::fs::OpenOptionsExt;
            loom_core::config::ensure_private_dir(&paths.home)
                .map_err(|e| format!("Cannot create {} ({e}).", paths.home.display()))?;
            let mut f = match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(format!("{} already exists.", file.display()));
                }
                Err(e) => return Err(format!("Cannot write {} ({e}).", file.display())),
            };
            f.write_all(DEFAULT_CONFIG.as_bytes()).map_err(|e| format!("Cannot write {} ({e}).", file.display()))?;
            outln(&format!("wrote {}", file.display())).map(|()| 0)
        }
    }
}

/// `5m`, `12h`, `7d` (before `now_ms`), or a time in milliseconds since the epoch.
pub(crate) fn parse_since(word: &str, now_ms: u64) -> Result<u64, String> {
    let w = word.trim();
    let bad = || format!("--since \"{word}\" is not a time. Use 90m, 12h or 7d, or milliseconds since the epoch.");
    if let Some((n, unit)) = w.char_indices().last().and_then(|(i, u)| w.get(..i).map(|n| (n, u))) {
        let mult: Option<u64> = match unit {
            'm' => Some(60_000),
            'h' => Some(3_600_000),
            'd' => Some(86_400_000),
            _ => None,
        };
        if let (Some(m), Ok(n)) = (mult, n.parse::<u64>()) {
            return Ok(now_ms.saturating_sub(n.saturating_mul(m)));
        }
    }
    w.parse::<u64>().map_err(|_| bad())
}

/// One line for the terminal: every control and bidirectional override replaced (a tripwire's detail and key carry
/// strings an agent chose), and no line break inside it.
fn terminal_line(text: &str) -> String {
    render::clean(text).replace(['\n', '\t'], "·")
}

fn monitor_status_lines(m: &loom_agent::monitor::core::MonitorStatus) -> Vec<String> {
    monitor_status_raw(m).iter().map(|l| terminal_line(l)).collect()
}

fn monitor_status_raw(m: &loom_agent::monitor::core::MonitorStatus) -> Vec<String> {
    let mut l = vec![format!(
        "monitor: {} ({} mode){}",
        m.state,
        m.mode,
        m.down_reason.as_deref().map_or(String::new(), |r| format!(": {r}"))
    )];
    l.push(format!(
        "read {} records, {} net decisions and {} floor events from {} sessions; {} open flags; {} paused, {} halted",
        m.counts.records,
        m.counts.net,
        m.counts.floor,
        m.sources,
        m.open_flags,
        m.paused.len(),
        m.halts.len()
    ));
    if m.egress_unbounded {
        l.push("egress: UNBOUNDED (the sandbox self-probe found a route outside the proxy)".to_string());
    }
    for f in &m.faults {
        l.push(format!("source fault: {f}"));
    }
    l.push(format!(
        "{:<6} {:<34} {:<9} {:>6} {:>5} {:>5} {:>5} {:>5}",
        "id", "tripwire", "starts", "fired", "S1", "S2", "S3", "S4"
    ));
    for t in &m.tripwires {
        l.push(format!(
            "{:<6} {:<34} {:<9} {:>6} {:>5} {:>5} {:>5} {:>5}",
            t.id, t.name, t.start, t.fired, t.by_severity[1], t.by_severity[2], t.by_severity[3], t.by_severity[4]
        ));
    }
    l.push(
        "Every tripwire is in shadow: a finding is recorded and shown, and changes nothing for any agent.".to_string(),
    );
    l
}

fn monitor_entry_line(e: &loom_agent::monitor::log::Entry) -> String {
    terminal_line(&monitor_entry_raw(e))
}

fn monitor_entry_raw(e: &loom_agent::monitor::log::Entry) -> String {
    let get = |k: &str| e.fields.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let when = e.ts_ms / 1000;
    match e.kind.slug() {
        "tripwire" => format!(
            "#{} {when} {} {} {} would {}{} {} ({})",
            e.seq,
            get("id"),
            get("severity"),
            get("session"),
            get("would"),
            if e.fields.get("precision").and_then(|v| v.as_bool()).unwrap_or(false) { " precision-list" } else { "" },
            get("detail"),
            get("category")
        ),
        "flag" => format!(
            "#{} {when} flag {} {} {} x{} {} [{}]",
            e.seq,
            get("flag"),
            get("severity"),
            get("category"),
            e.fields.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
            get("key"),
            e.fields.get("causes").map_or(String::new(), |c| c.to_string())
        ),
        "response" => format!(
            "#{} {when} response {} would {} {}",
            e.seq,
            get("level"),
            get("would"),
            e.fields.get("causes").map_or(String::new(), |c| c.to_string())
        ),
        other => format!("#{} {when} {other} {}", e.seq, serde_json::to_string(&e.fields).unwrap_or_default()),
    }
}

async fn cmd_monitor(paths: &Paths, args: MonitorArgs) -> Result<i32, String> {
    match args.action.unwrap_or(MonitorAction::Status) {
        MonitorAction::Status => {
            let m = client_of(paths)?.monitor_status().await?;
            for line in monitor_status_lines(&m) {
                outln(&line)?;
            }
            Ok(0)
        }
        MonitorAction::Log(a) => {
            let c = client_of(paths)?;
            let mission = c.mission_of(&a.target).await?;
            let since = a.since.as_deref().map(|w| parse_since(w, loom_core::now_ms())).transpose()?;
            let mut after = 0;
            let mut left = a.limit.max(1);
            loop {
                let page = c.monitor_log(&mission, after, left.min(2000), !a.all).await?;
                for e in &page.entries {
                    if since.is_some_and(|s| e.ts_ms < s) {
                        continue;
                    }
                    if a.json {
                        outln(&serde_json::to_string(e).map_err(|x| x.to_string())?)?;
                    } else {
                        outln(&monitor_entry_line(e))?;
                    }
                    left = left.saturating_sub(1);
                }
                match page.next_after {
                    Some(n) if left > 0 => after = n,
                    _ => break,
                }
            }
            Ok(0)
        }
        MonitorAction::Replay(a) => {
            let home = a.home.as_ref().map_or_else(|| paths.clone(), |h| Paths::at(h.clone()));
            let since = a.since.as_deref().map(|w| parse_since(w, loom_core::now_ms())).transpose()?;
            let positives = match &a.positives {
                Some(f) => std::fs::read_to_string(f)
                    .map_err(|e| format!("{} cannot be read: {e}.", f.display()))?
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(MissionId::from)
                    .collect(),
                None => Default::default(),
            };
            let key = if a.no_journal_key { None } else { loom_core::journal::load_existing_key(&home.journal_key()) };
            let report = tokio::task::spawn_blocking(move || {
                let env = loom_agent::monitor::replay::env_for_home(&home)?;
                let opts = loom_agent::monitor::replay::ReplayOpts { since_ms: since, positives };
                Ok::<_, String>(loom_agent::monitor::replay::run(&home, std::sync::Arc::new(env), key, &opts))
            })
            .await
            .map_err(|e| format!("The replay stopped: {e}."))??;
            if a.json {
                outln(&serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?)?;
            } else {
                for line in report.lines() {
                    outln(&line)?;
                }
            }
            Ok(0)
        }
    }
}

/// `loom models lineage [profile]`: reads the configuration and the packs; needs no daemon.
fn cmd_models_lineage(paths: &Paths, profile: Option<&str>) -> Result<i32, String> {
    let config = Config::load(&paths.config_file()).map_err(|e| e.to_string())?;
    let packs = loom_agent::pack::Packs::load(&paths.packs_dir())?;
    for line in loom_agent::monitor::lineage::show_lines(&config, &packs, profile)? {
        outln(&line)?;
    }
    Ok(0)
}

/// Run `launchctl` and return its output when it succeeds, else its complaint.
fn launchctl(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|e| format!("Cannot run launchctl ({e})."))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let said = String::from_utf8_lossy(&output.stderr);
        Err(format!("launchctl {} failed: {}", args.first().copied().unwrap_or(""), said.trim()))
    }
}

/// Prepare the home (`serve::prepare_home`) and write the agent's property list to `plist`. launchd opens the log the
/// list names itself, with its own default mode, so the log is created here first (0600); launchd appends to a file
/// that exists without changing its mode.
fn write_service_files(paths: &Paths, plist: &Path, exe: &Path) -> Result<(), String> {
    if let Some(dir) = plist.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create {} ({e}).", dir.display()))?;
    }
    crate::serve::prepare_home(paths)?;
    crate::serve::open_daemon_log(paths)?;
    std::fs::write(plist, crate::serve::launch_agent_plist(exe, &paths.home))
        .map_err(|e| format!("Cannot write {} ({e}).", plist.display()))
}

fn cmd_service(paths: &Paths, action: ServiceAction) -> Result<i32, String> {
    if !cfg!(target_os = "macos") {
        return Err("This command is for macOS (launchd).".to_string());
    }
    use crate::serve::SERVICE_LABEL;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is not set, so there is no LaunchAgents folder to use.")?;
    let plist = home.join("Library/LaunchAgents").join(format!("{SERVICE_LABEL}.plist"));
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    match action {
        ServiceAction::Install => {
            let exe = std::env::current_exe().map_err(|e| format!("Cannot find this program's path ({e})."))?;
            let config = Config::load(&paths.config_file()).map_err(|e| e.to_string())?;
            service_key_check(&config, &paths.model_keys_dir())?;
            write_service_files(paths, &plist, &exe)?;
            launchctl(&["bootstrap", &domain, &plist.display().to_string()])?;
            outln(&format!("installed {}; the daemon starts at login", plist.display())).map(|()| 0)
        }
        ServiceAction::Uninstall => {
            let target = format!("{domain}/{SERVICE_LABEL}");
            // Not being loaded is not a reason to keep the file.
            let unloaded = launchctl(&["bootout", &target]);
            match std::fs::remove_file(&plist) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && unloaded.is_err() => {
                    return Err("The service is not installed.".to_string());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("Cannot remove {} ({e}).", plist.display())),
            }
            outln("uninstalled").map(|()| 0)
        }
        ServiceAction::Status => match launchctl(&["print", &format!("{domain}/{SERVICE_LABEL}")]) {
            Ok(_) => outln("loaded").map(|()| 0),
            Err(_) => {
                outln(if plist.exists() { "installed but not loaded" } else { "not installed" })?;
                Ok(1)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::testkit::*;
    use loom_core::event::{Author, FinishReason, ModelResponse, Trigger};

    fn words(w: &[&str]) -> Vec<String> {
        w.iter().map(|s| s.to_string()).collect()
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        let mut all = vec!["loom"];
        all.extend_from_slice(args);
        Cli::try_parse_from(all)
    }

    fn ok(args: &[&str]) -> Command {
        match parse(args) {
            Ok(cli) => cli.command,
            Err(e) => panic!("{args:?} should parse: {e}"),
        }
    }

    fn rejected(args: &[&str]) {
        assert!(parse(args).is_err(), "{args:?} should be rejected");
    }

    #[test]
    fn monitor_commands_parse_and_since_reads_a_duration_or_a_time() {
        assert!(matches!(ok(&["monitor"]), Command::Monitor(MonitorArgs { action: None })));
        assert!(matches!(
            ok(&["monitor", "status"]),
            Command::Monitor(MonitorArgs { action: Some(MonitorAction::Status) })
        ));
        match ok(&["monitor", "log", "m-1", "--json", "--since", "7d", "--all", "-n", "5"]) {
            Command::Monitor(MonitorArgs { action: Some(MonitorAction::Log(a)) }) => {
                assert_eq!((a.target.as_str(), a.json, a.all, a.limit), ("m-1", true, true, 5));
                assert_eq!(a.since.as_deref(), Some("7d"));
            }
            other => panic!("not log: {other:?}"),
        }
        match ok(&["monitor", "replay", "--positives", "p.txt", "--home", "/h", "--no-journal-key", "--json"]) {
            Command::Monitor(MonitorArgs { action: Some(MonitorAction::Replay(a)) }) => {
                assert_eq!((a.json, a.no_journal_key), (true, true));
                assert_eq!(a.positives.as_deref(), Some(std::path::Path::new("p.txt")));
                assert_eq!(a.home.as_deref(), Some(std::path::Path::new("/h")));
            }
            other => panic!("not replay: {other:?}"),
        }
        assert!(Cli::try_parse_from(["loom", "monitor", "log"]).is_err(), "log needs a mission or session");
        let now = 10_000_000_000u64;
        assert_eq!(parse_since("90m", now).ok(), Some(now - 90 * 60_000));
        assert_eq!(parse_since("12h", now).ok(), Some(now - 12 * 3_600_000));
        assert_eq!(parse_since("7d", now).ok(), Some(now - 7 * 86_400_000));
        assert_eq!(parse_since("1234567", now).ok(), Some(1_234_567));
        let e = parse_since("soon", now).err().unwrap_or_default();
        assert!(e.contains("90m, 12h or 7d"), "{e}");
        assert_eq!(parse_since("99999d", 5).ok(), Some(0), "a window longer than the history starts at the beginning");
    }

    #[test]
    fn monitor_status_and_entries_print_in_words() {
        let t = loom_agent::monitor::core::TwStatus {
            id: "TW-10".into(),
            name: "other sessions and processes".into(),
            start: "precision".into(),
            state: "shadow".into(),
            fired: 3,
            by_severity: [0, 0, 1, 2, 0],
            missions: 2,
        };
        let m = loom_agent::monitor::core::MonitorStatus {
            state: "degraded".into(),
            mode: "shadow".into(),
            enabled: true,
            egress_unbounded: true,
            open_flags: 2,
            paused: vec![],
            halts: vec![],
            backlog_s: 0,
            heartbeat_ms: 1,
            last_seq: 9,
            sources: 4,
            counts: Default::default(),
            tripwires: vec![t],
            faults: vec!["a log does not continue its chain".into()],
            fleet_runs: 0,
            fleet_hits: 0,
            reviewers: vec![],
            down_reason: None,
        };
        let text = monitor_status_lines(&m).join("\n");
        assert!(text.contains("monitor: degraded (shadow mode)") && text.contains("2 open flags"), "{text}");
        assert!(text.contains("egress: UNBOUNDED") && text.contains("source fault: a log does not continue"), "{text}");
        assert!(text.contains("TW-10") && text.contains("changes nothing for any agent"), "{text}");
        let mut fields = serde_json::Map::new();
        fields.insert("id".into(), "TW-09".into());
        fields.insert("severity".into(), "s3".into());
        fields.insert("session".into(), "s-1".into());
        fields.insert("would".into(), "r3".into());
        fields.insert("precision".into(), true.into());
        fields.insert("detail".into(), "writes a hook".into());
        fields.insert("category".into(), "harness_attack".into());
        let e = loom_agent::monitor::log::Entry {
            seq: 7,
            ts_ms: 5_000,
            prev: String::new(),
            mac: String::new(),
            kind: loom_agent::monitor::log::EntryKind::Tripwire,
            fields,
        };
        let line = monitor_entry_line(&e);
        assert_eq!(line, "#7 5 TW-09 s3 s-1 would r3 precision-list writes a hook (harness_attack)");
        // What an agent chose reaches the terminal as text: no escape, no OSC, no bidi override, no line break.
        let mut hostile = e.clone();
        hostile
            .fields
            .insert("detail".into(), "x\u{1b}[2K\u{1b}[1Ahidden\u{1b}]52;c;ZWNobyBoaQ==\u{7}\u{202e}\nTW-99".into());
        hostile.fields.insert("key".into(), "k\u{1b}[2J".into());
        let line = monitor_entry_line(&hostile);
        assert!(!line.chars().any(|c| c.is_control() || ('\u{202a}'..='\u{202e}').contains(&c)), "{line:?}");
        assert!(!line.contains('\n'), "{line:?}");
        let mut flag = hostile.clone();
        flag.kind = loom_agent::monitor::log::EntryKind::Flag;
        let line = monitor_entry_line(&flag);
        assert!(!line.chars().any(char::is_control), "{line:?}");
        m_faults_are_clean();
    }

    fn m_faults_are_clean() {
        let m = loom_agent::monitor::core::MonitorStatus {
            state: "degraded".into(),
            mode: "shadow".into(),
            enabled: true,
            egress_unbounded: false,
            open_flags: 0,
            paused: vec![],
            halts: vec![],
            backlog_s: 0,
            heartbeat_ms: 1,
            last_seq: 1,
            sources: 1,
            counts: Default::default(),
            tripwires: vec![],
            faults: vec!["bad\u{1b}[2Jfault\nnext".into()],
            fleet_runs: 0,
            fleet_hits: 0,
            reviewers: vec![],
            down_reason: Some("why\u{1b}]52;c;AAAA\u{7}".into()),
        };
        for line in monitor_status_lines(&m) {
            assert!(!line.chars().any(char::is_control), "{line:?}");
        }
    }

    #[test]
    fn the_unverified_daemon_flag_is_global() {
        assert!(!parse(&["status"]).unwrap().unverified_daemon);
        assert!(parse(&["--unverified-daemon", "down"]).unwrap().unverified_daemon);
        assert!(parse(&["down", "--unverified-daemon"]).unwrap().unverified_daemon);
    }

    #[test]
    fn simple_commands_parse() {
        assert!(matches!(ok(&["daemon"]), Command::Daemon));
        assert!(matches!(ok(&["up"]), Command::Up));
        assert!(matches!(ok(&["down"]), Command::Down));
        assert!(matches!(ok(&["status"]), Command::Status));
        assert!(matches!(ok(&["inbox"]), Command::Inbox));
        assert!(matches!(ok(&["open"]), Command::Open(OpenArgs { print: false })));
        assert!(matches!(ok(&["open", "--print"]), Command::Open(OpenArgs { print: true })));
        assert!(matches!(ok(&["ls"]), Command::Ls(LsArgs { all: false })));
        assert!(matches!(ok(&["ls", "-a"]), Command::Ls(LsArgs { all: true })));
        assert!(matches!(ok(&["ls", "--all"]), Command::Ls(LsArgs { all: true })));
        rejected(&[]);
        rejected(&["nonsense"]);
        rejected(&["status", "extra"]);
    }

    #[test]
    fn run_parses_every_option() {
        let Command::Run(a) = ok(&[
            "run",
            "-w",
            "/work",
            "--pack",
            "p",
            "--role",
            "r",
            "-m",
            "big",
            "-t",
            "T",
            "--attended",
            "--max-steps",
            "5",
            "--max-minutes",
            "9",
            "--prior",
            "m-1",
            "--prior",
            "last",
            "--create-workspace",
            "-d",
            "--reasoning",
            "--full",
            "-v",
            "fix",
            "the",
            "bug",
        ]) else {
            panic!("not run");
        };
        assert_eq!(a.start.workspace, Some(PathBuf::from("/work")));
        assert!(a.start.create_workspace);
        assert_eq!(a.start.pack.as_deref(), Some("p"));
        assert_eq!(a.start.role.as_deref(), Some("r"));
        assert_eq!(a.start.model.as_deref(), Some("big"));
        assert_eq!(a.start.title.as_deref(), Some("T"));
        assert!(a.start.attended);
        assert_eq!((a.start.max_steps, a.start.max_minutes), (5, 9));
        assert_eq!(a.start.prior, words(&["m-1", "last"]));
        assert!(a.detach && a.show.reasoning && a.show.full && a.show.verbose);
        assert_eq!(a.message, words(&["fix", "the", "bug"]));
        let Command::Run(a) = ok(&["run"]) else { panic!("not run") };
        assert!(a.message.is_empty() && !a.detach && !a.start.attended && a.start.prior.is_empty());
        assert_eq!((a.start.max_steps, a.start.max_minutes), (0, 0));
        let Command::Run(a) = ok(&["run", "-"]) else { panic!("not run") };
        assert_eq!(a.message, words(&["-"]));
        let Command::Run(a) = ok(&["run", "--", "-5", "is", "negative"]) else { panic!("not run") };
        assert_eq!(a.message, words(&["-5", "is", "negative"]));
        rejected(&["run", "--max-steps", "many"]);
        rejected(&["run", "--prior"]);
        let Command::Chat(a) = ok(&["chat", "--prior", "s-9"]) else { panic!("not chat") };
        assert_eq!(a.start.prior, words(&["s-9"]));
        rejected(&["run", "--no-such-flag"]);
    }

    #[test]
    fn chat_tail_and_send_parse() {
        let Command::Chat(a) = ok(&["chat", "--session", "s-1", "-w", "/w", "--reasoning"]) else { panic!("not chat") };
        assert_eq!(a.session.as_deref(), Some("s-1"));
        assert!(a.show.reasoning);
        let Command::Chat(a) = ok(&["chat"]) else { panic!("not chat") };
        assert!(a.session.is_none());

        let Command::Tail(a) = ok(&["tail", "s-1", "--since", "40", "--no-follow", "--reasoning", "--full", "-v"])
        else {
            panic!("not tail")
        };
        assert_eq!((a.session.as_str(), a.since, a.no_follow), ("s-1", Some(40), true));
        assert!(a.show.reasoning && a.show.full && a.show.verbose);
        rejected(&["tail"]);
        rejected(&["tail", "s-1", "--since", "x"]);

        let Command::Send(a) = ok(&["send", "last", "hello", "there", "-d"]) else { panic!("not send") };
        assert_eq!((a.session.as_str(), a.detach), ("last", true));
        assert_eq!(a.text, words(&["hello", "there"]));
        let Command::Send(a) = ok(&["send", "last", "-"]) else { panic!("not send") };
        assert_eq!(a.text, words(&["-"]));
        rejected(&["send"]);
        let Command::Send(a) = ok(&["send", "s-1", "--file", "a.csv", "--file", "b.png", "look"]) else {
            panic!("not send")
        };
        assert_eq!(a.files, vec![PathBuf::from("a.csv"), PathBuf::from("b.png")]);
        assert_eq!(a.text, words(&["look"]));
        let Command::Run(a) = ok(&["run", "--file", "x.txt"]) else { panic!("not run") };
        assert_eq!((a.files, a.message.is_empty()), (vec![PathBuf::from("x.txt")], true));
    }

    #[test]
    fn session_commands_parse_and_need_their_argument() {
        assert!(matches!(ok(&["stop", "s-1"]), Command::Stop(SessionArg { .. })));
        assert!(matches!(ok(&["resume", "s-1"]), Command::Resume(_)));
        assert!(matches!(ok(&["compact", "s-1"]), Command::Compact(_)));
        assert!(matches!(ok(&["ledger", "m-1"]), Command::Ledger(_)));
        assert!(matches!(ok(&["window", "s-1"]), Command::Window(_)));
        for cmd in ["stop", "resume", "compact", "archive", "ledger", "score", "window", "net", "answer", "out"] {
            rejected(&[cmd]);
        }
        let Command::Score(a) = ok(&["score", "last"]) else { panic!("not score") };
        assert_eq!((a.session.as_str(), a.json), ("last", false));
        let Command::Score(a) = ok(&["score", "m-1", "--json"]) else { panic!("not score") };
        assert_eq!((a.session.as_str(), a.json), ("m-1", true));
        rejected(&["score", "s-1", "--csv"]);
        let Command::Archive(a) = ok(&["archive", "s-1", "--undo"]) else { panic!("not archive") };
        assert!(a.undo);
        let Command::Archive(a) = ok(&["archive", "s-1"]) else { panic!("not archive") };
        assert!(!a.undo);
        let Command::Rename(a) = ok(&["rename", "last", "Grafana", "CVE", "hunt"]) else { panic!("not rename") };
        assert_eq!((a.session.as_str(), a.title.join(" ").as_str()), ("last", "Grafana CVE hunt"));
        rejected(&["rename", "s-1"]); // a title is required
        let Command::Rule(a) = ok(&["rule", "s-1", "no", "prod"]) else { panic!("not rule") };
        assert_eq!((a.session.as_str(), a.text, a.withdraw), ("s-1", words(&["no", "prod"]), None));
        let Command::Rule(a) = ok(&["rule", "last", "--withdraw", "k2", "--reason", "done now"]) else {
            panic!("not rule")
        };
        assert_eq!((a.withdraw.as_deref(), a.reason.as_deref()), (Some("k2"), Some("done now")));
        assert!(a.text.is_empty());
        rejected(&["rule"]);
        rejected(&["rule", "s-1", "--withdraw", "k1", "extra words"]);
        rejected(&["rule", "s-1", "--reason", "why"]);
        // The reason and the scope are optional; a mission's ledger records a stock one in their place.
        let Command::Rule(a) = ok(&["rule", "s-1", "--withdraw", "k1"]) else { panic!("not rule") };
        assert_eq!((a.withdraw.as_deref(), a.reason), (Some("k1"), None));
        let Command::Approve(a) = ok(&["approve", "s-1", "ship", "it"]) else { panic!("not approve") };
        assert_eq!((a.text, a.scope), (words(&["ship", "it"]), None));
        let Command::Approve(a) = ok(&["approve", "s-1", "ship", "it", "--scope", "staging"]) else {
            panic!("not approve")
        };
        assert_eq!((a.text, a.scope.as_deref()), (words(&["ship", "it"]), Some("staging")));
        rejected(&["approve"]);
        let Command::Scope(a) = ok(&["scope", "last", "docs.example.test", "*.cdn.test"]) else { panic!("not scope") };
        assert_eq!(
            (a.session.as_deref(), a.hosts, a.note),
            (Some("last"), words(&["docs.example.test", "*.cdn.test"]), None)
        );
        let Command::Scope(a) = ok(&["scope", "s-1", "a.test", "--note", "for the docs"]) else { panic!("not scope") };
        assert_eq!((a.hosts, a.note.as_deref()), (words(&["a.test"]), Some("for the docs")));
        rejected(&["scope"]);
        rejected(&["scope", "s-1"]);
        let Command::Scope(a) = ok(&["scope", "revoke", "m-1", "a.test", "--reason", "wrong target"]) else {
            panic!("not scope revoke")
        };
        let Some(ScopeAction::Revoke(r)) = a.action else { panic!("not revoke") };
        assert_eq!((r.mission.as_str(), r.host.as_str(), r.reason.as_str()), ("m-1", "a.test", "wrong target"));
        rejected(&["scope", "revoke", "m-1", "a.test"]);
        rejected(&["scope", "revoke", "m-1", "--reason", "x"]);
        let Command::Release(a) = ok(&["release", "s-1", "target", "is", "gone"]) else { panic!("not release") };
        assert_eq!((a.session.as_str(), a.reason), ("s-1", words(&["target", "is", "gone"])));
        rejected(&["release"]);
        assert!(matches!(ok(&["gc"]), Command::Gc(GcArgs { apply: false })));
        assert!(matches!(ok(&["gc", "--apply"]), Command::Gc(GcArgs { apply: true })));
        rejected(&["gc", "--force"]);
        let Command::Answer(a) = ok(&["answer", "i-1", "yes", "please"]) else { panic!("not answer") };
        assert_eq!((a.item.as_str(), a.text), ("i-1", words(&["yes", "please"])));
        let Command::Answer(a) = ok(&["answer", "i-1"]) else { panic!("not answer") };
        assert!(a.text.is_empty());
        let Command::Net(a) = ok(&["net", "s-1"]) else { panic!("not net") };
        assert_eq!(a.limit, 200);
        let Command::Net(a) = ok(&["net", "s-1", "-n", "5"]) else { panic!("not net") };
        assert_eq!(a.limit, 5);
        rejected(&["net", "s-1", "-n", "lots"]);
        let Command::Out(a) = ok(&["out", "out:7f3a", "--lines", "10:20"]) else { panic!("not out") };
        assert_eq!((a.handle.as_str(), a.lines.as_deref()), ("out:7f3a", Some("10:20")));
        let Command::Out(a) = ok(&["out", "out:7f3a"]) else { panic!("not out") };
        assert!(a.lines.is_none());
    }

    #[test]
    fn config_and_service_parse() {
        assert!(matches!(ok(&["config", "path"]), Command::Config { action: ConfigAction::Path }));
        assert!(matches!(ok(&["config", "check"]), Command::Config { action: ConfigAction::Check }));
        assert!(matches!(ok(&["config", "init"]), Command::Config { action: ConfigAction::Init }));
        assert!(matches!(
            ok(&["models", "lineage"]),
            Command::Models { action: ModelsAction::Lineage { profile: None } }
        ));
        assert!(matches!(
            ok(&["models", "lineage", "dsv41"]),
            Command::Models { action: ModelsAction::Lineage { profile: Some(p) } } if p == "dsv41"
        ));
        rejected(&["models", "show"]); // a session: `models show` is a mission's models
        assert!(matches!(ok(&["service", "install"]), Command::Service { action: ServiceAction::Install }));
        assert!(matches!(ok(&["service", "uninstall"]), Command::Service { action: ServiceAction::Uninstall }));
        assert!(matches!(ok(&["service", "status"]), Command::Service { action: ServiceAction::Status }));
        rejected(&["config"]);
        rejected(&["config", "edit"]);
        rejected(&["service"]);
        assert!(matches!(ok(&["mcp", "list"]), Command::Mcp { action: McpAction::List }));
        let Command::Mcp { action: McpAction::Check(a) } = ok(&["mcp", "check", "github", "--workspace", "/w"]) else {
            panic!("not mcp check")
        };
        assert_eq!((a.server.as_str(), a.workspace), ("github", Some(PathBuf::from("/w"))));
        rejected(&["mcp"]);
        rejected(&["mcp", "check"]);
        assert!(matches!(ok(&["models", "list"]), Command::Models { action: ModelsAction::List }));
        assert!(matches!(ok(&["models", "reload"]), Command::Models { action: ModelsAction::Reload }));
        let Command::Models { action: ModelsAction::Set(a) } = ok(&["models", "set", "last", "big"]) else {
            panic!("not models set")
        };
        assert_eq!((a.session.as_str(), a.profile.as_str()), ("last", "big"));
        rejected(&["models"]);
        rejected(&["models", "set", "last"]); // a profile is required
        let Command::Models { action: ModelsAction::Show(a) } = ok(&["models", "show", "last"]) else {
            panic!("not models show")
        };
        assert_eq!(a.session, "last");
        let Command::Models { action: ModelsAction::Role(a) } =
            ok(&["models", "role", "last", "worker", "fast", "--now"])
        else {
            panic!("not models role")
        };
        assert_eq!((a.role.as_str(), a.profile.as_deref(), a.clear, a.now), ("worker", Some("fast"), false, true));
        let Command::Models { action: ModelsAction::Role(a) } = ok(&["models", "role", "last", "all", "--clear"])
        else {
            panic!("not models role --clear")
        };
        assert_eq!((cli_role(&a.role).as_str(), a.profile, a.clear), ("*", None, true));
        rejected(&["models", "role", "last", "worker"]); // a profile, or --clear
        rejected(&["models", "role", "last", "worker", "fast", "--clear"]);
        rejected(&["models", "role", "last", "worker", "--clear", "--now"]);
        // `all` spells every role on the command line: `*` alone is globbed by shells.
        let Command::Run(a) = ok(&["run", "--agent-model", "worker=fast", "--agent-model", "all=big", "go"]) else {
            panic!("not run")
        };
        assert_eq!(a.start.agent_models, vec![("worker".into(), "fast".into()), ("*".into(), "big".into())]);
        rejected(&["run", "--agent-model", "worker", "go"]);
        rejected(&["run", "--agent-model", "=fast", "go"]);
    }

    #[test]
    fn messages_are_joined_and_dash_means_standard_input() {
        assert_eq!(message_from_args(&words(&["fix", "the", "bug"])).as_deref(), Some("fix the bug"));
        assert_eq!(message_from_args(&words(&["one"])).as_deref(), Some("one"));
        assert_eq!(message_from_args(&words(&["-", "x"])).as_deref(), Some("- x"));
        assert_eq!(message_from_args(&words(&["-"])), None);
        assert_eq!(message_from_args(&[]), None);
        // The refusal names what was asked for: a rule or an approval is not a message.
        assert_eq!(read_message(&words(&["no", "prod"]), "rule").as_deref(), Ok("no prod"));
        assert_eq!(read_message(&words(&["  "]), "rule").unwrap_err(), "The rule is empty.");
        assert_eq!(read_message(&words(&[" ", ""]), "approval").unwrap_err(), "The approval is empty.");
        assert_eq!(read_message(&words(&[""]), "message").unwrap_err(), "The message is empty.");
    }

    #[test]
    fn receipt_lines_say_whether_the_lead_has_recorded_it() {
        let receipt = |queued: bool, ledger: bool, stock: Option<&str>| RuleReceipt {
            lead: SessionId::from("s-1"),
            queued,
            ledger,
            stock: stock.map(str::to_string),
        };
        assert_eq!(receipt_line("rule", "", &receipt(false, true, None)), "rule sent to s-1");
        assert_eq!(
            receipt_line("rule", "", &receipt(true, true, None)),
            "rule queued for s-1: the lead is in a turn and records it at its next step, not while a tool call is running; check with loom ledger s-1"
        );
        assert_eq!(
            receipt_line("approval", "scope", &receipt(false, true, Some("only what the approval says"))),
            "approval sent to s-1; scope recorded as \"only what the approval says\""
        );
        assert_eq!(
            receipt_line("withdrawal of k2", "reason", &receipt(true, true, Some("no reason given"))),
            "withdrawal of k2 queued for s-1: the lead is in a turn and records it at its next step, not while a tool call is running; reason recorded as \"no reason given\"; check with loom ledger s-1"
        );
        assert_eq!(
            receipt_line("rule", "", &receipt(false, false, None)),
            "rule sent to s-1; this mission keeps no ledger, so it is a note in the lead's window without an id"
        );
        // Words after --withdraw are refused by the parser; the help says where they belong.
        let help = parse(&["rule", "--help"]).unwrap_err().to_string();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(help.contains("say why with --reason"), "{help}");
    }

    #[test]
    fn scope_and_release_lines_say_what_was_granted_and_how_the_mission_closed() {
        let scope = |ledger: bool| ScopeReceipt {
            lead: SessionId::from("s-1"),
            hosts: vec!["a.test".to_string(), "*.b.test".to_string()],
            ledger,
        };
        assert_eq!(scope_line(&scope(true)), "scope granted for s-1: a.test, *.b.test");
        assert_eq!(
            scope_line(&scope(false)),
            "scope granted for s-1: a.test, *.b.test; this mission keeps no ledger, so the grant is not listed"
        );
        let release = |queued: bool| RuleReceipt { lead: SessionId::from("s-1"), queued, ledger: true, stock: None };
        assert_eq!(release_line(&release(false)), "closed by operator, goal not established: release sent to s-1");
        assert!(release_line(&release(true))
            .starts_with("closed by operator, goal not established: release queued for s-1"));
        // A blank reason is refused before anything is sent.
        assert_eq!(read_message(&words(&["  "]), "reason").unwrap_err(), "The reason is empty.");
    }

    #[test]
    fn line_ranges() {
        assert_eq!(parse_lines("10:20"), Ok((10, Some(20))));
        assert_eq!(parse_lines("10:"), Ok((10, None)));
        assert_eq!(parse_lines(":20"), Ok((1, Some(20))));
        assert_eq!(parse_lines("5:5"), Ok((5, Some(5))));
        assert_eq!(parse_lines(" 3 : 4 "), Ok((3, Some(4))));
        for bad in ["", ":", "10", "a:b", "10:x", "-1:5", "1:2:3", "10-20"] {
            let e = parse_lines(bad).unwrap_err();
            assert!(e.contains("is not a line range"), "{bad}: {e}");
        }
        assert!(parse_lines("0:5").unwrap_err().contains("line 0"));
        assert!(parse_lines(":0").unwrap_err().contains("line 0"));
        assert!(parse_lines("20:10").unwrap_err().contains("reversed"));
    }

    #[test]
    fn exit_codes_of_every_turn_end() {
        use TurnEndReason::*;
        let table = [
            (Yielded, Some(0)),
            (Finished, Some(0)),
            (Asked, Some(2)),
            (Blocked, Some(2)),
            (Parked, Some(2)),
            (Stopped, Some(1)),
            (BudgetExhausted, Some(1)),
            (Error, Some(1)),
            (Waiting, None),
        ];
        for (reason, code) in table {
            assert_eq!(follow_exit_code(reason), code, "{reason:?}");
        }
        assert_eq!(outcome_code(SessionOutcome::Done), 0);
        assert_eq!(outcome_code(SessionOutcome::Failed), 1);
    }

    #[test]
    fn default_config_is_valid() {
        let config = Config::parse(DEFAULT_CONFIG).unwrap();
        config.check().unwrap();
        assert_eq!(config.daemon.bind, "127.0.0.1:7878");
        assert_eq!(config.network.mode, loom_core::config::NetworkMode::DenyAll);
        assert_eq!(config.agents.unavailable_notice_s, 300);
        assert!(config.monitor.tripwires_only_profiles.is_empty(), "not LLM-reviewed is the operator's choice");
    }

    #[test]
    fn a_fresh_config_fails_the_check_until_the_operator_chooses() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join("home"));
        assert_eq!(cmd_config(&paths, ConfigAction::Init), Ok(0));
        // The start-up checks run before the model policy, and the default sandbox is the system's own (seatbelt,
        // or bubblewrap with its binary): with no OS sandbox they pass on every host, so the check reaches the
        // policy everywhere. The generated config has a `[sandbox]` table, with its `mode` commented out.
        let init = std::fs::read_to_string(paths.config_file()).unwrap();
        let none = init.replacen("\n[sandbox]\n", "\n[sandbox]\nmode = \"none\"\n", 1);
        assert_ne!(none, init, "the generated config has a [sandbox] table");
        std::fs::write(paths.config_file(), none).unwrap();
        let err = cmd_config(&paths, ConfigAction::Check).unwrap_err();
        assert!(err.starts_with("The model policy is not settled"), "{err}");
        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        let chosen = text.replace("# tripwires_only_profiles", "tripwires_only_profiles");
        let rest = chosen.replace("[models.local]", "[models.local]\nfamily = [\"qwen\"]\nrecipient = \"local\"");
        std::fs::write(paths.config_file(), rest).unwrap();
        assert_eq!(cmd_config(&paths, ConfigAction::Check), Ok(0));
    }

    #[test]
    fn the_generated_config_with_a_small_window_is_accepted() {
        let text = DEFAULT_CONFIG.replace("# context_window = 1000000", "context_window = 32768");
        assert!(text.contains("\ncontext_window = 32768"));
        let config = Config::parse(&text).unwrap();
        config.check().unwrap();
        // The session clamps the bounds to the window (`ContextCfg::compact_at`); the config keeps its values.
        assert_eq!(config.models["local"].context_window, Some(32768));
        assert_eq!(config.context.compact_at(Some(32768)), 13_106);
    }

    #[test]
    fn the_browser_address() {
        assert_eq!(open_url("127.0.0.1:7878", "abc"), "http://127.0.0.1:7878/#code=abc");
    }

    #[tokio::test]
    async fn open_builds_a_code_url_without_the_token() {
        let script = Script::default().route("POST", "/api/login-codes", 200, r#"{"code":"c0de","expires_in_s":60}"#);
        let (c, shared) = start(script).await;
        let url = login_url(&c).await.unwrap();
        assert_eq!(url, format!("{}/#code=c0de", c.base()));
        assert!(!url.contains(c.token()) && !url.contains("token="));
        let script = shared.lock().unwrap();
        assert_eq!((script.seen[0].method.as_str(), script.seen[0].target.as_str()), ("POST", "/api/login-codes"));
        assert_eq!(script.seen[0].auth.as_deref(), Some("Bearer tok-123"));
    }

    #[test]
    fn the_login_code_is_in_a_private_page_file_and_not_on_the_openers_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let login = dir.path().join("login");
        let url = "http://127.0.0.1:7878/#code=c0de1234&x=\"<y>";
        let mut argv: Vec<String> = Vec::new();
        let mut page_text = String::new();
        let res = launch_browser_with(&login, url, |program, page| {
            argv = vec![program.to_string(), page.display().to_string()];
            page_text = std::fs::read_to_string(page).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(page).unwrap().permissions().mode() & 0o777, 0o600);
                assert_eq!(std::fs::metadata(page.parent().unwrap()).unwrap().permissions().mode() & 0o077, 0);
            }
            Ok(true)
        });
        assert_eq!(res, Ok(()));
        // Nothing the opener is started with holds the code or the address.
        assert!(argv.iter().all(|a| !a.contains("c0de1234") && !a.contains("127.0.0.1:7878")), "{argv:?}");
        assert!(argv[1].starts_with(login.to_str().unwrap()) && argv[1].ends_with(".html"), "{argv:?}");
        // The page sends the browser on, with the address escaped where it is markup.
        assert!(page_text.contains("http://127.0.0.1:7878/#code=c0de1234&amp;x=&quot;&lt;y&gt;"), "{page_text}");
        assert!(page_text.contains("location.replace(") && page_text.contains("no-referrer"), "{page_text}");
        // Another page is another file; an old page is removed by the next open, a fresh one is not.
        let old = login.join("login-old.html");
        std::fs::write(&old, "x").unwrap();
        let aged = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options().write(true).open(&old).unwrap().set_modified(aged).unwrap();
        let keep = login.join("notes.txt");
        std::fs::write(&keep, "mine").unwrap();
        assert_eq!(launch_browser_with(&login, url, |_, _| Ok(true)), Ok(()));
        assert!(!old.exists(), "a stale page is removed");
        assert!(keep.exists(), "other files are left alone");
        assert_eq!(
            std::fs::read_dir(&login)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("login-"))
                .count(),
            2
        );
        // An opener that fails leaves no page and says what to do.
        let before = std::fs::read_dir(&login).unwrap().count();
        let err = launch_browser_with(&login, url, |_, _| Ok(false)).unwrap_err();
        assert!(err.contains("loom open --print"), "{err}");
        let err = launch_browser_with(&login, url, |_, _| Err(std::io::Error::other("no opener"))).unwrap_err();
        assert!(err.contains("no opener") && err.contains("loom open --print"), "{err}");
        assert_eq!(std::fs::read_dir(&login).unwrap().count(), before);
        // A directory that cannot be made is an error that says what to do.
        std::fs::write(dir.path().join("file"), "x").unwrap();
        let err = launch_browser_with(&dir.path().join("file").join("login"), url, |_, _| Ok(true)).unwrap_err();
        assert!(err.contains("loom open --print"), "{err}");
    }

    #[tokio::test]
    async fn open_writes_the_address_only_with_print() {
        let script = Script::default().route("POST", "/api/login-codes", 200, r#"{"code":"c0de","expires_in_s":60}"#);
        let (c, _) = start(script).await;
        let url = format!("{}/#code=c0de", c.base());

        // Without --print the browser gets the address; the one line written says what to do if an editor opened.
        let mut out = Vec::new();
        let mut launched = Vec::new();
        let code = open_with(&c, &OpenArgs { print: false }, &mut out, |u| {
            launched.push(u.to_string());
            Ok(())
        })
        .await;
        assert_eq!(code, Ok(0));
        assert_eq!(launched, [url.as_str()]);
        let note = String::from_utf8(out).unwrap();
        assert_eq!(note, OPENED_NOTE);
        assert!(note.contains("loom open --print") && !note.contains("c0de"), "{note}");

        // With --print it is written and nothing is started.
        let mut out = Vec::new();
        let code = open_with(&c, &OpenArgs { print: true }, &mut out, |_| Err("--print starts nothing".into())).await;
        assert_eq!(code, Ok(0));
        assert_eq!(String::from_utf8(out).unwrap(), format!("{url}\n"));

        // A browser that cannot be started is the command's error, still with nothing written.
        let mut out: Vec<u8> = Vec::new();
        let code = open_with(&c, &OpenArgs { print: false }, &mut out, |_| Err("no browser".into())).await;
        assert_eq!(code, Err("no browser".to_string()));
        assert!(out.is_empty());

        // A daemon that issues no code is the command's error before anything is written or started.
        let (c, _) = start(Script::default().route("POST", "/api/login-codes", 401, r#"{"error":"Refused."}"#)).await;
        let code = open_with(&c, &OpenArgs { print: true }, &mut out, |_| Err("nothing to open".into())).await;
        assert_eq!(code, Err("Refused.".to_string()));
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn down_waits_for_a_daemon_that_no_longer_answers_to_let_go_of_the_home() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join("home"));
        std::fs::create_dir_all(&paths.home).unwrap();
        std::fs::write(paths.token_file(), "t").unwrap();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let write = |pid: u32| {
            let file = crate::wire::DaemonFile { pid, bind: closed.to_string(), started_ms: 1 };
            std::fs::write(paths.home.join("daemon.json"), serde_json::to_string(&file).unwrap()).unwrap();
            file
        };
        let held = crate::serve::take_home_lock(&paths).unwrap();
        // A daemon that is starting holds the home before it writes `daemon.json` (here a stale one naming
        // a pid no process can have): it is not waited for.
        write(4_000_000_000);
        let err = tokio::time::timeout(Duration::from_secs(2), down(&paths, Duration::from_secs(60)))
            .await
            .unwrap()
            .unwrap_err();
        assert!(err.starts_with("The loom daemon is not running"), "{err}");
        // `daemon.json` names a live process (this one) where nothing answers: a daemon shutting down. Still
        // holding the home when the wait runs out, the error names the process to wait for.
        let file = write(std::process::id());
        let err = down(&paths, Duration::from_millis(200)).await.unwrap_err();
        assert!(err.contains(&format!("until process {} exits", file.pid)), "{err}");
        assert!(err.contains("Run `loom down` again to keep waiting"), "{err}");
        // Let go during the wait: `stopped`.
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(held);
        });
        assert_eq!(down(&paths, Duration::from_secs(5)).await, Ok(0));
        release.await.unwrap();
        // Nothing answers and nothing holds the home: the daemon is not running.
        let err = down(&paths, Duration::from_secs(5)).await.unwrap_err();
        assert!(err.starts_with("The loom daemon is not running"), "{err}");
    }

    #[test]
    fn config_init_writes_once_and_check_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join("home"));
        assert_eq!(cmd_config(&paths, ConfigAction::Init), Ok(0));
        assert_eq!(std::fs::read_to_string(paths.config_file()).unwrap(), DEFAULT_CONFIG);
        assert_eq!(
            cmd_config(&paths, ConfigAction::Init).unwrap_err(),
            format!("{} already exists.", paths.config_file().display())
        );
        // `check` runs the start-up checks, so the default sandbox (seatbelt) passes only where `up` would
        // accept it; on any other host it is refused with the sentence `up` gives. Past them, the generated file
        // does not choose "not LLM-reviewed" for the operator: the check asks.
        let err = cmd_config(&paths, ConfigAction::Check).unwrap_err();
        if cfg!(target_os = "macos") {
            assert!(err.starts_with("The model policy is not settled (2 to fix)"), "{err}");
        } else {
            assert!(err.contains("seatbelt") && err.contains("not macOS"), "{err}");
        }
        std::fs::write(paths.config_file(), "default_model = [").unwrap();
        assert!(cmd_config(&paths, ConfigAction::Check).unwrap_err().contains("config.toml"));
    }

    #[test]
    fn config_check_reads_the_key_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join("home"));
        std::fs::create_dir_all(&paths.home).unwrap();
        std::fs::write(paths.config_file(), "[models.m]\napi_key_file = \"m\"\n").unwrap();
        let err = cmd_config(&paths, ConfigAction::Check).unwrap_err();
        assert!(err.starts_with("models.m: ") && err.contains(&paths.model_keys_dir().join("m").display().to_string()));
    }

    #[test]
    fn config_check_fails_on_a_profile_nobody_reviews_and_says_what_to_add() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join("home"));
        std::fs::create_dir_all(&paths.home).unwrap();
        // The start-up checks run before the model policy, and seatbelt (the default) is macOS's: with no OS
        // sandbox they pass on every host, so the check reaches the policy on Linux too.
        let text = "[sandbox]\nmode = \"none\"\n\n[models.dsv41]\nbase_url = \"http://10.0.0.5:8000/v1\"\nfamily = [\"deepseek\"]\nalignment = \"stock\"\nrecipient = \"lan\"\n";
        std::fs::write(paths.config_file(), text).unwrap();
        let err = cmd_config(&paths, ConfigAction::Check).unwrap_err();
        assert!(err.contains("models.dsv41 has no eligible reviewer in the core pack"), "{err}");
        assert!(err.contains("tripwires_only_profiles = [\"dsv41\"]"), "{err}");
        std::fs::write(paths.config_file(), format!("{text}[monitor]\ntripwires_only_profiles = [\"dsv41\"]\n"))
            .unwrap();
        assert_eq!(cmd_config(&paths, ConfigAction::Check), Ok(0));
        assert_eq!(cmd_models_lineage(&paths, None), Ok(0));
        assert_eq!(cmd_models_lineage(&paths, Some("dsv41")), Ok(0));
        let err = cmd_models_lineage(&paths, Some("nope")).unwrap_err();
        assert!(err.contains("\"nope\"") && err.contains("dsv41"), "{err}");
    }

    #[test]
    fn service_install_key_check() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        let profile = |env: Option<&str>, file: Option<&str>| loom_core::config::ModelProfile {
            api_key_env: env.map(str::to_string),
            api_key_file: file.map(str::to_string),
            ..Default::default()
        };
        let mut c = Config::default();
        c.models.insert("m".into(), profile(Some("MY_KEY"), None));
        let err = service_key_check(&c, &keys).unwrap_err();
        assert!(err.contains("models.m") && err.contains("MY_KEY") && err.contains("api_key_file = \"m\""), "{err}");
        assert!(err.contains("printenv MY_KEY"), "{err}");
        c.models.insert("gpt 4/o".into(), profile(Some("MY_KEY"), None));
        c.models.remove("m");
        let spaced = dir.path().join("my keys");
        let err = service_key_check(&c, &spaced).unwrap_err();
        assert!(err.contains(&format!("printenv MY_KEY > '{}'", spaced.join("gpt-4-o").display())), "{err}");
        assert!(err.contains("[models.\"gpt 4/o\"]") && err.contains("api_key_file = \"gpt-4-o\""), "{err}");

        let mut c = Config::default();
        c.models.insert("m".into(), profile(None, Some("m")));
        let err = service_key_check(&c, &keys).unwrap_err();
        assert!(err.starts_with("models.m: ") && err.contains(&keys.join("m").display().to_string()), "{err}");

        let file = keys.join("m");
        std::fs::write(&file, "sk-1\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        service_key_check(&c, &keys).unwrap();
        c.models.insert("n".into(), profile(None, None));
        service_key_check(&c, &keys).unwrap();
        service_key_check(&Config::default(), &keys).unwrap();
    }

    #[test]
    fn service_install_files_tighten_the_home_and_create_the_log_before_launchd_opens_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::at(dir.path().join("home"));
        std::fs::create_dir_all(&paths.home).unwrap();
        std::fs::set_permissions(&paths.home, std::fs::Permissions::from_mode(0o755)).unwrap();
        let plist = dir.path().join("LaunchAgents").join("agent.plist");
        write_service_files(&paths, &plist, Path::new("/usr/local/bin/loom")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&paths.home), 0o700);
        assert_eq!(mode(&paths.logs_dir()), 0o700);
        let log = paths.logs_dir().join("loomd.log");
        assert_eq!(mode(&log), 0o600);
        assert!(std::fs::read_to_string(&plist).unwrap().contains(&log.display().to_string()));
    }

    #[test]
    fn new_session_from_options() {
        let cwd = Path::new("/here");
        let n = new_session(&StartOpts::default(), Some("go".into()), cwd, Vec::new());
        assert_eq!(n.workspace, PathBuf::from("/here"));
        assert!(n.prior.is_empty());
        assert_eq!(n.message.as_deref(), Some("go"));
        assert_eq!(n.unattended, None);
        assert_eq!(n.budget, Budget { max_steps: None, max_minutes: None });
        let opts = StartOpts {
            workspace: Some("/w".into()),
            pack: Some("p".into()),
            role: Some("r".into()),
            model: Some("m".into()),
            title: Some("t".into()),
            attended: true,
            max_steps: 7,
            max_minutes: 3,
            prior: Vec::new(),
            create_workspace: true,
            target: Some("acme".into()),
            no_intercept: true,
            agent_models: vec![("worker".into(), "fast".into()), (ANY_ROLE.into(), "big".into())],
        };
        let n = new_session(&opts, None, cwd, vec![MissionId::from("m-1"), MissionId::from("m-2")]);
        assert_eq!(n.intercept, Some(false));
        assert_eq!(n.prior, [MissionId::from("m-1"), MissionId::from("m-2")]);
        assert_eq!(
            n.role_models,
            std::collections::BTreeMap::from([
                ("worker".to_string(), "fast".to_string()),
                ("*".to_string(), "big".to_string())
            ])
        );
        assert_eq!(n.workspace, PathBuf::from("/w"));
        assert!(n.create_workspace && !new_session(&StartOpts::default(), None, cwd, Vec::new()).create_workspace);
        let tilde = StartOpts { workspace: Some("~/proj".into()), ..StartOpts::default() };
        assert_eq!(new_session(&tilde, None, cwd, Vec::new()).workspace, PathBuf::from("~/proj"));
        assert_eq!(
            (n.pack.as_deref(), n.role.as_deref(), n.model.as_deref(), n.title.as_deref()),
            (Some("p"), Some("r"), Some("m"), Some("t"))
        );
        assert_eq!(n.unattended, Some(false));
        assert_eq!(n.budget, Budget { max_steps: Some(7), max_minutes: Some(3) });
        assert!(n.message.is_none());
    }

    #[tokio::test]
    async fn prior_words_are_mission_ids_as_they_are_or_sessions_resolved_to_their_mission() {
        let asked = std::sync::Mutex::new(Vec::<String>::new());
        let resolve = |word: String| {
            asked.lock().unwrap().push(word.clone());
            async move {
                match word.as_str() {
                    "last" => Ok(MissionId::from("m-of-last")),
                    "s-1" => Ok(MissionId::from("m-of-s1")),
                    w => Err(format!("No session matches `{w}`.")),
                }
            }
        };
        let got = prior_missions(&words(&["m-9", "", "last", "  ", "s-1", " m-3 "]), resolve).await.unwrap();
        let want: Vec<MissionId> = ["m-9", "m-of-last", "m-of-s1", "m-3"].into_iter().map(MissionId::from).collect();
        assert_eq!(got, want);
        // Only the words that are not mission ids were looked up.
        assert_eq!(*asked.lock().unwrap(), ["last", "s-1"]);
        let resolve = |word: String| async move { Err::<MissionId, _>(format!("No session matches `{word}`.")) };
        assert_eq!(prior_missions(&words(&["m-1", "zzz"]), resolve).await.unwrap_err(), "No session matches `zzz`.");
        assert!(prior_missions(&[], resolve).await.unwrap().is_empty());
    }

    #[test]
    fn live_region_is_drawn_and_erased_by_exact_escape_sequences() {
        let id = |s: &str| s.to_string();
        let mut live = Live::default();
        assert_eq!(live.erase(), "");
        live.push(&Delta::Reasoning { text: "think".into() });
        live.push(&Delta::Text { text: "one\ntwo".into() });
        assert_eq!(live.draw(80, false, &id), "think\none\ntwo");
        // Three rows drawn: the cursor is two rows below the first.
        assert_eq!(live.erase(), "\x1b[2A\r\x1b[J");
        assert_eq!(live.erase(), "");
        let drawn = live.draw(80, true, &id);
        assert_eq!(drawn, "\x1b[2mthink\x1b[0m\none\ntwo");
        let again = live.draw(80, true, &id);
        assert!(again.starts_with("\x1b[2A\r\x1b[J"));
        live.push(&Delta::AttemptStart { attempt: 2 });
        assert_eq!(live.draw(80, true, &id), "\x1b[2A\r\x1b[J");
        assert_eq!(live.erase(), "");
    }

    #[test]
    fn live_region_wraps_long_lines_and_keeps_the_last_rows() {
        let id = |s: &str| s.to_string();
        let mut live = Live::default();
        live.push(&Delta::Text { text: "x".repeat(25) });
        // Width 11: rows of 10 characters.
        assert_eq!(live.draw(11, false, &id), format!("{}\n{}\n{}", "x".repeat(10), "x".repeat(10), "x".repeat(5)));
        let mut live = Live::default();
        live.push(&Delta::Text { text: (1..=10).map(|n| format!("l{n}\n")).collect() });
        assert_eq!(live.draw(80, false, &id), "l5\nl6\nl7\nl8\nl9\nl10");
        // Stored text is cleaned before it is drawn.
        let mut live = Live::default();
        live.push(&Delta::Text { text: "a\x1bb".into() });
        assert_eq!(live.draw(80, false, &|s: &str| s.replace('\x1b', "·")), "a·b");
    }

    // ---- against the stub daemon ----

    fn rec(seq: Seq, event: Event) -> Record {
        Record { seq, ts_ms: 0, author: Author::Model, prev: "0".repeat(64), event }
    }

    fn turn_end(seq: Seq, reason: TurnEndReason) -> Record {
        rec(seq, Event::TurnEnd { reason })
    }

    fn note(seq: Seq) -> Record {
        rec(seq, Event::TurnStart { trigger: Trigger::User })
    }

    fn event(r: &Record) -> String {
        sse(&BusEvent::Record { session: SessionId::from("s-1"), record: Box::new(r.clone()) })
    }

    fn data(records: &[Record]) -> Piece {
        Piece::Data(records.iter().map(event).collect())
    }

    fn rendered(r: &Record) -> String {
        format!("#{}\n", r.seq)
    }

    fn cfg<'a>(render_record: &'a dyn Fn(&Record) -> String) -> FollowCfg<'a> {
        FollowCfg {
            render: render_record,
            clean: &|s: &str| s.to_string(),
            deltas: false,
            color: false,
            width: 80,
            retry_delay: Duration::from_millis(5),
            stop_floor: None,
        }
    }

    async fn run_follow(c: &Client, after: Option<Seq>, floor: Option<Seq>) -> (Result<FollowEnd, String>, String) {
        let render_record = rendered;
        let mut cfg = cfg(&render_record);
        cfg.stop_floor = floor;
        let mut out = Vec::new();
        let r = follow(c, &SessionId::from("s-1"), after, &cfg, &mut out).await;
        (r, String::from_utf8(out).unwrap())
    }

    fn targets(shared: &Shared) -> Vec<String> {
        shared.lock().unwrap().seen.iter().map(|s| s.target.clone()).collect()
    }

    #[tokio::test]
    async fn follow_prints_each_record_once_and_ends_with_the_turn() {
        let script = Script::default().stream(vec![
            data(&[note(0), note(1)]),
            Piece::Pause(10),
            // A repeat of what was printed (a replay/live overlap) is not printed again.
            data(&[note(1), turn_end(2, TurnEndReason::Waiting), note(3)]),
            Piece::Pause(10),
            data(&[turn_end(4, TurnEndReason::Finished), note(5)]),
        ]);
        let (c, shared) = start(script).await;
        let (end, out) = run_follow(&c, None, None).await;
        assert_eq!(end.unwrap(), FollowEnd { code: 0, ended: false });
        assert_eq!(out, "#0\n#1\n#2\n#3\n#4\n");
        assert_eq!(targets(&shared), ["/api/sessions/s-1/stream"]);
    }

    #[tokio::test]
    async fn follow_exit_codes_follow_the_turn_end() {
        for (reason, code) in [
            (TurnEndReason::Asked, 2),
            (TurnEndReason::Parked, 2),
            (TurnEndReason::Stopped, 1),
            (TurnEndReason::Error, 1),
            (TurnEndReason::Yielded, 0),
        ] {
            let (c, _) = start(Script::default().stream(vec![data(&[note(0), turn_end(1, reason)])])).await;
            let (end, _) = run_follow(&c, None, None).await;
            assert_eq!(end.unwrap().code, code, "{reason:?}");
        }
        let end_rec = rec(1, Event::SessionEnd { outcome: SessionOutcome::Failed, detail: "x".into() });
        let (c, _) = start(Script::default().stream(vec![data(&[end_rec])])).await;
        assert_eq!(run_follow(&c, None, None).await.0.unwrap(), FollowEnd { code: 1, ended: true });
    }

    #[tokio::test]
    async fn follow_resumes_after_the_last_record_when_the_stream_drops() {
        let script = Script::default()
            .stream(vec![data(&[note(0), note(1)]), Piece::Pause(10), Piece::Abort])
            // The daemon closed this one cleanly without a turn end.
            .stream(vec![data(&[note(2)])])
            .stream(vec![data(&[note(3), turn_end(4, TurnEndReason::Finished)])]);
        let (c, shared) = start(script).await;
        let (end, out) = run_follow(&c, None, None).await;
        assert_eq!(end.unwrap().code, 0);
        assert_eq!(out, "#0\n#1\n#2\n#3\n#4\n");
        assert_eq!(
            targets(&shared),
            ["/api/sessions/s-1/stream", "/api/sessions/s-1/stream?after=1", "/api/sessions/s-1/stream?after=2"]
        );
    }

    #[tokio::test]
    async fn follow_survives_the_daemon_being_away_for_a_moment() {
        // The daemon drops the stream, refuses the next request (it is restarting), then serves.
        let script = Script::default()
            .stream(vec![data(&[note(0)]), Piece::Pause(10), Piece::Abort])
            .refuse_stream()
            .stream(vec![data(&[turn_end(1, TurnEndReason::Finished)])]);
        let (c, shared) = start(script).await;
        let (end, out) = run_follow(&c, None, None).await;
        assert_eq!(end.unwrap().code, 0);
        assert_eq!(out, "#0\n#1\n");
        assert_eq!(
            targets(&shared),
            ["/api/sessions/s-1/stream", "/api/sessions/s-1/stream?after=0", "/api/sessions/s-1/stream?after=0"]
        );
    }

    #[tokio::test]
    async fn follow_gives_up_after_five_breaks_with_a_sentence() {
        let mut script = Script::default();
        for _ in 0..8 {
            script = script.stream(vec![Piece::Data(": hi\n\n".into()), Piece::Pause(5), Piece::Abort]);
        }
        let (c, shared) = start(script).await;
        let (end, out) = run_follow(&c, Some(9), None).await;
        assert_eq!(out, "");
        assert_eq!(
            end.unwrap_err(),
            "The connection to the daemon kept breaking. Carry on with `loom tail s-1 --since 9`."
        );
        assert_eq!(targets(&shared).len(), 6);
    }

    #[tokio::test]
    async fn follow_when_the_daemon_is_gone_says_to_start_it() {
        let c = dead_client().await;
        let (end, _) = run_follow(&c, None, None).await;
        assert!(end.unwrap_err().contains("`loom up`"));
    }

    #[tokio::test]
    async fn follow_reopens_after_a_lagged_notice_and_ignores_other_sessions() {
        let other = sse(&BusEvent::Record { session: SessionId::from("s-2"), record: Box::new(note(7)) });
        let lagged = sse(&BusEvent::Lagged { missed: 40 });
        let script = Script::default()
            .stream(vec![data(&[note(0)]), Piece::Data(other), Piece::Data(lagged)])
            .stream(vec![data(&[note(0), note(1), turn_end(2, TurnEndReason::Finished)])]);
        let (c, shared) = start(script).await;
        let (end, out) = run_follow(&c, None, None).await;
        assert_eq!(end.unwrap().code, 0);
        assert_eq!(out, "#0\n#1\n#2\n");
        assert_eq!(targets(&shared)[1], "/api/sessions/s-1/stream?after=0");
    }

    #[tokio::test]
    async fn follow_ignores_turn_ends_at_or_below_the_floor() {
        let script = Script::default().stream(vec![data(&[
            note(0),
            turn_end(1, TurnEndReason::Finished),
            note(2),
            turn_end(3, TurnEndReason::Asked),
        ])]);
        let (c, _) = start(script).await;
        let (end, out) = run_follow(&c, None, Some(2)).await;
        assert_eq!(end.unwrap().code, 2);
        assert_eq!(out, "#0\n#1\n#2\n#3\n");
    }

    #[tokio::test]
    async fn follow_shows_deltas_on_a_terminal_and_erases_them_when_the_response_arrives() {
        let delta = |text: &str| {
            sse(&BusEvent::Delta {
                session: SessionId::from("s-1"),
                req_id: "r-1".into(),
                delta: Delta::Text { text: text.into() },
            })
        };
        let response = rec(
            1,
            Event::ModelResponse(ModelResponse {
                req_id: "r-1".into(),
                text: "hello".into(),
                reasoning: String::new(),
                tool_calls: vec![],
                finish: FinishReason::Stop,
                usage: Default::default(),
                timing: Default::default(),
                attempts: 1,
            }),
        );
        let script = Script::default().stream(vec![
            Piece::Data(delta("hel")),
            Piece::Pause(10),
            Piece::Data(delta("lo")),
            Piece::Pause(10),
            data(&[response, turn_end(2, TurnEndReason::Yielded)]),
        ]);
        let (c, _) = start(script).await;
        let render_record = rendered;
        let mut cfg = cfg(&render_record);
        cfg.deltas = true;
        let mut out = Vec::new();
        let end = follow(&c, &SessionId::from("s-1"), None, &cfg, &mut out).await.unwrap();
        assert_eq!(end.code, 0);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(out, "hel\r\x1b[Jhello\r\x1b[J#1\n#2\n");
    }

    #[tokio::test]
    async fn last_seq_finds_the_end_of_logs_of_every_size() {
        for n in [0u64, 1, 2, 3, 4, 5, 8, 9, 100, 1000] {
            let mut script = Script::default();
            script.log.replace((0..n).map(note).collect());
            let (c, shared) = start(script).await;
            let found = last_seq(&c, &SessionId::from("s-1")).await.unwrap();
            assert_eq!(found, n.checked_sub(1), "log of {n}");
            // Never more than about two probes per bit.
            assert!(shared.lock().unwrap().seen.len() <= 2 * 11 + 2, "log of {n}");
        }
    }

    #[tokio::test]
    async fn print_records_pages_through_the_log() {
        let mut script = Script::default();
        script.log.replace((0..1200).map(note).collect());
        let (c, shared) = start(script).await;
        let render_record = rendered;
        let mut out = Vec::new();
        print_records(&c, &SessionId::from("s-1"), Some(99), &render_record, &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1100);
        assert!(text.starts_with("#100\n") && text.ends_with("#1199\n"));
        assert_eq!(targets(&shared).len(), 3);
    }

    fn tail_args(since: Option<u64>, no_follow: bool) -> TailArgs {
        TailArgs {
            session: "s-1".into(),
            since,
            no_follow,
            show: ShowOpts { reasoning: false, full: false, verbose: false },
        }
    }

    fn detail_with(phase: Phase, last_end: Option<TurnEndReason>, outcome: Option<SessionOutcome>) -> String {
        let mut i = info("s-1", 1, false);
        i.status.phase = phase;
        i.status.last_end = last_end;
        i.status.outcome = outcome;
        let mut v = serde_json::to_value(&i).unwrap();
        v["children"] = serde_json::json!([]);
        v.to_string()
    }

    async fn run_tail(script: Script, args: TailArgs) -> (Result<i32, String>, String, Shared) {
        let (c, shared) = start(script).await;
        let render_record = rendered;
        let cfg = cfg(&render_record);
        let mut out = Vec::new();
        let r = tail_with(&c, &args, &cfg, &mut out).await;
        (r, String::from_utf8(out).unwrap(), shared)
    }

    fn base_script(detail: String) -> Script {
        let mut script = Script::default()
            .route("GET", "/api/sessions", 200, json(&vec![info("s-1", 1, false)]))
            .route("GET", "/api/sessions/s-1", 200, detail);
        script.log = Some((0..4).map(note).collect());
        script
    }

    #[tokio::test]
    async fn tail_of_a_running_session_follows_and_only_the_new_turn_end_counts() {
        let mut script = base_script(detail_with(Phase::Running, None, None));
        // The log holds a finished turn (seq 3 is the newest record); the live turn ends at 5.
        script.log = Some(vec![note(0), turn_end(1, TurnEndReason::Finished), note(2), note(3)]);
        let script = script.stream(vec![data(&[
            note(0),
            turn_end(1, TurnEndReason::Finished),
            note(2),
            note(3),
            note(4),
            turn_end(5, TurnEndReason::Blocked),
        ])]);
        let (r, out, shared) = run_tail(script, tail_args(None, false)).await;
        assert_eq!(r.unwrap(), 2);
        assert_eq!(out, "#0\n#1\n#2\n#3\n#4\n#5\n");
        assert!(targets(&shared).contains(&"/api/sessions/s-1/stream".to_string()));
    }

    #[tokio::test]
    async fn tail_no_follow_prints_what_exists_and_stops() {
        let script = base_script(detail_with(Phase::Running, None, None));
        let (r, out, shared) = run_tail(script, tail_args(Some(1), true)).await;
        assert_eq!(r.unwrap(), 0);
        assert_eq!(out, "#2\n#3\n");
        assert!(!targets(&shared).iter().any(|t| t.contains("/stream")));
    }

    #[tokio::test]
    async fn tail_of_a_session_at_rest_prints_and_exits_with_its_last_turn() {
        let script = base_script(detail_with(Phase::Idle, Some(TurnEndReason::Asked), None));
        let (r, out, _) = run_tail(script, tail_args(None, false)).await;
        assert_eq!(r.unwrap(), 2);
        assert_eq!(out, "#0\n#1\n#2\n#3\n");
        let script =
            base_script(detail_with(Phase::Ended, Some(TurnEndReason::Finished), Some(SessionOutcome::Failed)));
        let (r, _, _) = run_tail(script, tail_args(None, false)).await;
        assert_eq!(r.unwrap(), 1);
    }

    #[tokio::test]
    async fn tail_of_an_unknown_session_says_so() {
        let script = Script::default().route("GET", "/api/sessions", 200, "[]");
        let (r, _, _) = run_tail(script, tail_args(None, false)).await;
        assert_eq!(r.unwrap_err(), "No session matches `s-1`.");
    }

    #[tokio::test]
    async fn send_follows_only_what_comes_after_the_message() {
        let mut script = Script::default()
            .route("POST", "/api/sessions/s-1/messages", 202, "{}")
            .stream(vec![data(&[note(4), note(5), turn_end(6, TurnEndReason::Yielded)])]);
        script.log = Some((0..4).map(note).collect());
        let (c, shared) = start(script).await;
        let render_record = rendered;
        let cfg = cfg(&render_record);
        let mut out = Vec::new();
        let end = send_with(&c, &SessionId::from("s-1"), "go on", false, &cfg, &mut out).await.unwrap();
        assert_eq!(end.code, 0);
        assert_eq!(String::from_utf8(out).unwrap(), "#4\n#5\n#6\n");
        let seen = shared.lock().unwrap().seen.clone();
        let post = seen.iter().position(|s| s.method == "POST").unwrap();
        // The newest seq was found before the message was sent, and the stream starts after it.
        assert!(seen[..post].iter().all(|s| s.method == "GET"));
        assert_eq!(seen[post].body, r#"{"text":"go on"}"#);
        assert_eq!(seen.last().unwrap().target, "/api/sessions/s-1/stream?after=3");
    }

    #[tokio::test]
    async fn send_detached_does_not_follow() {
        let mut script = Script::default().route("POST", "/api/sessions/s-1/messages", 202, "{}");
        script.log = Some(vec![note(0)]);
        let (c, shared) = start(script).await;
        let render_record = rendered;
        let cfg = cfg(&render_record);
        let mut out = Vec::new();
        let end = send_with(&c, &SessionId::from("s-1"), "x", true, &cfg, &mut out).await.unwrap();
        assert_eq!(end.code, 0);
        assert_eq!(String::from_utf8(out).unwrap(), "sent to s-1\n");
        assert!(!targets(&shared).iter().any(|t| t.contains("/stream")));
    }

    #[tokio::test]
    async fn send_to_a_session_that_refuses_reports_the_sentence() {
        let mut script = Script::default().route(
            "POST",
            "/api/sessions/s-1/messages",
            409,
            r#"{"error":"Session s-1 is archived. Run `loom archive s-1 --undo` first."}"#,
        );
        script.log = Some(vec![]);
        let (c, _) = start(script).await;
        let render_record = rendered;
        let cfg = cfg(&render_record);
        let mut out = Vec::new();
        let e = send_with(&c, &SessionId::from("s-1"), "x", false, &cfg, &mut out).await.unwrap_err();
        assert_eq!(e, "Session s-1 is archived. Run `loom archive s-1 --undo` first.");
    }

    #[tokio::test]
    async fn out_pages_five_thousand_lines_at_a_time_and_cleans_the_text() {
        let handle = "out:ab";
        let script = Script::default().blob_total(12_000);
        let (c, shared) = start(script).await;
        let mut out = Vec::new();
        print_blob(&c, handle, None, &|s: &str| s.replace('\x1b', "·"), &mut out).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 12_000);
        assert!(text.starts_with("line 1·\nline 2·\n"));
        assert!(text.ends_with("line 12000·\n"));
        assert_eq!(
            targets(&shared),
            [
                "/api/blobs/out:ab/lines?start=1&end=5000",
                "/api/blobs/out:ab/lines?start=5001&end=10000",
                "/api/blobs/out:ab/lines?start=10001&end=15000"
            ]
        );
        // A range stops where it ends, and a range past the end stops where the output does.
        let (c, shared) = start(Script::default().blob_total(12_000)).await;
        let mut out = Vec::new();
        print_blob(&c, handle, Some((10, Some(12))), &|s: &str| s.to_string(), &mut out).await.unwrap();
        assert_eq!(String::from_utf8(out).unwrap().lines().count(), 3);
        assert_eq!(targets(&shared), ["/api/blobs/out:ab/lines?start=10&end=12"]);
        let (c, _) = start(Script::default().blob_total(7)).await;
        let mut out = Vec::new();
        print_blob(&c, handle, Some((5, None)), &|s: &str| s.to_string(), &mut out).await.unwrap();
        assert_eq!(String::from_utf8(out).unwrap().lines().count(), 3);
    }

    #[tokio::test]
    async fn tail_does_not_hang_if_turn_finishes_before_stop_floor() {
        use axum::extract::Query;
        use axum::http::header;
        use axum::response::Response;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicUsize::new(0));
        let log = vec![note(0), note(1), turn_end(2, TurnEndReason::Asked)];
        let sessions_body = json(&vec![info("s-1", 1, false)]);
        let running_body = detail_with(Phase::Running, None, None);
        let idle_body = detail_with(Phase::Idle, Some(TurnEndReason::Asked), None);

        let app = axum::Router::new()
            .route(
                "/api/sessions",
                axum::routing::get({
                    let sessions_body = sessions_body.clone();
                    move || async move { sessions_body }
                }),
            )
            .route(
                "/api/sessions/s-1",
                axum::routing::get({
                    let calls = calls.clone();
                    move || async move {
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            running_body.clone()
                        } else {
                            idle_body.clone()
                        }
                    }
                }),
            )
            .route(
                "/api/sessions/s-1/records",
                axum::routing::get({
                    let log = log.clone();
                    move |Query(q): Query<HashMap<String, String>>| async move {
                        let after = q.get("after").and_then(|v| v.parse::<Seq>().ok());
                        let limit = q.get("limit").and_then(|v| v.parse::<usize>().ok()).unwrap_or(500);
                        let records: Vec<Record> =
                            log.iter().filter(|r| after.is_none_or(|a| r.seq > a)).take(limit).cloned().collect();
                        let next_after = (records.len() == limit).then(|| records.last().map(|r| r.seq)).flatten();
                        json(&crate::wire::RecordsPage { records, next_after, prev_before: None })
                    }
                }),
            )
            .route(
                "/api/sessions/s-1/stream",
                axum::routing::get(|| async move {
                    let pending = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
                    Response::builder()
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(axum::body::Body::from_stream(pending))
                        .unwrap()
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let c = Client::new(&format!("http://{addr}"), "tok-123");
        let render_record = rendered;
        let cfg = cfg(&render_record);
        let mut out = Vec::new();
        let code = tokio::time::timeout(Duration::from_secs(2), tail_with(&c, &tail_args(None, false), &cfg, &mut out))
            .await
            .expect("tail_with must not hang")
            .unwrap();
        srv.abort();
        assert_eq!(code, 2);
        assert_eq!(String::from_utf8(out).unwrap(), "#0\n#1\n#2\n");
    }

    #[test]
    fn score_text_appends_harness_tax_summary_after_score_table() {
        use loom_agent::runtime::{ScoreView, SessionScore};
        use loom_core::scorecard::Scorecard;
        let card = Scorecard {
            steps: 5,
            calls: 4,
            malformed_calls: 1,
            text_only_nudges: 1,
            repaired_calls: 2,
            ceremony_refusals: 1,
            ..Scorecard::default()
        };
        let view = ScoreView {
            mission: MissionId::from("m-1"),
            sessions: vec![SessionScore {
                session: SessionId::from("s-1"),
                role: "lead".into(),
                parent: None,
                card: card.clone(),
            }],
            total: card.clone(),
        };
        let style = Style { color: false, width: 100 };
        let rendered = format_score_text(&view, &style);
        let table = render::score_table(&view, &style);
        assert_eq!(rendered, format!("{table}Harness tax: {}\n", card.harness_tax_summary()));
        assert!(rendered.ends_with(&format!("Harness tax: {}\n", card.harness_tax_summary())));
    }
}
