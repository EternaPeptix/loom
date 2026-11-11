//! The `loom` command.
//!
//! CONTRACT (bodies are placeholders for the implementer; the command-line shape below is fixed).
//! Every command except `daemon`, `up`, `config` and `service` is a client of the daemon
//! (`Client::from_home(&Paths::from_env())`). Errors are printed to stderr as `loom: {sentence}`
//! and the exit code is 1 unless stated. Output goes to stdout; colour only when stdout is a
//! terminal and `NO_COLOR` is not set; width from `COLUMNS`, else `ioctl(TIOCGWINSZ)`, else 100.
//!
//! ## Commands
//! - `daemon`: `serve::run`. `up`: `serve::spawn_background`, then print `loom is running on
//!   {bind}` (or `already running`). `down`: `client.shutdown()`, wait until it stops answering
//!   (10 s), print `stopped`.
//! - `status`: `render::status`. Exit 1 when the daemon is not running (with the usual sentence).
//! - `open`: print and open `http://{bind}/?token={token}` (`/usr/bin/open` on macOS, `xdg-open`
//!   elsewhere; `--print` only prints).
//! - `run [options] <message…>`: start a session and follow it. The message is the arguments
//!   joined by spaces; `-` or no message reads standard input to its end. Options → `NewSession`
//!   (`--workspace` defaults to the current directory; `--attended` sets `unattended: false`;
//!   `--max-steps`/`--max-minutes` → budget). Prints `session {id}` to stderr first. With
//!   `--detach`, stops there. Otherwise *follows* (below).
//! - `chat [options]`: a `chat`-role session on the terminal: prompt `› `, read a line (an empty
//!   line is ignored, end of input or `/quit` leaves), send it, follow until the turn ends, repeat.
//!   `--session <id>` continues an existing session instead of starting one.
//! - `ls [-a]`: `render::sessions_table` (`-a`: archived too).
//! - `tail <session> [--since <seq>] [--no-follow] [--reasoning] [--full] [--verbose]`: print the
//!   session's records and keep following. `--no-follow` prints what exists and stops.
//! - `send <session> <text…>` (`-` = standard input), then follows unless `--detach`.
//! - `stop <session>`, `resume <session>`, `reweave <session>`, `archive <session> [--undo]`: the
//!   call, then one line saying what was asked (`stop requested for {id}`).
//! - `inbox`: `render::inbox_list`. `answer <item> <text…>`: `client.answer`; `answered {item}`.
//! - `ledger <session|mission>`: the ledger's `markdown`.
//! - `window <session>`: `render::window_table`. `net <session> [-n <limit>]`: `render::net_table`.
//! - `out <handle> [--lines <a>:<b>]`: the stored output's lines (all of it, paged 5 000 lines at a
//!   time, without `--lines`), passed through `render::clean`.
//! - `config path` prints the config file's path; `config check` loads and checks it (`ok`, or the
//!   error and exit 1); `config init` writes [`DEFAULT_CONFIG`] if no file exists (refuses to
//!   overwrite: `{path} already exists.`).
//! - `service install|uninstall|status` (macOS; elsewhere `This command is for macOS (launchd).`):
//!   `install` writes `serve::launch_agent_plist` to `~/Library/LaunchAgents/{SERVICE_LABEL}.plist`
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
//! `follow_exit_code` for every turn end; `DEFAULT_CONFIG` parses with `Config::parse` and passes
//! `check()`; `open_url`.

use clap::{Args, Parser, Subcommand};
use loom_core::event::TurnEndReason;
use std::path::PathBuf;

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
# context_window = 1000000   # only needed when the server does not report it
max_concurrent = 4           # requests in flight at once (lead, agents and votes together)

[context]
# The request is re-woven (old tool output folded out of view, never lost) when it passes
# target_tokens, down to floor_tokens. Both must be below the model's window.
target_tokens = 400000
floor_tokens = 180000

[network]
# open | allowlist | deny_all. Private and local addresses are refused unless listed.
mode = "open"
allow_private = []

[agents]
max_children = 6
verify_finish = true
"#;

#[derive(Parser, Debug)]
#[command(name = "loom", version, about = "An agent harness for long, unattended work on a local model")]
pub struct Cli {
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
    Reweave(SessionArg),
    /// Hide a finished session (or bring it back with --undo)
    Archive(ArchiveArgs),
    /// List what is waiting for you
    Inbox,
    /// Answer an inbox item
    Answer(AnswerArgs),
    /// Print a mission's ledger
    Ledger(SessionArg),
    /// Show what is in a session's context
    Window(SessionArg),
    /// Show a session's network requests and how each was decided
    Net(NetArgs),
    /// Print a stored tool output
    Out(OutArgs),
    /// The configuration file
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Run the daemon as a login service (macOS)
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
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
    #[arg(short, long)]
    pub title: Option<String>,
    /// Do not resume by itself after a restart
    #[arg(long)]
    pub attended: bool,
    #[arg(long, default_value_t = 0)]
    pub max_steps: u32,
    #[arg(long, default_value_t = 0)]
    pub max_minutes: u32,
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
    pub session: String,
    #[arg(long)]
    pub undo: bool,
}

#[derive(Args, Debug)]
pub struct AnswerArgs {
    pub item: String,
    pub text: Vec<String>,
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

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigAction {
    Path,
    Check,
    Init,
}

#[derive(Subcommand, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Install,
    Uninstall,
    Status,
}

/// Run one command; the result is the process's exit code.
pub async fn run(cli: Cli) -> i32 {
    let _ = cli;
    todo!("implement per module contract")
}

/// The words of a message argument joined by spaces; `None` when standard input should be read
/// (no words, or the single word `-`).
pub fn message_from_args(words: &[String]) -> Option<String> {
    let _ = words;
    todo!("implement per module contract")
}

/// `10:20` → `(10, Some(20))`, `10:` → `(10, None)`, `:20` → `(1, Some(20))`. Lines are 1-based;
/// `0`, a reversed range and anything else is an error sentence.
pub fn parse_lines(text: &str) -> Result<(u64, Option<u64>), String> {
    let _ = text;
    todo!("implement per module contract")
}

/// Exit code of a followed session whose turn ended with `reason`; `None` = keep following.
pub fn follow_exit_code(reason: TurnEndReason) -> Option<i32> {
    let _ = reason;
    todo!("implement per module contract")
}

/// `http://{bind}/?token={token}`.
pub fn open_url(bind: &str, token: &str) -> String {
    let _ = (bind, token);
    todo!("implement per module contract")
}
