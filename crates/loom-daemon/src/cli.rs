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
//! - `rule <session> <text…>` (`-` = standard input): `client.add_rule`; `rule set for {id}`.
//!   `rule <session> --withdraw <rule-id> [--reason <text>]`: `client.withdraw_rule`.
//!   `approve <session> <text…> [--scope <text>]`: `client.approve`. A child's id reaches its lead.
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

use crate::client::{self, Client};
use crate::render::{self, RecordOpts, Style};
use clap::{Args, Parser, Subcommand};
use loom_agent::runtime::{BusEvent, Delta, NewSession};
use loom_agent::session::Phase;
use loom_core::config::{Config, Paths};
use loom_core::event::{Budget, Event, Record, Seq, SessionOutcome, TurnEndReason};
use loom_core::SessionId;
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
    /// Set a standing rule for a mission (or withdraw one with --withdraw)
    Rule(RuleArgs),
    /// Record an approval for a mission
    Approve(ApproveArgs),
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
pub struct RuleArgs {
    /// A session id, the beginning of one, or `last`
    pub session: String,
    /// Withdraw the rule with this id (such as k1) instead of setting one
    #[arg(long, value_name = "RULE_ID", conflicts_with = "text")]
    pub withdraw: Option<String>,
    /// Why the rule is withdrawn
    #[arg(long, requires = "withdraw")]
    pub reason: Option<String>,
    /// The rule ("-": read standard input)
    pub text: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ApproveArgs {
    /// A session id, the beginning of one, or `last`
    pub session: String,
    /// What the approval covers
    #[arg(long)]
    pub scope: Option<String>,
    /// What is approved ("-": read standard input)
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

/// `http://{bind}/?token={token}`.
pub fn open_url(bind: &str, token: &str) -> String {
    format!("http://{bind}/?token={token}")
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

/// The message of `run` and `send`: the words, or standard input for `-`. Reading from a terminal
/// happens only when asked for with `-`; with no words at all it is an error, never a silent wait.
fn read_message(words: &[String]) -> Result<String, String> {
    let text = match message_from_args(words) {
        Some(t) => t,
        None => {
            if words.is_empty() && std::io::stdin().is_terminal() {
                return Err("There is no message. Put it after the command, pipe it in, or give `-` to type it (end with Ctrl-D).".to_string());
            }
            read_stdin()?
        }
    };
    if text.trim().is_empty() {
        return Err("The message is empty.".to_string());
    }
    Ok(text)
}

fn non_zero(n: u32) -> Option<u32> {
    (n > 0).then_some(n)
}

/// The request `loom run` and `loom chat` make; `cwd` is the default workspace.
fn new_session(opts: &StartOpts, message: Option<String>, cwd: &Path) -> NewSession {
    let workspace = opts.workspace.clone().unwrap_or_else(|| cwd.to_path_buf());
    NewSession {
        workspace: std::path::absolute(&workspace).unwrap_or(workspace),
        pack: opts.pack.clone(),
        role: opts.role.clone(),
        model: opts.model.clone(),
        title: opts.title.clone(),
        unattended: opts.attended.then_some(false),
        budget: Budget { max_steps: non_zero(opts.max_steps), max_minutes: non_zero(opts.max_minutes) },
        message,
    }
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

/// `tail`: what exists, then what arrives, until the turn that is running (or the next one) ends. A
/// session at rest — ended, or idle after a turn that ended — has nothing to wait for: its records
/// are printed and the code is that of its last turn.
async fn tail_with(c: &Client, a: &TailArgs, cfg: &FollowCfg<'_>, out: &mut dyn Write) -> Result<i32, String> {
    let id = c.resolve(&a.session).await?;
    let status = c.session(&id).await?.info.status;
    let at_rest_code = match status.phase {
        Phase::Ended => Some(status.outcome.map(outcome_code).unwrap_or(0)),
        Phase::Idle => status.last_end.and_then(follow_exit_code),
        Phase::Running => None,
    };
    if a.no_follow || at_rest_code.is_some() {
        print_records(c, &id, a.since, cfg.render, out).await?;
        return Ok(if a.no_follow { 0 } else { at_rest_code.unwrap_or(0) });
    }
    let floor = last_seq(c, &id).await?;
    let cfg = FollowCfg { stop_floor: floor, ..*cfg };
    Ok(follow(c, &id, a.since, &cfg, out).await?.code)
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
    let baseline = last_seq(c, id).await?;
    c.send(id, text).await?;
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
            let text = read_message(&a.text)?;
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            let style = style();
            let opts = record_opts(&a.show);
            let render_record = |r: &Record| render::record(r, &style, &opts);
            let cfg = terminal_cfg(&render_record, &style, None);
            Ok(send_with(&c, &id, &text, a.detach, &cfg, &mut StdoutSink).await?.code)
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
        Command::Reweave(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            c.reweave(&id).await?;
            outln(&format!("re-weave requested for {id}")).map(|()| 0)
        }
        Command::Archive(a) => {
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            c.archive(&id, !a.undo).await?;
            outln(&format!("{} {id}", if a.undo { "restored" } else { "archived" })).map(|()| 0)
        }
        Command::Rule(a) => {
            let c = client_of(&paths)?;
            if let Some(rule) = &a.withdraw {
                let id = c.resolve(&a.session).await?;
                c.withdraw_rule(&id, rule, a.reason.as_deref().unwrap_or("")).await?;
                return outln(&format!("withdrawn {rule} for {id}")).map(|()| 0);
            }
            let text = read_message(&a.text)?;
            let id = c.resolve(&a.session).await?;
            c.add_rule(&id, &text).await?;
            outln(&format!("rule set for {id}")).map(|()| 0)
        }
        Command::Approve(a) => {
            let text = read_message(&a.text)?;
            let c = client_of(&paths)?;
            let id = c.resolve(&a.session).await?;
            c.approve(&id, &text, a.scope.as_deref().unwrap_or("")).await?;
            outln(&format!("approval recorded for {id}")).map(|()| 0)
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
            block(&view.markdown).map(|()| 0)
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
            block(&render::net_table(&entries, &style())).map(|()| 0)
        }
        Command::Out(a) => {
            let range = a.lines.as_deref().map(parse_lines).transpose()?;
            let c = client_of(&paths)?;
            print_blob(&c, &a.handle, range, &render::clean, &mut StdoutSink).await.map(|()| 0)
        }
    }
}

fn terminal_cfg<'a>(
    render_record: &'a dyn Fn(&Record) -> String,
    style: &Style,
    floor: Option<Seq>,
) -> FollowCfg<'a> {
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

async fn cmd_up(paths: &Paths) -> Result<i32, String> {
    let spawned = crate::serve::spawn_background(paths).await?;
    let bind = client::bind_from_home(paths)?;
    let line = match spawned {
        crate::serve::Spawned::Started => format!("loom is running on {bind}"),
        crate::serve::Spawned::Already => format!("loom is already running on {bind}"),
    };
    outln(&line).map(|()| 0)
}

async fn cmd_down(paths: &Paths) -> Result<i32, String> {
    let c = client_of(paths)?;
    c.shutdown().await?;
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
    outln("stopped").map(|()| 0)
}

async fn cmd_open(paths: &Paths, a: &OpenArgs) -> Result<i32, String> {
    let c = client_of(paths)?;
    // Say "not running" here rather than hand the browser an address nothing answers on.
    c.status().await?;
    let bind = c.base().strip_prefix("http://").unwrap_or(c.base());
    let url = open_url(bind, c.token());
    outln(&url)?;
    if a.print {
        return Ok(0);
    }
    let program = if cfg!(target_os = "macos") { "/usr/bin/open" } else { "xdg-open" };
    let status = std::process::Command::new(program)
        .arg(&url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("Cannot start {program} ({e}). Open the address above in a browser yourself."))?;
    if status.success() {
        Ok(0)
    } else {
        Err(format!("{program} could not open the address. Open the address above in a browser yourself."))
    }
}

async fn cmd_run(paths: &Paths, a: RunArgs) -> Result<i32, String> {
    let message = read_message(&a.message)?;
    let c = client_of(paths)?;
    let cwd = std::env::current_dir().map_err(|e| format!("Cannot find the current directory ({e}). Pass --workspace."))?;
    let info = c.create(&new_session(&a.start, Some(message), &cwd)).await?;
    let id = info.meta.id;
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
        Some(word) => c.resolve(word).await?,
        None => {
            let cwd = std::env::current_dir()
                .map_err(|e| format!("Cannot find the current directory ({e}). Pass --workspace."))?;
            let mut new = new_session(&a.start, None, &cwd);
            if new.role.is_none() {
                new.role = Some("chat".to_string());
            }
            let id = c.create(&new).await?.meta.id;
            errln(&format!("session {id}"));
            id
        }
    };
    let tty = std::io::stdin().is_terminal();
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

fn cmd_config(paths: &Paths, action: ConfigAction) -> Result<i32, String> {
    let file = paths.config_file();
    match action {
        ConfigAction::Path => outln(&file.display().to_string()).map(|()| 0),
        ConfigAction::Check => {
            Config::load(&file).map_err(|e| e.to_string())?;
            outln("ok").map(|()| 0)
        }
        ConfigAction::Init => {
            use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&paths.home)
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

fn cmd_service(paths: &Paths, action: ServiceAction) -> Result<i32, String> {
    if !cfg!(target_os = "macos") {
        return Err("This command is for macOS (launchd).".to_string());
    }
    use crate::serve::{launch_agent_plist, SERVICE_LABEL};
    let home = std::env::var_os("HOME").map(PathBuf::from).ok_or("HOME is not set, so there is no LaunchAgents folder to use.")?;
    let plist = home.join("Library/LaunchAgents").join(format!("{SERVICE_LABEL}.plist"));
    // SAFETY: getuid has no preconditions and cannot fail.
    let uid = unsafe { libc::getuid() };
    let domain = format!("gui/{uid}");
    match action {
        ServiceAction::Install => {
            let exe = std::env::current_exe().map_err(|e| format!("Cannot find this program's path ({e})."))?;
            for dir in [plist.parent(), Some(paths.logs_dir().as_path())].into_iter().flatten() {
                std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create {} ({e}).", dir.display()))?;
            }
            std::fs::write(&plist, launch_agent_plist(&exe, &paths.home))
                .map_err(|e| format!("Cannot write {} ({e}).", plist.display()))?;
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
            "run", "-w", "/work", "--pack", "p", "--role", "r", "-m", "big", "-t", "T", "--attended", "--max-steps", "5",
            "--max-minutes", "9", "-d", "--reasoning", "--full", "-v", "fix", "the", "bug",
        ]) else {
            panic!("not run");
        };
        assert_eq!(a.start.workspace, Some(PathBuf::from("/work")));
        assert_eq!(a.start.pack.as_deref(), Some("p"));
        assert_eq!(a.start.role.as_deref(), Some("r"));
        assert_eq!(a.start.model.as_deref(), Some("big"));
        assert_eq!(a.start.title.as_deref(), Some("T"));
        assert!(a.start.attended);
        assert_eq!((a.start.max_steps, a.start.max_minutes), (5, 9));
        assert!(a.detach && a.show.reasoning && a.show.full && a.show.verbose);
        assert_eq!(a.message, words(&["fix", "the", "bug"]));
        let Command::Run(a) = ok(&["run"]) else { panic!("not run") };
        assert!(a.message.is_empty() && !a.detach && !a.start.attended);
        assert_eq!((a.start.max_steps, a.start.max_minutes), (0, 0));
        let Command::Run(a) = ok(&["run", "-"]) else { panic!("not run") };
        assert_eq!(a.message, words(&["-"]));
        let Command::Run(a) = ok(&["run", "--", "-5", "is", "negative"]) else { panic!("not run") };
        assert_eq!(a.message, words(&["-5", "is", "negative"]));
        rejected(&["run", "--max-steps", "many"]);
        rejected(&["run", "--no-such-flag"]);
    }

    #[test]
    fn chat_tail_and_send_parse() {
        let Command::Chat(a) = ok(&["chat", "--session", "s-1", "-w", "/w", "--reasoning"]) else { panic!("not chat") };
        assert_eq!(a.session.as_deref(), Some("s-1"));
        assert!(a.show.reasoning);
        let Command::Chat(a) = ok(&["chat"]) else { panic!("not chat") };
        assert!(a.session.is_none());

        let Command::Tail(a) = ok(&["tail", "s-1", "--since", "40", "--no-follow", "--reasoning", "--full", "-v"]) else {
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
    }

    #[test]
    fn session_commands_parse_and_need_their_argument() {
        assert!(matches!(ok(&["stop", "s-1"]), Command::Stop(SessionArg { .. })));
        assert!(matches!(ok(&["resume", "s-1"]), Command::Resume(_)));
        assert!(matches!(ok(&["reweave", "s-1"]), Command::Reweave(_)));
        assert!(matches!(ok(&["ledger", "m-1"]), Command::Ledger(_)));
        assert!(matches!(ok(&["window", "s-1"]), Command::Window(_)));
        for cmd in ["stop", "resume", "reweave", "archive", "ledger", "window", "net", "answer", "out"] {
            rejected(&[cmd]);
        }
        let Command::Archive(a) = ok(&["archive", "s-1", "--undo"]) else { panic!("not archive") };
        assert!(a.undo);
        let Command::Archive(a) = ok(&["archive", "s-1"]) else { panic!("not archive") };
        assert!(!a.undo);
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
        let Command::Approve(a) = ok(&["approve", "s-1", "ship", "it", "--scope", "staging"]) else {
            panic!("not approve")
        };
        assert_eq!((a.text, a.scope.as_deref()), (words(&["ship", "it"]), Some("staging")));
        rejected(&["approve"]);
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
        assert!(matches!(ok(&["service", "install"]), Command::Service { action: ServiceAction::Install }));
        assert!(matches!(ok(&["service", "uninstall"]), Command::Service { action: ServiceAction::Uninstall }));
        assert!(matches!(ok(&["service", "status"]), Command::Service { action: ServiceAction::Status }));
        rejected(&["config"]);
        rejected(&["config", "edit"]);
        rejected(&["service"]);
    }

    #[test]
    fn messages_are_joined_and_dash_means_standard_input() {
        assert_eq!(message_from_args(&words(&["fix", "the", "bug"])).as_deref(), Some("fix the bug"));
        assert_eq!(message_from_args(&words(&["one"])).as_deref(), Some("one"));
        assert_eq!(message_from_args(&words(&["-", "x"])).as_deref(), Some("- x"));
        assert_eq!(message_from_args(&words(&["-"])), None);
        assert_eq!(message_from_args(&[]), None);
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
    }

    #[test]
    fn the_browser_address() {
        assert_eq!(open_url("127.0.0.1:7878", "abc"), "http://127.0.0.1:7878/?token=abc");
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
        assert_eq!(cmd_config(&paths, ConfigAction::Check), Ok(0));
        std::fs::write(paths.config_file(), "default_model = [").unwrap();
        assert!(cmd_config(&paths, ConfigAction::Check).unwrap_err().contains("config.toml"));
    }

    #[test]
    fn new_session_from_options() {
        let cwd = Path::new("/here");
        let n = new_session(&StartOpts::default(), Some("go".into()), cwd);
        assert_eq!(n.workspace, PathBuf::from("/here"));
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
        };
        let n = new_session(&opts, None, cwd);
        assert_eq!(n.workspace, PathBuf::from("/w"));
        assert_eq!((n.pack.as_deref(), n.role.as_deref(), n.model.as_deref(), n.title.as_deref()), (Some("p"), Some("r"), Some("m"), Some("t")));
        assert_eq!(n.unattended, Some(false));
        assert_eq!(n.budget, Budget { max_steps: Some(7), max_minutes: Some(3) });
        assert!(n.message.is_none());
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
            [
                "/api/sessions/s-1/stream",
                "/api/sessions/s-1/stream?after=1",
                "/api/sessions/s-1/stream?after=2"
            ]
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
        let script = base_script(detail_with(Phase::Ended, Some(TurnEndReason::Finished), Some(SessionOutcome::Failed)));
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
}
