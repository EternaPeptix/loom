//! Scripted models played against the real runtime, and what each run cost: the harness's evaluation kit.
//!
//! CONTRACT.
//!
//! A change to the harness is meant to get a model to a delivered result in fewer steps, or to send it
//! back less often. A real model answers whether it did slowly, and differently every time. This kit
//! answers the part of the question that does not depend on the model. A *scenario* fixes how a model
//! behaves: a list of moves, the same in every run. The real [`Runtime`] does everything else (the
//! built-in `core` pack, the ledger, the finish gate and its verifier, the step loop), and
//! `loom_core::scorecard` counts what the run took. The same scenario gives the same card until the
//! harness changes, so a card that changed is the measured effect of the change, and the cards pinned in
//! this module's tests are the record of it: a change that costs a behaviour a step shows up there as a
//! number to be changed on purpose.
//!
//! What a scenario cannot show is how a real model reacts to a prompt or to a message: its moves are
//! fixed. That is measured on recorded runs of a real model, with the same counts, by `loom score`.
//!
//! ## The task
//! One task, the same for every scenario, so that two cards differ only by the behaviour played and the
//! harness: the workspace holds `numbers.txt` (`3`, `4`, `35`, one per line) and the operator's message is
//! [`MESSAGE`]. The command that does the work adds the numbers up in the shell, writes the sum to
//! `sum.txt` and prints `sum.txt now holds 42`: one line, the one every quote is of. [`solved`] is the
//! check from outside the session: `sum.txt` holds `42` (surrounding whitespace aside).
//!
//! ## Moves
//! A [`Move`] is one reply of the scripted model, almost always one tool call:
//! - `Run`: `bash` with the task's command. `Look`: `bash` printing `numbers.txt`, which does no work.
//!   `Scan`: `dep_scan` with no arguments (the workspace): a dependency scan, which runs a scanner but not
//!   the target, so its output is analysis (`loom_core::event::EvidenceGrade::Analysis`), not a run.
//! - `Claim`: `claim` that `sum.txt` holds the sum. `Evidence(quote)`: `evidence` for claim `c1`.
//!   `Support`: `claim_update` of `c1` to `supported`. `Conclude(id)`: `conclude` as `met`, citing the
//!   evidence record `id`. `Finish(quote)`: `finish` with the answer and one quote.
//! - `Delegate`: `agent_spawn` of a worker that is to do the task and report.
//! - `Say(text)`: a reply without a call. `Call(name, arguments)`: a call exactly as written, for calls
//!   that are wrong. `Cut`: a `bash` call the output limit cut before its arguments ended.
//!
//! The quote of an `Evidence` or a `Finish` is of line 1 of the latest output the request shows: the last
//! handle in the header of the latest `bash` or `dep_scan` result (the output's own; a `dep_scan` header names
//! its stored VDR, SBOM and console before it), or, for a lead that delegated, the first handle of the
//! checked quotes in the latest agent's report. A [`Quote`] says how it is given: `ByLines` (handle and
//! line numbers, no text), `Exact` (with the line's text) or `Retyped` (with the text as a model writes
//! it from memory, `holds` become `contains`: it does not occur in the output). With no run in view the
//! handle is `out:00000000`, which no output has.
//!
//! ## A scenario
//! [`Scenario`]: a `name`; `plays`, the behaviour as the rest of the sentence "A model that ..."; the
//! moves of the `lead` and of every `worker` it starts, taken one per request in order; `verdicts`, what
//! each verifier the finish gate starts decides, in the order the verdicts are given (past the end:
//! accepted); and `configure`, the scenario's changes to the configuration. Which session a request
//! belongs to is read from its tools: `verdict` is a verifier, `agent_spawn` a lead, anything else a
//! worker. A session whose moves are used up replies [`OUT_OF_MOVES`] without a call from then on, so the
//! stop gate parks it and the run ends as not finished rather than hanging. A verifier takes two steps:
//! it opens the first output its assignment names with `out_read` (or, when it names none, prints
//! `sum.txt` with `bash`), then gives its `verdict` with that output as `opened`; a rejection carries the
//! objection [`OBJECTION`].
//!
//! ## The fake scanner
//! `dep_scan` runs the operator-installed `depscan` found on the PATH that commands inherit, which is the
//! process's own. [`FAKE_DEPSCAN`] is a POSIX shell script standing in for it: it writes one CycloneDX SBOM
//! (`sbom-eval.cdx.json`, one component) and one VDR (`sbom-eval.vdr.json`, one vulnerability marked
//! prioritized and reachable) into the directory after `--reports-dir`, prints one line, and exits 0, so
//! the scan's result is the same on every host. [`install_fake_depscan(dir)`] writes it to `dir/depscan`
//! (mode 0755) and returns that path. The kit never changes the process environment: whoever plays a
//! scenario that scans puts that directory first on the PATH of the process before it starts threads (the
//! `eval` example does so first thing; the tests play such a scenario in a child process of the test
//! binary whose PATH is set when it is spawned).
//!
//! ## `run(scenario, dir)`
//! Plays one scenario in the empty directory `dir`. A scenario with a `Scan` move among its lead's or
//! worker's moves is refused first, with nothing started, unless the first `depscan` on the process's PATH
//! is a file whose bytes are [`FAKE_DEPSCAN`]: the error says the scenario scans with `dep_scan`, that it
//! needs the kit's fake `depscan` first on PATH (`install_fake_depscan`), and what was found instead (a
//! path, or that there is none), because a real scanner, or none, would give another card. Then it writes the
//! workspace under `dir/workspace`, starts a `MockServer` with the scenario's script and a `Runtime` whose
//! home is `dir/home`, creates a lead session of the built-in `core` pack with [`MESSAGE`], and waits until its turn
//! has ended for a reason
//! other than `Waiting`. The configuration is the default one with: the mock server as the only model
//! (window 1 000 000), no sandbox, network `deny_all`, a notification command that does nothing (the
//! default would raise a desktop notification per run), then `scenario.configure`. So the finish gate's
//! verifier runs unless a scenario turns it off.
//!
//! Returns an [`Outcome`]: how the lead's turn ended, whether the task is [`solved`], and from
//! `Runtime::score` (what `loom score` prints for a recorded run) the number of sessions of the mission,
//! the lead's own card and the mission's total. Both the runtime and the server are shut down before it
//! returns, also on an error. Errors are sentences: the workspace or the server could not be set up, the runtime refused,
//! or the run did not end within [`RUN_TIMEOUT`].
//!
//! ## `suite()`
//! The scenarios, in the order `table` prints them. Each is a way small models are seen to behave; its
//! pinned card is in the tests.
//! - `direct`: does everything right the first time and quotes by line numbers.
//! - `retypes_quotes`: retypes its quotes from memory, and gets each wrong once (`evidence`, `finish`).
//! - `finishes_early`: calls `finish` straight after the run, then again with its claim still open.
//! - `malformed_calls`: begins with an argument the tool does not have, a tool that does not exist and a
//!   call the output limit cut.
//! - `rejected_once`: finishes on a result its verifier does not accept, then runs the target again.
//!   The lead is started afresh and the goal reopened, so it concludes a second time.
//! - `rejected_once_kept_in_view`: the same with `agents.fresh_start` off: the conclusion stands and new
//!   execution evidence settles the objection.
//! - `delegates`: hands the task to a worker, which retypes its quote wrong once, and cites the worker's
//!   run as its own evidence.
//! - `gives_up`: looks at the input, then replies in prose until the stop gate parks it.
//! - `concludes_on_a_scan`: scans the dependencies instead of running the target, attaches the scan's
//!   output as evidence, concludes and finishes on it, is refused both times, then runs the target and
//!   concludes and finishes on the run. Moves: `Scan, Claim, Evidence(ByLines), Support, Conclude("e1"),
//!   Finish(ByLines), Run, Evidence(ByLines), Conclude("e2"), Finish(ByLines)`. The `conclude` on `e1` is
//!   refused because analysis is not a run, so the `finish` after it is held by the goal pre-gate. A harness
//!   that took a scan for a run (`dep_scan` is an `Exec` tool) would let this model finish on the scan with
//!   `sum.txt` never written.
//! - `repaired_aliases`: begins with common training aliases (`bash` with `cmd`, `shell` with `command`)
//!   that are transparently repaired without costing extra malformed steps before finishing normally.
//!
//! ## `table(outcomes)`
//! The outcomes as text, one row each under a header line, columns separated by two spaces and as wide
//! as their widest cell: `scenario`, `end` (the turn end in snake case), `solved` (`yes`/`no`),
//! `sessions`, then the mission card's `Scorecard::cells()` under `scorecard::COLUMNS`. Each line ends
//! with a newline and none has trailing spaces.
//!
//! Tests required: every scenario of the suite gives its pinned outcome (end, solved, sessions, lead
//! card, mission card); a lead whose moves run out is parked; the names of the suite are distinct;
//! `table` for two outcomes, exactly. `concludes_on_a_scan` is played in a child process of the test binary
//! (the test runs itself again, filtered to an ignored test that does nothing unless a marker variable is
//! set, with a temporary directory holding the fake `depscan` first on the child's PATH); the child asserts
//! the pinned outcome and that the lead's log holds a `conclude` result with status `error` whose text
//! contains `analysis is not a run` and `e1 analysis by dep_scan`, and the parent asserts the child passed
//! and that it did play the scenario. `run` refuses a scanning scenario when the fake is not first on PATH
//! (in the test process itself, where it is not), with nothing started. `install_fake_depscan` writes an
//! executable file with exactly `FAKE_DEPSCAN`.

use crate::runtime::{NewSession, Runtime};
use crate::session::Phase;
use loom_core::config::{Config, ModelProfile, NetworkMode, Paths, SandboxMode};
use loom_core::event::{FinishReason, TurnEndReason};
use loom_core::scorecard::{self, Scorecard};
use loom_model::mock::{Action, MockServer, Reply, Script};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// What the operator asks for in every scenario.
pub const MESSAGE: &str = "Write the sum of the numbers in numbers.txt to sum.txt.";

/// The reply of a scripted session that has no move left.
pub const OUT_OF_MOVES: &str = "I have nothing more to do.";

/// The objection of a scripted verifier that does not accept a result.
pub const OBJECTION: &str = "No run after the last change shows what sum.txt holds.";

/// The longest a scenario may take before `run` gives up on it.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(120);

const POLL: Duration = Duration::from_millis(10);
const FILES: &[(&str, &str)] = &[("numbers.txt", "3\n4\n35\n")];
const RUN: &str = r#"s=0; while read n; do s=$((s+n)); done < numbers.txt; echo "$s" > sum.txt; echo "sum.txt now holds $(cat sum.txt)""#;
const PRINTED: &str = "sum.txt now holds 42";
const RETYPED: &str = "sum.txt now contains 42";
const ANSWER: &str = "sum.txt holds 42, the sum of the numbers in numbers.txt.";
const NO_HANDLE: &str = "out:00000000";

/// The `depscan` a scenario that scans runs: see *The fake scanner* in the module contract.
pub const FAKE_DEPSCAN: &str = r#"#!/bin/sh
reports=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--reports-dir" ]; then reports="$a"; fi
  prev="$a"
done
mkdir -p "$reports"
cat > "$reports/sbom-eval.cdx.json" <<'JSON'
{"bomFormat":"CycloneDX","components":[{"bom-ref":"pkg:cargo/eval@1.0.0"}]}
JSON
cat > "$reports/sbom-eval.vdr.json" <<'JSON'
{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"EVAL-0001","ratings":[{"severity":"high","score":7.5}],"affects":[{"ref":"pkg:cargo/eval@1.0.0","versions":[{"version":"1.0.0","status":"affected"},{"version":"1.0.1","status":"unaffected"}]}],"properties":[{"name":"depscan:prioritized","value":"true"},{"name":"depscan:insights","value":"Reachable"}]}]}
JSON
echo "fake depscan ran: $*"
"#;

/// How a scripted model gives a quote. See the module contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quote {
    ByLines,
    Exact,
    Retyped,
}

/// One reply of a scripted model. See the module contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Move {
    Run,
    Look,
    Scan,
    Claim,
    Evidence(Quote),
    Support,
    Conclude(&'static str),
    Finish(Quote),
    Delegate,
    Say(&'static str),
    Call(&'static str, &'static str),
    Cut,
}

/// A behaviour to play. See the module contract.
#[derive(Clone, Copy, Debug)]
pub struct Scenario {
    pub name: &'static str,
    pub plays: &'static str,
    pub lead: &'static [Move],
    pub worker: &'static [Move],
    pub verdicts: &'static [bool],
    pub configure: fn(&mut Config),
}

/// What a played scenario came to. See the module contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub scenario: String,
    pub end: TurnEndReason,
    pub solved: bool,
    pub sessions: usize,
    pub lead: Scorecard,
    pub mission: Scorecard,
}

/// Whether the task is done in `workspace`: `sum.txt` holds `42`.
pub fn solved(workspace: &Path) -> bool {
    std::fs::read_to_string(workspace.join("sum.txt")).is_ok_and(|text| text.trim() == "42")
}

fn as_configured(_: &mut Config) {}

fn kept_in_view(config: &mut Config) {
    config.agents.fresh_start = false;
}

/// The scenarios, in the order they are reported. See the module contract.
pub fn suite() -> Vec<Scenario> {
    use Move::{Call, Claim, Conclude, Cut, Delegate, Evidence, Finish, Look, Run, Say, Scan, Support};
    use Quote::{ByLines, Exact, Retyped};
    let base = Scenario { name: "", plays: "", lead: &[], worker: &[], verdicts: &[], configure: as_configured };
    vec![
        Scenario {
            name: "direct",
            plays: "does everything right the first time and quotes by line numbers",
            lead: &[Run, Claim, Evidence(ByLines), Support, Conclude("e1"), Finish(ByLines)],
            ..base
        },
        Scenario {
            name: "retypes_quotes",
            plays: "retypes its quotes from memory and gets each wrong once",
            lead: &[
                Run,
                Claim,
                Evidence(Retyped),
                Evidence(Exact),
                Support,
                Conclude("e1"),
                Finish(Retyped),
                Finish(Exact),
            ],
            ..base
        },
        Scenario {
            name: "finishes_early",
            plays: "calls finish straight after the run, then again with its claim still open",
            lead: &[
                Run,
                Finish(ByLines),
                Claim,
                Evidence(ByLines),
                Conclude("e1"),
                Finish(ByLines),
                Support,
                Finish(ByLines),
            ],
            ..base
        },
        Scenario {
            name: "malformed_calls",
            plays: "begins with an argument the tool does not have, a tool that does not exist and a call cut short",
            lead: &[
                Call("bash", r#"{"bogus": "cat numbers.txt"}"#),
                Call("no_such_tool", r#"{"command": "cat numbers.txt"}"#),
                Cut,
                Run,
                Claim,
                Evidence(ByLines),
                Support,
                Conclude("e1"),
                Finish(ByLines),
            ],
            ..base
        },
        Scenario {
            name: "rejected_once",
            plays: "finishes on a result its verifier does not accept, then runs the target again",
            lead: &[
                Run,
                Claim,
                Evidence(ByLines),
                Support,
                Conclude("e1"),
                Finish(ByLines),
                Run,
                Evidence(ByLines),
                Conclude("e2"),
                Finish(ByLines),
            ],
            verdicts: &[false, true],
            ..base
        },
        Scenario {
            name: "rejected_once_kept_in_view",
            plays: "does the same with the fresh start off: the rejection stays in view and the conclusion stands",
            lead: &[
                Run,
                Claim,
                Evidence(ByLines),
                Support,
                Conclude("e1"),
                Finish(ByLines),
                Run,
                Evidence(ByLines),
                Finish(ByLines),
            ],
            verdicts: &[false, true],
            configure: kept_in_view,
            ..base
        },
        Scenario {
            name: "delegates",
            plays: "hands the task to a worker, which retypes its quote wrong once, and cites the worker's run",
            lead: &[Delegate, Claim, Evidence(ByLines), Support, Conclude("e1"), Finish(ByLines)],
            worker: &[Run, Finish(Retyped), Finish(ByLines)],
            ..base
        },
        Scenario {
            name: "gives_up",
            plays: "looks at the input, then replies in prose until the stop gate parks it",
            lead: &[
                Look,
                Say("The numbers are there, but I cannot be sure of their sum."),
                Say("I was not able to complete this."),
                Say("I was not able to complete this."),
                Say("I was not able to complete this."),
            ],
            ..base
        },
        Scenario {
            name: "concludes_on_a_scan",
            plays: "scans the dependencies instead of running the target, concludes and finishes on the scan, and is refused",
            lead: &[
                Scan,
                Claim,
                Evidence(ByLines),
                Support,
                Conclude("e1"),
                Finish(ByLines),
                Run,
                Evidence(ByLines),
                Conclude("e2"),
                Finish(ByLines),
            ],
            ..base
        },
        Scenario {
            name: "repaired_aliases",
            plays: "calls bash with `cmd` and `shell` with `command` before finishing normally",
            lead: &[
                Call("bash", r#"{"cmd": "cat numbers.txt"}"#),
                Call(
                    "shell",
                    r#"{"command": "s=0; while read n; do s=$((s+n)); done < numbers.txt; echo $s > sum.txt; echo sum.txt now holds $(cat sum.txt)"}"#,
                ),
                Claim,
                Evidence(ByLines),
                Support,
                Conclude("e1"),
                Finish(ByLines),
            ],
            ..base
        },
    ]
}

/// Write [`FAKE_DEPSCAN`] to `dir/depscan` (mode 0755) and return that path.
pub fn install_fake_depscan(dir: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("depscan");
    std::fs::write(&path, FAKE_DEPSCAN).map_err(|e| format!("Could not write {}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("Could not make {} executable: {e}", path.display()))?;
    Ok(path)
}

/// What stands in the way of a scenario that scans: `None` when the first `depscan` on the PATH is the fake.
fn scanner_problem(scenario: &Scenario) -> Option<String> {
    if !scenario.lead.iter().chain(scenario.worker).any(|m| *m == Move::Scan) {
        return None;
    }
    let found = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path).map(|dir| dir.join("depscan")).find(|candidate| candidate.is_file())
    });
    // The length first: a real scanner can be a large binary, not worth reading to tell it apart.
    let is_fake = |path: &std::path::Path| {
        std::fs::metadata(path).is_ok_and(|m| u64::try_from(FAKE_DEPSCAN.len()).ok() == Some(m.len()))
            && std::fs::read(path).is_ok_and(|bytes| bytes == FAKE_DEPSCAN.as_bytes())
    };
    let seen = match found {
        Some(path) if is_fake(&path) => return None,
        Some(path) => format!("the first `depscan` on the PATH is {}", path.display()),
        None => "there is no `depscan` on the PATH".to_string(),
    };
    Some(format!(
        "The scenario `{}` scans with `dep_scan`, which needs the kit's fake `depscan` first on the PATH \
         (`evalkit::install_fake_depscan`), but {seen}; a real scanner, or none, would give another card.",
        scenario.name
    ))
}

// ---------------------------------------------------------------------------------------------
// The scripted model

fn has_tool(body: &Value, name: &str) -> bool {
    body.get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| tools.iter().any(|t| t.pointer("/function/name").and_then(Value::as_str) == Some(name)))
}

/// The texts of a request's messages of one role, oldest first.
fn texts_of<'a>(body: &'a Value, role: &str) -> Vec<&'a str> {
    body.get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .filter(|m| m.get("role").and_then(Value::as_str) == Some(role))
                .filter_map(|m| m.get("content").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

/// The first `out:` handle in `text`.
fn handle_in(text: &str) -> Option<String> {
    let mut rest = text;
    while let Some(at) = rest.find("out:") {
        let after = rest.get(at.saturating_add(4)..).unwrap_or("");
        let hex: String = after.chars().take_while(char::is_ascii_hexdigit).collect();
        if hex.len() >= 8 {
            return Some(format!("out:{hex}"));
        }
        rest = after;
    }
    None
}

/// The handle of the latest run a request shows: see *Moves* in the module contract.
fn run_in_view(body: &Value) -> Option<String> {
    texts_of(body, "tool").into_iter().rev().find_map(|text| {
        let header = text.lines().next().unwrap_or("");
        if header.starts_with("[bash ") || header.starts_with("[dep_scan ") {
            // The output's own handle closes the header; a scan's header names its report files before it.
            return header.rsplit(" · ").next().and_then(handle_in);
        }
        let quotes = text.find("Quotes (checked against the stored output by the harness)")?;
        handle_in(text.get(quotes..).unwrap_or(""))
    })
}

fn call(name: &str, args: Value) -> Action {
    Action::Reply(Reply::tool(name, args.to_string()))
}

/// A quote of line 1 of `handle`, as `finish` takes it.
fn quote(handle: &str, how: Quote) -> Value {
    let mut q = Map::new();
    q.insert("handle".into(), json!(handle));
    q.insert("start".into(), json!(1));
    q.insert("end".into(), json!(1));
    match how {
        Quote::ByLines => {}
        Quote::Exact => drop(q.insert("text".into(), json!(PRINTED))),
        Quote::Retyped => drop(q.insert("text".into(), json!(RETYPED))),
    }
    Value::Object(q)
}

/// The reply a move is, to the request `body`.
fn play(mv: Move, body: &Value) -> Action {
    let handle = || run_in_view(body).unwrap_or_else(|| NO_HANDLE.to_string());
    match mv {
        Move::Run => call("bash", json!({ "command": RUN })),
        Move::Look => call("bash", json!({ "command": "cat numbers.txt" })),
        Move::Scan => call("dep_scan", json!({})),
        Move::Claim => call("claim", json!({ "text": "sum.txt holds the sum of the numbers in numbers.txt, 42." })),
        Move::Evidence(how) => {
            let mut args = Map::new();
            args.insert("claim".into(), json!("c1"));
            if let Value::Object(q) = quote(&handle(), how) {
                for (key, value) in q {
                    args.insert(if key == "text" { "quote".into() } else { key }, value);
                }
            }
            args.insert("note".into(), json!("The run wrote the sum to sum.txt and printed what the file holds."));
            call("evidence", Value::Object(args))
        }
        Move::Support => {
            call("claim_update", json!({ "id": "c1", "status": "supported", "note": "Shown by the run." }))
        }
        Move::Conclude(evidence) => call(
            "conclude",
            json!({ "status": "met", "note": "The run printed the sum it wrote to sum.txt.", "evidence": [evidence] }),
        ),
        Move::Finish(how) => call("finish", json!({ "answer": ANSWER, "quotes": [quote(&handle(), how)] })),
        Move::Delegate => call(
            "agent_spawn",
            json!({
                "question": MESSAGE,
                "role": "worker",
                "return": "The line the command printed, quoted from its output.",
            }),
        ),
        Move::Say(text) => Action::Reply(Reply::text(text)),
        Move::Call(name, arguments) => Action::Reply(Reply::tool(name, arguments)),
        Move::Cut => {
            Action::Reply(Reply::tool("bash", r#"{"command": "cat numbers.tx"#).with_finish(FinishReason::Length))
        }
    }
}

/// One step of a scripted verifier: open something, then give the next verdict of `verdicts`.
fn verify(body: &Value, verdicts: &[bool], given: &mut usize) -> Action {
    let named = texts_of(body, "user").into_iter().find_map(handle_in);
    let results = texts_of(body, "tool");
    if results.is_empty() {
        return match named {
            Some(handle) => call("out_read", json!({ "handle": handle, "start": 1, "end": 20 })),
            None => call("bash", json!({ "command": "cat sum.txt" })),
        };
    }
    let opened = named.or_else(|| run_in_view(body)).unwrap_or_else(|| NO_HANDLE.to_string());
    let accepted = verdicts.get(*given).copied().unwrap_or(true);
    *given = given.saturating_add(1);
    if accepted {
        call("verdict", json!({ "accepted": true, "opened": [opened] }))
    } else {
        call("verdict", json!({ "accepted": false, "objections": [OBJECTION], "opened": [opened] }))
    }
}

/// The model of a scenario: each session's moves in order, by the session a request belongs to.
fn script(scenario: &Scenario) -> Script {
    let (lead, worker, verdicts) = (scenario.lead, scenario.worker, scenario.verdicts);
    let (mut lead_at, mut worker_at, mut given) = (0usize, 0usize, 0usize);
    Script::new(move |body, _| {
        // The note request of a compaction (a fresh start): it is not one of the session's moves.
        let last = body["messages"].as_array().and_then(|m| m.last()).and_then(|l| l["content"].as_str());
        if last.is_some_and(|c| c.starts_with(crate::texts::COMPACT_PROMPT)) {
            return Action::Reply(Reply::text("## Goal\nThe task.\n## Next\nRun the target again."));
        }
        if has_tool(body, "verdict") {
            return verify(body, verdicts, &mut given);
        }
        let (moves, at) = if has_tool(body, "agent_spawn") { (lead, &mut lead_at) } else { (worker, &mut worker_at) };
        let mv = moves.get(*at).copied();
        *at = at.saturating_add(1);
        match mv {
            Some(mv) => play(mv, body),
            None => Action::Reply(Reply::text(OUT_OF_MOVES)),
        }
    })
}

// ---------------------------------------------------------------------------------------------
// Playing a scenario

/// The configuration a scenario starts from: see `run` in the module contract.
fn base_config(base_url: String) -> Config {
    let mut config = Config::default();
    config.models.clear();
    config.models.insert(
        "mock".into(),
        ModelProfile {
            base_url,
            model: "mock".into(),
            context_window: Some(1_000_000),
            retry_window_s: 1,
            retry_max_delay_s: 1,
            stall_timeout_s: 30,
            ..ModelProfile::default()
        },
    );
    config.default_model = "mock".into();
    config.sandbox.mode = SandboxMode::None;
    config.network.mode = NetworkMode::DenyAll;
    config.tools.kill_grace_s = 1;
    config.notify.command = vec!["/bin/sh".into(), "-c".into(), ":".into()];
    config
}

async fn play_out(rt: &Runtime, scenario: &Scenario, workspace: &Path) -> Result<Outcome, String> {
    let new =
        NewSession { workspace: workspace.to_path_buf(), message: Some(MESSAGE.to_string()), ..NewSession::default() };
    let lead = rt.create_session(new).await?.meta;
    let deadline = tokio::time::Instant::now() + RUN_TIMEOUT;
    let end = loop {
        let status = rt.session(&lead.id).ok_or_else(|| format!("Session {} is gone.", lead.id))?.status;
        match status.last_end {
            Some(reason) if reason != TurnEndReason::Waiting && status.phase != Phase::Running => break reason,
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "The scenario `{}` did not end within {} seconds.",
                scenario.name,
                RUN_TIMEOUT.as_secs()
            ));
        }
        tokio::time::sleep(POLL).await;
    };
    let view = rt.score(&lead.mission).await?;
    let lead_card = view.sessions.iter().find(|s| s.session == lead.id).map(|s| s.card.clone()).unwrap_or_default();
    Ok(Outcome {
        scenario: scenario.name.to_string(),
        end,
        solved: solved(workspace),
        sessions: view.sessions.len(),
        lead: lead_card,
        mission: view.total,
    })
}

/// Play one scenario in the empty directory `dir`. See the module contract.
pub async fn run(scenario: &Scenario, dir: &Path) -> Result<Outcome, String> {
    if let Some(problem) = scanner_problem(scenario) {
        return Err(problem);
    }
    let workspace = dir.join("workspace");
    std::fs::create_dir_all(&workspace).map_err(|e| format!("Could not create {}: {e}", workspace.display()))?;
    for (name, text) in FILES {
        let path = workspace.join(name);
        std::fs::write(&path, text).map_err(|e| format!("Could not write {}: {e}", path.display()))?;
    }
    let server = MockServer::start(script(scenario))
        .await
        .map_err(|e| format!("Could not start the scripted model server: {e}"))?;
    let mut config = base_config(server.base_url());
    (scenario.configure)(&mut config);
    let outcome = match Runtime::start(config, Paths::at(dir.join("home"))).await {
        Ok(rt) => {
            let outcome = play_out(&rt, scenario, &workspace).await;
            rt.shutdown().await;
            outcome
        }
        Err(e) => Err(e),
    };
    server.shutdown().await;
    outcome
}

fn end_word(reason: TurnEndReason) -> String {
    serde_json::to_value(reason).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// The outcomes as a table. See the module contract.
pub fn table(outcomes: &[Outcome]) -> String {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut header: Vec<String> = ["scenario", "end", "solved", "sessions"].iter().map(|h| h.to_string()).collect();
    header.extend(scorecard::COLUMNS.iter().map(|h| h.to_string()));
    rows.push(header);
    for o in outcomes {
        let mut row = vec![
            o.scenario.clone(),
            end_word(o.end),
            if o.solved { "yes" } else { "no" }.to_string(),
            o.sessions.to_string(),
        ];
        row.extend(o.mission.cells());
        rows.push(row);
    }
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..columns)
        .map(|c| rows.iter().filter_map(|r| r.get(c)).map(|cell| cell.chars().count()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for row in &rows {
        let mut line = String::new();
        for (cell, width) in row.iter().zip(&widths) {
            if !line.is_empty() {
                line.push_str("  ");
            }
            line.push_str(cell);
            line.extend(std::iter::repeat_n(' ', width.saturating_sub(cell.chars().count())));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    async fn played(scenario: &Scenario) -> Outcome {
        let dir = tempfile::tempdir().unwrap();
        run(scenario, dir.path()).await.unwrap()
    }

    async fn played_named(name: &str) -> Outcome {
        let scenario = suite().into_iter().find(|s| s.name == name).unwrap();
        played(&scenario).await
    }

    /// A card from its counts: steps, steps to the delivered finish, calls, malformed calls, finish calls
    /// and how many of them were refused, quote refusals, the verifier's accepts and rejections, fresh starts.
    #[allow(clippy::too_many_arguments)]
    fn card(
        steps: u64,
        to_finish: Option<u64>,
        calls: u64,
        malformed: u64,
        finish: (u64, u64),
        quotes: u64,
        verifier: (u64, u64),
        fresh: u64,
    ) -> Scorecard {
        Scorecard {
            steps,
            finished: to_finish.is_some(),
            steps_to_finish: to_finish,
            calls,
            malformed_calls: malformed,
            finish_calls: finish.0,
            finish_refusals: finish.1,
            quote_refusals: quotes,
            verifier_accepts: verifier.0,
            verifier_rejections: verifier.1,
            fresh_starts: fresh,
            ..Scorecard::default()
        }
    }

    // The pinned cards. Each is what the harness asks of one behaviour today; a harness change that moves
    // one of these numbers is to change it here on purpose, and the difference is what the change did.

    #[tokio::test]
    async fn direct_is_the_floor_six_steps_and_a_check_of_two() {
        let o = played_named("direct").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 2));
        // run, claim, evidence, claim_update, conclude, finish: nothing is refused.
        assert_eq!(o.lead, card(6, Some(6), 6, 0, (1, 0), 0, (1, 0), 0));
        // The verifier opens the quoted output and gives its verdict.
        assert_eq!(o.mission, card(8, Some(6), 8, 0, (1, 0), 0, (1, 0), 0));
    }

    #[tokio::test]
    async fn a_quote_retyped_wrong_costs_a_step_each_time() {
        let o = played_named("retypes_quotes").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 2));
        // Two steps more than `direct`, both spent on a quote: one in `evidence`, one in `finish`.
        assert_eq!(o.lead, card(8, Some(8), 8, 0, (2, 1), 2, (1, 0), 0));
        assert_eq!(o.mission, card(10, Some(8), 10, 0, (2, 1), 2, (1, 0), 0));
    }

    #[tokio::test]
    async fn a_finish_made_too_early_is_held_without_a_verifier() {
        let o = played_named("finishes_early").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 2));
        // Refused once for the goal not concluded and once for the open claim; neither is a quote's
        // fault, and neither reached a verifier: one was started, for the finish that was delivered.
        let mut expected_lead = card(8, Some(8), 8, 0, (3, 2), 0, (1, 0), 0);
        expected_lead.ceremony_refusals = 2;
        assert_eq!(o.lead, expected_lead);
        let mut expected_mission = card(10, Some(8), 10, 0, (3, 2), 0, (1, 0), 0);
        expected_mission.ceremony_refusals = 2;
        assert_eq!(o.mission, expected_mission);
    }

    #[tokio::test]
    async fn malformed_calls_cost_a_step_each_and_are_counted() {
        let o = played_named("malformed_calls").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 2));
        // An argument the tool does not have, a tool that does not exist, a call cut by the output limit.
        assert_eq!(o.lead, card(9, Some(9), 9, 3, (1, 0), 0, (1, 0), 0));
        assert_eq!(o.lead.malformed_call_rate(), Some(3.0 / 9.0));
        assert_eq!(o.mission, card(11, Some(9), 11, 3, (1, 0), 0, (1, 0), 0));
    }

    #[tokio::test]
    async fn zero_training_aliases_are_repaired_without_cost() {
        let o = played_named("repaired_aliases").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 2));
        assert!(o.lead.repaired_calls >= 2, "{:?}", o.lead);
        assert_eq!(o.lead.malformed_calls, 0);
        assert!(o.lead.finished);
        let mut expected = card(7, Some(7), 7, 0, (1, 0), 0, (1, 0), 0);
        expected.repaired_calls = 2;
        assert_eq!(o.lead, expected);
    }

    #[tokio::test]
    async fn a_rejected_finish_starts_the_lead_afresh_and_has_it_conclude_again() {
        let o = played_named("rejected_once").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 3));
        // After the rejection: a new run, its evidence, a second conclude (the goal was reopened), finish.
        assert_eq!(o.lead, card(10, Some(10), 10, 0, (2, 1), 0, (1, 1), 1));
        assert_eq!(o.lead.verifier_accept_rate(), Some(0.5));
        // Each finish that reached the gate had its own verifier.
        assert_eq!(o.mission, card(14, Some(10), 14, 0, (2, 1), 0, (1, 1), 1));
    }

    #[tokio::test]
    async fn with_the_fresh_start_off_the_conclusion_stands_and_a_step_is_saved() {
        let o = played_named("rejected_once_kept_in_view").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 3));
        // One step fewer than `rejected_once`: no second conclude. That step is the price of the reopened
        // goal for a model that behaves the same either way; what the fresh start buys is a model that
        // does not, which only runs of a real model show.
        assert_eq!(o.lead, card(9, Some(9), 9, 0, (2, 1), 0, (1, 1), 0));
        assert_eq!(o.mission, card(13, Some(9), 13, 0, (2, 1), 0, (1, 1), 0));
    }

    #[tokio::test]
    async fn a_delegated_run_is_the_leads_evidence_and_the_workers_cost_is_the_missions() {
        let o = played_named("delegates").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 3));
        // The lead never ran the command: the worker's run, cited from its report, concludes the goal.
        assert_eq!(o.lead, card(6, Some(6), 6, 0, (1, 0), 0, (1, 0), 0));
        // The worker's three steps (one a quote refused) and the verifier's two are the mission's; the
        // result, and the steps to it, are the lead's.
        assert_eq!(o.mission, card(11, Some(6), 11, 0, (3, 1), 1, (1, 0), 0));
    }

    #[tokio::test]
    async fn a_model_that_gives_up_is_parked_and_its_run_is_not_a_fast_one() {
        let o = played_named("gives_up").await;
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Yielded, false, 1));
        // One look, then two replies without a call: the first nudged, the second ends the turn.
        let mut expected = card(3, None, 1, 0, (0, 0), 0, (0, 0), 0);
        expected.text_only_nudges = 1;
        assert_eq!(o.lead, expected);
        assert_eq!(o.lead.verifier_accept_rate(), None);
        assert_eq!(o.mission, o.lead);
    }

    #[tokio::test]
    async fn a_lead_whose_moves_run_out_is_parked_not_left_hanging() {
        let scenario = Scenario {
            name: "runs_out",
            plays: "runs the command and has no further move",
            lead: &[Move::Run],
            worker: &[],
            verdicts: &[],
            configure: as_configured,
        };
        let o = played(&scenario).await;
        // The work was done, and nothing was delivered: solved by the outside check, not finished.
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Yielded, true, 1));
        let mut expected = card(3, None, 1, 0, (0, 0), 0, (0, 0), 0);
        expected.text_only_nudges = 1;
        assert_eq!(o.lead, expected);
    }

    /// Set in the child process that plays `concludes_on_a_scan`.
    const CHILD_MARKER: &str = "LOOM_EVALKIT_SCAN_CHILD";
    const CHILD_PLAYED: &str = "evalkit scan child played the scenario";

    fn scan_scenario() -> Scenario {
        suite().into_iter().find(|s| s.name == "concludes_on_a_scan").unwrap()
    }

    /// The `tool_result` of `conclude` with status `error` in some session log under `home`.
    fn refused_conclusion(home: &Path) -> Option<String> {
        let mut logs = Vec::new();
        let mut pending = vec![home.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).ok()?.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else if path.file_name().is_some_and(|n| n == "log.jsonl")
                    && path.to_string_lossy().contains("sessions")
                {
                    logs.push(path);
                }
            }
        }
        logs.iter().filter_map(|log| std::fs::read_to_string(log).ok()).find_map(|text| {
            text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).find_map(|v| {
                let is_it = v["kind"] == "tool_result" && v["name"] == "conclude" && v["status"] == "error";
                is_it.then(|| v["text"].as_str().unwrap_or("").to_string())
            })
        })
    }

    /// Runs only as the child of `concludes_on_a_scan_is_refused_and_the_run_is_not_finished_on_it`.
    #[tokio::test]
    #[ignore = "played by its parent test, in a process whose PATH starts with the fake depscan"]
    async fn child_plays_the_scan_scenario() {
        if std::env::var_os(CHILD_MARKER).is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let o = run(&scan_scenario(), dir.path()).await.unwrap();
        assert_eq!((o.end, o.solved, o.sessions), (TurnEndReason::Finished, true, 2));
        // scan, claim, evidence, claim_update, conclude (refused), finish (held), run, evidence, conclude, finish.
        let mut expected_lead = card(10, Some(10), 10, 0, (2, 1), 0, (1, 0), 0);
        expected_lead.ceremony_refusals = 1;
        assert_eq!(o.lead, expected_lead);
        let mut expected_mission = card(12, Some(10), 12, 0, (2, 1), 0, (1, 0), 0);
        expected_mission.ceremony_refusals = 1;
        assert_eq!(o.mission, expected_mission);
        let refusal = refused_conclusion(&dir.path().join("home")).expect("no refused conclude in the logs");
        assert!(refusal.contains("analysis is not a run"), "{refusal}");
        assert!(refusal.contains("e1 analysis by dep_scan"), "{refusal}");
        println!("{CHILD_PLAYED}");
    }

    #[test]
    fn a_scan_does_not_conclude_the_goal() {
        let dir = tempfile::tempdir().unwrap();
        install_fake_depscan(dir.path()).unwrap();
        let path = std::env::join_paths(
            std::iter::once(dir.path().to_path_buf()).chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        let name = module_path!().split_once("::").map(|(_, rest)| rest).unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([&format!("{name}::child_plays_the_scan_scenario"), "--exact", "--ignored", "--nocapture"])
            .arg("--test-threads=1")
            .env("PATH", path)
            .env(CHILD_MARKER, "1")
            .output()
            .unwrap();
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(out.status.success(), "the child failed:\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert!(
            stdout.contains(CHILD_PLAYED),
            "the child did not play the scenario:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    #[tokio::test]
    async fn a_scanning_scenario_is_refused_when_the_fake_is_not_first_on_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let e = run(&scan_scenario(), dir.path()).await.unwrap_err();
        assert!(e.contains("concludes_on_a_scan") && e.contains("fake `depscan` first on the PATH"), "{e}");
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none(), "nothing was started: {e}");
    }

    #[test]
    fn the_fake_depscan_is_installed_executable_with_exactly_its_text() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = install_fake_depscan(dir.path()).unwrap();
        assert_eq!(path, dir.path().join("depscan"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), FAKE_DEPSCAN);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o755);
    }

    #[test]
    fn the_scenarios_have_distinct_names_and_say_what_they_play() {
        let suite = suite();
        let mut names: Vec<&str> = suite.iter().map(|s| s.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), suite.len());
        assert!(suite.iter().all(|s| !s.plays.is_empty() && !s.lead.is_empty()));
    }

    #[test]
    fn the_table_has_a_row_per_outcome_under_the_cards_headings() {
        let outcomes = [
            Outcome {
                scenario: "direct".into(),
                end: TurnEndReason::Finished,
                solved: true,
                sessions: 2,
                lead: card(6, Some(6), 6, 0, (1, 0), 0, (1, 0), 0),
                mission: card(8, Some(6), 8, 0, (1, 0), 0, (1, 0), 0),
            },
            Outcome {
                scenario: "gives_up".into(),
                end: TurnEndReason::BudgetExhausted,
                solved: false,
                sessions: 1,
                lead: card(5, None, 12, 3, (0, 0), 0, (0, 0), 0),
                mission: card(5, None, 12, 3, (0, 0), 0, (0, 0), 0),
            },
        ];
        let expected = "\
scenario  end               solved  sessions  steps  to finish  calls  malformed  finish refused  quote refused  verifier  fresh starts  hand offs  asks
direct    finished          yes     2         8      6          8      0 (0%)     0 of 1          0              1 of 1    0             0          0
gives_up  budget_exhausted  no      1         5      -          12     3 (25%)    0 of 0          0              -         0             0          0
";
        assert_eq!(table(&outcomes), expected);
        assert_eq!(table(&[]).lines().count(), 1, "the header alone");
    }
}
