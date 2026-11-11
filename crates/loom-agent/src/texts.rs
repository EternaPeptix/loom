//! Everything the step loop itself says to the model, in one place.
//!
//! These texts are part of the harness's behaviour: a small model does what the nearest clear
//! instruction says, so each one names what happened and the next action, and none of them mentions
//! context size or elapsed time as something to worry about. This file is complete.

use loom_core::event::ChildOutcome;

/// Longest excerpt of a model reply quoted back in a harness text.
pub const REPLY_EXCERPT_CHARS: usize = 2_000;
/// Lines of a finished background job's output shown in its arrival note.
pub const JOB_TAIL_LINES: u64 = 20;
/// Characters kept of each of those lines.
pub const JOB_TAIL_LINE_CHARS: usize = 400;
/// Steps a child gets after its budget is used up, to deliver what it has.
pub const BUDGET_GRACE_STEPS: u32 = 2;
/// Most output tokens of a digest request (reasoning included).
pub const DIGEST_MAX_TOKENS: u64 = 8_000;
/// Most output tokens of one `decide` vote (reasoning included).
pub const VOTE_MAX_TOKENS: u64 = 6_000;

/// `s` cut to `max` characters; when cut, `…[+N chars]` is appended.
pub fn cut(s: &str, max: usize) -> String {
    let total = s.chars().count();
    if total <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max).collect();
    format!("{kept}…[+{} chars]", total.saturating_sub(max))
}

/// The reply reached the output limit. `dropped_call` names the tool whose call was cut off, if any;
/// `ran` is how many complete calls of the same reply were run.
pub fn output_cut(completion_tokens: u64, dropped_call: Option<&str>, ran: usize) -> String {
    let mut out = format!("Your reply reached the output limit ({completion_tokens} tokens) and was cut off there.");
    match (dropped_call, ran) {
        (Some(name), 0) => out.push_str(&format!(
            " The `{name}` call it ended with was incomplete and did not run."
        )),
        (Some(name), n) => out.push_str(&format!(
            " The {n} complete tool call{} before it ran; the `{name}` call it ended with was incomplete and did not run.",
            if n == 1 { "" } else { "s" }
        )),
        (None, 0) => {}
        (None, n) => out.push_str(&format!(" Its {n} tool call{} ran.", if n == 1 { "" } else { "s" })),
    }
    out.push_str(
        " Make the call again in a shorter form: write long content to a file in several `write`/`edit` calls rather than in one, and keep explanations out of the reply.",
    );
    out
}

/// Result text for a call that was not run because an earlier call of the same reply ended the turn.
pub fn not_run_after(ender: &str) -> String {
    format!("Not run: `{ender}` came first in the same reply and ended the turn. If this call is still needed, make it in a later turn.")
}

/// Result text for a call to a tool the session's role may not use (forked children share their
/// parent's tool list in the request).
pub fn not_in_assignment(name: &str, role: &str, allowed: &[String]) -> String {
    format!(
        "`{name}` is not available in this assignment (role `{role}`). Nothing was executed. Available here: {}.",
        allowed.join(", ")
    )
}

/// `Interrupted::reason` when the operator stopped the session.
pub const REASON_OPERATOR: &str = "stopped by the operator";
/// `Interrupted::reason` when the harness process went away in the middle of a turn.
pub const REASON_RESTART: &str = "the harness was restarted";
/// `Interrupted::reason` when the agent that assigned the work stopped it.
pub const REASON_PARENT: &str = "stopped by the agent that assigned this work";

/// A stretch of steps that recorded nothing and changed nothing.
pub fn stall(steps: u32) -> String {
    format!(
        "The last {steps} steps recorded nothing in the ledger and changed no file. If you have learned something, record it now (`note`, or `claim` with `evidence`). If the current approach is not getting anywhere, record it as a dead end with `note` and take a different one. If you cannot continue, call `report_blocker`."
    )
}

/// A message from the parent agent to a running child.
pub fn agent_message(text: &str) -> String {
    format!("Message from the agent that assigned this work:\n{text}")
}

/// A standing rule from the operator. `id` is its ledger id when the mission has a ledger.
pub fn constraint(id: Option<&str>, text: &str) -> String {
    let id = id.map(|i| format!(" ({i})")).unwrap_or_default();
    format!(
        "The operator set a standing rule{id}. It applies to all work on this mission, yours and that of every agent you assign work to, until the operator withdraws it. Where it conflicts with an earlier instruction, the rule wins:\n{}",
        text.trim()
    )
}

/// The operator withdrew a standing rule.
pub fn constraint_withdrawn(id: &str, reason: &str) -> String {
    let reason = reason.trim();
    if reason.is_empty() {
        format!("The operator withdrew rule {id}. It no longer applies.")
    } else {
        format!("The operator withdrew rule {id}. It no longer applies. Reason: {}", sentence(reason))
    }
}

/// An approval from the operator. `id` is its ledger id when the mission has a ledger.
pub fn approval(id: Option<&str>, text: &str, scope: &str) -> String {
    let id = id.map(|i| format!(" ({i})")).unwrap_or_default();
    let scope = scope.trim();
    let covers = if scope.is_empty() {
        "It covers what is written here and nothing beyond it.".to_string()
    } else {
        format!("It covers what is written here, within this scope and nothing beyond it: {}", sentence(scope))
    };
    format!(
        "The operator gave an approval{id}. {covers} For anything it does not clearly cover, ask with `ask_user` rather than assume:\n{}",
        text.trim()
    )
}

/// The model server could not take the request even after folding (`why` is a complete sentence).
pub const OVERFLOW_UNFOLDABLE: &str = "The request no longer fits the model's context window and nothing more can be folded out of view.";

/// `s` as a sentence: trimmed, with a full stop added when it does not end in `.`, `!` or `?`.
pub fn sentence(s: &str) -> String {
    let s = s.trim();
    if s.ends_with('.') || s.ends_with('!') || s.ends_with('?') || s.is_empty() {
        s.to_string()
    } else {
        format!("{s}.")
    }
}

/// Note at the start of the turn that follows a harness restart.
pub const AFTER_RESTART: &str = "The harness was restarted while you were working. A call shown with no recorded result may or may not have taken effect: check the state of things before repeating it. Background jobs and agents from before the restart are gone; start them again if their results are still needed. Then carry on with the work.";

/// Note at the start of the turn after the operator pressed stop and then resumed.
pub const AFTER_STOP: &str = "The operator stopped the previous turn and has now resumed it. A call shown with no recorded result was interrupted: check the state of things before repeating it. Background jobs and agents from before the stop were ended. Carry on with the work.";

/// A background job ended while the session was doing something else (or waiting).
pub fn job_arrival(id: &str, command: &str, outcome: &str, detail: &str, handle: Option<&str>, lines: u64, tail: &str) -> String {
    let mut out = format!("Background job {id} ended: {outcome}.");
    if !detail.trim().is_empty() {
        out.push_str(&format!(" {}", detail.trim()));
    }
    out.push_str(&format!("\nCommand: {}", cut(command, 300)));
    match handle {
        Some(h) if lines > 0 => {
            out.push_str(&format!("\nIts complete output is stored as {h} ({lines} lines)."));
            if !tail.is_empty() {
                let shown = lines.min(JOB_TAIL_LINES);
                out.push_str(&format!(" The last {shown} line{}:\n{tail}", if shown == 1 { "" } else { "s" }));
            }
        }
        Some(_) => out.push_str("\nIt produced no output."),
        None => out.push_str("\nIts output could not be stored."),
    }
    out
}

/// Text recorded as a user message when the operator answers an inbox item.
pub fn inbox_answer(item_text: &str, answer: &str) -> String {
    format!("[The operator's answer to: {}]\n{answer}", cut(&one_line(item_text), 240))
}

/// The assignment's budget is used up; the child gets [`BUDGET_GRACE_STEPS`] more steps.
pub fn budget_reached(steps: u32, minutes: u64, can_finish: bool) -> String {
    let deliver = if can_finish {
        "Call `finish` now: give what you established, with quotes of the output that shows it, and say in `not_established` what you did not get to."
    } else {
        "Deliver your result now with the tool your role ends with, covering what you established and what you did not get to."
    };
    format!(
        "The budget for this assignment is used up ({steps} steps, {minutes} min). {deliver} You have {BUDGET_GRACE_STEPS} more steps; after that the assignment ends without a result."
    )
}

/// Report delivered to the parent for a child that used its budget without delivering.
pub fn budget_exhausted_report(steps: u32, minutes: u64, last_reply: &str) -> String {
    let mut out = format!(
        "The agent used its whole budget ({steps} steps, {minutes} min) and did not deliver a result. Nothing below is verified."
    );
    append_last_reply(&mut out, last_reply);
    out
}

/// Report delivered to the parent for a child that kept ending its replies without delivering.
pub fn gave_up_report(nudges: u32, last_reply: &str) -> String {
    let mut out = format!(
        "The agent stopped without delivering a result, after {nudges} reminders to do so. Nothing below is verified."
    );
    append_last_reply(&mut out, last_reply);
    out
}

/// Report delivered to the parent for a child that was stopped.
pub fn stopped_report(steps: u32) -> String {
    format!("The agent was stopped after {steps} steps and delivered no result.")
}

/// Report delivered to the parent for a child whose session failed (`why` is a complete sentence).
pub fn failed_report(why: &str, last_reply: &str) -> String {
    let mut out = format!("The agent's session failed and delivered no result. {why}");
    append_last_reply(&mut out, last_reply);
    out
}

fn append_last_reply(out: &mut String, last_reply: &str) {
    if last_reply.trim().is_empty() {
        out.push_str("\nIt wrote no message.");
    } else {
        out.push_str(&format!("\nIts last message:\n{}", cut(last_reply.trim(), REPLY_EXCERPT_CHARS)));
    }
}

/// The `brief` of a re-weave: what the model is told at the point where older material was folded.
/// `ledger_brief` is `LedgerState::brief`, empty for a session without a ledger.
pub fn reweave_brief(ledger_brief: &str) -> String {
    let mut out = String::from(
        "Older tool output above this point is now shown in shortened form. Nothing was deleted: each shortened result names its handle (out:…), `out_read` and `out_grep` open any part of it again, and `log_search` searches the whole session. If you need something you saw earlier, reopen it rather than working from memory.",
    );
    if !ledger_brief.trim().is_empty() {
        out.push_str("\n\nThe mission ledger at this point:\n");
        out.push_str(ledger_brief.trim_end());
    }
    out
}

/// The instruction of a digest request, sent after the session's current stable prefix.
pub const DIGEST_PROMPT: &str = "Some of your own earlier messages in this session are about to be folded out of view (tool output stays reachable through its handles, and the mission ledger stays as it is). Write down, for yourself, what you would otherwise lose: leads you have not followed up, partial results that are not yet in the ledger, where things are (files, lines, commands, handles), and anything you decided to try next and why. Be specific and brief: a list, at most 600 words. Do not call tools and do not address anyone; this is a note to yourself.";

/// Inbox text for a session the harness could not continue (`why` is a complete sentence).
pub fn turn_failed(why: &str) -> String {
    format!("The session could not continue. {why} Nothing was lost: answer here, or send the session a message, to make it try again.")
}

/// The question put to each `decide` voter, after the session's stable prefix.
pub fn vote_prompt(question: &str, options: &[String]) -> String {
    let mut out = format!(
        "Pause the work for one question. You are one of several independent copies being asked the same thing; answer for yourself from what you have seen so far. Do not call tools.\n\nQuestion: {question}\n\nOptions:\n"
    );
    for (i, o) in options.iter().enumerate() {
        out.push_str(&format!("{}. {o}\n", i.saturating_add(1)));
    }
    out.push_str(&format!(
        "\nReply in exactly this form:\nOPTION: <a number from 1 to {}>\nREASON: <one paragraph: the evidence you have seen that decides it>",
        options.len()
    ));
    out
}

/// Read a voter's reply: the option number (when it names exactly one valid option) and the reason.
pub fn parse_vote(reply: &str, n_options: usize) -> (Option<usize>, String) {
    let mut option = None;
    let mut reason = String::new();
    let mut in_reason = false;
    for line in reply.lines() {
        let trimmed = line.trim();
        let upper = trimmed.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("OPTION:") {
            in_reason = false;
            if option.is_none() {
                let digits: String = rest.trim().chars().take_while(char::is_ascii_digit).collect();
                option = digits.parse::<usize>().ok().filter(|n| (1..=n_options).contains(n));
            }
        } else if upper.starts_with("REASON:") {
            in_reason = true;
            reason = trimmed.chars().skip("REASON:".len()).collect::<String>().trim().to_string();
        } else if in_reason && !trimmed.is_empty() {
            if !reason.is_empty() {
                reason.push(' ');
            }
            reason.push_str(trimmed);
        }
    }
    if reason.is_empty() {
        reason = one_line(reply);
    }
    (option, reason)
}

/// How a child's outcome is written in text (`returned`, `budget_exhausted`, …).
pub fn outcome_word(outcome: ChildOutcome) -> &'static str {
    match outcome {
        ChildOutcome::Returned => "returned",
        ChildOutcome::Blocked => "blocked",
        ChildOutcome::BudgetExhausted => "budget_exhausted",
        ChildOutcome::Stopped => "stopped",
        ChildOutcome::Failed => "failed",
    }
}

/// `s` with every run of whitespace (including line breaks) collapsed to one space.
pub fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The first part of a forked agent's assignment. A fork starts with a copy of its parent's context,
/// system prompt included, so this states what is different from here on. The brief follows it.
pub fn fork_contract(role: &str, role_prompt: &str, tools: &[String]) -> String {
    format!(
        "You are now a separate agent. Everything above this message is the context of the agent that assigned you this work, copied so that you start with what it knows. You are not that agent: its role, its plan and its unfinished work are not yours, and it carries on separately. From this message on your role is `{role}`. It replaces the role described at the start of this context.\n\n{}\n\nTools you may call in this role: {}. A call to any other tool is refused.\n\nYour assignment follows.",
        role_prompt.trim(),
        tools.iter().map(|t| format!("`{t}`")).collect::<Vec<_>>().join(", ")
    )
}

/// The sentence of the system prompt that states the network policy. `mode` is `open`, `allowlist`
/// or `deny_all`.
pub fn network_sentence(mode: &str, allow: &[String], deny: &[String], allow_private: &[String]) -> String {
    let list = |v: &[String]| v.join(", ");
    let mut s = match mode {
        "deny_all" => return "There is no network access.".to_string(),
        "allowlist" => {
            if allow.is_empty() {
                return "There is no network access.".to_string();
            }
            format!(
                "Only these hosts can be reached, through the harness's proxy (already set in the environment of commands): {}. Everything else is refused.",
                list(allow)
            )
        }
        _ => {
            let private = if allow_private.is_empty() {
                "Addresses on private and local networks are refused.".to_string()
            } else {
                format!("Addresses on private and local networks are refused, except: {}.", list(allow_private))
            };
            format!(
                "Commands and `web_fetch` reach the internet through the harness's proxy (already set in the environment of commands). {private}"
            )
        }
    };
    if !deny.is_empty() {
        s.push_str(&format!(" Refused in every case: {}.", list(deny)));
    }
    s
}

/// A background job that was running when the harness went down.
pub fn job_lost(id: &str, command: &str) -> String {
    format!(
        "Background job {id} (`{}`) was running when the harness was restarted. It is no longer tracked: its outcome is unknown and it may have been cut off. Check what it left behind before relying on it, and start it again if it is still needed.",
        cut(&one_line(command), 120)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_counts_characters() {
        assert_eq!(cut("héllo", 5), "héllo");
        assert_eq!(cut("héllo wörld", 4), "héll…[+7 chars]");
    }

    #[test]
    fn output_cut_names_what_ran() {
        let a = output_cut(4096, None, 0);
        assert!(a.starts_with("Your reply reached the output limit (4096 tokens)"));
        assert!(!a.contains("did not run"));
        let b = output_cut(100, Some("write"), 0);
        assert!(b.contains("The `write` call it ended with was incomplete and did not run."));
        let c = output_cut(100, Some("write"), 2);
        assert!(c.contains("The 2 complete tool calls before it ran; the `write` call"));
        let d = output_cut(100, None, 1);
        assert!(d.contains("Its 1 tool call ran."));
    }

    #[test]
    fn job_arrival_forms() {
        let a = job_arrival("j1", "make test", "exit 2", "", Some("out:abc"), 120, "last line");
        assert!(a.starts_with("Background job j1 ended: exit 2.\nCommand: make test\n"));
        assert!(a.contains("stored as out:abc (120 lines). The last 20 lines:\nlast line"));
        let b = job_arrival("j2", "true", "exit 0", "", Some("out:abc"), 0, "");
        assert!(b.ends_with("It produced no output."));
        let c = job_arrival("j3", "yes", "killed", "output limit reached", None, 0, "");
        assert!(c.contains("ended: killed. output limit reached"));
        assert!(c.ends_with("Its output could not be stored."));
        let d = job_arrival("j4", "echo hi", "exit 0", "", Some("out:abc"), 1, "hi");
        assert!(d.contains("The last 1 line:\nhi"));
    }

    #[test]
    fn budget_and_reports() {
        assert!(budget_reached(40, 12, true).contains("Call `finish` now"));
        assert!(budget_reached(40, 12, false).contains("the tool your role ends with"));
        assert!(budget_exhausted_report(40, 12, "").ends_with("It wrote no message."));
        assert!(gave_up_report(3, "I think it is fine").ends_with("Its last message:\nI think it is fine"));
        assert!(failed_report("The model server refused the request.", " x ").contains("refused the request.\nIts last message:\nx"));
        assert_eq!(stopped_report(4), "The agent was stopped after 4 steps and delivered no result.");
    }

    #[test]
    fn reweave_brief_with_and_without_ledger() {
        assert!(!reweave_brief("").contains("mission ledger"));
        let b = reweave_brief("Goal: ship it\n");
        assert!(b.ends_with("The mission ledger at this point:\nGoal: ship it"));
    }

    #[test]
    fn votes_parse() {
        let opts = vec!["left".to_string(), "right".to_string()];
        let p = vote_prompt("which way?", &opts);
        assert!(p.contains("1. left\n2. right\n"));
        assert!(p.contains("a number from 1 to 2"));
        assert_eq!(parse_vote("OPTION: 2\nREASON: the log shows\nit on the right", 2), (Some(2), "the log shows it on the right".into()));
        assert_eq!(parse_vote("option: 1.\nreason: because", 2), (Some(1), "because".into()));
        assert_eq!(parse_vote("OPTION: 7\nREASON: x", 2), (None, "x".into()));
        assert_eq!(parse_vote("I would go left,\nprobably", 2), (None, "I would go left, probably".into()));
        assert_eq!(parse_vote("OPTION: 1\nOPTION: 2\nREASON: first wins", 2).0, Some(1));
    }

    #[test]
    fn fork_contract_and_network() {
        let c = fork_contract("worker", "# Your role: worker\n\nDo it.\n", &["bash".to_string(), "finish".to_string()]);
        assert!(c.contains("your role is `worker`"));
        assert!(c.contains("# Your role: worker\n\nDo it.\n\nTools you may call in this role: `bash`, `finish`."));
        assert!(c.ends_with("Your assignment follows."));
        assert_eq!(network_sentence("deny_all", &[], &[], &[]), "There is no network access.");
        assert_eq!(network_sentence("allowlist", &[], &[], &[]), "There is no network access.");
        let a = network_sentence("allowlist", &["pypi.org".to_string()], &["evil.example".to_string()], &[]);
        assert!(a.contains("pypi.org") && a.ends_with("Refused in every case: evil.example."));
        let o = network_sentence("open", &[], &[], &["192.168.0.0/24".to_string()]);
        assert!(o.contains("except: 192.168.0.0/24."));
        assert!(network_sentence("open", &[], &[], &[]).ends_with("local networks are refused."));
        assert!(job_lost("j3", "make   test").contains("job j3 (`make test`)"));
    }

    #[test]
    fn sentences_and_stall() {
        assert_eq!(sentence(" no route to host "), "no route to host.");
        assert_eq!(sentence("Refused."), "Refused.");
        assert_eq!(sentence(""), "");
        assert!(stall(30).starts_with("The last 30 steps recorded nothing"));
        assert_eq!(agent_message("stop at 3"), "Message from the agent that assigned this work:\nstop at 3");
    }

    #[test]
    fn answers_and_words() {
        assert_eq!(inbox_answer("Which\nbranch?", "main"), "[The operator's answer to: Which branch?]\nmain");
        assert_eq!(outcome_word(ChildOutcome::BudgetExhausted), "budget_exhausted");
        assert_eq!(not_in_assignment("write", "verifier", &["read".into(), "grep".into()]),
            "`write` is not available in this assignment (role `verifier`). Nothing was executed. Available here: read, grep.");
    }
}
