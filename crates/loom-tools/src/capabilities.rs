//! Session-local execution state and process-wide target admission.
//!
//! CONTRACT: state is shared by calls of one session, never inherited by a child or restored on
//! restart. Two HTTP exchanges at most may be in flight to the same normalized host in this daemon,
//! across sessions. Acquisition is cancellation safe. This bounds structured HTTP, not arbitrary shell
//! network traffic. `command_guard` normalizes up to three rounds of percent-encoding before checking
//! known interactive or unbounded command patterns; it is an execution-hygiene check, not a sandbox
//! boundary.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

pub struct SessionTools {
    pub http: tokio::sync::Mutex<crate::http::HttpState>,
    pub ptys: crate::pty::PtyTable,
    pub command_guard: bool,
    pub target_concurrency: u32,
    pub binary_cache: Mutex<BTreeMap<String, Vec<u8>>>,
    pub oracle_contract: crate::oracle::ContractCache,
    /// Finds a recorded exchange of this session by its `ex-` id, from the session log (set by the runtime).
    pub exchange_lookup: OnceLock<Arc<crate::traffic::ExchangeLookup>>,
    /// The credential profile items the session attaches to its in-scope requests (CONTRACTS-TRAFFIC-TARGETS
    /// S8), set by the runtime before the first call; unset = none.
    pub creds: OnceLock<Arc<loom_net::Inject>>,
    /// The session secret set (S5), set by the runtime with `creds`; unset = nothing to redact.
    pub secrets: OnceLock<Arc<loom_core::creds::Secrets>>,
    /// The proxy URL with the session's tool credential (S9), set by the runtime; unset = the command proxy
    /// from `ToolCtx::env` (tests and callers without a runtime).
    pub tool_proxy: OnceLock<String>,
    /// The mission target's `upstream_insecure` list (CONTRACTS-TRAFFIC-TARGETS S12), set by the runtime for a
    /// session with a target; unset = every certificate is verified.
    pub upstream_insecure: OnceLock<Vec<String>>,
    /// The mission target's scope, set with `upstream_insecure`; only used to word a certificate failure (S13).
    pub target_scope: OnceLock<loom_core::target::Scope>,
}

impl Default for SessionTools {
    fn default() -> Self {
        Self::new(false, 2)
    }
}

impl SessionTools {
    pub fn new(command_guard: bool, target_concurrency: u32) -> Self {
        Self {
            http: tokio::sync::Mutex::new(crate::http::HttpState::default()),
            ptys: crate::pty::PtyTable::default(),
            command_guard,
            target_concurrency: target_concurrency.clamp(1, 2),
            binary_cache: Mutex::new(BTreeMap::new()),
            oracle_contract: crate::oracle::ContractCache::default(),
            exchange_lookup: OnceLock::new(),
            creds: OnceLock::new(),
            secrets: OnceLock::new(),
            tool_proxy: OnceLock::new(),
            upstream_insecure: OnceLock::new(),
            target_scope: OnceLock::new(),
        }
    }
}

type Hosts = Mutex<BTreeMap<String, Arc<Semaphore>>>;
static HOSTS: OnceLock<Hosts> = OnceLock::new();

pub async fn target_permit(host: &str, cancel: &CancellationToken) -> Result<OwnedSemaphorePermit, String> {
    let sem = {
        let mut hosts = HOSTS.get_or_init(Hosts::default).lock().unwrap_or_else(|p| p.into_inner());
        // Keep the registry bounded. Retain entries with an acquisition or waiter holding a clone.
        if hosts.len() >= 4096 {
            hosts.retain(|_, sem| Arc::strong_count(sem) > 1);
        }
        if hosts.len() >= 4096 && !hosts.contains_key(host) {
            return Err("Target admission is at its host limit. Wait for existing requests to finish.".into());
        }
        hosts
            .entry(host.trim_end_matches('.').to_ascii_lowercase())
            .or_insert_with(|| Arc::new(Semaphore::new(2)))
            .clone()
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err("The request was cancelled while waiting for its target slot.".into()),
        r = sem.acquire_owned() => r.map_err(|_| "Target admission closed; try again after the daemon restarts.".into()),
    }
}

pub(crate) fn decode_percent_rounds(input: &str, rounds: usize) -> String {
    let mut current = input.to_string();
    for _ in 0..rounds {
        let bytes = current.as_bytes();
        let mut out = Vec::with_capacity(bytes.len().min(65_536));
        let mut i = 0usize;
        while let Some(&b) = bytes.get(i) {
            if out.len() >= 65_536 {
                break;
            }
            if b == b'%' {
                if let (Some(&hi), Some(&lo)) = (bytes.get(i.saturating_add(1)), bytes.get(i.saturating_add(2))) {
                    let hex_val = |c: u8| match c {
                        b'0'..=b'9' => Some(c - b'0'),
                        b'a'..=b'f' => Some(c - b'a' + 10),
                        b'A'..=b'F' => Some(c - b'A' + 10),
                        _ => None,
                    };
                    if let (Some(h), Some(l)) = (hex_val(hi), hex_val(lo)) {
                        out.push((h << 4) | l);
                        i = i.saturating_add(3);
                        continue;
                    }
                }
            }
            out.push(b);
            i = i.saturating_add(1);
        }
        let next = String::from_utf8_lossy(&out).into_owned();
        if next == current {
            break;
        }
        current = next;
    }
    current
}

pub fn guard_script(script: &str) -> Result<(), String> {
    let raw_tokens =
        shlex::split(script).ok_or("The command has unbalanced shell quoting. Correct it before running.")?;
    let decoded = decode_percent_rounds(script, 3);
    let tokens: Vec<String> = raw_tokens.iter().map(|t| decode_percent_rounds(t, 3)).collect();
    let matches_word = |t: &str, word: &str| t == word || t.rsplit('/').next() == Some(word);
    let has =
        |word: &str| raw_tokens.iter().any(|t| matches_word(t, word)) || tokens.iter().any(|t| matches_word(t, word));
    let blocked = if script.contains("/dev/tcp/") || decoded.to_ascii_lowercase().contains("/dev/tcp/") {
        Some("Use a bounded HTTP request or an explicit socket timeout instead of /dev/tcp.")
    } else if has("tail") && (has("-f") || has("--follow")) {
        Some("Use a bounded tail call without follow mode.")
    } else if has("sqlmap") && !has("--batch") {
        Some("Pass --batch and an explicit time budget to sqlmap.")
    } else if has("msfconsole") && !has("-x") {
        Some("Use pty_open for an interactive console, or pass msfconsole -x with a bounded script.")
    } else if ["hydra", "ffuf", "gobuster", "nxc"].iter().any(|t| has(t))
        && (script.to_ascii_lowercase().contains("rockyou") || decoded.to_ascii_lowercase().contains("rockyou"))
    {
        Some("Use a small explicit wordlist and a time/rate limit instead of an online rockyou run.")
    } else if has("hashcat")
        && !tokens.iter().enumerate().any(|(i, t)| {
            let value = t
                .strip_prefix("--runtime=")
                .or_else(|| (t == "--runtime").then(|| tokens.get(i.saturating_add(1)).map(String::as_str)).flatten());
            value.and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| (1..=300).contains(&n))
        })
    {
        Some("Pass hashcat --runtime with a value from 1 to 300 seconds.")
    } else {
        None
    };
    match blocked {
        Some(next) => Err(format!(
            "Command guard blocked an interactive or unbounded pattern. {next} This guard does not replace the sandbox or scope policy."
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guards_known_unbounded_patterns() {
        for s in [
            "sqlmap -u https://target",
            "hashcat hashes",
            "cat </dev/tcp/host/80",
            "hydra -P rockyou.txt host ssh",
            "hydra -P %72%6f%63%6b%79%6f%75.txt host ssh",
            "hydra -P %252572ockyou.txt host ssh",
            "python3 -c 'open(\"%252fdev%252ftcp%252fhost/80\")'",
            "tail -f log",
        ] {
            assert!(guard_script(s).is_err(), "{s}");
        }
        for s in ["sqlmap --batch -u https://target", "hashcat --runtime=30 hashes", "printf '%s%%20ok' hello"] {
            assert!(guard_script(s).is_ok(), "{s}");
        }
    }
    #[tokio::test]
    async fn admission_is_shared_and_cancellable() {
        let c = CancellationToken::new();
        let _a = target_permit("admission.test", &c).await.unwrap();
        let _b = target_permit("admission.test", &c).await.unwrap();
        c.cancel();
        assert!(target_permit("admission.test", &c).await.is_err());
    }
}
