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
    pub creds: OnceLock<Arc<ferret_net::Inject>>,
    /// Named credential profiles mounted for multi-principal HTTP testing (`as_profile`, `http_authz_matrix`).
    pub creds_profiles: OnceLock<BTreeMap<String, Arc<ferret_net::Inject>>>,
    /// Name of the default credential profile when `creds` is mounted (e.g. `"user_a"`).
    pub default_profile: OnceLock<String>,
    /// The mission id owning this session (used by mission-scoped tools such as OAST).
    pub mission_id: OnceLock<String>,
    /// Optional OAST callback broker mounted for blind out-of-band testing (`oast_mint`, `oast_poll`).
    pub oast: OnceLock<Arc<crate::oast::OastBroker>>,
    /// The session secret set (S5), set by the runtime with `creds`; unset = nothing to redact.
    pub secrets: OnceLock<Arc<ferret_core::creds::Secrets>>,
    /// The proxy URL with the session's tool credential (S9), set by the runtime; unset = the command proxy
    /// from `ToolCtx::env` (tests and callers without a runtime).
    pub tool_proxy: OnceLock<String>,
    /// The mission target's `upstream_insecure` list (CONTRACTS-TRAFFIC-TARGETS S12), set by the runtime for a
    /// session with a target; unset = every certificate is verified.
    pub upstream_insecure: OnceLock<Vec<String>>,
    /// The mission target's scope, set with `upstream_insecure`; only used to word a certificate failure (S13).
    pub target_scope: OnceLock<ferret_core::target::Scope>,
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
            creds_profiles: OnceLock::new(),
            default_profile: OnceLock::new(),
            mission_id: OnceLock::new(),
            oast: OnceLock::new(),
            secrets: OnceLock::new(),
            tool_proxy: OnceLock::new(),
            upstream_insecure: OnceLock::new(),
            target_scope: OnceLock::new(),
        }
    }

    /// Sorted names of all mounted credential profiles (excluding `"anon"`).
    pub fn mounted_profile_names(&self) -> Vec<String> {
        if let Some(map) = self.creds_profiles.get() {
            let mut names: Vec<String> =
                map.keys().filter(|k| !k.is_empty() && k.as_str() != "anon").cloned().collect();
            names.sort();
            names.dedup();
            return names;
        }
        if self.creds.get().is_some() {
            let name = self
                .default_profile
                .get()
                .map(String::as_str)
                .filter(|s| !s.is_empty() && *s != "anon")
                .unwrap_or("default");
            return vec![name.to_string()];
        }
        Vec::new()
    }

    /// Resolve which credential profile to inject and its canonical principal label (`"anon"` or
    /// `"profile:<name>"`).
    ///
    /// - `strip_auth == true` or `as_profile == Some("anon")` -> `(None, "anon")`
    /// - `as_profile == Some(name)` -> lookup in `creds_profiles` (or legacy default `creds` if
    ///   `creds_profiles` is unset and `name` matches `default_profile` / `"default"`), otherwise an
    ///   error naming all mounted profiles.
    /// - `as_profile == None` -> default `creds` + `default_profile` if mounted (`profile:<name>` or
    ///   `profile:default`), else `(None, "anon")`.
    pub fn resolve_profile(
        &self,
        as_profile: Option<&str>,
        strip_auth: bool,
    ) -> Result<(Option<Arc<ferret_net::Inject>>, String), String> {
        let requested = as_profile.map(str::trim).filter(|s| !s.is_empty());
        if strip_auth || requested == Some("anon") {
            return Ok((None, "anon".into()));
        }
        if let Some(name) = requested {
            if let Some(map) = self.creds_profiles.get() {
                if let Some(inject) = map.get(name) {
                    return Ok((Some(inject.clone()), format!("profile:{name}")));
                }
            } else if let Some(inject) = self.creds.get() {
                let default_name =
                    self.default_profile.get().map(String::as_str).filter(|s| !s.is_empty()).unwrap_or("default");
                if name == default_name {
                    return Ok((Some(inject.clone()), format!("profile:{name}")));
                }
            }
            let mounted = self.mounted_profile_names();
            return if mounted.is_empty() {
                Err(format!(
                    "Unknown credential profile `{name}`: no credential profiles are mounted in this session (only `anon` is available)."
                ))
            } else {
                Err(format!("Unknown credential profile `{name}`. Available profiles: anon, {}.", mounted.join(", ")))
            };
        }
        let default_name =
            self.default_profile.get().map(String::as_str).filter(|s| !s.is_empty()).unwrap_or("default");
        let default_inject = self
            .creds
            .get()
            .cloned()
            .or_else(|| self.default_profile.get().and_then(|d| self.creds_profiles.get()?.get(d).cloned()));
        match default_inject {
            Some(inject) => Ok((Some(inject), format!("profile:{default_name}"))),
            None => Ok((None, "anon".into())),
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

    #[test]
    fn resolve_profile_handles_multi_principal_anon_strip_and_legacy_creds() {
        use ferret_core::creds::{Item, ItemKind};
        let make_inject = |tok: &str| {
            Arc::new(ferret_net::Inject::new(vec![Item {
                kind: ItemKind::Header,
                name: "Authorization".into(),
                value: format!("Bearer {tok}"),
                host: "api.test".into(),
            }]))
        };

        // Unmounted session resolves default & anon to (None, "anon") and rejects named profiles.
        let empty = SessionTools::default();
        assert_eq!(empty.mounted_profile_names(), Vec::<String>::new());
        let (inj, tag) = empty.resolve_profile(None, false).unwrap();
        assert!(inj.is_none() && tag == "anon");
        let (inj, tag) = empty.resolve_profile(Some("anon"), false).unwrap();
        assert!(inj.is_none() && tag == "anon");
        let err = empty.resolve_profile(Some("admin"), false).unwrap_err();
        assert!(err.contains("no credential profiles"), "{err}");

        // Legacy single-profile session (`creds` only).
        let legacy = SessionTools::default();
        legacy.creds.set(make_inject("legacy-tok")).unwrap();
        assert_eq!(legacy.mounted_profile_names(), vec!["default".to_string()]);
        let (inj, tag) = legacy.resolve_profile(None, false).unwrap();
        assert!(inj.is_some() && tag == "profile:default");
        let (inj, tag) = legacy.resolve_profile(None, true).unwrap();
        assert!(inj.is_none() && tag == "anon");

        // Multi-principal session with `creds_profiles` + `default_profile`.
        let multi = SessionTools::default();
        let user_a = make_inject("tok-a");
        let user_b = make_inject("tok-b");
        multi.creds.set(user_a.clone()).unwrap();
        multi.default_profile.set("user_a".into()).unwrap();
        multi.creds_profiles.set(BTreeMap::from([("user_a".into(), user_a), ("user_b".into(), user_b)])).unwrap();
        assert_eq!(multi.mounted_profile_names(), vec!["user_a".to_string(), "user_b".to_string()]);

        let (inj, tag) = multi.resolve_profile(None, false).unwrap();
        assert_eq!(tag, "profile:user_a");
        assert_eq!(inj.unwrap().items()[0].value, "Bearer tok-a");

        let (inj, tag) = multi.resolve_profile(Some("user_b"), false).unwrap();
        assert_eq!(tag, "profile:user_b");
        assert_eq!(inj.unwrap().items()[0].value, "Bearer tok-b");

        let (inj, tag) = multi.resolve_profile(Some("anon"), false).unwrap();
        assert!(inj.is_none() && tag == "anon");

        let (inj, tag) = multi.resolve_profile(Some("user_b"), true).unwrap();
        assert!(inj.is_none() && tag == "anon");

        let err = multi.resolve_profile(Some("ghost"), false).unwrap_err();
        assert!(err.contains("ghost") && err.contains("user_a") && err.contains("user_b"), "{err}");
    }
}
