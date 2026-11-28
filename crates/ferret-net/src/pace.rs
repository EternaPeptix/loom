//! Target egress noise governor: per-host rate limiting, burst, concurrency caps, jitter,
//! and 429/503 backoff, plus code-owned low-and-slow scanner guidance.
//!
//! CONTRACT.
//!
//! - [`NoiseProfileName::Off`] is a strict passthrough: [`Governor::acquire`] returns immediately
//!   without waiting or allocating per-host state, and [`render_noise_profile_prompt`] returns an
//!   empty string so default prompts stay byte-for-byte identical.
//! - Active profiles (`quiet`, `balanced`, `aggressive`) enforce per-host token buckets (`rps`,
//!   `burst`), per-host concurrency (`max_per_host`), global concurrency (`max_global`, acquired
//!   last so a waiting host never holds a global slot), bounded random jitter (`<= MAX_JITTER`),
//!   and per-host backoff on upstream `429`/`503` responses (honoring numeric `Retry-After` up to
//!   `max_backoff`, else exponential `base_backoff`).
//! - Pacing waits are bounded by [`PACE_WAIT_MAX`] (30 s) so a target can never deadlock a command.

use ferret_core::config::NoiseProfileName;
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Maximum jitter added to a single request.
pub const MAX_JITTER: Duration = Duration::from_millis(250);
/// Hard cap on how long pacing delays one request before releasing it.
pub const PACE_WAIT_MAX: Duration = Duration::from_secs(30);

/// Resolved numeric parameters of one noise profile.
#[derive(Clone, Debug, PartialEq)]
pub struct NoiseProfile {
    pub name: NoiseProfileName,
    pub rps: f64,
    pub burst: u32,
    pub max_per_host: usize,
    pub max_global: usize,
    pub jitter: f64,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    pub user_agent: Option<String>,
}

impl NoiseProfile {
    pub fn from_name(name: NoiseProfileName, user_agent: Option<String>) -> Self {
        let ua = if name == NoiseProfileName::Off {
            None
        } else {
            user_agent.map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && !s.chars().any(char::is_control))
        };
        match name {
            NoiseProfileName::Off => Self {
                name,
                rps: 0.0,
                burst: 0,
                max_per_host: 0,
                max_global: 0,
                jitter: 0.0,
                base_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
                user_agent: None,
            },
            NoiseProfileName::Quiet => Self {
                name,
                rps: 2.0,
                burst: 4,
                max_per_host: 1,
                max_global: 8,
                jitter: 0.5,
                base_backoff: Duration::from_secs(2),
                max_backoff: Duration::from_secs(60),
                user_agent: ua,
            },
            NoiseProfileName::Balanced => Self {
                name,
                rps: 5.0,
                burst: 10,
                max_per_host: 2,
                max_global: 16,
                jitter: 0.2,
                base_backoff: Duration::from_secs(1),
                max_backoff: Duration::from_secs(30),
                user_agent: ua,
            },
            NoiseProfileName::Aggressive => Self {
                name,
                rps: 20.0,
                burst: 40,
                max_per_host: 4,
                max_global: 32,
                jitter: 0.1,
                base_backoff: Duration::from_millis(500),
                max_backoff: Duration::from_secs(10),
                user_agent: ua,
            },
        }
    }

    pub fn is_off(&self) -> bool {
        self.name == NoiseProfileName::Off || self.rps <= 0.0
    }
}

/// Per-host observability snapshot returned by [`Governor::snapshot`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostNoise {
    pub host: String,
    pub sent: u64,
    pub inflight: usize,
    pub peak_inflight: usize,
    pub backoffs: u64,
}

struct HostState {
    slots: Arc<Semaphore>,
    tokens: f64,
    last: Instant,
    not_before: Instant,
    backoff_attempt: u32,
    sent: u64,
    inflight: usize,
    peak_inflight: usize,
    backoffs: u64,
}

struct Inner {
    profile: NoiseProfile,
    global: Arc<Semaphore>,
    hosts: Mutex<HashMap<String, Arc<Mutex<HostState>>>>,
}

/// Shared proxy egress rate/concurrency governor.
#[derive(Clone)]
pub struct Governor {
    inner: Arc<Inner>,
}

/// Releases per-host and global concurrency permits when dropped.
pub struct PaceGuard {
    host_state: Arc<Mutex<HostState>>,
    _global_permit: OwnedSemaphorePermit,
    _host_permit: OwnedSemaphorePermit,
}

impl Drop for PaceGuard {
    fn drop(&mut self) {
        let mut h = self.host_state.lock().unwrap_or_else(|p| p.into_inner());
        h.inflight = h.inflight.saturating_sub(1);
    }
}

impl Default for Governor {
    fn default() -> Self {
        Self::new(NoiseProfile::from_name(NoiseProfileName::Off, None))
    }
}

impl Governor {
    pub fn new(profile: NoiseProfile) -> Self {
        let global_n = profile.max_global.max(1);
        Self {
            inner: Arc::new(Inner {
                profile,
                global: Arc::new(Semaphore::new(global_n)),
                hosts: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn is_off(&self) -> bool {
        self.inner.profile.is_off()
    }

    pub fn profile(&self) -> &NoiseProfile {
        &self.inner.profile
    }

    fn host_key(host: &str) -> String {
        crate::inject::norm_host(host)
    }

    fn host_state(&self, key: &str) -> Arc<Mutex<HostState>> {
        let mut map = self.inner.hosts.lock().unwrap_or_else(|p| p.into_inner());
        map.entry(key.to_string())
            .or_insert_with(|| {
                let now = Instant::now();
                Arc::new(Mutex::new(HostState {
                    slots: Arc::new(Semaphore::new(self.inner.profile.max_per_host.max(1))),
                    tokens: f64::from(self.inner.profile.burst.max(1)),
                    last: now,
                    not_before: now,
                    backoff_attempt: 0,
                    sent: 0,
                    inflight: 0,
                    peak_inflight: 0,
                    backoffs: 0,
                }))
            })
            .clone()
    }

    fn jitter(&self) -> Duration {
        let p = &self.inner.profile;
        if p.jitter <= 0.0 || p.rps <= 0.0 {
            return Duration::ZERO;
        }
        let max_d = Duration::from_secs_f64((p.jitter / p.rps).max(0.0)).min(MAX_JITTER);
        let max_ms = max_d.as_millis() as u64;
        if max_ms == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis(rand::rng().random_range(0..=max_ms))
    }

    /// Wait for a host slot, token refill/backoff + jitter, then a global slot.
    /// Returns `None` when the governor is `Off` or when the wait exceeds [`PACE_WAIT_MAX`] / cancels.
    pub async fn acquire(&self, host: &str, cancel: &CancellationToken) -> Option<PaceGuard> {
        if self.is_off() {
            return None;
        }
        let key = Self::host_key(host);
        let hs = self.host_state(&key);
        let host_slots = { hs.lock().unwrap_or_else(|p| p.into_inner()).slots.clone() };

        let deadline = tokio::time::Instant::now() + PACE_WAIT_MAX;
        let host_permit = tokio::select! {
            p = host_slots.acquire_owned() => p.ok()?,
            _ = tokio::time::sleep_until(deadline) => return None,
            _ = cancel.cancelled() => return None,
        };

        let wait = {
            let mut h = hs.lock().unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(h.last).as_secs_f64();
            let burst = f64::from(self.inner.profile.burst.max(1));
            h.tokens = (h.tokens + elapsed * self.inner.profile.rps).min(burst) - 1.0;
            h.last = now;
            let token_wait = if h.tokens < 0.0 {
                Duration::from_secs_f64((-h.tokens) / self.inner.profile.rps)
            } else {
                Duration::ZERO
            };
            let backoff_wait = h.not_before.saturating_duration_since(now);
            token_wait.max(backoff_wait).saturating_add(self.jitter())
        };

        if !wait.is_zero() {
            let until = (tokio::time::Instant::now() + wait).min(deadline);
            tokio::select! {
                _ = tokio::time::sleep_until(until) => {}
                _ = cancel.cancelled() => return None,
            }
        }

        let global_permit = tokio::select! {
            p = self.inner.global.clone().acquire_owned() => p.ok()?,
            _ = tokio::time::sleep_until(deadline) => return None,
            _ = cancel.cancelled() => return None,
        };

        {
            let mut h = hs.lock().unwrap_or_else(|p| p.into_inner());
            h.sent = h.sent.saturating_add(1);
            h.inflight = h.inflight.saturating_add(1);
            h.peak_inflight = h.peak_inflight.max(h.inflight);
        }

        Some(PaceGuard { host_state: hs, _global_permit: global_permit, _host_permit: host_permit })
    }

    /// Record an upstream HTTP status for `host`, updating 429/503 backoff state.
    pub fn note_response(&self, host: &str, status: u16, retry_after: Option<&str>) {
        if self.is_off() {
            return;
        }
        let key = Self::host_key(host);
        let hs = self.host_state(&key);
        let mut h = hs.lock().unwrap_or_else(|p| p.into_inner());
        if status == 429 || status == 503 {
            let p = &self.inner.profile;
            let parsed_ra = retry_after.map(str::trim).and_then(|s| s.parse::<u64>().ok()).map(Duration::from_secs);
            let delay = match parsed_ra {
                Some(d) => d.min(p.max_backoff),
                None => {
                    let shift = h.backoff_attempt.min(10);
                    p.base_backoff.saturating_mul(1u32 << shift).min(p.max_backoff)
                }
            };
            h.backoff_attempt = h.backoff_attempt.saturating_add(1);
            h.backoffs = h.backoffs.saturating_add(1);
            let until = Instant::now() + delay;
            if until > h.not_before {
                h.not_before = until;
            }
        } else if status < 500 {
            h.backoff_attempt = 0;
        }
    }

    /// Sorted per-host activity snapshot.
    pub fn snapshot(&self) -> Vec<HostNoise> {
        let map = self.inner.hosts.lock().unwrap_or_else(|p| p.into_inner());
        let mut out: Vec<HostNoise> = map
            .iter()
            .filter_map(|(host, hs)| {
                let h = hs.lock().unwrap_or_else(|p| p.into_inner());
                (h.sent > 0 || h.inflight > 0 || h.backoffs > 0).then(|| HostNoise {
                    host: host.clone(),
                    sent: h.sent,
                    inflight: h.inflight,
                    peak_inflight: h.peak_inflight,
                    backoffs: h.backoffs,
                })
            })
            .collect();
        out.sort_by(|a, b| a.host.cmp(&b.host));
        out
    }
}

/// Code-owned low-and-slow scanner guidance for non-`Off` noise profiles.
/// Returns `""` when `profile == Off` so default prompts remain byte-identical.
pub fn render_noise_profile_prompt(profile: NoiseProfileName) -> String {
    let p = NoiseProfile::from_name(profile, None);
    if p.is_off() {
        return String::new();
    }
    let rps = (p.rps.round() as u32).max(1);
    let conc = p.max_per_host.max(1);
    let delay_ms = 1000 / rps;
    let delay_sec = format!("{:.2}", 1.0 / f64::from(rps));
    let (timing, retries) = match profile {
        NoiseProfileName::Quiet => ("-T2", "2"),
        NoiseProfileName::Balanced => ("-T3", "2"),
        NoiseProfileName::Aggressive => ("-T4", "1"),
        NoiseProfileName::Off => return String::new(),
    };
    let inflight = if conc == 1 { "1 request".to_string() } else { format!("{conc} requests") };
    format!(
        "[Noise profile: {} — operator setting, not a target fact]\n\
         Stay within the target noise budget. When running CLI scanners, pass these rate flags:\n\
         - nmap: {timing} --max-rate {rps} --max-retries {retries}\n\
         - nuclei: -rate-limit {rps} -c {conc}\n\
         - httpx: -rl {rps} -t {conc}\n\
         - katana: -rl {rps} -c {conc}\n\
         - ffuf: -rate {rps} -t {conc}\n\
         - dalfox scan: --rate-limit {rps} --workers {conc}\n\
         - sqlmap: --delay={delay_sec} --threads=1\n\
         For any other tool, keep <= {rps} req/s per host, <= {inflight} in flight, and >= {delay_ms} ms between requests. \
         Do not run two scanners against the same host in parallel; back off on 429/503; never raise the rate to beat a deadline. \
         The proxy paces HTTP(S) requests automatically, but raw scanners still rely on these flags.",
        profile.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn off_profile_is_passthrough_and_empty_prompt() {
        let g = Governor::default();
        assert!(g.is_off());
        assert!(g.acquire("example.test", &CancellationToken::new()).await.is_none());
        assert!(render_noise_profile_prompt(NoiseProfileName::Off).is_empty());
    }

    #[tokio::test]
    async fn active_profile_tracks_sent_inflight_and_backoff_on_429() {
        let mut p = NoiseProfile::from_name(NoiseProfileName::Aggressive, Some("CustomUA/1.0".into()));
        p.jitter = 0.0;
        p.base_backoff = Duration::from_millis(50);
        p.max_backoff = Duration::from_millis(200);
        let g = Governor::new(p);
        let cancel = CancellationToken::new();

        let guard = g.acquire("Shop.Example.TEST.", &cancel).await.unwrap();
        let snap = g.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].host, "shop.example.test");
        assert_eq!(snap[0].sent, 1);
        assert_eq!(snap[0].inflight, 1);
        drop(guard);
        assert_eq!(g.snapshot()[0].inflight, 0);

        g.note_response("shop.example.test", 429, Some("1"));
        assert_eq!(g.snapshot()[0].backoffs, 1);

        let prompt = render_noise_profile_prompt(NoiseProfileName::Quiet);
        assert!(prompt.contains("-T2 --max-rate 2") && prompt.contains("nuclei: -rate-limit 2 -c 1"), "{prompt}");
    }
}
