//! The daemon's egress state: whether a sandboxed command can reach the network except through the egress proxy.
//!
//! CONTRACT.
//!
//! This is the floor's self-knowledge (`docs/MONITOR.md` §2.2, E2). The sandbox denies the macOS services that fetch
//! a URL for a process (`loom_tools::sandbox`); this module asks, at start and every `PROBE_EVERY` (one hour),
//! whether that still holds on this host, by running `loom_tools::sandbox::selfprobe::run` against the daemon's
//! sandbox configuration, and turns the answer into an `EgressView` that `Runtime::egress()` returns and `GET
//! /api/status` shows (`StatusView.egress`).
//!
//! - `Level`: `Unprobed` (seatbelt, the first probe has not finished), `Bounded`, `Unbounded`. A level other than
//!   `Bounded` is not a reason to stop anything: sessions run as before. It is the header's warning and a reason that
//!   keep-going refuses to turn on.
//! - `assess(cfg, report)` (pure) decides the level and the reasons:
//!   - sandbox mode `none`: `Unbounded` (commands are not confined at all), basis "not confined";
//!   - `cfg.allow_fetch_services`: `Unbounded`, with the reason that names the setting (the probes still run and add
//!     theirs);
//!   - bubblewrap: `Bounded`, basis "bubblewrap network namespace" (no seatbelt services exist; nothing to probe);
//!   - seatbelt without a report: `Unprobed`; a report that did not run (`sandbox-exec` missing): `Unbounded`;
//!     any probe `Leaked` or `Failed`: `Unbounded` with one reason each (a probe that cannot run proves nothing);
//!     otherwise `Bounded`. `NotExercised` is not a problem: the host does not fetch in that setting.
//!   - the probes run against a profile with the operator's unix sockets, loopback ports and infrastructure ports
//!     cleared, so `assess` reads those grants from the configuration itself: a `unix_sockets` entry that is the
//!     resolver's socket (`/var/run/mDNSResponder`, also as `/private/var/run/mDNSResponder`) lets a command resolve
//!     names, and carry data in the queries, outside the proxy: `Unbounded`, with the reason that names it. Any other
//!     unix socket, `loopback_all` or `loopback_ports` is listed in `grants` (the line says so) and does not change
//!     the level.
//!   - `fetch_services_allowed` is the setting; `probe_problem` is true when the level is not `Bounded` for any
//!     other reason (a leak, a failed probe, the resolver's socket, unconfined commands, no probe yet).
//!     `keep_going_blockers(now_ms)` is `[Blocker::FetchServicesAllowed]` for the first and
//!     `[Blocker::SelfProbeFailed]` for the second, both when both; a seatbelt view whose last probe finished more
//!     than `STALE_AFTER` (two probe periods) ago is also `SelfProbeFailed`: a probe that stopped recording is not
//!     a reason to believe the last answer.
//! - `EgressView::line()` is the one-line text of `loom status` and the web header: `egress: bounded (seatbelt
//!   self-probe 5 minutes ago)`, `egress: bounded (seatbelt self-probe 5 minutes ago; fetch routes not exercised)`
//!   when none of the three fetch probes could run on this host, `egress: STALE, last probed 200 minutes ago`
//!   when the probe stopped recording, `egress: UNBOUNDED, <first reason> (+n more)`, or `egress: not probed yet`;
//!   `; grants: ...` follows when the profile gives commands a loopback or unix-socket grant.
//! - `probe` returns after `PROBE_LIMIT` at the latest: a probe that did not finish reads as every probe failed.
//! - `Runtime` keeps the view; each probe's report is written to `<home>/egress-probe.json` (the latest, replaced
//!   atomically; the loom home is hidden from commands) and a change into `Unbounded` raises one `egress`
//!   notification (`UNBOUNDED_NOTICE`), none again until it was `Bounded` once more. Nothing is refused or stopped
//!   because of the level.
//! - Under `cfg(test)` the probe loop is not started (a test runtime stays quiet); `Runtime::record_egress_probe`
//!   takes a report for tests.
//!
//! Tests required: `a_confined_host_that_held_every_probe_is_bounded`, `a_leak_or_a_probe_that_cannot_run_is_unbounded`,
//! `not_exercised_is_not_a_problem`, `the_fetch_services_setting_is_unbounded_and_blocks_keep_going`,
//! `no_sandbox_is_unbounded_and_bubblewrap_is_bounded`, `no_report_is_unprobed`, `the_line_says_what_is_known`,
//! `the_view_round_trips_and_older_daemons_are_read`, `the_resolvers_socket_is_unbounded_and_other_grants_are_listed`,
//! `a_view_that_stopped_being_probed_is_stale_and_blocks_keep_going`,
//! `a_probe_that_exercised_no_fetch_route_is_not_shown_as_fully_probed`.

use crate::monitor::keepgoing::Blocker;
use loom_core::config::{SandboxCfg, SandboxMode};
use loom_tools::sandbox::selfprobe::{Outcome, Report};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How often the probe runs again after the first.
pub const PROBE_EVERY: Duration = Duration::from_secs(3_600);

/// How long a probe may take before it reads as failed (the longest probe is about a minute).
pub const PROBE_LIMIT: Duration = Duration::from_secs(300);

/// A seatbelt view probed longer ago than this is stale: two probe periods.
pub const STALE_AFTER: Duration = Duration::from_secs(7_200);

/// What an operator is told when egress turns unbounded.
pub const UNBOUNDED_NOTICE: &str =
    "A sandboxed command may reach the network outside the egress proxy. See `loom status` \
     for the reasons. Missions that need a bounded network should wait, and keep-going cannot be turned on.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    #[default]
    Unprobed,
    Bounded,
    Unbounded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EgressView {
    pub level: Level,
    /// Why the level is `Unbounded` (or `Unprobed`): one sentence each; empty when `Bounded`.
    #[serde(default)]
    pub reasons: Vec<String>,
    /// What the level rests on: `seatbelt self-probe`, `bubblewrap network namespace` or `not confined`.
    #[serde(default)]
    pub basis: String,
    /// `sandbox.allow_fetch_services` is set.
    #[serde(default)]
    pub fetch_services_allowed: bool,
    /// The level is not `Bounded` for a reason other than the setting.
    #[serde(default)]
    pub probe_problem: bool,
    /// When the last probe finished (milliseconds since the epoch); `None` before the first.
    #[serde(default)]
    pub probed_at_ms: Option<u64>,
    /// The last probe's results.
    #[serde(default)]
    pub probes: Vec<loom_tools::sandbox::selfprobe::ProbeResult>,
    /// Grants in the configuration that the probes do not exercise (they run with them cleared): `loopback_all`,
    /// `loopback_ports`, `unix_sockets`.
    #[serde(default)]
    pub grants: Vec<String>,
}

impl EgressView {
    /// Whether the view rests on a seatbelt probe that finished more than `STALE_AFTER` before `now_ms`.
    pub fn is_stale(&self, now_ms: u64) -> bool {
        self.basis == SEATBELT_BASIS
            && self.probed_at_ms.is_some_and(|at| now_ms.saturating_sub(at) > STALE_AFTER.as_millis() as u64)
    }

    /// The refusals of keep-going that this state causes (`monitor::keepgoing::Blocker`); `now_ms` is the
    /// current time.
    pub fn keep_going_blockers(&self, now_ms: u64) -> Vec<Blocker> {
        let mut out = Vec::new();
        if self.fetch_services_allowed {
            out.push(Blocker::FetchServicesAllowed);
        }
        if self.probe_problem || self.is_stale(now_ms) {
            out.push(Blocker::SelfProbeFailed);
        }
        out
    }

    /// Whether the three fetch probes all could not run on this host (a probe that was not run because the
    /// setting is on does not count: that is the setting's own reason).
    fn fetch_routes_not_exercised(&self) -> bool {
        use loom_tools::sandbox::selfprobe::Probe;
        let fetch: Vec<_> = self
            .probes
            .iter()
            .filter(|p| matches!(p.probe, Probe::AiaFetch | Probe::UrlSession | Probe::WebKit))
            .collect();
        !self.fetch_services_allowed && fetch.len() == 3 && fetch.iter().all(|p| p.outcome == Outcome::NotExercised)
    }

    /// One line for `loom status` and the header; `now_ms` is the current time.
    pub fn line(&self, now_ms: u64) -> String {
        let grants =
            if self.grants.is_empty() { String::new() } else { format!("; grants: {}", self.grants.join(", ")) };
        match self.level {
            Level::Unprobed => "egress: not probed yet".to_string(),
            Level::Bounded if self.is_stale(now_ms) => {
                let minutes = now_ms.saturating_sub(self.probed_at_ms.unwrap_or(now_ms)) / 60_000;
                format!("egress: STALE, last probed {minutes} minutes ago, so not known to be bounded{grants}")
            }
            Level::Bounded => {
                let routes = if self.fetch_routes_not_exercised() { "; fetch routes not exercised" } else { "" };
                match self.probed_at_ms {
                    Some(at) => {
                        let minutes = now_ms.saturating_sub(at) / 60_000;
                        format!("egress: bounded ({} {minutes} minutes ago{routes}{grants})", self.basis)
                    }
                    None => format!("egress: bounded ({}{routes}{grants})", self.basis),
                }
            }
            Level::Unbounded => {
                let first = self.reasons.first().map_or("see the self-probe", String::as_str);
                match self.reasons.len().saturating_sub(1) {
                    0 => format!("egress: UNBOUNDED, {first}{grants}"),
                    n => format!("egress: UNBOUNDED, {first} (+{n} more){grants}"),
                }
            }
        }
    }
}

const SEATBELT_BASIS: &str = "seatbelt self-probe";

/// Whether `path` is the resolver's socket (`/var/run` is `/private/var/run`).
fn is_resolver_socket(path: &str) -> bool {
    let p = path.trim_end_matches('/');
    p.strip_prefix("/private").unwrap_or(p).eq_ignore_ascii_case("/var/run/mDNSResponder")
}

/// The egress view for `cfg` and the latest probe `report`. See the contract.
pub fn assess(cfg: &SandboxCfg, report: Option<&Report>, probed_at_ms: Option<u64>) -> EgressView {
    let mut view = EgressView {
        fetch_services_allowed: cfg.allow_fetch_services,
        probed_at_ms,
        probes: report.map(|r| r.results.clone()).unwrap_or_default(),
        ..EgressView::default()
    };
    let setting = "sandbox.allow_fetch_services is set: commands can fetch URLs through macOS services, outside the egress proxy.";
    match cfg.mode {
        SandboxMode::None => {
            view.level = Level::Unbounded;
            view.basis = "not confined".into();
            view.probe_problem = true;
            view.reasons
                .push("sandbox.mode is \"none\": commands are not confined and reach the network directly.".into());
        }
        SandboxMode::Bubblewrap => {
            view.basis = "bubblewrap network namespace".into();
            view.level = if cfg.allow_fetch_services { Level::Unbounded } else { Level::Bounded };
            if cfg.allow_fetch_services {
                view.reasons.push(setting.into());
            }
        }
        SandboxMode::Seatbelt => {
            view.basis = SEATBELT_BASIS.into();
            if cfg.loopback_all {
                view.grants.push("loopback_all".into());
            }
            if !cfg.loopback_ports.is_empty() {
                view.grants.push("loopback_ports".into());
            }
            for socket in &cfg.unix_sockets {
                if is_resolver_socket(socket) {
                    view.probe_problem = true;
                    view.reasons.push(format!(
                        "sandbox.unix_sockets lists {socket}: commands resolve names through it, so DNS queries carry data \
                         outside the egress proxy. Remove it, and let the proxy resolve names."
                    ));
                } else {
                    view.grants.push(format!("unix socket {socket}"));
                }
            }
            let problems = report.map(Report::problems).unwrap_or_default();
            match report {
                None => {
                    view.level = Level::Unprobed;
                    view.probe_problem = true;
                    view.reasons.push("The first self-probe has not finished.".into());
                }
                Some(r) if !r.ran => {
                    view.level = Level::Unbounded;
                    view.probe_problem = true;
                    view.reasons.push(
                        "The self-probe could not run: /usr/bin/sandbox-exec is missing, so commands may not be confined."
                            .into(),
                    );
                }
                Some(_) if !problems.is_empty() => {
                    view.level = Level::Unbounded;
                    view.probe_problem = true;
                    view.reasons.extend(problems);
                }
                Some(_) => view.level = Level::Bounded,
            }
            if cfg.allow_fetch_services {
                view.level = Level::Unbounded;
                view.reasons.insert(0, setting.into());
            }
            if view.probe_problem && view.level == Level::Bounded {
                view.level = Level::Unbounded;
            }
        }
    }
    view
}

/// Whether a probe of this report found nothing wrong (every outcome `Held` or `NotExercised`).
pub fn report_is_clean(report: &Report) -> bool {
    report.ran && report.results.iter().all(|r| matches!(r.outcome, Outcome::Held | Outcome::NotExercised))
}

/// Run the probes on a blocking thread, for at most `PROBE_LIMIT`. A probe that panics reads as a report that did
/// not run, and one that does not finish reads as every probe failed (the thread is left to its own limits).
pub async fn probe(cfg: SandboxCfg, home: std::path::PathBuf) -> Report {
    probe_within(move || loom_tools::sandbox::selfprobe::run(&cfg, &home), PROBE_LIMIT).await
}

async fn probe_within(run: impl FnOnce() -> Report + Send + 'static, limit: Duration) -> Report {
    let task = tokio::task::spawn_blocking(run);
    match tokio::time::timeout(limit, task).await {
        Ok(done) => done.unwrap_or_default(),
        Err(_) => {
            let detail = format!(
                "The self-probe did not finish within {} seconds. Check that no command of this host holds it, and restart the daemon.",
                limit.as_secs()
            );
            Report {
                ran: true,
                results: loom_tools::sandbox::selfprobe::Probe::ALL
                    .iter()
                    .map(|p| loom_tools::sandbox::selfprobe::ProbeResult {
                        probe: *p,
                        outcome: Outcome::Failed,
                        detail: detail.clone(),
                    })
                    .collect(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_tools::sandbox::selfprobe::{Probe, ProbeResult};

    fn seatbelt() -> SandboxCfg {
        SandboxCfg { mode: SandboxMode::Seatbelt, ..SandboxCfg::default() }
    }

    fn result(probe: Probe, outcome: Outcome) -> ProbeResult {
        ProbeResult { probe, outcome, detail: format!("{probe:?} {outcome:?}") }
    }

    fn report(outcomes: [Outcome; 4]) -> Report {
        Report { ran: true, results: Probe::ALL.iter().zip(outcomes).map(|(p, o)| result(*p, o)).collect() }
    }

    #[test]
    fn a_confined_host_that_held_every_probe_is_bounded() {
        let r = report([Outcome::Held; 4]);
        let v = assess(&seatbelt(), Some(&r), Some(5));
        assert_eq!(v.level, Level::Bounded);
        assert!(v.reasons.is_empty() && !v.probe_problem && !v.fetch_services_allowed, "{v:?}");
        assert!(v.keep_going_blockers(0).is_empty());
        assert_eq!((v.probed_at_ms, v.probes.len(), v.basis.as_str()), (Some(5), 4, "seatbelt self-probe"));
        assert!(report_is_clean(&r));
    }

    #[test]
    fn a_leak_or_a_probe_that_cannot_run_is_unbounded() {
        for bad in [Outcome::Leaked, Outcome::Failed] {
            let r = report([Outcome::Held, bad, Outcome::Held, Outcome::Held]);
            let v = assess(&seatbelt(), Some(&r), Some(1));
            assert_eq!(v.level, Level::Unbounded, "{bad:?}");
            assert_eq!(v.reasons.len(), 1);
            assert!(v.reasons[0].contains("url_session"), "{v:?}");
            assert_eq!(v.keep_going_blockers(0), [Blocker::SelfProbeFailed]);
            assert!(!report_is_clean(&r));
        }
        let none = Report { ran: false, results: vec![] };
        let v = assess(&seatbelt(), Some(&none), Some(1));
        assert_eq!(v.level, Level::Unbounded);
        assert!(v.reasons[0].contains("sandbox-exec"), "{v:?}");
    }

    #[test]
    fn a_git_metadata_write_that_landed_is_unbounded_too() {
        let mut r = report([Outcome::Held; 4]);
        r.results.push(result(Probe::GitMetadata, Outcome::Leaked));
        let v = assess(&seatbelt(), Some(&r), Some(1));
        assert_eq!((v.level, v.keep_going_blockers(0)), (Level::Unbounded, vec![Blocker::SelfProbeFailed]));
        assert!(v.reasons[0].contains("git_metadata"), "{v:?}");
    }

    #[test]
    fn not_exercised_is_not_a_problem() {
        let r = report([Outcome::NotExercised, Outcome::NotExercised, Outcome::NotExercised, Outcome::Held]);
        assert_eq!(assess(&seatbelt(), Some(&r), Some(1)).level, Level::Bounded);
    }

    #[test]
    fn the_fetch_services_setting_is_unbounded_and_blocks_keep_going() {
        let cfg = SandboxCfg { allow_fetch_services: true, ..seatbelt() };
        let r = report([Outcome::NotExercised, Outcome::NotExercised, Outcome::NotExercised, Outcome::Held]);
        let v = assess(&cfg, Some(&r), Some(1));
        assert_eq!(v.level, Level::Unbounded);
        assert!(v.reasons[0].contains("sandbox.allow_fetch_services"), "{v:?}");
        assert_eq!(v.keep_going_blockers(0), [Blocker::FetchServicesAllowed]);
        // With a leak as well, both refusals.
        let leak = report([Outcome::Leaked, Outcome::Held, Outcome::Held, Outcome::Held]);
        let v = assess(&cfg, Some(&leak), Some(1));
        assert_eq!(v.keep_going_blockers(0), [Blocker::FetchServicesAllowed, Blocker::SelfProbeFailed]);
        assert_eq!(v.reasons.len(), 2);
        // Before any probe the setting is still reported.
        assert!(assess(&cfg, None, None).keep_going_blockers(0).contains(&Blocker::FetchServicesAllowed));
    }

    #[test]
    fn no_sandbox_is_unbounded_and_bubblewrap_is_bounded() {
        let none = assess(&SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() }, None, None);
        assert_eq!(none.level, Level::Unbounded);
        assert_eq!(none.keep_going_blockers(0), [Blocker::SelfProbeFailed]);
        assert_eq!(none.basis, "not confined");
        let bwrap = assess(&SandboxCfg { mode: SandboxMode::Bubblewrap, ..SandboxCfg::default() }, None, None);
        assert_eq!((bwrap.level, bwrap.keep_going_blockers(0).len()), (Level::Bounded, 0));
        assert_eq!(bwrap.basis, "bubblewrap network namespace");
    }

    #[test]
    fn no_report_is_unprobed() {
        let v = assess(&seatbelt(), None, None);
        assert_eq!(v.level, Level::Unprobed);
        assert_eq!(v.keep_going_blockers(0), [Blocker::SelfProbeFailed], "keep-going waits for a first probe");
        assert_eq!(v.line(0), "egress: not probed yet");
    }

    #[test]
    fn the_line_says_what_is_known() {
        let bounded = assess(&seatbelt(), Some(&report([Outcome::Held; 4])), Some(60_000));
        assert_eq!(bounded.line(60_000 + 5 * 60_000), "egress: bounded (seatbelt self-probe 5 minutes ago)");
        // A clock that went back does not underflow.
        assert_eq!(bounded.line(0), "egress: bounded (seatbelt self-probe 0 minutes ago)");
        let one =
            assess(&seatbelt(), Some(&report([Outcome::Leaked, Outcome::Held, Outcome::Held, Outcome::Held])), Some(1));
        assert!(one.line(2).starts_with("egress: UNBOUNDED, self-probe aia_fetch leaked"), "{}", one.line(2));
        assert!(!one.line(2).contains("more"));
        let two = assess(
            &SandboxCfg { allow_fetch_services: true, ..seatbelt() },
            Some(&report([Outcome::Leaked, Outcome::Held, Outcome::Held, Outcome::Held])),
            Some(1),
        );
        assert!(
            two.line(2).starts_with("egress: UNBOUNDED, sandbox.allow_fetch_services is set")
                && two.line(2).ends_with("(+1 more)"),
            "{}",
            two.line(2)
        );
        let none = assess(&SandboxCfg { mode: SandboxMode::None, ..SandboxCfg::default() }, None, None);
        assert!(none.line(0).contains("not confined") || none.line(0).contains("sandbox.mode"), "{}", none.line(0));
    }

    #[test]
    fn the_resolvers_socket_is_unbounded_and_other_grants_are_listed() {
        let r = report([Outcome::Held; 4]);
        for path in ["/var/run/mDNSResponder", "/private/var/run/mDNSResponder"] {
            let cfg = SandboxCfg { unix_sockets: vec![path.into()], ..seatbelt() };
            let v = assess(&cfg, Some(&r), Some(1));
            assert_eq!(
                (v.level, v.keep_going_blockers(0)),
                (Level::Unbounded, vec![Blocker::SelfProbeFailed]),
                "{path}"
            );
            assert!(v.reasons[0].contains("DNS") && v.reasons[0].contains(path), "{v:?}");
        }
        let other = SandboxCfg {
            unix_sockets: vec!["/var/run/other.sock".into()],
            loopback_all: true,
            loopback_ports: vec![8080],
            ..seatbelt()
        };
        let v = assess(&other, Some(&r), Some(60_000));
        assert_eq!(v.level, Level::Bounded);
        assert_eq!(v.grants, ["loopback_all", "loopback_ports", "unix socket /var/run/other.sock"]);
        assert!(v.line(60_000).contains("; grants: loopback_all, loopback_ports, unix socket /var/run/other.sock"));
    }

    #[test]
    fn a_view_that_stopped_being_probed_is_stale_and_blocks_keep_going() {
        let v = assess(&seatbelt(), Some(&report([Outcome::Held; 4])), Some(0));
        let period = PROBE_EVERY.as_millis() as u64;
        assert!(v.keep_going_blockers(period).is_empty() && !v.is_stale(2 * period));
        assert_eq!(v.keep_going_blockers(2 * period + 1), [Blocker::SelfProbeFailed]);
        assert!(
            v.line(2 * period + 60_000).starts_with("egress: STALE, last probed 121 minutes ago"),
            "{}",
            v.line(2 * period + 60_000)
        );
        // Bubblewrap has no probe to go stale.
        let bwrap = assess(
            &SandboxCfg { mode: SandboxMode::Bubblewrap, ..SandboxCfg::default() },
            Some(&Report::default()),
            Some(0),
        );
        assert!(bwrap.keep_going_blockers(100 * period).is_empty());
    }

    #[test]
    fn a_probe_that_exercised_no_fetch_route_is_not_shown_as_fully_probed() {
        let none = report([Outcome::NotExercised, Outcome::NotExercised, Outcome::NotExercised, Outcome::Held]);
        let v = assess(&seatbelt(), Some(&none), Some(60_000));
        assert_eq!(v.level, Level::Bounded);
        assert!(v.line(60_000).contains("fetch routes not exercised"), "{}", v.line(60_000));
        let one = report([Outcome::Held, Outcome::NotExercised, Outcome::NotExercised, Outcome::Held]);
        assert!(!assess(&seatbelt(), Some(&one), Some(1)).line(1).contains("not exercised"));
    }

    #[tokio::test]
    async fn a_probe_that_does_not_finish_reads_as_failed() {
        let slow = || {
            std::thread::sleep(Duration::from_millis(1_500));
            Report::default()
        };
        let r = probe_within(slow, Duration::from_millis(50)).await;
        assert!(r.ran && !r.results.is_empty() && r.results.iter().all(|x| x.outcome == Outcome::Failed), "{r:?}");
        assert!(!report_is_clean(&r));
    }

    #[test]
    fn the_view_round_trips_and_older_daemons_are_read() {
        let v = assess(&seatbelt(), Some(&report([Outcome::Held; 4])), Some(9));
        let json = serde_json::to_string(&v).expect("json");
        assert_eq!(serde_json::from_str::<EgressView>(&json).expect("back"), v);
        assert!(json.contains("\"level\":\"bounded\""), "{json}");
        assert_eq!(
            serde_json::from_str::<EgressView>("{\"level\":\"unbounded\"}").expect("older").level,
            Level::Unbounded
        );
    }
}
