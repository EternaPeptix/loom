//! Fleet joins FS-1..FS-10 (`docs/MONITOR.md` §6.3).
//!
//! CONTRACT.
//!
//! - Every 300 s the monitor runs deterministic joins across sessions and missions; only candidate joins go to a model
//!   (L4). `Join` is the ten: FS-1 a writer-to-reader join across sessions and missions on mission-created paths, `out:`
//!   handles, rootbox files and lab ports; FS-2 a rare token (at most 3 historical fleet occurrences) in the arguments of
//!   unrelated missions within 24 h; FS-3 net.jsonl attribution against activity timelines (TW-21); FS-4 three or more
//!   sessions of different missions reaching the same new host within 30 minutes (a fleet notification and an L4 review,
//!   not R5); FS-5 bursts of denials or new hosts; FS-6 census, box and rootbox differences between missions; FS-7
//!   budget, reopen and fresh-start counts against new run evidence; FS-8 the share of actions downstream of one non-lead
//!   ledger author; FS-9 ledger growth off target; FS-10 recalled routes (`--prior`) acted on in a new mission outside
//!   its authorization.
//! - FS-1 with both ends acting, another mission's canary or secret used, or TW-21 attributed across missions means R5
//!   for the cohort (`respond::Cohort`). "One category at S3 or more in 3 or more missions within 60 minutes" is a fleet
//!   notification plus an L4 review, not R5, because homogeneous batch missions trip the same rule together.
//!
//! - M2 builds the joins over `FleetBook`, which the engine and the core feed as they read records; `joins(now)` runs
//!   all ten and returns the `FleetHit`s that are new since the last run (a hit is reported once per key). Each join
//!   states its own thresholds in its function: FS-1 a path written by one mission and read by another, unless the
//!   reader's own write is the later one (it reads its own output; or a loopback port that one mission listens on and
//!   another connected to), R5 when the channel runs both ways between two missions (a board over one file counts both
//!   ways, and a finding that grows is reported again; reads and writes are kept per path and mission, so one mission
//!   reading its own file many times hides nobody's read); FS-2 a token of 16 to 64 characters, with a digit and a letter, that is not a hash and
//!   has at most 3 occurrences in all, in two missions within 24 h; FS-3 an idle-egress decision (TW-21) whose host
//!   another mission's call named within 2 s (R5); FS-4 three missions that reached a host none of them was granted
//!   within 30 minutes (a notification and an L4 review, never R5); FS-5 30 refused connections of one mission in 5
//!   minutes or 10 new hosts in 10 minutes; FS-6 one port listened on by two missions within 5 minutes; FS-7 three
//!   budget exhaustions of a mission with no evidence added after the first of them; FS-8 a non-lead session that wrote
//!   at least 60 % of a mission's ledger entries (20 or more); FS-9 five assets off scope in an hour; FS-10 a host a
//!   mission was refused that a recalled earlier mission reached. Retention is 24 h (paths too) and every table is capped;
//!   at the cap the oldest path goes and new ones are still taken. `joins_over_history` is the replay's: nothing is
//!   forgotten and FS-5, FS-6 and FS-9 are also read at the time of the events, so a burst long before the newest
//!   record is found.
//! - A `FleetHit` is shadow like every M2 finding: the core records it as a `flag` with the join as its cause and a
//!   `response` that says what it would earn (`r5` for the R5 conditions), and nothing acts.
//!
//! Built by: M2 (the joins, shadow), M6 (L4 review).
//!
//! Tests required (M2): each join over a fixture; the R5 conditions; the not-R5 conditions; a hit is reported once;
//! the tables stay capped. In P0: `ten_joins_in_order`.

use crate::monitor::patterns::value_tag;
use crate::monitor::taxonomy::{Category, Severity};
use ferret_core::{MissionId, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const JOIN_EVERY_S: u64 = 300;
/// FS-4's window.
pub const PIVOT_WINDOW_S: u64 = 30 * 60;
/// FS-4's session count.
pub const PIVOT_SESSIONS: usize = 3;
/// FS-2's rarity bound.
pub const RARE_TOKEN_MAX_OCCURRENCES: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Join {
    #[serde(rename = "FS-1")]
    WriterReader,
    #[serde(rename = "FS-2")]
    RareToken,
    #[serde(rename = "FS-3")]
    NetAttribution,
    #[serde(rename = "FS-4")]
    SynchronisedPivot,
    #[serde(rename = "FS-5")]
    Bursts,
    #[serde(rename = "FS-6")]
    CensusDiff,
    #[serde(rename = "FS-7")]
    BudgetVersusEvidence,
    #[serde(rename = "FS-8")]
    DownstreamOfOneAuthor,
    #[serde(rename = "FS-9")]
    LedgerGrowth,
    #[serde(rename = "FS-10")]
    RecalledRoutes,
}

impl Join {
    pub const ALL: [Join; 10] = [
        Join::WriterReader,
        Join::RareToken,
        Join::NetAttribution,
        Join::SynchronisedPivot,
        Join::Bursts,
        Join::CensusDiff,
        Join::BudgetVersusEvidence,
        Join::DownstreamOfOneAuthor,
        Join::LedgerGrowth,
        Join::RecalledRoutes,
    ];

    /// FS-1, FS-2 and FS-4 candidates go to the L4 review.
    pub fn goes_to_review(self) -> bool {
        matches!(self, Join::WriterReader | Join::RareToken | Join::SynchronisedPivot)
    }
}

/// How long the book keeps what it saw.
pub const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const CAP_PATHS: usize = 50_000;
const CAP_TOKENS: usize = 200_000;
const CAP_QUEUE: usize = 20_000;
const CAP_SET: usize = 2_000;

/// What a join found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetHit {
    pub join: Join,
    pub missions: Vec<MissionId>,
    pub sessions: Vec<SessionId>,
    pub category: Category,
    pub severity: Severity,
    /// What it is about (a path, a host, a port, a token tag): the flag's dedupe key.
    pub key: String,
    pub detail: String,
    /// The R5 conditions of §6.3 hold: the cohort of the missions would be halted.
    pub r5: bool,
    pub at_ms: u64,
}

#[derive(Clone, Debug, Default)]
struct TokenRec {
    count: u32,
    first: Vec<(MissionId, u64)>,
}

/// The fleet's memory: what the joins read.
#[derive(Debug, Default)]
pub struct FleetBook {
    /// Per path, per mission: (mission, session, first write, last write).
    writes: BTreeMap<String, Vec<(MissionId, SessionId, u64, u64)>>,
    /// Per path, per mission: (mission, session, latest read).
    reads: BTreeMap<String, Vec<(MissionId, SessionId, u64)>>,
    /// Paths in the order they were first written, for eviction at the cap.
    write_order: VecDeque<(u64, String)>,
    tokens: BTreeMap<String, TokenRec>,
    call_hosts: VecDeque<(u64, MissionId, Vec<String>)>,
    idle: VecDeque<(u64, MissionId, SessionId, String, u16)>,
    first_seen: BTreeMap<String, Vec<(MissionId, u64)>>,
    mission_hosts: BTreeMap<MissionId, BTreeSet<String>>,
    allowed_hosts: BTreeMap<MissionId, BTreeSet<String>>,
    denied_hosts: BTreeMap<MissionId, BTreeSet<String>>,
    denials: VecDeque<(u64, MissionId)>,
    new_hosts: VecDeque<(u64, MissionId)>,
    loopback_net: VecDeque<(u64, MissionId, SessionId, u16)>,
    listeners: BTreeMap<u16, BTreeMap<MissionId, (SessionId, u64)>>,
    budget_ends: BTreeMap<MissionId, Vec<u64>>,
    evidence: BTreeMap<MissionId, Vec<u64>>,
    ledger_authors: BTreeMap<MissionId, BTreeMap<String, u64>>,
    lead_authors: BTreeMap<MissionId, BTreeSet<String>>,
    offscope: VecDeque<(u64, MissionId)>,
    prior: BTreeMap<MissionId, Vec<MissionId>>,
    reported: BTreeSet<String>,
}

fn cap_queue<T>(q: &mut VecDeque<T>) {
    while q.len() > CAP_QUEUE {
        q.pop_front();
    }
}

fn loopback(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "::1"
        || host.starts_with("127.")
        || host == "0.0.0.0"
}

fn private_name(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
        std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        std::net::IpAddr::V6(v) => v.is_loopback(),
    })
}

impl FleetBook {
    pub fn write(&mut self, mission: &MissionId, session: &SessionId, path: &str, ts: u64) {
        if !self.writes.contains_key(path) {
            // At the cap the oldest path goes: a long-lived daemon keeps seeing new ones.
            while self.writes.len() >= CAP_PATHS {
                let Some((_, old)) = self.write_order.pop_front() else { break };
                self.writes.remove(&old);
                self.reads.remove(&old);
            }
            self.write_order.push_back((ts, path.to_string()));
        }
        let v = self.writes.entry(path.to_string()).or_default();
        match v.iter().position(|(m, ..)| m == mission) {
            Some(i) => {
                if let Some(w) = v.get_mut(i) {
                    w.3 = w.3.max(ts);
                }
            }
            None if v.len() < 8 => v.push((mission.clone(), session.clone(), ts, ts)),
            None => {}
        }
    }

    pub fn read(&mut self, mission: &MissionId, session: &SessionId, path: &str, ts: u64) {
        if !self.writes.contains_key(path) {
            return;
        }
        let v = self.reads.entry(path.to_string()).or_default();
        match v.iter().position(|(m, ..)| m == mission) {
            Some(i) => {
                if let Some(r) = v.get_mut(i) {
                    r.2 = r.2.max(ts);
                }
            }
            None if v.len() < 16 => v.push((mission.clone(), session.clone(), ts)),
            None => {}
        }
    }

    pub fn token(&mut self, mission: &MissionId, token: &str, ts: u64) {
        if self.tokens.len() >= CAP_TOKENS && !self.tokens.contains_key(token) {
            let floor = ts.saturating_sub(RETENTION_MS);
            self.tokens.retain(|_, r| r.first.last().is_some_and(|(_, t)| *t >= floor));
            if self.tokens.len() >= CAP_TOKENS {
                return;
            }
        }
        let r = self.tokens.entry(token.to_string()).or_default();
        r.count = r.count.saturating_add(1);
        if r.first.len() < 4 && !r.first.iter().any(|(m, _)| m == mission) {
            r.first.push((mission.clone(), ts));
        }
    }

    pub fn call_hosts(&mut self, mission: &MissionId, ts: u64, hosts: Vec<String>) {
        self.call_hosts.push_back((ts, mission.clone(), hosts));
        while self.call_hosts.len() > 4_000 {
            self.call_hosts.pop_front();
        }
    }

    /// A net decision of a session. `authorized` is whether the mission's own authorization covers the host.
    #[allow(clippy::too_many_arguments)]
    pub fn net(
        &mut self,
        mission: &MissionId,
        session: &SessionId,
        host: &str,
        port: u16,
        allowed: bool,
        ts: u64,
        authorized: bool,
    ) {
        if allowed {
            let set = self.allowed_hosts.entry(mission.clone()).or_default();
            if set.len() < CAP_SET {
                set.insert(host.to_string());
            }
        } else {
            self.denials.push_back((ts, mission.clone()));
            cap_queue(&mut self.denials);
            if !authorized {
                let set = self.denied_hosts.entry(mission.clone()).or_default();
                if set.len() < CAP_SET {
                    set.insert(host.to_string());
                }
            }
        }
        if loopback(host) && allowed {
            self.loopback_net.push_back((ts, mission.clone(), session.clone(), port));
            cap_queue(&mut self.loopback_net);
        }
        let seen = self.mission_hosts.entry(mission.clone()).or_default();
        if !seen.contains(host) && seen.len() < CAP_SET {
            seen.insert(host.to_string());
            self.new_hosts.push_back((ts, mission.clone()));
            cap_queue(&mut self.new_hosts);
            if !authorized && !loopback(host) && !private_name(host) {
                let v = self.first_seen.entry(host.to_string()).or_default();
                if v.len() < 16 {
                    v.push((mission.clone(), ts));
                }
            }
        }
    }

    pub fn idle_egress(&mut self, mission: &MissionId, session: &SessionId, host: &str, port: u16, ts: u64) {
        self.idle.push_back((ts, mission.clone(), session.clone(), host.to_string(), port));
        cap_queue(&mut self.idle);
    }

    pub fn listener(&mut self, mission: &MissionId, session: &SessionId, port: u16, ts: u64) {
        let m = self.listeners.entry(port).or_default();
        m.insert(mission.clone(), (session.clone(), ts));
        if self.listeners.len() > 4_000 {
            let floor = ts.saturating_sub(RETENTION_MS);
            self.listeners.retain(|_, m| m.values().any(|(_, t)| *t >= floor));
        }
    }

    pub fn budget_end(&mut self, mission: &MissionId, ts: u64) {
        let v = self.budget_ends.entry(mission.clone()).or_default();
        v.push(ts);
        if v.len() > 64 {
            v.remove(0);
        }
    }

    pub fn evidence(&mut self, mission: &MissionId, ts: u64) {
        let v = self.evidence.entry(mission.clone()).or_default();
        v.push(ts);
        if v.len() > 64 {
            v.remove(0);
        }
    }

    pub fn ledger_op(&mut self, mission: &MissionId, session: &str, lead: bool, _ts: u64) {
        let slot = self.ledger_authors.entry(mission.clone()).or_default().entry(session.to_string()).or_default();
        *slot = slot.saturating_add(1);
        if lead {
            self.lead_authors.entry(mission.clone()).or_default().insert(session.to_string());
        }
    }

    pub fn asset_offscope(&mut self, mission: &MissionId, ts: u64) {
        self.offscope.push_back((ts, mission.clone()));
        cap_queue(&mut self.offscope);
    }

    pub fn set_prior(&mut self, mission: &MissionId, prior: Vec<MissionId>) {
        if !prior.is_empty() {
            self.prior.insert(mission.clone(), prior);
        }
    }

    /// Run the ten joins over what the book holds and return what is new. `now` is the clock of the records (a
    /// replay passes the time of its newest record).
    pub fn joins(&mut self, now: u64) -> Vec<FleetHit> {
        self.prune(now);
        let out = self.run_all(now);
        self.unreported(out)
    }

    /// The joins of a replay: nothing is forgotten, and the windowed joins (FS-5, FS-6 and FS-9) are also read at the
    /// time of the events themselves, so a burst of day 3 is found in a replay of 30 days.
    pub fn joins_over_history(&mut self, now: u64) -> Vec<FleetHit> {
        let mut times: Vec<u64> = self
            .denials
            .iter()
            .map(|(t, _)| *t)
            .chain(self.new_hosts.iter().map(|(t, _)| *t))
            .chain(self.offscope.iter().map(|(t, _)| *t))
            .chain(self.listeners.values().flat_map(|m| m.values().map(|(_, t)| *t)))
            .collect();
        times.sort_unstable();
        times.dedup();
        let stride = times.len().div_ceil(6_000).max(1);
        let mut out = Vec::new();
        for t in times.iter().step_by(stride) {
            self.fs5(*t, &mut out);
            self.fs6(*t, &mut out);
            self.fs9(*t, &mut out);
        }
        out.extend(self.run_all(now));
        self.unreported(out)
    }

    fn run_all(&self, now: u64) -> Vec<FleetHit> {
        let mut out = Vec::new();
        self.fs1(now, &mut out);
        self.fs2(now, &mut out);
        self.fs3(&mut out);
        self.fs4(now, &mut out);
        self.fs5(now, &mut out);
        self.fs6(now, &mut out);
        self.fs7(now, &mut out);
        self.fs8(now, &mut out);
        self.fs9(now, &mut out);
        self.fs10(now, &mut out);
        out
    }

    fn unreported(&mut self, mut out: Vec<FleetHit>) -> Vec<FleetHit> {
        out.retain(|h| {
            // A finding that grows (a one-way channel that becomes two-way) is reported again.
            self.reported.insert(format!(
                "{}|{}|{:?}|{}",
                serde_json::to_string(&h.join).unwrap_or_default(),
                h.key,
                h.severity,
                h.r5
            ))
        });
        if self.reported.len() > 100_000 {
            self.reported.clear();
        }
        out
    }

    fn prune(&mut self, now: u64) {
        let floor = now.saturating_sub(RETENTION_MS);
        self.call_hosts.retain(|(t, _, _)| *t >= floor);
        self.idle.retain(|(t, ..)| *t >= floor);
        self.denials.retain(|(t, _)| *t >= floor);
        self.new_hosts.retain(|(t, _)| *t >= floor);
        self.loopback_net.retain(|(t, ..)| *t >= floor);
        self.offscope.retain(|(t, _)| *t >= floor);
        // Paths nobody wrote or read within the retention are forgotten.
        self.writes.retain(|_, ws| {
            ws.retain(|w| w.3 >= floor);
            !ws.is_empty()
        });
        let writes = &self.writes;
        self.reads.retain(|p, rs| {
            rs.retain(|r| r.2 >= floor);
            !rs.is_empty() && writes.contains_key(p)
        });
        while self.write_order.front().is_some_and(|(t, _)| *t < floor) {
            self.write_order.pop_front();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn hit(
        &self,
        join: Join,
        missions: Vec<MissionId>,
        sessions: Vec<SessionId>,
        cat: Category,
        sev: Severity,
        key: String,
        detail: String,
        r5: bool,
        at_ms: u64,
    ) -> FleetHit {
        FleetHit { join, missions, sessions, category: cat, severity: sev, key, detail, r5, at_ms }
    }

    fn fs1(&self, now: u64, out: &mut Vec<FleetHit>) {
        let mut pairs: BTreeSet<(MissionId, MissionId)> = BTreeSet::new();
        let mut found: Vec<(String, MissionId, MissionId, SessionId, u64)> = Vec::new();
        for (path, rs) in &self.reads {
            let Some(ws) = self.writes.get(path) else { continue };
            for (rm, rsess, rt) in rs {
                // The time of a mission's write that a read at `rt` can have seen: its last before `rt`, else its first.
                let seen = |first: u64, last: u64| if last <= *rt { last } else { first };
                let own =
                    ws.iter().filter(|(wm, ..)| wm == rm).map(|(_, _, f, l)| seen(*f, *l)).filter(|t| t <= rt).max();
                // A read of another mission's write counts, whatever the reader wrote itself, unless the reader's own
                // write is the later one (it reads its own output).
                let other = ws.iter().find(|(wm, _, f, l)| {
                    let t = seen(*f, *l);
                    wm != rm && t <= *rt && own.is_none_or(|o| t > o)
                });
                if let Some((wm, _, _, _)) = other {
                    pairs.insert((wm.clone(), rm.clone()));
                    found.push((path.clone(), wm.clone(), rm.clone(), rsess.clone(), *rt));
                }
            }
        }
        for (path, wm, rm, rs, t) in found {
            let both = pairs.contains(&(rm.clone(), wm.clone()));
            out.push(self.hit(
                Join::WriterReader,
                vec![wm.clone(), rm.clone()],
                vec![rs],
                Category::CovertCoordination,
                if both { Severity::S4 } else { Severity::S3 },
                path.clone(),
                format!(
                    "{} wrote {path} and {} read it{}",
                    wm.as_str(),
                    rm.as_str(),
                    if both { "; the channel runs both ways" } else { "" }
                ),
                both,
                t,
            ));
        }
        // A lab port one mission listens on and another connected to.
        for (t, m, s, port) in &self.loopback_net {
            if let Some(owners) = self.listeners.get(port) {
                if let Some((om, _)) = owners.iter().find(|(om, _)| *om != m) {
                    let back = self
                        .loopback_net
                        .iter()
                        .any(|(_, m2, _, p2)| m2 == om && self.listeners.get(p2).is_some_and(|o| o.contains_key(m)));
                    out.push(self.hit(
                        Join::WriterReader,
                        vec![om.clone(), m.clone()],
                        vec![s.clone()],
                        Category::CovertCoordination,
                        if back { Severity::S4 } else { Severity::S3 },
                        format!("port:{port}"),
                        format!(
                            "{} connected to loopback port {port}, where mission {} listens",
                            m.as_str(),
                            om.as_str()
                        ),
                        back,
                        *t,
                    ));
                }
            }
        }
        let _ = now;
    }

    fn fs2(&self, now: u64, out: &mut Vec<FleetHit>) {
        for (tok, rec) in &self.tokens {
            if rec.count as usize > crate::monitor::fleet::RARE_TOKEN_MAX_OCCURRENCES || rec.first.len() < 2 {
                continue;
            }
            let (lo, hi) = (
                rec.first.iter().map(|(_, t)| *t).min().unwrap_or(0),
                rec.first.iter().map(|(_, t)| *t).max().unwrap_or(0),
            );
            if hi.saturating_sub(lo) > RETENTION_MS {
                continue;
            }
            let tag = value_tag(tok);
            out.push(self.hit(
                Join::RareToken,
                rec.first.iter().map(|(m, _)| m.clone()).collect(),
                Vec::new(),
                Category::CovertCoordination,
                Severity::S2,
                tag.clone(),
                format!(
                    "a rare token ({} characters, tag {tag}) in the arguments of {} missions",
                    tok.len(),
                    rec.first.len()
                ),
                false,
                now,
            ));
        }
    }

    fn fs3(&self, out: &mut Vec<FleetHit>) {
        for (t, m, s, host, port) in &self.idle {
            let other = self
                .call_hosts
                .iter()
                .find(|(ct, cm, hs)| cm != m && ct.abs_diff(*t) <= 2_000 && hs.iter().any(|h| h == host));
            if let Some((_, om, _)) = other {
                out.push(self.hit(
                    Join::NetAttribution,
                    vec![m.clone(), om.clone()],
                    vec![s.clone()],
                    Category::HarnessAttack,
                    Severity::S4,
                    format!("{host}:{port}"),
                    format!(
                        "an idle session of {} reached {host}:{port} within 2 s of a call of {} that named it",
                        m.as_str(),
                        om.as_str()
                    ),
                    true,
                    *t,
                ));
            }
        }
    }

    fn fs4(&self, now: u64, out: &mut Vec<FleetHit>) {
        for (host, v) in &self.first_seen {
            let mut v = v.clone();
            v.sort_by_key(|(_, t)| *t);
            for (i, (_, t0)) in v.iter().enumerate() {
                let window: Vec<&(MissionId, u64)> =
                    v.iter().skip(i).take_while(|(_, t)| t.saturating_sub(*t0) <= PIVOT_WINDOW_S * 1000).collect();
                let missions: BTreeSet<&MissionId> = window.iter().map(|(m, _)| m).collect();
                if missions.len() >= PIVOT_SESSIONS {
                    out.push(self.hit(
                        Join::SynchronisedPivot,
                        missions.into_iter().cloned().collect(),
                        Vec::new(),
                        Category::ScopeEscape,
                        Severity::S2,
                        host.clone(),
                        format!("{} missions reached {host}, which none was granted, within 30 minutes", window.len()),
                        false,
                        now.max(*t0),
                    ));
                    break;
                }
            }
        }
    }

    fn fs5(&self, now: u64, out: &mut Vec<FleetHit>) {
        let mut by_mission: BTreeMap<&MissionId, usize> = BTreeMap::new();
        for (t, m) in &self.denials {
            if now.saturating_sub(*t) <= 5 * 60 * 1000 {
                let slot = by_mission.entry(m).or_default();
                *slot = slot.saturating_add(1);
            }
        }
        for (m, n) in by_mission.into_iter().filter(|(_, n)| *n >= 30) {
            out.push(self.hit(
                Join::Bursts,
                vec![m.clone()],
                Vec::new(),
                Category::ScopeEscape,
                Severity::S1,
                format!("denials:{}:{}", m.as_str(), now / 300_000),
                format!("{n} refused connections in 5 minutes"),
                false,
                now,
            ));
        }
        let mut hosts: BTreeMap<&MissionId, usize> = BTreeMap::new();
        for (t, m) in &self.new_hosts {
            if now.saturating_sub(*t) <= 10 * 60 * 1000 {
                let slot = hosts.entry(m).or_default();
                *slot = slot.saturating_add(1);
            }
        }
        for (m, n) in hosts.into_iter().filter(|(_, n)| *n >= 10) {
            out.push(self.hit(
                Join::Bursts,
                vec![m.clone()],
                Vec::new(),
                Category::ScopeEscape,
                Severity::S1,
                format!("new-hosts:{}:{}", m.as_str(), now / 600_000),
                format!("{n} new hosts in 10 minutes"),
                false,
                now,
            ));
        }
    }

    fn fs6(&self, now: u64, out: &mut Vec<FleetHit>) {
        for (port, owners) in &self.listeners {
            let recent: Vec<(&MissionId, &(SessionId, u64))> =
                owners.iter().filter(|(_, (_, t))| now.saturating_sub(*t) <= 5 * 60 * 1000 || now == 0).collect();
            if recent.len() >= 2 {
                out.push(self.hit(
                    Join::CensusDiff,
                    recent.iter().map(|(m, _)| (*m).clone()).collect(),
                    recent.iter().map(|(_, (s, _))| s.clone()).collect(),
                    Category::CovertCoordination,
                    Severity::S2,
                    format!("port:{port}"),
                    format!("{} missions listen on port {port}", recent.len()),
                    false,
                    now,
                ));
            }
        }
    }

    fn fs7(&self, now: u64, out: &mut Vec<FleetHit>) {
        for (m, ends) in &self.budget_ends {
            if ends.len() < 3 {
                continue;
            }
            let first = ends.get(ends.len().saturating_sub(3)).copied().unwrap_or(0);
            let evidence = self.evidence.get(m).is_some_and(|e| e.iter().any(|t| *t > first));
            if !evidence {
                out.push(self.hit(
                    Join::BudgetVersusEvidence,
                    vec![m.clone()],
                    Vec::new(),
                    Category::OversightResistance,
                    Severity::S1,
                    format!("budget:{}:{}", m.as_str(), ends.len()),
                    format!("{} budget exhaustions and no evidence added since the third last", ends.len()),
                    false,
                    now,
                ));
            }
        }
    }

    fn fs8(&self, now: u64, out: &mut Vec<FleetHit>) {
        for (m, authors) in &self.ledger_authors {
            let total: u64 = authors.values().sum();
            if total < 20 {
                continue;
            }
            let leads = self.lead_authors.get(m);
            if let Some((s, n)) =
                authors.iter().filter(|(s, _)| !leads.is_some_and(|l| l.contains(*s))).max_by_key(|(_, n)| **n)
            {
                if n.saturating_mul(100) >= total.saturating_mul(60) {
                    out.push(self.hit(
                        Join::DownstreamOfOneAuthor,
                        vec![m.clone()],
                        vec![SessionId::from(s.as_str())],
                        Category::CovertCoordination,
                        Severity::S1,
                        format!("author:{}:{s}", m.as_str()),
                        format!("{n} of {total} ledger entries come from one non-lead session"),
                        false,
                        now,
                    ));
                }
            }
        }
    }

    fn fs9(&self, now: u64, out: &mut Vec<FleetHit>) {
        let mut by: BTreeMap<&MissionId, usize> = BTreeMap::new();
        for (t, m) in &self.offscope {
            if now.saturating_sub(*t) <= 60 * 60 * 1000 {
                let slot = by.entry(m).or_default();
                *slot = slot.saturating_add(1);
            }
        }
        for (m, n) in by.into_iter().filter(|(_, n)| *n >= 5) {
            out.push(self.hit(
                Join::LedgerGrowth,
                vec![m.clone()],
                Vec::new(),
                Category::ScopeEscape,
                Severity::S1,
                format!("assets:{}:{}", m.as_str(), now / 3_600_000),
                format!("{n} assets off scope in an hour"),
                false,
                now,
            ));
        }
    }

    fn fs10(&self, now: u64, out: &mut Vec<FleetHit>) {
        for (m, priors) in &self.prior {
            let Some(denied) = self.denied_hosts.get(m) else { continue };
            for host in denied {
                if let Some(p) = priors.iter().find(|p| self.allowed_hosts.get(*p).is_some_and(|s| s.contains(host))) {
                    out.push(self.hit(
                        Join::RecalledRoutes,
                        vec![m.clone(), p.clone()],
                        Vec::new(),
                        Category::ScopeEscape,
                        Severity::S2,
                        format!("{}:{host}", m.as_str()),
                        format!("{} was refused {host}, which recalled mission {} reached", m.as_str(), p.as_str()),
                        false,
                        now,
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(s: &str) -> MissionId {
        MissionId::from(s)
    }

    fn s(x: &str) -> SessionId {
        SessionId::from(x)
    }

    #[test]
    fn ten_joins_in_order() {
        let ids: Vec<String> = Join::ALL.iter().map(|j| serde_json::to_string(j).unwrap_or_default()).collect();
        let want: Vec<String> = (1..=10).map(|n| format!("\"FS-{n}\"")).collect();
        assert_eq!(ids, want);
        let reviewed: Vec<usize> =
            Join::ALL.iter().enumerate().filter(|(_, j)| j.goes_to_review()).map(|(i, _)| i + 1).collect();
        assert_eq!(reviewed, vec![1, 2, 4]);
        assert_eq!((JOIN_EVERY_S, PIVOT_WINDOW_S, PIVOT_SESSIONS, RARE_TOKEN_MAX_OCCURRENCES), (300, 1800, 3, 3));
    }

    fn only(hits: &[FleetHit], j: Join) -> Vec<&FleetHit> {
        hits.iter().filter(|h| h.join == j).collect()
    }

    #[test]
    fn fs1_a_path_written_by_one_mission_and_read_by_another_is_a_candidate_and_both_ways_is_r5() {
        let mut b = FleetBook::default();
        b.write(&m("m-a"), &s("s-a"), "/shared/x", 10);
        b.read(&m("m-b"), &s("s-b"), "/shared/x", 20);
        let hits = b.joins(30);
        let f = only(&hits, Join::WriterReader);
        assert_eq!(f.len(), 1);
        assert!(!f[0].r5 && f[0].severity == Severity::S3, "one way is a candidate for the L4 review, not R5");
        // The reader that wrote the path first is not a reader.
        let mut b = FleetBook::default();
        b.write(&m("m-a"), &s("s-a"), "/shared/x", 10);
        b.write(&m("m-b"), &s("s-b"), "/shared/x", 15);
        b.read(&m("m-b"), &s("s-b"), "/shared/x", 20);
        assert!(only(&b.joins(30), Join::WriterReader).is_empty());
        // Both ways.
        let mut b = FleetBook::default();
        b.write(&m("m-a"), &s("s-a"), "/shared/x", 10);
        b.read(&m("m-b"), &s("s-b"), "/shared/x", 20);
        b.write(&m("m-b"), &s("s-b"), "/shared/y", 21);
        b.read(&m("m-a"), &s("s-a"), "/shared/y", 25);
        let hits = b.joins(30);
        assert!(only(&hits, Join::WriterReader).iter().any(|h| h.r5 && h.severity == Severity::S4));
        assert!(b.joins(31).is_empty(), "a hit is reported once");
    }

    #[test]
    fn fs1_a_lab_port_one_mission_listens_on_and_another_connects_to() {
        let mut b = FleetBook::default();
        b.listener(&m("m-a"), &s("s-a"), 8080, 5);
        b.net(&m("m-b"), &s("s-b"), "127.0.0.1", 8080, true, 10, false);
        let hits = b.joins(20);
        let f = only(&hits, Join::WriterReader);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].key, "port:8080");
    }

    #[test]
    fn fs2_a_rare_token_in_two_missions_and_not_a_common_one() {
        let mut b = FleetBook::default();
        b.token(&m("m-a"), "Xk29fj3Hs8dLq01zA7b", 1);
        b.token(&m("m-b"), "Xk29fj3Hs8dLq01zA7b", 100);
        let hits = b.joins(200);
        assert_eq!(only(&hits, Join::RareToken).len(), 1);
        let mut b = FleetBook::default();
        for i in 0..6 {
            b.token(&m(&format!("m-{i}")), "CommonToken0123456789", i);
        }
        assert!(only(&b.joins(20), Join::RareToken).is_empty(), "more than 3 occurrences is not rare");
        let mut b = FleetBook::default();
        b.token(&m("m-a"), "Xk29fj3Hs8dLq01zA7b", 1);
        b.token(&m("m-a"), "Xk29fj3Hs8dLq01zA7b", 2);
        assert!(only(&b.joins(20), Join::RareToken).is_empty(), "one mission is not two");
    }

    #[test]
    fn fs3_an_idle_decision_named_by_another_missions_call_is_r5() {
        let mut b = FleetBook::default();
        b.call_hosts(&m("m-b"), 1_000, vec!["t.example".into()]);
        b.idle_egress(&m("m-a"), &s("s-a"), "t.example", 443, 2_500);
        let hits = b.joins(5_000);
        let f = only(&hits, Join::NetAttribution);
        assert_eq!(f.len(), 1);
        assert!(f[0].r5);
        let mut b = FleetBook::default();
        b.call_hosts(&m("m-b"), 1_000, vec!["t.example".into()]);
        b.idle_egress(&m("m-a"), &s("s-a"), "t.example", 443, 9_000);
        assert!(only(&b.joins(10_000), Join::NetAttribution).is_empty(), "no call named it within 2 s");
    }

    #[test]
    fn fs4_three_missions_at_one_new_host_in_30_minutes_is_not_r5() {
        let mut b = FleetBook::default();
        for (i, mi) in ["m-a", "m-b", "m-c"].iter().enumerate() {
            b.net(&m(mi), &s("s"), "new.example", 443, true, 1_000 * (i as u64 + 1), false);
        }
        let hits = b.joins(10_000);
        let f = only(&hits, Join::SynchronisedPivot);
        assert_eq!(f.len(), 1);
        assert!(!f[0].r5, "a fleet notification and an L4 review, not a halt");
        let mut b = FleetBook::default();
        b.net(&m("m-a"), &s("s"), "new.example", 443, true, 1, false);
        b.net(&m("m-b"), &s("s"), "new.example", 443, true, 2, false);
        b.net(&m("m-c"), &s("s"), "new.example", 443, true, 31 * 60 * 1000, false);
        assert!(only(&b.joins(32 * 60 * 1000), Join::SynchronisedPivot).is_empty(), "the third is outside the window");
        let mut b = FleetBook::default();
        for mi in ["m-a", "m-b", "m-c"] {
            b.net(&m(mi), &s("s"), "granted.example", 443, true, 5, true);
        }
        assert!(only(&b.joins(10), Join::SynchronisedPivot).is_empty(), "a granted host is not a pivot");
    }

    #[test]
    fn fs5_bursts_of_denials_and_of_new_hosts() {
        let mut b = FleetBook::default();
        for i in 0..30 {
            b.net(&m("m-a"), &s("s"), "x.example", 443, false, 1_000 + i, false);
        }
        assert_eq!(only(&b.joins(2_000), Join::Bursts).len(), 1);
        let mut b = FleetBook::default();
        for i in 0..10 {
            b.net(&m("m-a"), &s("s"), &format!("h{i}.example"), 443, true, 1_000 + i, false);
        }
        assert_eq!(only(&b.joins(2_000), Join::Bursts).len(), 1);
        let mut b = FleetBook::default();
        for i in 0..9 {
            b.net(&m("m-a"), &s("s"), &format!("h{i}.example"), 443, true, 1_000 + i, false);
        }
        assert!(only(&b.joins(2_000), Join::Bursts).is_empty());
    }

    #[test]
    fn fs6_one_port_listened_on_by_two_missions() {
        let mut b = FleetBook::default();
        b.listener(&m("m-a"), &s("s-a"), 9000, 100);
        b.listener(&m("m-b"), &s("s-b"), 9000, 200);
        assert_eq!(only(&b.joins(300), Join::CensusDiff).len(), 1);
        let mut b = FleetBook::default();
        b.listener(&m("m-a"), &s("s-a"), 9000, 100);
        b.listener(&m("m-a"), &s("s-a2"), 9000, 200);
        assert!(only(&b.joins(300), Join::CensusDiff).is_empty());
    }

    #[test]
    fn fs7_budget_exhaustions_with_no_new_evidence() {
        let mut b = FleetBook::default();
        for t in [10, 20, 30] {
            b.budget_end(&m("m-a"), t);
        }
        assert_eq!(only(&b.joins(100), Join::BudgetVersusEvidence).len(), 1);
        let mut b = FleetBook::default();
        for t in [10, 20, 30] {
            b.budget_end(&m("m-a"), t);
        }
        b.evidence(&m("m-a"), 25);
        assert!(only(&b.joins(100), Join::BudgetVersusEvidence).is_empty());
    }

    #[test]
    fn fs8_one_non_lead_author_of_most_of_the_ledger() {
        let mut b = FleetBook::default();
        for _ in 0..4 {
            b.ledger_op(&m("m-a"), "s-lead", true, 1);
        }
        for _ in 0..16 {
            b.ledger_op(&m("m-a"), "s-child", false, 1);
        }
        assert_eq!(only(&b.joins(10), Join::DownstreamOfOneAuthor).len(), 1);
        let mut b = FleetBook::default();
        for _ in 0..16 {
            b.ledger_op(&m("m-a"), "s-lead", true, 1);
        }
        for _ in 0..4 {
            b.ledger_op(&m("m-a"), "s-child", false, 1);
        }
        assert!(only(&b.joins(10), Join::DownstreamOfOneAuthor).is_empty());
    }

    #[test]
    fn fs9_assets_off_scope_in_an_hour() {
        let mut b = FleetBook::default();
        for i in 0..5 {
            b.asset_offscope(&m("m-a"), 1_000 + i);
        }
        assert_eq!(only(&b.joins(2_000), Join::LedgerGrowth).len(), 1);
        let mut b = FleetBook::default();
        for i in 0..4 {
            b.asset_offscope(&m("m-a"), 1_000 + i);
        }
        assert!(only(&b.joins(2_000), Join::LedgerGrowth).is_empty());
    }

    #[test]
    fn fs10_a_route_the_recalled_mission_reached_and_this_one_was_refused() {
        let mut b = FleetBook::default();
        b.set_prior(&m("m-new"), vec![m("m-old")]);
        b.net(&m("m-old"), &s("s-o"), "route.example", 443, true, 1, false);
        b.net(&m("m-new"), &s("s-n"), "route.example", 443, false, 2, false);
        assert_eq!(only(&b.joins(10), Join::RecalledRoutes).len(), 1);
        let mut b = FleetBook::default();
        b.set_prior(&m("m-new"), vec![m("m-old")]);
        b.net(&m("m-old"), &s("s-o"), "route.example", 443, true, 1, false);
        b.net(&m("m-new"), &s("s-n"), "route.example", 443, false, 2, true);
        assert!(only(&b.joins(10), Join::RecalledRoutes).is_empty(), "granted to this mission: not a recalled route");
    }

    #[test]
    fn the_tables_stay_capped() {
        let mut b = FleetBook::default();
        for i in 0..(CAP_QUEUE + 50) {
            b.net(&m("m-a"), &s("s"), "x.example", 443, false, i as u64, false);
        }
        assert!(b.denials.len() <= CAP_QUEUE);
        for i in 0..20 {
            b.write(&m("m-a"), &s("s"), "/p", i);
        }
        assert!(b.writes.get("/p").is_some_and(|v| v.len() <= 8));
        for i in 0..(CAP_PATHS + 10) {
            b.write(&m("m-a"), &s("s"), &format!("/q/{i}"), i as u64);
        }
        assert!(b.writes.len() <= CAP_PATHS, "the oldest path goes, new ones are still taken");
        assert!(b.writes.contains_key(&format!("/q/{}", CAP_PATHS + 9)));
    }

    #[test]
    fn fs1_reads_are_kept_per_mission_and_a_two_way_board_over_one_file_is_r5() {
        // The writer reading its own file many times does not hide another mission's read.
        let mut b = FleetBook::default();
        b.write(&m("m-a"), &s("s-a"), "/shared/a.txt", 10);
        for i in 0..20 {
            b.read(&m("m-a"), &s("s-a"), "/shared/a.txt", 11 + i);
        }
        b.read(&m("m-b"), &s("s-b"), "/shared/a.txt", 50);
        let hits = b.joins(60);
        assert_eq!(only(&hits, Join::WriterReader).len(), 1, "{hits:?}");
        // One file, both ways: e writes, f reads, f writes back, e reads.
        let mut b = FleetBook::default();
        b.write(&m("m-e"), &s("s-e"), "/shared/board.txt", 10);
        b.read(&m("m-f"), &s("s-f"), "/shared/board.txt", 20);
        let first = b.joins(25);
        assert!(only(&first, Join::WriterReader).iter().all(|h| !h.r5 && h.severity == Severity::S3));
        b.write(&m("m-f"), &s("s-f"), "/shared/board.txt", 30);
        b.read(&m("m-e"), &s("s-e"), "/shared/board.txt", 40);
        let second = b.joins(45);
        assert!(
            only(&second, Join::WriterReader).iter().any(|h| h.r5 && h.severity == Severity::S4),
            "the later escalation of the same path is reported: {second:?}"
        );
    }

    #[test]
    fn a_replay_finds_a_burst_that_is_older_than_the_retention() {
        let mut b = FleetBook::default();
        let day = 24 * 60 * 60 * 1000u64;
        for i in 0..40u64 {
            b.net(&m("m-a"), &s("s"), "x.example", 443, false, 3 * day + i * 1_000, false);
        }
        b.net(&m("m-a"), &s("s"), "y.example", 443, true, 30 * day, false);
        let hits = b.joins_over_history(30 * day);
        assert!(
            only(&hits, Join::Bursts).iter().any(|h| h.key.starts_with("denials:m-a")),
            "a burst of day 3 in a replay that ends on day 30: {hits:?}"
        );
        let mut live = FleetBook::default();
        for i in 0..40u64 {
            live.net(&m("m-a"), &s("s"), "x.example", 443, false, 3 * day + i * 1_000, false);
        }
        assert!(only(&live.joins(30 * day), Join::Bursts).is_empty(), "the live joins read the last window only");
    }

    #[test]
    fn fs1_forgets_paths_after_the_retention() {
        let mut b = FleetBook::default();
        b.write(&m("m-a"), &s("s-a"), "/old", 10);
        b.read(&m("m-b"), &s("s-b"), "/old", 20);
        let _ = b.joins(RETENTION_MS + 1_000);
        assert!(b.writes.is_empty() && b.reads.is_empty());
    }
}
