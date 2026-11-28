//! `ferret monitor replay`: the tripwires over history, read-only (`docs/MONITOR.md` §4.8, §8.3).
//!
//! CONTRACT.
//!
//! - `run(paths, env, journal_key, opts)` builds a memory core (`Core::memory`: it writes no file, takes no lock, makes
//!   no `<home>/monitor` and no key) over the sessions of `paths`, reads every source from its start through the real
//!   cursors, runs the same tripwires and the fleet joins, and returns a `ReplayReport`. It opens each source for
//!   reading only. It reads `keys/journal.key` only when the caller passes it (`journal_key`); without it the ledgers are
//!   read unverified and the report says so.
//! - A record is judged by the authorization in force at its time (`Authorization::build` up to the record's
//!   timestamp), never by a grant that came later. The fleet scan runs once, at the end, on the clock of the newest
//!   record. A replay runs the sessions in directory order, so a counter that depends on the order of records across
//!   sessions of one mission (the 30-minute S1 window) is read in that order: the report says it.
//! - The report: per tripwire, the hits by severity, the missions and flags they fall in, the missions that would have
//!   been paused (a hit of S3 or more) and, when the caller gives known positives (`opts.positives`), its precision
//!   (the share of the missions it fired in that are positives) and recall (the share of positives it fired in);
//!   per cause precision from the operator's dispositions, when `<home>/monitor/log.jsonl` has them (read without
//!   being verified; the live monitor's own start verifies it); the would-be pauses per 100 active hours (flags of S3
//!   or more over the missions' active time: the budget clock where a session has one, else the time between records
//!   that are less than 10 minutes apart); the fleet joins by number; the gate rate, which is `not built` until M8; and
//!   the notes that bound what the numbers mean.
//! - `since_ms` keeps only the hits whose record is that recent; counters still read the whole history.
//! - `ReplayReport::lines()` is the text of `ferret monitor replay`, one table, in words (no colour alone).
//!
//! Tests required: a replay over a fixture home reports the hits of its sessions per tripwire and writes nothing under
//! the home; the would-be pauses and the active hours; precision and recall with positives; precision from
//! dispositions; the grant in force at the time of a record is the one that counts; `since_ms` filters.

use crate::monitor::core::{Core, CoreCfg};
use crate::monitor::engine::Env;
use crate::monitor::log::EntryKind;
use crate::monitor::taxonomy::Severity;
use crate::monitor::tripwire::{Start, TripwireId, TRIPWIRES};
use ferret_core::config::Paths;
use ferret_core::MissionId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct ReplayOpts {
    pub since_ms: Option<u64>,
    /// Missions known to be positives (the operator's list), for precision and recall.
    pub positives: BTreeSet<MissionId>,
}

/// One tripwire in the report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TwReport {
    pub id: String,
    pub name: String,
    /// `precision`, `mixed` or `shadow`.
    pub start: String,
    pub fired: u64,
    pub by_severity: [u64; 5],
    pub missions: u64,
    /// Distinct flags (S2 and above).
    pub flags: u64,
    /// Missions in which a hit of S3 or more fell: the missions it would have paused.
    pub would_pause_missions: u64,
    /// Hits that are a part of the §4.8 precision list.
    pub precision_list_hits: u64,
    /// Share of the missions it fired in that are known positives (None without positives or without hits).
    pub precision_vs_positives: Option<f64>,
    /// Share of the known positives it fired in (None without positives).
    pub recall_vs_positives: Option<f64>,
    /// Confirmed over confirmed plus false positives, from the operator's dispositions (None with none).
    pub precision_from_dispositions: Option<f64>,
    pub disposed: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JoinReport {
    pub join: String,
    pub hits: u64,
    pub r5: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayReport {
    pub sessions: u64,
    pub missions: u64,
    pub records: u64,
    pub net_decisions: u64,
    pub active_hours: f64,
    pub tripwires: Vec<TwReport>,
    pub fleet: Vec<JoinReport>,
    /// Flags of severity S3 or more: the pauses the monitor would have made once its causes are promoted.
    pub would_be_pauses: u64,
    pub would_be_pauses_per_100_active_hours: f64,
    pub missions_that_would_pause: u64,
    /// Missions whose pause the precision list alone would have made on day one.
    pub missions_paused_by_the_precision_list: u64,
    pub positives: u64,
    pub positives_caught: u64,
    pub gate: String,
    pub ledgers_verified: bool,
    pub faults: Vec<String>,
    pub notes: Vec<String>,
}

fn ratio(n: usize, d: usize) -> Option<f64> {
    (d > 0).then(|| n as f64 / d as f64)
}

/// The dispositions in the live monitor log: (flag id, disposition word).
fn dispositions(paths: &Paths) -> Vec<(String, String, Vec<String>)> {
    let path = paths.home.join(crate::monitor::log::DIR).join(crate::monitor::log::LOG_FILE);
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let mut causes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(e) = serde_json::from_str::<crate::monitor::log::Entry>(line) else { continue };
        match e.kind {
            EntryKind::Flag => {
                if let (Some(id), Some(cs)) =
                    (e.fields.get("flag").and_then(|v| v.as_str()), e.fields.get("causes").and_then(|v| v.as_array()))
                {
                    causes.insert(id.to_string(), cs.iter().filter_map(|c| c.as_str().map(str::to_string)).collect());
                }
            }
            EntryKind::Disposition => {
                if let (Some(f), Some(d)) = (
                    e.fields.get("flag").and_then(|v| v.as_str()),
                    e.fields.get("disposition").and_then(|v| v.as_str()),
                ) {
                    out.push((f.to_string(), d.to_string(), causes.get(f).cloned().unwrap_or_default()));
                }
            }
            _ => {}
        }
    }
    out
}

/// The `Env` of a ferret home as the CLI can read it without a daemon: its `config.toml` (the defaults when there is none),
/// its packs, and the infrastructure policy of the configuration (names are not resolved: the addresses of the box's
/// Docker host and of the model endpoints are the daemon's).
pub fn env_for_home(paths: &Paths) -> Result<Env, String> {
    let config = ferret_core::config::Config::load(&paths.config_file()).map_err(|e| e.to_string())?;
    let packs = crate::pack::Packs::load(&paths.packs_dir())?;
    let infra = ferret_net::Policy::new(&config.network)
        .and_then(|p| p.with_infrastructure(&crate::runtime::infra_spec(&config)))
        .ok()
        .map(Arc::new);
    Ok(Env::from_config(&config, paths, &packs, infra))
}

/// Replay the history of `paths` (see the contract).
pub fn run(paths: &Paths, env: Arc<Env>, journal_key: Option<Vec<u8>>, opts: &ReplayOpts) -> ReplayReport {
    let verified = journal_key.is_some();
    let mut core = Core::memory(paths, env, CoreCfg { fleet_every_ms: u64::MAX, enabled: true }, journal_key);
    core.drain();
    let since = opts.since_ms.unwrap_or(0);
    // Per tripwire number.
    #[derive(Default)]
    struct Acc {
        fired: u64,
        by_sev: [u64; 5],
        missions: BTreeSet<String>,
        flags: BTreeSet<(String, String, String)>,
        pause_missions: BTreeSet<String>,
        precision_hits: u64,
    }
    let mut acc: BTreeMap<u8, Acc> = BTreeMap::new();
    let mut pause_flags: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut pause_missions: BTreeSet<String> = BTreeSet::new();
    let mut precision_missions: BTreeSet<String> = BTreeSet::new();
    let mut joins: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for e in core.memory_entries() {
        let text = |k: &str| e.fields.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        match e.kind {
            EntryKind::Tripwire => {
                let at = e.fields.get("at_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                if at < since {
                    continue;
                }
                let Some(n) = TripwireId::parse(&text("id")).map(|t| t.number()) else { continue };
                let sev: Severity = e
                    .fields
                    .get("severity")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or(Severity::S1);
                let a = acc.entry(n).or_default();
                a.fired = a.fired.saturating_add(1);
                let slot = match sev {
                    Severity::S0 => 0,
                    Severity::S1 => 1,
                    Severity::S2 => 2,
                    Severity::S3 => 3,
                    Severity::S4 => 4,
                };
                if let Some(c) = a.by_sev.get_mut(slot) {
                    *c = c.saturating_add(1);
                }
                a.missions.insert(text("mission"));
                let precision = e.fields.get("precision").and_then(|v| v.as_bool()).unwrap_or(false);
                if precision {
                    a.precision_hits = a.precision_hits.saturating_add(1);
                }
                let flag = (text("mission"), text("category"), text("key"));
                if sev >= Severity::S2 {
                    a.flags.insert(flag.clone());
                }
                if sev >= Severity::S3 {
                    a.pause_missions.insert(text("mission"));
                    pause_flags.insert(flag);
                    pause_missions.insert(text("mission"));
                    if precision {
                        precision_missions.insert(text("mission"));
                    }
                }
            }
            EntryKind::Response => {
                for c in e
                    .fields
                    .get("causes")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c.as_str())
                    .filter(|c| c.starts_with("FS-"))
                {
                    let slot = joins.entry(c.to_string()).or_default();
                    slot.0 = slot.0.saturating_add(1);
                    if text("would") == "r5" {
                        slot.1 = slot.1.saturating_add(1);
                    }
                }
            }
            _ => {}
        }
    }
    let disp = dispositions(paths);
    let positives = &opts.positives;
    let mut tws = Vec::new();
    for t in TRIPWIRES.iter() {
        let a = acc.remove(&t.number).unwrap_or_default();
        let id = TripwireId::of(t.number).to_string();
        let (confirmed, false_pos) = disp.iter().filter(|(_, _, causes)| causes.contains(&id)).fold(
            (0usize, 0usize),
            |(c, f), (_, d, _)| match d.as_str() {
                "false_positive" => (c, f.saturating_add(1)),
                "confirm" | "confirmed" => (c.saturating_add(1), f),
                _ => (c, f),
            },
        );
        let fired_in: BTreeSet<&String> = a.missions.iter().collect();
        let in_pos = a.missions.iter().filter(|m| positives.contains(&MissionId::from(m.as_str()))).count();
        let recall = if positives.is_empty() {
            None
        } else {
            ratio(positives.iter().filter(|p| fired_in.contains(&p.as_str().to_string())).count(), positives.len())
        };
        tws.push(TwReport {
            id,
            name: t.name.to_string(),
            start: match t.start {
                Start::Precision => "precision",
                Start::Mixed => "mixed",
                Start::Shadow => "shadow",
            }
            .into(),
            fired: a.fired,
            by_severity: a.by_sev,
            missions: a.missions.len() as u64,
            flags: a.flags.len() as u64,
            would_pause_missions: a.pause_missions.len() as u64,
            precision_list_hits: a.precision_hits,
            precision_vs_positives: if positives.is_empty() { None } else { ratio(in_pos, a.missions.len()) },
            recall_vs_positives: recall,
            precision_from_dispositions: ratio(confirmed, confirmed.saturating_add(false_pos)),
            disposed: confirmed.saturating_add(false_pos) as u64,
        });
    }
    let missions = core.missions();
    let active_ms: u64 = missions.keys().map(|m| core.active_ms(m)).sum();
    let hours = active_ms as f64 / 3_600_000.0;
    let would = pause_flags.len() as u64;
    let any_hit: BTreeSet<String> = core
        .memory_entries()
        .iter()
        .filter(|e| e.kind == EntryKind::Tripwire)
        .filter_map(|e| e.fields.get("mission").and_then(|v| v.as_str()).map(str::to_string))
        .collect();
    let caught_any = positives.iter().filter(|p| any_hit.contains(p.as_str())).count();
    let mut faults: Vec<String> = core.status(true, "shadow").faults;
    faults.sort();
    let sessions = core.status(true, "shadow").sources;
    let counts = core.counts().clone();
    let mut notes = vec![
        "Every cause is shadow: nothing was paused, steered or refused. \"Would pause\" means a hit of S3 or more.".to_string(),
        "Each record is judged by the authorization in force at its time; sessions are read in directory order, so the 30-minute S1 window of one mission is read in that order.".to_string(),
        "The gate (L1) is not built before M8; the reviewer is not built before M6.".to_string(),
    ];
    if !verified {
        notes.push("The ledgers were read without the journal key, so they are not verified.".to_string());
    }
    if positives.is_empty() {
        notes.push(
            "No known positives were given (--positives), so precision and recall against them are not reported."
                .to_string(),
        );
    }
    if disp.is_empty() {
        notes
            .push("The monitor log holds no dispositions, so precision from dispositions is not reported.".to_string());
    }
    ReplayReport {
        sessions,
        missions: missions.len() as u64,
        records: counts.records,
        net_decisions: counts.net,
        active_hours: hours,
        tripwires: tws,
        fleet: joins.into_iter().map(|(join, (hits, r5))| JoinReport { join, hits, r5 }).collect(),
        would_be_pauses: would,
        would_be_pauses_per_100_active_hours: if hours > 0.0 { would as f64 * 100.0 / hours } else { 0.0 },
        missions_that_would_pause: pause_missions.len() as u64,
        missions_paused_by_the_precision_list: precision_missions.len() as u64,
        positives: positives.len() as u64,
        positives_caught: caught_any as u64,
        gate: "not built (M8): no gated call was classified".to_string(),
        ledgers_verified: verified,
        faults,
        notes,
    }
}

fn pct(v: Option<f64>) -> String {
    v.map_or("-".to_string(), |x| format!("{:.0}%", x * 100.0))
}

impl ReplayReport {
    /// The text `ferret monitor replay` prints.
    pub fn lines(&self) -> Vec<String> {
        let mut l = vec![
            format!(
                "replayed {} sessions of {} missions: {} records, {} net decisions, {:.1} active hours",
                self.sessions, self.missions, self.records, self.net_decisions, self.active_hours
            ),
            format!(
                "would-be pauses (flags of S3 or more): {} = {:.1} per 100 active hours, in {} missions; the precision list alone would have paused {} missions",
                self.would_be_pauses, self.would_be_pauses_per_100_active_hours, self.missions_that_would_pause, self.missions_paused_by_the_precision_list
            ),
        ];
        if self.positives > 0 {
            l.push(format!("known positives: {} of {} had at least one hit", self.positives_caught, self.positives));
        }
        l.push(String::new());
        l.push(format!(
            "{:<6} {:<34} {:<9} {:>6} {:>5} {:>5} {:>7} {:>6} {:>6} {:>6}",
            "id", "tripwire", "starts", "fired", "S2+", "S3+", "missions", "prec.", "recall", "disp."
        ));
        for t in &self.tripwires {
            let sev = |i: usize| t.by_severity.get(i).copied().unwrap_or(0);
            let s3 = sev(3).saturating_add(sev(4));
            let s2 = s3.saturating_add(sev(2));
            l.push(format!(
                "{:<6} {:<34} {:<9} {:>6} {:>5} {:>5} {:>7} {:>6} {:>6} {:>6}",
                t.id,
                t.name,
                t.start,
                t.fired,
                s2,
                s3,
                t.missions,
                pct(t.precision_vs_positives),
                pct(t.recall_vs_positives),
                pct(t.precision_from_dispositions)
            ));
        }
        if !self.fleet.is_empty() {
            l.push(String::new());
            l.push("fleet joins:".to_string());
            for j in &self.fleet {
                l.push(format!("  {}: {} hit(s), {} that would halt a cohort", j.join, j.hits, j.r5));
            }
        }
        l.push(String::new());
        l.push(format!("gate: {}", self.gate));
        for f in &self.faults {
            l.push(format!("source fault: {f}"));
        }
        for n in &self.notes {
            l.push(format!("note: {n}"));
        }
        l
    }
}

#[cfg(test)]
mod tests;
