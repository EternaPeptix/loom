//! Model lineage and reviewer eligibility (`docs/MONITOR.md` section 2.6). Built by M1.
//!
//! CONTRACT.
//!
//! - **What a profile is.** `loom_core::lineage` resolves each `[models.<p>]` to a `Lineage` (family set, alignment,
//!   recipient, and where each came from; the inference rules, the loopback rule and the normalization of names are its
//!   contract). This module re-exports it and adds the rules that decide who may review whom. `lineages_of(config)` is the
//!   table of every profile. A `Lineage` is recorded in `session_start` (`ModelRef::lineage`).
//! - **Reachable set P of a mission** (`reachable_profiles(config, packs, lead, pack, role_models)`): the lead's profile,
//!   and, for every role of the pack (a role the mission could start, verifiers included), its `model`,
//!   `escalation_model` and every `alloy_models` entry, and every profile `role_models` maps a role to. Sorted, without
//!   repeats. A pack that is not loaded, or a name that is not a configured profile, is an `Err` that names it. A role
//!   with no `model` inherits its parent's profile, which is in P already.
//! - **Eligibility** (`eligible(reviewer, &Request)`): `Ok(used)` when the reviewer may review a mission whose sessions
//!   run the profiles `request.reached`, listing the overrides it needed; else the first failing clause as `Ineligible`,
//!   checked in this order:
//!   1. `UnknownRecipient`: the reviewer's recipient is unknown or empty. Never overridable.
//!   2. `NotStock`: the reviewer's alignment is not `stock` (a relaxed or an undeclared one). Never overridable.
//!   3. `SameFamily`: the reviewer's family set meets the family set of any reached profile; an unknown family (empty)
//!      meets every family, and an empty `reached` is read as an unknown profile.
//!   4. `NewRecipient`: the reviewer's recipient is neither `local` nor `lan`, is not the recipient of **every** session
//!      whose data the review includes (`data_recipients`, non-empty; this is the intersection rule), and is not in
//!      `consented` (the pack's `[monitor.recipients]` list).
//!   5. `Unreachable`: `Facts::reachable` is false (health probe and heartbeat).
//!   6. `Unvetted`: `Facts::needs_vet` (the review would clear a gate or a reopen) and not `Facts::vetted` (a passing vet
//!      record for the model id the reviewer currently serves).
//!
//!   Clauses 3, 4 and 6 can be met by a live override of the same kind (`OverrideKind::{SameFamily, NewRecipient,
//!   Unvetted}`: non-empty reason, `now_ms < expires_ms`, default lifetime `OVERRIDE_TTL_MS` = 7 days). **No override
//!   counts** when a reached profile counts as a relaxed agent (`Lineage::counts_as_relaxed_agent`: alignment not
//!   declared `stock`), and none ever covers clauses 1, 2 or an empty reviewer list, so a relaxed profile is never a
//!   reviewer and "no reviewer" cannot be overridden. There is no global `allow_new_recipient`. `Ineligible::sentence`
//!   says what to change.
//! - **Selection** (`select(order, lineages, &Request, exclude)` to `Selection`): `order` is `[monitor] reviewers`.
//!   `mission` is the first profile of `order`, not in `exclude`, eligible for the whole reached set (with
//!   `request.data_recipients`). `per_profile` holds, for each reached profile, the first profile of `order` eligible
//!   for that profile alone (its own recipient as the data recipient), or `None`. A mission without `mission` has
//!   no mission-level review and no keep-going (`Selection::mission_level`). After a fault the caller selects again with
//!   the faulted profile in `exclude`: the next profile is chosen by the same rules, so it is never outside the allowed
//!   recipients. `select_with_verifier` adds a verifier's profile to the reached set and the data recipients before
//!   selecting: a verifier that collides with the reviewer re-chooses the reviewer, it never refuses the verifier.
//! - **No eligible reviewer** (`check_config(config, packs)`, used by `loom config check`; `coverage` and `describe_all`,
//!   used by `loom models show`): for every agent profile (not `purpose = "review"`) and every pack, the reviewers of
//!   `select` with the pack's consent and `Facts::STATIC` (reachable, no vet needed). The `Report` has `table` (one
//!   line per profile: the resolved values and where each came from; `loom config check` prints it), `problems` (each
//!   ends with the exact lines to add) and `notes`. A problem is: an agent profile not in `tripwires_only_profiles` whose
//!   family or recipient is unknown (the sentence says to declare it); a profile of `reviewers` whose family, alignment
//!   (must be declared `stock`) or recipient is not declared; an agent profile not in `tripwires_only_profiles` that
//!   has, in some pack, no reviewer for itself, with the three choices (consent to the first reviewer that fails only on
//!   its recipient, a stock model of another family on a host the operator owns, or the profile in
//!   `tripwires_only_profiles`), each with its lines. A note: an agent profile with an unknown alignment (it counts as
//!   relaxed); a profile with no reviewer for the whole mission of a pack but one of its own (mission-level review and
//!   keep-going unavailable); a profile in `tripwires_only_profiles` (shown as "not LLM-reviewed"); a review profile not
//!   in `reviewers`. `creation_refusal(config, packs, profile, pack)` is the sentence for refusing a mission of
//!   `profile` in `pack` at creation (`None` when it has a reviewer or is listed); the daemon uses it for real-target
//!   missions once the monitor is on (M2); lab missions are never refused by it.
//! - `show_lines(config, packs, only)` is `loom models show`: `describe_all`'s line of each profile, and under an agent
//!   profile one line per pack: `reviewed by X`, `reviewed by X per session only (…)`, `not LLM-reviewed (tripwires only,
//!   by your choice)` or `no eligible reviewer: …`; an unknown profile name is an `Err` listing the profiles.
//! - **Who the reviewer is not**: relaxed profiles. `Config::check` already refuses one in `reviewers`.
//! - The §2.6 assignment table is a selection test over the operator's fleet; so is "a non-DeepSeek fleet never reaches
//!   `qwen4max` while `dsv41_review` is eligible".
//!
//! Not built here: reachability and vet records (M2, M6 supply `Facts`), the monitor's configuration in `session_start`
//! (M2), the mid-mission re-choice on `loom models set` and the refusal of a spawn that collides with the reviewer (they
//! need the model switching of the ui work, `docs/MONITOR.md` section 9.2).
//!
//! Tests required: inference (in `loom_core::lineage`); every clause with a failing and a passing case; overrides (live,
//! expired, empty reason, never on a relaxed agent, never for clauses 1 and 2); the intersection rule; selection order,
//! fallback never leaving the allowed recipients, a colliding verifier re-choosing; the reachable set from a pack with role
//! models; the §2.6 table over the operator's fleet; `check_config` failing with the lines to add and passing once the
//! lines are added; the shipped example parses and passes.

use crate::pack::Packs;
use loom_core::config::{Config, ProfilePurpose};
pub use loom_core::lineage::{normalize_name, resolve, Alignment, FieldSources, Lineage, Source, FAMILIES};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How long an override lives when its giver names no end: 7 days.
pub const OVERRIDE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// Why a reviewer is not eligible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ineligible {
    SameFamily,
    NotStock,
    NewRecipient,
    UnknownRecipient,
    Unreachable,
    Unvetted,
}

impl Ineligible {
    /// A sentence for the operator: what is wrong with `reviewer` and what to change.
    pub fn sentence(&self, reviewer: &str) -> String {
        match self {
            Ineligible::SameFamily => format!(
                "{reviewer} shares a model family with a profile the mission can reach, so it would review its own kin. Choose a reviewer of another family."
            ),
            Ineligible::NotStock => format!(
                "{reviewer} is not declared alignment = \"stock\" (a relaxed or undeclared model is never a reviewer). Declare it under [models.{reviewer}] only if its refusals are intact; otherwise choose another reviewer."
            ),
            Ineligible::NewRecipient => format!(
                "{reviewer} would send transcripts to a provider that does not already receive them. Consent to that recipient for the pack under [monitor.recipients], or choose a reviewer on a host you own."
            ),
            Ineligible::UnknownRecipient => format!(
                "The recipient of {reviewer} is unknown (a loopback base_url could be a tunnel to anyone). Declare recipient = \"local\", \"lan\" or the provider's name under [models.{reviewer}]."
            ),
            Ineligible::Unreachable => {
                format!("{reviewer} is not reachable. Start it or choose another reviewer; nothing was cleared.")
            }
            Ineligible::Unvetted => format!(
                "{reviewer} has no passing vet record for the model it serves now, so it cannot clear a gate or a reopen. Run its vet, or answer the held item yourself."
            ),
        }
    }
}

/// What an override covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideKind {
    SameFamily,
    NewRecipient,
    Unvetted,
}

/// A typed, expiring operator override, given with the CLI bearer token and recorded in the monitor log (M2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Override {
    pub kind: OverrideKind,
    pub reason: String,
    /// Wall-clock milliseconds at which it stops counting.
    pub expires_ms: u64,
}

impl Override {
    /// True while it has a reason and has not expired.
    pub fn live(&self, now_ms: u64) -> bool {
        now_ms < self.expires_ms && !self.reason.trim().is_empty()
    }
}

/// What the runtime knows about a reviewer at the time of the question (clauses 5 and 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub reachable: bool,
    /// The review would clear a gate or a reopen.
    pub needs_vet: bool,
    /// A passing vet record exists for the model id the reviewer serves now.
    pub vetted: bool,
}

impl Facts {
    /// What a configuration check can say: reachable, and no clearing is asked of the reviewer.
    pub const STATIC: Facts = Facts { reachable: true, needs_vet: false, vetted: false };
}

/// One eligibility question.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    /// The profiles of the sessions the review covers and of everything else they can reach.
    pub reached: &'a [Lineage],
    /// The recipient of each session whose data the review includes.
    pub data_recipients: &'a [String],
    /// The pack's `[monitor.recipients]` list.
    pub consented: &'a [String],
    pub overrides: &'a [Override],
    pub now_ms: u64,
    /// What is known of a reviewer, by profile name.
    pub facts: &'a dyn Fn(&str) -> Facts,
}

/// The recipients of `reached`, one per profile.
pub fn recipients_of(reached: &[Lineage]) -> Vec<String> {
    reached.iter().map(|l| l.recipient.clone()).collect()
}

/// Is `reviewer` eligible for the review `req` asks about? `Ok` lists the overrides it needed.
pub fn eligible(reviewer: &Lineage, req: &Request) -> Result<Vec<OverrideKind>, Ineligible> {
    if reviewer.recipient_is_unknown() {
        return Err(Ineligible::UnknownRecipient);
    }
    if reviewer.alignment != Alignment::Stock {
        return Err(Ineligible::NotStock);
    }
    let relaxed_agent = req.reached.iter().any(Lineage::counts_as_relaxed_agent);
    let mut used = Vec::new();
    let mut overridden = |kind: OverrideKind| -> bool {
        let live = !relaxed_agent && req.overrides.iter().any(|o| o.kind == kind && o.live(req.now_ms));
        if live && !used.contains(&kind) {
            used.push(kind);
        }
        live
    };
    let same_family = req.reached.is_empty() || req.reached.iter().any(|p| reviewer.shares_family(p));
    if same_family && !overridden(OverrideKind::SameFamily) {
        return Err(Ineligible::SameFamily);
    }
    let me = normalize_name(&reviewer.recipient);
    let same_as_data = !req.data_recipients.is_empty() && req.data_recipients.iter().all(|d| normalize_name(d) == me);
    let consent = req.consented.iter().any(|c| normalize_name(c) == me);
    if !(reviewer.is_operator_owned() || same_as_data || consent || overridden(OverrideKind::NewRecipient)) {
        return Err(Ineligible::NewRecipient);
    }
    let facts = (req.facts)(&reviewer.profile);
    if !facts.reachable {
        return Err(Ineligible::Unreachable);
    }
    if facts.needs_vet && !facts.vetted && !overridden(OverrideKind::Unvetted) {
        return Err(Ineligible::Unvetted);
    }
    Ok(used)
}

/// Who reviews what, for one mission.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Selection {
    /// The reviewer eligible for the whole mission, if there is one.
    pub mission: Option<String>,
    /// The overrides the mission-level choice needed.
    pub mission_overrides: Vec<OverrideKind>,
    /// For each reached profile, the reviewer eligible for that profile alone.
    pub per_profile: BTreeMap<String, Option<String>>,
}

impl Selection {
    /// True when mission-level reviews (and keep-going) are available.
    pub fn mission_level(&self) -> bool {
        self.mission.is_some()
    }

    /// The reviewer of a session on `profile`: the mission's, else its own.
    pub fn reviewer_for(&self, profile: &str) -> Option<&str> {
        self.mission.as_deref().or_else(|| self.per_profile.get(profile).and_then(|r| r.as_deref()))
    }

    /// Reached profiles that no reviewer covers.
    pub fn unreviewed(&self) -> Vec<&str> {
        self.per_profile
            .iter()
            .filter(|(_, own)| own.is_none() && self.mission.is_none())
            .map(|(p, _)| p.as_str())
            .collect()
    }
}

/// Choose reviewers from `order` (`[monitor] reviewers`) for the review `req` asks about, leaving out `exclude`
/// (profiles that just faulted).
pub fn select(order: &[String], lineages: &BTreeMap<String, Lineage>, req: &Request, exclude: &[String]) -> Selection {
    let candidates: Vec<&Lineage> =
        order.iter().filter(|n| !exclude.contains(n)).filter_map(|n| lineages.get(n)).collect();
    let mut out = Selection::default();
    for c in &candidates {
        if let Ok(used) = eligible(c, req) {
            out.mission = Some(c.profile.clone());
            out.mission_overrides = used;
            break;
        }
    }
    for p in req.reached {
        if out.per_profile.contains_key(&p.profile) {
            continue;
        }
        let own_recipients = [p.recipient.clone()];
        let own = Request { reached: std::slice::from_ref(p), data_recipients: &own_recipients, ..*req };
        let pick = candidates.iter().find(|c| eligible(c, &own).is_ok()).map(|c| c.profile.clone());
        out.per_profile.insert(p.profile.clone(), pick);
    }
    out
}

/// `select` after adding a verifier's profile to what the mission reaches: a verifier that collides with the chosen
/// reviewer changes the reviewer, and is never itself refused.
pub fn select_with_verifier(
    order: &[String],
    lineages: &BTreeMap<String, Lineage>,
    req: &Request,
    verifier: &Lineage,
    exclude: &[String],
) -> Selection {
    let mut reached = req.reached.to_vec();
    if !reached.iter().any(|l| l.profile == verifier.profile) {
        reached.push(verifier.clone());
    }
    let mut data = req.data_recipients.to_vec();
    data.push(verifier.recipient.clone());
    select(order, lineages, &Request { reached: &reached, data_recipients: &data, ..*req }, exclude)
}

/// The lineage of every profile of the configuration.
pub fn lineages_of(config: &Config) -> BTreeMap<String, Lineage> {
    config.models.iter().map(|(name, p)| (name.clone(), resolve(name, p))).collect()
}

/// The profiles a mission led by `lead` in `pack` can reach (see the contract). `role_models` maps a role to the profile
/// the operator chose for it.
pub fn reachable_profiles(
    config: &Config,
    packs: &Packs,
    lead: &str,
    pack: &str,
    role_models: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    let p = packs
        .get(pack)
        .ok_or_else(|| format!("There is no pack \"{pack}\". Packs available: {}.", packs.names().join(", ")))?;
    let mut names: BTreeSet<String> = BTreeSet::new();
    names.insert(lead.to_string());
    for role in p.roles.values() {
        names.extend(role.model.iter().cloned());
        names.extend(role.escalation_model.iter().cloned());
        names.extend(role.alloy_models.iter().cloned());
    }
    names.extend(role_models.values().cloned());
    for n in &names {
        if !config.models.contains_key(n) {
            return Err(format!(
                "The mission of pack \"{pack}\" can reach the model profile \"{n}\", which is not configured. Add [models.{n}] or change the role that names it."
            ));
        }
    }
    Ok(names.into_iter().collect())
}

/// The consent list of `pack` (pack names compare normalized).
fn consent_of<'a>(config: &'a Config, pack: &str) -> &'a [String] {
    let want = normalize_name(pack);
    config.monitor.recipients.iter().find(|(k, _)| normalize_name(k) == want).map_or(&[][..], |(_, v)| v.as_slice())
}

/// Who reviews one agent profile in one pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub profile: String,
    pub pack: String,
    /// The reached set of a mission led by `profile` in `pack`.
    pub reached: Vec<String>,
    /// The reviewer for the whole mission.
    pub whole: Option<String>,
    /// The reviewer for the profile's own sessions.
    pub own: Option<String>,
}

fn static_facts(_: &str) -> Facts {
    Facts::STATIC
}

/// The configuration's agent profiles (not `purpose = "review"`).
fn agent_profiles(config: &Config) -> impl Iterator<Item = &String> {
    config.models.iter().filter(|(_, p)| p.purpose != Some(ProfilePurpose::Review)).map(|(n, _)| n)
}

/// For every agent profile and every pack: its reviewers (`Facts::STATIC`, the pack's consent, no overrides).
pub fn coverage(config: &Config, packs: &Packs) -> Result<Vec<Row>, String> {
    let lineages = lineages_of(config);
    let mut rows = Vec::new();
    for profile in agent_profiles(config) {
        for pack in packs.names() {
            let reached_names = reachable_profiles(config, packs, profile, &pack, &BTreeMap::new())?;
            let reached: Vec<Lineage> = reached_names.iter().filter_map(|n| lineages.get(n).cloned()).collect();
            let data = recipients_of(&reached);
            let req = Request {
                reached: &reached,
                data_recipients: &data,
                consented: consent_of(config, &pack),
                overrides: &[],
                now_ms: 0,
                facts: &static_facts,
            };
            let sel = select(&config.monitor.reviewers, &lineages, &req, &[]);
            let own = sel.per_profile.get(profile).cloned().flatten();
            rows.push(Row { profile: profile.clone(), pack, reached: reached_names, whole: sel.mission, own });
        }
    }
    Ok(rows)
}

/// `["a", "b"]`.
fn toml_list(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|i| format!("\"{i}\"")).collect::<Vec<_>>().join(", "))
}

/// The three ways out for a profile that has no reviewer in `pack`, each with the lines to add.
fn choices(config: &Config, lineages: &BTreeMap<String, Lineage>, profile: &str, pack: &str) -> String {
    let own = lineages.get(profile).cloned();
    let own_list: Vec<Lineage> = own.iter().cloned().collect();
    let data = recipients_of(&own_list);
    // The first reviewer that fails only on its recipient: consent would make it eligible.
    let consent_to = config.monitor.reviewers.iter().filter_map(|n| lineages.get(n)).find_map(|c| {
        let all = [c.recipient.clone()];
        let req = Request {
            reached: &own_list,
            data_recipients: &data,
            consented: &all,
            overrides: &[],
            now_ms: 0,
            facts: &static_facts,
        };
        (eligible(c, &Request { consented: &[], ..req }) == Err(Ineligible::NewRecipient) && eligible(c, &req).is_ok())
            .then(|| (c.profile.clone(), c.recipient.clone()))
    });
    let mut consent_line = String::new();
    if let Some((reviewer, recipient)) = consent_to {
        let mut list: Vec<String> = consent_of(config, pack).to_vec();
        list.push(recipient.clone());
        consent_line = format!(
            "(1) Consent to the provider that would review it: {reviewer} is eligible once the {pack} pack may send transcripts to \"{recipient}\". Add\n    [monitor.recipients]\n    {pack} = {}\n  (for a mission with real targets only features are sent, `[monitor.content] new_recipient_real_targets`).\n",
            toml_list(&list)
        );
    }
    let families: BTreeSet<String> = own.iter().flat_map(|l| l.family.iter().cloned()).collect();
    let mut listed = config.monitor.tripwires_only_profiles.clone();
    listed.push(profile.to_string());
    format!(
        "{consent_line}({}) Run a stock model of another family than {} on a host you own: add a profile with alignment = \"stock\", recipient = \"lan\" (or \"local\") and its family, and list it under `reviewers` in [monitor].\n({}) Accept tripwires only, on purpose (missions of {profile} are then shown as \"not LLM-reviewed\"). Add\n    [monitor]\n    tripwires_only_profiles = {}",
        if consent_line.is_empty() { "1" } else { "2" },
        if families.is_empty() { "this profile's".to_string() } else { families.into_iter().collect::<Vec<_>>().join(" or ") },
        if consent_line.is_empty() { "2" } else { "3" },
        toml_list(&listed),
    )
}

/// The sentence that refuses a mission of `profile` in `pack` that has no eligible reviewer, naming the three choices;
/// `None` when it has one, when the profile is listed in `tripwires_only_profiles`, or when it is not configured.
pub fn creation_refusal(config: &Config, packs: &Packs, profile: &str, pack: &str) -> Option<String> {
    if config.monitor.tripwires_only_profiles.iter().any(|p| p == profile) || !config.models.contains_key(profile) {
        return None;
    }
    let rows = coverage(config, packs).ok()?;
    let row = rows.iter().find(|r| r.profile == profile && r.pack == pack)?;
    if row.own.is_some() {
        return None;
    }
    let lineages = lineages_of(config);
    Some(format!(
        "No reviewer is eligible for {profile} in the {pack} pack, and a mission with real targets is not run unreviewed by accident. Choose one and restart the daemon:\n{}",
        choices(config, &lineages, profile, pack)
    ))
}

/// What `loom config check` found: the table to print, what fails it, and what to know.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Report {
    pub table: Vec<String>,
    pub problems: Vec<String>,
    pub notes: Vec<String>,
}

/// One line per profile for `loom config check` and `loom models show`.
pub fn describe_all(config: &Config) -> Vec<String> {
    let lineages = lineages_of(config);
    config
        .models
        .iter()
        .map(|(name, p)| {
            let l = lineages.get(name).map_or_else(String::new, Lineage::describe);
            let role = if p.purpose == Some(ProfilePurpose::Review) { "review profile" } else { "agent profile" };
            let trip = if config.monitor.tripwires_only_profiles.contains(name) { ", tripwires only" } else { "" };
            format!("{name}: {l} [{role}{trip}]")
        })
        .collect()
}

/// What `loom models show` prints: each profile's resolved values, and for an agent profile, who reviews its missions
/// in each pack. `only` names one profile; an unknown one is an `Err` that lists them.
pub fn show_lines(config: &Config, packs: &Packs, only: Option<&str>) -> Result<Vec<String>, String> {
    if let Some(name) = only {
        if !config.models.contains_key(name) {
            let names: Vec<&str> = config.models.keys().map(String::as_str).collect();
            return Err(format!("There is no model profile \"{name}\". Profiles: {}.", names.join(", ")));
        }
    }
    let rows = coverage(config, packs)?;
    let mut out = Vec::new();
    for line in describe_all(config) {
        let name = line.split(':').next().unwrap_or("").to_string();
        if only.is_some_and(|o| o != name) {
            continue;
        }
        out.push(line);
        for row in rows.iter().filter(|r| r.profile == name) {
            let listed = config.monitor.tripwires_only_profiles.contains(&name);
            let who = match (&row.own, &row.whole, listed) {
                (Some(r), Some(w), _) if r == w => format!("reviewed by {r}"),
                (Some(r), None, _) => format!("reviewed by {r} per session only (no one reviewer covers {}; no mission-level review, no keep-going)", row.reached.join(", ")),
                (Some(r), Some(w), _) => format!("reviewed by {w} (its own sessions by {r})"),
                (None, _, true) => "not LLM-reviewed (tripwires only, by your choice)".to_string(),
                (None, _, false) => "no eligible reviewer: `loom config check` says what to add".to_string(),
            };
            out.push(format!("  {}: {who}", row.pack));
        }
    }
    Ok(out)
}

/// Check the model policy of `config` against `packs` (see the contract).
pub fn check_config(config: &Config, packs: &Packs) -> Report {
    let lineages = lineages_of(config);
    let mut report = Report { table: describe_all(config), ..Report::default() };
    let tripwires = &config.monitor.tripwires_only_profiles;
    let reviewers = &config.monitor.reviewers;
    for (name, p) in &config.models {
        let Some(l) = lineages.get(name) else { continue };
        if reviewers.contains(name) {
            if l.family.is_empty() {
                report.problems.push(format!(
                    "models.{name} is a reviewer but its family is unknown, so it matches every family and would never be eligible. Declare it, for example\n    [models.{name}]\n    family = [\"qwen\"]    # one of: {}",
                    FAMILIES.join(", ")
                ));
            }
            if l.alignment != Alignment::Stock {
                report.problems.push(format!(
                    "models.{name} is a reviewer but its alignment is {}. A reviewer must be declared stock (its refusals intact):\n    [models.{name}]\n    alignment = \"stock\"",
                    l.alignment.word()
                ));
            }
            if l.recipient_is_unknown() {
                report.problems.push(format!(
                    "models.{name} is a reviewer but its recipient is unknown. Declare who receives its traffic:\n    [models.{name}]\n    recipient = \"lan\"    # or \"local\", or the provider's name"
                ));
            }
        }
        if p.purpose == Some(ProfilePurpose::Review) {
            if !reviewers.contains(name) {
                report.notes.push(format!("models.{name} has purpose = \"review\" but is not listed under [monitor] reviewers, so nothing uses it."));
            }
            continue;
        }
        if tripwires.contains(name) {
            report.notes.push(format!("{name}: not LLM-reviewed (listed in [monitor] tripwires_only_profiles): only the deterministic tripwires watch its missions."));
            continue;
        }
        let mut declared_ok = true;
        if l.family.is_empty() {
            declared_ok = false;
            report.problems.push(format!(
                "models.{name}: the family is unknown (the model id \"{}\" names none), so no reviewer can be shown to be unrelated. Declare it:\n    [models.{name}]\n    family = [\"deepseek\"]    # one of: {}; a distill lists both",
                p.model,
                FAMILIES.join(", ")
            ));
        }
        if l.recipient_is_unknown() {
            declared_ok = false;
            report.problems.push(format!(
                "models.{name}: the recipient is unknown (a loopback base_url could be a tunnel to anyone's cloud). Declare who receives its traffic:\n    [models.{name}]\n    recipient = \"lan\"    # \"local\" for this machine, \"lan\" for a host you own, or the provider's name"
            ));
        }
        if l.alignment == Alignment::Unknown {
            report.notes.push(format!("{name}: alignment is unknown, so its agents count as relaxed (stricter review, no overrides). Declare alignment = \"stock\" if its refusals are intact."));
        }
        if !declared_ok {
            continue;
        }
        let Ok(rows) = coverage(config, packs) else { continue };
        for row in rows.iter().filter(|r| &r.profile == name) {
            if row.own.is_none() {
                report.problems.push(format!(
                    "models.{name} has no eligible reviewer in the {} pack, so its missions would be watched by tripwires alone without anyone choosing that. Choose one:\n{}",
                    row.pack,
                    choices(config, &lineages, name, &row.pack)
                ));
            } else if row.whole.is_none() {
                report.notes.push(format!(
                    "{name}: in the {} pack no one reviewer is eligible for everything its missions can reach ({}), so each session is reviewed on its own; mission-level review and keep-going are unavailable.",
                    row.pack,
                    row.reached.join(", ")
                ));
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lin(profile: &str, family: &[&str], alignment: Alignment, recipient: &str) -> Lineage {
        Lineage {
            profile: profile.into(),
            family: family.iter().map(|s| s.to_string()).collect(),
            alignment,
            recipient: recipient.into(),
            source: Source::Declared,
            fields: FieldSources { family: Source::Declared, alignment: Source::Declared, recipient: Source::Declared },
        }
    }

    fn stock(profile: &str, family: &[&str], recipient: &str) -> Lineage {
        lin(profile, family, Alignment::Stock, recipient)
    }

    fn up(_: &str) -> Facts {
        Facts { reachable: true, needs_vet: false, vetted: false }
    }

    fn req<'a>(reached: &'a [Lineage], data: &'a [String], consented: &'a [String]) -> Request<'a> {
        Request { reached, data_recipients: data, consented, overrides: &[], now_ms: 1_000, facts: &up }
    }

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| i.to_string()).collect()
    }

    fn ov(kind: OverrideKind, expires_ms: u64) -> Override {
        Override { kind, reason: "the operator asked".into(), expires_ms }
    }

    #[test]
    fn parsing_and_forms() {
        assert_eq!(serde_json::to_string(&Alignment::Relaxed).unwrap_or_default(), "\"relaxed\"");
        assert!(serde_json::from_str::<Alignment>("\"uncensored\"").is_err());
        assert_eq!(serde_json::to_string(&Ineligible::SameFamily).unwrap_or_default(), "\"same_family\"");
        assert_eq!(serde_json::to_string(&OverrideKind::NewRecipient).unwrap_or_default(), "\"new_recipient\"");
        let a = stock("dsv41", &["deepseek"], "lan");
        let b = stock("qwen4max", &["qwen"], "alibaba");
        let distill = stock("distill", &["deepseek", "qwen"], "lan");
        assert!(a.is_operator_owned() && !b.is_operator_owned());
        assert!(!a.shares_family(&b));
        assert!(distill.shares_family(&a) && distill.shares_family(&b));
        assert!(stock("unk", &[], "unknown").shares_family(&a), "an unknown family matches every family");
    }

    #[test]
    fn names_are_compared_normalized() {
        let qwen_agent = stock("qwen", &["qwen"], "lan");
        assert!(stock("r", &["Qwen"], "alibaba").shares_family(&qwen_agent));
        assert!(stock("r", &[" qwen "], "alibaba").shares_family(&qwen_agent));
        let tm = stock("inkling", &["thinking-machines"], "lan");
        assert!(stock("r", &["thinking_machines"], "x").shares_family(&tm));
        assert!(!stock("r", &["Mistral"], "x").shares_family(&qwen_agent));
        assert!(
            stock("r", &["qwen"], " LAN ").is_operator_owned() && stock("r", &["qwen"], "Local").is_operator_owned()
        );
        assert_eq!(normalize_name(" Thinking_Machines "), "thinking-machines");
    }

    #[test]
    fn clause_one_the_recipient_must_be_known() {
        let agent = [stock("dsv41", &["deepseek"], "lan")];
        for r in ["unknown", "", " Unknown "] {
            let reviewer = stock("r", &["qwen"], r);
            assert_eq!(
                eligible(&reviewer, &req(&agent, &s(&["lan"]), &s(&["unknown", ""]))),
                Err(Ineligible::UnknownRecipient)
            );
        }
        let live = [ov(OverrideKind::NewRecipient, 9_999)];
        let reviewer = stock("r", &["qwen"], "unknown");
        let lan = s(&["lan"]);
        let r = Request { overrides: &live, ..req(&agent, &lan, &[]) };
        assert_eq!(
            eligible(&reviewer, &r),
            Err(Ineligible::UnknownRecipient),
            "no override covers an unknown recipient"
        );
    }

    #[test]
    fn clause_two_the_reviewer_must_be_declared_stock() {
        let agent = [stock("dsv41", &["deepseek"], "lan")];
        let data = s(&["lan"]);
        assert_eq!(eligible(&stock("r", &["qwen"], "lan"), &req(&agent, &data, &[])), Ok(vec![]));
        for a in [Alignment::Relaxed, Alignment::Unknown] {
            let r = lin("r", &["qwen"], a, "lan");
            assert_eq!(eligible(&r, &req(&agent, &data, &[])), Err(Ineligible::NotStock));
            let all = [
                ov(OverrideKind::SameFamily, 9_999),
                ov(OverrideKind::NewRecipient, 9_999),
                ov(OverrideKind::Unvetted, 9_999),
            ];
            let with = Request { overrides: &all, ..req(&agent, &data, &[]) };
            assert_eq!(
                eligible(&r, &with),
                Err(Ineligible::NotStock),
                "a relaxed or undeclared reviewer cannot be overridden in"
            );
        }
    }

    #[test]
    fn clause_three_families_must_be_disjoint() {
        let data = s(&["lan"]);
        let reviewer = stock("r", &["qwen"], "lan");
        let ok = [stock("a", &["deepseek"], "lan"), stock("b", &["glm"], "lan")];
        assert_eq!(eligible(&reviewer, &req(&ok, &data, &[])), Ok(vec![]));
        let bad = [stock("a", &["deepseek"], "lan"), stock("b", &["qwen", "llama"], "lan")];
        assert_eq!(
            eligible(&reviewer, &req(&bad, &data, &[])),
            Err(Ineligible::SameFamily),
            "every profile of P counts"
        );
        let unknown = [stock("a", &[], "lan")];
        assert_eq!(
            eligible(&reviewer, &req(&unknown, &data, &[])),
            Err(Ineligible::SameFamily),
            "unknown meets every family"
        );
        assert_eq!(eligible(&stock("r", &[], "lan"), &req(&ok, &data, &[])), Err(Ineligible::SameFamily));
        assert_eq!(
            eligible(&reviewer, &req(&[], &data, &[])),
            Err(Ineligible::SameFamily),
            "no profiles is an unknown one"
        );
        let spaced = [stock("a", &["QWEN "], "lan")];
        assert_eq!(eligible(&reviewer, &req(&spaced, &data, &[])), Err(Ineligible::SameFamily));
    }

    #[test]
    fn clause_four_a_new_recipient_needs_the_intersection_or_consent_or_an_override() {
        let reviewer = stock("qwen4max", &["qwen"], "alibaba");
        let on_lan = [stock("dsv41", &["deepseek"], "lan")];
        let lan = s(&["lan"]);
        assert_eq!(eligible(&reviewer, &req(&on_lan, &lan, &[])), Err(Ineligible::NewRecipient));
        assert_eq!(
            eligible(&reviewer, &req(&on_lan, &lan, &s(&["Alibaba"]))),
            Ok(vec![]),
            "consent, compared normalized"
        );
        assert_eq!(eligible(&reviewer, &req(&on_lan, &lan, &s(&["mistral"]))), Err(Ineligible::NewRecipient));
        // The same provider already receives every session's data: no new recipient.
        let on_ali = [stock("dseekv41", &["deepseek"], "alibaba"), stock("dseek4pro", &["deepseek"], "alibaba")];
        assert_eq!(eligible(&reviewer, &req(&on_ali, &s(&["alibaba", "alibaba"]), &[])), Ok(vec![]));
        // Only one of the two sessions' data is at that provider: not an intersection.
        assert_eq!(eligible(&reviewer, &req(&on_ali, &s(&["alibaba", "lan"]), &[])), Err(Ineligible::NewRecipient));
        assert_eq!(
            eligible(&reviewer, &req(&on_ali, &[], &[])),
            Err(Ineligible::NewRecipient),
            "no data recipients: no intersection"
        );
        // An override that is live covers it, an expired one or one without a reason does not.
        let live = [ov(OverrideKind::NewRecipient, 2_000)];
        assert_eq!(
            eligible(&reviewer, &Request { overrides: &live, ..req(&on_lan, &lan, &[]) }),
            Ok(vec![OverrideKind::NewRecipient])
        );
        let expired = [ov(OverrideKind::NewRecipient, 1_000)];
        assert_eq!(
            eligible(&reviewer, &Request { overrides: &expired, ..req(&on_lan, &lan, &[]) }),
            Err(Ineligible::NewRecipient)
        );
        let no_reason = [Override { kind: OverrideKind::NewRecipient, reason: "  ".into(), expires_ms: 9_999 }];
        assert_eq!(
            eligible(&reviewer, &Request { overrides: &no_reason, ..req(&on_lan, &lan, &[]) }),
            Err(Ineligible::NewRecipient)
        );
        let other_kind = [ov(OverrideKind::SameFamily, 9_999)];
        assert_eq!(
            eligible(&reviewer, &Request { overrides: &other_kind, ..req(&on_lan, &lan, &[]) }),
            Err(Ineligible::NewRecipient)
        );
    }

    #[test]
    fn clauses_five_and_six_reachable_and_vetted() {
        let agent = [stock("dsv41", &["deepseek"], "lan")];
        let data = s(&["lan"]);
        let reviewer = stock("r", &["qwen"], "lan");
        let down = |_: &str| Facts { reachable: false, needs_vet: false, vetted: false };
        assert_eq!(
            eligible(&reviewer, &Request { facts: &down, ..req(&agent, &data, &[]) }),
            Err(Ineligible::Unreachable)
        );
        let unvetted = |_: &str| Facts { reachable: true, needs_vet: true, vetted: false };
        assert_eq!(
            eligible(&reviewer, &Request { facts: &unvetted, ..req(&agent, &data, &[]) }),
            Err(Ineligible::Unvetted)
        );
        let vetted = |_: &str| Facts { reachable: true, needs_vet: true, vetted: true };
        assert_eq!(eligible(&reviewer, &Request { facts: &vetted, ..req(&agent, &data, &[]) }), Ok(vec![]));
        let not_needed = |_: &str| Facts { reachable: true, needs_vet: false, vetted: false };
        assert_eq!(
            eligible(&reviewer, &Request { facts: &not_needed, ..req(&agent, &data, &[]) }),
            Ok(vec![]),
            "a vet is asked only to clear"
        );
        let live = [ov(OverrideKind::Unvetted, 2_000)];
        assert_eq!(
            eligible(&reviewer, &Request { facts: &unvetted, overrides: &live, ..req(&agent, &data, &[]) }),
            Ok(vec![OverrideKind::Unvetted])
        );
        // Facts are asked per reviewer.
        let only_a = |n: &str| Facts { reachable: n == "a", needs_vet: false, vetted: false };
        let a = stock("a", &["qwen"], "lan");
        let b = stock("b", &["qwen"], "lan");
        let r = Request { facts: &only_a, ..req(&agent, &data, &[]) };
        assert!(eligible(&a, &r).is_ok() && eligible(&b, &r) == Err(Ineligible::Unreachable));
    }

    #[test]
    fn an_override_covers_a_family_clash_but_never_on_a_relaxed_agent() {
        let reviewer = stock("r", &["deepseek"], "lan");
        let data = s(&["lan"]);
        let live = [ov(OverrideKind::SameFamily, 9_999)];
        let stock_agent = [stock("dsv41", &["deepseek"], "lan")];
        assert_eq!(
            eligible(&reviewer, &Request { overrides: &live, ..req(&stock_agent, &data, &[]) }),
            Ok(vec![OverrideKind::SameFamily])
        );
        for relaxed in
            [lin("n", &["deepseek"], Alignment::Relaxed, "lan"), lin("n", &["deepseek"], Alignment::Unknown, "lan")]
        {
            let reached = [stock("dsv41", &["deepseek"], "lan"), relaxed];
            assert_eq!(
                eligible(&reviewer, &Request { overrides: &live, ..req(&reached, &data, &[]) }),
                Err(Ineligible::SameFamily),
                "a mission with a relaxed agent takes no override"
            );
        }
    }

    #[test]
    fn every_failure_has_a_sentence_that_says_what_to_do() {
        for e in [
            Ineligible::SameFamily,
            Ineligible::NotStock,
            Ineligible::NewRecipient,
            Ineligible::UnknownRecipient,
            Ineligible::Unreachable,
            Ineligible::Unvetted,
        ] {
            let t = e.sentence("qwen4max");
            assert!(t.contains("qwen4max") && t.ends_with('.') && t.len() > 40, "{t}");
        }
        assert!(Ineligible::NewRecipient.sentence("x").contains("[monitor.recipients]"));
    }

    fn fleet_config(extra_monitor: &str) -> Config {
        let text = format!(
            r#"
default_model = "dsv41"
[models.dsv41]
base_url = "http://10.0.0.5:8000/v1"
model = "deepseek-v4.1"
family = ["deepseek"]
alignment = "stock"
recipient = "lan"
[models.dsv41_review]
base_url = "http://10.0.0.5:8000/v1"
model = "deepseek-v4.1"
purpose = "review"
family = ["deepseek"]
alignment = "stock"
recipient = "lan"
[models.dseekv41]
base_url = "https://token-plan.maas.qwencloudapi.com/v1"
model = "deepseek-v4.1"
family = ["deepseek"]
alignment = "stock"
recipient = "alibaba"
[models.dseek4pro]
base_url = "https://token-plan.maas.qwencloudapi.com/v1"
model = "deepseek-v4-pro"
family = ["deepseek"]
alignment = "stock"
recipient = "alibaba"
[models.qwen]
base_url = "https://token-plan.maas.qwencloudapi.com/v1"
model = "qwen4-max-preview"
family = ["qwen"]
alignment = "stock"
recipient = "alibaba"
[models.qwen4max]
base_url = "https://token-plan.ap-southeast-1.maas.aliyuncs.com/v1"
model = "qwen4-max"
family = ["qwen"]
alignment = "stock"
recipient = "alibaba"
[models.necromicon]
base_url = "http://10.0.0.6:8000/v1"
model = "kimi-k2-abliterated"
family = ["kimi"]
alignment = "relaxed"
recipient = "lan"
[models.glm_unc]
base_url = "http://10.0.0.7:8000/v1"
model = "glm-5-uncensored"
family = ["glm"]
alignment = "relaxed"
recipient = "lan"
[models.mistral]
base_url = "https://api.mistral.ai/v1"
model = "mistral-large"
alignment = "stock"
recipient = "mistral"
[models.inklingv5]
base_url = "http://127.0.0.1:9000/v1"
model = "inkling-v5"
recipient = "thinking-machines"
[monitor]
reviewers = ["dsv41_review", "qwen4max", "mistral"]
{extra_monitor}
"#
        );
        let c = Config::parse(&text).unwrap_or_else(|e| panic!("{e}"));
        c.check().unwrap_or_else(|e| panic!("{e}"));
        c
    }

    fn consent_alibaba() -> &'static str {
        "[monitor.recipients]\nctf = [\"alibaba\"]\ncore = [\"alibaba\"]\nharnessmm = [\"alibaba\"]\nredteam = [\"alibaba\"]\nvr = [\"alibaba\"]\n"
    }

    fn pick(c: &Config, packs: &Packs, profile: &str, pack: &str) -> Row {
        let rows = coverage(c, packs).unwrap_or_else(|e| panic!("{e}"));
        rows.into_iter().find(|r| r.profile == profile && r.pack == pack).unwrap_or_else(|| panic!("{profile}"))
    }

    fn repo_packs() -> Packs {
        Packs::load(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../packs")))
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn the_assignment_table_for_the_operators_fleet() {
        let c = fleet_config(consent_alibaba());
        let packs = repo_packs();
        assert!(packs.get("ctf").is_some() && packs.get("core").is_some());
        for pack in ["core", "ctf"] {
            // dsv41 shares its family with dsv41_review: the consented hosted reviewer takes it.
            let r = pick(&c, &packs, "dsv41", pack);
            assert_eq!((r.own.as_deref(), r.whole.as_deref()), (Some("qwen4max"), Some("qwen4max")), "dsv41 in {pack}");
            // DeepSeek on Alibaba: the same provider already receives the transcripts.
            for p in ["dseekv41", "dseek4pro"] {
                let r = pick(&c, &packs, p, pack);
                assert_eq!(r.own.as_deref(), Some("qwen4max"), "{p}");
            }
            // Every other fleet is reviewed on the LAN, and never reaches qwen4max while dsv41_review is eligible.
            for p in ["qwen", "qwen4max", "necromicon", "glm_unc", "mistral", "inklingv5"] {
                let r = pick(&c, &packs, p, pack);
                assert_eq!(r.own.as_deref(), Some("dsv41_review"), "{p} in {pack}");
                assert_eq!(r.whole.as_deref(), Some("dsv41_review"), "{p} in {pack}");
            }
        }
        // The reviewer profile is not an agent: no row.
        let rows = coverage(&c, &packs).unwrap_or_else(|e| panic!("{e}"));
        assert!(rows.iter().all(|r| r.profile != "dsv41_review"));
    }

    #[test]
    fn without_consent_dsv41_has_no_reviewer_and_dseek_on_alibaba_still_has_one() {
        let c = fleet_config("");
        let packs = repo_packs();
        assert_eq!(pick(&c, &packs, "dsv41", "core").own, None);
        assert_eq!(pick(&c, &packs, "dseekv41", "core").own.as_deref(), Some("qwen4max"));
        assert_eq!(pick(&c, &packs, "qwen", "core").own.as_deref(), Some("dsv41_review"));
    }

    #[test]
    fn fallback_after_a_fault_never_leaves_the_allowed_recipients() {
        let c = fleet_config(consent_alibaba());
        let lineages = lineages_of(&c);
        let order = c.monitor.reviewers.clone();
        let necro = [lineages["necromicon"].clone()];
        let data = recipients_of(&necro);
        let consent = s(&["alibaba"]);
        let first = select(&order, &lineages, &req(&necro, &data, &consent), &[]);
        assert_eq!(first.mission.as_deref(), Some("dsv41_review"));
        // dsv41_review faults: the next in the list is qwen4max, which the pack consented to.
        let second = select(&order, &lineages, &req(&necro, &data, &consent), &s(&["dsv41_review"]));
        assert_eq!(second.mission.as_deref(), Some("qwen4max"));
        // Both fault: mistral's recipient is not consented to, so there is no third.
        let third = select(&order, &lineages, &req(&necro, &data, &consent), &s(&["dsv41_review", "qwen4max"]));
        assert_eq!(third.mission, None, "mistral is a new recipient nobody consented to");
        assert!(!third.mission_level() && third.unreviewed() == vec!["necromicon"]);
        // Without the consent the hosted reviewer is not available at all after the LAN one faults.
        let none = select(&order, &lineages, &req(&necro, &data, &[]), &s(&["dsv41_review"]));
        assert_eq!(none.mission, None);
        assert_eq!(none.reviewer_for("necromicon"), None);
    }

    #[test]
    fn a_colliding_verifier_re_chooses_the_reviewer() {
        let c = fleet_config(consent_alibaba());
        let lineages = lineages_of(&c);
        let order = c.monitor.reviewers.clone();
        let lead = [lineages["qwen"].clone()];
        let data = recipients_of(&lead);
        let consent = s(&["alibaba"]);
        let before = select(&order, &lineages, &req(&lead, &data, &consent), &[]);
        assert_eq!(before.mission.as_deref(), Some("dsv41_review"));
        // The pack's verifier runs on a DeepSeek profile: dsv41_review is now related to it.
        let verifier = lineages["dseekv41"].clone();
        let after = select_with_verifier(&order, &lineages, &req(&lead, &data, &consent), &verifier, &[]);
        assert_eq!(after.mission, None, "qwen4max shares the lead's family and dsv41_review the verifier's");
        assert!(after.per_profile.contains_key("dseekv41"), "the verifier is covered, not refused");
        assert_eq!(
            after.per_profile["qwen"].as_deref(),
            Some("dsv41_review"),
            "the lead alone is still reviewed on the LAN"
        );
        assert_eq!(after.per_profile["dseekv41"].as_deref(), Some("qwen4max"));
        // A verifier of a third family changes nothing.
        let third = lineages["glm_unc"].clone();
        let same = select_with_verifier(&order, &lineages, &req(&lead, &data, &consent), &third, &[]);
        assert_eq!(same.mission.as_deref(), Some("dsv41_review"));
    }

    fn pack_with_role_models(dir: &std::path::Path) -> Packs {
        let core = dir.join("core");
        std::fs::create_dir_all(core.join("roles")).unwrap_or_else(|e| panic!("{e}"));
        let toml = include_str!("../../../../packs/core/pack.toml")
            .replacen("\"request_scope\", \"conclude\", ", "", 1)
            .replace("[roles.worker]", "[roles.worker]\nmodel = \"mistral\"\nalloy_models = [\"qwen\", \"glm_unc\"]\nescalation_model = \"necromicon\"");
        std::fs::write(core.join("pack.toml"), toml).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(core.join("harness.md"), include_str!("../../../../packs/core/harness.md"))
            .unwrap_or_else(|e| panic!("{e}"));
        for (name, text) in [
            ("lead", include_str!("../../../../packs/core/roles/lead.md")),
            ("worker", include_str!("../../../../packs/core/roles/worker.md")),
            ("verifier", include_str!("../../../../packs/core/roles/verifier.md")),
            ("chat", include_str!("../../../../packs/core/roles/chat.md")),
        ] {
            std::fs::write(core.join("roles").join(format!("{name}.md")), text).unwrap_or_else(|e| panic!("{e}"));
        }
        Packs::load(dir).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn the_reachable_set_holds_the_lead_role_models_escalation_alloy_and_overrides() {
        let c = fleet_config("");
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let packs = pack_with_role_models(dir.path());
        let got = reachable_profiles(&c, &packs, "dsv41", "core", &BTreeMap::new()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(got, s(&["dsv41", "glm_unc", "mistral", "necromicon", "qwen"]));
        let mut roles = BTreeMap::new();
        roles.insert("verifier".to_string(), "dseekv41".to_string());
        let got = reachable_profiles(&c, &packs, "dsv41", "core", &roles).unwrap_or_else(|e| panic!("{e}"));
        assert!(got.contains(&"dseekv41".to_string()));
        let e = reachable_profiles(&c, &packs, "dsv41", "nope", &BTreeMap::new()).unwrap_err();
        assert!(e.contains("\"nope\"") && e.contains("core"), "{e}");
        roles.insert("worker".to_string(), "ghost".to_string());
        let e = reachable_profiles(&c, &packs, "dsv41", "core", &roles).unwrap_err();
        assert!(e.contains("\"ghost\"") && e.contains("[models.ghost]"), "{e}");
        // A mission led by a DeepSeek profile that can reach a Qwen alloy has no reviewer of both families on the LAN
        // except one outside them: mistral is hosted and not consented to, so only per-session review is left.
        let rows = coverage(&c, &packs).unwrap_or_else(|e| panic!("{e}"));
        let r = rows.iter().find(|r| r.profile == "dsv41" && r.pack == "core").unwrap_or_else(|| panic!("row"));
        assert_eq!(r.reached, s(&["dsv41", "glm_unc", "mistral", "necromicon", "qwen"]));
        assert_eq!(r.whole, None);
    }

    #[test]
    fn config_check_fails_without_a_reviewer_and_prints_the_lines_to_add() {
        let c = fleet_config("");
        let packs = repo_packs();
        let report = check_config(&c, &packs);
        let joined = report.problems.join("\n---\n");
        assert!(
            report.problems.iter().any(|p| p.starts_with("models.dsv41 has no eligible reviewer in the core pack")),
            "{joined}"
        );
        assert!(
            joined.contains("[monitor.recipients]\n    core = [\"alibaba\"]"),
            "the consent that fixes it: {joined}"
        );
        assert!(joined.contains("tripwires_only_profiles = [\"dsv41\"]"), "{joined}");
        assert!(joined.contains("alignment = \"stock\", recipient = \"lan\""), "{joined}");
        assert!(joined.contains("(1)") && joined.contains("(2)") && joined.contains("(3)"), "{joined}");
        assert!(
            !report.problems.iter().any(|p| p.starts_with("models.qwen ") || p.starts_with("models.necromicon")),
            "{joined}"
        );
        assert_eq!(report.table.len(), c.models.len());
        assert!(report.table.iter().any(|l| l
            .starts_with("dsv41: family deepseek (declared), alignment stock (declared), recipient lan (declared)")));
        assert!(report.table.iter().any(|l| l.contains("[review profile]")));
    }

    #[test]
    fn config_check_passes_once_the_lines_are_added() {
        let packs = repo_packs();
        // Choice 1: the consent.
        let report = check_config(&fleet_config(consent_alibaba()), &packs);
        assert_eq!(report.problems, Vec::<String>::new());
        // Choice 3: the explicit list. dsv41 is then a note, and shown as not LLM-reviewed.
        let report = check_config(&fleet_config("tripwires_only_profiles = [\"dsv41\"]"), &packs);
        assert_eq!(report.problems, Vec::<String>::new());
        assert!(report.notes.iter().any(|n| n.starts_with("dsv41: not LLM-reviewed")), "{:?}", report.notes);
        assert!(describe_all(&fleet_config("tripwires_only_profiles = [\"dsv41\"]"))
            .iter()
            .any(|l| l.starts_with("dsv41:") && l.ends_with(", tripwires only]")));
    }

    #[test]
    fn config_check_names_undeclared_lineage() {
        let packs = repo_packs();
        let mut c = fleet_config(consent_alibaba());
        // inklingv5 without a recipient: loopback is unknown.
        if let Some(p) = c.models.get_mut("inklingv5") {
            p.recipient = None;
        }
        let report = check_config(&c, &packs);
        let j = report.problems.join("\n");
        assert!(j.contains("models.inklingv5: the recipient is unknown") && j.contains("recipient = \"lan\""), "{j}");
        // A profile whose family cannot be inferred.
        let mut c = fleet_config(consent_alibaba());
        if let Some(p) = c.models.get_mut("mistral") {
            p.model = "default".into();
        }
        let j = check_config(&c, &packs).problems.join("\n");
        assert!(j.contains("models.mistral: the family is unknown") && j.contains("family = [\"deepseek\"]"), "{j}");
        // A listed tripwires-only profile does not have to declare them.
        if let Some(p) = c.models.get_mut("mistral") {
            let _ = p;
        }
        c.monitor.tripwires_only_profiles.push("mistral".into());
        let rep = check_config(&c, &packs);
        assert!(!rep.problems.iter().any(|p| p.starts_with("models.mistral:")));
        // Alignment unknown on an agent is a note; on a reviewer it is a problem.
        let mut c = fleet_config(consent_alibaba());
        if let Some(p) = c.models.get_mut("inklingv5") {
            p.alignment = None;
        }
        let rep = check_config(&c, &packs);
        assert!(rep.notes.iter().any(|n| n.starts_with("inklingv5: alignment is unknown")), "{:?}", rep.notes);
        assert!(rep.problems.is_empty(), "{:?}", rep.problems);
        if let Some(p) = c.models.get_mut("qwen4max") {
            p.alignment = None;
        }
        let j = check_config(&c, &packs).problems.join("\n");
        assert!(
            j.contains("models.qwen4max is a reviewer but its alignment is unknown")
                && j.contains("alignment = \"stock\""),
            "{j}"
        );
    }

    #[test]
    fn a_default_config_with_one_local_profile_must_choose() {
        let packs = repo_packs();
        let c = Config::parse("[models.local]\nmodel = \"default\"\n").unwrap_or_else(|e| panic!("{e}"));
        let rep = check_config(&c, &packs);
        assert_eq!(rep.problems.len(), 2, "family and recipient: {:?}", rep.problems);
        let c =
            Config::parse("[models.local]\nmodel = \"default\"\n[monitor]\ntripwires_only_profiles = [\"local\"]\n")
                .unwrap_or_else(|e| panic!("{e}"));
        assert!(check_config(&c, &packs).problems.is_empty());
    }

    #[test]
    fn models_show_says_who_reviews_what() {
        let packs = repo_packs();
        let c = fleet_config(consent_alibaba());
        let all = show_lines(&c, &packs, None).unwrap_or_else(|e| panic!("{e}"));
        assert!(all.iter().any(|l| l == "  core: reviewed by qwen4max"));
        assert!(all.iter().any(|l| l.starts_with("dsv41_review: ") && l.ends_with("[review profile]")));
        let one = show_lines(&c, &packs, Some("necromicon")).unwrap_or_else(|e| panic!("{e}"));
        assert!(one[0]
            .starts_with("necromicon: family kimi (declared), alignment relaxed (declared), recipient lan (declared)"));
        assert!(one.iter().any(|l| l == "  ctf: reviewed by dsv41_review") && one.len() == 1 + packs.names().len());
        let e = show_lines(&c, &packs, Some("nope")).unwrap_err();
        assert!(e.contains("\"nope\"") && e.contains("dsv41"), "{e}");
        let bare = show_lines(&fleet_config(""), &packs, Some("dsv41")).unwrap_or_else(|e| panic!("{e}"));
        assert!(bare.iter().any(|l| l.starts_with("  core: no eligible reviewer")), "{bare:?}");
        let listed = show_lines(&fleet_config("tripwires_only_profiles = [\"dsv41\"]"), &packs, Some("dsv41"))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(listed.iter().any(|l| l == "  core: not LLM-reviewed (tripwires only, by your choice)"), "{listed:?}");
    }

    #[test]
    fn creation_refusal_names_the_three_choices() {
        let packs = repo_packs();
        let c = fleet_config("");
        let t = creation_refusal(&c, &packs, "dsv41", "core").unwrap_or_default();
        assert!(t.starts_with("No reviewer is eligible for dsv41 in the core pack"), "{t}");
        assert!(
            t.contains("(1)") && t.contains("(2)") && t.contains("(3)") && t.contains("core = [\"alibaba\"]"),
            "{t}"
        );
        assert_eq!(creation_refusal(&c, &packs, "qwen", "core"), None, "it has a reviewer");
        assert_eq!(creation_refusal(&c, &packs, "ghost", "core"), None);
        let listed = fleet_config("tripwires_only_profiles = [\"dsv41\"]");
        assert_eq!(creation_refusal(&listed, &packs, "dsv41", "core"), None, "an explicit choice");
        assert_eq!(creation_refusal(&fleet_config(consent_alibaba()), &packs, "dsv41", "ctf"), None);
        // A fleet with no hosted reviewer to consent to gets two choices, numbered 1 and 2.
        let mut c = fleet_config("");
        c.monitor.reviewers = s(&["dsv41_review"]);
        let t = creation_refusal(&c, &packs, "dsv41", "core").unwrap_or_default();
        assert!(
            !t.contains("(3)") && t.contains("(1) Run a stock model") && t.contains("(2) Accept tripwires only"),
            "{t}"
        );
    }

    #[test]
    fn mission_level_review_is_unavailable_when_no_one_reviewer_covers_everything() {
        let c = fleet_config("");
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let packs = pack_with_role_models(dir.path());
        // A mission led by DeepSeek-on-Alibaba can reach Mistral, Qwen, GLM and Kimi profiles through its roles: no
        // one reviewer is unrelated to all of them, but the lead's own sessions have one.
        let r = pick(&c, &packs, "dseekv41", "core");
        assert_eq!((r.whole.as_deref(), r.own.as_deref()), (None, Some("qwen4max")));
        let rep = check_config(&c, &packs);
        assert!(
            rep.notes.iter().any(|n| n.starts_with("dseekv41: in the core pack")
                && n.contains("mission-level review and keep-going are unavailable")),
            "{:?}",
            rep.notes
        );
        assert!(!rep.problems.iter().any(|p| p.starts_with("models.dseekv41")), "{:?}", rep.problems);
    }

    #[test]
    fn the_shipped_example_parses_and_passes() {
        let doc = include_str!("../../../../docs/config.example.toml");
        // The file as shipped is a valid configuration and checks clean.
        let shipped = Config::parse(doc).unwrap_or_else(|e| panic!("{e}"));
        shipped.check().unwrap_or_else(|e| panic!("{e}"));
        assert!(check_config(&shipped, &repo_packs()).problems.is_empty());
        let mut on = false;
        let mut block = String::new();
        for line in doc.lines() {
            if line.trim() == "# BEGIN worked example" {
                on = true;
            } else if line.trim() == "# END worked example" {
                on = false;
            } else if on {
                let l = line.strip_prefix("# ").or_else(|| line.strip_prefix('#')).unwrap_or(line);
                block.push_str(l);
                block.push('\n');
            }
        }
        assert!(!block.trim().is_empty(), "the example has a block between BEGIN and END worked example");
        let c = Config::parse(&block).unwrap_or_else(|e| panic!("{e}\n{block}"));
        c.check().unwrap_or_else(|e| panic!("{e}"));
        let packs = repo_packs();
        let rep = check_config(&c, &packs);
        assert!(rep.problems.is_empty(), "{:?}", rep.problems);
        let r = pick(&c, &packs, "dsv41", "core");
        assert_eq!(r.own.as_deref(), Some("qwen4max"));
        assert_eq!(pick(&c, &packs, "necromicon", "ctf").own.as_deref(), Some("dsv41_review"));
        assert_eq!(c.monitor.content.new_recipient_real_targets, loom_core::config::RecipientContent::Features);
        let l = lineages_of(&c);
        assert_eq!(l["inklingv5"].alignment, Alignment::Unknown);
        assert_eq!(l["glm_unc"].alignment, Alignment::Relaxed);
        assert!(!c.monitor.reviewers.iter().any(|r| r == "glm_unc" || r == "necromicon"));
    }
}
