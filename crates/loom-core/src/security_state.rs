//! Durable, evidence-linked security observations and deterministic projections.
//!
//! CONTRACT. `SecurityOp` is additive inside `LedgerOp::Security`; old journals and state snapshots
//! remain readable. Asset IDs hash a canonical kind/locator, credential IDs hash asset/principal/
//! secret handle, and foothold IDs hash asset/principal/access. Upserts merge evidence, never erase
//! it. Credentials contain handles, never secret material. A record is an observation, not authority
//! to contact an asset. All cited evidence must exist and be attested in the owning mission.
//!
//! Mandatory coverage is open until tested with evidence or deferred with a nonblank reason. Typed
//! conditions unblock claim/dead-end references only when every prerequisite is recorded. Crash
//! signatures retain frame-zero lines, omit caller lines, and exclude timeout/OOM/non-crash outcomes;
//! each signature retains its last six attempts. Hypothesis priority belongs to the lead; verdicts
//! belong to an independent read-only verifier, enforced by the runtime tool using authenticated
//! session capabilities. Every supported/refuted verdict cites evidence, with counterevidence for
//! refutation. Fresh counterevidence reopens a previously supported hypothesis.
//!
//! `projection`, `why`, and `what_if` implement finite, function-free, range-restricted stratified
//! Datalog (variables start `?`, no aggregates/arithmetic). Negation is absence, not evidence of
//! truth. Retractions rebuild the projection and expose disappeared conclusions; base observations
//! and historical hypotheses are preserved. Evaluation is bounded and reports incompleteness rather
//! than presenting a truncated closure as complete. See `security_state::causal`.
//!
//! `path_suggest` returns at most three weighted simple paths of at most eight hops, omits expired
//! edges, and discounts edges out of known footholds. These are prioritization hints over explicit
//! relations, never validated attack paths. Prefix resolution prefers exact IDs/aliases and refuses
//! ambiguous prefixes. All maps/outputs have deterministic ordering.

pub mod causal;
pub use causal::{Atom, Fact, Literal, Projection, Rule, WhatIf};

use crate::ledger::LedgerState;
use crate::SessionId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_ATTEMPTS: usize = 6;
pub const MAX_RECORDS: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Host,
    Service,
    Endpoint,
    File,
    Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetInput {
    pub kind: AssetKind,
    pub locator: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default = "yes")]
    pub mandatory: bool,
    #[serde(default)]
    pub parent: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub kind: AssetKind,
    pub locator: String,
    pub evidence: Vec<String>,
    pub mandatory: bool,
    pub parent: Option<String>,
    pub coverage: CoverageDisposition,
    pub n: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoverageDisposition {
    #[default]
    Untested,
    Tested {
        evidence: Vec<String>,
    },
    Deferred {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialInput {
    pub asset: String,
    pub principal: String,
    pub secret_handle: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub unlocks: Vec<Condition>,
    #[serde(default)]
    pub expires_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub input: CredentialInput,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FootholdInput {
    pub asset: String,
    pub principal: String,
    pub access: String,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub unlocks: Vec<Condition>,
    #[serde(default)]
    pub expires_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Foothold {
    pub id: String,
    pub input: FootholdInput,
    pub n: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionKind {
    Auth,
    Cred,
    Role,
    Leak,
    Offset,
    Key,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub kind: ConditionKind,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedRoute {
    pub target: String,
    pub conditions: Vec<Condition>,
    pub n: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashOutcome {
    Crash,
    Timeout,
    Oom,
    NoCrash,
    FuzzerExit71,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashFrame {
    pub function: String,
    pub file: String,
    #[serde(default)]
    pub line: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashSignature {
    pub sanitizer: String,
    pub frames: Vec<CrashFrame>,
    pub outcome: CrashOutcome,
}

impl CrashSignature {
    pub fn key(&self) -> Result<String, String> {
        if self.outcome != CrashOutcome::Crash {
            return Err(
                "Only a real crash has a crash signature; record timeout, OOM, and non-crash outcomes as notes.".into(),
            );
        }
        text(&self.sanitizer, "sanitizer class")?;
        if self.frames.is_empty() || self.frames.len() > 3 {
            return Err("Give one to three crash frames; keep the source line only on frame zero.".into());
        }
        let mut parts = vec![self.sanitizer.trim().to_ascii_lowercase()];
        for (i, f) in self.frames.iter().enumerate() {
            text(&f.function, "crash function")?;
            text(&f.file, "crash source file")?;
            parts.push(format!(
                "{}@{}{}",
                f.function.trim(),
                f.file.trim(),
                if i == 0 { f.line.map(|n| format!(":{n}")).unwrap_or_default() } else { String::new() }
            ));
        }
        Ok(stable_id("cs", &parts.iter().map(String::as_str).collect::<Vec<_>>()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptInput {
    pub vector: String,
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashRecord {
    pub id: String,
    pub signature: CrashSignature,
    pub attempts: Vec<AttemptInput>,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    Open,
    Supported,
    Refuted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: String,
    pub text: String,
    pub priority: u8,
    pub owner: SessionId,
    pub status: HypothesisStatus,
    pub evidence: Vec<String>,
    pub counterevidence: Vec<String>,
    pub note: String,
    pub judge: Option<SessionId>,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationInput {
    pub from: String,
    pub to: String,
    pub kind: String,
    /// Integer cost, 1..=1000; smaller is easier/more useful to investigate.
    pub cost: u32,
    pub evidence: Vec<String>,
    #[serde(default)]
    pub expires_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relation {
    pub id: String,
    pub input: RelationInput,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedPath {
    pub assets: Vec<String>,
    pub relations: Vec<String>,
    pub cost: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertedFact {
    pub id: String,
    pub fact: Fact,
    pub evidence: Vec<String>,
    pub active: bool,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledRule {
    pub id: String,
    pub rule: Rule,
    pub active: bool,
    pub n: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecurityOp {
    /// One validated, sealed append for scanner imports. Nested batches are refused.
    Batch {
        operations: Vec<SecurityOp>,
    },
    AssetUpsert {
        asset: AssetInput,
    },
    CredentialAdd {
        credential: CredentialInput,
    },
    FootholdAdd {
        foothold: FootholdInput,
    },
    ConditionUnlock {
        conditions: Vec<Condition>,
        evidence: Vec<String>,
    },
    BlockedOn {
        target: String,
        conditions: Vec<Condition>,
    },
    RevisitAcknowledge {
        target: String,
    },
    CoverageSet {
        asset: String,
        disposition: CoverageDisposition,
    },
    CrashRecord {
        signature: CrashSignature,
        attempt: AttemptInput,
    },
    HypothesisOpen {
        text: String,
        priority: u8,
    },
    HypothesisPriority {
        id: String,
        priority: u8,
    },
    HypothesisEvidence {
        id: String,
        evidence: Vec<String>,
        counterevidence: Vec<String>,
    },
    HypothesisVerdict {
        id: String,
        status: HypothesisStatus,
        note: String,
        evidence: Vec<String>,
        counterevidence: Vec<String>,
    },
    RelationAdd {
        relation: RelationInput,
    },
    FactAssert {
        fact: Fact,
        evidence: Vec<String>,
    },
    FactRetract {
        id: String,
        reason: String,
    },
    RuleInstall {
        rule: Rule,
    },
    RuleRetract {
        id: String,
        reason: String,
    },
    AliasAdd {
        alias: String,
        target: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityState {
    pub assets: BTreeMap<String, Asset>,
    pub credentials: BTreeMap<String, Credential>,
    pub footholds: BTreeMap<String, Foothold>,
    pub unlocked: BTreeSet<Condition>,
    pub condition_evidence: BTreeMap<String, Vec<String>>,
    pub blocked: BTreeMap<String, BlockedRoute>,
    pub revisited: BTreeMap<String, u64>,
    pub crashes: BTreeMap<String, CrashRecord>,
    pub vector_attempts: BTreeMap<String, Vec<AttemptInput>>,
    pub hypotheses: BTreeMap<String, Hypothesis>,
    pub relations: BTreeMap<String, Relation>,
    pub facts: BTreeMap<String, AssertedFact>,
    pub rules: BTreeMap<String, InstalledRule>,
    pub aliases: BTreeMap<String, String>,
    /// Conclusions removed by the most recent fact/rule retraction.
    pub died: Vec<Fact>,
    /// Retraction differences are unknown when either closure exhausted its evaluation budget.
    pub retraction_limitation: Option<String>,
}

/// Hash a length-delimited tuple; no separator ambiguity or truncated-hash collisions.
pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut bytes = Vec::new();
    for p in parts {
        bytes.extend_from_slice(&u64::try_from(p.len()).unwrap_or(u64::MAX).to_le_bytes());
        bytes.extend_from_slice(p.as_bytes());
    }
    format!("{prefix}-{}", crate::sha256_hex(&bytes))
}

/// Canonicalize only distinctions that cannot change the named resource. URL paths retain case,
/// queries and fragments; URL credentials are refused. File/identity locators remain case-sensitive.
pub fn canonical_locator(kind: AssetKind, locator: &str) -> Result<String, String> {
    text(locator, "asset locator")?;
    let locator = locator.trim();
    match kind {
        AssetKind::Host => {
            if let Ok(ip) = locator.parse::<std::net::IpAddr>() {
                return Ok(ip.to_string());
            }
            if locator.chars().any(|c| c.is_whitespace() || matches!(c, '/' | ':' | '@')) {
                return Err("Give a host name or IP address, without a scheme, port, path, or credentials.".into());
            }
            let host = locator.trim_end_matches('.').to_ascii_lowercase();
            if host.is_empty() {
                return Err("Give a nonempty host name or IP address.".into());
            }
            Ok(host)
        }
        AssetKind::Endpoint | AssetKind::Service => {
            let mut url =
                url::Url::parse(locator).map_err(|_| "Give an absolute service or endpoint URL.".to_string())?;
            if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
                return Err(
                    "Give an absolute URL with a host and no embedded credentials; store a secret handle separately."
                        .into(),
                );
            }
            if let Some(host) = url.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()) {
                url.set_host(Some(&host))
                    .map_err(|_| "The URL host is invalid; correct it before recording the asset.".to_string())?;
            }
            Ok(url.to_string())
        }
        AssetKind::File | AssetKind::Identity => Ok(locator.to_string()),
    }
}

impl AssetInput {
    pub fn id(&self) -> Result<String, String> {
        Ok(stable_id("as", &[&format!("{:?}", self.kind), &canonical_locator(self.kind, &self.locator)?]))
    }
}

fn text(value: &str, name: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(format!("Give a nonblank {name} of at most 4096 bytes without control characters."));
    }
    Ok(())
}

fn merge<T: Clone + Ord>(into: &mut Vec<T>, values: &[T]) {
    let set: BTreeSet<_> = into.iter().chain(values).cloned().collect();
    *into = set.into_iter().collect();
}

fn conditions(values: &[Condition]) -> Result<(), String> {
    if values.is_empty() || values.len() > 64 {
        return Err("Give between one and 64 typed conditions.".into());
    }
    for c in values {
        text(&c.value, "condition value")?;
    }
    Ok(())
}

impl SecurityState {
    pub fn resolve(&self, wanted: &str) -> Result<String, String> {
        let ids: BTreeSet<&str> = self
            .assets
            .keys()
            .chain(self.credentials.keys())
            .chain(self.footholds.keys())
            .chain(self.crashes.keys())
            .chain(self.hypotheses.keys())
            .chain(self.relations.keys())
            .chain(self.facts.keys())
            .chain(self.rules.keys())
            .map(String::as_str)
            .collect();
        if ids.contains(wanted) {
            return Ok(wanted.to_string());
        }
        if let Some(id) = self.aliases.get(wanted) {
            return Ok(id.clone());
        }
        if wanted.len() < 4 {
            return Err("Use an exact ID or alias, or an unambiguous prefix of at least four characters.".into());
        }
        let matches: BTreeSet<_> = ids.into_iter().filter(|id| id.starts_with(wanted)).collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().unwrap_or_default().to_string()),
            0 => {
                Err(format!("No security record matches `{wanted}`; query the current records before choosing an ID."))
            }
            _ => Err(format!("The prefix `{wanted}` is ambiguous; give more characters or an exact ID.")),
        }
    }

    pub fn mandatory_open(&self) -> Vec<String> {
        self.assets
            .values()
            .filter(|a| a.mandatory && a.coverage == CoverageDisposition::Untested)
            .map(|a| a.id.clone())
            .collect()
    }

    pub fn newly_unlocked(&self) -> Vec<String> {
        self.newly_unlocked_at(0)
    }

    pub fn newly_unlocked_at(&self, now_ms: u64) -> Vec<String> {
        let mut available = self.unlocked.clone();
        for c in self.credentials.values().filter(|c| c.input.expires_ms.is_none_or(|t| t > now_ms)) {
            available.extend(c.input.unlocks.iter().cloned());
            available.insert(Condition { kind: ConditionKind::Cred, value: c.input.asset.clone() });
        }
        for f in self.footholds.values().filter(|f| f.input.expires_ms.is_none_or(|t| t > now_ms)) {
            available.extend(f.input.unlocks.iter().cloned());
            available.insert(Condition { kind: ConditionKind::Auth, value: f.input.asset.clone() });
        }
        self.blocked
            .values()
            .filter(|r| !self.revisited.contains_key(&r.target) && r.conditions.iter().all(|c| available.contains(c)))
            .map(|r| r.target.clone())
            .collect()
    }

    pub fn validate(&self, op: &SecurityOp, ledger: &LedgerState) -> Result<(), String> {
        let evidence = |refs: &[String], required: bool| -> Result<(), String> {
            if (required && refs.is_empty()) || refs.len() > 128 {
                return Err(
                    "Cite between one and 128 existing attested evidence IDs; record the observation first.".into()
                );
            }
            for id in refs {
                if !ledger.evidence.iter().any(|e| &e.id == id && e.input.attested) {
                    return Err(format!(
                        "Evidence `{id}` is missing or unattested; use the evidence tool before citing it."
                    ));
                }
            }
            Ok(())
        };
        let asset = |id: &str| -> Result<(), String> {
            if self.assets.contains_key(id) {
                Ok(())
            } else {
                Err(format!("Asset `{id}` does not exist; record it first."))
            }
        };
        let hypothesis = |id: &str| -> Result<(), String> {
            if self.hypotheses.contains_key(id) {
                Ok(())
            } else {
                Err(format!("Hypothesis `{id}` does not exist; the lead must open it first."))
            }
        };
        match op {
            SecurityOp::Batch { operations } => {
                if operations.is_empty() || operations.len() > 1000 {
                    return Err("Give one to 1000 security operations in one import batch.".into());
                }
                let mut staged = ledger.clone();
                for op in operations {
                    if matches!(op, SecurityOp::Batch { .. }) {
                        return Err("Nested security batches are not supported; flatten the operations.".into());
                    }
                    staged.security.validate(op, &staged)?;
                    staged.security.apply(op, 0, &SessionId::from("validation"));
                }
            }
            SecurityOp::AssetUpsert { asset: a } => {
                a.id()?;
                evidence(&a.evidence, true)?;
                if let Some(parent) = &a.parent {
                    asset(parent)?;
                    if Some(parent) == a.id().ok().as_ref() {
                        return Err("An asset cannot be its own parent; choose an existing containing asset.".into());
                    }
                }
                if let Some(old) = self.assets.get(&a.id()?) {
                    if old.parent != a.parent {
                        return Err(
                            "This canonical asset already has a different parent; preserve its recorded identity."
                                .into(),
                        );
                    }
                }
            }
            SecurityOp::CredentialAdd { credential: c } => {
                asset(&c.asset)?;
                text(&c.principal, "principal")?;
                evidence(&c.evidence, true)?;
                if !c
                    .secret_handle
                    .strip_prefix("out:")
                    .is_some_and(|h| (8..=64).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()))
                {
                    return Err("Store secret material in a blob and give its out: handle; do not place a password or key in the ledger.".into());
                }
                if c.unlocks.len() > 64 {
                    return Err("A credential may unlock at most 64 conditions.".into());
                }
                for c in &c.unlocks {
                    text(&c.value, "condition value")?;
                }
            }
            SecurityOp::FootholdAdd { foothold: f } => {
                asset(&f.asset)?;
                text(&f.principal, "principal")?;
                text(&f.access, "access")?;
                evidence(&f.evidence, true)?;
                if f.unlocks.len() > 64 {
                    return Err("A foothold may unlock at most 64 conditions.".into());
                }
                for c in &f.unlocks {
                    text(&c.value, "condition value")?;
                }
            }
            SecurityOp::ConditionUnlock { conditions: c, evidence: e } => {
                conditions(c)?;
                evidence(e, true)?;
            }
            SecurityOp::BlockedOn { target, conditions: c } => {
                if !ledger.claims.iter().any(|x| &x.id == target) && !ledger.dead_ends.iter().any(|x| &x.id == target) {
                    return Err(
                        "Blocked routes must name an existing claim or dead-end ID; record it before its conditions."
                            .into(),
                    );
                }
                conditions(c)?;
            }
            SecurityOp::RevisitAcknowledge { target } => {
                if !self.newly_unlocked().contains(target) {
                    return Err("Acknowledge an unlocked, unacknowledged route from security_query revisit.".into());
                }
            }
            SecurityOp::CoverageSet { asset: id, disposition } => {
                asset(id)?;
                match disposition {
                    CoverageDisposition::Tested { evidence: e } => evidence(e, true)?,
                    CoverageDisposition::Deferred { reason } => text(reason, "coverage deferral reason")?,
                    CoverageDisposition::Untested => {}
                }
            }
            SecurityOp::CrashRecord { signature, attempt } => {
                signature.key()?;
                text(&attempt.vector, "attempt vector")?;
                text(&attempt.summary, "attempt summary")?;
                if attempt.summary.lines().count() > 6 {
                    return Err("Keep the attempt summary within six compact lines.".into());
                }
                evidence(&attempt.evidence, true)?;
                if self.vector_attempts.len() >= MAX_RECORDS
                    && !self.vector_attempts.contains_key(attempt.vector.trim())
                {
                    return Err("The attempt registry reached its vector bound; start a narrower mission.".into());
                }
            }
            SecurityOp::HypothesisOpen { text: t, .. } => text(t, "hypothesis")?,
            SecurityOp::HypothesisPriority { id, .. } => hypothesis(id)?,
            SecurityOp::HypothesisEvidence { id, evidence: e, counterevidence: c } => {
                hypothesis(id)?;
                evidence(e, false)?;
                evidence(c, false)?;
                if e.is_empty() && c.is_empty() {
                    return Err("Attach supporting evidence or counterevidence to the hypothesis.".into());
                }
            }
            SecurityOp::HypothesisVerdict { id, status, note, evidence: e, counterevidence: c } => {
                hypothesis(id)?;
                text(note, "verdict note")?;
                evidence(e, false)?;
                evidence(c, false)?;
                if *status == HypothesisStatus::Open
                    || (*status == HypothesisStatus::Supported && e.is_empty())
                    || (*status == HypothesisStatus::Refuted && c.is_empty())
                {
                    return Err("A judge verdict must be supported with evidence, or refuted with counterevidence; use an evidence update to reopen.".into());
                }
                if self.hypotheses.get(id).is_some_and(|h| h.counterevidence.iter().any(|id| !c.contains(id))) {
                    return Err("The verdict must acknowledge every existing counterevidence ID; include and review them explicitly.".into());
                }
            }
            SecurityOp::RelationAdd { relation: r } => {
                asset(&r.from)?;
                asset(&r.to)?;
                text(&r.kind, "relation kind")?;
                evidence(&r.evidence, true)?;
                if r.cost == 0 || r.cost > 1000 || r.from == r.to {
                    return Err(
                        "A relation needs distinct assets and an integer investigation cost from one to 1000.".into()
                    );
                }
            }
            SecurityOp::FactAssert { fact, evidence: e } => {
                fact.validate()?;
                evidence(e, true)?;
                if self
                    .facts
                    .values()
                    .any(|f| f.active && f.fact.predicate == fact.predicate && f.fact.args.len() != fact.args.len())
                {
                    return Err(
                        "A predicate must keep one arity; use a different predicate name for another tuple shape."
                            .into(),
                    );
                }
                for r in self.rules.values().filter(|r| r.active) {
                    if std::iter::once(&r.rule.head)
                        .chain(r.rule.body.iter().map(|l| &l.atom))
                        .any(|a| a.predicate == fact.predicate && a.args.len() != fact.args.len())
                    {
                        return Err("The fact arity disagrees with an installed rule; correct the tuple shape.".into());
                    }
                }
            }
            SecurityOp::FactRetract { id, reason } => {
                text(reason, "retraction reason")?;
                if !self.facts.get(id).is_some_and(|f| f.active) {
                    return Err("Retract an existing active base fact, not a derived conclusion.".into());
                }
            }
            SecurityOp::RuleInstall { rule } => {
                let mut rules: Vec<_> = self.rules.values().filter(|r| r.active).map(|r| r.rule.clone()).collect();
                rules.push(rule.clone());
                causal::validate_rules(&rules)?;
                for atom in std::iter::once(&rule.head).chain(rule.body.iter().map(|l| &l.atom)) {
                    if self
                        .facts
                        .values()
                        .any(|f| f.active && f.fact.predicate == atom.predicate && f.fact.args.len() != atom.args.len())
                    {
                        return Err("The rule arity disagrees with an asserted fact; correct the tuple shape.".into());
                    }
                }
            }
            SecurityOp::RuleRetract { id, reason } => {
                text(reason, "retraction reason")?;
                if !self.rules.get(id).is_some_and(|r| r.active) {
                    return Err("Retract an existing active rule ID.".into());
                }
            }
            SecurityOp::AliasAdd { alias, target } => {
                text(alias, "alias")?;
                if self.aliases.len() >= MAX_RECORDS
                    || alias.len() > 128
                    || self.resolve(alias).is_ok()
                    || !self.all_ids().contains(target)
                {
                    return Err(
                        "Choose an unused alias of at most 128 bytes and an exact existing security record ID.".into(),
                    );
                }
            }
        }
        if self.all_ids().len() >= MAX_RECORDS
            && matches!(
                op,
                SecurityOp::AssetUpsert { .. }
                    | SecurityOp::CredentialAdd { .. }
                    | SecurityOp::FootholdAdd { .. }
                    | SecurityOp::HypothesisOpen { .. }
                    | SecurityOp::RelationAdd { .. }
                    | SecurityOp::FactAssert { .. }
                    | SecurityOp::RuleInstall { .. }
                    | SecurityOp::CrashRecord { .. }
            )
        {
            return Err("The security ledger reached its 10000-record bound; start a narrower mission instead of adding records.".into());
        }
        Ok(())
    }

    fn all_ids(&self) -> BTreeSet<String> {
        self.assets
            .keys()
            .chain(self.credentials.keys())
            .chain(self.footholds.keys())
            .chain(self.crashes.keys())
            .chain(self.hypotheses.keys())
            .chain(self.relations.keys())
            .chain(self.facts.keys())
            .chain(self.rules.keys())
            .cloned()
            .collect()
    }

    pub fn apply(&mut self, op: &SecurityOp, n: u64, session: &SessionId) {
        match op {
            SecurityOp::Batch { operations } => {
                for op in operations {
                    if !matches!(op, SecurityOp::Batch { .. }) {
                        self.apply(op, n, session);
                    }
                }
            }
            SecurityOp::AssetUpsert { asset: a } => {
                if let (Ok(id), Ok(locator)) = (a.id(), canonical_locator(a.kind, &a.locator)) {
                    let record = self.assets.entry(id.clone()).or_insert_with(|| Asset {
                        id: id.clone(),
                        kind: a.kind,
                        locator,
                        evidence: Vec::new(),
                        mandatory: a.mandatory,
                        parent: a.parent.clone(),
                        coverage: CoverageDisposition::Untested,
                        n,
                    });
                    merge(&mut record.evidence, &a.evidence);
                    record.mandatory |= a.mandatory;
                    if let Some(parent) = &a.parent {
                        self.add_relation(
                            RelationInput {
                                from: parent.clone(),
                                to: id,
                                kind: "contains".into(),
                                cost: 1,
                                evidence: a.evidence.clone(),
                                expires_ms: None,
                            },
                            n,
                        );
                    }
                }
            }
            SecurityOp::CredentialAdd { credential: c } => {
                let id = stable_id("cr", &[&c.asset, &c.principal, &c.secret_handle]);
                let record =
                    self.credentials.entry(id.clone()).or_insert_with(|| Credential { id, input: c.clone(), n });
                merge(&mut record.input.evidence, &c.evidence);
                merge(&mut record.input.unlocks, &c.unlocks);
                record.input.expires_ms = c.expires_ms;
                record.n = n;
            }
            SecurityOp::FootholdAdd { foothold: f } => {
                let id = stable_id("fh", &[&f.asset, &f.principal, &f.access]);
                let record = self.footholds.entry(id.clone()).or_insert_with(|| Foothold { id, input: f.clone(), n });
                merge(&mut record.input.evidence, &f.evidence);
                merge(&mut record.input.unlocks, &f.unlocks);
                record.input.expires_ms = f.expires_ms;
                record.n = n;
            }
            SecurityOp::ConditionUnlock { conditions, evidence } => {
                self.unlocked.extend(conditions.iter().cloned());
                for c in conditions {
                    let id = stable_id("cn", &[&format!("{:?}", c.kind), &c.value]);
                    merge(self.condition_evidence.entry(id).or_default(), evidence);
                }
            }
            SecurityOp::BlockedOn { target, conditions } => {
                self.revisited.remove(target);
                self.blocked
                    .insert(target.clone(), BlockedRoute { target: target.clone(), conditions: conditions.clone(), n });
            }
            SecurityOp::RevisitAcknowledge { target } => {
                self.revisited.insert(target.clone(), n);
            }
            SecurityOp::CoverageSet { asset, disposition } => {
                if let Some(a) = self.assets.get_mut(asset) {
                    a.coverage = disposition.clone();
                }
            }
            SecurityOp::CrashRecord { signature, attempt } => {
                if let Ok(id) = signature.key() {
                    let record = self.crashes.entry(id.clone()).or_insert_with(|| CrashRecord {
                        id,
                        signature: signature.clone(),
                        attempts: Vec::new(),
                        count: 0,
                    });
                    record.count = record.count.saturating_add(1);
                    record.attempts.push(attempt.clone());
                    if record.attempts.len() > MAX_ATTEMPTS {
                        record.attempts.remove(0);
                    }
                    let attempts = self.vector_attempts.entry(attempt.vector.trim().into()).or_default();
                    attempts.push(attempt.clone());
                    if attempts.len() > MAX_ATTEMPTS {
                        attempts.remove(0);
                    }
                }
            }
            SecurityOp::HypothesisOpen { text, priority } => {
                let id = stable_id("hy", &[text.trim()]);
                self.hypotheses.entry(id.clone()).or_insert_with(|| Hypothesis {
                    id,
                    text: text.trim().into(),
                    priority: *priority,
                    owner: session.clone(),
                    status: HypothesisStatus::Open,
                    evidence: Vec::new(),
                    counterevidence: Vec::new(),
                    note: String::new(),
                    judge: None,
                    n,
                });
            }
            SecurityOp::HypothesisPriority { id, priority } => {
                if let Some(h) = self.hypotheses.get_mut(id) {
                    h.priority = *priority;
                }
            }
            SecurityOp::HypothesisEvidence { id, evidence, counterevidence } => {
                if let Some(h) = self.hypotheses.get_mut(id) {
                    let new_counter = counterevidence.iter().any(|e| !h.counterevidence.contains(e));
                    let new_support = evidence.iter().any(|e| !h.evidence.contains(e));
                    merge(&mut h.evidence, evidence);
                    merge(&mut h.counterevidence, counterevidence);
                    if (new_counter && h.status == HypothesisStatus::Supported)
                        || (new_support && h.status == HypothesisStatus::Refuted)
                    {
                        h.status = HypothesisStatus::Open;
                        h.judge = None;
                    }
                }
            }
            SecurityOp::HypothesisVerdict { id, status, note, evidence, counterevidence } => {
                if let Some(h) = self.hypotheses.get_mut(id) {
                    h.status = *status;
                    h.note = note.clone();
                    h.judge = Some(session.clone());
                    merge(&mut h.evidence, evidence);
                    merge(&mut h.counterevidence, counterevidence);
                }
            }
            SecurityOp::RelationAdd { relation } => self.add_relation(relation.clone(), n),
            SecurityOp::FactAssert { fact, evidence } => {
                let id = fact.id();
                let record = self.facts.entry(id.clone()).or_insert_with(|| AssertedFact {
                    id,
                    fact: fact.clone(),
                    evidence: Vec::new(),
                    active: true,
                    n,
                });
                record.active = true;
                merge(&mut record.evidence, evidence);
            }
            SecurityOp::RuleInstall { rule } => {
                let id = rule.id();
                self.rules.insert(id.clone(), InstalledRule { id, rule: rule.clone(), active: true, n });
            }
            SecurityOp::FactRetract { id, .. } | SecurityOp::RuleRetract { id, .. } => {
                let before = self.projection();
                if let Some(f) = self.facts.get_mut(id) {
                    f.active = false;
                }
                if let Some(r) = self.rules.get_mut(id) {
                    r.active = false;
                }
                let after = self.projection();
                if before.complete && after.complete {
                    self.died = before.facts.into_iter().filter(|f| !after.contains(&f.fact)).map(|f| f.fact).collect();
                    self.retraction_limitation = None;
                } else {
                    self.died.clear();
                    self.retraction_limitation = Some("The retraction closure is incomplete; disappeared conclusions are unknown. Narrow the causal rules and query again.".into());
                }
            }
            SecurityOp::AliasAdd { alias, target } => {
                self.aliases.insert(alias.clone(), target.clone());
            }
        }
    }

    fn add_relation(&mut self, input: RelationInput, n: u64) {
        let id = stable_id("rl", &[&input.from, &input.to, &input.kind]);
        let r = self.relations.entry(id.clone()).or_insert_with(|| Relation { id, input: input.clone(), n });
        merge(&mut r.input.evidence, &input.evidence);
        r.input.cost = input.cost;
        r.input.expires_ms = input.expires_ms;
    }

    pub fn projection(&self) -> Projection {
        self.what_if(&[], &[]).projection
    }

    pub fn why(&self, fact: &Fact) -> Option<causal::Explanation> {
        self.projection().why(fact)
    }

    pub fn what_if(&self, assume: &[Fact], retract: &[String]) -> WhatIf {
        causal::evaluate(self, assume, retract)
    }

    pub fn path_suggest(&self, from: &str, to: &str, now_ms: u64) -> Vec<SuggestedPath> {
        let mut frontier = vec![SuggestedPath { assets: vec![from.into()], relations: Vec::new(), cost: 0 }];
        let mut found = Vec::new();
        let mut visited = 0usize;
        while !frontier.is_empty() && visited < 10_000 && found.len() < 3 {
            frontier.sort_by(|a, b| (b.cost, &b.assets, &b.relations).cmp(&(a.cost, &a.assets, &a.relations)));
            let Some(path) = frontier.pop() else {
                break;
            };
            visited = visited.saturating_add(1);
            let Some(last) = path.assets.last() else {
                continue;
            };
            if last == to && path.assets.len() > 1 {
                found.push(path);
                continue;
            }
            if path.relations.len() >= 8 {
                continue;
            }
            for edge in self.relations.values().filter(|e| {
                &e.input.from == last
                    && e.input.expires_ms.is_none_or(|t| t > now_ms)
                    && !path.assets.contains(&e.input.to)
            }) {
                let known = self
                    .footholds
                    .values()
                    .any(|f| &f.input.asset == last && f.input.expires_ms.is_none_or(|t| t > now_ms));
                let mut next = path.clone();
                next.assets.push(edge.input.to.clone());
                next.relations.push(edge.id.clone());
                next.cost = next.cost.saturating_add(u64::from(if known {
                    edge.input.cost.div_ceil(2)
                } else {
                    edge.input.cost
                }));
                frontier.push(next);
                if frontier.len() >= 10_000 {
                    break;
                }
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::{Entry, Evidence, EvidenceInput, EvidenceKind, LedgerOp};
    use crate::CallId;

    fn ledger() -> LedgerState {
        let mut l = LedgerState::default();
        for n in 1..=2 {
            l.evidence.push(Evidence {
                id: format!("e{n}"),
                n,
                input: EvidenceInput {
                    claim: "c1".into(),
                    kind: EvidenceKind::Execution,
                    supports: true,
                    session: "s-source".into(),
                    call_id: CallId::from("call"),
                    blob: None,
                    lines: None,
                    quote: None,
                    note: "test observation".into(),
                    attested: true,
                },
            });
        }
        l
    }
    fn apply(l: &mut LedgerState, op: SecurityOp) {
        l.validate(&LedgerOp::Security(op.clone()), false).unwrap();
        l.apply(&Entry {
            n: l.entries + 1,
            ts_ms: 0,
            session: "s-lead".into(),
            from_user: false,
            op: LedgerOp::Security(op),
            mac: String::new(),
        });
    }
    fn asset(l: &mut LedgerState, name: &str) -> String {
        let a = AssetInput {
            kind: AssetKind::Host,
            locator: name.into(),
            evidence: vec!["e1".into()],
            mandatory: true,
            parent: None,
        };
        let id = a.id().unwrap();
        apply(l, SecurityOp::AssetUpsert { asset: a });
        id
    }
    fn fact(name: &str, args: &[&str]) -> Fact {
        Fact { predicate: name.into(), args: args.iter().map(|s| (*s).into()).collect() }
    }
    fn atom(name: &str, args: &[&str]) -> Atom {
        Atom { predicate: name.into(), args: args.iter().map(|s| (*s).into()).collect() }
    }
    fn rule(name: &str, head: Atom, body: Vec<Literal>) -> Rule {
        Rule { name: name.into(), head, body }
    }
    fn positive(atom: Atom) -> Literal {
        Literal { atom, negated: false }
    }

    #[test]
    fn canonical_dedup_preserves_url_path_case_and_requires_attestation() {
        let mut l = ledger();
        let id = asset(&mut l, "Example.TEST.");
        assert_eq!(id, asset(&mut l, "example.test"));
        assert_eq!(l.security.assets.len(), 1);
        let url = canonical_locator(AssetKind::Endpoint, "HTTP://EXAMPLE.TEST:80/Case?q=Hi").unwrap();
        assert_eq!(url, "http://example.test/Case?q=Hi");
        assert_ne!(url, canonical_locator(AssetKind::Endpoint, "http://example.test/case?q=Hi").unwrap());
        assert!(canonical_locator(AssetKind::Endpoint, "https://user:pass@example.test").is_err());
        let no_evidence = SecurityOp::AssetUpsert {
            asset: AssetInput {
                kind: AssetKind::Host,
                locator: "other.test".into(),
                evidence: vec!["e404".into()],
                mandatory: true,
                parent: None,
            },
        };
        assert!(l.validate(&LedgerOp::Security(no_evidence), false).is_err());
        apply(&mut l, SecurityOp::AliasAdd { alias: "web".into(), target: id.clone() });
        assert_eq!(l.security.resolve("web").unwrap(), id);
        assert_eq!(l.security.resolve(&id.chars().take(14).collect::<String>()).unwrap(), id);
        assert!(l.security.resolve("as-").is_err());
    }

    #[test]
    fn coverage_and_typed_unlocks_do_not_close_without_evidence() {
        let mut l = ledger();
        let id = asset(&mut l, "example.test");
        assert_eq!(l.security.mandatory_open(), vec![id.clone()]);
        assert!(l
            .validate(&LedgerOp::FinishClaim { summary: "done".into(), evidence: vec!["e1".into()] }, false)
            .unwrap_err()
            .contains("coverage"));
        let bad = SecurityOp::CoverageSet {
            asset: id.clone(),
            disposition: CoverageDisposition::Tested { evidence: vec![] },
        };
        assert!(l.validate(&LedgerOp::Security(bad), false).is_err());
        let bad = SecurityOp::CoverageSet {
            asset: id.clone(),
            disposition: CoverageDisposition::Deferred { reason: " ".into() },
        };
        assert!(l.validate(&LedgerOp::Security(bad), false).is_err());
        apply(
            &mut l,
            SecurityOp::CoverageSet {
                asset: id.clone(),
                disposition: CoverageDisposition::Tested { evidence: vec!["e1".into()] },
            },
        );
        assert!(l.security.mandatory_open().is_empty());
        l.dead_ends.push(crate::ledger::DeadEnd { id: "x1".into(), what: "route".into(), why: "no auth".into(), n: 0 });
        let condition = Condition { kind: ConditionKind::Auth, value: id.clone() };
        apply(&mut l, SecurityOp::BlockedOn { target: "x1".into(), conditions: vec![condition.clone()] });
        assert!(l.security.newly_unlocked_at(100).is_empty());
        apply(
            &mut l,
            SecurityOp::FootholdAdd {
                foothold: FootholdInput {
                    asset: id,
                    principal: "dummy".into(),
                    access: "session".into(),
                    evidence: vec!["e1".into()],
                    unlocks: vec![],
                    expires_ms: Some(200),
                },
            },
        );
        assert_eq!(l.security.newly_unlocked_at(100), vec!["x1".to_string()]);
        assert!(l.security.newly_unlocked_at(201).is_empty());
        apply(&mut l, SecurityOp::RevisitAcknowledge { target: "x1".into() });
        assert!(l.security.newly_unlocked_at(100).is_empty());
        apply(&mut l, SecurityOp::BlockedOn { target: "x1".into(), conditions: vec![condition] });
        assert_eq!(l.security.newly_unlocked_at(100), vec!["x1".to_string()]);
    }

    #[test]
    fn crash_signatures_keep_root_line_ignore_caller_lines_and_bound_attempts() {
        let signature = CrashSignature {
            sanitizer: "ASAN-heap-overflow".into(),
            outcome: CrashOutcome::Crash,
            frames: vec![
                CrashFrame { function: "parse".into(), file: "a.c".into(), line: Some(7) },
                CrashFrame { function: "caller".into(), file: "b.c".into(), line: Some(8) },
            ],
        };
        let mut changed = signature.clone();
        changed.frames[1].line = Some(99);
        assert_eq!(signature.key().unwrap(), changed.key().unwrap());
        changed.frames[0].line = Some(8);
        assert_ne!(signature.key().unwrap(), changed.key().unwrap());
        changed.outcome = CrashOutcome::Oom;
        assert!(changed.key().is_err());
        let mut l = ledger();
        for i in 0..9 {
            apply(
                &mut l,
                SecurityOp::CrashRecord {
                    signature: signature.clone(),
                    attempt: AttemptInput {
                        vector: "parser".into(),
                        summary: format!("attempt {i}"),
                        evidence: vec!["e1".into()],
                    },
                },
            );
        }
        let record = l.security.crashes.values().next().unwrap();
        assert_eq!(record.count, 9);
        assert_eq!(record.attempts.len(), 6);
        assert_eq!(record.attempts[0].summary, "attempt 3");
        assert_eq!(l.security.vector_attempts.get("parser").unwrap().len(), 6);
    }

    #[test]
    fn causal_retraction_keeps_alternative_support_and_reports_dead_conclusions() {
        let mut l = ledger();
        let a = fact("observed", &["a"]);
        let b = fact("backup", &["a"]);
        apply(&mut l, SecurityOp::FactAssert { fact: a.clone(), evidence: vec!["e1".into()] });
        apply(&mut l, SecurityOp::FactAssert { fact: b.clone(), evidence: vec!["e2".into()] });
        for (name, base) in [("primary", "observed"), ("secondary", "backup")] {
            apply(
                &mut l,
                SecurityOp::RuleInstall {
                    rule: rule(name, atom("viable", &["?x"]), vec![positive(atom(base, &["?x"]))]),
                },
            );
        }
        apply(
            &mut l,
            SecurityOp::RuleInstall {
                rule: rule("downstream", atom("plan_ready", &["?x"]), vec![positive(atom("viable", &["?x"]))]),
            },
        );
        let result = l.security.projection();
        assert!(result.complete);
        assert!(result.contains(&fact("plan_ready", &["a"])));
        let explanation = result.why(&fact("plan_ready", &["a"])).unwrap();
        assert!(
            serde_json::to_string(&explanation).unwrap().contains("e1")
                || serde_json::to_string(&explanation).unwrap().contains("e2")
        );
        let snapshot = serde_json::to_vec(&l.security).unwrap();
        let hypothetical = l.security.what_if(&[], &[a.id(), b.id()]);
        assert!(hypothetical.died.contains(&fact("plan_ready", &["a"])));
        assert_eq!(snapshot, serde_json::to_vec(&l.security).unwrap());
        apply(&mut l, SecurityOp::FactRetract { id: a.id(), reason: "disproved".into() });
        assert!(l.security.projection().contains(&fact("plan_ready", &["a"])));
        apply(&mut l, SecurityOp::FactRetract { id: b.id(), reason: "disproved too".into() });
        assert!(l.security.died.contains(&fact("viable", &["a"])));
        assert!(l.security.died.contains(&fact("plan_ready", &["a"])));
    }

    #[test]
    fn stratified_negation_recomputes_and_unsafe_rules_are_rejected() {
        let mut l = ledger();
        let observed = fact("observed", &["a"]);
        apply(&mut l, SecurityOp::FactAssert { fact: observed, evidence: vec!["e1".into()] });
        let r = rule(
            "safe",
            atom("candidate", &["?x"]),
            vec![positive(atom("observed", &["?x"])), Literal { atom: atom("blocked", &["?x"]), negated: true }],
        );
        apply(&mut l, SecurityOp::RuleInstall { rule: r });
        assert!(l.security.projection().contains(&fact("candidate", &["a"])));
        apply(&mut l, SecurityOp::FactAssert { fact: fact("blocked", &["a"]), evidence: vec!["e1".into()] });
        assert!(!l.security.projection().contains(&fact("candidate", &["a"])));
        let negative_cycle = rule(
            "cycle",
            atom("blocked", &["?x"]),
            vec![positive(atom("observed", &["?x"])), Literal { atom: atom("candidate", &["?x"]), negated: true }],
        );
        assert!(l.validate(&LedgerOp::Security(SecurityOp::RuleInstall { rule: negative_cycle }), false).is_err());
        let unsafe_rule = rule("unsafe", atom("bad", &["?unbound"]), vec![positive(atom("observed", &["?x"]))]);
        assert!(l.validate(&LedgerOp::Security(SecurityOp::RuleInstall { rule: unsafe_rule }), false).is_err());
    }

    #[test]
    fn exhausted_closures_report_unknown_differences_instead_of_false_invalidation() {
        let mut l = ledger();
        for i in 0..101 {
            for p in ["left", "right"] {
                apply(
                    &mut l,
                    SecurityOp::FactAssert {
                        fact: Fact { predicate: p.into(), args: vec![i.to_string()] },
                        evidence: vec!["e1".into()],
                    },
                );
            }
        }
        apply(
            &mut l,
            SecurityOp::RuleInstall {
                rule: rule(
                    "cartesian",
                    atom("pair", &["?x", "?y"]),
                    vec![positive(atom("left", &["?x"])), positive(atom("right", &["?y"]))],
                ),
            },
        );
        assert!(!l.security.projection().complete);
        let retract: Vec<_> =
            (0..5).map(|i| Fact { predicate: "left".into(), args: vec![i.to_string()] }.id()).collect();
        let result = l.security.what_if(&[], &retract);
        assert!(!result.projection.complete);
        assert!(result.died.is_empty());
        assert!(result.added.is_empty());
        apply(&mut l, SecurityOp::FactRetract { id: retract[0].clone(), reason: "retracted observation".into() });
        assert!(l.security.died.is_empty());
        assert!(l.security.retraction_limitation.is_some());
    }

    #[test]
    fn paths_are_simple_expiry_aware_and_discount_known_footholds() {
        let mut l = ledger();
        let a = asset(&mut l, "a.test");
        let b = asset(&mut l, "b.test");
        let c = asset(&mut l, "c.test");
        for (from, to, cost, expiry) in
            [(&a, &b, 10, None), (&b, &c, 6, None), (&a, &c, 1, Some(100)), (&b, &a, 1, None)]
        {
            apply(
                &mut l,
                SecurityOp::RelationAdd {
                    relation: RelationInput {
                        from: from.clone(),
                        to: to.clone(),
                        kind: "reachable".into(),
                        cost,
                        expires_ms: expiry,
                        evidence: vec!["e1".into()],
                    },
                },
            );
        }
        assert_eq!(l.security.path_suggest(&a, &c, 101)[0].cost, 16);
        apply(
            &mut l,
            SecurityOp::FootholdAdd {
                foothold: FootholdInput {
                    asset: b.clone(),
                    principal: "dummy".into(),
                    access: "session".into(),
                    evidence: vec!["e1".into()],
                    unlocks: vec![],
                    expires_ms: Some(200),
                },
            },
        );
        let paths = l.security.path_suggest(&a, &c, 101);
        assert_eq!(paths[0].cost, 13);
        assert_eq!(paths[0].assets, vec![a, b, c]);
    }

    #[test]
    fn sealed_replay_batch_atomicity_and_old_snapshot_compatibility() {
        let dir = tempfile::tempdir().unwrap();
        let journal = crate::journal::Journal::new(dir.path().join("journal.jsonl"), vec![7; 32]);
        let session = SessionId::from("s-test");
        journal
            .append(&session, false, LedgerOp::ClaimAdd { text: "scanner observed host".into() }, &|_| Ok(()))
            .unwrap();
        let mut input = ledger().evidence[0].input.clone();
        input.claim = "c1".into();
        journal.append(&session, false, LedgerOp::EvidenceAdd(input), &|_| Ok(())).unwrap();
        let a = AssetInput {
            kind: AssetKind::Host,
            locator: "example.test".into(),
            evidence: vec!["e1".into()],
            mandatory: true,
            parent: None,
        };
        let batch = SecurityOp::Batch {
            operations: vec![
                SecurityOp::AssetUpsert { asset: a.clone() },
                SecurityOp::CoverageSet {
                    asset: a.id().unwrap(),
                    disposition: CoverageDisposition::Tested { evidence: vec!["e404".into()] },
                },
            ],
        };
        assert!(journal.append(&session, false, LedgerOp::Security(batch), &|_| Ok(())).is_err());
        assert!(journal.state().unwrap().security.assets.is_empty());
        let (_, saved) = journal
            .append(&session, false, LedgerOp::Security(SecurityOp::AssetUpsert { asset: a }), &|_| Ok(()))
            .unwrap();
        assert_eq!(saved, journal.state().unwrap());
        let mut json = serde_json::to_value(&saved).unwrap();
        json.as_object_mut().unwrap().remove("security");
        let old: LedgerState = serde_json::from_value(json).unwrap();
        assert_eq!(old.security, SecurityState::default());
        for e in journal.read().unwrap().into_iter().filter(|e| matches!(e.op, LedgerOp::Security(_))) {
            let json = serde_json::to_string(&e).unwrap();
            assert_eq!(e, serde_json::from_str::<Entry>(&json).unwrap());
        }
    }
}
