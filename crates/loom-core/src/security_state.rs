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
//! each signature retains its last six attempts. Prefix resolution prefers exact IDs/aliases and
//! refuses ambiguous prefixes. All maps/outputs have deterministic ordering.
//!
//! Hypotheses and the rule engine are not part of the state any more: the operations
//! `hypothesis_open`, `hypothesis_priority`, `hypothesis_evidence`, `hypothesis_verdict`,
//! `rule_install` and `rule_retract` stay deserializable so old journals load, are refused when
//! validated for a new append (`REMOVED_OP_REFUSAL`), and change nothing when applied. A snapshot
//! that still carries `hypotheses`, `rules`, `died` or `retraction_limitation` loads; they are dropped.
//!
//! `SecurityOp::action` is the serialized `action` tag of an op (`asset_upsert`, …, `batch`). A batch
//! stays one atomic append; when one of its operations fails validation the error is
//! "Operation {i} of {n} in the batch ({action}): {error}" (1-based `i`), so the caller can tell
//! which one to correct; a nested batch is one such operation ("Operation {i} of {n} in the batch
//! (batch): Nested security batches are not supported; flatten the operations."). Tests required: the
//! prefix for a failing second operation of three, the nested batch, and that nothing of the batch was
//! applied.

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

/// A ground tuple the lead asserted as an observation. It is recorded and shown, never evaluated.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub predicate: String,
    pub args: Vec<String>,
}

impl Fact {
    pub fn id(&self) -> String {
        let parts: Vec<_> =
            std::iter::once(self.predicate.as_str()).chain(self.args.iter().map(String::as_str)).collect();
        stable_id("ft", &parts)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.predicate.is_empty()
            || self.predicate.len() > 80
            || !self.predicate.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || self.args.len() > 8
        {
            return Err(
                "Use an ASCII predicate name of one to 80 letters/digits/underscores and at most eight arguments."
                    .into(),
            );
        }
        for a in &self.args {
            text(a, "fact argument")?;
        }
        Ok(())
    }
}

/// The shape of a removed `rule_install` operation, kept so old journals deserialize.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Atom {
    pub predicate: String,
    pub args: Vec<String>,
}

/// See [`Atom`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Literal {
    pub atom: Atom,
    #[serde(default)]
    pub negated: bool,
}

/// See [`Atom`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub head: Atom,
    pub body: Vec<Literal>,
}

/// What a call to one of the removed hypothesis or rule operations is told.
pub const REMOVED_OP_REFUSAL: &str = "Hypotheses are not recorded in the security state any more: write the idea as a note (`note` with kind `decision`) or test it and record what the run showed.";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertedFact {
    pub id: String,
    pub fact: Fact,
    pub evidence: Vec<String>,
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
    pub relations: BTreeMap<String, Relation>,
    pub facts: BTreeMap<String, AssertedFact>,
    pub aliases: BTreeMap<String, String>,
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

impl SecurityOp {
    /// The serialized `action` tag of this op.
    pub fn action(&self) -> &'static str {
        match self {
            SecurityOp::Batch { .. } => "batch",
            SecurityOp::AssetUpsert { .. } => "asset_upsert",
            SecurityOp::CredentialAdd { .. } => "credential_add",
            SecurityOp::FootholdAdd { .. } => "foothold_add",
            SecurityOp::ConditionUnlock { .. } => "condition_unlock",
            SecurityOp::BlockedOn { .. } => "blocked_on",
            SecurityOp::RevisitAcknowledge { .. } => "revisit_acknowledge",
            SecurityOp::CoverageSet { .. } => "coverage_set",
            SecurityOp::CrashRecord { .. } => "crash_record",
            SecurityOp::HypothesisOpen { .. } => "hypothesis_open",
            SecurityOp::HypothesisPriority { .. } => "hypothesis_priority",
            SecurityOp::HypothesisEvidence { .. } => "hypothesis_evidence",
            SecurityOp::HypothesisVerdict { .. } => "hypothesis_verdict",
            SecurityOp::RelationAdd { .. } => "relation_add",
            SecurityOp::FactAssert { .. } => "fact_assert",
            SecurityOp::FactRetract { .. } => "fact_retract",
            SecurityOp::RuleInstall { .. } => "rule_install",
            SecurityOp::RuleRetract { .. } => "rule_retract",
            SecurityOp::AliasAdd { .. } => "alias_add",
        }
    }
}

impl SecurityState {
    pub fn resolve(&self, wanted: &str) -> Result<String, String> {
        let ids: BTreeSet<&str> = self
            .assets
            .keys()
            .chain(self.credentials.keys())
            .chain(self.footholds.keys())
            .chain(self.crashes.keys())
            .chain(self.relations.keys())
            .chain(self.facts.keys())
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
        match op {
            SecurityOp::Batch { operations } => {
                if operations.is_empty() || operations.len() > 1000 {
                    return Err("Give one to 1000 security operations in one import batch.".into());
                }
                let mut staged = ledger.clone();
                let n = operations.len();
                for (i, op) in operations.iter().enumerate() {
                    if matches!(op, SecurityOp::Batch { .. }) {
                        return Err(format!(
                            "Operation {} of {n} in the batch ({}): Nested security batches are not supported; \
                             flatten the operations.",
                            i.saturating_add(1),
                            op.action()
                        ));
                    }
                    staged.security.validate(op, &staged).map_err(|e| {
                        format!("Operation {} of {n} in the batch ({}): {e}", i.saturating_add(1), op.action())
                    })?;
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
            SecurityOp::HypothesisOpen { .. }
            | SecurityOp::HypothesisPriority { .. }
            | SecurityOp::HypothesisEvidence { .. }
            | SecurityOp::HypothesisVerdict { .. }
            | SecurityOp::RuleInstall { .. }
            | SecurityOp::RuleRetract { .. } => return Err(REMOVED_OP_REFUSAL.into()),
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
            }
            SecurityOp::FactRetract { id, reason } => {
                text(reason, "retraction reason")?;
                if !self.facts.get(id).is_some_and(|f| f.active) {
                    return Err("Retract an existing active base fact, not a derived conclusion.".into());
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
                    | SecurityOp::RelationAdd { .. }
                    | SecurityOp::FactAssert { .. }
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
            .chain(self.relations.keys())
            .chain(self.facts.keys())
            .cloned()
            .collect()
    }

    // `session` is kept so callers and the journal format do not change; no operation uses it any more.
    #[allow(clippy::only_used_in_recursion)]
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
            // Removed operations: old journals still hold them; they change nothing.
            SecurityOp::HypothesisOpen { .. }
            | SecurityOp::HypothesisPriority { .. }
            | SecurityOp::HypothesisEvidence { .. }
            | SecurityOp::HypothesisVerdict { .. }
            | SecurityOp::RuleInstall { .. }
            | SecurityOp::RuleRetract { .. } => {}
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
            SecurityOp::FactRetract { id, .. } => {
                if let Some(f) = self.facts.get_mut(id) {
                    f.active = false;
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
                    tool: None,
                    grade: None,
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
    fn final_acceptance_rechecks_coverage_added_after_the_finish_claim() {
        let mut l = ledger();
        let op = LedgerOp::FinishClaim { summary: "fixture result".into(), evidence: vec!["e1".into()] };
        l.validate(&op, false).unwrap();
        l.apply(&Entry { n: 1, ts_ms: 0, session: "s-lead".into(), from_user: false, op, mac: String::new() });
        asset(&mut l, "newly-discovered.test");
        let verdict = |accepted| LedgerOp::FinishVerdict {
            claim: "f1".into(),
            accepted,
            objections: vec![],
            verifier: Some("s-judge".into()),
        };
        assert!(l.validate(&verdict(true), false).unwrap_err().contains("coverage"));
        assert!(l.validate(&verdict(false), false).is_ok());
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
    fn batch_error_names_the_failing_operation_and_applies_nothing() {
        let l = ledger();
        let host = |name: &str, evidence: &str| SecurityOp::AssetUpsert {
            asset: AssetInput {
                kind: AssetKind::Host,
                locator: name.into(),
                evidence: vec![evidence.into()],
                mandatory: true,
                parent: None,
            },
        };
        let ops =
            vec![host("a.test", "e1"), host("b.test", "e404"), SecurityOp::RevisitAcknowledge { target: "x".into() }];
        for op in &ops {
            assert_eq!(serde_json::to_value(op).unwrap()["action"], op.action());
        }
        let batch = SecurityOp::Batch { operations: ops };
        assert_eq!(serde_json::to_value(&batch).unwrap()["action"], batch.action());
        let err = l.validate(&LedgerOp::Security(batch), false).unwrap_err();
        assert!(err.starts_with("Operation 2 of 3 in the batch (asset_upsert): "), "{err}");
        assert!(err.contains("e404"), "{err}");
        assert!(l.security.assets.is_empty());
        // A nested batch is one of the operations that fails, and is named like the others.
        let nested = SecurityOp::Batch {
            operations: vec![host("a.test", "e1"), SecurityOp::Batch { operations: vec![host("c.test", "e1")] }],
        };
        let err = l.validate(&LedgerOp::Security(nested), false).unwrap_err();
        assert_eq!(
            err,
            "Operation 2 of 2 in the batch (batch): Nested security batches are not supported; flatten the operations."
        );
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

    fn removed_ops() -> Vec<SecurityOp> {
        vec![
            SecurityOp::HypothesisOpen { text: "the admin panel trusts a header".into(), priority: 3 },
            SecurityOp::HypothesisPriority { id: "hy-1".into(), priority: 5 },
            SecurityOp::HypothesisEvidence {
                id: "hy-1".into(),
                evidence: vec!["e1".into()],
                counterevidence: Vec::new(),
            },
            SecurityOp::HypothesisVerdict {
                id: "hy-1".into(),
                status: HypothesisStatus::Supported,
                note: "run showed it".into(),
                evidence: vec!["e1".into()],
                counterevidence: Vec::new(),
            },
            SecurityOp::RuleInstall {
                rule: Rule {
                    name: "r".into(),
                    head: Atom { predicate: "viable".into(), args: vec!["?x".into()] },
                    body: vec![Literal {
                        atom: Atom { predicate: "asset".into(), args: vec!["?x".into(), "?k".into(), "?l".into()] },
                        negated: false,
                    }],
                },
            },
            SecurityOp::RuleRetract { id: "ru-1".into(), reason: "gone".into() },
        ]
    }

    #[test]
    fn old_logs_with_removed_ops_load_and_project_the_rest_unchanged() {
        let mut l = ledger();
        let id = asset(&mut l, "example.test");
        apply(&mut l, SecurityOp::AliasAdd { alias: "web".into(), target: id.clone() });
        let expected = l.security.clone();
        // Every removed op deserializes from its old JSON, applies as a no-op, and is named by `action`.
        for op in removed_ops() {
            let json = serde_json::to_string(&op).unwrap();
            let back: SecurityOp = serde_json::from_str(&json).unwrap();
            assert_eq!(back, op);
            assert_eq!(serde_json::to_value(&op).unwrap()["action"], op.action());
            l.security.apply(&op, 99, &SessionId::from("s-old"));
            assert_eq!(l.security, expected, "{}", op.action());
        }
        // They are also fine inside an old batch, and a new append of one is refused.
        l.security.apply(&SecurityOp::Batch { operations: removed_ops() }, 100, &SessionId::from("s-old"));
        assert_eq!(l.security, expected);
        for op in removed_ops() {
            let err = l.validate(&LedgerOp::Security(op), false).unwrap_err();
            assert_eq!(err, REMOVED_OP_REFUSAL);
        }
        // A snapshot written with the removed fields still loads and drops them.
        let mut json = serde_json::to_value(&expected).unwrap();
        json["hypotheses"] = serde_json::json!({"hy-1": {"id": "hy-1", "text": "t", "priority": 1, "status": "open"}});
        json["rules"] = serde_json::json!({});
        json["died"] = serde_json::json!([{"predicate": "viable", "args": ["a"]}]);
        json["retraction_limitation"] = serde_json::json!("old text");
        let loaded: SecurityState = serde_json::from_value(json).unwrap();
        assert_eq!(loaded, expected);
        assert_eq!(loaded.aliases.get("web"), Some(&id));
        assert_eq!(loaded.assets.len(), 1);
    }

    #[test]
    fn asserted_facts_are_recorded_and_retracted_without_an_engine() {
        let mut l = ledger();
        let f = Fact { predicate: "seen".into(), args: vec!["a".into()] };
        apply(&mut l, SecurityOp::FactAssert { fact: f.clone(), evidence: vec!["e1".into()] });
        apply(&mut l, SecurityOp::FactRetract { id: f.id(), reason: "mistaken".into() });
        assert!(!l.security.facts[&f.id()].active);
        let wrong = SecurityOp::FactAssert {
            fact: Fact { predicate: "seen".into(), args: vec![] },
            evidence: vec!["e1".into()],
        };
        assert!(l.validate(&LedgerOp::Security(wrong), false).is_ok());
    }
}
