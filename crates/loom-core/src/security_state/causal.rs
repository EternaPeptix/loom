//! Bounded stratified Datalog over ground string tuples. No functions, aggregates, arithmetic,
//! confidence-as-truth, or arbitrary code. First derivations form acyclic explanation trees.

use super::{stable_id, text, SecurityState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_FACTS: usize = 10_000;
const MAX_WORK: usize = 200_000;

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
        Atom { predicate: self.predicate.clone(), args: self.args.clone() }.validate()?;
        if self.args.iter().any(|a| variable(a)) {
            return Err("Base facts must be ground strings; variables belong in rules.".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Atom {
    pub predicate: String,
    pub args: Vec<String>,
}

impl Atom {
    fn validate(&self) -> Result<(), String> {
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
            text(a, "fact/rule argument")?;
            if a == "?" {
                return Err("Name variables after the question mark, for example ?asset.".into());
            }
        }
        Ok(())
    }
}

fn variable(a: &str) -> bool {
    a.starts_with('?')
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Literal {
    pub atom: Atom,
    #[serde(default)]
    pub negated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub head: Atom,
    pub body: Vec<Literal>,
}

impl Rule {
    pub fn id(&self) -> String {
        // Explicit tuple encoding avoids depending on JSON map order.
        let mut parts = vec![self.name.clone(), self.head.predicate.clone(), self.head.args.len().to_string()];
        parts.extend(self.head.args.iter().cloned());
        parts.push(self.body.len().to_string());
        for l in &self.body {
            parts.push(if l.negated { "negative".into() } else { "positive".into() });
            parts.push(l.atom.predicate.clone());
            parts.push(l.atom.args.len().to_string());
            parts.extend(l.atom.args.iter().cloned());
        }
        stable_id("ru", &parts.iter().map(String::as_str).collect::<Vec<_>>())
    }
}

/// Refuse unsafe variables, mixed arities, and recursion through negation. Positive recursion is
/// allowed; all negative dependencies must be strictly below the head's stratum.
pub fn validate_rules(rules: &[Rule]) -> Result<BTreeMap<String, usize>, String> {
    if rules.len() > 128 {
        return Err("Install at most 128 active causal rules in a mission.".into());
    }
    let mut arities = BTreeMap::from([
        ("asset".to_string(), 3),
        ("credential".into(), 3),
        ("foothold".into(), 4),
        ("related".into(), 3),
        ("condition".into(), 2),
    ]);
    let mut strata = BTreeMap::new();
    for rule in rules {
        text(&rule.name, "rule name")?;
        rule.head.validate()?;
        if rule.body.is_empty() || rule.body.len() > 8 {
            return Err("A causal rule needs one to eight body literals.".into());
        }
        let bound: BTreeSet<_> = rule
            .body
            .iter()
            .filter(|l| !l.negated)
            .flat_map(|l| l.atom.args.iter())
            .filter(|a| variable(a))
            .cloned()
            .collect();
        for atom in std::iter::once(&rule.head).chain(rule.body.iter().map(|l| &l.atom)) {
            atom.validate()?;
            if let Some(old) = arities.insert(atom.predicate.clone(), atom.args.len()) {
                if old != atom.args.len() {
                    return Err(format!(
                        "Predicate {} has conflicting arities; use one arity everywhere.",
                        atom.predicate
                    ));
                }
            }
            strata.entry(atom.predicate.clone()).or_insert(0usize);
        }
        for arg in rule.head.args.iter().chain(rule.body.iter().filter(|l| l.negated).flat_map(|l| &l.atom.args)) {
            if variable(arg) && !bound.contains(arg) {
                return Err(format!(
                    "Variable {arg} must be bound by a positive body literal before it appears in a head or negation."
                ));
            }
        }
    }
    for round in 0..=strata.len() {
        let mut changed = false;
        for rule in rules {
            for literal in &rule.body {
                let needed = strata
                    .get(&literal.atom.predicate)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(usize::from(literal.negated));
                let current = strata.entry(rule.head.predicate.clone()).or_default();
                if *current < needed {
                    *current = needed;
                    changed = true;
                }
            }
        }
        if !changed {
            return Ok(strata);
        }
        if round >= strata.len() {
            return Err(
                "Causal rules recurse through negation; separate them into strictly lower negative strata.".into()
            );
        }
    }
    Ok(strata)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedFact {
    pub fact: Fact,
    /// Base record ID, or rule ID when this fact was derived.
    pub source: String,
    pub evidence: Vec<String>,
    pub premises: Vec<Fact>,
    pub absent: Vec<Fact>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Projection {
    pub facts: Vec<DerivedFact>,
    pub complete: bool,
    pub limitation: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    pub fact: Fact,
    pub source: String,
    pub premises: Vec<Explanation>,
    pub absent: Vec<Fact>,
    pub evidence: Vec<String>,
    pub truncated: bool,
}

impl Projection {
    pub fn contains(&self, fact: &Fact) -> bool {
        self.facts.iter().any(|f| &f.fact == fact)
    }
    pub fn why(&self, fact: &Fact) -> Option<Explanation> {
        self.explain(fact, &mut BTreeSet::new())
    }
    fn explain(&self, fact: &Fact, seen: &mut BTreeSet<Fact>) -> Option<Explanation> {
        let d = self.facts.iter().find(|d| &d.fact == fact)?;
        if seen.len() >= 128 || !seen.insert(fact.clone()) {
            return Some(Explanation {
                fact: fact.clone(),
                source: d.source.clone(),
                premises: Vec::new(),
                absent: d.absent.clone(),
                evidence: d.evidence.clone(),
                truncated: true,
            });
        }
        let premises = d.premises.iter().filter_map(|p| self.explain(p, seen)).collect();
        seen.remove(fact);
        Some(Explanation {
            fact: fact.clone(),
            source: d.source.clone(),
            premises,
            absent: d.absent.clone(),
            evidence: d.evidence.clone(),
            truncated: false,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhatIf {
    pub projection: Projection,
    pub added: Vec<Fact>,
    pub died: Vec<Fact>,
}

type Binding = (BTreeMap<String, String>, Vec<Fact>);

fn bind(atom: &Atom, fact: &Fact, env: &BTreeMap<String, String>) -> Option<BTreeMap<String, String>> {
    if atom.predicate != fact.predicate || atom.args.len() != fact.args.len() {
        return None;
    }
    let mut result = env.clone();
    for (a, value) in atom.args.iter().zip(&fact.args) {
        if variable(a) {
            if result.get(a).is_some_and(|old| old != value) {
                return None;
            }
            result.insert(a.clone(), value.clone());
        } else if a != value {
            return None;
        }
    }
    Some(result)
}

fn ground(atom: &Atom, env: &BTreeMap<String, String>) -> Option<Fact> {
    let mut args = Vec::new();
    for arg in &atom.args {
        args.push(if variable(arg) { env.get(arg)?.clone() } else { arg.clone() });
    }
    Some(Fact { predicate: atom.predicate.clone(), args })
}

fn base(state: &SecurityState, assume: &[Fact], retract: &[String]) -> BTreeMap<Fact, DerivedFact> {
    let mut out = BTreeMap::new();
    let mut insert = |fact: Fact, source: &str, evidence: &[String]| {
        if !retract.iter().any(|r| r == source || r == &fact.id()) {
            out.entry(fact.clone()).or_insert_with(|| DerivedFact {
                fact,
                source: source.into(),
                evidence: evidence.to_vec(),
                premises: Vec::new(),
                absent: Vec::new(),
            });
        }
    };
    for a in state.assets.values() {
        insert(
            Fact {
                predicate: "asset".into(),
                args: vec![a.id.clone(), format!("{:?}", a.kind).to_ascii_lowercase(), a.locator.clone()],
            },
            &a.id,
            &a.evidence,
        );
    }
    for c in state.credentials.values() {
        insert(
            Fact {
                predicate: "credential".into(),
                args: vec![c.id.clone(), c.input.asset.clone(), c.input.principal.clone()],
            },
            &c.id,
            &c.input.evidence,
        );
    }
    for f in state.footholds.values() {
        insert(
            Fact {
                predicate: "foothold".into(),
                args: vec![f.id.clone(), f.input.asset.clone(), f.input.principal.clone(), f.input.access.clone()],
            },
            &f.id,
            &f.input.evidence,
        );
    }
    for r in state.relations.values() {
        insert(
            Fact {
                predicate: "related".into(),
                args: vec![r.input.from.clone(), r.input.to.clone(), r.input.kind.clone()],
            },
            &r.id,
            &r.input.evidence,
        );
    }
    for c in &state.unlocked {
        let fact = Fact {
            predicate: "condition".into(),
            args: vec![format!("{:?}", c.kind).to_ascii_lowercase(), c.value.clone()],
        };
        let id = stable_id("cn", &[&format!("{:?}", c.kind), &c.value]);
        insert(fact, &id, state.condition_evidence.get(&id).map(Vec::as_slice).unwrap_or(&[]));
    }
    for f in state.facts.values().filter(|f| f.active) {
        insert(f.fact.clone(), &f.id, &f.evidence);
    }
    for f in assume {
        insert(f.clone(), "hypothetical", &[]);
    }
    out
}

fn closure(state: &SecurityState, assume: &[Fact], retract: &[String]) -> Projection {
    let mut facts = base(state, assume, retract);
    if facts.len() > MAX_FACTS {
        return limited(facts, "The base fact count exceeds the causal budget; narrow the input.");
    }
    let mut arities = BTreeMap::new();
    for fact in facts.keys() {
        if let Some(old) = arities.insert(&fact.predicate, fact.args.len()) {
            if old != fact.args.len() {
                return limited(
                    facts.clone(),
                    "A predicate has conflicting fact arities; correct the source or hypothetical tuples.",
                );
            }
        }
    }
    let rules: Vec<_> = state.rules.values().filter(|r| r.active && !retract.contains(&r.id)).collect();
    let values: Vec<_> = rules.iter().map(|r| r.rule.clone()).collect();
    let strata = match validate_rules(&values) {
        Ok(s) => s,
        Err(e) => return Projection { facts: facts.into_values().collect(), complete: false, limitation: Some(e) },
    };
    let max = strata.values().copied().max().unwrap_or(0);
    let mut work = 0usize;
    for level in 0..=max {
        loop {
            let mut additions = BTreeMap::new();
            for installed in rules.iter().filter(|r| strata.get(&r.rule.head.predicate).copied().unwrap_or(0) == level)
            {
                let rule = &installed.rule;
                let mut rows: Vec<Binding> = vec![(BTreeMap::new(), Vec::new())];
                for literal in rule.body.iter().filter(|l| !l.negated) {
                    let mut joined = Vec::new();
                    for (env, premises) in rows {
                        for fact in facts.keys().filter(|f| f.predicate == literal.atom.predicate) {
                            work = work.saturating_add(1);
                            if work > MAX_WORK {
                                return limited(
                                    facts,
                                    "Causal join budget exhausted; narrow the rules or input facts.",
                                );
                            }
                            if let Some(next) = bind(&literal.atom, fact, &env) {
                                let mut supports = premises.clone();
                                supports.push(fact.clone());
                                joined.push((next, supports));
                            }
                        }
                    }
                    rows = joined;
                }
                for (env, premises) in rows {
                    let absent: Vec<_> =
                        rule.body.iter().filter(|l| l.negated).filter_map(|l| ground(&l.atom, &env)).collect();
                    if absent.iter().any(|f| facts.contains_key(f)) {
                        continue;
                    }
                    let Some(fact) = ground(&rule.head, &env) else {
                        continue;
                    };
                    if !facts.contains_key(&fact) {
                        additions.entry(fact.clone()).or_insert_with(|| DerivedFact {
                            fact,
                            source: installed.id.clone(),
                            evidence: Vec::new(),
                            premises,
                            absent,
                        });
                    }
                }
            }
            if additions.is_empty() {
                break;
            }
            if facts.len().saturating_add(additions.len()) > MAX_FACTS {
                return limited(facts, "Causal fact budget exhausted; narrow the rules or input facts.");
            }
            facts.extend(additions);
        }
    }
    Projection { facts: facts.into_values().collect(), complete: true, limitation: None }
}

fn limited(facts: BTreeMap<Fact, DerivedFact>, message: &str) -> Projection {
    Projection { facts: facts.into_values().collect(), complete: false, limitation: Some(message.into()) }
}

pub fn evaluate(state: &SecurityState, assume: &[Fact], retract: &[String]) -> WhatIf {
    let mut projection = closure(state, assume, retract);
    if assume.is_empty() && retract.is_empty() {
        return WhatIf { projection, added: Vec::new(), died: Vec::new() };
    }
    let before = closure(state, &[], &[]);
    if !projection.complete || !before.complete {
        projection.complete = false;
        if projection.limitation.is_none() {
            projection.limitation =
                Some("The baseline closure is incomplete; hypothetical differences are unknown.".into());
        }
        return WhatIf { projection, added: Vec::new(), died: Vec::new() };
    }
    let added = projection.facts.iter().filter(|f| !before.contains(&f.fact)).map(|f| f.fact.clone()).collect();
    let died = before.facts.iter().filter(|f| !projection.contains(&f.fact)).map(|f| f.fact.clone()).collect();
    WhatIf { projection, added, died }
}
