//! Model lineage and reviewer eligibility (`docs/MONITOR.md` §2.6).
//!
//! CONTRACT.
//!
//! - Each `[models.<p>]` profile will declare `family` (a set: a distill belongs to both families), `alignment`
//!   (`stock`, `relaxed` or `unknown`), `recipient` (who receives the traffic: `local`, `lan` for an operator-owned host,
//!   or a provider name) and optionally `purpose = "review"`. The keys are added to `loom_core::config::ModelProfile`
//!   (which is `deny_unknown_fields`) by M1, with their defaults, and recorded additively in `session_start` and
//!   `model_switched`. P0 adds none of them.
//! - Inference, used only when a key is unset, with the source (`declared`, `inferred`, `unknown`) recorded: the model
//!   name containing `deepseek` gives deepseek; `qwen` or `qwq`: qwen; `mistral`, `magistral`, `devstral` or `ministral`:
//!   mistral; `glm` or `chatglm`: glm; `kimi` or `moonshot`: kimi; `llama`: llama; `inkling`: thinking-machines; `gpt` or
//!   `o` followed by a digit: openai; `claude`: anthropic; `gemini` or `gemma`: google. The markers `uncensored`,
//!   `abliterat`, `dealign`, `crack`, `heretic` and `unchained` infer `relaxed`. An unknown family matches every family.
//!   An undeclared alignment makes an agent profile count as relaxed and a reviewer ineligible. A loopback `base_url` has
//!   recipient `unknown` until declared.
//! - The **reachable profile set** P of a mission: the lead, `role_models`, each pack role's model, the verifier
//!   choices, `escalation_model` and `alloy_models`.
//! - **Eligibility** of reviewer R for a review covering sessions S with reachable set P: (1) the families of R and of
//!   every profile in P (for an L2 review of one session, that session's profile) are disjoint; (2) R's alignment is
//!   declared `stock`; (3) R's recipient is `local` or `lan`, or is in the intersection of the recipients of every session
//!   whose data the review includes, or is in the pack's consent list `[monitor.recipients] <pack>`, or an unexpired
//!   per-mission override exists; `unknown` is never eligible; (4) R is reachable (health probe and heartbeat); (5) to
//!   clear a gate or a reopen, R has a passing vet record for the model id it currently serves, keyed on the response's
//!   `model` field.
//! - Selection: `[monitor] reviewers` is an ordered list. Per mission the first profile eligible for the whole mission is
//!   used; otherwise each session gets its own reviewer and mission-level reviews, and keep-going, are unavailable. On a
//!   fault the next eligible profile is used, never one outside the allowed recipients. A verifier choice that collides
//!   re-chooses the reviewer; it does not refuse the verifier.
//! - Overrides (`same_family`, `new_recipient`, `unvetted`), each with a typed reason, expire (one reopen or 7 days by
//!   default), are recorded in the monitor log, shown as a badge, and given only with the CLI bearer token. Never for a
//!   relaxed reviewer, never for "no reviewer", never on a mission with a relaxed agent. There is no global
//!   `allow_new_recipient` key.
//! - Relaxed profiles are never reviewers. A profile with no eligible reviewer must be listed in
//!   `[monitor] tripwires_only_profiles`; otherwise `loom config check` fails and real-target missions on it are refused at
//!   creation with a sentence naming the three choices (a reviewer on a consented recipient, a local stock model, the
//!   explicit list).
//!
//! Built by: M1 (profile keys, inference, eligibility, `config check`); M6 uses it.
//!
//! Tests required (M1): inference for every pattern above and for a name that matches none; a distill in two
//! families; loopback is unknown; every clause of eligibility with a failing and a passing case; selection order and
//! fallback never leaving the allowed recipients; a colliding verifier re-chooses; `config check` fails and prints the
//! lines to add. In P0: `parsing_and_forms`, `eligibility_is_not_built_yet`.

use crate::monitor::{not_built, MonitorError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alignment {
    Stock,
    Relaxed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Declared,
    Inferred,
    Unknown,
}

/// What the monitor knows about one model profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lineage {
    pub profile: String,
    /// Empty means unknown, which matches every family.
    pub family: BTreeSet<String>,
    pub alignment: Alignment,
    pub recipient: String,
    pub source: Source,
}

impl Lineage {
    /// True when the recipient is `local` or `lan`: no data leaves the operator's hosts.
    pub fn is_operator_owned(&self) -> bool {
        self.recipient == "local" || self.recipient == "lan"
    }

    /// True when the family sets overlap, or either is unknown (empty).
    pub fn shares_family(&self, other: &Lineage) -> bool {
        self.family.is_empty() || other.family.is_empty() || self.family.intersection(&other.family).next().is_some()
    }
}

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

/// Is `reviewer` eligible for a review whose data goes to `data_recipients`, over the profiles `reached` (M1)?
pub fn eligible(
    _reviewer: &Lineage,
    _reached: &[Lineage],
    _data_recipients: &[String],
    _consented: &[String],
) -> Result<Result<(), Ineligible>, MonitorError> {
    not_built("reviewer eligibility", "M1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(profile: &str, family: &[&str], recipient: &str) -> Lineage {
        Lineage {
            profile: profile.into(),
            family: family.iter().map(|s| s.to_string()).collect(),
            alignment: Alignment::Stock,
            recipient: recipient.into(),
            source: Source::Declared,
        }
    }

    #[test]
    fn parsing_and_forms() {
        assert_eq!(serde_json::to_string(&Alignment::Relaxed).unwrap_or_default(), "\"relaxed\"");
        assert!(serde_json::from_str::<Alignment>("\"uncensored\"").is_err());
        let a = l("dsv41", &["deepseek"], "lan");
        let b = l("qwen4max", &["qwen"], "alibaba");
        let distill = l("distill", &["deepseek", "qwen"], "lan");
        assert!(a.is_operator_owned() && !b.is_operator_owned());
        assert!(!a.shares_family(&b));
        assert!(distill.shares_family(&a) && distill.shares_family(&b));
        assert!(l("unk", &[], "unknown").shares_family(&a), "an unknown family matches every family");
    }

    #[test]
    fn eligibility_is_not_built_yet() {
        let a = l("dsv41", &["deepseek"], "lan");
        let b = l("qwen4max", &["qwen"], "alibaba");
        assert!(eligible(&b, &[a], &[], &[]).is_err());
    }
}
