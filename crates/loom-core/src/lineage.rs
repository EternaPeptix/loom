//! What the monitor knows about a model profile: its family, alignment and data recipient
//! (`docs/MONITOR.md` section 2.6). Pure; the eligibility rules that use it are `loom_agent::monitor::lineage`.
//!
//! CONTRACT.
//!
//! - `Lineage { profile, family, alignment, recipient, source, fields }` is what a profile resolves to
//!   (`resolve(name, &ModelProfile)`). `family` is a set (a distill belongs to both families; **empty means unknown, which
//!   matches every family**). `alignment` is `stock`, `relaxed` or `unknown`. `recipient` is who receives the traffic:
//!   `local` (this machine), `lan` (a host the operator owns), a provider name, or `unknown`. `fields` says, for each of
//!   the three, whether it was `declared` in `[models.<p>]`, `inferred`, or is `unknown`; `source` is the whole in one word:
//!   `unknown` when the family is empty, the alignment is unknown or the recipient is unknown; else `declared` when all
//!   three were declared; else `inferred`. A `Lineage` is recorded in `session_start` (`ModelRef::lineage`).
//! - Declared values win. Otherwise, inference, with the source recorded:
//!   - **Family** from the model id (`ModelProfile::model`, ASCII-lowercased), every pattern that matches adding its
//!     family: `deepseek` gives deepseek; `qwen` or `qwq`: qwen; `mistral`, `magistral`, `devstral` or `ministral`: mistral;
//!     `glm` or `chatglm`: glm; `kimi` or `moonshot`: kimi; `llama`: llama; `inkling`: thinking-machines; `gpt`, or a
//!     word of the id (ids split at every character that is not a letter or digit) that is `o` followed by a digit:
//!     openai; `claude`: anthropic; `gemini` or `gemma`: google. `deepseek-r1-distill-qwen-32b` is deepseek and qwen. An id
//!     that matches none (including the default `default`) leaves the family unknown.
//!   - **Alignment** is inferred only as `relaxed`, from the markers `uncensored`, `abliterat`, `dealign`, `crack`,
//!     `heretic` or `unchained` in the model id or the profile name. It is never inferred as `stock`: `stock` is a
//!     declaration. No marker and no declaration is `unknown`.
//!   - **Recipient** is the host of `base_url`, ASCII-lowercased, **except** that a loopback host (`localhost`,
//!     `*.localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`) or one that cannot be read is `unknown` until declared: a loopback
//!     address can be a tunnel to anyone's cloud. A private LAN address is its own name, not `lan`, until declared.
//! - `normalize_name` trims, ASCII-lowercases and maps `_` to `-`; family and recipient names are compared normalized
//!   (`shares_family`, `is_operator_owned` normalize both sides themselves, whatever a caller built). `resolve` stores
//!   normalized names. `FAMILIES` is the vocabulary above; a declared family outside it, and outside `[monitor]
//!   known_families`, is a `Config::check` error, so a typo cannot make a same-family reviewer look disjoint.
//!
//! Tests required: inference for every pattern and for ids that match none; a distill; `o` followed by a digit only as a
//! word; relaxed markers in the id and in the name; declared values win over inference; loopback, `localhost`, IPv6 and
//! an unreadable URL are `unknown` and a hosted URL is its host (userinfo, port and path ignored); the source rules;
//! normalized comparison; serde forms and that an older record without `fields` reads.

use crate::config::ModelProfile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Whether a model's refusals are intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alignment {
    Stock,
    Relaxed,
    #[default]
    Unknown,
}

impl Alignment {
    pub fn word(self) -> &'static str {
        match self {
            Alignment::Stock => "stock",
            Alignment::Relaxed => "relaxed",
            Alignment::Unknown => "unknown",
        }
    }
}

/// Where a lineage value came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Declared,
    Inferred,
    #[default]
    Unknown,
}

impl Source {
    pub fn word(self) -> &'static str {
        match self {
            Source::Declared => "declared",
            Source::Inferred => "inferred",
            Source::Unknown => "unknown",
        }
    }
}

/// Where each of the three values came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FieldSources {
    pub family: Source,
    pub alignment: Source,
    pub recipient: Source,
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
    /// Added with M1; absent in records written before.
    #[serde(default)]
    pub fields: FieldSources,
}

/// The families loom can infer from a model id: the vocabulary of a declaration.
pub const FAMILIES: [&str; 10] =
    ["deepseek", "qwen", "mistral", "glm", "kimi", "llama", "thinking-machines", "openai", "anthropic", "google"];

/// Substrings of a model id and the family each gives.
const FAMILY_PATTERNS: [(&str, &str); 17] = [
    ("deepseek", "deepseek"),
    ("qwen", "qwen"),
    ("qwq", "qwen"),
    ("mistral", "mistral"),
    ("magistral", "mistral"),
    ("devstral", "mistral"),
    ("ministral", "mistral"),
    ("glm", "glm"),
    ("kimi", "kimi"),
    ("moonshot", "kimi"),
    ("llama", "llama"),
    ("inkling", "thinking-machines"),
    ("gpt", "openai"),
    ("claude", "anthropic"),
    ("gemini", "google"),
    ("gemma", "google"),
    ("chatglm", "glm"),
];

/// Markers in a model id or profile name of a model whose refusals were removed.
pub const RELAXED_MARKERS: [&str; 6] = ["uncensored", "abliterat", "dealign", "crack", "heretic", "unchained"];

/// The comparison form of a family or recipient name: trimmed, ASCII-lowercase, `_` as `-`.
pub fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('_', "-")
}

/// The families a model id names; empty when it matches none.
pub fn infer_family(model_id: &str) -> BTreeSet<String> {
    let id = model_id.to_ascii_lowercase();
    let mut out: BTreeSet<String> =
        FAMILY_PATTERNS.iter().filter(|(pat, _)| id.contains(pat)).map(|(_, fam)| (*fam).to_string()).collect();
    let o_digit = id.split(|c: char| !c.is_ascii_alphanumeric()).any(|word| {
        let mut chars = word.chars();
        chars.next() == Some('o') && chars.next().is_some_and(|c| c.is_ascii_digit())
    });
    if o_digit {
        out.insert("openai".to_string());
    }
    out
}

/// The relaxed marker `text` holds, if any.
pub fn relaxed_marker(text: &str) -> Option<&'static str> {
    let t = text.to_ascii_lowercase();
    RELAXED_MARKERS.iter().copied().find(|m| t.contains(m))
}

/// The host of a base URL, lowercased, without userinfo, port or path; `None` when there is none.
pub fn host_of(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = if let Some(inner) = host_port.strip_prefix('[') {
        inner.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let name_like = host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if host.is_empty() || !name_like {
        None
    } else {
        Some(host)
    }
}

/// True for a host that is this machine.
pub fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback() || ip.is_unspecified(),
        Err(_) => false,
    }
}

/// The recipient a base URL implies: its host, or `None` for a loopback or unreadable one.
pub fn recipient_from_base_url(url: &str) -> Option<String> {
    let host = host_of(url)?;
    if is_loopback_host(&host) {
        None
    } else {
        Some(host)
    }
}

/// True when `name` is in the inference vocabulary or in `extra` (compared normalized).
pub fn known_family(name: &str, extra: &[String]) -> bool {
    let n = normalize_name(name);
    FAMILIES.contains(&n.as_str()) || extra.iter().any(|e| normalize_name(e) == n)
}

/// What profile `name` resolves to: declared values, else inference (see the module contract).
pub fn resolve(name: &str, profile: &ModelProfile) -> Lineage {
    let declared_family: BTreeSet<String> =
        profile.family.iter().flatten().map(|f| normalize_name(f)).filter(|f| !f.is_empty()).collect();
    let (family, family_source) = if !declared_family.is_empty() {
        (declared_family, Source::Declared)
    } else {
        let inferred = infer_family(&profile.model);
        let source = if inferred.is_empty() { Source::Unknown } else { Source::Inferred };
        (inferred, source)
    };
    let (alignment, alignment_source) = match profile.alignment {
        Some(a) => (a, if a == Alignment::Unknown { Source::Unknown } else { Source::Declared }),
        None if relaxed_marker(&profile.model).is_some() || relaxed_marker(name).is_some() => {
            (Alignment::Relaxed, Source::Inferred)
        }
        None => (Alignment::Unknown, Source::Unknown),
    };
    let declared_recipient = profile.recipient.as_deref().map(normalize_name).filter(|r| !r.is_empty());
    let (recipient, recipient_source) = match declared_recipient {
        Some(r) if r != "unknown" => (r, Source::Declared),
        Some(_) => ("unknown".to_string(), Source::Unknown),
        None => match recipient_from_base_url(&profile.base_url) {
            Some(host) => (host, Source::Inferred),
            None => ("unknown".to_string(), Source::Unknown),
        },
    };
    let fields = FieldSources { family: family_source, alignment: alignment_source, recipient: recipient_source };
    let any_unknown =
        fields.family == Source::Unknown || fields.alignment == Source::Unknown || fields.recipient == Source::Unknown;
    let all_declared = fields.family == Source::Declared
        && fields.alignment == Source::Declared
        && fields.recipient == Source::Declared;
    let source = if any_unknown {
        Source::Unknown
    } else if all_declared {
        Source::Declared
    } else {
        Source::Inferred
    };
    Lineage { profile: name.to_string(), family, alignment, recipient, source, fields }
}

impl Lineage {
    /// True when the recipient is `local` or `lan`: no data leaves the operator's hosts.
    pub fn is_operator_owned(&self) -> bool {
        matches!(normalize_name(&self.recipient).as_str(), "local" | "lan")
    }

    /// True when the recipient is unknown (empty counts): such a profile is never a reviewer for anyone.
    pub fn recipient_is_unknown(&self) -> bool {
        let r = normalize_name(&self.recipient);
        r.is_empty() || r == "unknown"
    }

    /// True when the family sets overlap, or either is unknown (empty). Names are compared normalized.
    pub fn shares_family(&self, other: &Lineage) -> bool {
        let norm = |l: &Lineage| -> BTreeSet<String> { l.family.iter().map(|f| normalize_name(f)).collect() };
        let (a, b) = (norm(self), norm(other));
        a.is_empty() || b.is_empty() || a.intersection(&b).next().is_some()
    }

    /// True when, as an agent, this profile counts as relaxed: declared or inferred relaxed, or alignment not declared.
    pub fn counts_as_relaxed_agent(&self) -> bool {
        self.alignment != Alignment::Stock
    }

    /// The families as `a+b`, or `unknown`.
    pub fn family_word(&self) -> String {
        if self.family.is_empty() {
            "unknown".to_string()
        } else {
            self.family.iter().cloned().collect::<Vec<_>>().join("+")
        }
    }

    /// One line: the three values and where each came from.
    pub fn describe(&self) -> String {
        format!(
            "family {} ({}), alignment {} ({}), recipient {} ({})",
            self.family_word(),
            self.fields.family.word(),
            self.alignment.word(),
            self.fields.alignment.word(),
            if self.recipient.is_empty() { "unknown" } else { &self.recipient },
            self.fields.recipient.word()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(model: &str, base: &str) -> ModelProfile {
        ModelProfile { model: model.into(), base_url: base.into(), ..ModelProfile::default() }
    }

    fn fam(id: &str) -> Vec<String> {
        infer_family(id).into_iter().collect()
    }

    #[test]
    fn every_inference_pattern() {
        for (id, want) in [
            ("deepseek-v4.1", "deepseek"),
            ("Qwen3-max", "qwen"),
            ("qwq-32b", "qwen"),
            ("mistral-large", "mistral"),
            ("magistral-medium", "mistral"),
            ("devstral-small", "mistral"),
            ("ministral-8b", "mistral"),
            ("glm-5", "glm"),
            ("chatglm3", "glm"),
            ("kimi-k2", "kimi"),
            ("moonshot-v1", "kimi"),
            ("llama-3.3-70b", "llama"),
            ("inkling-v5", "thinking-machines"),
            ("gpt-5", "openai"),
            ("o3-mini", "openai"),
            ("openai/o1", "openai"),
            ("claude-opus", "anthropic"),
            ("gemini-2.5", "google"),
            ("gemma-3", "google"),
        ] {
            assert_eq!(fam(id), vec![want.to_string()], "{id}");
        }
        for id in ["default", "", "some-model", "foo-o-bar", "fo3", "model-x", "zo1"] {
            assert!(infer_family(id).is_empty(), "{id}: {:?}", infer_family(id));
        }
        assert_eq!(fam("o3"), vec!["openai".to_string()], "o followed by a digit counts as a word of its own");
    }

    #[test]
    fn a_distill_is_in_both_families() {
        assert_eq!(fam("deepseek-r1-distill-qwen-32b"), vec!["deepseek".to_string(), "qwen".to_string()]);
    }

    #[test]
    fn relaxed_markers_in_the_id_and_the_name() {
        for m in RELAXED_MARKERS {
            assert_eq!(relaxed_marker(&format!("glm-{m}-x")), Some(m));
        }
        assert_eq!(relaxed_marker("GLM-Uncensored"), Some("uncensored"));
        assert_eq!(relaxed_marker("glm-5"), None);
        let by_id = resolve("a", &p("glm-5-abliterated", "https://x.example/v1"));
        assert_eq!((by_id.alignment, by_id.fields.alignment), (Alignment::Relaxed, Source::Inferred));
        let by_name = resolve("glm_uncensored", &p("glm-5", "https://x.example/v1"));
        assert_eq!(by_name.alignment, Alignment::Relaxed);
        let plain = resolve("glm", &p("glm-5", "https://x.example/v1"));
        assert_eq!((plain.alignment, plain.fields.alignment), (Alignment::Unknown, Source::Unknown));
    }

    #[test]
    fn declared_values_win_and_the_source_follows() {
        let mut prof = p("deepseek-v4", "http://10.0.0.5:8000/v1");
        let inferred = resolve("dsv41", &prof);
        assert_eq!(inferred.family_word(), "deepseek");
        assert_eq!((inferred.recipient.as_str(), inferred.fields.recipient), ("10.0.0.5", Source::Inferred));
        assert_eq!(inferred.source, Source::Unknown, "an alignment nobody declared leaves the whole unknown");
        prof.family = Some(vec!["Kimi".into(), " deepseek ".into()]);
        prof.alignment = Some(Alignment::Stock);
        prof.recipient = Some("LAN".into());
        let declared = resolve("dsv41", &prof);
        assert_eq!(declared.family_word(), "deepseek+kimi", "a declaration replaces the inference, normalized");
        assert_eq!((declared.alignment, declared.recipient.as_str()), (Alignment::Stock, "lan"));
        assert_eq!(declared.source, Source::Declared);
        assert!(declared.is_operator_owned());
        prof.family = None;
        let mixed = resolve("dsv41", &prof);
        assert_eq!((mixed.source, mixed.fields.family), (Source::Inferred, Source::Inferred));
        prof.alignment = Some(Alignment::Unknown);
        assert_eq!(resolve("dsv41", &prof).source, Source::Unknown);
        prof.alignment = Some(Alignment::Stock);
        prof.model = "default".into();
        assert_eq!(resolve("dsv41", &prof).source, Source::Unknown, "no family at all");
    }

    #[test]
    fn a_loopback_recipient_is_unknown_until_declared() {
        for url in [
            "http://127.0.0.1:8000/v1",
            "http://localhost:8000/v1",
            "http://LOCALHOST/v1",
            "http://[::1]:9000/v1",
            "http://127.4.5.6/v1",
            "http://0.0.0.0:1/v1",
            "http://foo.localhost/v1",
            "not a url at all",
            "",
        ] {
            let l = resolve("x", &p("m", url));
            assert_eq!((l.recipient.as_str(), l.fields.recipient), ("unknown", Source::Unknown), "{url}");
            assert!(l.recipient_is_unknown() && !l.is_operator_owned(), "{url}");
        }
        let mut prof = p("m", "http://127.0.0.1:8000/v1");
        prof.recipient = Some("local".into());
        let l = resolve("x", &prof);
        assert_eq!((l.recipient.as_str(), l.fields.recipient), ("local", Source::Declared));
        prof.recipient = Some("unknown".into());
        assert!(resolve("x", &prof).recipient_is_unknown());
        let hosted = resolve("x", &p("m", "https://user:pw@Token-Plan.Example.com:8443/compatible/v1?x=1"));
        assert_eq!(hosted.recipient, "token-plan.example.com");
        assert_eq!(resolve("x", &p("m", "https://[2001:db8::1]:443/v1")).recipient, "2001:db8::1");
        assert_eq!(resolve("x", &p("m", "api.example.com/v1")).recipient, "api.example.com");
    }

    #[test]
    fn names_are_compared_normalized() {
        let mk = |fam: &[&str], rec: &str| Lineage {
            profile: "p".into(),
            family: fam.iter().map(|s| s.to_string()).collect(),
            alignment: Alignment::Stock,
            recipient: rec.into(),
            source: Source::Declared,
            fields: FieldSources::default(),
        };
        assert!(mk(&["Qwen"], "x").shares_family(&mk(&["qwen"], "x")));
        assert!(mk(&["thinking_machines"], "x").shares_family(&mk(&["thinking-machines"], "x")));
        assert!(!mk(&["Mistral"], "x").shares_family(&mk(&["qwen"], "x")));
        assert!(mk(&[], "x").shares_family(&mk(&["qwen"], "x")), "unknown matches every family");
        assert!(mk(&["a"], " LAN ").is_operator_owned() && mk(&["a"], "Local").is_operator_owned());
        assert!(known_family("Thinking_Machines", &[]) && !known_family("deepseeq", &[]));
        assert!(known_family("Acme", &["acme".to_string()]));
    }

    #[test]
    fn forms_and_old_records() {
        assert_eq!(serde_json::to_string(&Alignment::Relaxed).unwrap_or_default(), "\"relaxed\"");
        assert!(serde_json::from_str::<Alignment>("\"uncensored\"").is_err());
        let old = r#"{"profile":"p","family":["qwen"],"alignment":"stock","recipient":"lan","source":"declared"}"#;
        let l: Lineage = serde_json::from_str(old).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(l.fields, FieldSources::default());
        let line = resolve("x", &p("qwen3", "https://a.example/v1")).describe();
        assert_eq!(line, "family qwen (inferred), alignment unknown (unknown), recipient a.example (inferred)");
        assert!(resolve("x", &p("m", "")).counts_as_relaxed_agent(), "an undeclared alignment counts as relaxed");
    }
}
