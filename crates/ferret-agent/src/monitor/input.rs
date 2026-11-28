//! Building review inputs: what a reviewer is shown, how, and under which limits (`docs/MONITOR.md` §2.4, §2.5).
//!
//! CONTRACT.
//!
//! - `ReviewKind`: `gate` (L1: one pending action, the files it runs and the previous 5 calls; no reasoning, no outputs),
//!   `step` (L2: a batch of one session), `tree` (L3: the mission tree, with the coverage invariant of §5.3 K8), `fleet`
//!   (L4: candidate joins only). `Content`: `full` (redacted content) or `features` (hashes, lengths, classes; no raw
//!   target content). A new-recipient reviewer gets `features` for real-target missions (decision D9); secrets are
//!   redacted in every case.
//! - Layout, stable prefix first so a mission's cached prefix is reused: the compiled system text and few-shot pairs;
//!   AUTHORIZATION (`auth::Authorization`, operator-authored only); HARNESS FACTS (computed classes only: destination
//!   labels `D1..`, credential matches as type, keyed tag and origin, net decisions as labels, first-seen destinations,
//!   sandbox refusals, tripwires fired, ledger op kinds, cross-session joins, census deltas, and for keep-going the reopen
//!   count and budget used); CARRIED STATE (`{category, record labels, score}` per open suspicion, **no free text**:
//!   suspicions only grow until the operator disposes of them); then the RECORDS, labelled `R1..Rn` for this review.
//! - Every agent-influenced string (reasoning, call arguments, file contents, outputs, briefs, messages, recall briefs,
//!   destination strings) is DATA: between `=====DATA <fence>=====` and `=====END <fence>=====`, every line prefixed
//!   `│ ` through `ferret_core::tagsafe::quote_lines`. The fence is per mission, derived from the keyed seed, and never in
//!   agent-visible state. Harness-computed facts never contain an agent string.
//! - Normalisation before matching and display: zero-width and bidi characters removed and counted, host confusables
//!   mapped to ASCII, control characters shown as `\xNN`.
//! - Decoding: secret matching decodes base64, hex, URL and gzip runs of at least `DECODE_MIN_RUN` (8) bytes; a run of at
//!   least `DISPLAY_PREVIEW_MIN` (256) bytes shows as `[base64 3,412 bytes; decoded preview …; secrets: 1 (aws-key
//!   #k:a1b2c3d4)]`.
//! - Redaction: every credential-shaped value and every value in the harness-built secret index becomes
//!   `[secret:<type>:<tag>]` where `tag` is the first 8 hex characters of HMAC-SHA256(`monitor.key`, value), before the
//!   request leaves the daemon (`redaction_tag` formats it). Keyed, so the recipient cannot brute-force a low-entropy
//!   secret.
//! - Reasoning is excerpted by content: deterministic scanners run over the full text (the pre-filter, host, path and
//!   credential extraction, scope words, script shift), each hit is shown with `HIT_CONTEXT_CHARS` (300) either side, then
//!   head and tail fill the rest of `STEP_REASONING_CHARS` (1,500) per step. Calls show up to `CALL_ARG_BYTES` (2 KiB)
//!   plus extraction hits; results show status, size, the first `RESULT_HEAD_LINES` (40) and last `RESULT_TAIL_LINES`
//!   (20) lines and scanner hits, labelled "printed by the agent's program". A child's window also includes its brief, the
//!   messages it received and the ledger entries it acted on. The first window of a mission includes any recall brief.
//! - The whole input is at most `REVIEW_MAX_TOKENS` (48,000) tokens; longer missions use extract-then-evaluate.
//! - On a provider rejection (such as a content filter's 400) the request is retried once with `Content::Features`; the
//!   verdict is then **degraded**: it may raise a flag, never clears a gate or a reopen.
//! - A built input is stored content-addressed under `<home>/monitor/inputs/<sha256>`; `ReviewInput::sha256` is that
//!   name, which a verdict cites (I6).
//!
//! Built by: M6. The pre-filter regular expression is in `docs/MONITOR.md` §2.4.
//!
//! Tests required (M6): fence and quoting under hostile input (a line that is itself a fence, a forged `<harness`, a
//! fake `R12` pointer, a zero-width split of a keyword); redaction tags are stable per value and differ per key; the
//! decode rule; budgets honoured to the character; no agent string reachable from the facts block; the stable prefix is
//! byte-identical across two reviews of one mission; features-only contains no raw content. In P0:
//! `fences_have_the_documented_shape`, `redaction_tags_have_the_documented_shape`, `the_budgets_are_the_documented_ones`,
//! `building_is_not_built_yet`.

use crate::monitor::{not_built, MonitorError};
use serde::{Deserialize, Serialize};

pub const REVIEW_MAX_TOKENS: u64 = 48_000;
pub const STEP_REASONING_CHARS: usize = 1_500;
pub const HIT_CONTEXT_CHARS: usize = 300;
pub const CALL_ARG_BYTES: usize = 2_048;
pub const RESULT_HEAD_LINES: usize = 40;
pub const RESULT_TAIL_LINES: usize = 20;
pub const GATE_PREVIOUS_CALLS: usize = 5;
pub const GATE_FILE_BYTES: usize = 8_192;
pub const DECODE_MIN_RUN: usize = 8;
pub const DISPLAY_PREVIEW_MIN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKind {
    Gate,
    Step,
    Tree,
    Fleet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    Full,
    Features,
}

/// A rendered input and the name it is stored under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewInput {
    pub kind: ReviewKind,
    pub content: Content,
    pub sha256: String,
    pub text: String,
}

/// The opening line of a DATA block.
pub fn fence_open(fence: &str) -> String {
    format!("=====DATA {fence}=====")
}

/// The closing line of a DATA block.
pub fn fence_close(fence: &str) -> String {
    format!("=====END {fence}=====")
}

/// How a redacted secret is written: `[secret:<type>:<tag>]`. `tag` is the first 8 hex characters of the keyed MAC;
/// anything else in its place is replaced by `unkeyed` so a caller's mistake cannot print a value.
pub fn redaction_tag(kind: &str, tag: &str) -> String {
    let kind: String = kind.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect();
    let tag = if tag.len() == 8 && tag.chars().all(|c| c.is_ascii_hexdigit()) {
        tag.to_ascii_lowercase()
    } else {
        "unkeyed".into()
    };
    format!("[secret:{kind}:{tag}]")
}

/// Render the input for one review (M6).
pub fn build(_kind: ReviewKind, _content: Content) -> Result<ReviewInput, MonitorError> {
    not_built("review input builder", "M6")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fences_have_the_documented_shape() {
        assert_eq!(fence_open("f9"), "=====DATA f9=====");
        assert_eq!(fence_close("f9"), "=====END f9=====");
    }

    #[test]
    fn redaction_tags_have_the_documented_shape() {
        assert_eq!(redaction_tag("aws-key", "A1B2C3D4"), "[secret:aws-key:a1b2c3d4]");
        assert_eq!(redaction_tag("jwt", "zz"), "[secret:jwt:unkeyed]");
        assert_eq!(redaction_tag("a]b\nc", "a1b2c3d4"), "[secret:abc:a1b2c3d4]");
    }

    #[test]
    fn the_budgets_are_the_documented_ones() {
        assert_eq!(
            (REVIEW_MAX_TOKENS, STEP_REASONING_CHARS, HIT_CONTEXT_CHARS, CALL_ARG_BYTES, GATE_PREVIOUS_CALLS),
            (48_000, 1_500, 300, 2_048, 5)
        );
        assert_eq!((RESULT_HEAD_LINES, RESULT_TAIL_LINES, DECODE_MIN_RUN, DISPLAY_PREVIEW_MIN), (40, 20, 8, 256));
        assert_eq!(GATE_FILE_BYTES, 8 * 1024);
    }

    #[test]
    fn building_is_not_built_yet() {
        assert!(build(ReviewKind::Step, Content::Full).is_err());
        assert_eq!(serde_json::to_string(&ReviewKind::Tree).unwrap_or_default(), "\"tree\"");
    }
}
