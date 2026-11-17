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
//! Built by: M2 (the joins, shadow), M6 (L4 review).
//!
//! Tests required (M2): each join over a fixture; the R5 conditions; the not-R5 conditions. In P0: `ten_joins_in_order`.

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
