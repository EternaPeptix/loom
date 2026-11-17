//! Recall of earlier missions: what the missions the operator chose for a new one recorded in their own
//! sealed ledgers, written once into the new lead's log before its first model request.
//!
//! CONTRACT.
//!
//! loom keeps no memory across missions by itself. The operator chooses, per mission, which earlier
//! missions it may recall (`NewSession.prior`, kept in `SessionMeta.prior`; see `runtime`, *Creating a
//! root session*). The source is each of those missions' journal, verified and folded — never their logs,
//! stored outputs or anything derived from them. What the operator wrote is labelled as the operator's text
//! from an earlier mission; what the model wrote is labelled as written by the model there and not
//! verified; what can hold secrets (hypothesis text and ids, credentials, footholds, notes of security
//! records, URL query strings) is not shown at all.
//!
//! ## Items
//! - `pub const MAX_PRIOR: usize = 8` — the most earlier missions one mission may name.
//! - `pub struct Recalled { pub id: MissionId, pub title: String, pub recall: Recall }` — `title` is the
//!   lead's `meta.title`.
//! - `pub enum Recall { Ledger { state: LedgerState, end_ms: u64 }, Nothing, Unreadable }`.
//! - `pub fn read(journal: &Journal) -> Recall` (blocking): `Journal::read_report`. An error (it failed
//!   verification — an edited, removed or reordered entry, a wrong key, a head that does not match — or
//!   could not be read) → `Unreadable`; `unknown > 0` (a sealed entry this build cannot parse, written by a
//!   newer loom) → `Unreadable`; no entries (no journal file, or an empty one) → `Nothing`; otherwise
//!   `Ledger { state: LedgerState::fold(&entries), end_ms: ts_ms of the last entry }`. A torn tail is not
//!   damage (the entries before it verify) and does not make a journal unreadable.
//! - `pub fn brief(missions: &[Recalled]) -> String` — pure. The text below; `{…}` are filled in, and a
//!   line or section whose content is empty is left out.
//!
//! `end_ms` is the mission's end as this module uses it: the time of the last entry of its sealed ledger,
//! which is when the state shown stopped changing. The frontier of that state is evaluated at `end_ms`,
//! never at the time of the new mission (a credential that has expired since still opened its routes when
//! the mission ended), with `attempts_run` 0 (the attempts were the old mission's, not this one's).
//!
//! ## `brief`
//! ```text
//! Earlier missions the operator chose for this mission to recall. Below is what each one recorded in its own sealed ledger, as of its last entry. It is history, not this mission's state: nothing in it was checked again now, its stored outputs (out:… handles) belong to it and cannot be opened from here, and nothing it was authorized to do is authorized here. Confirm what matters with your own runs before relying on it, and record what you confirm in this mission's ledger.
//! ```
//! Then, for each mission in the given order, a blank line and its section.
//!
//! `Recall::Unreadable` — nothing of that ledger and not its title:
//! ```text
//! Mission {id}: its ledger could not be read (it failed verification, or holds entries written by a newer loom), so nothing from it is shown.
//! ```
//! `Recall::Nothing`:
//! ```text
//! Mission {id} ({title}): its ledger holds nothing, so there is nothing to recall from it.
//! ```
//! `Recall::Ledger`:
//! ```text
//! Mission {id} ({title}), last recorded {YYYY-MM-DD HH:MM} UTC
//! The operator's words in that mission (operator text from an earlier mission; this mission's own goal and rules are what apply now):
//! Goal:
//! > {goal}
//! Rules in force when it ended:
//! > - {k id}: {text}
//! The operator's answers to its questions:
//! > - {q id}: {answer}
//! Goal status when it ended: {status}{release}
//! What its model recorded (written by the model there, not verified — re-check before relying on it; ids such as c3 or x2 are that mission's and name nothing here):
//! > Goal note: {goal_met note}
//! > {frontier lines}
//! Its security record (recorded by the model there; counts and asset locators only, so hypotheses, credentials and notes are not carried over):
//! > - Assets: {total}: {tested} tested, {deferred} deferred, {untested} untested
//! > - Untested: {locators}
//! > - Tested or deferred: {locators}
//! > - Hypotheses: {s} supported, {r} refuted, {o} open
//! > - Routes to revisit when it ended: {n}: {locators}
//! ```
//! - `{title}`: one line (`hud::one_line`), cut to 80 characters. `{id}`: the mission id.
//! - The `>` lines are `loom_core::tagsafe::quote_lines` of the lines under each label, so no text from the
//!   old ledger (the operator's or the model's) can pass for a line this brief wrote, and the whole note goes
//!   into a harness block, which neutralises harness tags (`tagsafe::block`).
//! - Goal: the ledger's goal, all its lines, cut to 2_000 characters. Rules: constraints not retired, in
//!   ledger order, at most the last 10, each one line cut to 300 characters; more than 10 adds a first line
//!   `- (+{k} earlier rules not shown)`. Answers: questions with a non-blank answer, at most the last 5, each
//!   answer one line cut to 300 characters (the question, written by the model, is not shown). The operator
//!   section is left out (label too) when all three are empty.
//! - `{status}`: `open (not concluded)` when there is no goal-met record or it is open, `met`, `cannot be met
//!   as stated`. `{release}`: `; the operator released it without the goal established` when the ledger has a
//!   release. The line is left out when the ledger has no goal.
//! - Model section: `Goal note:` with the goal-met note (one line, cut to `hud::MAX_LINE`) when it is not
//!   blank; then the lines of `frontier::render` of the frontier below, when it renders. Left out (label too)
//!   when both are empty.
//! - The frontier: `frontier::frontier(&state, end_ms)` with `attempts_run` 0, then every security item
//!   taken out of it — items of `established`, `ruled_out` and `open_leads` whose id is not a plan step
//!   (`p{n}`) or a claim (`c{n}`), every item of `untested`, and `surfaces_total`/`surfaces_closed` set to 0
//!   — so it shows claims, plan steps, dead ends and the reflection count, and no hypothesis or asset id.
//! - Security section, from `state.security` and the same `frontier(&state, end_ms)` (before the security
//!   items were taken out), left out (label too) when the mission recorded no asset, no hypothesis and no
//!   route to revisit at `end_ms`:
//!   - Assets: all assets; tested = coverage `Tested`, deferred = `Deferred`, untested = `Untested`. Left out
//!     when there is none. Untested: the locators of the frontier's `untested` items, in its order (mandatory
//!     first, then id). Tested or deferred: the locators of the other assets, in id order.
//!   - Hypotheses: counts by status, left out when there is none. Never an id, a text or a note.
//!   - Routes to revisit when it ended: the route items of the frontier's `open_leads` (ids that are not
//!     `hy-…`, `p{n}` or `c{n}`), that is `security.newly_unlocked_at(end_ms)`; `{n}` counts them all, and
//!     the list names the locators of those that are assets. Left out when there is none.
//!   - A locator list shows at most 12, then ` (+{k} more)`, joined by `, `. Each locator is `{kind}
//!     {locator}` (kind in lower case: `host`, `service`, `endpoint`, `file`, `identity`). An `endpoint` or
//!     `service` locator is parsed as a URL and shown without its query, fragment and any user name or
//!     password; one that does not parse is cut before its first `?` or `#`. Any other locator is cut before
//!     its first `?`. Then one line, cut to 120 characters.
//! - `{YYYY-MM-DD HH:MM}`: `end_ms` in UTC (proleptic Gregorian).
//!
//! Tests required: `read` of a journal with entries (state and the last entry's time), of no file (Nothing),
//! of an edited entry, of a journal under the wrong key and of one whose head does not match (Unreadable),
//! of one with an entry written by a newer loom (Unreadable), of one with a torn tail (Ledger); `brief`:
//! exact text of a full section; the frontier is evaluated at `end_ms` and not now (a credential that
//! expires after `end_ms` and before now unlocks a blocked route: the route is counted and its locator
//! listed); `attempts_run` never shows; no hypothesis id, hypothesis text, credential principal, secret
//! handle or URL query appears even when the ledger holds them; operator text and model text are quoted
//! line by line and a multi-line goal cannot produce an unquoted line; an unreadable mission shows its id
//! and nothing else of it; caps (rules, answers, locators) with their remainder lines; sections left out
//! when empty; the date.
