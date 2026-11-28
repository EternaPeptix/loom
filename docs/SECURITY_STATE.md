# Durable security state

Security state is an additive projection of the sealed mission journal. Existing journals and ledger
snapshots remain readable. New `security` journal entries contain a typed `action`; an older Ferret
build refuses to append after an unknown action rather than dropping it. No security observation
grants network scope, approves an action, or establishes a vulnerability by itself.

Packs opt into `security_record`, `security_query`, and `security_ingest`. Observation writes cite existing
attested mission evidence. These tools use the same sealed append and recorded-tool pipeline as the
other ledger tools. `security_query` never writes or executes a target. Planning, aliases, rule
installation, and retraction reasons do not themselves constitute observations.

## Assets, credentials, footholds, and coverage

`security_record` accepts one `operation` object:

```json
{"operation":{"action":"asset_upsert","asset":{"kind":"host","locator":"Example.TEST.","evidence":["e1"],"mandatory":true}}}
```

Its result names what the write changed, not the whole state: the journal `entry`, the touched records
in full under `recorded` (their ids and a count per collection when they are many), `removed` ids, the
size of each collection under `counts`, and where to read the rest (`security_query`).

Asset kinds are `host`, `service`, `endpoint`, `file`, and `identity`. Host/IP spelling and URL scheme,
host, and default port are canonicalized. URL paths, query strings, and identity/file locators retain
case. URL credentials are rejected. IDs are full SHA-256 hashes of length-delimited typed tuples, so
deduplication is deterministic across machines. Repeated observations merge their evidence; they
cannot change an asset's parent or downgrade mandatory coverage. A parent creates a `contains`
relation automatically. `alias_add {alias,target}` provides human-readable aliases. Tool inputs accept
exact aliases or unique prefixes of at least four characters; ambiguity is an error.

`credential_add` takes `credential` with `asset`, `principal`, `secret_handle`, `evidence`, optional
`unlocks` and `expires_ms`. `secret_handle` must resolve to an existing output blob and is recorded in
full canonical form. Passwords, private keys, and tokens do not belong in this field. `foothold_add`
takes `foothold` with `asset`, `principal`, `access`, `evidence`, optional `unlocks` and `expires_ms`.
Credentials and footholds are deduplicated, evidence-linked observations; they do not prove that a
login or operation will still work. Reobserving a record updates its expiry and merges evidence.

Every mandatory asset starts with `coverage.status=untested`. `coverage_set` requires an asset ID and
one of these dispositions:

```json
{"status":"tested","evidence":["e2"]}
{"status":"deferred","reason":"The required fixture is not available in this mission."}
{"status":"untested"}
```

Missing/unattested evidence and blank deferral reasons are rejected. `mandatory_open()` supplies the
finish gate with remaining asset IDs. Tested coverage records that an observation exists; it does
not mechanically establish exhaustive testing of the asset.

Every evidence record carries the grade the harness gave the output it quotes (`docs/DESIGN.md` §7):
`run`, `analysis` (`dep_scan`, `bin_decompile`, `bin_xrefs`), `read`, or `reference` (`cve_lookup`,
`cve_search`, `advisory_lookup`, a reference-host `web_fetch`). Security records cite evidence ids and
accept any attested grade. The goal-met conclusion, a verifier's objection and stuck detection accept
only a run, so a scanner verdict, a decompilation, an imported scan or an advisory can locate a lead
and support a claim, but cannot by itself show that the goal is met.

## Per-`(surface, risk_area)` coverage & evidence provenance

In addition to asset-level `coverage_set`, `security_record` supports per-`(surface, risk_area)`
coverage entries (`cv-<sha256>`) with five explicit dispositions:

- `reported`: confirmed issue backed by at least one attested evidence ID (`evidence:[eN]`).
- `no_issue_found`: tested thoroughly and found nothing (requires attested `evidence` or a nonblank `reason`).
- `ruled_out`: disproved a specific candidate; requires both `control` (the specific defense/guard) and `location` (file:line, handler, or config where it runs).
- `not_applicable`: risk cannot apply to this surface; requires a nonblank `reason`.
- `needs_follow_up`: plausible but unresolved; requires a nonblank `reason` naming the specific proof gap or blocker.

Entries are uniquely keyed by case-insensitive trimmed `(surface, risk_area)`. Attempting to call
`coverage_record` on an existing `(surface, risk_area)` is rejected with the existing entry's ID,
author, and current outcome, directing the agent to call `coverage_update` instead. `coverage_update`
updates the row in place while preserving every prior state in `history` (keeping `surface`,
`risk_area`, and `recorded_by` immutable).

`security_query {view:"coverage"}` keeps legacy `mandatory_open` and `assets` fields while
separating `agent_reported` coverage entries (with per-entry resolved `evidence_provenance`) from
`machine_observed` runtime facts (attested evidence grade counts, mandatory assets still open,
worker child sessions that recorded no coverage under `silent_children`, and `gaps.unbacked_clears`
flagging any `no_issue_found`/`ruled_out` claim that has no attested `run` evidence). Optional
filters `outcome` and `surface` narrow the returned entries.

## Structured findings & SARIF 2.1.0 export

`security_record` records structured security findings (`fn-<sha256>`) via `finding_record` and
revises or withdraws them via `finding_update` (keeping a per-update `revisions` audit trail):

- Required quality gates: `title`, `description`, `impact`, `target`, attested `evidence:[eN]`
  (or inline `out:` handles synthesized automatically), `counterevidence` (strongest case against
  the finding or controls checked), `confidence` (`high|medium|low`, with `confidence_rationale`
  required whenever confidence is not `high`), `severity_change_conditions`, and either an 8-metric
  CVSS 3.1 `cvss_breakdown` (from which `cvss`, `cvss_vector`, and `severity` are computed
  mechanically per FIRST CVSS v3.1) or an explicit `severity` (`critical|high|medium|low|info`).
- Optional structured fields: `technical_analysis`, `remediation_steps`, `assumptions`,
  `poc_description`, `poc_handle` (an `out:` handle to a stored PoC — raw exploit payloads are
  never embedded into SARIF), `fix_effort`, `endpoint`, `method`, `cwe` (`CWE-NNN`), `cve`
  (`CVE-YYYY-NNNN+`), `http_exchanges`, `asset`, `claim`, and repo-relative POSIX `code_locations`
  (`{file, start_line, end_line, snippet?, label?, fix_before?, fix_after?}`). Whenever any
  `code_locations` item carries `fix_after`, `fix_verification` is required.
- Duplicate findings are rejected with the existing `fn-` ID so updates go through `finding_update`.
- `security_query {view:"findings", severity?:...}` lists findings with resolved
  `evidence_provenance` and active/withdrawn severity counts.

Export or inspect any mission's active findings and per-surface coverage provenance (OASIS SARIF 2.1.0,
compatible with GitHub Code Scanning `upload-sarif` and ASPM tools):

- CLI inspect: `ferret findings <session|mission> [-a/--all] [--severity <critical|high|medium|low|info>] [--json]`
- CLI export: `ferret sarif <session|mission> [-o findings.sarif] [--repo-name owner/repo --repo-uri ... --commit ... --branch ... --git-ref ...]`
- HTTP API: `GET /api/missions/{id}/sarif`

SARIF rules are keyed on canonical `CWE-NNN` (with `helpUri`, `security-severity`, and `stride:<leg>`
tags), physical locations drop unsafe paths and anchor locationless DAST findings to `SECURITY.md`
with `properties.synthetic_location: true`, verified `fix_before`/`fix_after` pairs emit SARIF
`fixes`, deterministic `partialFingerprints.primaryLocationLineHash` and `ferret_vuln_class_hash`
enable cross-run alert reconciliation, non-`reported` coverage entries ride as `pass` /
`notApplicable` / `open` results (`level: "none"`), and `run.invocations[0]` sets
`executionSuccessful: false` with warning notifications whenever follow-up gaps, untested mandatory
assets, silent children, or operator release leave coverage incomplete.

## How `security_record` reads near misses

Logged missions refused many `security_record` calls for shape rather than substance, so the tool reads
an operation where its meaning is unambiguous and says exactly what it did. Each rewrite is one
sentence under `normalized` in the result (`{"entry": n, "normalized": [...], "state": ...}`; the key is
absent when nothing was rewritten). What is read:

- `ops` or `items` for a batch's `operations`; a batch element is read on its own and a failing element
  is named, whichever check refuses it ("Operation 2 of 3 in the batch (asset_upsert): ..."). A batch stays one atomic append.
- Wrapper fields for `asset_upsert`, `credential_add`, `foothold_add`, `relation_add` given at the top
  level, `evidence` given beside the wrapper, `username`/`user` for `principal`.
- A host locator written with a scheme, port, path or credentials is recorded as the host. A service or
  endpoint locator without a scheme gets `https://` when its port is 443 and `http://` otherwise. A locator
  loses a leading HTTP method and any text after the URL, and a path is joined to the URL of its
  `parent` when the scheme, host and port stay the same. User information in a given value is never quoted back. A description after
  a relative path is cut like one after a URL, and `ftp:21`-style host names are not read as URLs.
- `ops` is read as `operations`. The asset in a `cred` or `auth` condition may be an alias or prefix; it is stored as
  the full asset ID.

What is refused, before anything is recorded and with the shape to send: an action that belongs to
another tool, an unknown action, a removed operation (`hypothesis_*`, `rule_*`: "Hypotheses are not recorded in the
security state any more: write the idea as a note (`note` with kind `decision`) or test it and record what
the run showed."), a condition that is not a typed `{kind, value}`, a
service or endpoint locator that is a bare path with no parent. Evidence must
still exist and be attested, authority is still checked by the tool and the core, and these records
never authorize network access. The tool description lists the exact shape of every action and differs

## Conditions, revisits, and crashes

`blocked_on {target,conditions}` associates an existing claim/dead-end ID with typed prerequisites:
each condition is `{kind,value}` where kind is `auth`, `cred`, `role`, `leak`, `offset`, or `key`.
`condition_unlock {conditions,evidence}` records explicit satisfaction. Credentials automatically
satisfy `cred:<asset ID>`; footholds satisfy `auth:<asset ID>`, in addition to their explicit unlocks.
`security_query {view:"revisit",now_ms:...}` excludes expired credential/foothold observations and
lists only routes whose entire prerequisite set is available. `revisit_acknowledge {target}` removes
a handled notification; setting `blocked_on` again makes the route eligible for another notification.
The pure `newly_unlocked()` API uses time zero; callers that need current validity use
`newly_unlocked_at(now_ms)`.

`crash_record` takes `signature` and `attempt`. A signature has a sanitizer class, one to three
`{function,file,line?}` frames, and outcome `crash`. Only frame zero's line participates in its ID;
caller lines do not. Timeout, OOM, no-crash, and libFuzzer exit-71 outcomes cannot be crash signatures.
Each signature keeps a total attempt count and its six most recent compact attempts. Attempts cite
attested evidence. This is structured signature deduplication, not a parser that trusts arbitrary
sanitizer prose or a determination that a crash matches the requested vulnerability.

Hypotheses and the rule engine are not part of the harness: the operations `hypothesis_open`,
`hypothesis_priority`, `hypothesis_evidence`, `hypothesis_verdict`, `rule_install` and `rule_retract` are
refused when new, and older journals that hold them still load (they change nothing when the state is
read). Deciding what is probably true and what follows from it is the model's work; the state keeps only
what was observed. `fact_assert {fact:{predicate,args},evidence}` records a ground string tuple with its
evidence and `fact_retract {id,reason}` deactivates it, keeping history. There is no derivation from facts,
no `why`, no `what_if` and no `path_suggest`.

## Relations

`relation_add` takes `relation:{from,to,kind,cost,evidence,expires_ms?}`. Endpoints must be existing
assets. Costs are integers 1–1000. Relations are explicit observations; nothing is searched over them.

## Scanner imports

`security_ingest {format,handle,evidence}` reads an existing observed `out:` blob. Evidence must cite
that exact blob, and the producer must be a mission observation, such as an executed command or read
file. Model prose, another agent's report, and runtime state playback are refused. Imports execute
no scanner, network request, or target code.

The supported input shapes are deliberately explicit:

| Format | Accepted shape |
| --- | --- |
| `nmap` | One `nmaprun` XML root; IPv4/IPv6 host addresses and open TCP/UDP/SCTP ports. The inert `<!DOCTYPE nmaprun>` declaration is accepted; external/entity-bearing DTDs are refused. |
| `nuclei` | JSONL objects with `matched-at` or `host`. |
| `ffuf` | JSON object with `results` array; every result has an absolute `url`. |
| `netexec` | JSON array, or `hosts`/`results` array, with `host`/`hostname`/`ip`, optional numeric `port` and documented `protocol`. Plain console output is unsupported. |
| `bloodhound` | JSON `data` array and supported `meta.type`; objects supply `Properties.name` or `ObjectIdentifier`. |

Imports are limited to 2 MiB and 500 canonical assets. Required-field, parse, or validation errors
reject the entire import. A single atomic sealed batch makes assets and their containing-host
relationships durable. Scanner severity, credentials, group membership, and exploitability claims
are not imported as verified facts. Unsupported scanner versions/formats fail visibly rather than
guessing their meaning.

## Deterministic 3-axis finding deduplication

Every structured finding (`finding_record`) computes a deterministic SHA-256 `fingerprint` across three
canonical axes:
1. normalized vulnerability class (canonical `CWE-NNN` when present, otherwise normalized `vuln_class`);
2. canonical host / asset locator (stripping credentials and trailing dots); and
3. normalized endpoint path plus sorted query parameter names (or primary `code_location` when no URL is given).

Recording a second active finding with the same fingerprint is rejected so agents refine the existing
`fn-...` record via `finding_update` instead of creating reworded duplicates. Withdrawn findings do not
block recording a newly substantiated finding.

## HAR 1.2 traffic export and import

Operators can inspect captured mission HTTP traffic live or round-trip it with Burp Suite, OWASP ZAP, or browser DevTools:
- `ferret traffic <session> [--host HOST] [--after SEQ] [-n N] [--json]` (or `ferret traffic --target <name> [--node NODE] [-n N] [--json]`)
- `GET /api/missions/{id}/har?host=&limit=` or `ferret har export <session|mission> [-o out.har] [--host HOST] [--limit N]`
- `POST /api/missions/{id}/har` or `ferret har import <session|mission> traffic.har`

URL userinfo is always stripped; binary bodies use `encoding: "base64"`; imported exchanges get preserved
`_ferretExchangeId` values or deterministic `ex-har-*` IDs so repeated imports skip duplicates idempotently.

## Egress noise governor, assessment `User-Agent`, and operator-only rewrite rules

- **`[network] noise_profile`**: `"off"` (default passthrough) | `"quiet"` (2 rps, concurrency 1/host, 8 global) |
  `"balanced"` (5 rps, 2/host, 16 global) | `"aggressive"` (20 rps, 4/host, 32 global). Enforced mechanically in
  the egress proxy with jitter and `429`/`503` (`Retry-After`) per-host backoff; non-`off` profiles also inject
  a code-owned low-and-slow CLI scanner flags block into the session prompt. Inspect live counters with
  `ferret net --noise [--json]` or `GET /api/network/noise`.
- **`[network.assessment_ua]`**: optional `{ origins = ["https://app.example.test"], reference = "bb-42" }`.
  Attaches `User-Agent: Ferret-Assessment/1.0 (engagement=bb-42)` ONLY on exact approved `(scheme, host, port)`
  origins when a request has no explicit `User-Agent`, never leaking across cross-origin redirects.
- **Operator-only proxy rewrite rules**: managed exclusively via `/api/traffic/rewrite-rules` and
  `ferret rewrite list [--json]|add|enable|disable|rm|example` (never exposed as an agent tool). Rules are created disabled,
  stored atomically in `<ferret home>/rewrite_rules.json` (0600), refuse mutating framing/hop/`Host`/`Proxy-*`
  headers or `CONNECT`, mask `sensitive: true` values on API reads, and reload live without restarting.

## Operator-scoped read-only email inbox (`[mail]` / `inbox_read`)

Disabled by default. Operators who want agents to activate bug bounty platform or target test accounts and
read OTP / confirmation links without exposing personal mail can configure `[mail]` in `config.toml`:

```toml
[mail]
enabled = true
backend = "imaps"                        # or "maildir" (with maildir_path = "/path/to/maildir") for local labs
host = "imap.gmail.com"
port = 993
username = "researcher@gmail.com"
password_file = "~/.ferret/keys/mail.pass" # must be chmod 600; never inline
auth = "login"                           # or "xoauth2"
folder = "INBOX"
allow_senders = ["*@hackerone.com", "*@bugcrowd.com", "*@intigriti.com", "*@yeswehack.com", "*@*.target.example"]
allow_recipients = ["researcher+bb-*@gmail.com"] # optional plus-address filter
require_auth_pass = true                 # default false; true requires Authentication-Results dkim=pass or spf=pass
max_age_minutes = 120                    # only recent mail (0 = unbounded)
max_messages = 20                        # 1..=50
# roles = ["lead", "worker"]             # optional; empty = every non-read-only role
```

- `allow_senders` is mandatory and cannot be `*` or `*@*`. Display-name spoofing (`"security@hackerone.com" <phish@evil.test>`) is stripped before matching.
- IMAPS opens the mailbox strictly read-only (`EXAMINE` + `BODY.PEEK[...]`), checks policy on headers BEFORE fetching any body, and never reveals non-matching messages.
- `inbox_read` is dynamically registered ONLY when `[mail] enabled = true`; verify setup with `ferret mail check`.

## Two-way Signal notifications and replies (`[signal]`)

Disabled by default. Connects natively from `ferret daemon` to a local `signal-cli daemon --http` instance
(outbound JSON-RPC `/api/v1/rpc`, inbound SSE `/api/v1/events`) so operators receive `blocker`, `question`,
`approval`, `parked`, `finished`, `error`, and optional `disk` alerts on Signal (plus `[notify] repeat_minutes`
and post-restart open-blocker reminders) and can answer or steer missions directly from their phone:

- **Strict sender & group allowlists:** `allow_from` is mandatory, validated at config check time (explicit
  E.164 phone numbers like `+15550199` or Signal ACI/PNI UUIDs; `*` is refused), and unauthorized senders are
  ignored (logged at `warn`). `allow_groups` accepts raw `<groupId>` or `group:<groupId>` (normalized on
  load; a `group:<groupId>` `recipient` is allowed automatically).
- **Phone Number Privacy (PNP):** When Signal hides phone numbers, inbound envelopes may carry only
  `sourceUuid`. Discover your ACI UUID via `signal-cli -a +15550100 listContacts --all-recipients` and
  include it in `allow_from` (and `recipient` if needed); plain `<uuid>`, `u:<uuid>`, and `PNI:<uuid>` are
  accepted.
- **Safety-number trust (`UNTRUSTED_IDENTITY`):** After a Signal reinstall or device change, inspect pending
  identities with `signal-cli -a +15550100 listIdentities` and trust the verified safety number with
  `signal-cli -a +15550100 trust -v "<safety-number>" <recipient>` (or `trust -a <recipient>` for your own
  re-linked device), then verify with `ferret signal test`.
- **Safe routing & scope approvals:** Quote-replying to an alert routes directly to that inbox item
  (`Runtime::answer`, expanding option numbers `1..N`), grants/denies `request_scope` approvals
  (`approve`/`yes`/`all`, host numbers like `1 2`, or `deny`/`no`/`dismiss`), or sends a follow-up to that
  session (`Runtime::send_message`) for `finished`/`error` alerts, persisted across restarts in
  `<ferret home>/signal_sent.json` (mode `0600`). Unmatched quote-replies never fall through to answer a
  different mission's open blocker.
- **Commands & diagnostics:** Plain DM replies answer an unambiguous sole open blocking item (group chatter
  is ignored unless quoted, `@<id>`-addressed, or a slash command); `/inbox`, `/status`, `/tail [id|#n] [count]`,
  `/scope <id|#n> [host...]`, `/dismiss [id|#n]`, `/stop [id|#n]`, `/resume [id|#n]`, `/approve <id|#n> <text>`,
  `/rule <id|#n> <text>`, `/release <id|#n> <reason>`, `/mute [15m|2h|off]`, `/unmute`, and `/help` (`/start`)
  work from Signal. Verify setup with `ferret signal check` and `ferret signal test`, and monitor live bridge
  health in `ferret status` / `GET /api/status`. See `docs/RUN.md` ("Signal") for step-by-step setup and
  troubleshooting.
- **Isolated guest chat & unknown-sender gatekeeper (`[signal.guests]`):** Disabled by default (fail-closed:
  non-operator senders stay silently dropped). When enabled, guest routing is strictly DM-only (non-operator
  group messages are always silently dropped). Unknown DM senders never invoke an LLM: blocked contacts are
  silently dropped (matched across E.164, Signal UUID, and learned PNP mappings), while new senders receive
  a fixed `unknown_reply` gated by `unknown_cooldown_hours` and trigger a quote-replyable
  `[Ferret · NEW CONTACT]` owner alert. Approved guests (static `allow` with `*` refused, or owner-approved
  in `<ferret home>/signal_guests.json` mode `0600`) can never reach operator slash commands, sessions,
  workspaces, files, mail, or inbox items; their turns run asynchronously through `Runtime::isolated_guest_chat`
  (`Priority::Background`, `text_calls: false`, immutable safety boundary preamble ahead of optional
  `persona`, zero tools or strictly `leave_note_for_owner` capped at 3 notes / 15 min and 500 chars),
  bounded by a 2000-character inbound limit, `rate_limit_per_hour`, and a per-guest single-flight guard.
  Owners manage guests via quote-replies or `/guests` and `/guest approve|revoke|block|unblock|clear|say`.



