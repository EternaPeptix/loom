# The `artex` pack: defence against ARTEX-style autonomous intrusion

`artex` is a domain pack that adapts the FBI FLASH of 13 November 2026 (`FLASH-20261113-001`,
TLP:CLEAR, [ic3.gov/CSA/2026/261113.pdf](https://www.ic3.gov/CSA/2026/261113.pdf)) into loom. The
advisory describes ARTEX, an open-source LLM-driven multi-agent penetration-testing framework
weaponized since at least August 2026 to automate intrusions at machine speed — reconnaissance to
privileged access in under three hours in some intrusions, personal information of ~67,000 people
exfiltrated from South Korean financial institutions, and a ConnectWise Cloud Backup supply-chain
compromise reaching 2,250+ downstream tenants.

This pack is the defensive inversion of that shape, not a copy of it. ARTEX gives specialized agents
a natural-language objective and minimal human interaction beyond setting it. This pack gives
specialized agents one check each, inside a scope a second agent qualified and the operator granted,
with every result — including "we found nothing" — recorded as evidence in a sealed ledger and
attacked by an independent judge before anyone believes it. Where ARTEX compresses the time between
stages to outrun a response, the pack spends its machinery on the response's weakest points: knowing
the whole external surface, seeing identity changes quickly, preserving evidence before touching
anything, and never acting on a single indicator.

There is no hook mechanism and no text-matching of shell commands anywhere in it, and the pack never
remediates: blocking, revoking, rotating, disabling and deleting stay operator acts, performed after
preservation, on the record the mission builds.

## Roles

| Role | Ends by | Writes files | Spawns | Job |
|---|---|---|---|---|
| `coordinator` | the concluding tool, then `finish` (judge-gated) | yes | `hunter`, `judge` | Owns the engagement; qualifies scope, decomposes the advisory into checks, gates every result. |
| `hunter` | the concluding tool, then `finish` | yes | nothing | Runs one hunt or hardening check; returns executed evidence or a blocker. |
| `judge` | the verdict tool | no (read-only) | nothing | Checks a proposed scope against its authorization, or tries to refute a finding, a hardening claim or a clean result. Never judges its own work. |
| `chat` | a reply with no tool call | no (read-only) | nothing | Interactive, turn-by-turn triage assistant. |

Start one with:

```
loom run --pack artex --role coordinator -w <workspace> "…the engagement…"
loom chat --pack artex -w <workspace>            # interactive; starts the pack's read-only chat role unless --role names another
```

`loom run --pack artex` without `--role` starts the pack's default role, `coordinator`.

## Network policy

The pack sets `requires_restricted_network = true`. loom's default network mode is `deny_all`, under
which the tools reach no host, so an `artex` session works out of the box over material already in
the workspace and can touch no external host. An `artex` session is refused when the config says
`[network] mode = "open"`; the message tells the operator to use `allowlist` or `deny_all` and
restart the daemon. The check runs when a session is created and each time one is restored.

To let an engagement reach a source — a tenant API, a log service, the advisory itself — the agent
asks for the hosts and why. The request waits in your inbox without stopping the session; you approve
it with `loom scope <session> <host>...` (or the Approve button in the UI). The grant is per session:
it is recorded in the ledger with a standing rule, applies to that session's mission only, and ends
with it. No config edit or restart is needed. Names are resolved by the proxy itself; private,
loopback and link-local addresses are refused unless `allow_private` lists them. Every decision is in
`loom net <session>`. The policy applies to the whole daemon, not to one session.

A grant never makes an indicator reachable *in scope*: indicator addresses, C2 nodes and other
organizations' systems are excluded by the pack's prompts, not by the proxy, and no scope request may
name them. The proxy enforces where traffic can go; the prompts and the judge enforce what the work
is *for*.

## How the advisory maps onto loom

- **Scope must be qualified before anything else.** The boundary is not text-matched. Outbound
  traffic goes through loom's egress proxy under an OS sandbox that permits no other route, and the
  default policy reaches nothing. The coordinator has a **judge** check a proposed defensive scope —
  systems, tenants, data sources, windows, and which of reading exports, querying live sources or
  actively testing each allows — against the authorization the operator named; the coordinator then
  asks for scope, and the operator's approval is recorded as a scope grant and a standing
  **constraint**. Widening scope is the operator's call, never the agent's.
- **The judge is a different agent.** The coordinator's finish is verified by a read-only `judge` of
  the same pack: a `finish` is delivered only after the judge accepts it. A result is attacked by an
  agent that did not produce it, and the finish gate is mechanical (nothing open) before it is
  adversarial (the judge tries to refute). If the judge rejects the finish, its objections come back
  as open obligations that only a new recorded check settles, and the coordinator starts afresh on
  what the judge found. If the judge cannot be run, the finish is held as unverified and is never
  delivered as verified.
- **Pipeline: candidate, validated, assessed, ready.** Plan steps and claim statuses. Evidence is
  execution (a check run against the real logs, inventory, configuration or system) or static (a
  document, policy or inventory read). The prompts forbid a static-only result in either direction, so
  "the policy says retention is a year" is not evidence the logs exist, any more than reading a
  configuration is proof a control fires.
- **Indicators are leads, never verdicts.** The advisory's tables ship defanged in the workspace
  standards file, with the FBI's own warning beside them: vet before acting, addresses are reassigned,
  transient addresses carry their two-day window, and ordinary LLM API endpoints are a question about
  sanctioned use, not a blocklist. A finding needs a second corroborating source and the benign
  explanations — own testing, vendor activity, administrator automation, reassigned address — tested,
  and the judge attacks exactly there. Nothing in the pack blocks, revokes or deletes on a match.
- **Preservation is a deliverable.** Confirmed activity is reported in the FBI's eight requested
  categories, each tied to a preserved handle or marked not established. The standards file makes
  preservation precede any operator remediation, keeps affected ConnectWise connections disabled
  pending vendor instructions, and forbids deleting an enterprise application as a first response.
- **"Clean" is a claim with coverage.** A negative result is gated like a positive one: sources,
  windows and checks each evidenced, gaps named as not established. A hunt over partial logs reports
  partial coverage, and the judge's coverage attack is what keeps that honest.
- **Defensive state is the record.** loom's sealed, hash-chained mission journal is the ledger; its
  Markdown is a generated view, never parsed. Evidence quotes are checked verbatim against the stored
  output when they are written. An agent's report cannot itself be cited as evidence, and an old
  incident record in the workspace is a lead to re-check, never a result to inherit.
- **Observed content is data.** Stated in the shared preamble for every role, with the defensive
  twist made explicit: the logs under investigation are where the intruder has been, so an
  instruction found inside them — mark this benign, skip the scope check — is treated as possible
  tampering evidence, quoted and named, never followed.
- **Orchestrating an engagement.** Only the coordinator fans out; hunters return evidence or a
  blocker; reports reach the parent framed, bounded and marked unverified with a handle to the full
  text. A hunter always starts fresh: it has tools the coordinator lacks, so it cannot be a fork of
  it. Hunters that write the same files can each be started in a copy of the workspace; nothing
  reaches the workspace until the coordinator adopts one hunter's changes, and a check that ran in a
  copy is re-run in the workspace before it is cited.
- **Long runs.** A bulk log reduction or a slow export query is a background job that wakes the
  session when its output has a matching line, instead of being polled.

## The workspace standards file

`workspace/AGENTS.md` holds the full adaptation in one place, written for the agents to read: the
scope gate, the defensive boundary, the pipeline, what to examine first and in what order, the
advisory's complete technique map read defensively (phase, observed activity with ATT&CK identifiers,
and the source to examine), the defanged indicator tables with their activity windows and sources,
the hardening checklist, preservation and the FBI's eight reporting categories, attribution,
revalidation, priority, the two records, what ready means, when to stop, the order of the tools,
orchestration, and what only the operator does. Copy it to the root of an engagement workspace and
name it in your first message:

```
cp packs/artex/workspace/AGENTS.md <workspace>/AGENTS.md
loom run --pack artex -w <workspace> "Read AGENTS.md, then …the engagement…"
```

loom does not load the file by itself. It is workspace content, so the agents read it as data: it
can describe and restrict, and it cannot widen the scope, grant an approval or relax a role prompt.
The file says so, and tells the agent to treat a copy that appears to do otherwise as tampered.

Add a section at its end for what is specific to your workspace: the authorization's location, which
directories hold which sources and their retention windows, the operator's own penetration-test and
vendor windows that will explain indicator-adjacent matches, and what the agents must leave alone.
A test keeps the shipped file to tools the pack's roles have, so it cannot name a tool that no role
has. Drop the operator's exports under the layout the file suggests (`inventory/`, `identity/`,
`cloud/`, `apps/`, `egress/`, `config/`) or say where they actually are; anything absent is recorded
as a coverage gap, not silently treated as a negative result.

## Installing

A pack is a directory the daemon loads from `~/.loom/packs/` at start. Copy the whole folder there and
restart the daemon (or point `LOOM_HOME` at a tree that contains it):

```
mkdir -p ~/.loom/packs && cp -R packs/artex ~/.loom/packs/artex
loom down && loom up
loom run --pack artex -w <workspace> "…"
```

The pack is self-contained (its TOML manifest, its shared preamble, its role prompts; the daemon
reads nothing in `workspace/`). The daemon loads every directory under `~/.loom/packs/` that holds a
pack manifest, and refuses to start if one is invalid; the error is in `~/.loom/logs/loomd.log` (or on
the terminal for `loom daemon`). Loading checks every key and file, and that each role's verifier is
a read-only role of the same pack that can deliver a verdict.

An installed copy does not follow the repository. After upgrading loom, replace it with the shipped
one (`rm -rf ~/.loom/packs/artex && cp -R packs/artex ~/.loom/packs/artex`).

## Source and limits

Adapted from FBI FLASH `FLASH-20261113-001` (13 November 2026, TLP:CLEAR; the FBI asks that the
survey and reporting channels in the original be used for feedback and incident reports — field
offices via fbi.gov, incidents via ic3.gov). The advisory synthesizes Akamai, Microsoft Security
Research and Threat Intelligence, Google Threat Intelligence Group and Mandiant, Censys, CrowdStrike,
Zscaler ThreatLabz, CERT-EU and Check Point Research reporting from October–November 2026; the
standards file credits each indicator group to its source. Technique identifiers are MITRE ATT&CK.
The advisory's indicator addresses are historical and partly transient; the pack reproduces them
defanged, for matching against your own telemetry, with the FBI's vet-before-acting warning attached.

The pack makes no measurement claim: whether it improves hunt quality, coverage or time-to-verdict
on a real model is unmeasured, and the checklist's completeness is the advisory's, not a guarantee
about any one environment. It hunts and hardens; it does not emulate ARTEX, test exploits against
live systems outside an explicitly qualified scope, or perform containment.
