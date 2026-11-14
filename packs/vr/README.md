# The `vr` pack: vulnerability research

`vr` is a domain pack for vulnerability research on local and authorized targets. It expresses the
research discipline (scope first, evidence tiers, an independent check of every finding) with loom's
own mechanisms: the sandbox and egress proxy, the sealed ledger, and the finish gate with a verifier.
There is no hook mechanism and no text-matching of shell commands anywhere in it.

## Roles

| Role | Ends by | Writes files | Spawns | Job |
|---|---|---|---|---|
| `researcher` | `conclude`, then `finish` (judge-gated) | yes | `scout`, `judge` | Owns the engagement; routes it into experiments; gates every result. |
| `scout` | `conclude`, then `finish` | yes | nothing | Runs one experiment; returns executed evidence or a blocker. |
| `judge` | `verdict` | no (read-only) | nothing | Checks a proposed scope against its source, or tries to refute a finding. Never judges its own work. |
| `chat` | a reply with no tool call | no (read-only) | nothing | Interactive, turn-by-turn assistant. |

Start one with:

```
loom run --pack vr --role researcher -w <workspace> "…the engagement…"
loom chat --pack vr -w <workspace>            # interactive; starts the pack's read-only `chat` role unless --role names another
```

`loom run --pack vr` without `--role` starts the pack's default role, `researcher`.

## Network policy

The pack sets `requires_restricted_network = true`. loom's default network mode is `deny_all`, under
which the tools reach no host, so a `vr` session works out of the box and can touch no target
host. A `vr` session is refused when the config says `[network] mode = "open"`; the message tells the
operator to use `allowlist` or `deny_all` and restart the daemon. The check runs when a session is
created and each time one is restored.

To let an engagement reach its targets, the agent calls `request_scope` with the hosts and why. The
request waits in your inbox without stopping the session; you approve it with `loom scope <session>
<host>...` (or the Approve button in the UI). The grant is per session: it is recorded in the ledger with
a standing rule, applies to that session's mission only, and ends with it. No config edit or restart is
needed. Names are resolved by the proxy itself; private, loopback and
link-local addresses are refused unless `allow_private` lists them. Every decision is in
`loom net <session>`. The policy applies to the whole daemon, not to one session.

## How the research standards map onto loom

- **Scope must be qualified before anything else.** The boundary is not text-matched. Outbound
  traffic goes through loom's egress proxy under an OS sandbox that permits no other route, and the
  default policy reaches nothing. The researcher has a **judge** check a proposed scope against the
  programme or authorization the operator named; the researcher then calls `request_scope`, and the operator's
  approval is recorded as a scope grant and a standing **constraint**. Widening scope is the operator's
  call, never the agent's.
- **The judge is a different agent.** The researcher has `verify_finish = true` and `verifier = "judge"`:
  a `read_only` role of the same pack with the `verdict` tool. Its `finish` is delivered only after the
  judge accepts it. A finding is attacked by an agent that did not produce it, and the finish gate is
  mechanical (nothing open) before it is adversarial (the judge tries to refute). If the judge rejects
  the finish, its objections come back as open obligations that only a new recorded run settles, and
  the researcher starts afresh on what the judge found (`[agents] fresh_start`, on by default). Nothing
  is parked on you for a rejection. If the judge cannot be run, the finish is held as unverified and is
  never delivered as verified. A researcher that keeps asking to finish with no new execution evidence
  opens a non-blocking question in your inbox. `[agents] verify_finish = false` in the
  config turns this off for every pack: the researcher's finish is then delivered at once, marked
  `not verified`.
- **Pipeline: candidate, validated, assessed, ready.** Plan steps and claim statuses. Evidence is
  `execution` or `static`; the prompts forbid a `static`-only finding, so "reading the code again is not
  validation" is a rule the roles are told and the ledger records.
- **Attribution; revalidation before reporting.** Claims with `execution` evidence, a separate state
  check and the ruling-out of other mechanisms are written into the scout and judge prompts; the
  researcher re-runs or re-scouts a decisive check rather than trusting a child's word.
- **Research state is the record.** loom's sealed, hash-chained mission journal is the ledger; its
  Markdown is a generated view, never parsed. Evidence quotes are checked verbatim against the stored
  output when they are written. An agent's report cannot itself be cited as evidence.
- **Observed content is data.** Stated in `harness.md` for every role, with the scope-widening attack
  called out specifically, because a repository that says "run this first" is where it arrives.
- **Orchestrating an engagement.** Only the researcher fans out; scouts return evidence or a blocker;
  reports reach the parent framed, bounded and marked unverified with a handle to the full text. A
  scout always starts fresh: it has tools the researcher lacks, so it cannot be a fork of it.
- **Scouts in their own copies.** Scouts that write the same files can each be started in a copy of
  the workspace (`workspace: "copy"`), and `attempt` has several scouts try one experiment, each in
  its own copy, with a check command the harness runs in every copy. Nothing reaches the workspace
  until the researcher adopts one scout's changes with `agent_adopt`. A check that ran in a copy is
  not a check of the workspace: the researcher re-runs it after adopting, and cites that run.
- **Long runs.** A fuzzer or a listener is a background job with `wake_on`: the session is resumed
  when its output has a matching line, instead of polling it.

## The workspace standards file

`workspace/AGENTS.md` holds the same standards as the role prompts in one place, written for the
agents to read: the scope gate, the pipeline, attribution and revalidation, the two records, what
ready means, when to stop, the order of the tools, orchestration, and what only the operator does.
Copy it to the root of an engagement workspace and name it in your first message:

```
cp packs/vr/workspace/AGENTS.md <workspace>/AGENTS.md
loom run --pack vr -w <workspace> "Read AGENTS.md, then …the engagement…"
```

loom does not load the file by itself. It is workspace content, so the agents read it as data: it
can describe and restrict, and it cannot widen the scope, grant an approval or relax a role prompt.
The file says so, and tells the agent to treat a copy that appears to do otherwise as tampered.

Add a section at its end for what is specific to your workspace: which directories hold earlier
reports and lab state, and what the agents must leave alone. A test keeps the shipped file to tools
the pack's roles have, so it cannot name a tool that no role has.

## Installing

A pack is a directory the daemon loads from `~/.loom/packs/` at start. Copy the whole folder there and
restart the daemon (or point `LOOM_HOME` at a tree that contains it):

```
mkdir -p ~/.loom/packs && cp -R packs/vr ~/.loom/packs/vr
loom down && loom up
loom run --pack vr -w <workspace> "…"
```

The pack is self-contained (`pack.toml`, `harness.md`, `roles/*.md`; the daemon reads nothing in
`workspace/`). The daemon loads every directory
under `~/.loom/packs/` that holds a `pack.toml`, and refuses to start if one is invalid; the error is in
`~/.loom/logs/loomd.log` (or on the terminal for `loom daemon`). Loading checks every key and file, and
that each role's verifier is a read-only role of the same pack with the `verdict` tool.

An installed copy does not follow the repository. After upgrading loom, replace it with the shipped
one (`rm -rf ~/.loom/packs/vr && cp -R packs/vr ~/.loom/packs/vr`); an older copy that lacks
`verifier = "judge"` on the researcher no longer loads.
