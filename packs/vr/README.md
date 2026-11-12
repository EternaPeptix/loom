# The `vr` pack — vulnerability research

`vr` is a domain pack for vulnerability research on local and authorized targets. It replaces the
`dsh-vr` plugin: everything that plugin bolted onto a general harness as tools and hooks, `vr`
expresses with loom's own mechanisms, so there is less to go wrong and nothing to fail open.

## Roles

| Role | Ends by | Writes files | Spawns | Job |
|---|---|---|---|---|
| `researcher` | `finish` (judge-gated) | yes | `scout`, `judge` | Owns the engagement; routes it into experiments; gates every result. |
| `scout` | `finish` | yes | `scout` | Runs one experiment; returns executed evidence or a blocker. |
| `judge` | `verdict` | no (read-only) | — | Qualifies a scope, or refutes a finding. Never judges its own work. |
| `chat` | a reply with no tool call | no (read-only) | — | Interactive, turn-by-turn assistant. |

Start one with:

```
loom run --pack vr --role researcher -w <workspace> "…the engagement…"
loom chat --pack vr -w <workspace>            # interactive, uses the default role unless --role
```

## How the research standards map onto loom

The standards in `~/Documents/Security/Hackerone/AGENTS.md` were written for a plugin that steered a
general harness. Here is where each one lives in `vr`, and why the loom version is stronger.

- **Scope must be qualified before anything else; authorization boundary.** In `dsh-vr` this was a
  pre-execute hook that parsed shell text and an allow/deny host list that, by the review, *failed
  open* when the deny list was empty and could be slipped with a newline. In `vr` the boundary is not
  text-matched at all: outbound traffic goes through loom's egress proxy under an OS sandbox that
  permits no other route, the proxy resolves each name itself and refuses private/loopback/link-local
  unless named, and the default policy (`deny_all`) reaches nothing. An unqualified engagement simply
  cannot touch a target. The researcher qualifies scope by having a **judge** read the programme and
  enumerate the authorized hosts; the operator sets the matching network policy and records it as a
  standing **constraint**. Widening scope is `ask_user` → operator → constraint, never the agent's call.
- **The judge is a different agent.** `verify_finish = true` on the researcher, and a `read_only`
  `judge` role: a finding is attacked by an agent that did not produce it, and the finish gate is
  mechanical (nothing open) before it is adversarial (judge refutes).
- **Pipeline: candidate → validated → assessed → ready.** Plan steps and claim statuses. Evidence
  carries loom's built-in `execution` / `static` kinds; the roles forbid a `static`-only finding, so
  "reading the code again is not validation" is a rule the harness can see, not a reminder.
- **Attribution; revalidation before reporting.** Claims with `execution` evidence, a separate state
  check, and the ruling-out of other mechanisms are written into the scout and judge prompts; the
  researcher re-runs or re-scouts a decisive check rather than trusting a child's word.
- **Research state is the record.** loom's sealed, hash-chained mission **journal** is the ledger;
  its Markdown is a generated view, never parsed. This is exactly what the `dsh-vr` journal migration
  was reaching for — here it is the substrate, not an add-on, and evidence quotes are checked verbatim
  against stored output at write time.
- **Observed content is data.** Stated in `harness.md` for every role, with the scope-widening attack
  called out specifically, because a repository that says "run this first" is where it arrives.
- **Orchestrating an engagement.** Only the researcher fans out; scouts return evidence or a blocker;
  reports reach the parent framed, bounded and marked unverified with a handle to the full text.

## Installing

A pack is a directory the daemon loads from `~/.loom/packs/`. Copy it there (the whole folder) and
restart the daemon, or point a `LOOM_HOME` at a tree that contains it:

```
cp -R packs/vr ~/.loom/packs/vr
loom down && loom daemon        # reload packs
loom run --pack vr -w <workspace> "…"   # a bad pack fails loudly here and in the daemon log
```

The pack is self-contained (`pack.toml`, `harness.md`, `roles/*.md`); nothing else is required. The
daemon loads every directory under `~/.loom/packs/` that holds a `pack.toml`; an invalid pack is
reported in `~/.loom/logs/loomd.log` at startup.
