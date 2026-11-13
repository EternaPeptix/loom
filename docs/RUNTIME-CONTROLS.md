# Runtime controls for role packs

These controls are opt-in role/pack configuration. Existing packs continue to load. Named profiles
are configuration keys under `[models]`, not provider model identifiers.

```toml
command_guard = "offensive"  # off (default) or offensive; consumed by tool preflight
target_concurrency = 2       # positive; default 2

[roles.solver]
model = "fast"
escalation_model = "strong"
alloy_models = ["fast", "alternative"]
max_exec_calls = 12
flag_regex = 'FLAG\{[^}]+\}'

[roles.dispatcher]
require_distinct_verifier_profile = true
```

A role's `model` is the root's default unless the operator explicitly selects another profile. Fresh
children inherit the parent unless their role selects a profile. `alloy_models` rotates sibling
assignments; its cursor is reserved before discovery so parallel fanout gets distinct slots. A
restart resumes the cursor from persisted child metadata. After any failed or budget-exhausted child
of that role, `escalation_model` takes precedence for subsequent assignments. Failures before child
creation can consume a rotation slot. This is assignment-level routing, not an in-place model swap.
Every selected profile uses its own discovered model/context window, client and request limiter.

A fork that would select another profile is refused: use a fresh assignment carrying mission state
and evidence references. Forks retain the parent's model-facing prefix and replay settings.
`require_distinct_verifier_profile` rejects a verifier sharing the parent's named profile, including
recovered gate verifiers. Different profile names do not prove different model families or independent
judgment. These controls do not guarantee provider cache hits or performance gains.

`max_exec_calls` counts admitted Exec attempts over the session's own records, including failures and
interrupted attempts. Zero denies every Exec attempt; omitted means unlimited. A fork starts its own
counter. Counts survive restart and reweave; the operator renewing a root's time/step budget does not
reset its lifetime execution counter. Existing logs count historical non-denied, non-invalid Exec
results. The limit counts tool admissions, not shell subcommands, HTTP requests or subprocesses.

Time budgets count active turns and tools/model work. The harness writes non-rendered `budget_clock`
transitions before/after limiter queues and retries. Idle turns pause the clock. Interrupted queued
work stays paused; an interrupted active interval closes at the last durable record timestamp rather
than charging unknown downtime. Old schema 1 sessions keep accumulated wall time until adopting the
clock. This is not a deadline for background jobs while an agent is idle.

Budget wrap-up keeps tool definitions unchanged in the request. One shared admission policy covers
streamed local speculative reads and normal dispatch. It allows stored-output inspection,
`ledger`/mission/security queries, codec calculations, evidence and claim updates, existing plan steps
closed as done/dropped, notes, closing PTYs, stopping work and terminal tools. `job_wait` must name
`timeout_s <= 2`. Security ledger cleanup may attach evidence, close coverage or retract existing
facts/rules; creating assets, hypotheses, credentials, rules or batches is refused. Unknown tools fail
closed. Existing finish/evidence requirements remain in force: if fresh execution would be necessary,
use `report_blocker` with the partial result. Budget exhaustion is reported as unverified, never as
verified success. Verification children started by a terminal gate retain their independent budgets.

Output-limit nudges ask for one short complete tool call first. Reasoning-only replies receive a
specific nudge without copying their reasoning; both paths retain the bounded no-progress breaker.

The HUD adds advisory repeated-outcome warnings over the latest 64 result records. Fingerprints use
up to 4096 admitted characters and normalize ISO timestamps/long hexadecimal addresses; they preserve
HTTP status, ordinary numbers, tool status, exit code and signal. They supplement exact repetitions,
never block tools or establish equivalent failures. A role's `flag_regex` alerts on admitted result
views, naming the stored output; hidden portions are not exhaustively scanned. Matches remain
unverified candidates requiring inspection and a challenge oracle or independent verifier.
