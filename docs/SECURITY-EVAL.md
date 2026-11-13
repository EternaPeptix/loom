# Security workflow qualification

The new runtime/tools/packs are implemented features, not a demonstrated benchmark improvement.
External harness scores, answering-context reductions and model-diversity anecdotes do not measure
Loom. There is no vendored `loom-frontier`, Cybench, CyberGym corpus or authenticated lab deployment
in this repository. Integrate those runners with their actual versioned contracts; do not fabricate
an invocation, score or trusted acceptance endpoint.

## Release qualification

Run the workspace tests and all-target Clippy, the UI tests, the pack loader/tool-grant tests and the
mandatory native Linux confinement job. Local mock/model-server fixtures establish routing and gate
behavior; native subprocess/network fixtures establish the tested boundary. They establish neither
live model quality nor broad security immunity. Optional external decompiler/debugger backends must
be tested separately on each supported toolchain and object format.

## Paired model evaluation

Pin Loom commit, model/profile/discovery metadata, reasoning/output limits, pack files, oracle
contracts, target/source hashes, tools/container images and random seeds. Use independent fresh
workspaces/sessions for each arm. Keep the same acceptance oracle, scope, hard deadline, token/step
budget and verifier policy. Randomize paired order and repeat each task; do not select completed
episodes after observing their outcome. Include exploratory and verifier model usage, all children,
retries, fallback, tool execution and checker costs.

Compare default Loom against one change at a time before the combined pack: heterogeneous fresh
children, wrap-up/caps, typed-state projections, structured HTTP, binary tools, and the full workflow.
Include ordinary multi-tool replies and batched bash as baselines. Keep directed tool probes separate
from complete mission results. Separate local reasoning-model families/profile effects from harness
effects. Use held-out tasks, not examples shown in the prompts.

Use a balanced task set: authenticated web/control cases, stateful HTTP/races, binary crash/control
pairs (including shared libraries), crypto/offset tasks, blocked-route revisits and multi-stage local
lab chains. Include adversarial negatives: fake banners/flags, stale credentials, scope denials,
modified targets, duplicate/off-target crashes, OOM/exit71, missing backends, reasoning-only replies,
queue outages and interrupted usage streams. Do not contact live third-party targets.

Record per episode:

- End-to-end monotonic wall time and right-censoring/deadline; model queue/active/tool/checker time
  separately. Active budget time is not end-to-end latency.
- Complete prompt/completion/reasoning usage across every actor/child/verifier request; cached and
  uncached counts only when reported. Missing/cancelled-stream usage is unknown: retain known-token
  lower bounds, never fill missing usage with zero or claim exact cost.
- Independent oracle acceptance and immutable-target/control checks, plus verified mission finish.
  Partial artifact score and model verdict are secondary; a partial result is not completed success.
- Tool/process counts, gate refusals, fallbacks, repeated/crash signatures, and concrete failure
  classification. Preserve failed/timed-out episodes in the denominator.

Report paired task-level distributions and uncertainty. Compare latency to verified success; show
censored failures separately rather than averaging deadlines as completed latency. Token ratios need
complete comparable usage in both arms. Check quality/non-inferiority on an adequately repeated held-out
set before interpreting a latency/token improvement. Short deterministic smoke fixtures are regression
checks, not CyberGym/Cybench performance results.

`tools/security-eval.py` analyzes exported per-episode JSONL records without running targets or model
calls. It preserves censored episodes and unknown usage, checks pairing/settings identity and emits
descriptive JSON. See its module contract for the input schema. A deployment runner should export
those records after its independently trusted checker, together with raw logs/receipts and hashes.
