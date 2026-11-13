# Guarded continuation prototype

This experiment applies one idea from [HarnessMM](https://arxiv.org/pdf/2610.32813v2): author an
action once, then use observed execution conditions to decide whether to dispatch it without another
model callback. The model's weights stay fixed. Loom's prototype is a small linear chain, not the
paper's full graph controller or recursive harness-optimization system.

The feature is opt-in through the `guarded_plan` tool. The built-in `core` pack does not grant it.
`packs/harnessmm/` copies the core roles and grants it only to the lead and worker. The verifier
remains unchanged. These files and mock tests establish no real-model latency or quality improvement.

## Enabling an isolated experiment

Install `packs/harnessmm` as a subdirectory of the daemon's packs directory, normally
`~/.loom/packs/harnessmm` (or `<LOOM_HOME>/packs/harnessmm`). Packs are loaded at daemon startup;
choose an appropriate restart window rather than changing a running session's tools. Then select it
explicitly for a new mission:

```sh
loom run --pack harnessmm -w /path/to/workspace "Check the parser and its tests"
```

Selecting `core` keeps ordinary execution. A custom pack can grant `guarded_plan` explicitly, but
that grant cannot add tool permissions: each stored tool must already belong to the role.

## Literal chain contract

Call `guarded_plan` with one JSON object containing `nodes`. Each node contains:

- `tool`: an existing, role-granted built-in observation, navigation, file or process tool;
- `arguments`: the complete literal argument object that passes the normal tool schema;
- `guard`: `start` for the first node, `previous_success` for every successor;
- `unchanged`: optional existing regular input-file paths to snapshot at authorship and recheck
  before dispatching that node.

There are at most 8 nodes, 65,536 serialized bytes of submitted plan JSON, 32 file-guard entries
across the plan, and 16 MiB per guarded file. Guard checks compare both resolved path and content
hash. A guard path must remain readable under the session sandbox. List every file dependency whose
change would invalidate a stored decision; guards are not automatic dependency discovery.
Checks are snapshots before dispatch, not filesystem transactions: use an isolated workspace for
experiments that require inputs to stay fixed while a command runs.

For example, after deciding both commands and inspecting their inputs, an actor could submit:

```json
{
  "nodes": [
    {
      "tool": "bash",
      "arguments": {"command": "python3 -m py_compile src/parser.py"},
      "guard": "start",
      "unchanged": ["src/parser.py"]
    },
    {
      "tool": "bash",
      "arguments": {"command": "python3 -m unittest tests.test_parser"},
      "guard": "previous_success",
      "unchanged": ["src/parser.py", "tests/test_parser.py"]
    }
  ]
}
```

This does not infer the second command from compilation output. Its exact arguments are fixed in
the authored plan. A nonzero exit, denial, interruption, or a background process without a completed
exit receipt prevents the successor. The controller does not repair arguments, fill placeholders,
template output into commands, choose semantic branches, or decide that the goal is met. A zero exit
code establishes an execution condition; it is not a proof of an action's correctness.

## Execution and fallback

Stored actions use the native tool pipeline: role checks, argument validation, sandbox/network
policy, cancellation, existing budget checks, full output storage and admission, and ordinary result
records. State-changing ledger tools, agent orchestration tools and ending tools cannot be stored
in a continuation. `finish` and independent verification remain actor decisions under their normal
gates.

Before dispatch, the controller rechecks predecessor success, guarded inputs and the mission's goal,
constraints and approvals. New instructions or external arrivals return control to the actor rather
than continuing a stale decision. Changed input paths/content, changed standing rules, failed or
incomplete receipts, and cancellation also stop reuse. An action that intentionally changes an input
guarded by a later node will cause that later guard to fail; the actor must inspect and reauthor.

Plan authorship and dispatch are recorded explicitly. A stored action identifies the originating
plan/call, literal arguments and the substituted model boundary. It is not a fabricated model
response. A restart discards the in-memory continuation; log records are evidence for inspection,
not instructions to replay side effects. The ordinary interrupted-tool rules still apply.

The controller reading an exit receipt does not mean the model read the output. Stored results stay
addressable while observation is deferred. Only output actually included for the actor can receive
model-observed standing. The actor must inspect outputs before using them as evidence; a plan is
never permission to skip evidence or finish gates.

## Evaluating whether to retain it

Use paired, held-out coding and research tasks with the same model, prompts, context policy, tools,
verification, limits and server conditions. Compare at least:

1. Ordinary Loom, including its existing multiple-tool replies and batched shell commands.
2. The opt-in guarded continuation pack.

Count complete tasks, including failures, authorship, guard inspection, remaining model calls,
fallback, retries and verification. Report successful completion and correctness first; then model
callback count, generated tokens, uncached prefill, queue time, end-to-end wall time, verifier
rejections and operator interventions. Distinguish cached from uncached input instead of treating
all input tokens as equivalent local compute costs.

Include failed builds, ambiguous outputs, changed inputs, changed constraints, background jobs,
cancellation and crashes. A useful test shows both that an eligible action skips a model callback
and that an ineligible action returns control without executing its successor. Instrumentation and
mock results are not measurements of real-model speed or proof that quality is preserved. Deployment
should remain optional until paired measurements support a useful gain without unacceptable task
regressions.
