# Operator acceptance contracts

`oracle_check` checks a candidate against the operator's protected
`<workspace>/.loom/security-oracle.json`. The actor supplies the candidate, not its expected value,
endpoint, replay command, baseline or success rule. Unsandboxed mode is refused. The contract is
hashed and pinned at first use in a session; changing it requires a new verifier. A symlink to an
actor-writable contract is refused.

The CTF/redteam finish gates require supporting attested evidence from a passing receipt produced by
an independent child in the role's configured verifier role. Raw target banners, regex candidate
flags, model-written JSON, ordinary `Execution` evidence and PTY trailers cannot satisfy that gate.
The receipt's contract digest must match the current operator contract. Use `verify`/a fresh verifier
to obtain the receipt before concluding `met`, then quote it with `evidence`. An unconfigured contract
is a blocker, never a reason to manufacture an expected answer. Honest budget/blocker settlement
remains available.

The operator chooses what constitutes acceptance. These are mechanical checks of that stated
contract; a weak success criterion remains weak. The harness does not infer authorization,
exploitability or universal absence of other attack routes from a passing check.

## Exact flag

```json
{"kind":"flag_exact","sha256":"SHA256_OF_THE_TRIMMED_UTF8_FLAG"}
```

Only the candidate is trimmed. The protected configuration holds the expected hash, not a flag the
actor can copy. Passive `flag_regex` matches are prompts to verify, never completion evidence.

## Clean attack and benign-control replay

```json
{
  "kind":"clean_replay",
  "files":[{"path":"challenge","sha256":"PINNED_TARGET_SHA256","executable":true}],
  "argv":["./challenge","{input}"],
  "baseline_base64":"YmVuaWdu",
  "attack_exit":139,
  "attack_output_regex":"AddressSanitizer:.*target_parser",
  "control_exit":0,
  "timeout_s":30
}
```

The operator pins every required target/harness file. Each run gets an independent fresh copy of
those exact bytes. Staging is under protected `<loom_home>/oracle-runs`, outside all session scratch trees. The replay
sandbox hides original actor-writable roots and all sibling/current session paths, makes the
snapshot read-only and grants writes only to its separate private temp directory. Input and output
stay separate from target files. Pre/post hashes additionally detect changes. Timeout, known OOM and
libFuzzer exit 71 never pass. The attack must meet both the configured exit and target-specific output
criterion; the benign control must meet its distinct exit criterion without the attack output.
Exit 139 is an exit-code observation, not an independently authenticated signal classification.

`{input}` is a private file containing candidate bytes; `{snapshot}` is the readonly snapshot path.
Arguments are passed as quoted literal argv elements, not model-generated shell. The executable is a
pinned target or an absolute interpreter outside mutable actor roots; PATH lookup and inherited
interpreter/loader startup hooks are refused. The operator owns
interpreter/build prerequisites and the meaning of the criterion. This mode does not provision a VM,
rebuild patched targets, or grant a networked guest permission beyond the session's existing policy.

## Signed trusted supervisor / platform submission

```json
{"kind":"signed_supervisor","endpoint":"https://trusted-lab.example/verify","key_file":".loom/oracle-secrets/key","require_root":true}
```

The endpoint receives a fresh `nonce`, `candidate_sha256`, and `candidate_base64`. It returns exactly
these fields:

```json
{"nonce":"...","candidate_sha256":"...","accepted":true,"uid":0,"admin_enabled":null,"mac":"HEX_HMAC_SHA256"}
```

The HMAC message is five newline-separated UTF-8 values: nonce, candidate hash, lowercase accepted
boolean, UID decimal or empty, lowercase admin_enabled boolean or empty (no final newline). The key
is raw bytes (at least 32), must be agent-unreadable even through its actual descriptor path, and is
never put in the process environment or receipt. `.loom/oracle-secrets` is unreadable by default.
The endpoint itself still requires an operator scope grant.

`require_root` requires authentic acceptance plus UID zero or an enabled administrator claim. The
trusted supervisor must measure the target session/effect independently. Returning the supervisor's
own UID, trusting a supplied UID string, or signing arbitrary client claims is not a valid privilege
oracle. A PTY nonce provides none of this authentication. Provisioning an independently trusted guest
sidecar or platform submission adapter is an operator integration, not automatic remote exploitation.

## Differential HTTP

The `differential_http` contract contains fixed `attack` and `control` request objects, a
`success_body_regex`, and optional `normalize_regex`. Candidate text can replace `{{candidate}}` in
their raw bodies. Acceptance requires a complete target 2xx attack, a complete target 401/403/404
control, the pinned body criterion only in the attack, and no proxy-generated response. Both requests
use scoped HTTP transport. Normalized body Jaccard similarity is reported as a diagnostic; similarity
alone cannot pass. This tests the chosen authorization differential, not all possible BOLA/IDOR cases.

The verifier's structured disqualifiers can force rejection: mechanism-only harm, modified target,
static-only evidence, an out-of-scope hop, or a duplicate signature. `accepted: true` cannot override
those fields. Scope and coverage checks remain independent of oracle acceptance.
