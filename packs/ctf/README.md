# CTF pack

Opt-in roles for authorized local challenges and scoped CTF services. The dispatcher has four direct
execution starts; solver roles have 35-step slices. Web/binary/crypto roles keep tools relevant to
their work (at most 26 per role). An observer returns bounded recommendations to the dispatcher, which
relays them to active solvers. Profile diversity is operator configured; no cache hit or quality gain
is assumed.

Copy this directory into the configured packs directory, configure scoped target access, and install
the operator acceptance contract described in [SECURITY-ORACLES](../../docs/SECURITY-ORACLES.md).
Start a **new** mission with pack `ctf`, role `dispatcher`. On Linux use the supported Bubblewrap
configuration and create the reserved workspace `.loom` directory first. Subprocess networking is
deny-all there; trusted structured HTTP still uses explicit mission grants. Interactive TCP pivots
need a separately qualified proxy/guest bridge and are not supplied by this pack.

Create a legacy claim and pass its actual `cN` ID to the verifier; there is no implicit `c0`. Use
`agent_spawn` with `role: flag_judge` for pre-conclusion verification. Open its receipt, attach
supporting evidence, close claims/plan steps, then conclude/finish. The automatic finish verifier
challenges the result again. Missing oracle/scope/backend prerequisites are explicit blockers.

To configure heterogeneous review, set `model = "your-judge-profile"` on `flag_judge`, solver profile
fields as appropriate, and optionally `require_distinct_verifier_profile = true` on `dispatcher`.
Those profile names must exist in the operator's model configuration. Read-only/verdict roles retain
authenticated ledger review capabilities; filesystem read-only does not mean the journal is frozen.

External tools such as rizin/pdg, GDB/Python, pwntools or z3 are optional operator prerequisites for
the relevant challenge; Loom does not install them. See [tool limits](../../docs/SECURITY-TOOLS.md)
and the [evaluation protocol](../../docs/SECURITY-EVAL.md) before making performance claims.

The pack is marked `solvable`, which tells roles the challenge was built to be solved and refuses `conclude` unreachable; remove the key for targets that are not solvable by construction.
