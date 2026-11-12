# Experimental guarded continuations

This is an opt-in copy of the general `core` roles. Only `lead` and `worker` gain `guarded_plan`;
`verifier` and `chat` keep the core tool set and prompts. The normal finish and verification gates
still apply. Installing this pack does not change the built-in `core` pack.

See [the prototype contract, example and evaluation plan](../../docs/HARNESSMM.md). The prototype
has mock/source regression coverage; it has no established real-model speedup.
