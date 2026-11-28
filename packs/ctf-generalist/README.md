# CTF Generalist pack

A/B benchmark companion to [ctf](../ctf/README.md). Keeps the exact same safety, scope, oracle, and independent `flag_judge` verification contract as `ctf`, but collapses the four specialized solver roles (`solver`, `web_solver`, `binary_solver`, `crypto_solver`) into a single unified generalist `solver` role (32 tools, 35-step slices).

Use this pack to measure whether unified generalist workers outperform specialized role silos on your target model (especially on mixed-domain chains that pivot from web to binary reversing or SSH/box tooling) without changing verification rigor:

```bash
# Run the same target under both packs and compare scorecards:
ferret run --pack ctf ...
ferret run --pack ctf-generalist ...
ferret score <mission-ctf> --json
ferret score <mission-generalist> --json
```

Pair with `[agents] lead_fold_every_settlements = 4` (see [RUNTIME-CONTROLS](../../docs/RUNTIME-CONTROLS.md)) when evaluating long multi-stage chains so the dispatcher periodically folds settled child chatter back to the sealed ledger between delegation waves.
