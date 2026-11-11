# Implementing a module

Each module that still needs a body starts with a `CONTRACT` in its documentation and has `todo!()`
in the functions to fill in. The contract and `docs/DESIGN.md` are the specification.

## Rules

- Fill in the bodies. Public names, signatures, types, constants and serde attributes are fixed —
  other crates are written against them. Private helpers, private types and extra `impl` blocks in
  your own file(s) are yours to add.
- Stay inside the files you were given. If you need something from another file changed, finish with
  the best version that works without it and say what you would change in your report.
- Where the contract is silent or two statements disagree, take the reading that best serves
  `docs/DESIGN.md` §2, implement it, cover it with a test, and list it in your report. Do not stop
  to ask.
- No `unwrap`, `expect`, `panic!`, `unreachable!`, indexing that can go out of bounds, or arithmetic
  that can overflow or underflow, outside tests. Text is cut on character boundaries only.
- Errors that can reach the model are sentences that say what to do next.
- Comments say what the code does or why; they do not narrate how it came to be.
- Tests: the contract's "Tests required" list is the minimum. Use `tempfile` for anything on disk.
  Tests never touch the network or the real `~/.loom`.
- Dependencies come from `[workspace.dependencies]`. If you need a new one, add it there and in your
  crate's manifest, and say so in your report.

## Building and testing

Never run `cargo` on this machine. Use the wrapper, which runs it on the build host, with a lane
name of your own so your build does not wait on anyone else's:

```
LOOM_LANE=<lane> ./x test -p <crate> <module>::
LOOM_LANE=<lane> ./x clippy -p <crate> --all-targets -- -D warnings
```

Other modules of the same crate may still contain `todo!()`; their tests are not yours to run. A
clippy finding in a file that is not yours is not yours to fix — mention it.

## Finishing

Your tests pass, clippy is clean for your files, and the work is committed on your branch
(`git add` only your files; one commit; message `<crate>: implement <module>`). Report:

1. what you implemented, in three or four lines;
2. number of tests and what the last test run printed (`test result:` line);
3. every place you chose a reading of the contract, and anything in it you believe is wrong;
4. anything you would change in a file that is not yours.
