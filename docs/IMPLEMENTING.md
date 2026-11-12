# Contributing to loom

`docs/DESIGN.md` is the specification of what loom does and why. This file is about how to change the
code.

## Where things are

Six crates under `crates/` (`loom-core`, `loom-model`, `loom-tools`, `loom-net`, `loom-agent`,
`loom-daemon`), the web UI under `ui/` (plain JavaScript, no build step), the macOS menu-bar app under
`gui/`, role packs under `packs/`, and documents under `docs/`. `README.md` has the crate table.

## The module contract

Most modules start with a module comment headed `CONTRACT`. It is the precise specification of that
module: the public names and signatures, the behaviour, the exact sentences that reach the operator or
the model, and the tests the module must have. `docs/DESIGN.md` gives the reasons; the contract gives
the details. They must stay true of the code:

- When you change what a module does, change its `CONTRACT` in the same commit. A contract that
  disagrees with the code is a bug in one of them.
- When a change alters behaviour that `docs/DESIGN.md`, `docs/RUN.md`, `docs/UI.md`, the README, a
  pack's prompt or `docs/config.example.toml` describe, update those too.
- Public names, signatures, types, constants and serde attributes are depended on by other crates and
  by files on disk (logs, journals, settlement and status files). Do not change a serialized shape
  without keeping old files readable; add, do not rename, and say so in `CHANGELOG.md`.

## Rules

- Stay inside the module you are changing where you can. If a fix needs a change elsewhere, make it in
  the same commit and say so in the message.
- Where the contract is silent or two statements disagree, take the reading that best serves
  `docs/DESIGN.md` section 2, implement it, cover it with a test, and write the choice in the commit
  message.
- No `unwrap`, `expect`, `panic!`, `unreachable!`, indexing that can go out of bounds, or arithmetic
  that can overflow or underflow, outside tests. Text is cut on character boundaries only.
- Errors that can reach the model are sentences that say what to do next. Text the model sees comes from
  `crates/loom-agent/src/texts.rs` (or the module that owns the tool), not from ad-hoc strings.
- Comments say what the code does or why; they do not narrate how it came to be.
- Dependencies come from `[workspace.dependencies]` in the root `Cargo.toml`. A new one is added there
  and in the crate's manifest.
- Keep lines to about 120 columns and match the style around you. The tree is not formatted with
  `rustfmt` yet, so do not reformat code you did not change.

## Building and testing

You need Rust 1.85 or newer. From the repository root:

```
cargo build --release -p loom-daemon                  # the `loom` binary
cargo test --workspace                                # everything
cargo test -p loom-tools sandbox::                    # one crate, one module
cargo clippy --workspace --all-targets -- -D warnings # must be clean
node --test ui/core.test.js                           # the web UI's logic
```

Tests live next to the code in `#[cfg(test)] mod tests` blocks; `crates/loom-model/examples/live.rs` is a
manual check against a real server. Rules for tests:

- A contract's "Tests required" list is the minimum.
- Use `tempfile` for anything on disk. Tests never touch the network or the real `~/.loom`.
- Model traffic goes to the scripted `MockServer` in `loom-model`, never a real server.
- Tests that execute `sandbox-exec` skip themselves when `/usr/bin/sandbox-exec` is missing.
- A new behaviour gets a test that fails without it.

`./x` is an optional wrapper that copies the tree to another machine and runs cargo there, for when you
would rather not build on your own. It runs `cargo` with the arguments you give it, on the host named
by `LOOM_BUILD_HOST` (set it to `local` to run cargo in place). `LOOM_LANE=<name>` gives your builds a
separate source copy and target directory on that host so parallel work does not wait on a lock:

```
LOOM_BUILD_HOST=<host> LOOM_LANE=<lane> ./x test -p <crate> <module>::
LOOM_BUILD_HOST=<host> LOOM_LANE=<lane> ./x clippy --workspace --all-targets -- -D warnings
```

The lane name may contain letters, digits, `-` and `_` only. `gui/build.sh` builds the desktop app the
same way and also requires `LOOM_BUILD_HOST`.

## Committing

One logical change per commit, with a message of the form `<area>: <what changed>`. Tests pass and
clippy is clean before you commit. Say in the message which reading of a contract you chose, and
anything you believe is wrong in code you did not touch.
