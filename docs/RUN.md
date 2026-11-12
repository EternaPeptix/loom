# Running loom

## Build

```
./x --pull-bin            # builds release on the build host, copies ./bin/loom
```

To run the daemon on the build host itself (where the model server is reachable and heavy tool
work belongs), build and run there instead of pulling the binary to a laptop:

```
ssh <build-host> 'export PATH=$HOME/.cargo/bin:$PATH; cd ~/loom-build/src-main && \
  CARGO_TARGET_DIR=$HOME/loom-build/target-main cargo build --release -p loom-daemon'
# the binary is then at ~/loom-build/target-main/release/loom on that host
```

## Configure

`~/.loom/config.toml` on the host that runs the daemon. Start from `docs/config.example.toml`.
Only `default_model` and one `[models.<name>]` with a `base_url` are required; everything else has a
default. `reasoning_effort` and the other `extra_body` fields are fixed for a session's life (the
chat template renders them into the prompt head, so changing them mid-session would break the cache).

## Start

```
loom daemon            # foreground
loom up                # background; `loom down` stops it (sessions resume when it starts again)
loom status            # the daemon, the model it discovered, what is running
```

The daemon binds loopback only. To reach its UI or API from another machine, forward the port over
SSH (`ssh -L 7878:127.0.0.1:7878 <host>`), never bind it to a public address.

## A mission

```
loom run <workspace-dir> "the task, in plain words"
```

`run` starts a lead session in that directory and follows its record on the terminal. The lead owns
a mission ledger (goal, constraints, plan, claims with evidence), may delegate to workers and have a
verifier attack its `finish`, and stops only through a terminating tool. Other commands:

```
loom ls                # sessions
loom tail <id>         # follow a session's record
loom send <id> "..."   # add a message to a running or idle session
loom window <id>       # what is currently in the model's context, and what was folded out
loom net <id>          # every network request the session made and how it was decided
loom inbox             # questions, approvals and blockers waiting for you
loom answer <item> ... # answer one
loom stop <id> / loom resume <id>
```

## First run checklist

1. `loom status` shows the model and a non-zero context window discovered from the server.
2. `loom run` on a tiny workspace with a question whose answer you already know (e.g. "how many
   `.rs` files are here and how many lines total?"). Confirm: the lead calls `bash`, the result
   carries the `[tool · exit 0 · … · out:…]` envelope, the lead records a claim with a quote that
   matches, `finish` passes the verifier, and the ledger shows the goal and the claim.
3. `loom window <id>` — the stable prefix is the system prompt, your message, and the turns; the
   `<harness-state>` block is not part of it.
