# Structured security tools

These tools are opt-in role grants. Installing a pack does not grant network scope or install external
programs. Use the enforced OS sandbox and explicit engagement scope for untrusted targets. Rust 1.88
is required by the HTTP cookie-store dependency.

## HTTP

`http_send` takes a `request` object with `url`, `method`, `headers`, and one of `body`, `body_base64`
or `json`. `http_repeat` takes a completed `request_id` and a patch with method/path/query/headers/
cookies/body changes. Null header values delete a header. Host, Content-Length, Transfer-Encoding and
proxy/hop headers are removed; the client supplies valid framing. Redirects are returned for explicit
inspection, never followed automatically. This is an application exchange record, not a packet capture
or raw HTTP desynchronization tool.

```json
{"request":{"url":"https://authorized.example/login","method":"POST","json":{"user":"lab"}},"capture":{"jwt":"json:/access_token"}}
```

```json
{"request_id":"rq1","patch":{"path":"/account","headers":{"Authorization":"Bearer {{jwt}}"}}}
```

The session has its own RFC cookie jar. Captures may use `json:/pointer`, `header:Name`, or
`regex:pattern` (first group). Captures expand only on the origin where they were obtained; replay
cannot change origin. Cookies, captures and replay IDs are discarded on daemon restart, never silently
adopted from an untrusted scratch file. Request/response evidence can contain credentials; only record
what the investigation needs. Typed credential records store output handles rather than duplicating
secret values in the HUD.

`race_count` releases 2–20 workers at a barrier. Each worker still acquires target admission, so the
daemon sends at most two simultaneous structured requests to a normalized host, shared across
sessions. Pack `target_concurrency = 1` serializes that session's batches; values above two are currently
clamped to two. A barrier does not guarantee simultaneous packet arrival. Arbitrary commands in bash
are outside this HTTP semaphore. A cancelled/timed-out exchange may have changed the target; inspect
state before retrying. Partial batches do not invent completed replay IDs.

## Interactive processes

`pty_open` starts an interactive bash or an explicitly requested program. `pty_exec` accepts either a
framed shell `command`, or exact interactive `input` (include a newline to submit a line). Use empty
input to poll. `pty_close` stops the whole tracked group. IDs are session-local: `S1`, `1`, `#1`, `last`.
At most eight terminals are open. A deadline leaves the terminal running; an output limit or
cancellation closes it. Sessions refuse to finish with open terminals. Stop/archive/shutdown also
close them. Protected process-group identity checkpoints support conservative restart cleanup; unknown
or reused identities are not signalled. Transcript output is stored and can be quoted normally.

Nonce trailers and prompt matching are framing aids. A program can forge them, including an exit or
UID string. They cannot establish privilege or task success. Commands that detach into other process
groups are outside the original process-group guarantee.

Pack `command_guard = "offensive"` enables conservative lexical hygiene rules for known interactive
or unbounded command patterns. It is not a complete shell AST interpreter, a security boundary, or a
target-scope classifier. Scripts, aliases and encodings can express the same effects in other ways;
the OS sandbox and proxy remain the boundaries. Bash `idle_timeout_s` is optional because legitimate
silent computation can look like blocked input. Use batch flags or PTY input when appropriate.

## Exact calculations and binary inspection

`codec_calc` provides checked unsigned 64-bit arithmetic, endian packing, encodings, unverified JWT
header/payload decoding, bounded cyclic patterns/offsets and reproducible HMAC-SHA1 TOTP with an
explicit timestamp. Decoding a JWT establishes no signature or authorization fact.

`bin_survey` reads a descriptor-checked regular ELF/PE/Mach-O file up to 64 MiB without executing it.
ELF results include available mitigation indicators, exports/constructors, imports by capability,
functions by size and selected strings. It reports unknown for facts it cannot establish, including
runtime seccomp enforcement. Shared objects are approached through exports/constructors without a
`main` assumption. PE/Mach-O summaries report available header/import/export metadata; mitigation
indicators remain separate from runtime protection and do not constitute a full mitigation audit.

`bin_decompile` and `bin_xrefs` use an operator-installed rizin backend (a compatible `pdg` plugin is
needed for decompilation). Queries are cached by content hash and selector. The stateless backend may
reanalyze for a new query; this is not a daemon-wide once-per-binary index. Decompilation displays at
most 120 lines and stores the full result. Xref BFS has depth 1–4 and expands at most 12 nodes. Missing
backends produce errors rather than fabricated pseudocode. Target modification invalidates the cache.

`gdb_probe` disables startup files, auto-load scripts and debuginfod, sets one sink breakpoint, and
inspects up to eight simple expressions in a bounded batch. Inferior output is captured separately
under a file-size limit and indexed alongside debugger output with explicit byte boundaries; inferior
function calls are disabled. GDB/Python support and target debug information are operator prerequisites;
unavailable measurements remain unknown. Debugger observations are not independent proof of a goal.

All subprocess adapters use ordinary sandboxing, cancellation, process-group tracking, output caps
and explicit deadlines. They do not install packages or change host services.
