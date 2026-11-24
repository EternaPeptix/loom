# Contract: MCP servers as tools

Normative for the work merged with it. Each part names the files it owns. When the work is done its
rules move into `docs/DESIGN.md` (a new section "MCP servers"), `docs/RUN.md` and `docs/UI.md`, and this
file shrinks to a pointer.

Goal: an operator's existing MCP servers become loom tools without weakening anything loom enforces.
An MCP tool runs inside the session's sandbox and network policy, its result is a stored output like
any other (admitted, cut, keyed, quotable as evidence, checked by the verifier), and the model sees it
under the name models are trained on (`mcp__{server}__{tool}`, as Claude Code names them).

Out of scope for this contract: MCP resources and prompts as their own features, sampling, elicitation,
roots, OAuth flows, deferred tool loading. Each is refused or ignored as said below.

## M1. Configuration (`loom-core/src/config.rs`, `docs/config.example.toml`)

```toml
[mcp]
max_schema_tokens = 20000      # per role: MCP tool definitions beyond this are left out (M6)
idle_close_s = 600             # a server with no call for this long is closed; it starts again on the next call

[mcp.servers.github]
command = ["npx", "-y", "@modelcontextprotocol/server-github"]   # stdio: argv, run in the session sandbox
env = { GITHUB_PERSONAL_ACCESS_TOKEN = "env:GITHUB_PAT" }        # value: "env:NAME" | "file:/path" | literal
cwd = "."                      # relative to the workspace (default: the workspace)
hosts = ["api.github.com"]     # granted to the session's proxy while this server is configured (M4)
tools = ["search_issues", "get_issue"]   # default: every tool the server lists
roles = ["lead", "worker"]     # default: every role that is not read-only
read_only = false              # true: the operator says no tool of this server changes anything; then
                               # read-only roles (the verifier) get it too
timeout_s = 120                # per call

[mcp.servers.docs]
url = "https://mcp.example.com/mcp"                              # Streamable HTTP
headers = { Authorization = "env:DOCS_MCP_AUTH" }
```

- Exactly one of `command` and `url`. A server name matches `[a-z0-9_-]{1,32}`. Unknown keys are refused
  (the config's existing `deny_unknown_fields` rule).
- `env:NAME` reads the daemon's environment at session start; `file:/path` reads the file (trimmed). A
  literal value is allowed and makes the daemon log a warning at start that a secret is written in the
  config. A missing `env:`/`file:` source fails that server's start (M3), not the daemon's.
- Values are never written to any log or record; records carry the names only.
- `[mcp]` absent or `servers` empty: nothing below happens and no request changes.

## M2. Protocol (`loom-tools/src/mcp.rs` and `loom-tools/src/mcp/` if it grows)

JSON-RPC 2.0, written by hand on `serde_json` and `reqwest` (no new dependency).

- **Handshake.** `initialize` with `protocolVersion` the newest this client implements, `clientInfo
  {name: "loom", version}` and `capabilities: {}`; then `notifications/initialized`. The client works
  with servers answering `2024-11-05`, `2025-03-26`, `2025-06-18` or `2025-11-25`; any other answer ends
  the connection with an error naming the versions.
- **Listing.** `tools/list`, following `nextCursor` until it is absent (at most 50 pages).
- **Calls.** `tools/call {name, arguments}`. A JSON-RPC error answer is a failed call (M5), not a
  connection failure.
- **Server to client.** `ping` is answered `{}`. Every other request is answered with error `-32601`
  (method not found): loom offers no sampling, elicitation or roots. Notifications are read and dropped,
  except `notifications/tools/list_changed`, which is recorded for the UI (M8) and changes nothing in a
  running session (M6).
- **Cancel.** A call that times out or is stopped sends `notifications/cancelled {requestId, reason}`.
- **stdio.** Newline-delimited JSON on the child's stdin/stdout. stderr is read into a ring of its last
  200 lines and never parsed. A line that is not JSON is dropped and counted.
- **Streamable HTTP.** POST each message to `url` with `Accept: application/json, text/event-stream`
  and the configured headers. Keep the `Mcp-Session-Id` the initialize answer gives and send it, with
  `MCP-Protocol-Version`, on every later request. An answer is either one JSON body or an SSE stream read
  until the response with the request's id; other messages in the stream are handled as server-to-client
  messages above. HTTP 404 with a session id means the server forgot the session: initialize again once.
  On close, send `DELETE` with the session id (errors ignored). No GET listening stream.

## M3. Where a server runs (`loom-tools/src/mcp.rs`)

- **stdio** servers run as a child of the session's sandbox: the program and arguments are the result of
  `ctx.sandbox.command("exec " + shell-quoted argv)`, the working directory is `cwd` resolved against the
  workspace with `ctx.sandbox.resolve`, and the environment is `ctx.sandbox.env(...)` over the server's
  resolved `env` (the sandbox's own filtering applies, except that names the server's `env` sets are
  passed). The process is a new process group, killed with the group when the connection closes. A
  read-only session's sandbox is read-only for the server too.
- **HTTP** servers are reached the way `web_fetch` reaches the network (`web.rs` `build_client`): through
  the session's egress proxy when there is one, so the session's network policy decides and every
  connection is in `net.jsonl`.
- **Lifetime.** One connection per session per server, opened on the first call (or by the listing at
  a mission's start, M6), closed after `idle_close_s` without a call, when a turn of the session ends
  `finished` or `stopped` (nothing of such a session runs on: the monitor reads a process of it as a
  survivor, MONITOR.md TW-20), when a child settles, when the session ends, or when it is archived. A closed or crashed connection opens again on the next call; a call that finds the server
  dead restarts it once and its result carries the fact `server restarted`. A start that fails gives the
  call an error result with the reason and the last 40 stderr lines.

## M4. Network

A stdio server's own connections go through the session proxy like every sandboxed process. `hosts` of a
configured server are added to the session's allowed hosts for every session whose role gets that server
(M6). The proxy cannot tell the server's connections from the agent's: a host granted for a server is
reachable by the agent's `bash` too. `docs/DESIGN.md` says so in its threat notes, and the session start
note (M6) names the hosts each server added.

## M5. A call and its result (`loom-tools/src/mcp.rs` `McpTool`)

`McpTool` implements `Tool` for one tool of one server.

- **spec.** Name `mcp__{server}__{tool}`, where `{tool}` is the server's tool name with every character
  outside `[A-Za-z0-9_-]` replaced by `_`, cut so the whole name is at most 64 characters (a collision
  after this keeps the first and leaves the other out, named in the start note). Description: the
  server's description, cut at 2,000 characters. Parameters: the server's `inputSchema` with a top-level
  `$schema` key removed; `{"type":"object","properties":{}}` when it is missing. Class `Read` when the
  server's annotation `readOnlyHint` is true, else `Exec`. Never speculative.
- **arguments.** Loom's `schema::check` runs only when the schema uses nothing but the keywords it
  supports (new `schema::checkable(&Value) -> bool`); otherwise only "the arguments are a JSON object" is
  checked and the server validates. Unknown arguments follow the schema's `additionalProperties`.
- **result.** The content blocks become the body, in order, blocks separated by a blank line:
  - `text`: its text.
  - `image`: stored as an image blob and attached with `ToolOutput::with_images` (subject to
    `tools.max_image_bytes`; over it, the line `[image not kept: {mime}, {bytes} bytes]`).
  - `audio`: `[audio not shown: {mime}, {bytes} bytes]`.
  - `resource_link`: `[resource {uri}{ · name}{ · mimeType}]`.
  - `resource` with `text`: `[resource {uri}]` then the text; with `blob`: `[resource {uri}: {mime},
    {bytes} bytes, not shown]`.
  - `structuredContent` with no text block: the JSON, pretty-printed.
  - no content at all: `(no content)`.
- **status.** `isError: true` → `Error`, outcome `error`. A JSON-RPC error → `Error`, outcome
  `mcp error {code}`, the body the error's message (and `data` as JSON when present). Timeout →
  `Timeout`, outcome `stopped after {n}s`. Stop → `Interrupted`. Otherwise `Ok`, outcome `ok`.
  Facts: `{server}` always; `server restarted` when M3 restarted it.
- Everything else is the ordinary tool path: admission (cut, key, limits), the stored output and its
  `out:` key, `read`/`grep` on that key, quoting as evidence, the verifier reading it, completeness facts,
  compaction's key table. Nothing about the finish gate or the verifier changes for MCP: a claim a call
  supports is cited and quoted like any other.

## M6. Which sessions get which tools (`loom-agent`: `runtime.rs`, `rtools/mod.rs`, `session.rs`)

- **Listing once per mission.** When a mission's lead session starts, the runtime connects to every
  configured server whose `roles` include any role of the mission's pack (in its sandbox), lists its
  tools, and records the listing in `session_start` (new field `mcp: Vec<McpListing>`, serde default and
  skipped when empty; `McpListing { server, transport: "stdio"|"http", protocol, server_name,
  server_version, tools: Vec<McpToolDef>, error: Option<String> }`, `McpToolDef { name, description,
  input_schema, read_only_hint: Option<bool> }`). A server that fails to start or list is recorded with
  its `error` and no tools. Children take the listing from their mission's lead record, and a session
  opened from its log takes it from its own record, so a session's tool list (and its request prefix)
  never changes while it lives; new or removed server tools reach the next mission. A call to a tool the
  server no longer has gets the server's error as its result.
- **Per role.** A role gets the tools of each server whose `roles` name it (default: every role that is
  not read-only; a read-only role only when `read_only = true`), filtered by `tools`, in the order the
  server listed them, after the role's own tools. If their definitions together pass
  `max_schema_tokens` (estimated like the other tool definitions), the rest are left out.
- **Start note.** A session with MCP tools gets one harness note at start, for the operator and the
  model: per server, how many tools it got, the hosts it added, what was left out (by `tools`, by the
  size budget, by a name collision) and any start error. No note when nothing is configured.
- `hidden_tools`, the dialect layer and the tool-shape aliases do not apply to MCP tools.

## M7. Daemon and CLI (`loom-daemon`: `api.rs`, `wire.rs`, `cli.rs`, `client.rs`)

- `GET /api/sessions/{id}/mcp` → `[{server, transport, state: "not started"|"running"|"closed"|"failed",
  tools: [name], error, stderr_tail: [line], list_changed: bool, calls, last_call_ms}]` for the servers
  of that session.
- `POST /api/mcp/{server}/check` `{workspace}` → starts the server in a scratch sandbox for that
  workspace (the same rules as a session: proxy, policy, and a sandbox identity of its own, `mcp-check-<id>`, so the
  census finds what the server leaves; what is left is stopped before the scratch directory is removed), lists its
  tools and closes it: `{protocol,
  server_name, server_version, tools: [{name, description, read_only_hint}], stderr_tail}` or the error
  with the stderr tail. Refused (409) for a workspace the daemon refuses elsewhere.
- CLI: `loom mcp list` (the configured servers, their transport and roles, from the daemon's config) and
  `loom mcp check <server> [--workspace DIR]` (the route above; prints the tools or the error and stderr).

## M8. Web UI (`ui/`, `tools/ui-preview.mjs`, `docs/UI.md`)

- A tool row whose name starts with `mcp__` shows `{server} · {tool}` with a small "MCP" badge, and the
  full name in the tooltip. Its body, output, key and copy actions are those of any tool row.
- The Session tab lists the session's servers from the route above: name, transport, state, tool count
  (expandable to the names), last error and stderr tail (collapsed), and "tools changed since start" when
  `list_changed`.
- The Context tab's tool definitions part counts MCP tools with the rest, and its label says how many are
  MCP (`Tool definitions · 26 (4 MCP)`).
- The fixture has a session with two MCP calls (one text result, one `isError`) and the route above.

## M9. Tests

- Protocol against an in-process fake server over stdio (a small script run by `/bin/sh` that echoes
  canned lines is enough) and over HTTP (a local `axum`/hyper route): handshake and version check,
  paging, a call, a JSON-RPC error, `isError`, a server-to-client `ping` and an unknown request, a
  timeout sending `notifications/cancelled`, a crashed server restarted once, the stderr ring.
- Content mapping: every block kind, `structuredContent`, empty content, an image over the limit.
- Naming: sanitising, the 64-character cut, a collision.
- Sandbox: a stdio server cannot write outside the workspace and its connections are refused under
  `deny_all` (the same tests the `bash` sandbox tests use, run through the MCP path).
- Wiring: the listing is recorded once per mission and reused by a child and by a reopened session; role
  selection and `read_only`; the size budget; the start note; a session with no `[mcp]` gets byte-for-byte
  the same requests as before.
- Secrets: a resolved `env:` value appears in no record and no log line.
