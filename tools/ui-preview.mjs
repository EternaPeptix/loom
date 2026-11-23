// Isolated UI fixtures: no model, daemon, credentials, or workspace writes.
// Run: node tools/ui-preview.mjs [port], then open the printed URL (/#code=facefeedfacefeed signs in, then /#/s/s-audit).
// Fixture-only routes: GET /__fixture/state, POST /__fixture/question, POST /__fixture/reconnect, and
// POST /__fixture/stream (streams a short live reply into s-other: reasoning, text and a tool call as delta frames, then
// the model_response, tool_call and tool_result records; a second step follows, so a work group grows while it runs).
// Pass 2 adds: GET /api/missions/{id}/score (the daemon's ScoreView), POST /__fixture/end {session?, outcome?} (ends the
// running s-notify mission live and opens its "finished" inbox item), and POST /api/sessions/{id}/reweave (202, writes a
// reweave record). New sessions: m-fleet (13 agents to depth 4, s-fl-*), s-parked (parked on necromicon with a recorded
// error), s-quiet (running, last record 41 min old), s-notify (running, for /__fixture/end), s-tools (every ToolStatus),
// s-big (5,000 records for Find).
// Workspace folders add (shapes and status codes mirror crates/loom-daemon: refusals are 409, a missing path 404, a bad query 400):
// GET /api/fs/dirs?path= (fake home /fixture/user; /fixture/home is the loom home and is refused;
// /fixture/user/many has 2,300 folders; /fixture/user/shared is a link), POST /api/sessions (a missing workspace is refused
// with the daemon's sentence; with create_workspace it is made and the answer carries created: true), and the Files routes
// GET /api/sessions/{id}/files?path= and .../files/lines?path=&start=&count= over the workspaces /fixture/loom (nested
// folders, big.log with 20,000 lines, target.bin binary, huge.sql over the 32 MiB cap, outside a link, locked unreadable,
// pipe not a file, generated with 2,050 entries, .loom closed) and /fixture/indexer.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ui = join(dirname(fileURLToPath(import.meta.url)), "..", "ui");
const now = Date.now();
// The login code must be lowercase hex, 16–128 chars, so the UI's codeFromHash accepts it (real codes are 32 hex chars).
const LOGIN_CODE = "facefeedfacefeed";
const blob = "ab".repeat(32);
const bigBlob = "cd".repeat(32); // a stored output of 3 MiB, over the 2 MiB a copy button fetches
const clients = new Set();
const requests = [];
const logs = new Map();
const lines = Array.from({ length: 5000 }, (_, i) => `stored output line ${i + 1}`);
lines[1593] = "outcome,"; lines[1594] = "report: text,"; lines[1595] = "full: None,";
lines[1596] = "payload: serde_json::Value::Null,"; lines[1597] = "steps,"; lines[1598] = "usage: Usage::default(),";
lines[211] = "$ sh -c 'sleep 30 & exit 0'"; lines[212] = "job settled (exit 0) while pid 4127 still running"; lines[213] = "tracked: 0 processes";

// Profiles as the daemon's ModelHealth reports them; "necromicon" is the unreachable one.
const profiles = [
  { profile: "dsv41", base_url: "https://api.fixture.invalid/dsv41/v1", model: "dsv41", reachable: true, detail: "", context_window: 1000000, max_concurrent: 4 },
  { profile: "qwen", base_url: "https://api.fixture.invalid/qwen/v1", model: "qwen4-max-preview", reachable: true, detail: "", context_window: 262144, max_concurrent: 2 },
  { profile: "necromicon", base_url: "http://10.0.0.9:8000/v1", model: "necromicon", reachable: false, detail: "connection refused: http://10.0.0.9:8000/v1 did not answer; start the server or run `loom models reload` after fixing the profile's base_url.", context_window: 128000, max_concurrent: 1 },
];
const modelRef = p => ({ profile: p.profile, model: p.model, context_window: p.context_window });

// The Models tab's view of a mission (crates/loom-agent MissionModels): the lead's model, the choice per role, live profiles.
const roleChoices = new Map(); // mission -> {any: string|null, roles: Map<role, string|null>}
function missionModels(id) {
  const info = sessions.find(s => s.id === id);
  if (!info) return null;
  const lead = info.parent ? sessions.find(s => s.mission === info.mission && !s.parent) || info : info;
  const ch = roleChoices.get(lead.mission) || { any: null, roles: new Map() };
  const kids = sessions.filter(s => s.mission === lead.mission && s.parent && s.status.phase !== "ended");
  const packRoles = lead.pack === "ctf"
    ? [["dispatcher", "dsv41", [], null], ["web_solver", null, ["qwen", "dsv41"], "dsv41"], ["crypto_solver", "dsv41", [], null], ["binary_solver", "dsv41", [], null], ["worker", null, [], null], ["verifier", "qwen", [], null]]
    : [["worker", null, [], null], ["verifier", null, [], null]];
  const roles = packRoles.map(([role, pack_model, alloy_models, escalation_model]) => ({
    role, verifier: role === "verifier", chosen: ch.roles.get(role) ?? null, pack_model, alloy_models, escalation_model,
    agents: kids.filter(k => (k.role || "worker") === role).map(k => ({ session: k.id, profile: k.profile, forked: false })),
  }));
  return { mission: lead.mission, lead: lead.id, lead_model: { profile: lead.profile, model: lead.model, context_window: lead.context_window },
    any_role: ch.any, roles, profiles: profiles.map(p => p.profile), default_model: "dsv41" };
}
const profileOf = name => profiles.find(p => p.profile === name);
function session(id, title, { parent = null, phase = "running", last_end = null, outcome = null, workspace = "/fixture/loom", profile = "dsv41", prompt = 86000, cached = 84000, mission = null, role = null, pack = "core", age = 3600000, step = 48, completion = 18000 } = {}) {
  const p = profileOf(profile);
  return { id, title, mission: mission || (parent || id === "s-audit" ? "m-audit" : "m-" + id), parent, workspace, pack, role: role || (parent ? "worker" : "lead"), profile: p.profile, model: p.model, context_window: p.context_window, created_ms: now - age, unattended: true, archived: false, active: phase === "running", status: { phase, step, last_end, outcome, epoch: 1, prompt_tokens: prompt, cached_tokens: cached, completion_tokens_total: completion, open_inbox: 0 } };
}
const sessions = [
  session("s-audit", "Audit harness reliability", { phase: "idle", last_end: "waiting", profile: "dsv41" }),
  session("s-worker", "Review recovery", { parent: "s-audit", profile: "qwen", prompt: 120000, cached: 90000 }),
  session("s-other", "Indexer benchmark", { workspace: "/fixture/indexer", profile: "qwen", prompt: 190000, cached: 150000 }),
  session("s-result", "Dependency review", { phase: "ended", last_end: "finished", outcome: "done", workspace: "/fixture/docs", profile: "necromicon", prompt: 40000, cached: 0 }),
];
// Pass-2 fixtures. `custom` sessions write their own start records below (with chosen timestamps); the generic loop skips them.
const MIN = 60000;
const custom = new Set();
const budgets = new Map([["s-audit", { max_steps: 120, max_minutes: 90 }], ["s-fl-lead", { max_steps: 200, max_minutes: 240 }]]);
// [id, title, parent, role, phase, last_end, outcome, profile, step, completion tokens, minutes since created, minutes since its last record]
const fleet = [
  ["s-fl-lead", "Fleet: audit the build pipeline", null, "lead", "running", null, null, "dsv41", 142, 1240000, 300, 0.5],
  ["s-fl-dispatch", "Dispatch: split the audit", "s-fl-lead", "dispatcher", "running", null, null, "dsv41", 61, 310000, 290, 1],
  ["s-fl-web", "Solver: web build hooks", "s-fl-dispatch", "web_solver", "running", null, null, "qwen", 88, 480000, 270, 2],
  ["s-fl-webcheck", "Verifier: web build hooks", "s-fl-web", "verifier", "running", null, null, "qwen", 12, 41000, 40, 0.2],
  ["s-fl-crypto", "Solver: artifact signing", "s-fl-dispatch", "crypto_solver", "idle", "asked", null, "dsv41", 54, 220000, 262, 22],
  ["s-fl-bin", "Solver: release binary", "s-fl-dispatch", "binary_solver", "ended", "finished", "done", "dsv41", 73, 390000, 255, 95],
  ["s-fl-judge", "Judge: release binary claims", "s-fl-bin", "judge", "ended", "error", "failed", "qwen", 9, 22000, 120, 70],
  ["s-fl-deep", "Re-check: signature offsets", "s-fl-judge", "worker", "ended", "finished", "done", "qwen", 6, 15000, 100, 80],
  ["s-fl-recon", "Recon: dependency inventory", "s-fl-lead", "worker", "idle", "waiting", null, "qwen", 37, 150000, 280, 7],
  ["s-fl-docs", "Docs: write up findings", "s-fl-lead", "worker", "ended", "finished", "done", "dsv41", 25, 98000, 200, 31],
  ["s-fl-net", "Net: registry mirrors", "s-fl-lead", "worker", "running", null, null, "qwen", 44, 260000, 150, 3],
  ["s-fl-verify", "Verifier: lead claims", "s-fl-lead", "verifier", "ended", "budget_exhausted", "budget_exhausted", "dsv41", 30, 120000, 180, 55],
  ["s-fl-stopped", "Probe: retry timings", "s-fl-recon", "worker", "idle", "stopped", null, "qwen", 18, 64000, 140, 44],
];
for (const [id, title, parent, role, phase, last_end, outcome, profile, step, completion, age] of fleet) {
  sessions.push(session(id, title, { parent, role, phase, last_end, outcome, profile, step, completion, age: age * MIN, mission: "m-fleet", pack: "ctf", workspace: "/fixture/pipeline", prompt: 60000 + step * 700, cached: 50000 + step * 600 }));
  custom.add(id);
}
sessions.push(
  session("s-parked", "Fix the flaky recovery test", { phase: "idle", last_end: "parked", profile: "necromicon", workspace: "/fixture/loom", step: 63, completion: 71000, prompt: 90000, cached: 0, age: 5 * 3600000 }),
  session("s-quiet", "Rebuild the search index", { phase: "running", profile: "dsv41", workspace: "/fixture/indexer", step: 27, completion: 33000, prompt: 410000, cached: 380000, age: 2 * 3600000 }),
  session("s-notify", "Nightly dependency sweep", { phase: "running", profile: "qwen", workspace: "/fixture/docs", step: 12, completion: 9000, age: 40 * MIN }),
  session("s-tools", "Tool result shapes", { phase: "idle", last_end: "waiting", profile: "dsv41", workspace: "/fixture/loom", step: 9, completion: 6000, age: 90 * MIN }),
  session("s-big", "Long investigation (5,000 records)", { phase: "idle", last_end: "waiting", profile: "dsv41", workspace: "/fixture/loom", step: 1250, completion: 900000, prompt: 300000, cached: 280000, age: 6 * 3600000 }),
);
for (const id of ["s-parked", "s-quiet", "s-notify", "s-tools", "s-big", "s-result"]) custom.add(id);
let inbox = [
  { session: "s-audit", mission: "m-audit", title: "Audit harness reliability", opened_ms: now - 240000, item: { item_id: "i-scope", item_kind: "question", text: "Include the desktop app in this audit?", options: ["Include desktop", "Runtime only"], blocking: true, call_id: "question", reference: "q1" } },
  { session: "s-result", mission: "m-s-result", title: "Dependency review", opened_ms: now - 600000, item: { item_id: "i-result", item_kind: "finished", text: "The review is ready to read.", options: [], blocking: false, call_id: "finish" } },
];
let startupClock = now - 16 * 60000; // the records written at startup are spread over the minutes before it
function append(id, kind, fields = {}, author = "harness", live = false) {
  const log = logs.get(id) || []; logs.set(id, log);
  const record = { seq: log.length, ts_ms: fields.ts_ms ?? (live ? Date.now() : (startupClock += 40000)), author, prev: "0".repeat(64), kind, ...fields };
  log.push(record);
  if (live) emit({ type: "record", session: id, record });
  return record;
}
for (const info of sessions.filter(s => !custom.has(s.id))) {
  append(info.id, "session_start", { session: info.id, mission: info.mission, parent: info.parent, workspace: info.workspace, pack: info.pack, role: info.role, termination: "explicit", model: info.id === "s-audit" ? modelRef(profileOf("necromicon")) : modelRef(profileOf(info.profile)), budget: budgets.get(info.id) || {}, reasoning_replay: "all", tools: [] });
  append(info.id, "user_message", { text: "Review reliability and preserve the evidence." }, "user");
}
append("s-audit", "tool_call", { call_id: "bash1", req_id: "r1", name: "bash", args: { command: "cargo test recovery" }, class: "exec" }, "model");
append("s-audit", "tool_result", { call_id: "bash1", name: "bash", status: "error", text: "error: test recovery::report_after_crash failed", cut: false, class: "exec", meta: {}, duration_ms: 900 }, "tool");
append("s-audit", "model_switched", { from: modelRef(profileOf("necromicon")), to: modelRef(profileOf("dsv41")), reasoning_replay: "all", reason: "operator" }, "harness");
append("s-audit", "tool_call", { call_id: "read1", req_id: "r1", name: "read", args: { path: "runtime.rs", start: 1594, end: 1599 }, class: "read" }, "model");
append("s-audit", "tool_result", { call_id: "read1", name: "read", status: "ok", text: lines.slice(1593, 1599).join("\n"), output: { id: blob, bytes: 128000, lines: 5000 }, cut: true, class: "read", meta: { shown: [[1594, 1599]] }, duration_ms: 4 }, "tool");
append("s-audit", "model_response", { req_id: "r1", text: "## Preliminary finding\n\n**Recovery requires verification.**\n\n- Source evidence is attached.\n- A crash reproduction remains open.\n\n```rust\nfull: None,\n```\n\n<img src=\"https://example.invalid/leak.png\" onerror=\"alert(1)\">", reasoning: "Review the exact source and preserve uncertainty.", tool_calls: [], finish: "stop", usage: { prompt_tokens: 86000, cached_tokens: 84000, completion_tokens: 100 }, timing: { total_ms: 1200 }, attempts: 1 }, "model");
append("s-audit", "ledger", { n: 9, summary: "Claim and source evidence recorded." });
append("s-audit", "inbox_opened", inbox[0].item);
append("s-audit", "turn_end", { reason: "waiting" });
// ---- Pass-2 records -------------------------------------------------------------------------------------------------
const startOf = (info, ts_ms, text) => {
  append(info.id, "session_start", { ts_ms, session: info.id, mission: info.mission, parent: info.parent, workspace: info.workspace, pack: info.pack, role: info.role, termination: "explicit", model: modelRef(profileOf(info.profile)), budget: budgets.get(info.id) || {}, reasoning_replay: "all", tools: [] });
  append(info.id, "user_message", { ts_ms: ts_ms + 1000, text }, "user");
};
const sessionOf = id => sessions.find(s => s.id === id);
let callN = 0;
/** One model step (request, response with one call, the call, its result) starting at `t`; returns the next free time. */
function step(id, t, { text = "", command = "make check", status = "ok", out = "ok", exit = null, ms = 1500, meta = {}, cut = false, output = null, name = "bash", cls = "exec", args = null }) {
  const n = ++callN; const req_id = `fx-r${n}`; const call_id = `fx-c${n}`;
  const a = args || { command };
  append(id, "model_request", { ts_ms: t, req_id, step: n, epoch: 1, purpose: "step", est_tokens: 80000 }, "harness");
  append(id, "model_response", { ts_ms: t + 800, req_id, text, reasoning: "", tool_calls: [{ call_id, name, arguments: JSON.stringify(a), complete: status !== "invalid" }], finish: "tool_calls", usage: { prompt_tokens: 80000, cached_tokens: 76000, completion_tokens: 50 }, timing: { ttft_ms: 300, total_ms: 800 }, attempts: 1 }, "model");
  append(id, "tool_call", { ts_ms: t + 900, call_id, req_id, name, args: status === "invalid" ? null : a, class: cls }, "model");
  append(id, "tool_result", { ts_ms: t + 900 + ms, call_id, name, status, text: out, ...(output ? { output } : {}), cut, class: cls, meta: { ...(exit === null ? {} : { exit_code: exit }), ...meta }, duration_ms: ms }, "tool");
  return t + 1000 + ms;
}

// The fleet. Each agent's records end at its "minutes since last record"; parents record each spawn and each settle.
for (const [id, title, parent, , , , , , , , age] of fleet) {
  const created = now - age * MIN;
  startOf(sessionOf(id), created, parent ? `Assignment from ${parent}: ${title}.` : "Audit the build pipeline: find where a release could ship unverified.");
  if (parent) append(id, "harness_note", { ts_ms: created + 2000, note: "assignment", text: `Your brief: ${title}. Return findings with evidence.` }, "harness");
}
for (const [id, title, parent, role, , , , , , , age] of fleet) {
  if (!parent) continue;
  append(parent, "child_spawned", { ts_ms: now - age * MIN - 500, child: id, role, mode: "fresh", brief: { question: title.replace(/^[^:]+: /, "") + "?", scope: "/fixture/pipeline", return: "findings with evidence" }, budget: { max_steps: 60, max_minutes: 90 }, call_id: "fx-spawn-" + id }, "harness");
}
for (const [id, , parent, , phase, last_end, outcome, , nsteps, , age, quiet] of fleet) {
  const lastTs = now - quiet * MIN; let t = now - age * MIN + 60000;
  const rounds = Math.min(3, Math.max(1, Math.floor(nsteps / 20)));
  for (let i = 0; i < rounds; i++) t = step(id, Math.min(t, lastTs - 8000), { text: i === 0 ? "Starting with the build configuration." : "", command: ["make check", "rg -n 'verify' build/", "cat release.toml"][i], out: ["ok: 214 tests", "build/sign.sh:12: verify=false", "channel = \"stable\""][i], exit: 0 });
  if (phase === "ended") {
    const failed = outcome === "failed";
    append(id, "turn_end", { ts_ms: lastTs - 2000, reason: outcome === "done" ? "finished" : failed ? "error" : "budget_exhausted" }, "harness");
    append(id, "session_end", { ts_ms: lastTs, outcome, detail: failed ? "The model request failed after 3 attempts." : outcome === "budget_exhausted" ? "The step budget was used up." : "Finished." }, "harness");
    append(parent, "child_settled", { ts_ms: lastTs + 500, child: id, outcome: outcome === "done" ? "returned" : outcome, report: failed ? "No report: the child failed." : `Report from ${id}: findings recorded in the ledger.`, full: null, usage: {}, steps: nsteps, inline: false }, "harness");
  } else if (phase === "idle") {
    append(id, "turn_end", { ts_ms: lastTs, reason: last_end }, "harness");
  } else {
    append(id, "model_request", { ts_ms: lastTs, req_id: "fx-run-" + id, step: nsteps, epoch: 1, purpose: "step", est_tokens: 80000 }, "harness");
  }
}
// Parent logs were appended to out of time order: sort each by timestamp and renumber.
for (const [id] of fleet) { const log = logs.get(id); log.sort((a, b) => a.ts_ms - b.ts_ms || a.seq - b.seq); log.forEach((r, i) => { r.seq = i; }); }

// A blocking question, a scope request and a parked card for the inbox. The parked text is the daemon's texts::turn_failed(why).
const err = "connection refused: http://10.0.0.9:8000/v1 did not answer; start the server or run `loom models reload` after fixing the profile's base_url.";
inbox.push(
  { session: "s-fl-crypto", mission: "m-fleet", title: "Solver: artifact signing", opened_ms: now - 22 * MIN, item: { item_id: "i-fl-key", item_kind: "question", text: "The signing key is not in the workspace. Is it in the vault, or should the signature check be skipped?", options: ["Use the vault key", "Skip the signature check"], blocking: true, call_id: "question", reference: "q2" } },
  { session: "s-fl-net", mission: "m-fleet", title: "Net: registry mirrors", opened_ms: now - 9 * MIN, item: { item_id: "i-fl-scope", item_kind: "approval", text: "Needs to read the package index to compare mirror hashes.", options: ["registry.fixture.invalid", "mirror.fixture.invalid"], blocking: false, call_id: "request_scope" } },
  { session: "s-parked", mission: "m-s-parked", title: "Fix the flaky recovery test", opened_ms: now - 50 * MIN, item: { item_id: "i-parked", item_kind: "parked", text: "The session could not continue. The model request failed after 3 attempts: " + err + " Nothing was lost: answer here, or send the session a message, to make it try again.", options: [], blocking: true, call_id: "stop_gate" } },
);
append("s-fl-crypto", "inbox_opened", { ts_ms: now - 22 * MIN + 1, ...inbox.find(e => e.item.item_id === "i-fl-key").item }, "harness");
append("s-fl-net", "inbox_opened", { ts_ms: now - 9 * MIN, ...inbox.find(e => e.item.item_id === "i-fl-scope").item }, "harness");

// s-parked: on necromicon (unreachable); the model request failed three times and the record keeps the error sentence.
{
  const t0 = now - 5 * 3600000;
  startOf(sessionOf("s-parked"), t0, "Fix the flaky recovery test and show it passing 20 times in a row.");
  step("s-parked", t0 + 60000, { text: "Running the test once to see the failure.", command: "cargo test recovery::report_after_crash", status: "error", out: "error: test recovery::report_after_crash failed\nassertion failed: report.answer.is_some()", exit: 101, ms: 4200 });
  append("s-parked", "model_request", { ts_ms: now - 62 * MIN, req_id: "fx-park-1", step: 63, epoch: 1, purpose: "step", est_tokens: 90000 }, "harness");
  append("s-parked", "model_response", { ts_ms: now - 61 * MIN, req_id: "fx-park-1", text: "", reasoning: "", tool_calls: [], finish: "error", usage: { prompt_tokens: 0, cached_tokens: 0, completion_tokens: 0 }, timing: { total_ms: 3000 }, attempts: 3 }, "model");
  append("s-parked", "harness_note", { ts_ms: now - 61 * MIN + 500, note: "info", text: "The model request failed after 3 attempts: " + err }, "harness");
  append("s-parked", "turn_end", { ts_ms: now - 60 * MIN, reason: "error" }, "harness");
  append("s-parked", "harness_note", { ts_ms: now - 55 * MIN, note: "nudge", text: "Nothing is recorded since the last error. Continue the goal or ask the operator." }, "harness");
  append("s-parked", "turn_end", { ts_ms: now - 50 * MIN, reason: "parked" }, "harness");
  append("s-parked", "inbox_opened", { ts_ms: now - 50 * MIN + 1, ...inbox.find(e => e.item.item_id === "i-parked").item }, "harness");
}
// s-result: a finished review. Its report is the last reply; the "finished" inbox item points at it.
{
  const t0 = now - 25 * MIN;
  startOf(sessionOf("s-result"), t0, "Review the dependency tree and list anything unmaintained or vulnerable.");
  const t = step("s-result", t0 + 2 * MIN, { text: "Reading the lockfile.", command: "cargo tree --depth 1", out: "loom v0.1.0\n├── axum v0.8.4\n├── serde v1.0.228\n└── tokio v1.48.0", exit: 0, ms: 2100 });
  append("s-result", "model_request", { ts_ms: t, req_id: "fx-result-final", step: 48, epoch: 1, purpose: "step", est_tokens: 40000 }, "harness");
  append("s-result", "model_response", { ts_ms: now - 11 * MIN, req_id: "fx-result-final", text: "## Dependency review\n\nNo direct dependency is unmaintained. Two need attention:\n\n1. **rand 0.10.3** has a patch release (0.10.4) with a fix for `fill_bytes` on short buffers.\n2. **shlex 1.3.0** is a major version behind; 2.0 changes quoting of empty strings.\n\nNo advisory matches the lockfile.", reasoning: "", tool_calls: [], finish: "stop", usage: { prompt_tokens: 40000, cached_tokens: 0, completion_tokens: 160 }, timing: { total_ms: 5200 }, attempts: 1 }, "model");
  append("s-result", "inbox_opened", { ts_ms: now - 10 * MIN, ...inbox.find(e => e.item.item_id === "i-result").item }, "harness");
  append("s-result", "turn_end", { ts_ms: now - 10 * MIN + 1, reason: "finished" }, "harness");
  append("s-result", "session_end", { ts_ms: now - 10 * MIN + 2, outcome: "done", detail: "Finished." }, "harness");
}
// s-quiet: running, and its last record is 41 minutes old.
{
  const t0 = now - 2 * 3600000;
  startOf(sessionOf("s-quiet"), t0, "Rebuild the search index from the full corpus.");
  step("s-quiet", t0 + 5 * MIN, { text: "Starting the rebuild.", command: "indexer rebuild --full", out: "ok: rebuild started, 4 shards", exit: 0 });
  append("s-quiet", "model_request", { ts_ms: now - 41 * MIN, req_id: "fx-quiet", step: 27, epoch: 1, purpose: "step", est_tokens: 410000 }, "harness");
}
// s-notify: running with fresh records; POST /__fixture/end finishes it.
{
  const t0 = now - 40 * MIN;
  startOf(sessionOf("s-notify"), t0, "Check every dependency for a newer release and list the breaking ones.");
  step("s-notify", t0 + 3 * MIN, { text: "Listing the manifests.", command: "ls */Cargo.toml", out: "crates/a/Cargo.toml\ncrates/b/Cargo.toml", exit: 0 });
  append("s-notify", "model_request", { ts_ms: now - 20000, req_id: "fx-notify", step: 12, epoch: 1, purpose: "step", est_tokens: 60000 }, "harness");
}
// s-tools: one result of each failure shape, back to back so they sit in one work group.
{
  const t0 = now - 90 * MIN; let t = t0 + 2 * MIN;
  startOf(sessionOf("s-tools"), t0, "Try the build, write the config, and read the log.");
  t = step("s-tools", t, { text: "Running the tests.", command: "make test", status: "error", out: "make: *** [test] Error 2", exit: 2 });
  t = step("s-tools", t, { command: "make lint", out: "lint: clean", exit: 0 });
  // Paths for the Files tab's "Open file": inside /fixture/loom (absolute and relative), the binary one, and one that is not there.
  t = step("s-tools", t, { name: "read", cls: "read", args: { path: "/fixture/loom/crates/loom-agent/src/runtime.rs", start: 1, end: 5 }, out: "//! runtime.rs: fixture source\n    // line 2 of runtime.rs", ms: 12 });
  t = step("s-tools", t, { name: "edit", cls: "write", args: { path: "notes/no-newline.txt", old: "one", new: "two" }, out: "edited notes/no-newline.txt", ms: 9 });
  t = step("s-tools", t, { name: "read", cls: "read", args: { path: "target.bin" }, out: "(binary file)", ms: 4 });
  t = step("s-tools", t, { name: "read", cls: "read", args: { path: "src/removed.rs" }, status: "error", out: "no such file: src/removed.rs", ms: 4 });
  t = step("s-tools", t, { name: "write", cls: "write", args: { path: "/etc/hosts", text: "127.0.0.1 fixture" }, status: "denied", out: "denied: /etc/hosts is outside the sandbox's writable paths (the workspace and /tmp). Nothing was written." });
  t = step("s-tools", t, { name: "read", cls: "read", args: { path: "big.log", start: "top" }, status: "invalid", out: "invalid arguments for read: `start` must be an integer, got \"top\". Nothing ran.", ms: 5 });
  t = step("s-tools", t, { command: "sleep 600", status: "timeout", out: "timed out after 120s; the process was killed. Its output so far is stored.", ms: 120000 });
  t = step("s-tools", t, { command: "cargo build --release", status: "interrupted", out: "interrupted: the session was stopped while this ran; its effects are unknown.", ms: 30000 });
  t = step("s-tools", t, { name: "read", cls: "read", args: { path: "big.log", start: 1, end: 200 }, out: lines.slice(0, 200).join("\n"), cut: true, output: { id: blob, bytes: 128000, lines: 5000 }, meta: { shown: [[1, 200]] }, ms: 6 });
  t = step("s-tools", t, { command: "cat build.log", cut: true, out: "build line 1\nbuild line 2\n[output cut: 3 MiB stored]", output: { id: bigBlob, bytes: 3 * 1024 * 1024, lines: 60000 }, meta: { shown: [[1, 2]] }, ms: 40 });
  t = step("s-tools", t, { command: "cat build-unsized.log", cut: true, out: "build line 1\n[output cut]", output: { id: bigBlob, lines: 60000 }, meta: { shown: [[1, 1]] }, ms: 40 }); // no recorded size: the length is read from the route
  t = step("s-tools", t, { command: "make test", status: "error", out: "make: *** [test] Error 1", exit: 1 });
  append("s-tools", "turn_end", { ts_ms: t + 1000, reason: "waiting" }, "harness");
}
// s-big: 5,000 records (1,250 steps of request, response, call, result) with known needles for Find.
{
  const id = "s-big"; const t0 = now - 6 * 3600000;
  startOf(sessionOf(id), t0, "Investigate the slow shutdown and keep notes as you go.");
  append(id, "turn_start", { ts_ms: t0 + 2000, trigger: "user" }, "harness");
  lines[4199] = "deep-needle: only in the stored output, past the cut";
  for (let i = 0; i < 1250; i++) {
    const t = t0 + 10000 + i * 15000; const req_id = `big-r${i}`; const call_id = `big-c${i}`;
    let out = `ok: step ${i} listed ${i % 7 + 1} files`, text = "";
    if (i % 97 === 0) out += `\nneedle ${i}: shutdown waits on the flush`;
    if (i === 7 || i === 1203) out += "\nrare-token-xyz appears here";
    if (i === 500) out += "\nNeedle (capitalised) in the middle";
    if (i === 640) text = "Notes: the naïve café path skips the flush.";
    if (i === 900) out += "\nliteral a.b*c(d) [x] must match as typed";
    if (i % 50 === 0) text = text || `Checkpoint ${i}: still reading the shutdown path.`;
    const cut = i === 1100;
    if (cut) out = lines.slice(0, 40).join("\n") + "\n[output cut: 5000 lines stored]";
    if (i === 600) append(id, "user_message", { ts_ms: t - 500, text: "Please also check the retry path." }, "user");
    append(id, "model_request", { ts_ms: t, req_id, step: i + 1, epoch: 1, purpose: "step", est_tokens: 300000 }, "harness");
    append(id, "model_response", { ts_ms: t + 3000, req_id, text, reasoning: "", tool_calls: [{ call_id, name: "bash", arguments: JSON.stringify({ command: `ls dir${i}` }), complete: true }], finish: "tool_calls", usage: { prompt_tokens: 300000, cached_tokens: 280000, completion_tokens: 40 }, timing: { ttft_ms: 400, total_ms: 3000 }, attempts: 1 }, "model");
    append(id, "tool_call", { ts_ms: t + 3100, call_id, req_id, name: "bash", args: { command: `ls dir${i}` }, class: "exec" }, "model");
    append(id, "tool_result", { ts_ms: t + 3300, call_id, name: "bash", status: "ok", text: out, ...(cut ? { output: { id: blob, bytes: 128000, lines: 5000 } } : {}), cut, class: "exec", meta: { exit_code: 0 }, duration_ms: 200 }, "tool");
  }
  append(id, "turn_end", { ts_ms: t0 + 10000 + 1250 * 15000, reason: "waiting" }, "harness");
}

const ledger = { entries: 9, goal: "Find actionable reliability defects and preserve source evidence.", constraints: [{ id: "k1", text: "Read-only review." }], plan: [{ id: "p1", text: "Inspect recovery paths", status: "done", note: "Source finding recorded." }, { id: "p2", text: "Review tool execution", status: "doing" }, { id: "p3", text: "Independently verify findings", status: "todo" }], claims: [{ id: "c1", text: "Recovered reports may omit the answer.", status: "open", evidence: ["e1"], note: "Crash reproduction pending." }, { id: "c2", text: "Process tracking ends when the shell exits.", status: "supported", evidence: ["e2", "e3"] }], evidence: [{ id: "e1", supports: true, kind: "static", attested: true, quote: "full: None,", blob, lines: [1596, 1596], session: "s-audit", call_id: "read1", note: "Source text only." }, { id: "e2", supports: true, kind: "execution", attested: true, quote: "job settled (exit 0) while pid 4127 still running", blob, lines: [212, 214], session: "s-worker", call_id: "bash7" }, { id: "e3", supports: false, kind: "note", attested: false, quote: "a foreground pipeline was tracked to completion", note: "Only observed with a backgrounded child." }], obligations: [{ id: "o1", kind: "agent", text: "Recovery review", outcome: null }], decisions: [], dead_ends: [], questions: [] };

// m-fleet keeps a ledger too: a six-step plan (two done, one doing) for the progress line, and an open claim.
const fleetLedger = { entries: 14, goal: "Find where a release of the build pipeline could ship unverified.", constraints: [{ id: "k1", text: "Read-only: change nothing in the pipeline." }], plan: [{ id: "p1", text: "Inventory the dependencies", status: "done", note: "" }, { id: "p2", text: "Trace the release signing path", status: "done", note: "Signing key is out of the workspace." }, { id: "p3", text: "Audit the web build hooks", status: "doing", note: "" }, { id: "p4", text: "Check the registry mirrors", status: "todo", note: "" }, { id: "p5", text: "Re-check the release binary claims", status: "todo", note: "" }, { id: "p6", text: "Write up the findings", status: "todo", note: "" }], claims: [{ id: "c1", text: "build/sign.sh skips verification when verify=false.", status: "open", evidence: [], note: "Reproduction pending." }], evidence: [], obligations: [], decisions: [], dead_ends: [], questions: [{ id: "q2", text: "Is the signing key in the vault?", status: "open" }] };
const ledgers = new Map([["m-audit", ledger], ["m-fleet", fleetLedger]]);

// GET /api/missions/{id}/score: the daemon's ScoreView, { mission, sessions: [{ session, role, parent, card }], total }.
// Cards are folded from each log the way loom-core's scorecard::score does (steps, calls, malformed, finish refusals,
// quote refusals, finished), except where `cardOverride` gives a hand-set one so the fleet shows varied counts.
const card0 = () => ({ steps: 0, finished: false, steps_to_finish: null, calls: 0, malformed_calls: 0, finish_calls: 0, finish_refusals: 0, quote_refusals: 0, verifier_accepts: 0, verifier_rejections: 0, fresh_starts: 0, hand_offs: 0, asks: 0, unrecorded: false });
const cardOverride = {
  "s-fl-lead": { steps: 142, calls: 131, malformed_calls: 4, finish_calls: 2, finish_refusals: 1, quote_refusals: 3, verifier_accepts: 1, verifier_rejections: 2, fresh_starts: 1, asks: 2 },
  "s-fl-dispatch": { steps: 61, calls: 70, malformed_calls: 1 },
  "s-fl-web": { steps: 88, calls: 104, malformed_calls: 9, quote_refusals: 5, finish_calls: 3, finish_refusals: 3 },
  "s-fl-webcheck": { steps: 12, calls: 15, verifier_rejections: 1 },
  "s-fl-crypto": { steps: 54, calls: 60, asks: 1, hand_offs: 1 },
  "s-fl-bin": { steps: 73, calls: 80, finish_calls: 1, finished: true, steps_to_finish: 73, verifier_accepts: 1 },
  "s-fl-judge": { steps: 9, calls: 7, malformed_calls: 2 },
  "s-fl-deep": { steps: 6, calls: 6, finish_calls: 1, finished: true, steps_to_finish: 6 },
  "s-fl-recon": { steps: 37, calls: 41 },
  "s-fl-docs": { steps: 25, calls: 19, finish_calls: 1, finished: true, steps_to_finish: 25 },
  "s-fl-net": { steps: 44, calls: 52, malformed_calls: 3, asks: 1 },
  "s-fl-verify": { steps: 30, calls: 33, finish_refusals: 2, finish_calls: 2, verifier_rejections: 1 },
  "s-fl-stopped": { unrecorded: true, steps: 18, calls: 20 },
};
function cardOf(id) {
  if (cardOverride[id]) return { ...card0(), ...cardOverride[id] };
  const card = card0();
  for (const r of logs.get(id) || []) {
    if (r.kind === "model_request" && r.purpose === "step") card.steps++;
    if (r.kind === "model_response") { card.calls += (r.tool_calls || []).length; card.malformed_calls += (r.tool_calls || []).filter(c => !c.complete).length; }
    if (r.kind === "tool_result") {
      if (r.status === "invalid") card.malformed_calls++;
      if (r.meta && r.meta.refusal === "quote") card.quote_refusals++;
      if (r.name === "finish") { card.finish_calls++; if (r.status !== "ok") card.finish_refusals++; }
    }
    if (r.kind === "session_end" && r.outcome === "done") card.finished = true;
  }
  return card;
}
/** The lead's card with every other session's added (Scorecard::add): counts sum, `unrecorded` ORs, the lead keeps finished/steps_to_finish. */
function scoreView(mission) {
  const members = sessions.filter(s => s.mission === mission);
  if (!members.length) return null;
  members.sort((a, b) => (a.parent !== null) - (b.parent !== null) || a.created_ms - b.created_ms || (a.id < b.id ? -1 : 1));
  const scored = members.map(s => ({ session: s.id, role: s.role, parent: s.parent, card: cardOf(s.id) }));
  const total = { ...scored[0].card };
  for (const o of scored.slice(1)) for (const k of Object.keys(total)) {
    if (k === "unrecorded") total[k] = total[k] || o.card[k];
    else if (typeof total[k] === "number") total[k] += o.card[k];
  }
  return { mission, sessions: scored, total };
}
let scoreCalls = 0;

let streaming = false;
const delta = (id, req_id, d) => emit({ type: "delta", session: id, req_id, delta: d });
/** One streamed step into s-other: deltas for reasoning, then text, then a call; then the records the daemon writes. */
async function streamStep(n, { text, reasoning, command, run_ms }) {
  const id = "s-other"; const info = sessions.find(s => s.id === id);
  const req_id = `fixture-stream-${Date.now()}-${n}`; const call_id = `stream-call-${Date.now()}-${n}`;
  info.status = { ...info.status, step: info.status.step + 1 }; emit({ type: "status", session: id, status: info.status });
  append(id, "model_request", { req_id, step: info.status.step, epoch: 1, purpose: "step", est_tokens: info.status.prompt_tokens }, "harness", true);
  for (const part of reasoning.match(/.{1,24}/g)) { delta(id, req_id, { delta: "reasoning", text: part }); await wait(120); }
  for (const part of text.match(/.{1,16}/g) || []) { delta(id, req_id, { delta: "text", text: part }); await wait(120); }
  const args = JSON.stringify({ command });
  delta(id, req_id, { delta: "tool_call_start", index: 0, name: "bash" });
  for (const part of args.match(/.{1,12}/g)) { delta(id, req_id, { delta: "tool_call_args", index: 0, text: part }); await wait(80); }
  await wait(300);
  append(id, "model_response", { req_id, text, reasoning, tool_calls: [{ call_id, name: "bash", arguments: args, complete: true }], finish: "tool_calls", usage: { prompt_tokens: info.status.prompt_tokens, cached_tokens: info.status.cached_tokens, completion_tokens: 60 }, timing: { ttft_ms: 300, total_ms: 2500 }, attempts: 1 }, "model", true);
  append(id, "tool_call", { call_id, req_id, name: "bash", args: { command }, class: "exec" }, "model", true);
  await wait(run_ms);
  append(id, "tool_result", { call_id, name: "bash", status: "ok", text: "ok: " + command, cut: false, class: "exec", meta: { exit_code: 0 }, duration_ms: run_ms }, "tool", true);
}
async function streamReply() {
  const id = "s-other";
  if (!(logs.get(id) || []).some(r => r.kind === "turn_start")) append(id, "turn_start", { trigger: "user" }, "harness", true);
  await streamStep(1, { reasoning: "The indexer benchmark needs a baseline first, so run the smallest corpus and read the timing.", text: "Running the baseline on the small corpus.", command: "indexer bench --corpus small", run_ms: 3500 });
  await streamStep(2, { reasoning: "Now compare against the large corpus.", text: "", command: "indexer bench --corpus large", run_ms: 5000 });
}
function emit(event) { for (const res of clients) res.write("data: " + JSON.stringify(event) + "\n\n"); }
function json(res, value, status = 200) { const body = JSON.stringify(value); res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); res.end(body); }
async function body(req) { let text = ""; for await (const chunk of req) text += chunk; return text ? JSON.parse(text) : {}; }
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
// ---- Workspace folders: the picker (GET /api/fs/dirs), creating a missing workspace (POST /api/sessions with
// create_workspace) and the Files tab (GET /api/sessions/{id}/files, .../files/lines). All in memory; nothing is read or written on disk.
const USER_HOME = "/fixture/user";
const LOOM_HOME = "/fixture/home"; // /api/status.home: workspaces inside it are refused, as the daemon refuses them
const FILE_CAP = 32 * 1024 * 1024;
const dirNode = (children = {}, extra = {}) => ({ kind: "dir", mtime: now - 3600000, children, ...extra });
const fileNode = (text, mtime = now - 7200000) => ({ kind: "file", mtime, text });
const rustText = (name) => Array.from({ length: 140 }, (_, i) => i === 0 ? `//! ${name}: fixture source` : i % 9 === 0 ? `fn step_${i}() -> usize { ${i} }` : `    // line ${i + 1} of ${name}`).join("\n") + "\n";
const bigLog = Array.from({ length: 20000 }, (_, i) => `2026-11-16T10:${String(Math.floor(i / 600) % 60).padStart(2, "0")}:${String(i % 60).padStart(2, "0")}Z INFO tick ${i + 1}${i === 12344 ? " needle: only in the loaded range" : ""}`).join("\n") + "\n";
function loomTree() {
  return dirNode({
    "Cargo.toml": fileNode("[workspace]\nmembers = [\"crates/*\"]\n"),
    "README.md": fileNode("# loom\n\nA fixture workspace.\n\nA <b>line</b> with markup stays inert text.\n", now - 60000),
    ".gitignore": fileNode("target/\n"), ".env": fileNode("FIXTURE=1\n"),
    ".loom": dirNode({ "oracle.key": fileNode("never listed\n") }, { harness: true }),
    crates: dirNode({
      "loom-agent": dirNode({ src: dirNode({ "runtime.rs": fileNode(rustText("runtime.rs")), "session.rs": fileNode(rustText("session.rs")), "pack.rs": fileNode(rustText("pack.rs")) }) }),
      "loom-core": dirNode({ src: dirNode({ "ledger.rs": fileNode(rustText("ledger.rs")), "event.rs": fileNode(rustText("event.rs")) }) }),
    }),
    docs: dirNode({ "DESIGN.md": fileNode("# Design\n\nFixture text.\n"), "UI.md": fileNode("# UI\n") }),
    notes: dirNode({ "empty.txt": fileNode(""), "no-newline.txt": fileNode("one line without a final newline") }),
    "big.log": fileNode(bigLog, now - 90000),
    "huge.sql": { kind: "file", mtime: now - 86400000, huge: 40 * 1024 * 1024 },
    "target.bin": { kind: "file", mtime: now - 5 * 86400000, binary: 4096 },
    outside: { kind: "link", mtime: now - 86400000 },
    locked: dirNode({}, { error: "Permission denied (os error 13)" }),
    pipe: { kind: "other", mtime: now - 86400000 },
    generated: dirNode({}, { many: 2050 }),
  });
}
function indexerTree() {
  return dirNode({
    "bench.toml": fileNode("[corpus]\nsmall = 10\nlarge = 1000\n"), ".loom": dirNode({}, { harness: true }),
    src: dirNode({ "index.rs": fileNode(rustText("index.rs")) }),
    results: dirNode({ "baseline.csv": fileNode("corpus,ms\nsmall,412\nlarge,9120\n", now - 600000) }),
  });
}
const wsRoots = new Map([["/fixture/loom", loomTree()], ["/fixture/indexer", indexerTree()], ["/fixture/docs", dirNode({ "plan.md": fileNode("# Plan\n") })], ["/fixture/pipeline", dirNode({ "build.sh": fileNode("#!/bin/sh\n") })]]);
const fsStatic = new Map([
  ["/", ["fixture"]],
  ["/fixture", ["user", "loom", "indexer", "docs", "pipeline", "tmp"]],
  ["/fixture/home", [".loom"]], ["/fixture/tmp", ["scratch"]],
  ["/fixture/user", ["code", "Documents", ".config", ".cache", "shared", "many"]],
  ["/fixture/user/code", ["alpha", "beta", "gamma"]],
  ["/fixture/user/Documents", ["Invoices", "Notes"]],
]);
const fsLinks = new Map([["/fixture/user/shared", "/fixture/tmp"]]);
const fsFiles = new Set(["/fixture/user/readme.txt"]);
const expandHome = (p) => p === "~" ? USER_HOME : p.startsWith("~/") ? USER_HOME + p.slice(1) : p;
const cleanPath = (p) => p.length > 1 ? p.replace(/\/+$/, "") : p;
const inside = (p, root) => p === root || p.startsWith(root + "/");
function wsNode(path) {
  for (const [root, tree] of wsRoots) {
    if (!inside(path, root)) continue;
    let node = tree;
    for (const part of path.slice(root.length).split("/").filter(Boolean)) { node = node.kind === "dir" && node.children ? node.children[part] : null; if (!node) return null; }
    return node;
  }
  return null;
}
/** The names of the folders directly in `path` ({name, link?}), or null when there is no folder there. */
function fsDirs(path) {
  if (path === "/fixture/user/many") return Array.from({ length: 2300 }, (_, i) => ({ name: "d" + String(i + 1).padStart(4, "0") }));
  const real = fsLinks.get(path) || path;
  if (fsStatic.has(real)) {
    return fsStatic.get(real).map((name) => ({ name, link: fsLinks.has(real === "/" ? "/" + name : real + "/" + name) || undefined }));
  }
  // A folder named in its parent's list but with no list of its own is empty.
  const above = real.slice(0, real.lastIndexOf("/")) || "/";
  if (fsStatic.has(above) && fsStatic.get(above).includes(real.slice(real.lastIndexOf("/") + 1))) return [];
  const node = wsNode(real);
  if (node && node.kind === "dir") return Object.entries(node.children || {}).filter(([, c]) => c.kind === "dir").map(([name]) => ({ name }));
  return null;
}
function fsMkdirp(path) {
  let at = "";
  for (const part of path.split("/").filter(Boolean)) {
    const parent = at || "/"; at += "/" + part;
    if (fsDirs(at) !== null) continue;
    if (fsStatic.has(parent)) fsStatic.get(parent).push(part);
    else { const node = wsNode(parent); if (node && node.children) node.children[part] = dirNode(); }
    fsStatic.set(at, fsStatic.get(at) || []);
  }
  if (!wsNode(path) && !wsRoots.has(path) && !path.startsWith("/fixture/user")) wsRoots.set(path, dirNode());
}
function fsListing(rawPath) {
  const path = cleanPath(expandHome(String(rawPath || USER_HOME)));
  if (!path.startsWith("/")) return { status: 409, error: `${path} is not an absolute path. Give a path that starts with / or ~/.` };
  if (inside(path, LOOM_HOME)) return { status: 409, error: `The loom home (${LOOM_HOME}) is not listed: it holds the daemon's keys and sessions. Choose another folder.` };
  if (fsFiles.has(path)) return { status: 409, error: `${path} is not a folder.` };
  const dirs = fsDirs(path);
  if (dirs === null) return { status: 404, error: `There is no folder ${path}.` };
  const resolved = fsLinks.get(path) || path;
  const entries = dirs.map((d) => {
    const full = resolved === "/" ? "/" + d.name : resolved + "/" + d.name;
    const target = fsLinks.get(full);
    return { name: d.name, path: target || full, hidden: d.name.startsWith("."), link: !!target };
  }).sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  const shown = entries.slice(0, 2000);
  return { status: 200, value: { path: resolved, parent: resolved === "/" ? null : resolved.slice(0, resolved.lastIndexOf("/")) || "/", home: USER_HOME, entries: shown, more: entries.length - shown.length } };
}
const workspaceOf = (id) => (sessions.find((s) => s.id === id) || {}).workspace;
/** Resolve a workspace-relative path as the daemon's fsview::resolve_in does (every refusal is a 409 except a missing path, 404). */
function wsResolve(id, rel) {
  const ws = workspaceOf(id);
  if (!ws) return { status: 404, error: `There is no session ${id}.` };
  const root = wsRoots.get(ws);
  if (!root) return { status: 404, error: `There is no file or folder ${rel} in the workspace.` };
  const raw = String(rel || "");
  if (raw.includes("\0")) return { status: 409, error: "That path is not valid: it contains a NUL character." };
  if (raw.startsWith("/")) return { status: 409, error: `The path ${raw} is absolute. Give a path relative to the workspace.` };
  const pieces = raw.split("/").filter((p) => p && p !== ".");
  if (pieces.includes("..")) return { status: 409, error: `The path ${raw} uses \`..\`. Paths are relative to the workspace and stay inside it.` };
  const text = pieces.join("/");
  if (pieces[0] && pieces[0].toLowerCase() === ".loom") return { status: 409, error: `${text} is not shown: harness files are not shown.` };
  let node = root;
  for (const part of pieces) {
    node = node.kind === "dir" ? (node.children || {})[part] : null;
    if (!node) return { status: 404, error: `There is no file or folder ${text} in the workspace.` };
    if (node.kind === "link") return { status: 409, error: `${text} is a link that leads outside the workspace (/fixture/outside); it is not followed.` };
  }
  return { node, ws, parts: pieces, text };
}
const nodeSize = (n) => n.kind === "file" ? (n.huge ?? n.binary ?? Buffer.byteLength(n.text || "")) : 0;
function filesListing(id, rel) {
  const r = wsResolve(id, rel);
  if (r.error) return r;
  const shown = r.text || "the workspace root";
  if (r.node.kind !== "dir") return { status: 409, error: `${shown} is a file, not a folder. Read it with the files/lines route.` };
  if (r.node.error) return { status: 409, error: `${shown} cannot be listed: ${r.node.error}.` };
  let names = Object.entries(r.node.children || {});
  if (r.node.many) names = names.concat(Array.from({ length: r.node.many }, (_, i) => [`item-${String(i + 1).padStart(4, "0")}.txt`, fileNode("x\n")]));
  const entries = names.map(([name, c]) => {
    const closed = r.parts.length === 0 && name.toLowerCase() === ".loom";
    return {
      name, kind: closed ? "dir" : c.kind, size: closed ? 0 : nodeSize(c), mtime_ms: closed ? 0 : c.mtime, hidden: name.startsWith("."),
      ...(closed ? { note: "harness files are not shown" } : {}),
    };
  }).sort((a, b) => (a.kind === "dir" ? 0 : 1) - (b.kind === "dir" ? 0 : 1) || a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { value: { root: r.ws, path: r.text, entries: entries.slice(0, 2000), more: Math.max(0, entries.length - 2000) } };
}
function filesLines(id, rel, start, count) {
  const r = wsResolve(id, rel);
  if (r.error) return r;
  if (!r.text) return { status: 409, error: "Name a file: the path is the workspace root." };
  if (r.node.kind !== "file") return { status: 409, error: `${r.text} is ${r.node.kind === "dir" ? "a directory" : "not a regular file"}, not a file that can be shown.` };
  const size = nodeSize(r.node);
  if (r.node.huge) return { status: 409, error: `${r.text} is ${Math.floor(size / 1048576)} MiB, more than the 32 MiB the viewer reads. Look at part of it with \`sed -n\` or \`head\` in a terminal.` };
  const mtime_ms = r.node.mtime;
  if (r.node.binary) return { value: { path: r.text, text: "", first: 0, last: 0, total: 0, total_lines: 0, bytes: size, mtime_ms, binary: true } };
  // Raw lines, each with its own newline (the last has none when the file has none), as the daemon cuts them.
  const lines = r.node.text === "" ? [] : r.node.text.match(/[^\n]*\n|[^\n]+$/g);
  const total = lines.length;
  const first = Math.max(1, Math.floor(start) || 1);
  const n = Math.max(1, Math.min(5000, Math.floor(count) || 2000));
  const last = Math.min(total, first + n - 1);
  const text = first > total ? "" : lines.slice(first - 1, last).join("");
  return { value: { path: r.text, text, first, last, total, total_lines: total, bytes: size, mtime_ms, binary: false } };
}
let createdSessions = 0;
async function createSession(data) {
  const raw = String(data.workspace || "").trim();
  if (!raw) return { status: 400, error: "A workspace is required." };
  if (data.create_workspace !== undefined && typeof data.create_workspace !== "boolean") return { status: 400, error: "create_workspace must be true or false." };
  const path = cleanPath(expandHome(raw));
  if (!path.startsWith("/")) return { status: 409, error: `The workspace ${raw} is a relative path that does not exist. Give an absolute path, or one that starts with ~/.` };
  if (inside(path, LOOM_HOME)) return { status: 409, error: `The workspace ${path} is inside the loom home (${LOOM_HOME}) or its copies folder, which sessions cannot use. Choose a folder elsewhere.` };
  // As the daemon does, the earlier missions to recall are checked before any folder is made.
  if (data.prior !== undefined) {
    if (!Array.isArray(data.prior)) return { status: 400, error: "prior must be a list of mission ids." };
    const named = [...new Set(data.prior.map(m => String(m).trim()).filter(Boolean))];
    if (named.length > 8) return { status: 409, error: `Name at most 8 earlier missions to recall; ${named.length} were named.` };
    const unknown = named.find(m => !sessions.some(s => s.mission === m));
    if (unknown !== undefined) return { status: 404, error: `There is no mission ${unknown} to recall.` };
  }
  let created = false;
  if (fsDirs(path) === null) {
    if (!data.create_workspace) return { status: 409, error: `The workspace ${path} does not exist. Create it from the new-mission form (Create), or run \`loom run --create-workspace\`.` };
    fsMkdirp(path); created = true;
  }
  const id = "s-new-" + (++createdSessions);
  const info = session(id, String(data.title || "").trim() || String(data.message || "New mission").split("\n")[0].slice(0, 60), { phase: "idle", last_end: "waiting", workspace: path, profile: data.model && profileOf(data.model) ? data.model : "dsv41", mission: "m-" + id, age: 0 });
  sessions.push(info);
  append(id, "session_start", { session: id, mission: info.mission, parent: null, workspace: path, pack: info.pack, role: info.role, termination: "explicit", model: modelRef(profileOf(info.profile)), budget: {}, reasoning_replay: "all", tools: [] }, "harness", false);
  append(id, "user_message", { text: data.message }, "user");
  emit({ type: "session", info });
  return { status: 201, value: { ...info, created } };
}

// GET /api/sessions/{id}/window as the daemon answers it (WindowView with the additive breakdown, measured_now, last_request, fold_at
// and fold_to). The parts are characters at a ratio, scaled to the server's count the way the daemon does it, so they add up.
// s-quiet has no counted request (the default-ratio basis), s-notify has no known window, s-parked is past its fold mark with
// nothing cached, and the rest are counted.
const PART_CHARS = { system: 18234, tools: 61230, rules: 640, assignment: 0, resume: 5200, conversation: 172850, tool_output: 229560, pinned: 11575, agent_reports: 16361, notes: 3636, stubs: 36506, other: 0 };
const PART_COUNT = { tools: 42, rules: 2, assignment: 0, conversation: 96, tool_output: 128, pinned: 3, agent_reports: 2, notes: 6, stubs: 57, other: 0 };
function windowFor(info) {
  const st = (info && info.status) || {};
  const id = info ? info.id : "";
  const win = id === "s-notify" ? null : info && info.context_window ? info.context_window : 262144;
  const counted = id !== "s-quiet";
  const total = id === "s-parked" ? 120000 : Math.max(20000, st.prompt_tokens || 148812);
  const ratio = 3.3;
  // The characters are kept in proportion to the size the session has, at about 3.6 characters a token when counted.
  const mult = (total * (counted ? 3.6 : ratio)) / Object.values(PART_CHARS).reduce((a, b) => a + b, 0);
  const chars = Object.fromEntries(Object.entries(PART_CHARS).map(([k, c]) => [k, Math.round(c * mult)]));
  const raw = Object.fromEntries(Object.entries(chars).map(([k, c]) => [k, Math.ceil(c / ratio)]));
  const hudChars = 2310;
  const rawHud = Math.ceil(hudChars / ratio);
  const rawSum = Object.values(raw).reduce((a, b) => a + b, 0) + rawHud;
  const estTotal = Math.ceil(rawSum * 1.005);
  const measured = counted ? total : null;
  const factor = measured ? measured / estTotal : 1;
  const segments = Object.entries(raw).map(([key, t]) => ({ key, chars: chars[key], tokens: Math.floor(t * factor), ...(key in PART_COUNT ? { count: PART_COUNT[key] } : {}) }));
  const used = segments.reduce((a, x) => a + x.tokens, 0) + Math.floor(rawHud * factor);
  const grand = measured || estTotal;
  segments.push({ key: "framing", chars: 0, tokens: Math.max(0, grand - used) });
  segments.push({ key: "hud", chars: hudChars, tokens: Math.floor(rawHud * factor) });
  const sum = segments.reduce((a, x) => a + x.tokens, 0);
  const lastPrompt = counted ? Math.round(total * 0.984) : 0;
  const foldAt = win ? Math.min(400000, Math.floor(win / 5 * 4), win - 20480) : 400000;
  const foldTo = win ? Math.min(180000, Math.floor(win / 2)) : 180000;
  return {
    epoch: 3, est_tokens: estTotal, target_tokens: 400000, floor_tokens: 180000, context_window: win,
    prompt_tokens: lastPrompt, cached_tokens: id === "s-parked" ? 0 : counted ? Math.round(lastPrompt * 0.88) : 0,
    items: [
      { seq: 1, kind: "session_start", role: "system", chars: PART_CHARS.system, state: "live", pinned: false, call_id: null, class: null, preview: "You are the lead of this mission. The workspace is /fixture/loom." },
      { seq: 2, kind: "user_message", role: "user", chars: 420, state: "live", pinned: false, call_id: null, class: null, preview: "Audit the reliability of the retry path and report what you find." },
      { seq: 3, kind: "harness_note", role: "user", chars: 320, state: "live", pinned: false, call_id: null, class: null, preview: "<harness kind=\"constraint\">Do not push to main.", note: "constraint" },
      { seq: 5, kind: "model_response", role: "assistant", chars: 880, state: "live", pinned: false, call_id: null, class: null, preview: "Reading the retry module first." },
      { seq: 6, kind: "tool_result", role: "tool", chars: 6400, state: "live", pinned: true, call_id: "c-1", class: "read", preview: "pub fn backoff(attempt: u32) -> Duration {" },
      { seq: 9, kind: "tool_result", role: "tool", chars: 180, state: "stubbed", pinned: false, call_id: "c-2", class: "exec", preview: "[evicted from view; the call and its result remain in the session record]" },
    ],
    breakdown: { basis: measured ? "scaled_to_measured" : "default_ratio", chars_per_token: measured ? Math.round(ratio / factor * 100) / 100 : ratio, total_tokens: sum, segments },
    measured_now: measured,
    last_request: { req_id: "r-41", step: 41, epoch: 3, n_messages: 120, est_tokens: estTotal, prompt_tokens: lastPrompt, cached_tokens: id === "s-parked" ? 0 : counted ? Math.round(lastPrompt * 0.88) : 0, hud_bytes: hudChars },
    fold_at: id === "s-parked" ? 100000 : foldAt, fold_to: id === "s-parked" ? 60000 : foldTo,
  };
}

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname;
    if (path === "/__fixture/state") return json(res, { requests, inbox, scoreCalls });
    const scoreMatch = path.match(/^\/api\/missions\/([^/]+)\/score$/);
    if (scoreMatch && req.method === "GET") {
      scoreCalls++;
      const view = scoreView(decodeURIComponent(scoreMatch[1]));
      return view ? json(res, view) : json(res, { error: `There is no mission ${decodeURIComponent(scoreMatch[1])}.` }, 404);
    }
    if (path === "/__fixture/question" && req.method === "POST") {
      const item = { session: "s-audit", mission: "m-audit", title: "Audit harness reliability", opened_ms: Date.now(), item: { item_id: "i-extra-" + inbox.length, item_kind: "question", text: "A second question arrived while you were typing.", options: [], blocking: false } };
      inbox.push(item); append("s-audit", "inbox_opened", item.item, "harness", true); return json(res, {});
    }
    if (path === "/__fixture/stream" && req.method === "POST") {
      if (streaming) return json(res, { error: "A fixture reply is already streaming into s-other." }, 409);
      streaming = true; streamReply().catch(() => {}).finally(() => { streaming = false; });
      return json(res, { started: true, session: "s-other" });
    }
    if (path === "/__fixture/end" && req.method === "POST") {
      // Ends a running mission as the daemon would: turn_end, session_end, the status and session frames, and (for a
      // finish) the "finished" inbox item. Body: { session?: "s-notify", outcome?: "done" | "failed" | "budget_exhausted" | "stopped" }.
      const data = await body(req); const id = data.session || "s-notify"; const info = sessions.find(s => s.id === id);
      if (!info) return json(res, { error: "No such fixture session." }, 404);
      if (info.status.phase === "ended") return json(res, { error: `Session ${id} has already ended.` }, 409);
      const outcome = ["done", "failed", "budget_exhausted", "stopped"].includes(data.outcome) ? data.outcome : "done";
      const last_end = outcome === "done" ? "finished" : outcome === "failed" ? "error" : outcome;
      append(id, "turn_end", { reason: last_end }, "harness", true);
      if (info.parent) {
        // An agent settles: session_end and phase "ended". A root lead does neither; it goes back to idle with last_end.
        append(id, "session_end", { outcome, detail: outcome === "done" ? "Finished." : "Ended by the fixture." }, "harness", true);
        info.active = false; info.status = { ...info.status, phase: "ended", last_end, outcome, step: info.status.step + 1 };
      } else {
        info.active = false; info.status = { ...info.status, phase: "idle", last_end, outcome: null, step: info.status.step + 1 };
      }
      if (outcome === "done") {
        const item = { item_id: "i-end-" + id, item_kind: "finished", text: "The sweep is finished: 3 breaking releases listed.", options: [], blocking: false, call_id: "finish" };
        inbox.push({ session: id, mission: info.mission, title: info.title, opened_ms: Date.now(), item });
        append(id, "inbox_opened", item, "harness", true);
      }
      emit({ type: "status", session: id, status: info.status });
      emit({ type: "session", info: { ...info, status: { ...info.status, open_inbox: inbox.filter(e => e.session === id).length } } });
      return json(res, { session: id, outcome });
    }
    if (path === "/__fixture/reconnect" && req.method === "POST") { for (const client of clients) client.end(); clients.clear(); return json(res, {}); }
    if (path === "/api/events") {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
      res.write(": fixture ready\n\n"); clients.add(res);
      const timer = setInterval(() => res.write(": fixture heartbeat\n\n"), 10000);
      req.on("close", () => { clients.delete(res); clearInterval(timer); }); return;
    }
    if (req.method === "POST" && path === "/api/web-sessions") {
      const data = await body(req); requests.push({ path, body: data });
      if (data.code !== LOGIN_CODE) return json(res, { error: "That login code is not valid. Run `loom login` for a new one." }, 401);
      return json(res, { secret: "fixture-secret" });
    }
    if (req.method === "POST" && path.startsWith("/api/")) {
      const data = await body(req); requests.push({ path, body: data });
      const parts = path.split("/");
      if (path === "/api/sessions") { const made = await createSession(data); return made.error ? json(res, { error: made.error }, made.status) : json(res, made.value, made.status); }
      if (parts[2] === "inbox") {
        const entry = inbox.find(e => e.item.item_id === parts[3]);
        if (!entry) return json(res, { error: "No such open fixture item." }, 404);
        await wait(300); inbox = inbox.filter(e => e !== entry); append(entry.session, "inbox_resolved", { item_id: entry.item.item_id, answer: data.answer }, "user", true); return json(res, {}, 202);
      }
      const id = parts[3]; const info = sessions.find(s => s.id === id);
      if (!info) return json(res, { error: "No such fixture session." }, 404);
      if (parts[4] === "role-model") {
        const view = missionModels(id);
        const ch = roleChoices.get(view.mission) || { any: null, roles: new Map() };
        if (data.role === "*") ch.any = data.profile || null; else ch.roles.set(data.role, data.profile || null);
        roleChoices.set(view.mission, ch);
        return json(res, { switched: [], models: missionModels(id) });
      }
      if (parts[4] === "model") {
        // The daemon refuses to re-seat a finished session (Runtime::switch); so does the fixture.
        if (info.status.phase === "ended") return json(res, { error: `Session ${id} has ended, so its model no longer changes.` }, 409);
        const target = profileOf(data.profile);
        if (!target) return json(res, { error: `There is no model profile named \`${data.profile}\`; pick one of ${profiles.map(p => p.profile).join(", ")}.` }, 404);
        const live = info.status.phase === "running";
        await wait(300);
        const from = { profile: info.profile, model: info.model, context_window: info.context_window };
        Object.assign(info, { profile: target.profile, model: target.model, context_window: target.context_window });
        append(id, "model_switched", { from, to: modelRef(target), reasoning_replay: "all", reason: "operator" }, "harness", true);
        emit({ type: "session", info: { ...info, status: { ...info.status, open_inbox: inbox.filter(e => e.session === id).length } } });
        return json(res, { session: id, model: modelRef(target), live });
      }
      if (parts[4] === "messages") {
        await wait(2500); append(id, "user_message", { text: data.text }, "user", true); append(id, "model_request", { req_id: "fixture-delivery", purpose: "step", step: 49 }, "harness", true);
      } else if (parts[4] === "reweave") {
        if (info.status.phase === "ended") return json(res, { error: `Session ${id} has ended, so there is nothing to re-weave.` }, 409);
        await wait(400);
        const log = logs.get(id) || [];
        append(id, "reweave", { epoch: info.status.epoch + 1, upto_seq: Math.max(0, log.length - 1), evictions: [], brief: "Fixture re-weave: older outputs became stubs; the ledger snapshot follows.", digest: null, reason: "operator", before_tokens: info.status.prompt_tokens, after_tokens_est: 30000 }, "harness", true);
        info.status = { ...info.status, epoch: info.status.epoch + 1 };
      } else if (parts[4] === "stop") { await wait(500); info.status = { ...info.status, phase: "idle", last_end: "stopped" }; }
      else if (parts[4] === "resume") info.status = { ...info.status, phase: "running", last_end: null };
      else if (parts[4] === "archive") info.archived = data.archived;
      emit({ type: "status", session: id, status: info.status }); return json(res, {}, 202);
    }
    const modelsMatch = path.match(/^\/api\/sessions\/([^/]+)\/models$/);
    if (modelsMatch && req.method === "GET") { const v = missionModels(decodeURIComponent(modelsMatch[1])); return v ? json(res, v) : json(res, { error: "No such fixture session." }, 404); }
    if (path === "/api/fs/dirs") { const r = fsListing(url.searchParams.get("path")); return r.error ? json(res, { error: r.error }, r.status) : json(res, r.value); }
    const filesMatch = path.match(/^\/api\/sessions\/([^/]+)\/files(\/lines)?$/);
    if (filesMatch && req.method === "GET") {
      const sid = decodeURIComponent(filesMatch[1]);
      let r;
      if (filesMatch[2]) {
        // The daemon's query rules: path is required, start and count are numbers when present (400 otherwise).
        const q = url.searchParams, num = (k) => (q.has(k) ? (/^\d+$/.test(q.get(k)) ? Number(q.get(k)) : NaN) : undefined);
        if (!(q.get("path") || "").trim()) r = { status: 400, error: "path is required: the file's path relative to the workspace" };
        else if (Number.isNaN(num("start")) || Number.isNaN(num("count"))) r = { status: 400, error: "start and count must be whole numbers." };
        else r = filesLines(sid, q.get("path"), num("start"), num("count"));
      } else r = filesListing(sid, url.searchParams.get("path") || "");
      return r.error ? json(res, { error: r.error }, r.status) : json(res, r.value);
    }
    if (path === "/api/sessions") return json(res, sessions.map(s => ({ ...s, status: { ...s.status, open_inbox: inbox.filter(e => e.session === s.id).length } })));
    if (path === "/api/inbox") return json(res, inbox);
    if (path === "/api/status") return json(res, { version: "fixture", pid: 0, started_ms: now, bind: "127.0.0.1:7878", proxy_port: 0, home: "/fixture/home", sandbox: "seatbelt", network: "allowlist", disk: { free_bytes: 200e9, total_bytes: 500e9 }, models: profiles, sessions_total: sessions.length, sessions_active: sessions.filter(s => s.active).length, sessions_running: sessions.filter(s => s.status.phase === "running").length, inbox_open: inbox.length });
    if (path === "/api/models") return json(res, { default_model: "dsv41", models: profiles });
    if (path.endsWith("/records")) { const after = Number(url.searchParams.get("after") ?? -1); return json(res, { records: (logs.get(path.split("/")[3]) || []).filter(r => r.seq > after), next_after: null }); }
    if (path.endsWith("/ledger")) return json(res, { state: ledgers.get(decodeURIComponent(path.split("/")[3] || "")) || { entries: 0 }, markdown: "" });
    if (path.endsWith("/window")) return json(res, windowFor(sessions.find(x => x.id === decodeURIComponent(path.split("/")[3] || ""))));
    if (path.endsWith("/net")) return json(res, []);
    const rawMatch = path.match(/^\/api\/blobs\/([^/]+)\/raw$/);
    if (rawMatch) {
      // The whole stored output, as the daemon's blob_raw sends it (an attachment of bytes with a length).
      const bytes = Buffer.from(decodeURIComponent(rawMatch[1]) === bigBlob ? "x".repeat(3 * 1024 * 1024 - 1) + "\n" : lines.join("\n") + "\n");
      res.writeHead(200, { "content-type": "application/octet-stream", "content-length": bytes.length, "content-disposition": 'attachment; filename="out-fixture"' });
      return res.end(bytes);
    }
    if (path.endsWith("/lines")) {
      const first = Math.max(1, Math.min(lines.length, Number(url.searchParams.get("start") || 1)));
      const last = Math.min(lines.length, first + 4999, Number(url.searchParams.get("end") || first + 999));
      return json(res, { text: lines.slice(first - 1, last).join("\n") + "\n", first, last, total: lines.length });
    }
    const assets = { "/": ["index.html", "text/html"], "/app.js": ["app.js", "text/javascript"], "/core.js": ["core.js", "text/javascript"], "/style.css": ["style.css", "text/css"] };
    if (!assets[path]) return json(res, { error: "No such fixture route." }, 404);
    const [file, type] = assets[path];
    res.writeHead(200, { "content-type": type + "; charset=utf-8", "cache-control": "no-store", "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" });
    res.end(await readFile(join(ui, file)));
  } catch (e) { json(res, { error: e.message }, 500); }
});
const port = Number(process.argv[2] || 8766);
server.listen(port, "127.0.0.1", () => {
  const base = `http://127.0.0.1:${server.address().port}`;
  console.log(`UI fixtures: ${base}/#code=${LOGIN_CODE} (then /#/s/s-audit)`);
  console.log(`Fixture routes: GET /__fixture/state; POST /__fixture/question, /__fixture/reconnect, /__fixture/stream (a live reply, a running work group and its ticking label in s-other: curl -X POST ${base}/__fixture/stream)`);
});
