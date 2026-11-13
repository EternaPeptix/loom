// Isolated UI fixtures: no model, daemon, credentials, or workspace writes.
// Run: node tools/ui-preview.mjs [port], then open /#/s/s-audit.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ui = join(dirname(fileURLToPath(import.meta.url)), "..", "ui");
const now = Date.now();
const blob = "ab".repeat(32);
const clients = new Set();
const requests = [];
const logs = new Map();
const lines = Array.from({ length: 5000 }, (_, i) => `stored output line ${i + 1}`);
lines[1593] = "outcome,"; lines[1594] = "report: text,"; lines[1595] = "full: None,";
lines[1596] = "payload: serde_json::Value::Null,"; lines[1597] = "steps,"; lines[1598] = "usage: Usage::default(),";
lines[211] = "$ sh -c 'sleep 30 & exit 0'"; lines[212] = "job settled (exit 0) while pid 4127 still running"; lines[213] = "tracked: 0 processes";

function session(id, title, { parent = null, phase = "running", last_end = null, outcome = null } = {}) {
  return { id, title, mission: parent || id === "s-audit" ? "m-audit" : "m-" + id, parent, workspace: "/fixture/loom", pack: "core", role: parent ? "worker" : "lead", profile: "fixture", model: "Fixture model", context_window: 1000000, created_ms: now - 3600000, unattended: true, archived: false, active: phase === "running", status: { phase, step: 48, last_end, outcome, epoch: 1, prompt_tokens: 86000, cached_tokens: 84000, completion_tokens_total: 18000, open_inbox: 0 } };
}
const sessions = [
  session("s-audit", "Audit harness reliability", { phase: "idle", last_end: "waiting" }),
  session("s-worker", "Review recovery", { parent: "s-audit" }),
  session("s-other", "Indexer benchmark"),
  session("s-result", "Dependency review", { phase: "ended", last_end: "finished", outcome: "done" }),
];
let inbox = [
  { session: "s-audit", mission: "m-audit", title: "Audit harness reliability", opened_ms: now - 240000, item: { item_id: "i-scope", item_kind: "question", text: "Include the desktop app in this audit?", options: ["Include desktop", "Runtime only"], blocking: true, call_id: "question", reference: "q1" } },
  { session: "s-result", mission: "m-s-result", title: "Dependency review", opened_ms: now - 600000, item: { item_id: "i-result", item_kind: "finished", text: "The review is ready to read.", options: [], blocking: false, call_id: "finish" } },
];
let startupClock = now - 16 * 60000; // the records written at startup are spread over the minutes before it
function append(id, kind, fields = {}, author = "harness", live = false) {
  const log = logs.get(id) || []; logs.set(id, log);
  const record = { seq: log.length, ts_ms: live ? Date.now() : (startupClock += 40000), author, prev: "0".repeat(64), kind, ...fields };
  log.push(record);
  if (live) emit({ type: "record", session: id, record });
  return record;
}
for (const info of sessions) {
  append(info.id, "session_start", { session: info.id, mission: info.mission, parent: info.parent, workspace: info.workspace, pack: info.pack, role: info.role, termination: "explicit", model: { profile: "fixture", model: "Fixture model", context_window: 1000000 }, budget: {}, reasoning_replay: "all", tools: [] });
  append(info.id, "user_message", { text: "Review reliability and preserve the evidence." }, "user");
}
append("s-audit", "tool_call", { call_id: "bash1", req_id: "r1", name: "bash", args: { command: "cargo test recovery" }, class: "exec" }, "model");
append("s-audit", "tool_result", { call_id: "bash1", name: "bash", status: "error", text: "error: test recovery::report_after_crash failed", cut: false, class: "exec", meta: {}, duration_ms: 900 }, "tool");
append("s-audit", "tool_call", { call_id: "read1", req_id: "r1", name: "read", args: { path: "runtime.rs", start: 1594, end: 1599 }, class: "read" }, "model");
append("s-audit", "tool_result", { call_id: "read1", name: "read", status: "ok", text: lines.slice(1593, 1599).join("\n"), output: { id: blob, bytes: 128000, lines: 5000 }, cut: true, class: "read", meta: { shown: [[1594, 1599]] }, duration_ms: 4 }, "tool");
append("s-audit", "model_response", { req_id: "r1", text: "## Preliminary finding\n\n**Recovery requires verification.**\n\n- Source evidence is attached.\n- A crash reproduction remains open.\n\n```rust\nfull: None,\n```\n\n<img src=\"https://example.invalid/leak.png\" onerror=\"alert(1)\">", reasoning: "Review the exact source and preserve uncertainty.", tool_calls: [], finish: "stop", usage: { prompt_tokens: 86000, cached_tokens: 84000, completion_tokens: 100 }, timing: { total_ms: 1200 }, attempts: 1 }, "model");
append("s-audit", "ledger", { n: 9, summary: "Claim and source evidence recorded." });
append("s-audit", "inbox_opened", inbox[0].item);
append("s-audit", "turn_end", { reason: "waiting" });
const ledger = { entries: 9, goal: "Find actionable reliability defects and preserve source evidence.", constraints: [{ id: "k1", text: "Read-only review." }], plan: [{ id: "p1", text: "Inspect recovery paths", status: "done", note: "Source finding recorded." }, { id: "p2", text: "Review tool execution", status: "doing" }, { id: "p3", text: "Independently verify findings", status: "todo" }], claims: [{ id: "c1", text: "Recovered reports may omit the answer.", status: "open", evidence: ["e1"], note: "Crash reproduction pending." }, { id: "c2", text: "Process tracking ends when the shell exits.", status: "supported", evidence: ["e2", "e3"] }], evidence: [{ id: "e1", supports: true, kind: "static", attested: true, quote: "full: None,", blob, lines: [1596, 1596], session: "s-audit", call_id: "read1", note: "Source text only." }, { id: "e2", supports: true, kind: "execution", attested: true, quote: "job settled (exit 0) while pid 4127 still running", blob, lines: [212, 214], session: "s-worker", call_id: "bash7" }, { id: "e3", supports: false, kind: "note", attested: false, quote: "a foreground pipeline was tracked to completion", note: "Only observed with a backgrounded child." }], obligations: [{ id: "o1", kind: "agent", text: "Recovery review", outcome: null }], decisions: [], dead_ends: [], questions: [] };

function emit(event) { for (const res of clients) res.write("data: " + JSON.stringify(event) + "\n\n"); }
function json(res, value, status = 200) { const body = JSON.stringify(value); res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" }); res.end(body); }
async function body(req) { let text = ""; for await (const chunk of req) text += chunk; return text ? JSON.parse(text) : {}; }
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    const path = url.pathname;
    if (path === "/__fixture/state") return json(res, { requests, inbox });
    if (path === "/__fixture/question" && req.method === "POST") {
      const item = { session: "s-audit", mission: "m-audit", title: "Audit harness reliability", opened_ms: Date.now(), item: { item_id: "i-extra-" + inbox.length, item_kind: "question", text: "A second question arrived while you were typing.", options: [], blocking: false } };
      inbox.push(item); append("s-audit", "inbox_opened", item.item, "harness", true); return json(res, {});
    }
    if (path === "/__fixture/reconnect" && req.method === "POST") { for (const client of clients) client.end(); clients.clear(); return json(res, {}); }
    if (path === "/api/events") {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
      res.write(": fixture ready\n\n"); clients.add(res);
      const timer = setInterval(() => res.write(": fixture heartbeat\n\n"), 10000);
      req.on("close", () => { clients.delete(res); clearInterval(timer); }); return;
    }
    if (req.method === "POST" && path.startsWith("/api/")) {
      const data = await body(req); requests.push({ path, body: data });
      const parts = path.split("/");
      if (parts[2] === "inbox") {
        const entry = inbox.find(e => e.item.item_id === parts[3]);
        if (!entry) return json(res, { error: "No such open fixture item." }, 404);
        await wait(300); inbox = inbox.filter(e => e !== entry); append(entry.session, "inbox_resolved", { item_id: entry.item.item_id, answer: data.answer }, "user", true); return json(res, {}, 202);
      }
      const id = parts[3]; const info = sessions.find(s => s.id === id);
      if (!info) return json(res, { error: "No such fixture session." }, 404);
      if (parts[4] === "messages") {
        await wait(2500); append(id, "user_message", { text: data.text }, "user", true); append(id, "model_request", { req_id: "fixture-delivery", purpose: "step", step: 49 }, "harness", true);
      } else if (parts[4] === "stop") { await wait(500); info.status = { ...info.status, phase: "idle", last_end: "stopped" }; }
      else if (parts[4] === "resume") info.status = { ...info.status, phase: "running", last_end: null };
      else if (parts[4] === "archive") info.archived = data.archived;
      emit({ type: "status", session: id, status: info.status }); return json(res, {}, 202);
    }
    if (path === "/api/sessions") return json(res, sessions.map(s => ({ ...s, status: { ...s.status, open_inbox: inbox.filter(e => e.session === s.id).length } })));
    if (path === "/api/inbox") return json(res, inbox);
    if (path === "/api/status") return json(res, { models: [{ profile: "fixture", reachable: true, model: "Fixture model" }] });
    if (path.endsWith("/records")) { const after = Number(url.searchParams.get("after") ?? -1); return json(res, { records: (logs.get(path.split("/")[3]) || []).filter(r => r.seq > after), next_after: null }); }
    if (path.endsWith("/ledger")) return json(res, { state: path.includes("m-audit") ? ledger : { entries: 0 }, markdown: "" });
    if (path.endsWith("/window")) return json(res, { est_tokens: 86000, prompt_tokens: 86000, cached_tokens: 84000, epoch: 1, context_window: 1000000, floor_tokens: 180000, target_tokens: 400000, items: [] });
    if (path.endsWith("/net")) return json(res, []);
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
server.listen(port, "127.0.0.1", () => console.log(`UI fixtures: http://127.0.0.1:${server.address().port}/#/s/s-audit`));
