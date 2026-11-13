import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as C from "./core.js";

const here = dirname(fileURLToPath(import.meta.url));

// ---- fixtures: one record of every kind, shaped like `one_of_each` in loom-core/src/event.rs ----

const BLOB = { id: "ab".repeat(32), bytes: 10, lines: 2 };
const BRIEF = { question: "q", return: "r" };
let seqCounter = 0;
function rec(kind, fields = {}, author = "harness", seq = seqCounter++) {
  return { seq, ts_ms: 1000 + seq, author, prev: "0".repeat(64), kind, ...fields };
}
function oneOfEach() {
  seqCounter = 0;
  return [
    rec("session_start", { session: "s-a", mission: "m-a", parent: null, workspace: "/w", pack: "core", role: "lead", termination: "explicit", model: { profile: "local", model: "m", context_window: 1000 }, reasoning_replay: "all", system_prompt: "sys", tools: [], budget: {}, unattended: true, title: "t" }),
    rec("forked", { session: "s-a", parent: "s-p", upto_seq: 4, role: "worker", termination: "explicit", budget: {}, brief: BRIEF, contract: "c", allowed_tools: null, title: "t" }),
    rec("user_message", { text: "hi" }, "user"),
    rec("harness_note", { note: "nudge", text: "n" }),
    rec("turn_start", { trigger: "user" }),
    rec("model_request", { req_id: "r-1", step: 1, epoch: 0, purpose: "step", n_messages: 3, stable_hash: "h", hud: BLOB, est_tokens: 9 }),
    rec("model_response", { req_id: "r-1", text: "t", reasoning: "r\nr2", tool_calls: [{ call_id: "c1", name: "bash", arguments: "{\"command\":\"ls\"}", complete: true }], finish: "tool_calls", usage: { prompt_tokens: 5, cached_tokens: 4, completion_tokens: 3, reasoning_tokens: 2 }, timing: { queue_ms: 1, ttft_ms: 2, total_ms: 3000 }, attempts: 1 }, "model"),
    rec("tool_call", { call_id: "c1", req_id: "r-1", name: "bash", args: { command: "ls" }, class: "exec" }, "model"),
    rec("tool_result", { call_id: "c1", name: "bash", status: "ok", text: "ok", output: BLOB, cut: true, class: "exec", meta: {}, duration_ms: 5 }, "tool"),
    rec("reweave", { epoch: 1, upto_seq: 7, evictions: [{ seq: 3, action: { stub: { text: "s" } } }, { seq: 4, action: "drop" }, { seq: 5, action: "drop_reasoning" }], brief: "b", digest: "d", reason: "target", before_tokens: 9000, after_tokens_est: 4000 }),
    rec("pin", { call_id: "c1", reason: "r" }),
    rec("unpin", { call_id: "c1" }),
    rec("child_spawned", { child: "s-b", role: "worker", mode: "fork", brief: BRIEF, budget: {}, call_id: "c1" }),
    rec("child_settled", { child: "s-b", outcome: "returned", report: "r", full: BLOB, usage: {}, steps: 2, inline: true }, { agent: "s-b" }),
    rec("job_registered", { job_id: "j1", call_id: "c1", command: "make" }),
    rec("job_settled", { job_id: "j1", exit_code: 0, output: BLOB, detail: "d" }),
    rec("inbox_opened", { item_id: "i-1", item_kind: "question", text: "t", options: ["a"], blocking: true, call_id: "c1", reference: "q1" }),
    rec("inbox_resolved", { item_id: "i-1", answer: "a" }, "user"),
    rec("ledger", { n: 3, summary: "s" }),
    rec("net", { host: "h", port: 443, method: "CONNECT", allowed: false, rule: "deny", resolved: "1.2.3.4" }),
    rec("cache_break", { req_id: "r-1", first_diff_message: 2, detail: "d" }),
    rec("interrupted", { reason: "r" }),
    rec("turn_end", { reason: "finished" }),
    rec("session_end", { outcome: "done", detail: "d" }),
    rec("from_the_future", { x: 1 }),
  ];
}

// ---- formatters ----

test("tokens", () => {
  assert.equal(C.tokens(0), "0");
  assert.equal(C.tokens(812), "812");
  assert.equal(C.tokens(1000), "1k");
  assert.equal(C.tokens(12345), "12.3k");
  assert.equal(C.tokens(123456), "123k");
  assert.equal(C.tokens(999999), "1M");
  assert.equal(C.tokens(1_050_000), "1.05M");
  assert.equal(C.tokens(2_500_000), "2.5M");
});

test("seconds", () => {
  assert.equal(C.seconds(5), "5ms");
  assert.equal(C.seconds(4200), "4.2s");
  assert.equal(C.seconds(12_400), "12s");
  assert.equal(C.seconds(65_000), "1m05s");
  assert.equal(C.seconds(3_720_000), "1h02m");
});

test("age", () => {
  assert.equal(C.age(10_000, 9_000), "now");
  assert.equal(C.age(10_000, 20_000), "now");
  assert.equal(C.age(100_000, 70_000), "30s");
  assert.equal(C.age(1_000_000, 1_000_000 - 5 * 60_000), "5m");
  assert.equal(C.age(1e9, 1e9 - 3 * 3600_000), "3h");
  assert.equal(C.age(1e9, 1e9 - 2 * 86400_000), "2d");
});

test("cached share", () => {
  assert.equal(C.cachedShare(80, 100), "80%");
  assert.equal(C.cachedShare(0, 100), "0%");
  assert.equal(C.cachedShare(5, 0), "");
  assert.equal(C.cachedShare(500, 100), "100%");
});

test("clip counts lines and cuts at the limit", () => {
  assert.deepEqual(C.clip("", 3), { text: "", total: 0, clipped: false });
  assert.deepEqual(C.clip("a\nb\n", 2), { text: "a\nb\n", total: 2, clipped: false });
  assert.deepEqual(C.clip("a\nb\nc", 2), { text: "a\nb", total: 3, clipped: true });
  assert.equal(C.clip("a\nb\nc\nd\n", 1).text, "a");
  assert.equal(C.lineCount("x\ny"), 2);
});

test("argsLine: bash is its command, file tools their path, the rest compact JSON", () => {
  assert.equal(C.argsLine("bash", { command: "ls  -la\n  /tmp" }), "ls -la /tmp");
  assert.equal(C.argsLine("read", { path: "/w/a.rs", offset: 3 }), "/w/a.rs");
  assert.equal(C.argsLine("edit", { path: "/w/b.rs", old: "x" }), "/w/b.rs");
  assert.equal(C.argsLine("grep", { pattern: "x", path: "." }), '{"pattern":"x","path":"."}');
  assert.equal(C.argsLine("bash", null), "");
  assert.ok(C.argsLine("bash", { command: "x".repeat(1000) }, 50).length <= 50);
});

test("shownOfTotal", () => {
  const cut = C.shownOfTotal({ cut: true, output: { id: "x", bytes: 9, lines: 5400 }, meta: { shown: [[1, 60], [5341, 5400]] } });
  assert.equal(cut.shown, 120);
  assert.equal(cut.total, 5400);
  assert.equal(cut.blob, "x");
  assert.equal(cut.words, "The model was shown 120 of 5,400 lines (output cut).");
  assert.equal(cut.complete, false);

  const whole = C.shownOfTotal({ cut: false, output: { id: "y", bytes: 9, lines: 7 }, meta: {} });
  assert.equal(whole.shown, 7);
  assert.equal(whole.complete, true);
  assert.equal(whole.words, "All 7 lines shown.");

  const noShown = C.shownOfTotal({ cut: true, output: { id: "z", bytes: 9, lines: 100 }, meta: {} });
  assert.equal(noShown.shown, null);
  assert.match(noShown.words, /cut.*100 lines/);

  // meta.shown refers to of_blob when present
  const view = C.shownOfTotal({ cut: false, output: null, meta: { of_blob: "big", shown: [[10, 19], [15, 30]] } });
  assert.equal(view.blob, "big");
  assert.equal(view.shown, 21);
  assert.equal(view.total, null);

  const none = C.shownOfTotal({ cut: false, output: null, meta: {} });
  assert.equal(none.blob, null);
  assert.equal(none.words, "");
  assert.equal(C.shownOfTotal({ cut: true, output: null, meta: {} }).words, "Output was cut.");
});

test("mergeRanges merges overlapping and adjacent ranges, drops nonsense", () => {
  assert.deepEqual(C.mergeRanges([[5, 9], [1, 3], [4, 4], [20, 10], "x"]), [[1, 9]]);
  assert.deepEqual(C.mergeRanges(undefined), []);
});

test("responseFooter", () => {
  const f = C.responseFooter({ usage: { prompt_tokens: 12345, cached_tokens: 9876, completion_tokens: 340 }, timing: { total_ms: 4200 }, attempts: 1 });
  assert.equal(f, "prompt 12.3k · 80% cached · completion 340 · 4.2s");
  assert.match(C.responseFooter({ usage: {}, timing: {}, attempts: 3 }), /3 attempts$/);
  assert.equal(C.finishWarning("length").level, "warn");
  assert.equal(C.finishWarning("stop"), null);
});

test("reweave summary and eviction words", () => {
  const s = C.reweaveSummary({ reason: "target", evictions: [1, 2, 3], before_tokens: 400000, after_tokens_est: 180000 });
  assert.equal(s, "context re-woven (target) — 3 items folded out of view, about 400k → 180k tokens");
  assert.match(C.evictionWords({ seq: 1, action: { stub: { text: "gone" } } }), /^stub: gone/);
  assert.equal(C.evictionWords({ seq: 1, action: "drop" }), "dropped");
  assert.equal(C.evictionWords({ seq: 1, action: "drop_reasoning" }), "reasoning dropped");
});

test("urls", () => {
  assert.equal(C.linesUrl("ab/c", 1, 1000), "/api/blobs/ab%2Fc/lines?start=1&end=1000");
  assert.equal(C.recordsUrl("s-1", null, 500), "/api/sessions/s-1/records?limit=500");
  assert.equal(C.recordsUrl("s-1", 0, 500), "/api/sessions/s-1/records?after=0&limit=500");
});

// ---- sessions ----

function info(id, over = {}) {
  return {
    id, mission: "m-" + id, parent: null, workspace: "/w", pack: "core", role: "lead", profile: "local", model: "m",
    context_window: 1000, title: "title " + id, created_ms: 1000, mode: null, awaited: false, unattended: true, archived: false,
    active: true, status: { phase: "idle", step: 0, last_end: null, outcome: null, fork_point: null, epoch: 0, prompt_tokens: 0, cached_tokens: 0, completion_tokens_total: 0, open_inbox: 0 },
    ...over,
  };
}
const st = (o) => ({ phase: "idle", step: 0, last_end: null, outcome: null, open_inbox: 0, ...o });

test("session store: list, event, status", () => {
  const store = C.createSessionStore();
  C.applySessionList(store, [info("s-1"), info("s-2", { created_ms: 2000 })]);
  assert.equal(store.byId.size, 2);
  C.applySessionEvent(store, info("s-3", { created_ms: 3000 }));
  assert.equal(store.byId.size, 3);
  assert.equal(C.applyStatus(store, "s-1", st({ phase: "running", step: 4 })), true);
  assert.equal(store.byId.get("s-1").status.step, 4);
  assert.equal(C.applyStatus(store, "s-nope", st({})), false);
});

test("session rows: roots newest first, agents nested oldest first, archived hidden", () => {
  const store = C.createSessionStore();
  C.applySessionList(store, [
    info("s-old", { created_ms: 1000 }),
    info("s-new", { created_ms: 5000 }),
    info("s-new-b", { created_ms: 5200, parent: "s-new" }),
    info("s-new-a", { created_ms: 5100, parent: "s-new" }),
    info("s-arch", { created_ms: 9000, archived: true }),
    info("s-orphan", { created_ms: 100, parent: "s-gone" }),
  ]);
  let rows = C.sessionRows(store);
  assert.deepEqual(rows.map((r) => [r.info.id, r.depth]), [["s-new", 0], ["s-new-a", 1], ["s-new-b", 1], ["s-old", 0], ["s-orphan", 0]]);
  rows = C.sessionRows(store, { showArchived: true });
  assert.equal(rows[0].info.id, "s-arch");
});

test("state mark", () => {
  assert.equal(C.stateMark(info("a", { status: st({ phase: "running" }) }), 0), "running");
  assert.equal(C.stateMark(info("a", { status: st({ phase: "running" }) }), 1), "needs_you");
  assert.equal(C.stateMark(info("a", { status: st({ last_end: "waiting" }) }), 0), "waiting");
  assert.equal(C.stateMark(info("a", { status: st({ last_end: "stopped" }) }), 0), "stopped");
  assert.equal(C.stateMark(info("a", { status: st({ last_end: "finished" }) }), 0), "finished");
  assert.equal(C.stateMark(info("a", { status: st({ last_end: "error" }) }), 0), "failed");
  assert.equal(C.stateMark(info("a", { status: st({ last_end: "yielded" }) }), 0), "idle");
  assert.equal(C.stateMark(info("a", { status: st({ phase: "ended", outcome: "done" }) }), 0), "finished");
  assert.equal(C.stateMark(info("a", { status: st({ phase: "ended", outcome: "failed" }) }), 0), "failed");
  assert.equal(C.stateMark(info("a", { status: st({ phase: "ended", outcome: "budget_exhausted" }) }), 0), "failed");
  assert.equal(C.stateMark(info("a", { status: st({ phase: "ended", outcome: "stopped" }) }), 0), "stopped");
  // without an inbox count the status decides
  assert.equal(C.stateMark(info("a", { status: st({ open_inbox: 2, last_end: "asked" }) })), "needs_you");
  assert.equal(C.stateMark(info("a", { status: st({ open_inbox: 2 }) }), 0), "idle");
});

test("classified attention separates blockers, nonblocking questions and results", () => {
  const inbox = C.createInbox();
  const entries = [
    { session: "s-1", item: { item_id: "i-result", item_kind: "finished", blocking: false } },
    { session: "s-1", item: { item_id: "i-question", item_kind: "question", blocking: false } },
    { session: "s-2", item: { item_id: "i-block", item_kind: "question", blocking: true } },
  ];
  C.applyInboxList(inbox, entries);
  const first = C.attentionFor(inbox, "s-1");
  assert.deepEqual(first, { open: 2, blocking: 0, questions: 1, results: 1 });
  assert.deepEqual(C.attentionFor(inbox, "s-2"), { open: 1, blocking: 1, questions: 0, results: 0 });
  assert.deepEqual(C.attentionFor(inbox, "missing"), { open: 0, blocking: 0, questions: 0, results: 0 });
  assert.equal(C.stateMark(info("s-1"), first), "question");
  assert.equal(C.stateMark(info("s-1", { status: st({ phase: "running" }) }), first), "running");
  assert.equal(C.stateMark(info("s-1"), { ...first, questions: 0 }), "result_ready");
  assert.equal(C.stateMark(info("s-1", { status: st({ phase: "ended", outcome: "done" }) }), first), "result_ready");
  assert.equal(C.stateMark(info("s-1", { status: st({ phase: "ended", outcome: "failed" }) }), first), "failed");
  assert.equal(C.stateMark(info("s-2", { status: st({ phase: "running" }) }), C.attentionFor(inbox, "s-2")), "needs_you");
  assert.equal(C.markWords("result_ready"), "result ready");
  assert.match(C.markWords("question"), /work can continue/);
});

test("mission groups aggregate descendant attention and collapse agents", () => {
  const store = C.createSessionStore();
  C.applySessionList(store, [
    info("old", { created_ms: 100, status: st({ phase: "running" }) }),
    info("new", { created_ms: 300, status: st({ phase: "running" }) }),
    info("needs", { created_ms: 200 }),
    info("worker", { parent: "needs", created_ms: 210 }),
    info("grandchild", { parent: "worker", created_ms: 220 }),
    info("ready", { status: st({ last_end: "finished" }) }),
    info("archived", { archived: true }),
  ]);
  const inbox = C.createInbox();
  C.applyInboxList(inbox, [{ session: "grandchild", item: { item_id: "i", item_kind: "question", blocking: true } }]);
  let groups = C.missionGroups(store, inbox);
  assert.deepEqual(groups.map((g) => g.key), ["needs_answer", "running", "ready"]);
  assert.deepEqual(groups[0].rows.map((r) => r.info.id), ["needs"]);
  assert.equal(groups[0].rows[0].agentCount, 2);
  assert.equal(groups[0].rows[0].attention.blocking, 1);
  assert.deepEqual(groups[1].rows.map((r) => r.info.id), ["new", "old"]);
  groups = C.missionGroups(store, inbox, { expanded: new Set(["needs"]) });
  assert.deepEqual(groups[0].rows.map((r) => [r.info.id, r.depth, r.mission]), [["needs", 0, "needs"], ["worker", 1, "needs"], ["grandchild", 2, "needs"]]);
  C.applyStatus(store, "old", st({ phase: "running", step: 900 }));
  assert.deepEqual(C.missionGroups(store, inbox)[1].rows.map((r) => r.info.id), ["new", "old"], "step updates do not reorder peers");
  groups = C.missionGroups(store, inbox, { showArchived: true });
  assert(groups.flatMap((g) => g.rows).some((r) => r.info.id === "archived"));
});

test("row activity uses recorded update time, never creation age", () => {
  const session = info("s", { created_ms: 0, status: st({ phase: "running", step: 999 }) });
  assert.equal(C.rowActivity(session, null, 86400000), "running · activity not loaded");
  const record = { kind: "tool_call", name: "read", args: { path: "src/a.rs" }, ts_ms: 1000 };
  assert.equal(C.rowActivity(session, record, 61000), "read started: src/a.rs · 1m ago");
  assert.equal(C.rowActivity(session, record, 2000), "read started: src/a.rs · just now");
  assert.match(C.rowActivity(session, { kind: "pin", ts_ms: 61000 }, 62000), /activity not loaded/);
});

test("mission overview derives factual changes without treating a tool pass as verified work", () => {
  const records = [
    { seq: 5, ts_ms: 5000, kind: "inbox_opened", item_kind: "question", blocking: true },
    { seq: 1, ts_ms: 1000, kind: "tool_result", name: "bash", status: "ok", class: "exec", text: "tests passed" },
    { seq: 2, ts_ms: 2000, kind: "ledger", summary: "Added source claim." },
    { seq: 3, ts_ms: 3000, kind: "tool_result", name: "edit", status: "ok", class: "write", meta: { path: "src/a.rs" } },
    { seq: 4, ts_ms: 4000, kind: "tool_result", name: "bash", status: "error", class: "exec" },
    { seq: 6, ts_ms: 6000, kind: "model_request" },
  ];
  const state = {
    plan: [{ id: "p1", status: "done" }, { id: "p2", status: "doing" }, { id: "p3", status: "todo" }],
    claims: [{ status: "open" }, { status: "supported" }, { status: "refuted" }],
    obligations: [{ id: "o1", outcome: null }, { id: "o2", outcome: "done" }],
  };
  const entries = [{ item: { item_id: "q1", blocking: true } }, { item: { item_id: "q2", blocking: false } }];
  const view = C.missionOverview(new Map(records.map((r) => [r.seq, r])), state, entries, 2);
  assert.deepEqual(view.activeSteps, [{ id: "p2", status: "doing" }]);
  // every change is listed; only those recorded after the previous visit are fresh
  assert.deepEqual(view.changes.map((c) => [c.seq, c.fresh]), [[2, false], [3, true], [4, true], [5, true]]);
  assert.equal(view.changes[1].text, "Write tool completed: src/a.rs");
  assert.deepEqual(view.changes.map((c) => c.tone), ["", "", "bad", ""], "only the failed tool result is marked");
  assert.ok(C.missionOverview(records, state, entries).changes.every((c) => !c.fresh), "nothing is new on a first visit");
  const ended = C.missionOverview([{ seq: 1, kind: "session_end", outcome: "failed" }, { seq: 2, kind: "interrupted" }, { seq: 3, kind: "session_end", outcome: "done" }], null, []);
  assert.deepEqual(ended.changes.map((c) => c.tone), ["bad", "bad", ""]);
  assert.deepEqual(view.lastActivity, { seq: 6, ts: 6000, text: "Model request started", kind: "model_request" });
  assert.deepEqual(view.counts, { planTotal: 3, planDone: 1, claimsOpen: 1, claimsSupported: 1, openObligations: 1, pendingDecisions: 1, failedChecks: 1 });
  assert.equal(view.pendingDecisions[0].item.item_id, "q1");
  assert(!JSON.stringify(view).includes("verified"));
  assert.equal(C.missionOverview([], null, []).lastActivity, null);
});

test("recent changes are newest first, split at the previous visit, and say when they are cut", () => {
  const changes = Array.from({ length: 12 }, (_, i) => ({ seq: i + 1, fresh: i >= 10 }));
  const recent = C.recentChanges(changes, 5);
  assert.deepEqual(recent.fresh.map((c) => c.seq), [12, 11]);
  assert.deepEqual(recent.earlier.map((c) => c.seq), [10, 9, 8]);
  assert.deepEqual([recent.shown, recent.total], [5, 12]);
  assert.deepEqual(C.recentChanges(null), { fresh: [], earlier: [], shown: 0, total: 0 });
});

test("plan progress counts the steps still in the plan", () => {
  const plan = [{ status: "done" }, { status: "doing" }, { status: "todo" }, { status: "dropped" }];
  const progress = C.planProgress(plan);
  assert.deepEqual(progress.segments, ["done", "doing", "todo"], "a dropped step has no segment");
  assert.equal(progress.label, "1 of 3 steps done");
  assert.equal(progress.words, "1 of 3 steps done, 1 in progress");
  assert.equal(C.planProgress([{ status: "done" }]).words, "1 of 1 step done");
  assert.equal(C.planProgress(null).total, 0);
  assert.deepEqual(["todo", "doing", "done", "dropped"].map(C.stepWords), ["To do", "In progress", "Done", "Dropped"]);
  assert.deepEqual(["todo", "doing", "done", "dropped", "later"].map(C.stepIcon), ["ring", "half", "check", "cross", "ring"]);
});

test("counts name their noun in the right number", () => {
  assert.equal(C.count(1, "agent"), "1 agent");
  assert.equal(C.count(0, "agent"), "0 agents");
  assert.equal(C.count(1200, "match", "matches"), "1,200 matches");
});

test("what waits on the operator is tallied by class with the oldest opening time", () => {
  const inbox = C.createInbox();
  C.applyInboxList(inbox, [
    { session: "lead", opened_ms: 5000, item: { item_id: "a", item_kind: "question", blocking: true } },
    { session: "worker", opened_ms: 2000, item: { item_id: "b", item_kind: "approval", blocking: true } },
    { session: "lead", opened_ms: 3000, item: { item_id: "c", item_kind: "question", blocking: false } },
    { session: "lead", item: { item_id: "d", item_kind: "finished", blocking: false } },
    { session: "elsewhere", opened_ms: 1, item: { item_id: "e", item_kind: "blocker", blocking: true } },
  ]);
  const waiting = C.waitingFor(inbox, ["lead", "worker"]);
  assert.deepEqual(waiting.blocking, { count: 2, since: 2000, kind: "approval" }, "the kind is that of the oldest blocking item");
  assert.deepEqual(waiting.questions, { count: 1, since: 3000 });
  assert.deepEqual(waiting.results, { count: 1, since: null }, "an item without an opening time has no age");
  assert.equal(C.waitingFor(inbox, new Set(["none"])).blocking.count, 0);
});

test("mission rows carry running agents and what is waiting", () => {
  const store = C.createSessionStore();
  C.applySessionList(store, [
    info("lead", { status: st({ last_end: "waiting" }) }),
    info("w1", { parent: "lead", role: "worker", created_ms: 1100, status: st({ phase: "running" }) }),
    info("w2", { parent: "lead", role: "worker", created_ms: 1200 }),
  ]);
  const inbox = C.createInbox();
  C.applyInboxList(inbox, [{ session: "w1", opened_ms: 1000, item: { item_id: "i", item_kind: "question", blocking: true } }]);
  const rows = C.missionGroups(store, inbox, { expanded: new Set(["lead"]) })[0].rows;
  assert.deepEqual(rows.map((r) => [r.info.id, r.agentCount, r.agentsRunning]), [["lead", 2, 1], ["w1", 0, 0], ["w2", 0, 0]]);
  assert.equal(rows[0].waiting.blocking.count, 1, "the mission row counts what its agents are waiting for");
  assert.equal(rows[1].waiting.blocking.count, 1);
  assert.equal(rows[2].waiting.blocking.count, 0);
  // the second line of each row
  const now = 1000 + 7 * 60000;
  assert.equal(C.rowSummary(rows[0], null, now), "Question waiting 7m · lead waiting");
  assert.equal(C.rowSummary(rows[1], null, now), "worker · question waiting 7m");
  assert.equal(C.rowSummary(rows[2], null, now), "worker · idle");
  assert.equal(C.rowSummary(rows[0], null, 1000), "Question just arrived · lead waiting");
});

test("a row summary puts waiting first, then recorded activity, never the creation age", () => {
  const row = (over = {}, waiting = {}) => ({
    info: info("s", { created_ms: 0, ...over }),
    waiting: { blocking: { count: 0, since: null, kind: null }, questions: { count: 0, since: null }, results: { count: 0, since: null }, ...waiting },
  });
  const record = { kind: "tool_result", name: "read", status: "ok", ts_ms: 1000 };
  assert.equal(C.rowSummary(row({ status: st({ phase: "running" }) }), null, 9e9), "Running · open it to load activity");
  assert.equal(C.rowSummary(row({ status: st({ phase: "running" }) }), record, 13000), "read: completed · 12s ago");
  assert.equal(C.rowSummary(row({ parent: "p", role: "worker", status: st({ phase: "running" }) }), record, 13000), "worker · read: completed · 12s ago");
  assert.equal(C.rowSummary(row({}, { blocking: { count: 3, since: 0, kind: "question" } }), record, 600000), "3 requests waiting · oldest 10m · lead idle");
  assert.equal(C.rowSummary(row({}, { blocking: { count: 1, since: null, kind: "parked" } }), record, 600000), "Parked session waiting · lead idle");
  assert.equal(C.rowSummary(row({ status: st({ phase: "ended", outcome: "done" }) }, { results: { count: 1, since: 0 } }), null, 780000), "Result ready 13m · finished");
  assert.equal(C.rowSummary(row({ status: st({ phase: "running" }) }, { questions: { count: 1, since: 0 } }), null, 60000), "Question open 1m · work can continue");
  assert.equal(C.rowSummary({ info: info("s") }, null, 0), "Idle · open it to load activity", "a row without a tally is still described");
});

test("standing separates what waits on the operator from how execution stands", () => {
  const texts = (s) => s.pills.map((p) => p.text);
  const lead = info("lead", { status: st({ last_end: "waiting" }) });
  const needs = C.missionStanding(lead, { open: 1, blocking: 1, questions: 0, results: 0 }, 2);
  assert.equal(needs.mark, "needs_you");
  assert.deepEqual(texts(needs), ["Needs your answer", "Lead waiting", "2 agents running"]);
  assert.deepEqual(needs.pills.map((p) => p.tone), ["attention", "", "running"]);
  assert.deepEqual(texts(C.missionStanding(lead, { blocking: 0 }, 1)), ["Waiting for jobs or agents", "1 agent running"]);
  const agent = info("w", { parent: "lead", status: st({ phase: "running" }) });
  assert.deepEqual(texts(C.missionStanding(agent, { blocking: 1 }, 5)), ["Needs your answer", "Agent running"], "an agent row never counts agents");
  assert.deepEqual(texts(C.missionStanding(info("x", { status: st({ phase: "ended", outcome: "failed" }) }), { blocking: 0 })), ["Failed"]);
  // a chat has no lead: its root is called a session, in the header and in the list
  const chat = info("chat", { role: "chat", status: st({ phase: "running" }) });
  assert.deepEqual(texts(C.missionStanding(chat, { blocking: 1 })), ["Needs your answer", "Session running"]);
  assert.equal(C.rowSummary({ info: chat, waiting: C.waitingFor({ items: new Map([["i", { session: "chat", opened_ms: 0, item: { item_id: "i", item_kind: "approval", blocking: true } }]]) }, ["chat"]) }, null, 120000), "Approval waiting 2m · session running");
  assert.deepEqual([C.rootNoun(lead), C.rootNoun(chat), C.rootNoun(null)], ["lead", "session", "session"]);
  assert.deepEqual(
    [st({ phase: "running" }), st({ phase: "ended", outcome: "stopped" }), st({ phase: "ended", outcome: "budget_exhausted" }), st({ phase: "ended", outcome: "done" }), st({ last_end: "waiting" }), st({ last_end: "stopped" }), st({})]
      .map((status) => C.executionWord({ status })),
    ["running", "stopped", "failed", "finished", "waiting", "stopped", "idle"]);
  assert.equal(C.executionWord(null), "idle");
});

test("draft destinations are isolated and completing a send preserves subsequent edits", () => {
  const drafts = C.createDraftStore();
  C.setDraft(drafts, "session:s-one", "first mission draft");
  C.setDraft(drafts, "session:s-two", "second mission draft");
  C.setDraft(drafts, "inbox:i-one", "answer draft");
  assert.equal(C.getDraft(drafts, "session:s-one"), "first mission draft");
  assert.equal(C.getDraft(drafts, "session:s-two"), "second mission draft");
  assert.equal(C.getDraft(drafts, "session:missing"), "");
  const submitted = C.getDraft(drafts, "session:s-one");
  C.setDraft(drafts, "session:s-one", "new text while sending");
  assert.equal(C.clearDraftIfUnchanged(drafts, "session:s-one", submitted), false);
  assert.equal(C.getDraft(drafts, "session:s-one"), "new text while sending");
  assert.equal(C.clearDraftIfUnchanged(drafts, "inbox:i-one", "answer draft"), true);
  assert.equal(C.getDraft(drafts, "inbox:i-one"), "");
  assert.equal(C.getDraft(drafts, "session:s-two"), "second mission draft");
  C.setDraft(drafts, "session:s-two", "");
  assert.equal(drafts.has("session:s-two"), false);
  assert.equal(C.clearDraft(drafts, "session:s-one"), true);
});

test("failed HTTP acknowledgement preserves independently recorded message delivery", () => {
  const sending = { state: "delivered", accepted: false, sentText: "continue", afterSeq: 10, recordedSeq: 11, text: "Delivered to a model step." };
  const result = C.sendFailure(sending, "Connection closed");
  assert.equal(result.state, "delivered");
  assert.equal(result.recordedSeq, 11);
  assert.equal(result.sentText, "continue");
  assert.equal(result.afterSeq, 10);
  assert.match(result.text, /Delivered to a model step.*HTTP acknowledgement unavailable/);
  assert.equal(sending.text, "Delivered to a model step.", "the state reducer does not mutate its input");
  const recorded = C.sendFailure({ ...sending, state: "queued", recordedSeq: 0 }, "Request timed out");
  assert.equal(recorded.state, "queued");
  assert.equal(recorded.recordedSeq, 0);
  assert.match(recorded.text, /Message recorded.*HTTP acknowledgement unavailable/);
});

test("unconfirmed sends retain their correlation baseline for a late receipt", () => {
  const sending = { state: "sending", accepted: true, sentText: "continue", afterSeq: 50 };
  const result = C.sendFailure(sending, "Network unavailable");
  assert.equal(result.state, "uncertain");
  assert.equal(result.accepted, false);
  assert.equal(result.sentText, "continue");
  assert.equal(result.afterSeq, 50);
  assert.match(result.text, /could not be confirmed.*Check the record before retrying/);
  assert(!result.text.includes("Not sent"));
  assert.equal(result.recordedSeq, undefined);
});

test("a definite request rejection fails an unrecorded send", () => {
  const result = C.sendFailure({ state: "sending", sentText: "continue", afterSeq: 3 }, "This session has ended.", { rejected: true });
  assert.equal(result.state, "failed");
  assert.equal(result.accepted, false);
  assert.equal(result.sentText, "continue");
  assert.equal(result.afterSeq, 3);
  assert.equal(result.text, "Message rejected: This session has ended.");
});

test("mission routes preserve destination and view across navigation", () => {
  assert.deepEqual(C.parseRoute("#/s/s-one"), { view: "session", session: "s-one", section: "overview" });
  for (const section of ["overview", "record", "evidence"]) {
    assert.deepEqual(C.parseRoute(C.sessionHash("s/one ?#", section)), { view: "session", session: "s/one ?#", section });
  }
  assert.deepEqual(C.parseRoute("#/inbox"), { view: "inbox" });
  assert.deepEqual(C.parseRoute("#/new"), { view: "new" });
  for (const hash of ["", "#/s/", "#/s/%XX/record", "#/s/s-one/unknown", "#/s/s-one/record/extra"]) assert.deepEqual(C.parseRoute(hash), { view: "empty" });
  assert.equal(C.sessionHash("s-one", "unknown"), "#/s/s-one/overview");
});

test("session actions", () => {
  assert.deepEqual(
    Object.entries(C.sessionActions(info("a", { status: st({ phase: "running" }) }))).filter(([, v]) => v).map(([k]) => k),
    ["stop", "archive", "send", "running"],
  );
  const stopped = C.sessionActions(info("a", { status: st({ last_end: "stopped" }) }));
  assert.equal(stopped.resume, true);
  assert.equal(stopped.stop, false);
  const agent = C.sessionActions(info("b", { parent: "a", status: st({ last_end: "waiting" }) }));
  assert.equal(agent.send, false);
  assert.equal(agent.archive, false);
  assert.equal(agent.stop, true);
  const arch = C.sessionActions(info("a", { archived: true }));
  assert.equal(arch.unarchive, true);
  assert.equal(arch.send, false);
  assert.equal(C.sessionActions(info("a", { status: st({ phase: "ended", outcome: "done", last_end: "stopped" }) })).resume, false);
});

test("row detail and health dot", () => {
  const i = info("a", { role: "lead", created_ms: 0, status: st({ step: 7, prompt_tokens: 12345 }) });
  assert.equal(C.rowDetail(i, 2 * 3600_000), "lead · step 7 · 12.3k · 2h");
  assert.equal(C.healthDot({ connected: false, models: [] }).state, "red");
  assert.equal(C.healthDot({ connected: true, models: [{ profile: "p", reachable: true }] }).state, "green");
  const amber = C.healthDot({ connected: true, models: [{ profile: "p", reachable: false, detail: "refused" }] });
  assert.equal(amber.state, "amber");
  assert.match(amber.tip, /p: refused/);
});

// ---- inbox ----

test("inbox: records open and resolve items, blocking first, titles", () => {
  const inbox = C.createInbox();
  const lookup = (id) => ({ mission: "m-1", title: "T " + id });
  const q = rec("inbox_opened", { item_id: "i-1", item_kind: "question", text: "go?", options: ["y", "n"], blocking: true }, "harness", 5);
  const fin = rec("inbox_opened", { item_id: "i-0", item_kind: "finished", text: "done", blocking: false }, "harness", 2);
  const fin2 = rec("inbox_opened", { item_id: "i-2", item_kind: "finished", text: "done2" }, "harness", 9);
  assert.equal(C.applyInboxRecord(inbox, "s-1", fin2, lookup), "opened");
  assert.equal(C.applyInboxRecord(inbox, "s-1", fin, lookup), "opened");
  assert.equal(C.applyInboxRecord(inbox, "s-1", q, lookup), "opened");
  assert.equal(C.applyInboxRecord(inbox, "s-1", q, lookup), null, "announced once");
  assert.deepEqual(C.inboxSorted(inbox).map((e) => e.item.item_id), ["i-1", "i-0", "i-2"]);
  assert.deepEqual(C.inboxCounts(inbox), { open: 3, blocking: 1 });
  assert.equal(C.inboxCountFor(inbox, "s-1"), 3);
  assert.equal(inbox.items.get("i-1").title, "T s-1");
  assert.deepEqual(inbox.items.get("i-1").item.options, ["y", "n"]);
  assert.equal(C.applyInboxRecord(inbox, "s-1", rec("inbox_resolved", { item_id: "i-1", answer: "y" }), lookup), "resolved");
  assert.equal(C.applyInboxRecord(inbox, "s-1", rec("inbox_resolved", { item_id: "i-1", answer: "y" }), lookup), null);
  assert.deepEqual(C.inboxCounts(inbox), { open: 2, blocking: 0 });
});

test("inbox from the api list and the page title", () => {
  const inbox = C.createInbox();
  C.applyInboxList(inbox, [{ session: "s-1", mission: "m", title: "t", opened_ms: 1, item: { item_id: "i-9", item_kind: "blocker", text: "x", options: [], blocking: true } }]);
  assert.deepEqual(C.inboxCounts(inbox), { open: 1, blocking: 1 });
  assert.equal(C.pageTitle({ open: 0, blocking: 0 }), "loom");
  assert.equal(C.pageTitle({ open: 2, blocking: 0 }), "(2) loom");
  assert.equal(C.pageTitle({ open: 2, blocking: 1 }), "(2) needs you · loom");
  const n = C.notificationFor(inbox.items.get("i-9"));
  assert.equal(n.tag, "i-9");
  assert.match(n.title, /blocker/);
});

// ---- record store ----

test("records appear once and in order whatever the delivery order", () => {
  const recs = [];
  for (let i = 0; i < 12; i++) recs.push(rec("user_message", { text: "m" + i }, "user", i));
  const shuffled = [8, 9, 3, 0, 1, 2, 3, 4, 11, 5, 6, 7, 10, 0, 9];
  const store = C.createRecordStore("s-1");
  const news = shuffled.map((i) => C.applyRecord(store, recs[i]));
  assert.equal(store.next, 12);
  assert.equal(store.ahead.size, 0);
  assert.deepEqual(store.blocks.map((b) => b.text), recs.map((r) => r.text));
  assert.equal(news.filter(Boolean).length, 12, "each seq is new exactly once");
  assert.equal(C.lastSeq(store), 11);
  assert.equal(C.missing(store), null);
});

test("page fetch and live stream overlapping give the same transcript", () => {
  const recs = [];
  for (let i = 0; i < 30; i++) recs.push(rec("user_message", { text: "m" + i }, "user", i));
  const store = C.createRecordStore("s-1");
  C.applyRecords(store, recs.slice(25, 28)); // live events arrive first
  assert.equal(store.blocks.length, 0);
  assert.deepEqual(C.missing(store), { after: null, upTo: 24 });
  C.applyRecords(store, recs.slice(0, 20)); // first page
  assert.equal(store.next, 20);
  assert.deepEqual(C.missing(store), { after: 19, upTo: 24 });
  C.applyRecords(store, recs.slice(15, 26)); // second page overlaps both
  assert.equal(store.next, 28);
  C.applyRecords(store, recs.slice(28));
  assert.deepEqual(store.blocks.map((b) => b.seq), [...Array(30).keys()]);
  assert.deepEqual([...store.records.keys()], [...Array(30).keys()], "only applied records enter the overview source");
  assert.strictEqual(store.records.get(8), recs[8]);
});

test("a duplicate buffered record is ignored", () => {
  const store = C.createRecordStore("s");
  assert.equal(C.applyRecord(store, rec("user_message", { text: "x" }, "user", 3)), true);
  assert.equal(C.applyRecord(store, rec("user_message", { text: "x" }, "user", 3)), false);
  assert.equal(C.applyRecord(store, { kind: "user_message" }), false);
});

test("one record of each kind: shown kinds produce blocks, hidden kinds do not", () => {
  const store = C.createRecordStore("s-a");
  C.applyRecords(store, oneOfEach());
  const kinds = store.blocks.map((b) => b.kind);
  assert.deepEqual(kinds, [
    "user", "note", "line" /* model_request, detail */, "response", "tool", "reweave", "child_spawned", "child_settled",
    "line" /* job registered */, "line" /* job settled */, "inbox", "line" /* ledger */, "line" /* cache break */,
    "line" /* interrupted */, "divider", "end",
  ]);
  assert.equal(store.blocks[2].detail, true);
  const r = store.blocks.find((b) => b.kind === "response");
  assert.equal(r.reasoningLines, 2);
  assert.equal(r.footer, "prompt 5 · 80% cached · completion 3 · 3.0s");
  const inbox = store.blocks.find((b) => b.kind === "inbox");
  assert.equal(inbox.resolved.answer, "a");
  assert.equal(store.blocks.find((b) => b.kind === "child_settled").inline, true);
  assert.equal(store.ended, true);
  assert.equal(store.next, 25, "the unknown kind still advances the sequence");
});

test("tool call and result are one block", () => {
  const store = C.createRecordStore("s");
  C.applyRecord(store, rec("model_response", { req_id: "r1", tool_calls: [{ call_id: "c1", name: "bash", arguments: "{}", complete: true }], finish: "tool_calls" }, "model", 0));
  C.applyRecord(store, rec("tool_call", { call_id: "c1", req_id: "r1", name: "bash", args: { command: "ls" }, class: "exec" }, "model", 1));
  assert.equal(store.blocks.length, 2);
  const b = store.blocks[1];
  assert.equal(b.state, "running");
  assert.equal(b.argsLine, "ls");
  C.takeDirty(store);
  C.applyRecord(store, rec("tool_result", { call_id: "c1", name: "bash", status: "error", text: "a\nb\nc", output: { id: "i", bytes: 1, lines: 3 }, cut: false, class: "exec", meta: { exit_code: 1 }, duration_ms: 1500 }, "tool", 2));
  assert.equal(store.blocks.length, 2, "no new block for the result");
  assert.equal(b.state, "done");
  assert.equal(b.result.status, "error");
  assert.equal(b.result.lines, 3);
  assert.equal(b.result.shown.complete, true);
  assert.deepEqual(C.takeDirty(store), [1]);
  assert.deepEqual(C.takeDirty(store), []);
});

test("a call without a result when the turn ends is marked as having none; a late result fixes it", () => {
  const store = C.createRecordStore("s");
  C.applyRecord(store, rec("tool_call", { call_id: "c1", req_id: "r", name: "bash", args: {}, class: "exec" }, "model", 0));
  C.applyRecord(store, rec("tool_call", { call_id: "c2", req_id: "r", name: "read", args: { path: "/a" }, class: "read" }, "model", 1));
  assert.equal(store.blocks[0].state, "running");
  C.applyRecord(store, rec("tool_result", { call_id: "c2", name: "read", status: "ok", text: "x", cut: false, class: "read", meta: {}, duration_ms: 1 }, "tool", 2));
  C.applyRecord(store, rec("interrupted", { reason: "restart" }, "harness", 3));
  assert.equal(store.blocks[0].state, "missing");
  assert.equal(store.blocks[1].state, "done");
  C.applyRecord(store, rec("tool_result", { call_id: "c1", name: "bash", status: "ok", text: "late", cut: false, class: "exec", meta: {}, duration_ms: 1 }, "tool", 4));
  assert.equal(store.blocks[0].state, "done");
});

test("a result without its call is shown as its own block; invalid args fall back to what the model wrote", () => {
  const store = C.createRecordStore("s");
  C.applyRecord(store, rec("tool_result", { call_id: "zz", name: "bash", status: "ok", text: "x", cut: false, class: "exec", meta: {}, duration_ms: 1 }, "tool", 0));
  assert.equal(store.blocks[0].kind, "tool");
  assert.equal(store.blocks[0].state, "done");

  const s2 = C.createRecordStore("s");
  C.applyRecord(s2, rec("model_response", { req_id: "r", tool_calls: [{ call_id: "c9", name: "edit", arguments: "{oops", complete: true }], finish: "tool_calls" }, "model", 0));
  C.applyRecord(s2, rec("tool_call", { call_id: "c9", req_id: "r", name: "edit", args: null, class: "write" }, "model", 1));
  assert.equal(s2.blocks[1].argsInvalid, true);
  assert.equal(s2.blocks[1].argsLine, "{oops");
});

test("a reply cut inside a tool call says so", () => {
  const store = C.createRecordStore("s");
  C.applyRecord(store, rec("model_response", { req_id: "r", tool_calls: [{ call_id: "c1", name: "write", arguments: "{\"pa", complete: false }], finish: "length" }, "model", 0));
  assert.deepEqual(store.blocks[0].cutCalls, ["write"]);
  assert.equal(store.blocks[0].warning.level, "warn");
});

test("inbox card pairs with its resolution, and stays unresolved until then", () => {
  const store = C.createRecordStore("s");
  C.applyRecord(store, rec("inbox_opened", { item_id: "i1", item_kind: "finished", text: "result", blocking: false }, "harness", 0));
  assert.equal(store.blocks[0].resolved, null);
  C.applyRecord(store, rec("inbox_resolved", { item_id: "i1", answer: "" }, "user", 1));
  assert.deepEqual(store.blocks[0].resolved.answer, "");
  assert.equal(store.blocks.length, 1);
  C.applyRecord(store, rec("inbox_resolved", { item_id: "nope", answer: "x" }, "user", 2));
  assert.equal(store.blocks[1].kind, "line");
});

test("deltas fold into a pending reply, cleared by the response with the same req_id", () => {
  const store = C.createRecordStore("s");
  assert.equal(C.applyDelta(store, "r1", { delta: "attempt_start", attempt: 1 }), true);
  C.applyDelta(store, "r1", { delta: "reasoning", text: "think" });
  C.applyDelta(store, "r1", { delta: "reasoning", text: "ing" });
  C.applyDelta(store, "r1", { delta: "text", text: "Hel" });
  C.applyDelta(store, "r1", { delta: "text", text: "lo" });
  C.applyDelta(store, "r1", { delta: "tool_call_start", index: 0, name: "bash" });
  C.applyDelta(store, "r1", { delta: "tool_call_args", index: 0, text: "{\"command\"" });
  C.applyDelta(store, "r1", { delta: "tool_call_args", index: 0, text: ":\"ls\"}" });
  assert.deepEqual(store.pending, { req_id: "r1", attempt: 1, text: "Hello", reasoning: "thinking", calls: [{ index: 0, name: "bash", args: "{\"command\":\"ls\"}" }], retrying: null });

  C.applyDelta(store, "r1", { delta: "retrying", attempt: 2, after_ms: 500, reason: "502" });
  assert.equal(C.retryingWords(store.pending.retrying), "retrying (attempt 2): 502");
  C.applyDelta(store, "r1", { delta: "attempt_start", attempt: 2 });
  assert.equal(store.pending.text, "");
  assert.equal(store.pending.retrying, null);
  assert.equal(store.pending.attempt, 2);

  C.applyDelta(store, "r1", { delta: "text", text: "again" });
  // a response for another request leaves it alone
  C.applyRecord(store, rec("model_response", { req_id: "other", finish: "stop" }, "model", 0));
  assert.ok(store.pending);
  C.applyRecord(store, rec("model_response", { req_id: "r1", text: "again", finish: "stop" }, "model", 1));
  assert.equal(store.pending, null);
  // a late delta for a finished request does not bring it back
  assert.equal(C.applyDelta(store, "r1", { delta: "text", text: "x" }), false);
  assert.equal(store.pending, null);
});

test("a turn end or interruption clears a reply that will never finish", () => {
  const store = C.createRecordStore("s");
  C.applyDelta(store, "r1", { delta: "text", text: "x" });
  C.applyRecord(store, rec("interrupted", { reason: "stop" }, "harness", 0));
  assert.equal(store.pending, null);
});

// ---- windowing and scrolling ----

test("transcript windowing", () => {
  assert.equal(C.initialFrom(10), 0);
  assert.equal(C.initialFrom(10_000), 9_700);
  assert.equal(C.earlierFrom(9_700), 9_400);
  assert.equal(C.earlierFrom(100), 0);
  assert.equal(C.trimFrom(1000, 0), 0);
  assert.equal(C.trimFrom(2000, 300), 500);
  assert.equal(C.atEnd(900, 100, 1000), true);
  assert.equal(C.atEnd(500, 100, 1000), false);
});

test("a 10,000 record session applies fast and hands out only the tail", () => {
  const store = C.createRecordStore("s");
  const t0 = performance.now();
  for (let i = 0; i < 10_000; i += 4) {
    store.dirty.clear();
    C.applyRecord(store, rec("model_response", { req_id: "r" + i, text: "t", tool_calls: [{ call_id: "c" + i, name: "bash", arguments: "{}", complete: true }], finish: "tool_calls" }, "model", i));
    C.applyRecord(store, rec("tool_call", { call_id: "c" + i, req_id: "r" + i, name: "bash", args: { command: "ls" }, class: "exec" }, "model", i + 1));
    C.applyRecord(store, rec("tool_result", { call_id: "c" + i, name: "bash", status: "ok", text: "x", cut: false, class: "exec", meta: {}, duration_ms: 1 }, "tool", i + 2));
    C.applyRecord(store, rec("turn_end", { reason: "waiting" }, "harness", i + 3));
  }
  assert.ok(performance.now() - t0 < 2000);
  assert.equal(store.next, 10_000);
  assert.equal(store.openCalls.size, 0);
  assert.deepEqual(C.takeDirty(store).length <= 4, true, "one record dirties O(1) blocks");
});

test("composer keys", () => {
  assert.equal(C.composerAction({ key: "Enter", shiftKey: false, isComposing: false, text: "hi" }), "send");
  assert.equal(C.composerAction({ key: "Enter", shiftKey: true, isComposing: false, text: "hi" }), "none");
  assert.equal(C.composerAction({ key: "Enter", shiftKey: false, isComposing: true, text: "hi" }), "none");
  assert.equal(C.composerAction({ key: "Enter", shiftKey: false, isComposing: false, text: "  " }), "ignore");
  assert.equal(C.composerAction({ key: "a", shiftKey: false, isComposing: false, text: "hi" }), "none");
});

// ---- blob viewer ----

test("blob viewer pages in order until the end", () => {
  const v = C.createViewer("b", 2500);
  assert.deepEqual(C.nextRange(v), { start: 1, end: 1000 });
  assert.equal(C.applyLines(v, { text: "a", first: 1, last: 1000, total: 2500 }), true);
  assert.deepEqual(C.nextRange(v), { start: 1001, end: 2000 });
  assert.equal(C.applyLines(v, { text: "x", first: 5, last: 10, total: 2500 }), false, "out of order page refused");
  C.applyLines(v, { text: "b", first: 1001, last: 2000, total: 2500 });
  C.applyLines(v, { text: "c", first: 2001, last: 2500, total: 2500 });
  assert.equal(v.done, true);
  assert.equal(C.nextRange(v), null);
  assert.deepEqual(v.chunks, ["a", "b", "c"]);
});

test("blob viewer pages backwards from a range opened in the middle", () => {
  const v = C.createViewer("b", 5000);
  assert.equal(C.earlierRange(v), null, "nothing is loaded yet");
  C.applyLines(v, { text: "m", first: 1593, last: 1608, total: 5000 });
  assert.deepEqual(C.earlierRange(v), { start: 593, end: 1592 });
  assert.equal(C.applyEarlierLines(v, { text: "x", first: 1, last: 500, total: 5000 }), false, "a page that does not touch the loaded lines is refused");
  assert.equal(C.applyEarlierLines(v, { text: "e", first: 593, last: 1592, total: 5000 }), true);
  assert.deepEqual([v.first, v.last, v.chunks], [593, 1608, ["e", "m"]]);
  assert.deepEqual(C.earlierRange(v), { start: 1, end: 592 }, "the first page stops at line 1");
  C.applyEarlierLines(v, { text: "s", first: 1, last: 592, total: 5000 });
  assert.equal(C.earlierRange(v), null, "loaded from the first line");
  assert.deepEqual(C.nextRange(v), { start: 1609, end: 2608 }, "later pages still follow the loaded lines");
});

test("stored text splits into its lines without a phantom last line", () => {
  assert.deepEqual(C.splitLines("a\nb\n"), ["a", "b"]);
  assert.deepEqual(C.splitLines("a\n\nb"), ["a", "", "b"]);
  assert.deepEqual(C.splitLines("\n"), [""], "one empty line");
  assert.deepEqual(C.splitLines(""), []);
  assert.deepEqual(C.splitLines(null), []);
});

test("go to line accepts whole lines inside the output and says what is allowed otherwise", () => {
  assert.deepEqual(C.lineTarget(" 2000 ", 5000), { line: 2000 });
  assert.deepEqual(C.lineTarget(5000, 5000), { line: 5000 });
  for (const bad of ["", "0", "-3", "1.5", "abc", "5001", "1e99"]) {
    assert.equal(C.lineTarget(bad, 5000).error, "Choose a line from 1 to 5,000.", `"${bad}"`);
  }
  assert.deepEqual(C.lineTarget("7", 0), { line: 7 }, "an unknown length does not bound the line");
  assert.equal(C.lineTarget("0", 0).error, "Choose a line number of 1 or more.");
});

test("find searches line text only, without regard to case, and steps both ways", () => {
  const lines = ["stored output line 1593", "outcome,", "full: None,", "ΣΑΣ none"];
  assert.deepEqual(C.findInLines(lines, "NONE"), [{ index: 2, at: 6, length: 4 }, { index: 3, at: 4, length: 4 }]);
  assert.deepEqual(C.findInLines(lines, "1594"), [], "a line number is not part of the text");
  assert.deepEqual(C.findInLines(lines, ""), []);
  assert.deepEqual(C.findInLines(lines, ".*"), [], "the query is literal");
  assert.equal(C.findInLines(["İstanbul none"], "none")[0].at, -1, "no exact place when lower-casing changes the length");
  assert.equal(C.stepMatch(3, -1, 1), 0);
  assert.equal(C.stepMatch(3, -1, -1), 2, "previous from nowhere is the last match");
  assert.equal(C.stepMatch(3, 2, 1), 0, "next wraps");
  assert.equal(C.stepMatch(3, 0, -1), 2, "previous wraps");
  assert.equal(C.stepMatch(0, -1, 1), -1);
});

test("a copied reference names the line gone to, else the cited lines, else what is loaded", () => {
  const v = { ...C.createViewer("abc", 5000), first: 1593, last: 1608, source: {} };
  assert.equal(C.viewerReference(v), "out:abc lines 1593–1608");
  v.source = { citeStart: 212, citeEnd: 214, session: "s-audit", call: "read1" };
  assert.equal(C.viewerReference(v), "out:abc lines 212–214 (s-audit, call read1)");
  v.source = { citeStart: 1596, session: "s-audit" };
  assert.equal(C.viewerReference(v), "out:abc line 1596 (s-audit)");
  v.target = 2000;
  assert.equal(C.viewerReference(v), "out:abc line 2000 (s-audit)");
  assert.equal(C.sourceRangeWords(7, 7), "line 7");
});

// ---- context, ledger, network ----

test("context meter has marks at floor and target", () => {
  const m = C.windowMeter({ est_tokens: 150_000, context_window: 1_000_000, floor_tokens: 180_000, target_tokens: 400_000 });
  assert.equal(m.inViewPct, 15);
  assert.equal(m.floorPct, 18);
  assert.equal(m.targetPct, 40);
  assert.equal(m.over, false);
  assert.equal(m.label, "150k of 1M");
  const unknown = C.windowMeter({ est_tokens: 500_000, context_window: null, floor_tokens: 180_000, target_tokens: 400_000 });
  assert.equal(unknown.known, false);
  assert.equal(unknown.over, true);
  assert.ok(unknown.inViewPct <= 100 && unknown.targetPct < 100);
  assert.equal(C.windowMeter({ est_tokens: 5e9, context_window: 1000, floor_tokens: 0, target_tokens: 0 }).inViewPct, 100);
  const s = C.statusMeter(info("a", { context_window: 1000, status: st({ prompt_tokens: 250 }) }));
  assert.equal(s.inViewPct, 25);
});

test("window summary and rows", () => {
  const w = {
    epoch: 1, est_tokens: 10, target_tokens: 1, floor_tokens: 1, context_window: 100, prompt_tokens: 100, cached_tokens: 50,
    items: [
      { seq: 1, kind: "user_message", state: "live", chars: 40, pinned: true, preview: "hi" },
      { seq: 2, kind: "tool_result", state: "stubbed", chars: 2000, pinned: false, preview: "[stub]" },
      { seq: 3, kind: "model_response", state: "reasoning_dropped", chars: 30, preview: "x" },
      { seq: 4, kind: "tool_result", state: "dropped", chars: 0, preview: "" },
    ],
  };
  const s = C.windowSummary(w);
  assert.deepEqual(s.counts, { live: 1, stubbed: 1, reasoning_dropped: 1, dropped: 1 });
  assert.equal(s.folded, 3);
  assert.equal(s.pinned, 1);
  assert.equal(s.cached, "50%");
  assert.equal(C.windowRows(w).length, 4);
  assert.equal(C.windowRows(w, { hideFolded: true }).length, 2);
  assert.equal(C.windowRows(w)[2].stateWords, "reasoning dropped");
  assert.equal(C.windowRows(w)[1].size, "2k chars");
});

test("ledger model joins evidence to claims and keeps open obligations only", () => {
  const view = {
    markdown: "",
    state: {
      goal: "g", entries: 5, constraints: [{ id: "k1", text: "no net", retired: null }],
      plan: [{ id: "p1", text: "do", status: "doing", note: "", evidence: [] }],
      decisions: [{ id: "d1", text: "x", reason: "y", n: 1 }], dead_ends: [{ id: "x1", what: "w", why: "z", n: 2 }],
      claims: [{ id: "c1", text: "it works", status: "supported", note: "", evidence: ["e1"] }],
      evidence: [{ id: "e1", claim: "c1", kind: "execution", supports: true, session: "s", call_id: "c1", blob: "bb", lines: [3, 9], quote: "ok", note: "n", attested: true, n: 4 }],
      obligations: [{ id: "o1", kind: "job", text: "wait", reference: "", outcome: null }, { id: "o2", kind: "job", text: "done", reference: "", outcome: "ok" }],
      approvals: [], questions: [{ id: "q1", text: "?", blocking: true, answer: null }], finishes: [],
    },
  };
  const m = C.ledgerModel(view);
  assert.equal(m.empty, false);
  assert.equal(m.claims[0].evidence[0].lines, "lines 3–9");
  assert.equal(m.claims[0].evidence[0].attested, true);
  assert.equal(m.claims[0].evidence[0].session, "s", "source navigation retains the producer session");
  delete view.state.evidence[0].session;
  assert.equal(C.ledgerModel(view).claims[0].evidence[0].session, null, "older evidence has no invented producer");
  assert.deepEqual(m.obligations.map((o) => o.id), ["o1"]);
  assert.equal(m.questions[0].answer, null);
  assert.equal(C.ledgerModel({ state: { entries: 0 } }).empty, true);
});

test("evidence keeps a usable line range, and a quote match is not the direction of the evidence", () => {
  const ev = (lines) => C.ledgerModel({ state: { entries: 1, claims: [{ id: "c1", text: "t", status: "open", evidence: ["e1"] }], evidence: [{ id: "e1", supports: true, kind: "static", attested: true, quote: "q", blob: "b", lines }] } }).claims[0].evidence[0];
  assert.deepEqual([ev([1596, 1596]).range, ev([1596, 1596]).lines], [[1596, 1596], "line 1596"]);
  assert.deepEqual([ev([212, 214]).range, ev([212, 214]).lines], [[212, 214], "lines 212–214"]);
  for (const bad of [undefined, null, [0, 3], [9, 3]]) assert.deepEqual([ev(bad).range, ev(bad).lines], [null, ""], JSON.stringify(bad));
  const standing = (e) => { const s = C.evidenceStanding(e); return [s.quote.text, s.quote.tone, s.direction.text]; };
  assert.deepEqual(standing({ quote: "q", attested: true, supports: true }), ["Quote matches stored output", "ok", "Supports"]);
  assert.deepEqual(standing({ quote: "q", attested: true, supports: false }), ["Quote matches stored output", "ok", "Undermines"]);
  assert.deepEqual(standing({ quote: "q", attested: false, supports: true }), ["Quote not checked against stored output", "warn", "Supports"]);
  assert.deepEqual(standing({ quote: "", attested: false, supports: false }), ["No quote recorded", "dim", "Undermines"]);
  for (const e of [{ quote: "q", attested: true, supports: true }, { quote: "q" }, {}]) {
    assert.doesNotMatch(JSON.stringify(C.evidenceStanding(e)), /verif|confirm|proved|failed/i, "neither fact is verification, and an unchecked quote did not fail");
  }
});

test("claim filters count by recorded status and offer withdrawn only when it is used", () => {
  const claims = [{ id: "c1", status: "open" }, { id: "c2", status: "supported" }, { id: "c3", status: "open" }];
  assert.deepEqual(C.claimFilters(claims).map((f) => [f.key, f.label, f.count]), [["all", "All", 3], ["open", "Open", 2], ["supported", "Supported", 1], ["refuted", "Refuted", 0]]);
  assert.deepEqual(C.filterClaims(claims, "open").map((c) => c.id), ["c1", "c3"]);
  assert.deepEqual(C.filterClaims(claims, "refuted"), []);
  assert.equal(C.filterClaims(claims, "all").length, 3);
  assert.equal(C.filterClaims(claims, "withdrawn").length, 3, "a filter that is not offered shows every claim");
  const withdrawn = [...claims, { id: "c4", status: "withdrawn" }];
  assert.deepEqual(C.claimFilters(withdrawn).at(-1), { key: "withdrawn", label: "Withdrawn", count: 1 });
  assert.deepEqual(C.filterClaims(withdrawn, "withdrawn").map((c) => c.id), ["c4"]);
  assert.deepEqual(C.claimFilters(null).map((f) => f.count), [0, 0, 0, 0]);
  assert.equal(C.claimStatusWords("refuted"), "Refuted");
});

test("net rows and live dedupe", () => {
  const e = { ts_ms: 1, host: "h", port: 443, method: "CONNECT", allowed: false, rule: "default deny", resolved: null };
  const r = C.netRow(e);
  assert.equal(r.verdict, "refused");
  assert.equal(r.target, "h:443");
  const list = [e];
  C.applyNet(list, { ...e });
  assert.equal(list.length, 1);
  C.applyNet(list, { ...e, ts_ms: 2 });
  assert.equal(list.length, 2);
});

// ---- event planning ----

test("planEvent", () => {
  const ctx = { openId: "s-1", ledgerMission: "m-1", known: (id) => id !== "s-new", missionOf: (id) => (id === "s-2" ? "m-1" : "m-9") };
  const fx = (ev) => C.planEvent(ev, ctx).map((e) => e.fx);
  assert.deepEqual(fx({ type: "record", session: "s-1", record: rec("user_message", { text: "x" }) }), ["apply_record"]);
  assert.deepEqual(fx({ type: "record", session: "s-1", record: rec("turn_end", { reason: "waiting" }) }), ["apply_record", "refetch_window"]);
  assert.deepEqual(fx({ type: "record", session: "s-1", record: rec("reweave", {}) }), ["apply_record", "refetch_window"]);
  assert.deepEqual(fx({ type: "record", session: "s-7", record: rec("user_message", { text: "x" }) }), []);
  assert.deepEqual(fx({ type: "record", session: "s-7", record: rec("inbox_opened", { item_id: "i" }) }), ["inbox_record"]);
  assert.deepEqual(fx({ type: "record", session: "s-2", record: rec("ledger", { n: 1, summary: "s" }) }), ["refetch_ledger"], "another session of the mission");
  assert.deepEqual(fx({ type: "record", session: "s-8", record: rec("ledger", { n: 1, summary: "s" }) }), []);
  assert.deepEqual(fx({ type: "status", session: "s-new", status: {} }), ["status", "refetch_sessions"]);
  assert.deepEqual(fx({ type: "status", session: "s-1", status: {} }), ["status", "header"]);
  assert.deepEqual(fx({ type: "delta", session: "s-1", req_id: "r", delta: { delta: "text", text: "x" } }), ["apply_delta"]);
  assert.deepEqual(fx({ type: "delta", session: "s-2", req_id: "r", delta: { delta: "text", text: "x" } }), []);
  assert.deepEqual(fx({ type: "net", session: "s-1", entry: {} }), ["net"]);
  assert.deepEqual(fx({ type: "lagged", missed: 5 }), ["refetch_sessions", "refetch_inbox", "refetch_records"]);
  assert.deepEqual(C.planEvent({ type: "lagged", missed: 5 }, { ...ctx, openId: null }).map((e) => e.fx), ["refetch_sessions", "refetch_inbox"]);
  assert.deepEqual(fx({ type: "error", session: null, message: "boom" }), ["notice"]);
  assert.deepEqual(fx({ type: "settled", session: "s-1" }), []);
  assert.deepEqual(fx({ type: "from_the_future" }), []);
  assert.deepEqual(fx(null), []);
});

// ---- forms and errors ----

test("new session form", () => {
  assert.match(C.buildNewSession({ workspace: " ", message: "x" }).error, /Workspace/);
  assert.match(C.buildNewSession({ workspace: "/w", message: "  " }).error, /message/);
  assert.deepEqual(C.buildNewSession({ workspace: " /w ", message: " do it ", role: "chat", model: "local", title: " ", unattended: false }).body, {
    workspace: "/w", message: "do it", role: "chat", unattended: false, model: "local",
  });
  assert.equal(C.buildNewSession({ workspace: "/w", message: "x", title: "T", unattended: true }).body.title, "T");
});

test("error sentence", () => {
  assert.equal(C.errorSentence(409, '{"error":"Stop the session before archiving it."}'), "Stop the session before archiving it.");
  assert.equal(C.errorSentence(500, ""), "The request failed (500).");
  assert.equal(C.errorSentence(502, "bad gateway"), "bad gateway");
});

// ---- safety: nothing in the shipped DOM code can turn record content into markup ----

function stripComments(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

test("index.html and app.js contain no HTML sinks, inline handlers, inline styles or remote URLs", () => {
  const html = readFileSync(join(here, "index.html"), "utf8");
  const app = readFileSync(join(here, "app.js"), "utf8");
  const core = readFileSync(join(here, "core.js"), "utf8");
  const bad = [
    ["innerHTML", /innerHTML/],
    ["outerHTML", /outerHTML/],
    ["insertAdjacentHTML", /insertAdjacentHTML/],
    ["document.write", /document\s*\.\s*write/],
    ["eval(", /(^|[^A-Za-z0-9_$])eval\s*\(/],
    ["new Function", /new\s+Function/],
    ["Function(", /(^|[^A-Za-z0-9_$.])Function\s*\(/],
    ["setTimeout with a string", /set(Timeout|Interval)\s*\(\s*["'`]/],
    ["srcdoc", /srcdoc/i],
    ["createContextualFragment", /createContextualFragment/],
    ["DOMParser", /DOMParser/],
    ["inline style attribute", /style\s*=\s*["']/],
    ["setAttribute style", /setAttribute\(\s*["']style["']/],
    ["setAttribute on*", /setAttribute\(\s*["']on/i],
    ["on* property", /\.on[a-z]+\s*=[^=]/],
  ];
  for (const [name, re] of bad) {
    assert.ok(!re.test(stripComments(app)), `app.js has ${name}`);
    assert.ok(!re.test(stripComments(core)), `core.js has ${name}`);
  }
  // html: no inline script, no on*= attribute, no style attribute, no style element, no remote URL
  const htmlNoComments = html.replace(/<!--[\s\S]*?-->/g, "");
  for (const [name, re] of [
    ["innerHTML", /innerHTML/],
    ["inline on* attribute", /<[^>]*\son[a-z]+\s*=/i],
    ["style attribute", /<[^>]*\sstyle\s*=/i],
    ["style element", /<style[\s>]/i],
    ["http(s) URL", /https?:\/\//i],
    ["javascript: URL", /javascript:/i],
  ]) assert.ok(!re.test(htmlNoComments), `index.html has ${name}`);
  for (const m of htmlNoComments.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    assert.match(m[1], /\ssrc="\/[^"]+"/, "scripts are loaded from the daemon");
    assert.equal(m[2].trim(), "", "no inline script body");
  }
  assert.ok(/<script[^>]*type="module"[^>]*src="\/app\.js"/.test(htmlNoComments) || /<script[^>]*src="\/app\.js"[^>]*type="module"/.test(htmlNoComments));
  // no http(s) URL anywhere in app.js or core.js outside comments
  assert.ok(!/https?:\/\//i.test(stripComments(app)), "app.js has a remote URL");
  assert.ok(!/https?:\/\//i.test(stripComments(core)), "core.js has a remote URL");
  // core.js is pure
  assert.ok(!/\b(document|window|fetch|localStorage|EventSource)\b/.test(stripComments(core)), "core.js touches the browser");
});

test("every drawing the scripts name is in the icon template, and every id they look up is in the page", () => {
  const html = readFileSync(join(here, "index.html"), "utf8");
  const app = stripComments(readFileSync(join(here, "app.js"), "utf8"));
  const template = html.match(/<template id="icons">([\s\S]*?)<\/template>/);
  assert.ok(template, "index.html carries the icon template");
  const drawn = new Set([...template[1].matchAll(/data-icon="([a-z-]+)"/g)].map((m) => m[1]));
  const named = new Set([...app.matchAll(/\bicon\("([a-z-]+)"\)/g)].map((m) => m[1]));
  for (const mark of ["needs_you", "running", "waiting", "stopped", "finished", "failed", "idle", "result_ready", "question", "not a mark"]) named.add(C.markIcon(mark));
  for (const status of ["todo", "doing", "done", "dropped", "not a status"]) named.add(C.stepIcon(status));
  for (const evidence of [{ quote: "q", attested: true }, { quote: "q" }]) named.add(C.evidenceStanding(evidence).quote.icon);
  for (const status of [st({ phase: "running" }), st({ last_end: "waiting" }), st({ phase: "ended", outcome: "failed" }), st({ phase: "ended", outcome: "done" }), st({ last_end: "stopped" }), st({})]) {
    for (const attention of [{ blocking: 1 }, { blocking: 0, questions: 1 }, { blocking: 0, results: 1 }, { blocking: 0 }]) {
      for (const p of C.missionStanding(info("s", { status }), attention, 1).pills) if (p.icon) named.add(p.icon);
    }
  }
  assert.ok(named.size >= 10, "the marks, the steps and the evidence chips have drawings");
  for (const name of named) assert.ok(drawn.has(name), `index.html has no drawing for "${name}"`);
  // a drawing never carries meaning alone: the words beside it do, so it is hidden from speech
  for (const m of html.matchAll(/<svg\b[^>]*>/g)) assert.match(m[0], /aria-hidden="true"/, m[0]);
  const ids = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
  const lookups = [...app.matchAll(/\$\("([A-Za-z0-9_-]+)"\)/g)].map((m) => m[1]);
  assert.ok(lookups.length > 50);
  for (const id of lookups) assert.ok(ids.has(id), `app.js looks up #${id}, which index.html does not have`);
});

test("two fields share the stored output dialog, so it is not a form and each field handles Enter", () => {
  const html = readFileSync(join(here, "index.html"), "utf8");
  const app = stripComments(readFileSync(join(here, "app.js"), "utf8"));
  const dialog = html.match(/<dialog id="viewer"[\s\S]*?<\/dialog>/)[0];
  assert.doesNotMatch(dialog, /<form\b/, "a form with two fields and no submit button swallows Enter");
  assert.equal((dialog.match(/<button\b[^>]*>/g) || []).filter((b) => !/type="button"/.test(b)).length, 0);
  for (const field of ["viewer-start", "viewer-find"]) {
    assert.match(app, new RegExp(`\\$\\("${field}"\\)\\.addEventListener\\("keydown"`), `${field} handles Enter itself`);
  }
  // opening puts focus on the lines, so Enter is never left resting on Close
  assert.match(app, /\$\("viewer-scroll"\)\.focus\(/);
  assert.match(dialog, /id="viewer-scroll"[^>]*tabindex="0"/);
});

test("the files the daemon embeds exist and the stylesheet carries no remote loads", () => {
  for (const f of ["index.html", "style.css", "core.js", "app.js"]) assert.ok(readFileSync(join(here, f), "utf8").length > 100, f);
  const css = readFileSync(join(here, "style.css"), "utf8");
  assert.ok(!/@import|url\(\s*["']?https?:/i.test(css));
  assert.ok(/prefers-color-scheme:\s*light/.test(css));
});
