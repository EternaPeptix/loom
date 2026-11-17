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
    rec("job_matched", { job_id: "j1", pattern: "CRASH", output: BLOB, from: 0, shown: [2], matches: 1 }),
    rec("inbox_opened", { item_id: "i-1", item_kind: "question", text: "t", options: ["a"], blocking: true, call_id: "c1", reference: "q1" }),
    rec("inbox_resolved", { item_id: "i-1", answer: "a" }, "user"),
    rec("ledger", { n: 3, summary: "s" }),
    rec("net", { host: "h", port: 443, method: "CONNECT", allowed: false, rule: "deny", resolved: "1.2.3.4" }),
    rec("cache_break", { req_id: "r-1", first_diff_message: 2, detail: "d" }),
    rec("model_switched", { from: { profile: "a", model: "m1", context_window: 1000 }, to: { profile: "b", model: "m2", context_window: 0 }, reasoning_replay: "none", reason: "operator" }),
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
  const deferred = C.shownOfTotal({ cut: false, output: { id: "stored", lines: 7 }, meta: { deferred_observation: true } });
  assert.match(deferred.words, /initially deferred/);
  assert.doesNotMatch(deferred.words, /All 7 lines shown/);
});

test("mergeRanges merges overlapping and adjacent ranges, drops nonsense", () => {
  assert.deepEqual(C.mergeRanges([[5, 9], [1, 3], [4, 4], [20, 10], "x"]), [[1, 9]]);
  assert.deepEqual(C.mergeRanges(undefined), []);
});

test("tokensPerSecond counts the tokens after the first over the time after the first", () => {
  const r = (n, first, total) => ({ kind: "response", usage: { completion_tokens: n }, timing: { ttft_ms: first, total_ms: total } });
  assert.equal(C.tokensPerSecond(r(201, 500, 4500)), 50);
  assert.equal(C.tokensPerSecond(r(1, 500, 4500)), null);        // one token has no rate
  assert.equal(C.tokensPerSecond(r(201, 0, 4500)), null);        // no first-token time recorded
  assert.equal(C.tokensPerSecond(r(201, 4500, 4500)), null);     // no time after the first token
  assert.equal(C.tokensPerSecond({}), null);
  assert.equal(C.speedText(46.24), "46.2 tok/s");
  assert.equal(C.speedText(131.6), "132 tok/s");
  assert.equal(C.speedText(null), "");
  const one = C.sessionSpeed([{ kind: "user" }, r(201, 500, 4500)]);
  assert.equal(one.label, "50.0 tok/s");
  // The latest reply first, then all counted replies together: (200 + 100) tokens over (4 + 4) seconds.
  const two = C.sessionSpeed([r(201, 500, 4500), { kind: "tool" }, r(1, 100, 200), r(101, 1000, 5000)]);
  assert.equal(two.label, "25.0 tok/s · 37.5 tok/s over 2 replies");
  assert.equal(C.sessionSpeed([{ kind: "user" }]).label, "");
  assert.equal(C.sessionSpeed(undefined).label, "");
});

test("responseFooter", () => {
  const f = C.responseFooter({ usage: { prompt_tokens: 12345, cached_tokens: 9876, completion_tokens: 340 }, timing: { total_ms: 4200 }, attempts: 1 });
  assert.equal(f, "prompt 12.3k · 80% cached · completion 340 · 4.2s");
  assert.match(C.responseFooter({ usage: {}, timing: {}, attempts: 3 }), /3 attempts$/);
  // With a first-token time the footer also gives the generation speed.
  const g = C.responseFooter({ usage: { prompt_tokens: 100, completion_tokens: 201 }, timing: { ttft_ms: 500, total_ms: 4500 } });
  assert.equal(g, "prompt 100 · 0% cached · completion 201 · 50.0 tok/s · 4.5s");
  assert.equal(C.finishWarning("length").level, "warn");
  assert.equal(C.finishWarning("stop"), null);
});

test("reweave summary and eviction words", () => {
  const s = C.reweaveSummary({ reason: "target", evictions: [1, 2, 3], before_tokens: 400000, after_tokens_est: 180000 });
  assert.equal(s, "context re-woven (target) — 3 items folded out of view, about 400k → 180k tokens");
  assert.match(C.evictionWords({ seq: 1, action: { stub: { text: "gone" } } }), /^stub: gone/);
  assert.equal(C.evictionWords({ seq: 1, action: "drop" }), "dropped");
  assert.equal(C.evictionWords({ seq: 1, action: "drop_reasoning" }), "reasoning dropped");
  assert.equal(C.evictionWords({ seq: 1, action: "remove" }), "call and result out of view");
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

test("mission rows carry what is waiting, and the second line of each", () => {
  const inbox = C.createInbox();
  C.applyInboxList(inbox, [{ session: "w1", opened_ms: 1000, item: { item_id: "i", item_kind: "question", blocking: true } }]);
  const rows = [
    { info: info("lead", { status: st({ last_end: "waiting" }) }), waiting: C.waitingFor(inbox, ["lead", "w1", "w2"]) },
    { info: info("w1", { parent: "lead", role: "worker", status: st({ phase: "running" }) }), waiting: C.waitingFor(inbox, ["w1"]) },
    { info: info("w2", { parent: "lead", role: "worker" }), waiting: C.waitingFor(inbox, ["w2"]) },
  ];
  assert.equal(rows[0].waiting.blocking.count, 1, "the mission row counts what its agents are waiting for");
  assert.equal(rows[1].waiting.blocking.count, 1);
  assert.equal(rows[2].waiting.blocking.count, 0);
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
  assert.deepEqual(C.parseRoute("#/s/s-one"), { view: "session", session: "s-one", section: "chat" });
  for (const section of ["chat", "overview", "evidence"]) {
    assert.deepEqual(C.parseRoute(C.sessionHash("s/one ?#", section)), { view: "session", session: "s/one ?#", section });
  }
  // the old name of the chat tab opens chat and says what to rewrite the address to
  assert.deepEqual(C.parseRoute("#/s/s-one/record"), { view: "session", session: "s-one", section: "chat", rewrite: "#/s/s-one/chat" });
  assert.equal(C.sessionHash("s-one", "record"), "#/s/s-one/chat");
  assert.deepEqual(C.parseRoute("#/inbox"), { view: "inbox" });
  assert.deepEqual(C.parseRoute("#/new"), { view: "new" });
  for (const hash of ["", "#/s/", "#/s/%XX/record", "#/s/s-one/unknown", "#/s/s-one/record/extra"]) assert.deepEqual(C.parseRoute(hash), { view: "empty" });
  assert.equal(C.sessionHash("s-one", "unknown"), "#/s/s-one/chat");
  assert.equal(C.sessionHash("s-one"), "#/s/s-one/chat");
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

test("health dot", () => {
  assert.equal(C.healthDot({ connected: false, models: [] }).state, "red");
  assert.equal(C.healthDot({ connected: true, models: [{ profile: "p", reachable: true }] }).state, "green");
  const amber = C.healthDot({ connected: true, models: [{ profile: "p", reachable: false, detail: "refused" }] });
  assert.equal(amber.state, "amber");
  assert.match(amber.tip, /p: refused/);
});

test("diskWarning: a sentence below 5 GiB or 5 percent free, null otherwise or when unknown", () => {
  const GiB = 1024 ** 3;
  assert.equal(C.diskWarning(null), null);
  assert.equal(C.diskWarning(undefined), null);
  assert.equal(C.diskWarning({ free_bytes: 400 * GiB, total_bytes: 1000 * GiB }), null);
  assert.equal(C.diskWarning({ free_bytes: 5 * GiB, total_bytes: 40 * GiB }), null);
  assert.match(C.diskWarning({ free_bytes: 3 * GiB, total_bytes: 1000 * GiB }), /^Low disk space: 3\.0 GiB free of 1000\.0 GiB\..*loom gc/);
  assert.match(C.diskWarning({ free_bytes: 40 * GiB, total_bytes: 1000 * GiB }), /Low disk space/);
  assert.equal(C.diskWarning({ free_bytes: 0, total_bytes: 0 }), null);
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
});

test("inbox list does not resurrect an item the operator already answered", () => {
  // The daemon resolves a dismissal asynchronously; a refetch in that window still lists the item.
  const inbox = C.createInbox();
  const list = [
    { session: "s-1", title: "t", opened_ms: 1, item: { item_id: "i-done", item_kind: "finished", text: "r", options: [], blocking: false } },
    { session: "s-1", title: "t", opened_ms: 2, item: { item_id: "i-live", item_kind: "question", text: "q", options: [], blocking: true } },
  ];
  const answered = new Map([["i-done", { answer: "" }]]);
  C.applyInboxList(inbox, list, answered);
  assert.deepEqual([...inbox.items.keys()], ["i-live"], "the answered item is not re-added");
  // With no answered set the whole list applies (back-compatible).
  C.applyInboxList(inbox, list);
  assert.deepEqual([...inbox.items.keys()].sort(), ["i-done", "i-live"]);
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
    "line" /* job registered */, "line" /* job settled */, "line" /* job matched */, "inbox", "line" /* ledger */, "line" /* cache break */,
    "line" /* model switched */, "line" /* interrupted */, "divider", "end",
  ]);
  const switched = store.blocks.find((b) => b.kind === "line" && /model switched/.test(b.text));
  assert.equal(switched.text, "model switched: a (m1, 1k context) → b (m2) · operator");
  assert.equal(store.blocks[2].detail, true);
  const r = store.blocks.find((b) => b.kind === "response");
  assert.equal(r.reasoningLines, 2);
  assert.equal(r.footer, "prompt 5 · 80% cached · completion 3 · 0.7 tok/s · 3.0s");
  const inbox = store.blocks.find((b) => b.kind === "inbox");
  assert.equal(inbox.resolved.answer, "a");
  assert.equal(store.blocks.find((b) => b.kind === "child_settled").inline, true);
  const matched = store.blocks.find((b) => b.kind === "line" && /matching/.test(b.text));
  assert.equal(matched.text, "job j1 wrote 1 line matching /CRASH/");
  assert.deepEqual(matched.blob, BLOB, "the stored part of the output opens from the line");
  assert.equal(C.recordActivity(rec("job_matched", { job_id: "j1", pattern: "CRASH", matches: 1 })), "Job j1 wrote a line matching /CRASH/");
  assert.equal(store.ended, true);
  assert.equal(store.next, 27, "the unknown kind still advances the sequence");
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

test("the ledger model carries a notice for what the read could not show", () => {
  assert.deepEqual(C.ledgerModel({ state: { entries: 1 } }).notices, []);
  const m = C.ledgerModel({
    state: { entries: 0 }, skipped: 2, skipped_detail: "entry 4: op `x`", torn_tail: true, ahead_of_head: 1,
  });
  assert.equal(m.notices.length, 3);
  assert.match(m.notices[0], /^2 ledger entries written by a newer loom are not shown \(first: entry 4: op `x`\)/);
  assert.match(m.notices[1], /interrupted write/);
  assert.match(m.notices[2], /^1 ledger entry is not vouched for/);
});

test("operator rule requests build their routes and refuse blank input", () => {
  assert.deepEqual(C.ruleRequest("s-1", "  no prod "), { path: "/api/sessions/s-1/rules", body: { text: "no prod" } });
  assert.ok(C.ruleRequest("s-1", "   ").error);
  assert.deepEqual(C.approvalRequest("s/1", "ship", " staging "), { path: "/api/sessions/s%2F1/approvals", body: { text: "ship", scope: "staging" } });
  assert.equal(C.approvalRequest("s-1", "ship").body.scope, "");
  assert.ok(C.approvalRequest("s-1", "").error);
  assert.deepEqual(C.withdrawRequest("s-1", "k1", " done "), { path: "/api/sessions/s-1/rules/k1/withdraw", body: { reason: "done" } });
  assert.deepEqual(C.withdrawRequest("s-1", "k 1", "").body, { reason: "" }, "no reason typed: the daemon records a stock one");
  assert.equal(C.withdrawRequest("s-1", "k 1", "").path, "/api/sessions/s-1/rules/k%201/withdraw");
  assert.ok(C.withdrawRequest("s-1", "", "x").error);
});

test("the rules control lists the rules in force and marks used approvals", () => {
  const m = C.ledgerModel({
    state: {
      entries: 5,
      constraints: [{ id: "k1", text: "old rule", retired: "lifted" }, { id: "k2", text: "no prod", retired: null }],
      approvals: [{ id: "a1", text: "ok to push", scope: "git push", used_for: "pushed v2" }, { id: "a2", text: "deploy", scope: "staging", used_for: null }],
    },
  });
  assert.deepEqual(m.approvals[1], { id: "a2", text: "deploy", scope: "staging", usedFor: null });
  assert.deepEqual(C.ruleLists(m), {
    rules: [{ id: "k2", text: "no prod" }],
    asking: null,
    approvals: [
      { id: "a1", text: "ok to push", used: true, note: "used for: pushed v2" },
      { id: "a2", text: "deploy", used: false, note: "scope: staging" },
    ],
  });
  // No ledger (the request failed, or the mission keeps none): nothing to list, the inputs remain.
  assert.deepEqual(C.ruleLists(null), { rules: [], asking: null, approvals: [] });
  assert.deepEqual(C.ruleLists(C.ledgerModel({ state: { entries: 0 } })), { rules: [], asking: null, approvals: [] });
  // The withdrawal being confirmed stays open across redraws only while its rule is in force.
  assert.equal(C.ruleLists(m, "k2").asking, "k2");
  assert.equal(C.ruleLists(m, "k1").asking, null, "k1 is already retired");
  assert.equal(C.ruleLists(m, "k9").asking, null);
  assert.equal(C.ruleLists(null, "k2").asking, null);
});

test("the rules control says when a request is only queued or will never be listed", () => {
  // An idle lead of a mission with a ledger: the lists show it, nothing more to say.
  assert.equal(C.ruleNotice({ lead: "s-1", queued: false, ledger: true, stock: null }), "");
  const queued = C.ruleNotice({ lead: "s-1", queued: true, ledger: true, stock: null });
  assert.match(queued, /^Sent, not recorded yet: the lead was in a turn/);
  assert.match(queued, /no need to send it again\.$/);
  const noLedger = C.ruleNotice({ lead: "s-1", queued: false, ledger: false, stock: null });
  assert.match(noLedger, /^This mission keeps no ledger: .* nothing is listed here\.$/);
  const both = C.ruleNotice({ lead: "s-1", queued: true, ledger: false, stock: null });
  assert.ok(both.startsWith("Sent, not recorded yet") && both.endsWith(noLedger) && !both.includes("shows here"));
  assert.equal(C.ruleNotice(null), "");

  assert.match(C.rulesHint("No ledger: this mission's lead does not keep one."), /^Nothing is listed while this mission has no ledger\./);
  assert.equal(C.rulesHint(null), "");
  assert.equal(C.rulesHint("There is no mission m-1."), "");
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
  assert.deepEqual(fx({ type: "session", info: { id: "s-1", archived: false } }), ["session"], "a plain session event only updates the list");
  // the open session's ledger is loaded once its session is known, and only while none is held or loading
  const open = (ctxOver) => C.planEvent({ type: "session", info: { id: "s-1", mission: "m-5", archived: false } }, { ...ctx, ...ctxOver }).map((e) => e.fx);
  assert.deepEqual(open({}), ["session", "load_ledger"]);
  assert.deepEqual(open({ ledgerMission: "m-5" }), ["session"]);
  assert.deepEqual(open({ ledgerPending: true }), ["session"]);
  assert.deepEqual(C.planEvent({ type: "session", info: { id: "s-2", mission: "m-5" } }, ctx).map((e) => e.fx), ["session"], "another session");
  assert.deepEqual(C.planEvent({ type: "session", info: { id: "s-1", mission: "m-5" } }, ctx).find((e) => e.fx === "load_ledger"), { fx: "load_ledger", mission: "m-5" });
  assert.deepEqual(fx({ type: "session", info: { id: "s-1", archived: true, status: { open_inbox: 1 } } }), ["session", "refetch_inbox"], "an archived session clears its inbox items");
  assert.deepEqual(fx({ type: "session", info: { id: "s-1", archived: false, status: { open_inbox: 2 } } }), ["session", "refetch_inbox"], "a session that reports open inbox items pulls them");
  assert.deepEqual(fx({ type: "lagged", missed: 5 }), ["refetch_sessions", "refetch_inbox", "refetch_status", "refetch_ledger", "refetch_records"], "a lag re-reads the ledger and the status too");
  assert.deepEqual(C.planEvent({ type: "lagged", missed: 5 }, { ...ctx, openId: null, ledgerMission: null }).map((e) => e.fx), ["refetch_sessions", "refetch_inbox", "refetch_status"]);
  assert.deepEqual(C.planEvent({ type: "lagged", missed: 5 }, ctx).find((e) => e.fx === "refetch_ledger"), { fx: "refetch_ledger", mission: "m-1" });
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
  // The agents' model goes with a lead, as the choice for every role; a chat lead starts no agents.
  assert.deepEqual(C.buildNewSession({ workspace: "/w", message: "x", role: "lead", agentModel: "fast" }).body.role_models, { "*": "fast" });
  assert.equal(C.buildNewSession({ workspace: "/w", message: "x", role: "chat", agentModel: "fast" }).body.role_models, undefined);
  assert.equal(C.buildNewSession({ workspace: "/w", message: "x", role: "lead", agentModel: "" }).body.role_models, undefined);
});

test("models tab words and requests", () => {
  const role = (over) => ({ role: "worker", verifier: false, chosen: null, pack_model: null, alloy_models: [], escalation_model: null, agents: [], ...over });
  assert.equal(C.packChoiceWords(role({})), "the lead's");
  assert.equal(C.packChoiceWords(role({ pack_model: "big" })), "big");
  assert.equal(C.packChoiceWords(role({ pack_model: "big", alloy_models: ["a", "b"] })), "rotates a, b", "rotation wins over the role's model");
  assert.equal(C.packChoiceWords(role({ escalation_model: "huge" })), "the lead's, huge after a failed agent");
  // The every-role choice covers a role without its own, not the finish gate's verifier.
  assert.equal(C.roleDefaultLabel(role({}), "fast"), "Every role's choice (fast)");
  assert.equal(C.roleDefaultLabel(role({ verifier: true, pack_model: "big" }), "fast"), "As the pack says (big)");
  assert.equal(C.roleDefaultLabel(role({}), null), "As the pack says (the lead's)");
  assert.deepEqual(C.roleModelBody("worker", "fast", true), { role: "worker", profile: "fast", now: true });
  assert.deepEqual(C.roleModelBody("*", "", true), { role: "*", profile: null, now: false }, "clearing moves nobody");
  assert.equal(C.runningAgentsWords([]), "No agent of this role is running.");
  assert.equal(
    C.runningAgentsWords([{ session: "s-a", profile: "fast", forked: false }, { session: "s-b", profile: "big", forked: true }]),
    "Running: s-a on fast, s-b on big (forked)",
  );
});

test("error sentence", () => {
  assert.equal(C.errorSentence(409, '{"error":"Stop the session before archiving it."}'), "Stop the session before archiving it.");
  assert.equal(C.errorSentence(500, ""), "The request failed (500).");
  assert.equal(C.errorSentence(502, "bad gateway"), "bad gateway");
});

test("the login code is read from the fragment only when it is a whole hex code", () => {
  const code = "0123456789abcdef0123456789abcdef";
  assert.equal(C.codeFromHash("#code=" + code), code);
  for (const h of ["", "#", "#/s/s-1", "#code=", "#code=xyz", "#code=" + code + "&x=1", "#x=1&code=" + code, "code=" + code, "#code=ABCDEF0123456789ABCDEF", "#code=" + "a".repeat(129), null, undefined])
    assert.equal(C.codeFromHash(h), null, String(h));
});

test("reconnect delays double from one second up to fifteen", () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 50].map(C.reconnectDelayMs), [1000, 2000, 4000, 8000, 15000, 15000, 15000]);
  assert.equal(C.reconnectDelayMs(-3), 1000);
  assert.equal(C.reconnectDelayMs(NaN), 1000);
});

test("SSE parser: events, comments, CRLF and CR, multi-line data, ids, and splits anywhere", () => {
  const feedAll = (chunks) => {
    const p = C.createSseParser();
    return chunks.flatMap((c) => p.feed(c));
  };
  const text = ': keep-alive\n\ndata: {"a":1}\n\nid: 7\ndata: one\ndata:two\ndata\n\nevent: x\ndata: after\r\n\r\ndata: cr\r\rdata:last\n\n';
  const want = [
    { data: '{"a":1}', id: null },
    { data: "one\ntwo\n", id: "7" },
    { data: "after", id: "7" },
    { data: "cr", id: "7" },
    { data: "last", id: "7" },
  ];
  assert.deepEqual(feedAll([text]), want);
  // Cut at every position, including between CR and LF.
  for (let i = 0; i <= text.length; i++) assert.deepEqual(feedAll([text.slice(0, i), text.slice(i)]), want, "cut at " + i);
  // One character at a time.
  assert.deepEqual(feedAll([...text]), want);
  // An unfinished event is held back; a comment alone and an event without data deliver nothing.
  assert.deepEqual(feedAll(["data: half"]), []);
  assert.deepEqual(feedAll([": c\n\n", "id: 3\n\n", "event: e\n\n"]), []);
  // A colon inside the value and a missing space are kept as written.
  assert.deepEqual(feedAll(["data:a: b\n\n", "data:  two spaces\n\n"]), [{ data: "a: b", id: null }, { data: " two spaces", id: null }]);
});

test("SSE parser: a long line arriving in small chunks costs its length once", () => {
  // 8 MB in 1 KB chunks. Searching the whole unfinished line again on every chunk is ten seconds
  // of work or more; searching only what arrived is some tens of milliseconds.
  const body = "x".repeat(8 << 20);
  const text = "data: " + body + "\r\n\r\ndata: next\n\n";
  const p = C.createSseParser();
  const out = [];
  const began = performance.now();
  for (let i = 0; i < text.length; i += 1024) out.push(...p.feed(text.slice(i, i + 1024)));
  const took = performance.now() - began;
  assert.equal(out.length, 2);
  assert.ok(out[0].data === body, "the long line arrives whole");
  assert.deepEqual(out[1], { data: "next", id: null });
  assert.ok(took < 2000, `took ${Math.round(took)} ms`);
});

test("events are handed on one by one: bad JSON is skipped and a handler that throws is reported, not fatal", () => {
  const events = [{ data: '{"n":1}' }, { data: "not json" }, { data: '{"n":2}' }, { data: "" }, { data: '{"n":3}' }];
  const handled = [];
  const reported = [];
  C.deliverEvents(events, (ev) => {
    if (ev.n === 2) throw new Error("cannot show 2");
    handled.push(ev.n);
  }, (e) => reported.push(e.message));
  assert.deepEqual(handled, [1, 3]);
  assert.deepEqual(reported, ["cannot show 2"]);
  C.deliverEvents([], () => assert.fail("nothing to hand on"), () => assert.fail("nothing to report"));
});

// ---- app.js where it runs without a real page: a tab that is not signed in ----

/** Load a fresh copy of app.js at `hash` against a daemon that refuses every login code. */
async function loadSignedOutPage(t, hash) {
  const page = { shown: [], hashchange: [], reloads: 0, requests: [], replaced: [] };
  const fake = {
    document: {
      createElement: (tag) => ({ tag }),
      body: { replaceChildren: (...kids) => (page.shown = kids.map((k) => k.textContent)) },
    },
    window: { addEventListener: (type, fn) => type === "hashchange" && page.hashchange.push(fn) },
    location: { hash, pathname: "/", search: "", reload: () => page.reloads++ },
    history: { replaceState: (_state, _title, url) => page.replaced.push(url) },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    fetch: async (url, init) => {
      page.requests.push({ url, ...init });
      return { ok: false, status: 401 };
    },
  };
  for (const [name, value] of Object.entries(fake)) {
    const before = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
    t.after(() => (before ? Object.defineProperty(globalThis, name, before) : delete globalThis[name]));
  }
  await import("./app.js?page=" + encodeURIComponent(t.name + hash));
  await new Promise((resolve) => setImmediate(resolve));
  return page;
}

test("app.js: with no code and no stored secret the page says to run loom open, and a login address arriving in that tab loads it again", async (t) => {
  const page = await loadSignedOutPage(t, "");
  assert.deepEqual(page.requests, []);
  assert.deepEqual(page.shown, [C.LOST_TOKEN]);
  // Pasting an address into the tab changes only the fragment; the page is not loaded by the browser.
  const arrive = (hash) => {
    globalThis.location.hash = hash;
    for (const fn of page.hashchange) fn();
  };
  arrive("#/inbox");
  arrive("#code=xyz");
  assert.equal(page.reloads, 0);
  arrive("#code=0123456789abcdef0123456789abcdef");
  assert.equal(page.reloads, 1);
});

test("app.js: a code the daemon refuses is sent once without credentials, leaves the address, and the page says to run loom open", async (t) => {
  const code = "0123456789abcdef0123456789abcdef";
  const page = await loadSignedOutPage(t, "#code=" + code);
  assert.deepEqual(page.requests, [
    { url: "/api/web-sessions", method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) },
  ]);
  assert.deepEqual(page.replaced, ["/"]);
  assert.deepEqual(page.shown, [C.LOST_TOKEN]);
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
  // the names the core code picks at run time and app.js clones through icon(variable)
  const mk = (phase, extra = {}) => infoOf("s", { status: { phase, step: 1, ...extra } });
  for (const [i, attention, opts] of [[mk("idle"), { blocking: 1 }], [mk("running"), {}], [mk("idle", { last_end: "waiting" }), {}], [mk("idle"), {}, { fresh: true }], [mk("ended", { outcome: "failed" }), {}], [mk("ended", { outcome: "stopped" }), {}], [mk("idle"), {}], [mk("ended", { outcome: "done" }), {}]]) named.add(C.rowMark(i, attention, opts).icon);
  for (const block of [{ name: "agent_spawn" }, { name: "edit_file" }, { cls: "exec" }, { cls: "read" }, { cls: "write" }, { cls: "nav" }, { cls: "state" }, { cls: "terminal" }, {}]) named.add(C.toolIcon(block));
  for (const block of [{ state: "running" }, { state: "missing" }, { state: "done", result: { status: "ok" } }, { state: "done", result: { status: "error" } }]) named.add(C.toolRow(block).capsule.icon);
  for (const [status, attention] of [[{ phase: "idle", last_end: "yielded" }, { questions: 1 }], [{ phase: "idle", last_end: "yielded" }, { results: 1 }], [{ phase: "ended", outcome: "stopped" }, {}], [{ phase: "idle", last_end: "waiting" }, {}]]) named.add(C.runWords(infoOf("s", { status }), { attention }).icon);
  named.add(C.identityChips(info("s", {}), { models: [{ profile: info("s").profile, reachable: false }] }).model.warn?.icon || "alert");
  for (const reason of [{ blocking: { count: 1 } }, { blocking: { count: 0 }, questions: { count: 1 } }, { blocking: { count: 0 }, results: { count: 1 } }]) named.add(C.waitingReason(reason, 1).icon);
  named.add("alert");
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

// ---- scope requests, park choices, granted hosts ----

const scopeItem = (over = {}) => ({ item_id: "i-9", item_kind: "approval", text: "Needs docs.example.test for the API reference.", options: ["docs.example.test", "*.cdn.test"], blocking: false, ...over });

test("a scope request is a non-blocking approval whose options are the hosts", () => {
  assert.deepEqual(C.scopeRequestHosts(scopeItem()), ["docs.example.test", "*.cdn.test"]);
  assert.equal(C.inboxCardKind(scopeItem()), "scope request");
  // an approval that blocks, or names no hosts, or another kind, is not one
  assert.equal(C.scopeRequestHosts(scopeItem({ blocking: true })), null);
  assert.equal(C.scopeRequestHosts(scopeItem({ options: [] })), null);
  assert.equal(C.scopeRequestHosts(scopeItem({ item_kind: "question" })), null);
  assert.equal(C.inboxCardKind(scopeItem({ blocking: true })), "approval");
});

test("approving hosts builds the /scope request, refusing an empty list", () => {
  assert.deepEqual(C.scopeRequest("s-1", [" a.test ", "*.b.test"], "approved from the inbox"), {
    path: "/api/sessions/s-1/scope",
    body: { hosts: ["a.test", "*.b.test"], note: "approved from the inbox" },
  });
  assert.deepEqual(C.scopeRequest("s/1", ["a.test"]).body, { hosts: ["a.test"] });
  assert.equal(C.scopeRequest("s/1", ["a.test"]).path, "/api/sessions/s%2F1/scope");
  assert.deepEqual(C.scopeRequest("s-1", [" ", ""]), { error: "Name the hosts to grant." });
});

test("a blocking blocker or park offers its choices, cheapest first, and closing needs a reason", () => {
  const labels = (item) => C.parkChoices(item).map((c) => c.label);
  const blocker = { item_id: "i-1", item_kind: "blocker", text: "Stuck.", options: [], blocking: true };
  assert.deepEqual(labels(blocker), ["Keep working", "Provide what's missing", "Accept as blocked and close"]);
  const budget = { item_id: "i-2", item_kind: "parked", text: "The session could not continue. The session's budget is used up.", options: [], blocking: true };
  assert.deepEqual(labels(budget), ["Keep working", "Keep working (more budget)", "Accept as blocked and close"]);
  const other = { item_id: "i-3", item_kind: "parked", text: "The model server did not answer.", options: [], blocking: true };
  assert.deepEqual(labels(other), ["Keep working", "Accept as blocked and close"]);
  const [keep] = C.parkChoices(blocker);
  assert.deepEqual([keep.action, keep.answer], ["answer", "Keep working on the goal."]);
  assert.equal(C.parkChoices(blocker)[1].action, "provide");
  assert.equal(C.parkChoices(blocker).at(-1).action, "release");
  // labels the item carries do not change the choices or what is sent
  const given = { ...blocker, options: ["Whatever", "Do it"] };
  assert.deepEqual(labels(given), labels(blocker));
  assert.equal(C.parkChoices(given)[0].answer, "Keep working on the goal.");
  const named = { ...other, options: ["Keep working (more budget)"] };
  assert.deepEqual(labels(named), ["Keep working", "Keep working (more budget)", "Accept as blocked and close"]);
  // other items have none
  assert.equal(C.parkChoices({ ...blocker, blocking: false }), null);
  assert.equal(C.parkChoices({ ...blocker, item_kind: "question" }), null);
  assert.equal(C.parkChoices({ ...blocker, item_kind: "finished" }), null);
  assert.match(C.PARK_HELP, /next step/);

  assert.deepEqual(C.releaseRequest("s-1", "  target is gone "), { path: "/api/sessions/s-1/release", body: { reason: "target is gone" } });
  assert.deepEqual(C.releaseRequest("s-1", "   "), { error: "Write why the mission is closed without the goal established." });
  assert.deepEqual(C.releaseRequest("s-1"), { error: "Write why the mission is closed without the goal established." });
});

test("granted hosts and the outcome come from the ledger state", () => {
  const grants = [{ id: "s1", hosts: ["a.test", "B.test"] }, { id: "s2", hosts: ["b.TEST", "c.test"] }];
  assert.deepEqual(C.grantedHosts(grants), ["a.test", "B.test", "c.test"]);
  assert.deepEqual(C.grantedHosts(undefined), []);
  const model = C.ledgerModel({ state: { entries: 3, scope_grants: grants, goal_met: null, release: null } });
  assert.deepEqual(model.scope, ["a.test", "B.test", "c.test"]);
  assert.equal(model.outcome, null);
  assert.equal(C.scopeLine(model), "Hosts granted by the operator: a.test, B.test, c.test");
  assert.equal(C.scopeLine({ scope: [] }), "No hosts granted by the operator.");
  assert.equal(C.scopeLine(null), "No hosts granted by the operator.");
  // a release reads as closed by the operator, never as finished
  const released = C.ledgerModel({ state: { entries: 4, release: { reason: "target gone", n: 4 }, goal_met: { status: "supported", note: "x", evidence: [], n: 2 } } });
  assert.deepEqual(released.outcome, { words: "Closed by operator, goal not established", detail: "target gone" });
  assert.match(C.ledgerModel({ state: { entries: 1, goal_met: { status: "supported", note: "ran it", evidence: ["e1"], n: 1 } } }).outcome.words, /^Goal met/);
  assert.match(C.ledgerModel({ state: { entries: 1, goal_met: { status: "refuted", note: "n", evidence: ["e1"], n: 1 } } }).outcome.words, /unreachable/);
  assert.equal(C.outcomeOf({ goal_met: { status: "open", note: "", evidence: [], n: 0 } }), null);
});

// ---------------------------------------------------------------------------------------------
// Chat-first redesign

function storeOf(records) {
  const store = C.createRecordStore("s-a");
  C.applyRecords(store, records);
  return store;
}
// A small record builder with explicit seq/ts so timing is under the test's control.
let sq = 0;
const R = (kind, fields = {}, ts = 1000 + sq * 1000, author = "harness") => ({ seq: sq++, ts_ms: ts, author, prev: "0".repeat(64), kind, ...fields });
const MODEL_A = { profile: "dsv41", model: "deepseek-v4.1", context_window: 1048576 };
const MODEL_B = { profile: "qwen", model: "qwen4-max-preview", context_window: 262144 };
const start = (m = MODEL_A) => R("session_start", { session: "s-a", mission: "m-a", parent: null, workspace: "/w", pack: "core", role: "lead", model: m, tools: [], budget: {} });
const reply = (id, text, extra = {}) => R("model_response", { req_id: id, text, reasoning: "", tool_calls: [], finish: "stop", usage: { prompt_tokens: 100, cached_tokens: 50, completion_tokens: 10 }, timing: { ttft_ms: 100, total_ms: 1100 }, attempts: 1, ...extra }, undefined, "model");
const call = (id, name = "bash", cls = "exec") => R("tool_call", { call_id: id, req_id: "r", name, args: { command: "ls" }, class: cls }, undefined, "model");
const result = (id, status = "ok", extra = {}) => R("tool_result", { call_id: id, name: "bash", status, text: "x", class: "exec", meta: {}, duration_ms: 500, ...extra }, undefined, "tool");
const reset = () => { sq = 0; };

test("formatWindow names a context window", () => {
  assert.equal(C.formatWindow(1048576), "1M");
  assert.equal(C.formatWindow(1000000), "1M");
  assert.equal(C.formatWindow(2000000), "2M");
  assert.equal(C.formatWindow(1500000), "1.5M");
  assert.equal(C.formatWindow(262144), "262k");
  assert.equal(C.formatWindow(128000), "128k");
  assert.equal(C.formatWindow(800), "800");
  for (const v of [0, null, undefined, NaN, -5, "x"]) assert.equal(C.formatWindow(v), "");
});

test("the store keeps the start model and follows model_switched", () => {
  reset();
  const store = storeOf([
    start(), R("user_message", { text: "hi" }, undefined, "user"), reply("r1", "one"),
    R("model_switched", { from: MODEL_A, to: MODEL_B, reason: "operator" }), reply("r2", "two"),
  ]);
  assert.equal(store.start.model.profile, "dsv41");
  assert.deepEqual(store.models.map((m) => m.profile), ["dsv41", "qwen"]);
  assert.equal(C.modelAt(store, 0).profile, "dsv41");
  assert.equal(C.modelAt(store, 2).profile, "dsv41");
  assert.equal(C.modelAt(store, 3).profile, "qwen"); // the switch record itself is already on the new model
  assert.equal(C.modelAt(store, 4).profile, "qwen");
  assert.equal(C.modelAt(createEmpty(), 3), null);
  // live info wins over the record store; the store answers when info has no profile
  assert.deepEqual(C.currentModel(store, { profile: "necromicon", model: "n", context_window: 8000 }), { profile: "necromicon", model: "n", context_window: 8000 });
  assert.deepEqual(C.currentModel(store, {}), { profile: "qwen", model: "qwen4-max-preview", context_window: 262144 });
  assert.equal(C.currentModel(createEmpty(), {}), null);
  // the switch block carries both sides
  const sw = store.blocks.find((b) => b.switch);
  assert.equal(sw.kind, "line");
  assert.equal(sw.switch.from.profile, "dsv41");
  assert.equal(sw.switch.to.model, "qwen4-max-preview");
  assert.equal(sw.switch.reason, "operator");
});
function createEmpty() { return C.createRecordStore("x"); }

test("the store tracks the running turn and the tool result time", () => {
  reset();
  const store = storeOf([start(), R("turn_start", { trigger: "user" }, 5000), call("c1")]);
  assert.deepEqual(store.turn, { seq: 1, ts: 5000 });
  C.applyRecord(store, result("c1"));
  assert.equal(store.blocks[0].result.ts, store.records.get(3).ts_ms);
  C.applyRecord(store, R("turn_end", { reason: "finished" }));
  assert.equal(store.turn, null);
  C.applyRecord(store, R("turn_start", {}, 9000));
  assert.equal(store.turn.ts, 9000);
  C.applyRecord(store, R("session_end", { outcome: "done" }));
  assert.equal(store.turn, null);
  C.applyRecord(store, R("turn_start", {}, 9500));
  C.applyRecord(store, R("interrupted", { reason: "r" }));
  assert.equal(store.turn, null);
});

const kinds = (items) => items.map((i) => (i.type === "block" ? i.block.kind : i.type));

test("chatItems groups consecutive tool calls and text-less replies, with the model chip first", () => {
  reset();
  const store = storeOf([
    start(), R("user_message", { text: "go" }, undefined, "user"),
    reply("r1", "", { reasoning: "a\nb", tool_calls: [{ call_id: "c1", name: "bash", arguments: "{}", complete: true }] }),
    call("c1"), result("c1"),
    reply("r2", "", { tool_calls: [{ call_id: "c2", name: "bash", arguments: "{}", complete: true }] }),
    call("c2"), result("c2", "error"),
    R("ledger", { n: 1, summary: "s" }),
    reply("r3", "all done"),
  ]);
  const items = C.chatItems(store.blocks, { models: store.models });
  assert.deepEqual(kinds(items), ["user", "model", "group", "response"]);
  assert.deepEqual([items[1].profile, items[1].model, items[1].reason], ["dsv41", "deepseek-v4.1", "start"]);
  const g = items[2];
  assert.equal(g.toolCount, 2);
  assert.equal(g.failed, 1);
  assert.equal(g.running, false);
  assert.equal(g.blocks.length, 5); // two text-less replies, two tools, the ledger line
  assert.equal(g.key, "g" + g.blocks[0].seq);
  assert.equal(g.open, false); // not last, nothing running, not expanded
  assert.equal(items[3].last, true);
  assert.equal(items[3].model.profile, "dsv41");
  assert.equal(items[3].differs, false);
  // the first text-less reply keeps its reasoning for a Thought row
  assert.equal(C.thoughtLabel(g.blocks[0]), "Thought · 2 lines");
  assert.equal(C.thoughtLabel(g.blocks[2]), "");
});

test("a running group is open, and so is the last item; expandAll and the open set open the rest", () => {
  reset();
  const store = storeOf([start(), R("user_message", { text: "go" }, undefined, "user"), call("c1"), result("c1"), reply("r", "mid"), call("c2")]);
  const items = C.chatItems(store.blocks, { models: store.models });
  const groups = items.filter((i) => i.type === "group");
  assert.equal(groups.length, 2);
  assert.equal(groups[0].open, false);
  assert.equal(groups[1].running, true);
  assert.equal(groups[1].open, true);
  assert.equal(groups[1].last, true);
  assert.equal(C.chatItems(store.blocks, { models: store.models, expandAll: true }).filter((i) => i.type === "group").every((g) => g.open), true);
  assert.equal(C.chatItems(store.blocks, { models: store.models, open: new Set([groups[0].key]) }).filter((i) => i.type === "group")[0].open, true);
  // a finished last group is open only because it is last
  C.applyRecord(store, result("c2"));
  assert.equal(C.chatItems(store.blocks, { models: store.models }).filter((i) => i.type === "group")[1].open, true);
  C.applyRecord(store, reply("r9", "done"));
  assert.equal(C.chatItems(store.blocks, { models: store.models }).filter((i) => i.type === "group")[1].open, false);
});

test("group keys stay put when the chat grows", () => {
  reset();
  const store = storeOf([start(), call("c1"), result("c1")]);
  const key = C.chatItems(store.blocks, { models: store.models }).find((i) => i.type === "group").key;
  C.applyRecord(store, call("c2"));
  C.applyRecord(store, result("c2"));
  C.applyRecord(store, reply("r", "text"));
  const after = C.chatItems(store.blocks, { models: store.models });
  assert.equal(after.find((i) => i.type === "group").key, key);
  assert.equal(after.find((i) => i.type === "group").toolCount, 2);
});

test("a group counts a call with no result and one whose result was never recorded", () => {
  reset();
  const store = storeOf([start(), call("c1"), R("turn_end", { reason: "stopped" })]);
  const items = C.chatItems(store.blocks, { models: store.models });
  const g = items.find((i) => i.type === "group");
  assert.equal(g.running, false);
  assert.equal(g.missing, 1);
  assert.equal(g.failed, 0);
  assert.match(C.groupLabel(g, 0).text, /1 tool call · 1 without a result$/);
  assert.equal(kinds(items).at(-1), "divider");
});

test("a model switch ends the group, is shown as a line, and starts a new chip", () => {
  reset();
  const store = storeOf([
    start(), R("user_message", { text: "go" }, undefined, "user"), call("c1"), result("c1"),
    R("model_switched", { from: MODEL_A, to: MODEL_B, reason: "operator" }),
    call("c2"), result("c2"), reply("r", "answer"),
  ]);
  const items = C.chatItems(store.blocks, { models: store.models });
  assert.deepEqual(kinds(items), ["user", "model", "group", "line", "model", "group", "response"]);
  assert.equal(items[1].profile, "dsv41");
  assert.equal(items[3].block.switch.to.profile, "qwen");
  assert.deepEqual([items[4].profile, items[4].reason], ["qwen", "switch"]);
  assert.equal(items[6].model.profile, "qwen");
  assert.equal(items[6].differs, false);
  // without model data there are no chips
  assert.equal(C.chatItems(store.blocks).some((i) => i.type === "model"), false);
});

test("every boundary starts a new chip; a reply in the same segment does not", () => {
  reset();
  const store = storeOf([
    start(), reply("r0", "first"), reply("r1", "second"),
    R("child_spawned", { child: "s-b", role: "worker", mode: "fork", brief: {}, budget: {} }),
    reply("r2", "third"), R("turn_end", { reason: "yielded" }), reply("r3", "fourth"),
    R("user_message", { text: "u" }, undefined, "user"), reply("r4", "fifth"),
  ]);
  const items = C.chatItems(store.blocks, { models: store.models });
  assert.deepEqual(kinds(items), [
    "model", "response", "response", "child_spawned", "model", "response", "divider", "model", "response", "user", "model", "response",
  ]);
});

test("request detail lines are hidden unless asked for; they never split a group or change its key", () => {
  reset();
  const request = (n) => R("model_request", { req_id: "r" + n, step: n, epoch: 0, purpose: "step", est_tokens: 5 });
  const store = storeOf([
    start(), R("user_message", { text: "go" }, undefined, "user"),
    request(1), reply("r1", "", { tool_calls: [{ call_id: "c1", name: "bash", arguments: "{}", complete: true }] }), call("c1"), result("c1"),
    request(2), reply("r2", "", { tool_calls: [{ call_id: "c2", name: "bash", arguments: "{}", complete: true }] }), call("c2"), result("c2"),
    request(3), reply("r3", "done"),
  ]);
  const hidden = C.chatItems(store.blocks, { models: store.models });
  const shown = C.chatItems(store.blocks, { models: store.models, details: true });
  const groups = (items) => items.filter((i) => i.type === "group");
  assert.equal(groups(hidden).length, 1);
  assert.equal(groups(shown).length, 1, "request lines do not make a second group");
  assert.deepEqual(groups(shown).map((g) => g.key), groups(hidden).map((g) => g.key), "the group key is the same with details on and off");
  // counts and the record count are unchanged; a request inside the run is a member that shows when the group is open
  assert.equal(groups(shown)[0].toolCount, groups(hidden)[0].toolCount);
  assert.equal(groups(shown)[0].records, groups(hidden)[0].records);
  assert.ok(groups(shown)[0].blocks.length > groups(hidden)[0].blocks.length);
  assert.ok(groups(shown)[0].blocks.some((b) => b.sub === "request"));
  // a request in front of the run, and one in front of the reply, stand alone as detail lines
  const lead = shown.filter((i) => i.type === "block" && i.block.sub === "request");
  assert.equal(lead.length, 2);
  assert.equal(hidden.some((i) => i.type === "block" && i.block.sub === "request"), false);
  // the last group stays open when a request line trails it
  reset();
  const tail = storeOf([start(), call("c1"), result("c1"), request(9)]);
  assert.equal(C.chatItems(tail.blocks, { models: tail.models, details: true }).find((i) => i.type === "group").open, true);
});

test("a group that has only request details and ledger lines counts its records without the details", () => {
  reset();
  const store = storeOf([start(), R("ledger", { n: 1, summary: "s" }), R("model_request", { req_id: "r", step: 1, epoch: 0, purpose: "step", est_tokens: 5 }), R("ledger", { n: 2, summary: "t" })]);
  const g = C.chatItems(store.blocks, { models: store.models, details: true }).find((i) => i.type === "group");
  assert.equal(g.records, 2);
});

test("groupKeyForSeq finds the group holding a call, its result or a line", () => {
  reset();
  const store = storeOf([start(), R("user_message", { text: "go" }, undefined, "user"), call("c1"), result("c1"), reply("r", "t")]);
  const items = C.chatItems(store.blocks, { models: store.models });
  const key = items.find((i) => i.type === "group").key;
  assert.equal(C.groupKeyForSeq(items, 2), key);
  assert.equal(C.groupKeyForSeq(items, 3), key); // the result's seq
  assert.equal(C.groupKeyForSeq(items, 4), null); // the reply is not in a group
  assert.equal(C.groupKeyForSeq(items, 99), null);
  assert.equal(C.groupKeyForSeq(null, 1), null);
});

test("groupLabel: duration, counts, failures and running", () => {
  const base = { type: "group", toolCount: 4, failed: 0, missing: 0, running: false, startTs: 1000, endTs: 13000 };
  assert.equal(C.groupLabel(base, 0).text, "Worked for 12s · 4 tool calls");
  assert.equal(C.groupLabel({ ...base, toolCount: 1 }, 0).text, "Worked for 12s · 1 tool call");
  assert.equal(C.groupLabel({ ...base, failed: 2 }, 0).text, "Worked for 12s · 4 tool calls · 2 failed");
  const run = C.groupLabel({ ...base, running: true }, 31000);
  assert.equal(run.text, "Worked for 30s · 4 tool calls · running");
  assert.equal(run.running, true);
  assert.equal(C.groupLabel({ ...base, endTs: 1200 }, 0).duration, "under 1s");
});

test("tool rows: icon by class and name, capsule by state", () => {
  reset();
  const store = storeOf([
    start(), call("c1"), result("c1", "ok", { meta: { exit_code: 0 } }),
    call("c2"), result("c2", "error", { meta: { exit_code: 2 } }),
    call("c3"), call("c4", "read_file", "read"), result("c4"),
    R("turn_end", { reason: "stopped" }),
  ]);
  const rows = store.blocks.filter((b) => b.kind === "tool").map(C.toolRow);
  assert.deepEqual(rows[0].capsule, { text: "exit 0", tone: "ok", icon: "check" });
  assert.equal(rows[0].duration, "500ms");
  assert.equal(rows[0].icon, "tool-exec");
  assert.deepEqual(rows[1].capsule, { text: "exit 2", tone: "neutral", icon: "exit" }, "a non-zero exit is its own neutral shape, not the red cross");
  assert.equal(rows[1].outcome, "exit");
  assert.deepEqual(rows[2].capsule, { text: "no result", tone: "warn", icon: "alert" });
  assert.equal(rows[3].icon, "tool-read");
  assert.equal(rows[0].argsLine, "ls");
  const running = C.toolRow({ kind: "tool", name: "bash", cls: "exec", state: "running", argsLine: "make", result: null });
  assert.deepEqual(running.capsule, { text: "running", tone: "running", icon: "dot" });
  assert.equal(C.toolIcon({ name: "edit", cls: "write" }), "tool-write");
  assert.equal(C.toolIcon({ name: "grep", cls: "nav" }), "tool-nav");
  assert.equal(C.toolIcon({ name: "ledger_note", cls: "state" }), "tool-state");
  assert.equal(C.toolIcon({ name: "agent_spawn", cls: "state" }), "tool-agent");
  assert.equal(C.toolIcon({ name: "x" }), "tool-exec");
  assert.equal(C.toolRow({ kind: "tool", name: "x", state: "done", result: { status: "timeout", meta: {}, duration_ms: 0 } }).capsule.text, "timeout");
});

test("replyMeta is quiet and leads with the profile only when asked", () => {
  const r = { usage: { prompt_tokens: 100, cached_tokens: 92, completion_tokens: 11 }, timing: { ttft_ms: 100, total_ms: 1100 } };
  assert.equal(C.replyMeta(r), "10.0 tok/s · 1.1s · cache 92%");
  assert.equal(C.replyMeta(r, "qwen"), "qwen · 10.0 tok/s · 1.1s · cache 92%");
  assert.equal(C.replyMeta({ usage: {}, timing: {} }), "");
});

test("a reply whose model differs from the segment chip says so", () => {
  reset();
  // the chip is for the segment start; a switch record is missing from the window but the models list has it
  const blocks = [{ kind: "response", seq: 5, ts: 1, text: "t", reasoningLines: 0 }];
  const models = [{ seq: 0, profile: "a", model: "m1", context_window: 0 }, { seq: 3, profile: "b", model: "m2", context_window: 0 }];
  const items = C.chatItems([{ kind: "response", seq: 1, ts: 1, text: "x" }, ...blocks], { models });
  assert.deepEqual(kinds(items), ["model", "response", "response"]);
  assert.equal(items[1].differs, false);
  assert.equal(items[2].differs, true);
  assert.equal(items[2].model.profile, "b");
});

// ---- sidebar

function infoOf(id, extra = {}) {
  return { id, mission: extra.mission || id, parent: null, workspace: "/w/a", role: "lead", pack: "core", profile: "dsv41", model: "m", context_window: 1048576, title: id, created_ms: 1000, status: { phase: "idle", step: 1, last_end: "yielded", prompt_tokens: 0, cached_tokens: 0, open_inbox: 0 }, ...extra };
}
function sessionStore(list) { const s = C.createSessionStore(); C.applySessionList(s, list); return s; }
const blockingItem = (session, kind = "approval", opened = 1000) => ({ session, item: { item_id: session + kind, item_kind: kind, blocking: true }, opened_ms: opened });
function inboxWith(entries) {
  const inbox = C.createInbox();
  for (const e of entries) inbox.items.set(e.item.item_id, e);
  return inbox;
}

test("workspaceName is the last path component", () => {
  assert.equal(C.workspaceName("/Users/me/code/loom"), "loom");
  assert.equal(C.workspaceName("/Users/me/code/loom/"), "loom");
  assert.equal(C.workspaceName("/"), "no workspace");
  assert.equal(C.workspaceName(""), "no workspace");
  assert.equal(C.workspaceName(null), "no workspace");
});

test("rowMark precedence: needs you > running > new > failed > idle/ended, each with its own shape", () => {
  const run = (phase, extra = {}) => infoOf("s", { status: { phase, step: 1, ...extra } });
  const blocking = { blocking: 1 };
  assert.equal(C.rowMark(run("running"), blocking, { fresh: true }).mark, "needs_you");
  assert.equal(C.rowMark(run("running"), {}, { fresh: true }).mark, "running");
  assert.equal(C.rowMark(run("idle"), {}, { fresh: true }).mark, "new");
  assert.equal(C.rowMark(run("ended", { outcome: "failed" }), {}, { fresh: true }).mark, "new");
  assert.equal(C.rowMark(run("ended", { outcome: "failed" }), {}).mark, "failed");
  assert.equal(C.rowMark(run("ended", { outcome: "budget_exhausted" }), {}).mark, "failed");
  assert.equal(C.rowMark(run("ended", { outcome: "done" }), {}).mark, "ended");
  assert.equal(C.rowMark(run("ended", { outcome: "stopped" }), {}).mark, "stopped");
  assert.notEqual(C.rowMark(run("ended", { outcome: "stopped" }), {}).icon, C.rowMark(run("ended", { outcome: "done" }), {}).icon, "a stop is not drawn as a success");
  assert.equal(C.rowMark(run("idle", { last_end: "yielded" }), {}).mark, "idle");
  assert.equal(C.rowMark(run("idle", { last_end: "waiting" }), {}).mark, "waiting");
  // an ended session has nothing to answer
  assert.equal(C.rowMark(run("ended", { outcome: "done" }), blocking).mark, "ended");
  // the mission's aggregate can make a root run
  assert.equal(C.rowMark(run("idle"), {}, { running: true }).mark, "running");
  const shapes = ["needs_you", "running", "waiting", "new", "failed", "stopped", "idle", "ended"].map((m) => {
    const sample = { needs_you: [run("idle"), blocking], running: [run("running"), {}], waiting: [run("idle", { last_end: "waiting" }), {}], new: [run("idle"), {}, { fresh: true }], failed: [run("ended", { outcome: "failed" }), {}], stopped: [run("ended", { outcome: "stopped" }), {}], idle: [run("idle"), {}], ended: [run("ended", { outcome: "done" }), {}] }[m];
    const r = C.rowMark(...sample);
    assert.equal(r.mark, m);
    assert.ok(r.words);
    return r.icon;
  });
  assert.equal(new Set(shapes).size, shapes.length, "each state has its own icon");
});

test("workspaceGroups: groups by workspace, newest activity first, Needs you pinned on top", () => {
  const list = [
    infoOf("old", { workspace: "/w/alpha", created_ms: 1000 }),
    infoOf("mid", { workspace: "/w/beta", created_ms: 2000, profile: "qwen", role: "chat" }),
    infoOf("new", { workspace: "/w/alpha", created_ms: 3000 }),
    infoOf("ask", { workspace: "/w/gamma", created_ms: 500 }),
  ];
  const now = 400000;
  const groups = C.workspaceGroups(sessionStore(list), inboxWith([blockingItem("ask", "approval", 100000)]), {}, now);
  assert.deepEqual(groups.map((g) => g.key), ["needs_you", "ws:/w/alpha", "ws:/w/beta"]);
  assert.equal(groups[0].label, "Needs you");
  assert.deepEqual(groups[0].rows.map((r) => r.info.id), ["ask"]);
  assert.equal(groups[1].label, "alpha");
  assert.equal(groups[1].tip, "/w/alpha");
  assert.deepEqual(groups[1].rows.map((r) => r.info.id), ["new", "old"]);
  // the waiting reason replaces the age on the identity line
  const ask = groups[0].rows[0];
  assert.equal(ask.mark.mark, "needs_you");
  // the model and role stay on the line; the reason is its own line, so the profile is never cut off
  assert.equal(ask.identity.text, "dsv41 · lead");
  assert.deepEqual(ask.identity.parts.slice(0, 2), ["dsv41", "lead"]);
  assert.equal(ask.identity.waiting.text, "Approval waiting 5m");
  assert.equal(ask.identity.waiting.icon, "diamond");
  // no record has been loaded for the others: the age is unknown, never the time since creation
  assert.equal(groups[2].rows[0].identity.text, "qwen · chat · activity not loaded");
  assert.equal(groups[2].rows[0].identity.age, C.ACTIVITY_UNKNOWN);
  assert.equal(groups[2].rows[0].recordedMs, null);
  assert.equal(groups[2].rows[0].identity.waiting, null);
  // with a loaded record the age comes from the record
  const loaded = C.workspaceGroups(sessionStore(list), inboxWith([]), {}, now, { activity: new Map([["mid", { seq: 4, ts: now - 120000 }]]) });
  assert.equal(loaded.flatMap((g) => g.rows).find((r) => r.info.id === "mid").identity.text, "qwen · chat · 2m");
});

test("workspaceGroups: activity orders groups and rows; agents nest under their mission when expanded", () => {
  const list = [
    infoOf("m1", { workspace: "/w/a", created_ms: 1000 }),
    infoOf("m2", { workspace: "/w/b", created_ms: 2000 }),
    infoOf("w1", { workspace: "/w/a", parent: "m1", mission: "m1", role: "worker", created_ms: 1500, profile: "qwen", status: { phase: "running", step: 3 } }),
  ];
  const activity = new Map([["w1", { seq: 9, ts: 50000 }], ["m2", { seq: 2, ts: 20000 }]]);
  const store = sessionStore(list);
  const collapsed = C.workspaceGroups(store, C.createInbox(), {}, 60000, { activity });
  assert.deepEqual(collapsed.map((g) => g.label), ["a", "b"]); // a: agent activity at 50000 beats b at 20000
  assert.deepEqual(collapsed[0].rows.map((r) => r.info.id), ["m1"]);
  const root = collapsed[0].rows[0];
  assert.equal(root.agentCount, 1);
  assert.equal(root.agentsRunning, 1);
  assert.equal(root.mark.mark, "running"); // the mission runs while its agent runs
  assert.equal(root.expanded, false);
  const open = C.workspaceGroups(store, C.createInbox(), {}, 60000, { activity, expanded: new Set(["m1"]) });
  assert.deepEqual(open[0].rows.map((r) => [r.info.id, r.depth]), [["m1", 0], ["w1", 1]]);
  assert.equal(open[0].rows[1].identity.text, "qwen · worker · 10s");
  assert.equal(open[0].rows[0].identity.text, "dsv41 · lead · 10s"); // the root shows its newest recorded time (its agent's)
  // flipping the order of activity flips the groups
  const flipped = C.workspaceGroups(store, C.createInbox(), {}, 60000, { activity: new Map([["m2", { seq: 2, ts: 59000 }]]) });
  assert.deepEqual(flipped.map((g) => g.label), ["b", "a"]);
});

test("workspaceGroups: a blocking agent pulls its whole mission into Needs you; new needs a watermark", () => {
  const list = [
    infoOf("m1", { workspace: "/w/a" }),
    infoOf("w1", { workspace: "/w/a", parent: "m1", mission: "m1", role: "worker", created_ms: 1500 }),
    infoOf("m2", { workspace: "/w/b", created_ms: 900 }),
    infoOf("m3", { workspace: "/w/b", created_ms: 800 }),
  ];
  const activity = new Map([["m2", { seq: 7, ts: 5000 }], ["m3", { seq: 7, ts: 4000 }]]);
  const groups = C.workspaceGroups(sessionStore(list), inboxWith([blockingItem("w1")]), { m2: 3, m3: 7 }, 10000, { activity });
  assert.equal(groups[0].key, "needs_you");
  assert.equal(groups[0].rows[0].info.id, "m1");
  assert.equal(groups[0].rows[0].waiting.blocking.count, 1);
  const b = groups.find((g) => g.key === "ws:/w/b");
  assert.equal(b.rows.find((r) => r.info.id === "m2").mark.mark, "new"); // seq 7 is past the watermark 3
  assert.equal(b.rows.find((r) => r.info.id === "m3").mark.mark, "idle"); // seen up to 7
  // a Map works as well as an object, and a session never visited is not new
  const viaMap = C.workspaceGroups(sessionStore(list), C.createInbox(), new Map([["m2", 3]]), 10000, { activity });
  const rows = viaMap.flatMap((g) => g.rows);
  assert.equal(rows.find((r) => r.info.id === "m2").mark.mark, "new");
  assert.equal(rows.find((r) => r.info.id === "m3").mark.mark, "idle");
});

test("workspaceGroups: archived roots only when asked; no sessions, no groups", () => {
  const list = [infoOf("a", { archived: true }), infoOf("b")];
  const store = sessionStore(list);
  assert.deepEqual(C.workspaceGroups(store, C.createInbox(), {}, 1).flatMap((g) => g.rows.map((r) => r.info.id)), ["b"]);
  assert.deepEqual(C.workspaceGroups(store, C.createInbox(), {}, 1, { showArchived: true }).flatMap((g) => g.rows.map((r) => r.info.id)).sort(), ["a", "b"]);
  assert.deepEqual(C.workspaceGroups(sessionStore([]), C.createInbox(), {}, 1), []);
  assert.equal(C.workspaceGroups(sessionStore([infoOf("x", { workspace: "" })]), C.createInbox(), {}, 1)[0].label, "no workspace");
});

test("waitingReason words", () => {
  assert.equal(C.waitingReason({ blocking: { count: 0 } }, 1), null);
  assert.equal(C.waitingReason(null, 1), null);
  assert.equal(C.waitingReason({ blocking: { count: 1, kind: "question", since: 1000 } }, 1001).text, "Question just arrived");
  assert.equal(C.waitingReason({ blocking: { count: 1, kind: "blocker", since: 0 } }, 120000).text, "Blocker waiting 2m");
  assert.equal(C.waitingReason({ blocking: { count: 3, kind: "approval", since: 0 } }, 120000).text, "3 requests waiting");
});

// ---- identity bar

test("runWords: running with elapsed, idle, waiting for you, ended", () => {
  const mk = (status, extra = {}) => infoOf("s", { status, ...extra });
  const running = C.runWords(mk({ phase: "running", step: 214 }), { now: 100000, startMs: 38000 });
  assert.equal(running.text, "Running · step 214 · 1m02s");
  assert.equal(running.running, true);
  assert.equal(running.icon, "dot");
  assert.equal(C.runWords(mk({ phase: "running", step: 2 }), { now: 100000 }).text, "Running · step 2"); // start unknown
  assert.equal(C.runWords(mk({ phase: "running", step: 0 }), { now: 5000, startMs: 4000 }).text, "Running · 1s");
  assert.equal(C.runWords(mk({ phase: "idle", step: 7, last_end: "yielded" }), {}).text, "Idle · step 7");
  assert.equal(C.runWords(mk({ phase: "idle", step: 7, last_end: "waiting" }), {}).text, "Waiting for jobs or agents · step 7");
  assert.equal(C.runWords(mk({ phase: "idle", step: 7, last_end: "stopped" }), {}).text, "Stopped · step 7");
  const waiting = C.runWords(mk({ phase: "running", step: 7 }), { attention: { blocking: 1 } });
  assert.equal(waiting.text, "Waiting for you");
  assert.equal(waiting.running, false);
  assert.equal(waiting.icon, "diamond");
  assert.equal(C.runWords(mk({ phase: "ended", outcome: "done" }), {}).text, "Ended · done");
  assert.equal(C.runWords(mk({ phase: "ended", outcome: "failed" }), {}).text, "Ended · failed");
  assert.equal(C.runWords(mk({ phase: "ended", outcome: "budget_exhausted" }), {}).text, "Ended · budget exhausted");
  assert.equal(C.runWords(mk({ phase: "ended", outcome: "stopped" }), {}).text, "Ended · stopped");
  assert.equal(C.runWords(mk({ phase: "ended" }), {}).text, "Ended · done");
  assert.equal(C.runWords({ id: "x" }, {}).text, "Idle");
  // each run state has its own shape
  const icons = [running, waiting, C.runWords(mk({ phase: "idle", step: 1, last_end: "yielded" }), {}), C.runWords(mk({ phase: "ended", outcome: "failed" }), {})].map((r) => r.icon);
  assert.equal(new Set(icons).size, 4);
});

test("identityChips: model, role, id and run", () => {
  const info = infoOf("session-abcdef-0123", { profile: "qwen", model: "qwen4-max-preview", context_window: 1048576, pack: "core", role: "lead", status: { phase: "running", step: 4 } });
  const status = { models: [{ profile: "qwen", base_url: "http://x.test/v1", model: "qwen4-max-preview", reachable: true, detail: "", context_window: 1048576 }] };
  const chips = C.identityChips(info, status, { now: 10000, startMs: 4000 });
  assert.equal(chips.model.text, "qwen · qwen4-max-preview · 1M");
  assert.equal(chips.model.reachable, true);
  assert.equal(chips.model.warn, null);
  assert.match(chips.model.tip, /http:\/\/x\.test\/v1/);
  assert.match(chips.model.tip, /reachable/);
  assert.equal(chips.role.text, "core / lead");
  assert.equal(chips.id.text, "session-ab");
  assert.equal(chips.id.full, "session-abcdef-0123");
  assert.equal(chips.run.text, "Running · step 4 · 6s");
});

test("identityChips: an unreachable profile warns, an unknown one is not a warning, a missing window is dropped", () => {
  const info = infoOf("s", { profile: "necromicon", model: "necromicon", context_window: 0 });
  const down = C.identityChips(info, { models: [{ profile: "necromicon", base_url: "b", model: "necromicon", reachable: false, detail: "connection refused", context_window: 0 }] });
  assert.deepEqual(down.model.warn, { icon: "alert", word: "unreachable" });
  assert.equal(down.model.reachable, false);
  assert.equal(down.model.text, "necromicon · necromicon");
  assert.match(down.model.tip, /unreachable: connection refused/);
  // other profiles' health does not matter; no status at all is not a warning
  assert.equal(C.identityChips(info, { models: [{ profile: "other", reachable: false }] }).model.warn, null);
  const none = C.identityChips(info, null);
  assert.equal(none.model.warn, null);
  assert.equal(none.model.reachable, null);
  // the window falls back to the daemon's figure
  assert.equal(C.identityChips(info, { models: [{ profile: "necromicon", reachable: true, context_window: 262144 }] }).model.text, "necromicon · necromicon · 262k");
  // no profile on the info: the record store's model is used
  const fromStore = C.identityChips({ id: "s", role: "lead" }, null, { current: { profile: "qwen", model: "q", context_window: 8000 } });
  assert.equal(fromStore.model.text, "qwen · q · 8k");
  assert.equal(C.identityChips({ id: "s" }, null).model.text, "unknown profile");
});

test("identityChips: an agent's role tip names its mission", () => {
  const agent = infoOf("w1", { parent: "m1", role: "worker", pack: "core" });
  const chips = C.identityChips(agent, null, { mission: infoOf("m1", { title: "Ship it" }) });
  assert.equal(chips.role.text, "core / worker");
  assert.equal(chips.role.tip, "agent of Ship it");
  assert.equal(C.identityChips(infoOf("m1"), null).role.tip, "lead of its mission");
  assert.equal(C.identityChips(infoOf("m1", { role: "chat" }), null).role.tip, "session");
});

test("breadcrumbs: a root is its own title; an agent has linked ancestors; a long chain collapses", () => {
  const list = [
    infoOf("m", { title: "Mission" }), infoOf("a", { parent: "m", title: "", role: "worker" }),
    infoOf("b", { parent: "a", title: "B title" }), infoOf("c", { parent: "b", title: "C" }), infoOf("d", { parent: "c", title: "" }),
  ];
  const store = sessionStore(list);
  assert.deepEqual(C.breadcrumbs(store, "m"), [{ id: "m", label: "Mission", tip: "m", current: true, ellipsis: false }]);
  assert.deepEqual(C.breadcrumbs(store, "a").map((c) => [c.label, c.current]), [["Mission", false], ["a", true]]);
  const deep = C.breadcrumbs(store, "d");
  assert.deepEqual(deep.map((c) => c.label), ["Mission", "…", "C", "d"]);
  assert.equal(deep[1].ellipsis, true);
  assert.equal(deep[1].id, null);
  assert.equal(deep[1].tip, "a / B title");
  assert.equal(deep[3].current, true);
  assert.deepEqual(C.breadcrumbs(store, "missing"), [{ id: "missing", label: "missing", tip: "missing", current: true, ellipsis: false }]);
  // a cycle in the data does not hang
  const cyc = sessionStore([infoOf("x", { parent: "y" }), infoOf("y", { parent: "x" })]);
  assert.ok(C.breadcrumbs(cyc, "x").length <= 2);
});

test("shortId is the first ten characters", () => {
  assert.equal(C.shortId("0123456789abcdef"), "0123456789");
  assert.equal(C.shortId("s-1"), "s-1");
  assert.equal(C.shortId(null), "");
});

// ---- stats

test("sessionStats: speed, cache, context and step; missing data is omitted", () => {
  reset();
  const store = storeOf([start(), reply("r1", "x", { usage: { prompt_tokens: 10, completion_tokens: 11 }, timing: { ttft_ms: 100, total_ms: 1100 } })]);
  const info = infoOf("s", { context_window: 1048576, status: { phase: "running", step: 214, prompt_tokens: 325000, cached_tokens: 299000 } });
  const stats = C.sessionStats(info, store.blocks);
  assert.deepEqual(stats, { speed: "10.0 tok/s", cache: "cache 92%", context: "context 31% of 1M", step: "step 214" });
  // nothing known: every part is empty, never zero
  assert.deepEqual(C.sessionStats({ id: "s" }, []), { speed: "", cache: "", context: "", step: "" });
  assert.deepEqual(C.sessionStats(infoOf("s", { context_window: 0, status: { phase: "idle", step: 0, prompt_tokens: 500, cached_tokens: 0 } }), null), { speed: "", cache: "cache 0%", context: "", step: "" });
  // a tiny context still reads as at least 1%
  assert.equal(C.sessionStats(infoOf("s", { context_window: 1000000, status: { prompt_tokens: 10, step: 1 } }), []).context, "context 1% of 1M");
  assert.equal(C.sessionStats(null, undefined).step, "");
});

test("seatOptions lists configured profiles and keeps an unconfigured current one", () => {
  const models = [{ profile: "a", model: "ma", reachable: true }, { profile: "b", model: "mb", reachable: false }];
  assert.deepEqual(C.seatOptions(models, { profile: "a" }).map(o => o.label), ["a", "b (not reachable)"]);
  assert.equal(C.seatOptions(models, { profile: "a" })[1].unreachable, true);
  const gone = C.seatOptions(models, { profile: "old" });
  assert.equal(gone[2].value, "old");
  assert.equal(gone[2].label, "old (not configured)");
  assert.deepEqual(C.seatOptions(null, null), []);
});

test("seatConfirm asks before switching and says what it costs", () => {
  const models = [{ profile: "a", model: "ma", reachable: true }, { profile: "b", model: "mb", reachable: false }];
  const q = C.seatConfirm(models, { profile: "a" }, "b");
  assert.match(q.text, /^Switch this session to b \(mb\) from its next step\? The next request re-reads the whole prompt once\./);
  assert.match(q.text, /not reachable/);
  assert.equal(q.yes, "Switch");
  assert.equal(q.no, "Keep a");
  assert.equal(C.seatConfirm(models, { profile: "a" }, "a"), null);
  assert.equal(C.seatConfirm(models, { profile: "a" }, "zzz"), null);
});

test("seatReceipt says when the switch takes effect", () => {
  const r = { session: "s", model: { profile: "b", model: "mb" }, live: true };
  assert.equal(C.seatReceipt(r), "Switched to b (mb); takes effect at the next step.");
  assert.match(C.seatReceipt({ ...r, live: false }), /when it next runs/);
  assert.match(C.seatReceipt({}), /Switched to the new model/);
});

// ---- review fixes: windowing, labels, waiting words

test("windowItems keeps a group that crosses the window, clipped, with its model chip and the earlier count", () => {
  reset();
  const calls = [];
  for (let i = 0; i < 6; i++) calls.push(call("c" + i), result("c" + i));
  const store = storeOf([start(), R("user_message", { text: "go" }, undefined, "user"), ...calls, R("user_message", { text: "again" }, undefined, "user"), reply("r", "ok")]);
  const items = C.chatItems(store.blocks, { models: store.models });
  const group = items.find((i) => i.type === "group");
  const from = group.blocks[4].id; // the window starts inside the group
  const windowed = C.windowItems(items, from);
  const g = windowed.find((i) => i.type === "group");
  assert.equal(g.key, group.key, "the key does not change");
  assert.equal(g.blocks.length, group.blocks.length, "the whole group is still known: its counts are not cut");
  assert.equal(g.toolCount, group.toolCount);
  assert.deepEqual(g.shown.map((b) => b.id), group.blocks.filter((b) => b.id >= from).map((b) => b.id));
  assert.equal(g.earlier, group.blocks.filter((b) => b.id < from).length);
  // the chip in front of the clipped group stays, even though its own seq is before the window
  assert.equal(windowed[0].type, "model");
  assert.equal(windowed[1].type, "group");
  // nothing in the window is a group's last member: it goes, and so does its chip
  const late = C.windowItems(items, store.blocks.length - 1);
  assert.deepEqual(late.map((i) => i.type), ["model", "block"]);
  assert.equal(C.windowItems(items, 0), items);
  assert.equal(C.windowItems(items, from).every((i) => i.type !== "group" || i.shown.every((b) => b.id >= from)), true);
});

test("a long open group is windowed to the shown members, so rendering is bounded", () => {
  reset();
  const recs = [start(), R("user_message", { text: "go" }, undefined, "user")];
  for (let i = 0; i < 400; i++) recs.push(reply("r" + i, "", { tool_calls: [{ call_id: "c" + i, name: "bash", arguments: "{}", complete: true }] }), call("c" + i), result("c" + i));
  const store = storeOf(recs);
  const items = C.chatItems(store.blocks, { models: store.models });
  assert.equal(items.filter((i) => i.type === "group").length, 1);
  const from = store.blocks.length - 300;
  const g = C.windowItems(items, from).find((i) => i.type === "group");
  assert.equal(g.shown.length, 300);
  assert.equal(g.earlier, g.blocks.length - 300);
  assert.equal(g.toolCount, 400);
});

test("groupLabel: warnings are counted and the spoken name has no ticking clock while running", () => {
  const g = { type: "group", toolCount: 3, failed: 1, missing: 0, warnings: 2, running: true, startTs: 1000, endTs: 1000 };
  const a = C.groupLabel(g, 42000);
  const b = C.groupLabel(g, 43000);
  assert.equal(a.text, "Worked for 41s · 3 tool calls · 1 failed · 2 warnings · running");
  assert.equal(a.spoken, "Work in progress · 3 tool calls · 1 failed · 2 warnings · running");
  assert.equal(a.spoken, b.spoken, "the name does not change while the seconds do");
  assert.notEqual(a.text, b.text);
  const done = C.groupLabel({ ...g, running: false, endTs: 13000 }, 0);
  assert.equal(done.spoken, "Worked for 12s · 3 tool calls · 1 failed · 2 warnings");
  assert.equal(C.groupLabel({ ...g, warnings: 0, failed: 0 }, 5000).text, "Worked for 4.0s · 3 tool calls · running");
});

test("a folded group counts the warnings among its members", () => {
  reset();
  const store = storeOf([
    start(), R("user_message", { text: "go" }, undefined, "user"),
    reply("r1", "", { finish: "length", tool_calls: [{ call_id: "c1", name: "bash", arguments: "{", complete: false }] }),
    R("job_settled", { job_id: "j", exit_code: 2, output: null, detail: "" }),
    R("cache_break", { req_id: "r", first_diff_message: 2, detail: "d" }),
    R("job_settled", { job_id: "k", exit_code: 0, output: null, detail: "" }),
    reply("r2", "done"),
  ]);
  const g = C.chatItems(store.blocks, { models: store.models }).find((i) => i.type === "group");
  assert.equal(g.warnings, 3, "a cut reply, a failed job and a cache break");
  assert.equal(g.toolCount, 0);
  assert.match(C.groupLabel(g, 0).text, /3 warnings/);
});

test("waitingReason also says a nonblocking question and a ready result, in their own shapes", () => {
  const none = { blocking: { count: 0 }, questions: { count: 0 }, results: { count: 0 } };
  assert.equal(C.waitingReason(none, 1), null);
  const q = C.waitingReason({ ...none, questions: { count: 1, since: 0 } }, 120000);
  assert.deepEqual(q, { text: "Question open 2m", icon: "question", tone: "info" });
  const r = C.waitingReason({ ...none, results: { count: 1, since: 0 } }, 600000);
  assert.deepEqual(r, { text: "Result ready 10m", icon: "diamond-outline", tone: "ok" });
  assert.equal(C.waitingReason({ ...none, questions: { count: 2 } }, 5).text, "2 questions open");
  // a blocking request wins, and keeps the urgent shape
  assert.equal(C.waitingReason({ ...none, blocking: { count: 1, kind: "approval", since: 0 }, questions: { count: 1 } }, 60000).icon, "diamond");
  assert.notEqual(q.icon, "diamond");
});

test("a session with a nonblocking question or a ready result says so on its row", () => {
  const list = [infoOf("q", { workspace: "/w/a" }), infoOf("r", { workspace: "/w/b", status: { phase: "ended", outcome: "done", step: 3 } })];
  const q = { item_id: "i-q", item_kind: "question", blocking: false, text: "t" };
  const r = { item_id: "i-r", item_kind: "finished", blocking: false, text: "t" };
  const inbox = C.createInbox();
  inbox.items.set("i-q", { session: "q", mission: "q", opened_ms: 0, item: q });
  inbox.items.set("i-r", { session: "r", mission: "r", opened_ms: 0, item: r });
  const rows = C.workspaceGroups(sessionStore(list), inbox, {}, 600000).flatMap((g) => g.rows);
  assert.equal(rows.find((x) => x.info.id === "q").identity.waiting.text, "Question open 10m");
  assert.equal(rows.find((x) => x.info.id === "r").identity.waiting.text, "Result ready 10m");
  assert.equal(rows.find((x) => x.info.id === "q").mark.mark, "idle", "only a blocking request takes the needs-you mark");
});

test("runWords says an open question and a ready result in words, not only by shape", () => {
  const live = infoOf("s", { status: { phase: "idle", step: 7, last_end: "yielded" } });
  assert.equal(C.runWords(live, { attention: { blocking: 0, questions: 1, results: 0 } }).text, "Idle · step 7 · question open");
  assert.equal(C.runWords(live, { attention: { blocking: 0, questions: 0, results: 1 } }).text, "Idle · step 7 · result ready");
  const ended = infoOf("s", { status: { phase: "ended", step: 7, outcome: "done" } });
  assert.equal(C.runWords(ended, { attention: { blocking: 0, results: 1 } }).text, "Ended · done · result ready");
  assert.equal(C.runWords(ended, { attention: { blocking: 0 } }).text, "Ended · done");
  assert.notEqual(C.runWords(live, { attention: { questions: 1 } }).icon, C.runWords(live, { attention: { results: 1 } }).icon);
});

test("identityLine: the age is a recorded time or an explicit unknown, and a waiting reason has its own line", () => {
  const i = infoOf("s", { profile: "qwen", role: "chat" });
  assert.equal(C.identityLine(i, 1000, null, 61000).text, "qwen · chat · 1m");
  assert.equal(C.identityLine(i, null, null, 61000).text, "qwen · chat · activity not loaded");
  assert.equal(C.identityLine(i, undefined, null, 61000).age, "activity not loaded");
  const w = C.identityLine(i, 1000, { blocking: { count: 1, kind: "question", since: 1000 } }, 61000);
  assert.equal(w.text, "qwen · chat");
  assert.equal(w.waiting.text, "Question waiting 1m");
});

test("workspaceGroups: a row with no loaded activity never shows its creation as an age, and still sorts", () => {
  const list = [infoOf("old", { workspace: "/w/a", created_ms: 1000 }), infoOf("new", { workspace: "/w/a", created_ms: 900000 })];
  const rows = C.workspaceGroups(sessionStore(list), C.createInbox(), {}, 1000000)[0].rows;
  assert.deepEqual(rows.map((r) => r.info.id), ["new", "old"]);
  for (const r of rows) assert.equal(r.identity.age, "activity not loaded");
});

test("connectionWords: short words for the sidebar, the detail in the tooltip", () => {
  const live = C.connectionWords({ connected: true, everConnected: true, lastUpdateText: "Last update 2s ago" });
  assert.equal(live.short, "Live");
  assert.match(live.tip, /Last update 2s ago/);
  const amber = C.connectionWords({ connected: true, everConnected: true, models: [{ profile: "necromicon", reachable: false, detail: "refused" }, { profile: "qwen", reachable: true }] });
  assert.equal(amber.short, "Live", "an unreachable model is not on the sidebar line");
  assert.match(amber.tip, /necromicon: unreachable \(refused\)/);
  assert.doesNotMatch(amber.tip, /qwen/);
  assert.match(C.connectionWords({ connected: true, statusError: "boom" }).tip, /Model status unavailable: boom/);
  assert.equal(C.connectionWords({}).short, "Connecting…");
  assert.equal(C.connectionWords({ everConnected: true, attempts: 1 }).short, "Reconnecting…");
  assert.equal(C.connectionWords({ everConnected: true, attempts: 3 }).short, "Offline");
  assert.match(C.connectionWords({ everConnected: true }).tip, /execution state unknown/);
  for (const w of [live, amber, C.connectionWords({}), C.connectionWords({ attempts: 9 })]) assert.ok(w.short.length <= 14, "short enough for the sidebar");
});

test("seatAvailability: an ended session's seat is disabled with the reason; a busy switch only holds its own session", () => {
  const live = infoOf("a", { status: { phase: "idle" } });
  assert.deepEqual(C.seatAvailability(live, null, 2), { disabled: false, reason: "" });
  const ended = C.seatAvailability(infoOf("a", { status: { phase: "ended", outcome: "done" } }), null, 2);
  assert.equal(ended.disabled, true);
  assert.equal(ended.reason, "This session has ended; its model no longer changes.");
  assert.equal(C.seatAvailability(live, "a", 2).disabled, true, "the session being switched waits");
  assert.equal(C.seatAvailability(infoOf("b", { status: { phase: "idle" } }), "a", 2).disabled, false, "another session's switch does not hold this seat");
  assert.equal(C.seatAvailability(live, null, 0).disabled, true);
  assert.equal(C.seatAvailability(null, null, 2).disabled, true);
});

test("receiptApplies: a receipt never overwrites a session that a newer frame has changed", () => {
  const before = { profile: "dsv41", model: "deepseek-v4.1" };
  assert.equal(C.receiptApplies({ profile: "dsv41", model: "deepseek-v4.1" }, before), true);
  assert.equal(C.receiptApplies({ profile: "qwen", model: "q" }, before), false, "a frame already moved it on");
  assert.equal(C.receiptApplies({ profile: "dsv41", model: "other-id" }, before), false);
  assert.equal(C.receiptApplies(undefined, before), false);
  assert.equal(C.receiptApplies({ profile: "a" }, null), false);
  assert.equal(C.receiptApplies({ profile: "a" }, { profile: "a", model: "" }), true);
});

test("sendStateText: the newer of the switch note and the message state wins; loading comes first", () => {
  const seat = { text: "Switched to qwen (q); takes effect at the next step.", at: 5 };
  assert.equal(C.sendStateText({ seat, message: { text: "Message accepted · awaiting its recorded delivery.", at: 4 } }), seat.text, "the switch came last");
  assert.equal(C.sendStateText({ seat, message: { text: "Delivered to a model step.", at: 6 } }), "Delivered to a model step.", "a receipt that settles after the switch shows");
  assert.equal(C.sendStateText({ seat, message: { text: "Message rejected: no", at: 9 } }), "Message rejected: no");
  assert.equal(C.sendStateText({ seat: null, message: { text: "m", at: 1 } }), "m");
  assert.equal(C.sendStateText({ seat, message: null }), seat.text);
  assert.equal(C.sendStateText({ seat, message: { text: "m", at: 9 }, loaded: false }), "Loading the record before messages can be sent.");
  assert.equal(C.sendStateText({}), "");
});

// ---------------------------------------------------------------------------------------------
// Pass 2

test("applySessionList without sinceRev replaces; with it, entries changed by events since the request are kept", () => {
  const store = C.createSessionStore();
  C.applySessionList(store, [info("a"), info("b")]);
  assert.deepEqual([...store.byId.keys()], ["a", "b"]);
  // a request goes out at this rev; events arrive while it is in flight
  const rev = store.rev;
  C.applyStatus(store, "a", st({ phase: "running", step: 9 }));
  C.applySessionEvent(store, info("c", { title: "born during the request" }));
  const snapshot = [info("a", { status: st({ step: 1 }) }), info("b", { title: "newer b" })];
  C.applySessionList(store, snapshot, { sinceRev: rev });
  assert.equal(store.byId.get("a").status.step, 9, "the status event is newer than the snapshot");
  assert.equal(store.byId.get("a").status.phase, "running");
  assert.equal(store.byId.get("b").title, "newer b", "an untouched session takes the snapshot");
  assert.equal(store.byId.get("c").title, "born during the request", "a session the snapshot does not list yet is kept");
  // the next snapshot, requested after those events, replaces them
  const rev2 = store.rev;
  C.applySessionList(store, [info("a", { title: "from the list" })], { sinceRev: rev2 });
  assert.deepEqual([...store.byId.keys()], ["a"]);
  assert.equal(store.byId.get("a").title, "from the list");
  // without sinceRev nothing is kept
  C.applySessionEvent(store, info("d"));
  C.applySessionList(store, [info("a")]);
  assert.deepEqual([...store.byId.keys()], ["a"]);
  assert.equal(store.changed.size, 0);
});

test("proseTree: paragraphs, headings, lists, bold and code, and fenced code collected in one pass", () => {
  const t = C.proseTree("# Title with `x`\n\nfirst **bold** line\nsecond line\n\n- a\n- b\n1. one\n2) two\n\n```sh\nls -l\n\ncat x\n```\nafter");
  assert.deepEqual(t.map((b) => b.type), ["h", "p", "ul", "ol", "pre", "p"]);
  assert.deepEqual(t[0].inline, [{ type: "text", text: "Title with " }, { type: "code", text: "x" }]);
  assert.deepEqual(t[1].inline, [{ type: "text", text: "first " }, { type: "strong", text: "bold" }, { type: "text", text: " line\nsecond line" }]);
  assert.deepEqual(t[2].items, [[{ type: "text", text: "a" }], [{ type: "text", text: "b" }]]);
  assert.equal(t[3].items.length, 2);
  assert.equal(t[4].text, "ls -l\n\ncat x", "lines, blank ones included, joined once");
  assert.deepEqual(t[5].inline, [{ type: "text", text: "after" }]);
  // an unterminated fence runs to the end; markup inside a fence is not read
  assert.deepEqual(C.proseTree("```\n**no**\n- x"), [{ type: "pre", text: "**no**\n- x" }]);
  assert.deepEqual(C.proseTree(""), []);
  assert.deepEqual(C.proseTree(null), []);
  // a switch of list kind starts a new list; a blank line ends one
  assert.deepEqual(C.proseTree("- a\n1. b\n\n- c").map((b) => b.type), ["ul", "ol", "ul"]);
  // raw HTML stays text
  assert.deepEqual(C.proseTree("<img src=x onerror=1>")[0].inline, [{ type: "text", text: "<img src=x onerror=1>" }]);
  // linear: a 200k-line fence is one pass
  const big = "```\n" + "x".repeat(20) + "\n".repeat(0) + Array.from({ length: 200000 }, () => "line").join("\n") + "\n```";
  const t0 = performance.now();
  assert.equal(C.proseTree(big)[0].text.split("\n").length, 200000);
  assert.ok(performance.now() - t0 < 1000, "O(L), not O(L squared)");
});

test("quietFor: only a running session with a known old last record, neutral and factual", () => {
  const run = info("a", { status: st({ phase: "running" }) });
  const now = 10_000_000;
  assert.equal(C.quietFor(run, { ts: now - 5 * 60000 }, now), null, "5 minutes is not quiet");
  assert.equal(C.quietFor(run, { ts: now - C.QUIET_MS }, now), null, "the threshold itself is not past it");
  const q = C.quietFor(run, { ts: now - 41 * 60000 - 5000 }, now);
  assert.equal(q.text, "no new record for 41m");
  assert.equal(q.icon, "hourglass");
  assert.equal(q.tone, "", "never amber");
  assert.match(q.tip, /can be normal/);
  assert.doesNotMatch(JSON.stringify(q), /stall(ed)?\b.*stuck|stuck|hung/i);
  assert.equal(C.quietFor(run, now - 3 * 3600000, now).text, "no new record for 3h", "a bare time works too");
  assert.equal(C.quietFor(run, null, now), null, "unknown age shows nothing");
  assert.equal(C.quietFor(run, { seq: 3 }, now), null);
  assert.equal(C.quietFor(info("a", { status: st({ phase: "idle" }) }), { ts: 0 }, now), null, "only running sessions");
  assert.equal(C.quietFor(info("a", { status: st({ phase: "ended" }) }), { ts: 0 }, now), null);
  assert.equal(C.quietFor(null, { ts: 0 }, now), null);
  // ranked below what waits on the operator
  const waiting = C.waitingFor(inboxWith([blockingItem("a")]), ["a"]);
  assert.equal(C.rowReason(waiting, run, { ts: 0 }, now).tone, "attention");
  assert.equal(C.rowReason(C.waitingFor(C.createInbox(), ["a"]), run, { ts: 0 }, now).icon, "hourglass");
});

test("switcherRows: needs you, then running, then recent; plain substring over title, id prefix, workspace, profile, role", () => {
  const store = sessionStore([
    info("s-idle-old", { title: "Old thing", created_ms: 1000 }),
    info("s-idle-new", { title: "New thing", created_ms: 9000 }),
    info("s-run", { title: "Scan hosts", status: st({ phase: "running" }), workspace: "/w/necro", profile: "necromicon" }),
    info("s-need", { title: "Port 8443", status: st({ phase: "running" }), role: "solver", parent: "s-run", created_ms: 2000 }),
    info("s-need2", { title: "Port 22", workspace: "/w/ssh" }),
    info("s-gone", { title: "Archived", archived: true }),
  ]);
  const inbox = inboxWith([blockingItem("s-need", "approval", 5000), blockingItem("s-need2", "blocker", 3000)]);
  const rows = C.switcherRows(store, inbox, "", { now: 100000 });
  assert.deepEqual(rows.map((r) => r.id), ["s-need2", "s-need", "s-run", "s-idle-new", "s-idle-old"], "oldest wait first; archived left out");
  assert.deepEqual(rows.map((r) => r.group), ["needs_you", "needs_you", "running", "other", "other"]);
  assert.equal(rows[0].mark.icon, "diamond");
  assert.match(rows[1].reason.text, /^Approval waiting/);
  assert.equal(rows[2].identity.parts[1], "lead");
  assert.equal(C.switcherRows(store, inbox, "", { showArchived: true, now: 1 }).length, 6);
  // with activity, recent first among the rest
  const activity = new Map([["s-idle-old", { seq: 1, ts: 90000 }]]);
  assert.equal(C.switcherRows(store, inbox, "", { now: 100000, activity }).at(-2).id, "s-idle-old");
  assert.equal(C.switcherRows(store, inbox, "", { now: 100000, activity }).find((r) => r.id === "s-idle-old").identity.age, "10s");
  const ids = (q) => C.switcherRows(store, inbox, q, { now: 100000 }).map((r) => r.id);
  assert.deepEqual(ids("port"), ["s-need2", "s-need"], "title, case-insensitive");
  assert.deepEqual(ids("8443"), ["s-need"]);
  assert.deepEqual(ids("s-need"), ["s-need2", "s-need"], "id prefix");
  assert.deepEqual(ids("need"), [], "an id is matched by its prefix, not from the middle");
  assert.deepEqual(ids("-need"), []);
  assert.deepEqual(ids("necro"), ["s-run"], "workspace name");
  assert.deepEqual(ids("ssh"), ["s-need2"], "workspace name");
  assert.deepEqual(ids("solver"), ["s-need"], "role");
  assert.deepEqual(ids("necromicon"), ["s-run"], "profile");
  assert.equal(C.switcherRows(store, inbox, "port", { now: 1 })[0].matched, "title");
  assert.deepEqual(ids("p.rt"), [], "no pattern matching");
  assert.deepEqual(ids("   "), ids(""), "a blank query is no query");
});

test("nextNeedsYou cycles the missions that need you and says where it is", () => {
  const store = sessionStore([
    info("a", { mission: "ma" }), info("a-kid", { mission: "ma", parent: "a" }),
    info("b", { mission: "mb" }), info("c", { mission: "mc" }), info("quiet", { mission: "mq" }),
    info("done", { mission: "md", status: st({ phase: "ended", outcome: "done" }) }),
  ]);
  const inbox = inboxWith([
    blockingItem("a-kid", "approval", 3000), blockingItem("a", "question", 4000),
    blockingItem("b", "blocker", 1000), blockingItem("c", "approval", 2000), blockingItem("done", "parked", 500),
    { session: "quiet", item: { item_id: "q", item_kind: "question", blocking: false }, opened_ms: 1 },
  ]);
  const n = C.nextNeedsYou(store, inbox, "quiet", 1);
  assert.deepEqual([n.id, n.index, n.total, n.words], ["b", 1, 3, "1 of 3 needing you"], "from elsewhere, the longest-waiting mission");
  assert.equal(C.nextNeedsYou(store, inbox, "b", 1).id, "c");
  assert.equal(C.nextNeedsYou(store, inbox, "c", 1).id, "a-kid", "lands on the session holding the oldest blocking item");
  assert.equal(C.nextNeedsYou(store, inbox, "a", 1).id, "b", "cycles");
  assert.equal(C.nextNeedsYou(store, inbox, "a-kid", 1).words, "1 of 3 needing you");
  assert.equal(C.nextNeedsYou(store, inbox, "b", -1).id, "a-kid");
  assert.equal(C.nextNeedsYou(store, inbox, "quiet", -1).words, "3 of 3 needing you");
  assert.equal(C.nextNeedsYou(store, C.createInbox(), "a", 1), null);
});

test("missionEnding: a root that goes to ended, once, never for this tab's own stop", () => {
  const was = info("m", { title: "Mission", status: st({ phase: "running" }) });
  const ended = (outcome) => info("m", { title: "Mission", status: st({ phase: "ended", outcome }) });
  assert.deepEqual(C.missionEnding(was, ended("failed")), { session: "m", mission: "m-m", title: "Mission", outcome: "failed", words: "failed" });
  assert.equal(C.missionEnding(was, ended("done")).words, "done");
  assert.equal(C.missionEnding(was, ended("budget_exhausted")).words, "budget exhausted");
  assert.equal(C.missionEnding(ended("done"), ended("done")), null, "already ended: no second notice");
  assert.equal(C.missionEnding(was, was), null);
  assert.equal(C.missionEnding(null, ended("done")), null, "a session not seen before is history, not news");
  assert.equal(C.missionEnding(was, { ...ended("done"), parent: "p" }), null, "agents are not missions");
  assert.equal(C.missionEnding(was, ended("stopped"), { requested: new Set(["m"]) }), null, "a stop this tab asked for");
  assert.equal(C.missionEnding(was, ended("stopped"), { requested: new Set(["other"]) }).outcome, "stopped");
  assert.equal(C.missionEnding(was, ended("failed"), { requested: new Set(["m"]) }).outcome, "failed", "only a stop is excused");
  // a status frame: the held info with the new status
  assert.equal(C.missionEnding(was, { ...was, status: st({ phase: "ended", outcome: "done" }) }).outcome, "done");
  // through the store, the way the page holds it
  const store = sessionStore([was]);
  const before = store.byId.get("m");
  C.applyStatus(store, "m", st({ phase: "ended", outcome: "done" }));
  assert.ok(C.missionEnding(before, store.byId.get("m")));
});

const notice = (over = {}) => C.noticeOfInbox({ session: "s-1", title: "Scan", item: { item_id: "i-1", item_kind: "approval", blocking: true, text: "May I curl x?" }, ...over }, 1000);

test("notices: blocking and result items and endings, with the sidebar's nouns", () => {
  assert.deepEqual(notice(), { tag: "i-1", session: "s-1", title: "Scan", at: 1000, kind: "needs_you", noun: "Approval waiting", text: "May I curl x?" });
  assert.equal(notice({ item: { item_id: "i", item_kind: "parked", blocking: true, text: "t" } }).noun, "Parked session waiting");
  assert.equal(notice({ item: { item_id: "i", item_kind: "finished", blocking: false, text: "ok" } }).noun, "Result ready");
  assert.equal(notice({ item: { item_id: "i", item_kind: "finished", blocking: false, text: "ok" } }).kind, "result");
  assert.equal(notice({ item: { item_id: "i", item_kind: "question", blocking: false, text: "q" } }), null, "a question work can go on without");
  assert.equal(C.noticeOfInbox(null, 1), null);
  const end = C.noticeOfEnding(C.missionEnding(info("m", { status: st({ phase: "running" }) }), info("m", { status: st({ phase: "ended", outcome: "failed" }) })), 2000);
  assert.deepEqual([end.tag, end.kind, end.noun, end.outcome], ["end:m", "ended", "Mission failed", "failed"]);
  assert.equal(C.noticeOfEnding(null, 1), null);
  assert.equal(C.noticeOfEnding({ session: "m", title: "t", outcome: "done", words: "done" }, 1).noun, "Mission finished");
});

test("planNotifications: a 5 s window, one combined notification, a click target, tags to close", () => {
  const a = notice();
  const b = notice({ session: "s-2", title: "Brute", item: { item_id: "i-2", item_kind: "blocker", blocking: true, text: "Stuck" } });
  const fin = C.noticeOfEnding({ session: "m-3", title: "Recon", outcome: "done", words: "done" }, 3000);
  // waiting inside the window
  let plan = C.planNotifications([a], { now: 1000 + 4999 });
  assert.deepEqual([plan.due, plan.wait, plan.notification, plan.rest], [false, 1, null, [a]]);
  assert.deepEqual(C.planNotifications([], { now: 1 }), { due: false, wait: null, notification: null, rest: [] });
  // one item: its own noun and mission, and the session as the target
  plan = C.planNotifications([a], { now: 6000 });
  assert.equal(plan.due, true);
  assert.deepEqual(plan.rest, []);
  assert.deepEqual(plan.notification, {
    tag: "i-1", title: "Approval waiting", body: "Scan: May I curl x?", target: { hash: "#/s/s-1/chat", session: "s-1" },
    covers: ["i-1"], sessions: ["s-1"], counts: { needs: 1, results: 0, ended: 0 },
  });
  // several: counts in the title, the inbox as the target
  plan = C.planNotifications([a, b, fin], { now: 8000 });
  assert.equal(plan.notification.title, "2 need you · 1 finished");
  assert.equal(plan.notification.target.hash, "#/inbox");
  assert.equal(plan.notification.target.session, null);
  assert.deepEqual(plan.notification.covers, ["i-1", "i-2", "end:m-3"]);
  assert.deepEqual(plan.notification.body.split("\n"), ["Approval waiting: Scan", "Blocker waiting: Brute", "Mission finished: Recon"]);
  assert.match(plan.notification.tag, /^batch:/);
  assert.equal(C.planNotifications([a, b, fin], { now: 8000 }).notification.tag, plan.notification.tag, "stable for the same batch");
  // an item announced twice is one
  assert.equal(C.planNotifications([a, { ...a, at: 1500 }], { now: 8000 }).notification.title, "Approval waiting");
  // mixed endings and results, and a long list is cut honestly
  const many = Array.from({ length: 6 }, (_, i) => notice({ item: { item_id: "x" + i, item_kind: "approval", blocking: true, text: "t" }, title: "T" + i }));
  const lines = C.planNotifications(many, { now: 9000 }).notification.body.split("\n");
  assert.equal(lines.length, 5);
  assert.equal(lines.at(-1), "and 2 more");
  const mixed = C.planNotifications([fin, C.noticeOfEnding({ session: "m-4", title: "x", outcome: "failed", words: "failed" }, 3000), notice({ item: { item_id: "r", item_kind: "finished", blocking: false, text: "" } })], { now: 9000 });
  assert.equal(mixed.notification.title, "1 result ready · 1 finished · 1 failed");
  // the page is shown and focused: nothing is shown, the batch is consumed
  assert.deepEqual(C.planNotifications([a, b], { now: 9000, visible: true }), { due: true, wait: 0, notification: null, rest: [] });
  assert.equal(C.planNotifications([a], { now: 1000 + C.NOTIFY_WINDOW_MS }).due, true);
  assert.equal(C.planNotifications([a], { now: 3000, windowMs: 1000 }).due, true);
});

test("closableNotifications: on resolve, when the session or the inbox is opened", () => {
  const one = C.planNotifications([notice()], { now: 9000 }).notification;
  const two = C.planNotifications([notice(), notice({ session: "s-2", item: { item_id: "i-2", item_kind: "blocker", blocking: true, text: "t" } })], { now: 9000 }).notification;
  const ended = C.planNotifications([C.noticeOfEnding({ session: "m", title: "t", outcome: "done", words: "done" }, 1000)], { now: 9000 }).notification;
  const shown = [one, two, ended];
  const close = (ctx) => C.closableNotifications(shown, ctx);
  assert.deepEqual(close({ openItems: new Set(["i-1", "i-2"]), opened: {} }), [], "still open: stays");
  assert.deepEqual(close({ openItems: new Set(["i-2"]), opened: {} }), ["i-1"], "its item resolved");
  assert.deepEqual(close({ openItems: new Set(), opened: {} }), [one.tag, two.tag], "all resolved; an ending has nothing to resolve");
  assert.deepEqual(close({ openItems: new Set(["i-1", "i-2"]), opened: { session: "s-1" } }), ["i-1"], "its session was opened");
  assert.deepEqual(close({ openItems: new Set(["i-1", "i-2"]), opened: { session: "m" } }), [ended.tag]);
  assert.deepEqual(close({ openItems: ["i-1", "i-2"], opened: { inbox: true } }), [two.tag], "the inbox closes the combined one");
  assert.deepEqual(C.closableNotifications(null, {}), []);
});

const scoreView = () => ({
  mission: "m-1",
  sessions: [
    { session: "lead", role: "lead", parent: null, card: { steps: 40, finished: true, steps_to_finish: 40, calls: 90, malformed_calls: 2, finish_calls: 1, finish_refusals: 1, quote_refusals: 0, verifier_accepts: 3, verifier_rejections: 1, fresh_starts: 0, hand_offs: 0, asks: 1, unrecorded: false } },
    { session: "kid", role: "solver", parent: "lead", card: { steps: 5, finished: false, steps_to_finish: null, calls: 0, malformed_calls: 0, finish_calls: 0, finish_refusals: 0, quote_refusals: 0, verifier_accepts: 0, verifier_rejections: 0, fresh_starts: 0, hand_offs: 1, asks: 0, unrecorded: true } },
  ],
  total: { steps: 45, finished: true, steps_to_finish: 40, calls: 90, malformed_calls: 2, finish_calls: 1, finish_refusals: 1, quote_refusals: 0, verifier_accepts: 3, verifier_rejections: 1, fresh_starts: 0, hand_offs: 1, asks: 1, unrecorded: false },
});

test("scoreRows shapes /score: eight cells per session, the total, and the fine print", () => {
  const s = C.scoreRows(scoreView());
  assert.equal(s.mission, "m-1");
  assert.deepEqual(s.rows.map((r) => r.session), ["lead", "kid"]);
  assert.equal(s.bySession.get("kid").role, "solver");
  const lead = s.bySession.get("lead");
  assert.deepEqual(lead.cells.map((c) => c.key), ["calls", "malformed_calls", "quote_refusals", "finish_refusals", "verifier_accepts", "verifier_rejections", "hand_offs", "asks"]);
  assert.equal(lead.cells.length, 8, "zeros are kept: the count is the fact");
  assert.equal(lead.text, "90 calls · 2 malformed calls · 1 finish refusal · 3 verifier accepts · 1 verifier reject · 1 ask");
  assert.deepEqual([lead.steps, lead.finished, lead.stepsToFinish, lead.unrecorded], [40, true, 40, false]);
  assert.equal(s.bySession.get("kid").text, "1 hand-off");
  assert.equal(s.bySession.get("kid").unrecorded, true);
  assert.equal(s.total.cells.find((c) => c.key === "hand_offs").value, 1);
  assert.equal(s.label, "Mission total: the result is the lead's, the effort everyone's");
  assert.equal(s.fineprint, "Run numbers describe effort, not completion.");
  assert.equal(C.scoreRows({ mission: "m", sessions: [{ session: "x", card: {} }], total: {} }).rows[0].text, "no calls recorded");
  for (const bad of [null, {}, { sessions: [] }, { sessions: "x", total: {} }]) assert.equal(C.scoreRows(bad), null);
});

test("scoreDue: on open and Refresh, then at most every 120 s while shown and something runs", () => {
  assert.equal(C.scoreDue({ force: true, shown: false }), true);
  assert.equal(C.scoreDue({ shown: true, running: true, lastMs: undefined, now: 5 }), true, "never fetched");
  assert.equal(C.scoreDue({ shown: true, running: true, lastMs: 1000, now: 1000 + 119999 }), false);
  assert.equal(C.scoreDue({ shown: true, running: true, lastMs: 1000, now: 1000 + 120000 }), true);
  assert.equal(C.scoreDue({ shown: false, running: true, lastMs: 0, now: 1e9 }), false, "not while the tab is hidden");
  assert.equal(C.scoreDue({ shown: true, running: false, lastMs: 0, now: 1e9 }), false, "not again when nothing runs");
  assert.equal(C.scoreDue({ shown: true, running: false, lastMs: null }), true, "a finished mission is read once when its tab is shown");
  assert.equal(C.scoreDue(), false);
});

test("agentGroups: fixed groups, creation order that never re-sorts, depth 3 and breadcrumbs, the score row", () => {
  const mk = (id, over = {}) => info(id, { mission: "M", parent: null, created_ms: 1000, role: "solver", title: "agent " + id, ...over });
  const store = sessionStore([
    mk("lead", { role: "lead", status: st({ phase: "running", step: 40, completion_tokens_total: 1_200_000 }) }),
    mk("b", { parent: "lead", created_ms: 3000, status: st({ phase: "running" }) }),
    mk("a", { parent: "lead", created_ms: 2000, status: st({ phase: "running", step: 7 }) }),
    mk("a1", { parent: "a", created_ms: 2500, status: st({ phase: "idle", last_end: "waiting" }) }),
    mk("a2", { parent: "a1", created_ms: 2600 }),
    mk("a3", { parent: "a2", created_ms: 2700 }),
    mk("a4", { parent: "a3", created_ms: 2800, status: st({ phase: "ended", outcome: "failed" }) }),
    mk("ask", { parent: "lead", created_ms: 4000, status: st({ phase: "running" }) }),
    mk("other", { mission: "other" }),
  ]);
  const inbox = inboxWith([blockingItem("ask")]);
  const activity = new Map([["a", { seq: 9, ts: 100000 - 41 * 60000 }]]);
  const g = C.agentGroups(store, inbox, "M", { now: 100000, activity, score: C.scoreRows({ ...scoreView(), sessions: [{ session: "a", role: "solver", parent: "lead", card: { calls: 4 } }] }), spawns: new Map([["a", 12]]) });
  assert.deepEqual(g.groups.map((x) => x.key), ["needs_you", "running", "waiting", "idle", "ended"]);
  assert.equal(g.total, 8, "only this mission");
  assert.equal(g.running, 4, "the one that needs you is running too");
  assert.equal(g.badge, "4 running");
  assert.deepEqual(g.groups.find((x) => x.key === "running").rows.map((r) => r.id), ["lead", "a", "b"], "creation order");
  assert.equal(g.groups.find((x) => x.key === "ended").folded, true);
  assert.equal(g.groups[0].folded, false);
  const row = (id) => g.groups.flatMap((x) => x.rows).find((r) => r.id === id);
  assert.deepEqual([row("lead").depth, row("a").depth, row("a3").depth, row("a4").depth], [0, 1, 4, 5]);
  assert.deepEqual([row("a3").indent, row("a4").indent], [3, 3], "indented to depth 3");
  assert.deepEqual(row("a4").crumbs, ["agent lead", "agent a", "agent a1", "agent a2", "agent a3"].slice(0, 5), "deeper ones carry the way down");
  assert.deepEqual(row("a2").crumbs, []);
  assert.equal(row("a4").outcome, "failed");
  assert.equal(row("lead").generated, "1.2M generated");
  assert.equal(row("a").roleLine, "solver · local");
  assert.equal(row("a").ageText, "41m ago");
  assert.equal(row("a").quiet.text, "no new record for 41m");
  assert.equal(row("b").ageText, null, "unknown age is not made up");
  assert.equal(row("a").score.cells[0].value, 4);
  assert.equal(row("b").score, null);
  assert.equal(row("a").spawnSeq, 12);
  assert.equal(row("b").spawnSeq, null);
  assert.equal(row("ask").waiting.tone, "attention");
  assert.equal(row("a").step, 7);
  // a step update or a new record changes no order
  C.applyStatus(store, "b", st({ phase: "running", step: 500 }));
  const again = C.agentGroups(store, inbox, "M", { now: 100000, activity: new Map([["b", { seq: 1, ts: 99999 }]]) });
  assert.deepEqual(again.groups.find((x) => x.key === "running").rows.map((r) => r.id), ["lead", "a", "b"]);
  assert.deepEqual(C.agentGroups(store, inbox, "nope").groups, []);
  assert.equal(C.agentGroups(sessionStore([mk("x")]), C.createInbox(), "M").badge, "");
});

test("a mission with 12 agents at mixed phases: every agent in exactly one group", () => {
  const phases = [{ phase: "running" }, { phase: "idle", last_end: "waiting" }, { phase: "idle" }, { phase: "ended", outcome: "done" }];
  const list = [info("lead", { mission: "M", role: "lead", created_ms: 1 })];
  for (let i = 0; i < 12; i++) list.push(info("w" + i, { mission: "M", parent: i < 4 ? "lead" : "w" + (i % 4), created_ms: 10 + i, status: st(phases[i % 4]) }));
  const g = C.agentGroups(sessionStore(list), C.createInbox(), "M", { now: 1 });
  assert.equal(g.groups.reduce((n, x) => n + x.rows.length, 0), 13);
  assert.equal(new Set(g.groups.flatMap((x) => x.rows.map((r) => r.id))).size, 13);
});

test("toolOutcome and toolRow say how each ToolStatus ended, each with its own shape", () => {
  const row = (status, meta = {}) => C.toolRow({ kind: "tool", name: "bash", cls: "exec", state: "done", result: { status, meta, duration_ms: 0, shown: { complete: true } } });
  assert.deepEqual(row("ok").capsule, { text: "ok", tone: "ok", icon: "check" });
  assert.deepEqual(row("ok", { exit_code: 0 }).capsule, { text: "exit 0", tone: "ok", icon: "check" });
  assert.deepEqual(row("error", { exit_code: 1 }).capsule, { text: "exit 1", tone: "neutral", icon: "exit" });
  assert.deepEqual(row("error").capsule, { text: "error", tone: "bad", icon: "cross" }, "a failure without an exit code keeps the cross");
  assert.deepEqual(row("error", { exit_code: 0 }).capsule, { text: "error", tone: "bad", icon: "cross" });
  assert.deepEqual(row("denied").capsule, { text: "denied", tone: "warn", icon: "lock" });
  assert.deepEqual(row("invalid").capsule, { text: "invalid", tone: "neutral", icon: "invalid" });
  assert.deepEqual(row("timeout").capsule, { text: "timeout", tone: "warn", icon: "clock" });
  assert.deepEqual(row("interrupted").capsule, { text: "interrupted", tone: "warn", icon: "interrupted" });
  const shapes = ["exit", "failed", "denied", "invalid", "timeout", "interrupted"].map((k) => C.TOOL_OUTCOME_LOOK[k].icon);
  assert.equal(new Set(shapes).size, 6, "one shape per outcome");
  assert.equal(row("denied").outcome, "denied");
  assert.match(row("denied").words, /Refused by policy/);
  assert.match(row("invalid").words, /nothing ran/);
  assert.match(row("error", { exit_code: 3 }).words, /exited with code 3/);
  assert.match(row("interrupted").words, /effects are unknown/);
  assert.equal(row("ok").words, "");
  assert.equal(C.toolOutcome(null).kind, "ok");
  assert.equal(C.toolOutcome({ status: "weird" }).kind, "failed", "an unknown status is not called ok");
  assert.deepEqual(C.toolRow({ state: "missing", result: null }).capsule, { text: "no result", tone: "warn", icon: "alert" });
});

test("a group counts each ToolStatus on its own and says so in its header", () => {
  reset();
  const store = storeOf([
    start(), call("c1"), result("c1", "ok"), call("c2"), result("c2", "error", { meta: { exit_code: 1 } }), call("c3"), result("c3", "error", { meta: { exit_code: 2 } }),
    call("c4"), result("c4", "denied"), call("c5"), result("c5", "invalid"), call("c6"), result("c6", "timeout"), call("c7"), result("c7", "interrupted"),
    call("c8"), result("c8", "error"), call("c9"), R("turn_end", { reason: "stopped" }),
  ]);
  const g = C.chatItems(store.blocks, { models: store.models }).find((i) => i.type === "group");
  assert.deepEqual([g.toolCount, g.exited, g.failed, g.denied, g.invalid, g.timedOut, g.interrupted, g.missing], [9, 2, 1, 1, 1, 1, 1, 1]);
  const label = C.groupLabel(g, 0);
  assert.match(label.text, / · 9 tool calls · 2 exited non-zero · 1 failed · 1 denied by policy · 1 invalid · 1 timed out · 1 interrupted · 1 without a result$/);
  assert.deepEqual([label.exited, label.denied, label.invalid, label.timedOut, label.interrupted], [2, 1, 1, 1, 1]);
  // the old shape of a group (no new counts) still reads
  assert.equal(C.groupLabel({ type: "group", toolCount: 2, failed: 1, missing: 0, running: false, startTs: 0, endTs: 5000 }, 0).text, "Worked for 5.0s · 2 tool calls · 1 failed");
  assert.equal(C.groupLabel({ type: "group", toolCount: 1, denied: 1, missing: 0, running: false, startTs: 0, endTs: 5000 }, 0).spoken, "Worked for 5.0s · 1 tool call · 1 denied by policy");
});

test("partialView marks a call whose output the model saw only in part", () => {
  const out = { id: "blob1", lines: 18442 };
  const cut = { status: "ok", cut: true, output: out, meta: { shown: [[1, 200]] } };
  assert.deepEqual(C.partialView(cut), { words: "The model was shown 200 of 18,442 lines (output cut).", shown: 200, total: 18442, cut: true });
  assert.equal(C.partialView({ status: "ok", cut: false, output: out, meta: { shown: [[1, 18442]] } }), null, "all shown");
  assert.equal(C.partialView({ status: "ok", cut: false, output: null, meta: {} }), null, "nothing stored, nothing cut");
  assert.equal(C.partialView({ status: "ok", cut: true, output: null, meta: {} }).words, "Output was cut.");
  assert.equal(C.partialView({ status: "ok", output: out, meta: { of_blob: "blob1", shown: [[10, 20]] } }), null, "a view the model asked for is not a cut");
  assert.equal(C.partialView({ status: "ok", output: { id: "b", lines: 10 }, meta: { shown: [[1, 4]] } }).shown, 4);
  assert.equal(C.partialView(null), null);
  const r = C.toolRow({ kind: "tool", name: "bash", cls: "exec", state: "done", result: { ...cut, shown: C.shownOfTotal(cut) } });
  assert.equal(r.partial.words, "The model was shown 200 of 18,442 lines (output cut).");
  assert.equal(C.toolRow({ kind: "tool", name: "bash", state: "done", result: { status: "ok", meta: {} } }).partial, null);
  // counted by the group
  reset();
  const store = storeOf([start(), call("c1"), result("c1", "ok", { cut: true, output: out, meta: { shown: [[1, 200]] } }), call("c2"), result("c2")]);
  assert.equal(C.chatItems(store.blocks, { models: store.models }).find((i) => i.type === "group").partial, 1);
});

test("chatItems puts a 'New since your last visit' item at the watermark, and windowItems keeps it with what follows", () => {
  reset();
  const store = storeOf([
    start(), R("user_message", { text: "go" }, undefined, "user"), call("c1"), result("c1"), reply("r1", "one"), // seqs 0..4
    R("user_message", { text: "more" }, undefined, "user"), reply("r2", "two"),                                 // 5, 6
  ]);
  const items = C.chatItems(store.blocks, { models: store.models, sinceSeq: 4 });
  assert.deepEqual(kinds(items), ["user", "model", "group", "response", "since", "user", "model", "response"]);
  const at = items.findIndex((i) => i.type === "since");
  assert.deepEqual(kinds(items).slice(at - 1, at + 2), ["response", "since", "user"]);
  assert.deepEqual([items[at].seq, items[at].count, items[at].straddles, items[at].text], [4, 2, false, "New since your last visit · 2 records"]);
  // nothing new, or everything new, or no watermark: no item
  assert.equal(C.chatItems(store.blocks, { models: store.models, sinceSeq: 6 }).some((i) => i.type === "since"), false);
  assert.equal(C.chatItems(store.blocks, { models: store.models, sinceSeq: -1 }).some((i) => i.type === "since"), false, "everything is new: no divider");
  assert.equal(C.chatItems(store.blocks, { models: store.models }).some((i) => i.type === "since"), false);
  assert.equal(C.chatItems(store.blocks, { models: store.models, sinceSeq: null }).some((i) => i.type === "since"), false);
  // one new record reads in the singular; a tool's result counts on its own
  assert.equal(C.chatItems(store.blocks, { models: store.models, sinceSeq: 5 }).find((i) => i.type === "since").text, "New since your last visit · 1 record");
  const r1 = C.chatItems(store.blocks, { models: store.models, sinceSeq: 2 });
  assert.equal(r1.find((i) => i.type === "since").count, 4, "result 3, reply 4, user 5, reply 6");
  assert.equal(r1.find((i) => i.type === "since").straddles, true, "the group began before it");
  assert.equal(r1[r1.findIndex((i) => i.type === "since") + 1].type, "group");
  // the last item is still the last real item
  assert.equal(items.at(-1).last, true);
  assert.notEqual(items.find((i) => i.type === "since").last, true);
  // a model chip that opens the new part moves the divider before it
  const sw = storeOf((reset(), [start(), reply("a", "x"), R("model_switched", { from: MODEL_A, to: MODEL_B, reason: "operator" }), reply("b", "y")]));
  const si = C.chatItems(sw.blocks, { models: sw.models, sinceSeq: 1 });
  assert.deepEqual(kinds(si), ["model", "response", "since", "line", "model", "response"]);
  assert.equal(si[2].count, 2);
  // when the chip itself is the first new thing, the divider goes before the chip
  const chipFirst = C.chatItems([{ id: 0, kind: "user", seq: 1, ts: 1, text: "a" }, { id: 1, kind: "response", seq: 5, ts: 1, text: "b" }], { models: [{ seq: 0, profile: "p", model: "m", context_window: 0 }], sinceSeq: 3 });
  assert.deepEqual(kinds(chipFirst), ["user", "since", "model", "response"]);
  // windowItems drops a divider whose item is out of the window and keeps one whose item stays
  const all = C.chatItems(store.blocks, { models: store.models, sinceSeq: 4 });
  const idOf = (it) => (it.type === "block" ? it.block.id : it.type === "group" ? it.blocks[0].id : -1);
  const firstNew = all[all.findIndex((i) => i.type === "since") + 1];
  assert.equal(C.windowItems(all, idOf(firstNew)).some((i) => i.type === "since"), true);
  assert.equal(C.windowItems(all, idOf(firstNew) + 1).some((i) => i.type === "since"), false);
});

test("recordsAfter counts new records for Jump, and jumpLabel says it", () => {
  reset();
  const store = storeOf([start(), call("c1"), R("user_message", { text: "x" }, undefined, "user"), result("c1"), reply("r", "t")]); // 0..4, the start is no block
  assert.equal(C.recordsAfter(store.blocks, -1), 4);
  assert.equal(C.recordsAfter(store.blocks, 1), 3);
  assert.equal(C.recordsAfter(store.blocks, 2), 2, "the result (3) and the reply (4)");
  assert.equal(C.recordsAfter(store.blocks, 4), 0);
  assert.equal(C.recordsAfter(store.blocks, null), 0);
  assert.equal(C.recordsAfter(null, 1), 0);
  assert.equal(C.jumpLabel(0), "Jump to latest");
  assert.equal(C.jumpLabel(12), "Jump to latest · 12 new");
  assert.equal(C.jumpLabel(12000), "Jump to latest · 12,000 new");
});

test("findInRecord: literal, over every loaded block including folded groups, with an honest count", () => {
  reset();
  const recs = [start(), R("user_message", { text: "Check port 8443 please" }, undefined, "user"), reply("r1", "", { tool_calls: [{ call_id: "c1", name: "bash", arguments: "{}", complete: true }] })];
  recs.push(call("c1"), result("c1", "ok", { text: "listening on PORT 8443\nand more" }));
  recs.push(call("c2"), result("c2", "denied", { text: "refused by sandbox" }));
  recs.push(call("c3"), result("c3", "error", { text: "no such file", meta: { exit_code: 2 } }));
  recs.push(reply("r2", "The [port] (8443) is open. a.b"), R("inbox_opened", { item_id: "i1", item_kind: "question", text: "Scan 8443 too?", options: [], blocking: false }));
  const store = storeOf(recs);
  const all = C.findInRecord(store.blocks, "8443");
  assert.equal(all.count, 4);
  assert.deepEqual(all.hits.map((h) => h.field), ["text", "result", "text", "text"]);
  assert.deepEqual(all.hits.map((h) => h.id), [...all.hits.map((h) => h.id)].sort((a, b) => a - b), "record order");
  assert.equal(all.hits[1].seq, store.blocks[all.hits[1].id].result.seq, "a hit in an output jumps to the result record");
  assert.deepEqual(all.hits[1].snippet, { before: "listening on PORT ", match: "8443", after: " and more" }, "case-insensitive on the text around it; the match keeps its own case");
  assert.equal(all.searched, 10, "every loaded record, tools counted as call and result");
  assert.equal(C.findInRecord(store.blocks, "  8443 ").query, "8443");
  assert.equal(C.findInRecord(store.blocks, "8443", "messages").count, 3);
  assert.equal(C.findInRecord(store.blocks, "8443", "tools").count, 1);
  assert.equal(C.findInRecord(store.blocks, "refused", "failures").count, 1);
  assert.equal(C.findInRecord(store.blocks, "no such", "failures").count, 1);
  assert.equal(C.findInRecord(store.blocks, "listening", "failures").count, 0, "an ok call is not a failure");
  assert.equal(C.findInRecord(store.blocks, "listening", "nonsense").count, 1, "an unknown kind is all");
  assert.equal(C.findInRecord(store.blocks, "(8443)").count, 1, "literal, not a pattern");
  assert.equal(C.findInRecord(store.blocks, "a.b").count, 1);
  assert.equal(C.findInRecord(store.blocks, "a.c").count, 0, "the dot is not a wildcard");
  assert.equal(C.findInRecord(store.blocks, "bash").count, 3, "a call is found by its name");
  assert.equal(C.findInRecord(store.blocks, "").count, 0);
  assert.equal(C.findInRecord(null, "x").count, 0);
  // inside a folded group and outside the rendered window: the search reads blocks, not the page
  const items = C.chatItems(store.blocks, { models: store.models });
  const inGroup = items.find((i) => i.type === "group" && !i.open);
  assert.ok(inGroup, "the group is folded");
  assert.ok(all.hits.some((h) => inGroup.blocks.some((b) => b.id === h.id)));
});

test("findWords: the count wording is honest about scope and cut outputs", () => {
  const r = { query: "x", count: 17, capped: false, searched: 12480, cutOutputs: 0 };
  assert.equal(C.findWords(r, 2), "3 of 17 in 12,480 loaded records");
  assert.equal(C.findWords(r), "17 matches in 12,480 loaded records");
  assert.equal(C.findWords({ ...r, count: 1 }), "1 match in 12,480 loaded records");
  assert.equal(C.findWords({ ...r, count: 0 }), "No match in 12,480 loaded records");
  assert.equal(C.findWords({ ...r, searched: 1, count: 0 }), "No match in 1 loaded record");
  assert.equal(C.findWords({ ...r, capped: true, count: 2000 }, 0), "1 of 2,000+ in 12,480 loaded records");
  assert.equal(C.findWords({ ...r, cutOutputs: 2 }, 0), "1 of 17 in 12,480 loaded records. 2 outputs cut before the end: search them in the output viewer");
  assert.match(C.findWords({ ...r, cutOutputs: 1 }), /1 output cut before the end: search it in the output viewer$/);
  assert.equal(C.findWords({ ...r, query: "" }), "");
  assert.equal(C.findWords(null), "");
  assert.equal(C.findWords(r, 99), "17 matches in 12,480 loaded records", "an index outside the hits is no position");
  // cut outputs are counted from what was searched
  reset();
  const store = storeOf([start(), call("c1"), result("c1", "ok", { text: "found", cut: true, output: { id: "b", lines: 5000 } }), call("c2"), result("c2", "ok", { text: "found" })]);
  const res = C.findInRecord(store.blocks, "found");
  assert.equal(res.cutOutputs, 1);
  assert.match(C.findWords(res, 0), /^1 of 2 in 4 loaded records\. 1 output cut/);
});

test("findInRecord stays quick over 100k records", () => {
  const blocks = Array.from({ length: 100000 }, (_, i) => ({ id: i, seq: i, kind: "response", text: i === 99999 ? "the needle here" : "plain text " + i }));
  const t0 = performance.now();
  const r = C.findInRecord(blocks, "needle");
  assert.equal(r.count, 1);
  assert.equal(r.searched, 100000);
  assert.ok(performance.now() - t0 < 500);
  assert.equal(C.findInRecord(blocks, "plain", "all").capped, true);
  assert.equal(C.findInRecord(blocks, "plain", "all").count, 2000);
});

test("progressLine: plan, the step in progress, and the budget as a limit", () => {
  const plan = [{ text: "recon", status: "done" }, { text: "scan the hosts and read the first banner", status: "doing" }, { text: "report", status: "todo" }, { text: "old", status: "dropped" }];
  const p = C.progressLine({ plan, step: 214, budget: { max_steps: 400, max_minutes: 480 }, minutes: 3 * 60 + 12 });
  assert.equal(p.text, "Plan 1 of 3 done · now: scan the hosts and read the first banner · budget 214 of 400 steps · 3h12m of 8h");
  assert.deepEqual(p.parts.map((x) => x.key), ["plan", "now", "budget"]);
  assert.match(p.label, /The budget is a limit, not a measure of progress\.$/);
  assert.equal(C.progressLine({ plan: [{ text: "a", status: "todo" }] }).text, "Plan 0 of 1 done");
  assert.equal(C.progressLine({ plan: [{ text: "a", status: "todo" }] }).label, "Plan 0 of 1 done", "no budget, no caveat");
  assert.equal(C.progressLine({ step: 9, budget: { max_steps: 100 } }).text, "budget 9 of 100 steps");
  assert.equal(C.progressLine({ budget: { max_minutes: 45 }, minutes: 12 }).text, "budget 12m of 45m");
  assert.equal(C.progressLine({ budget: { max_minutes: 90 }, minutes: 70 }).text, "budget 1h10m of 1h30m");
  assert.equal(C.progressLine({ budget: { max_minutes: 45 } }), null, "a limit with no known start is not a figure");
  assert.equal(C.progressLine({ plan: [{ text: "x", status: "dropped" }], step: 5, budget: {} }), null);
  assert.equal(C.progressLine({ plan: [], budget: { max_steps: null, max_minutes: null } }), null, "nothing known: hidden");
  assert.equal(C.progressLine(), null);
  assert.equal(C.progressLine({ plan: [{ text: "x", status: "done" }, { text: "y", status: "done" }] }).text, "Plan 2 of 2 done");
});

test("parseRoute and sessionHash know the Agents tab", () => {
  assert.equal(C.sessionHash("s-1", "agents"), "#/s/s-1/agents");
  assert.deepEqual(C.parseRoute("#/s/s-1/agents"), { view: "session", session: "s-1", section: "agents" });
  assert.equal(C.sessionHash("s-1", "nope"), "#/s/s-1/chat");
});

// The drawings the new outcomes name.
test("the icon template draws the pass-2 shapes", () => {
  const html = readFileSync(join(here, "index.html"), "utf8");
  const drawn = new Set([...html.match(/<template id="icons">([\s\S]*?)<\/template>/)[1].matchAll(/data-icon="([a-z-]+)"/g)].map((m) => m[1]));
  const named = new Set(Object.values(C.TOOL_OUTCOME_LOOK).map((l) => l.icon));
  named.add(C.quietFor(info("a", { status: st({ phase: "running" }) }), { ts: 0 }, 1e9).icon);
  for (const name of named) assert.ok(drawn.has(name), `index.html has no drawing for "${name}"`);
});

// ---- keyboard

test("typingTarget: text fields type, buttons and checkboxes do not", () => {
  assert.equal(C.typingTarget({ tagName: "TEXTAREA" }), true);
  assert.equal(C.typingTarget({ tagName: "SELECT" }), true);
  assert.equal(C.typingTarget({ tagName: "INPUT", type: "search" }), true);
  assert.equal(C.typingTarget({ tagName: "INPUT" }), true);
  assert.equal(C.typingTarget({ tagName: "INPUT", type: "checkbox" }), false);
  assert.equal(C.typingTarget({ tagName: "DIV", isContentEditable: true }), true);
  assert.equal(C.typingTarget({ tagName: "BUTTON" }), false);
  assert.equal(C.typingTarget(null), false);
});

test("shortcutFor: Ctrl/Cmd+K anywhere, other keys never while typing, Escape and Stop have none", () => {
  const f = (e, o) => C.shortcutFor({ key: "", ...e }, o);
  assert.equal(f({ key: "k", ctrlKey: true }, { typing: true }), "switch");
  assert.equal(f({ key: "K", metaKey: true }), "switch");
  assert.equal(f({ key: "k" }), null, "a bare k is nothing");
  assert.equal(f({ key: "k", ctrlKey: true }, { mac: true, typing: true }), null, "on a Mac Ctrl+K stays the system's delete-to-end-of-line");
  assert.equal(f({ key: "k", metaKey: true }, { mac: true }), "switch");
  assert.equal(f({ key: "k", metaKey: true }, { mac: false }), null, "elsewhere only Ctrl");
  assert.equal(f({ key: "k", ctrlKey: true }, { mac: false }), "switch");
  assert.equal(f({ key: "/", shiftKey: true }), "find", "a layout where / needs Shift");
  assert.equal(f({ key: "/" }), "find");
  assert.equal(f({ key: "/" }, { typing: true }), null);
  assert.equal(f({ key: "?", shiftKey: true }), "keys");
  assert.equal(f({ key: "?" }, { typing: true }), null);
  assert.equal(f({ key: "ArrowDown", altKey: true }), "row-next");
  assert.equal(f({ key: "ArrowUp", altKey: true }), "row-prev");
  assert.equal(f({ key: "ArrowDown", altKey: true, shiftKey: true }), "needs-next");
  assert.equal(f({ key: "ArrowUp", altKey: true, shiftKey: true }), "needs-prev");
  assert.equal(f({ key: "ArrowDown", altKey: true }, { typing: true }), null);
  assert.equal(f({ key: "ArrowDown" }), null);
  assert.equal(f({ key: "/", ctrlKey: true }), null, "a browser chord is left alone");
  assert.equal(f({ key: "k", ctrlKey: true, isComposing: true }), null);
  for (const key of ["Escape", "s", "c", "x", "."]) assert.equal(f({ key, ctrlKey: key === "c" }), null, key + " binds nothing");
});

test("stepIndex steps without wrapping and starts at an end", () => {
  assert.equal(C.stepIndex(0, -1, 1), null);
  assert.equal(C.stepIndex(3, -1, 1), 0);
  assert.equal(C.stepIndex(3, -1, -1), 2);
  assert.equal(C.stepIndex(3, 0, 1), 1);
  assert.equal(C.stepIndex(3, 2, 1), null);
  assert.equal(C.stepIndex(3, 0, -1), null);
  assert.equal(C.stepIndex(3, 9, -1), 2);
});

test("keySheet lists real keys, spells Cmd and Option on a Mac, and offers no key to stop", () => {
  const flat = (mac) => C.keySheet(mac).flatMap((g) => g.rows);
  assert.ok(flat(false).some((r) => r.keys.join("+") === "Ctrl+K"));
  assert.ok(flat(true).some((r) => r.keys.join("+") === "Cmd+K"));
  assert.ok(flat(true).some((r) => r.keys.join("+") === "Option+Shift+↓"));
  assert.ok(!flat(false).some((r) => /stop|interrupt/i.test(r.text.replace(/never stops anything/, ""))));
});

test("foldConfirm names the session and says what a fold does", () => {
  const q = C.foldConfirm("Fix the flaky test");
  assert.match(q.text, /^Fold Fix the flaky test's context now\? Older outputs become stubs that keep their out: handles; the next request re-reads the whole prompt once\.$/);
  assert.equal(q.yes, "Fold now");
  assert.match(C.foldConfirm().text, /^Fold the context of this session now\?/);
});

test("lastRecordedError reads the failure sentence the daemon records in a parked item or a failed-request answer", () => {
  const parked = { kind: "inbox", item: { item_kind: "parked", text: "The session could not continue. The model request failed after 3 attempts: connection refused: http://x/v1 Nothing was lost: answer here, or send the session a message, to make it try again." }, resolved: null };
  assert.equal(C.lastRecordedError([parked]), "The model request failed after 3 attempts: connection refused: http://x/v1");
  const unavailable = { kind: "inbox", item: { item_kind: "blocker", text: "The model server at http://x has been unavailable since 2026-11-12 14:03:07 UTC." }, resolved: { answer: "Answered automatically: the request ended without a reply at 2026-11-12 14:09:41 UTC: request timed out. The session handles that as any failed request." } };
  assert.equal(C.lastRecordedError([parked, unavailable]), "request timed out.", "the latest one");
  assert.equal(C.lastRecordedError([unavailable, parked]), "The model request failed after 3 attempts: connection refused: http://x/v1");
  assert.equal(C.lastRecordedError([{ kind: "inbox", item: { item_kind: "parked", text: "The session could not continue. The session's budget is used up. Nothing was lost: answer." }, resolved: null }]), null, "a budget end is not an error");
  assert.equal(C.lastRecordedError([{ kind: "line", sub: "interrupted", reason: "model request failed: x" }]), null, "an interruption is an operator stop, a restart or damage, not a failure");
  assert.equal(C.lastRecordedError([]), null);
  assert.equal(C.lastRecordedError(null), null);
});

test("inboxGroups puts missions that block first, each group oldest first", () => {
  const mk = (id, mission, blocking, at) => [id, { session: id, mission, title: "t-" + id, opened_ms: at, item: { item_id: id, item_kind: blocking ? "question" : "finished", blocking } }];
  const inbox = { items: new Map([mk("a", "m1", false, 10), mk("b", "m2", true, 30), mk("c", "m1", true, 50), mk("d", "m3", false, 5), mk("e", "m2", false, 1)]) };
  const g = C.inboxGroups(inbox, (m) => "Mission " + m);
  assert.deepEqual(g.map((x) => x.mission), ["m2", "m1", "m3"]);
  assert.deepEqual(g[0].entries.map((e) => e.item.item_id), ["b", "e"]);
  assert.deepEqual([g[0].open, g[0].blocking, g[2].blocking], [2, 1, 0]);
  assert.equal(g[0].title, "Mission m2");
  assert.deepEqual(C.inboxGroups({ items: new Map() }), []);
  const lone = C.inboxGroups({ items: new Map([mk("z", "", true, 1)]) });
  assert.equal(lone[0].title, "t-z");
});

test("refusalAnswer needs a reason and prefixes it; isRefusal reads it back", () => {
  assert.ok(C.refusalAnswer("  ").error);
  assert.equal(C.refusalAnswer(" too broad ").answer, "Refused: too broad");
  assert.ok(C.isRefusal("Refused: x"));
  assert.ok(!C.isRefusal("Keep going"));
});

test("answerSendKey is Ctrl or Cmd with Enter only", () => {
  assert.ok(C.answerSendKey({ key: "Enter", ctrlKey: true }));
  assert.ok(C.answerSendKey({ key: "Enter", metaKey: true }));
  assert.ok(!C.answerSendKey({ key: "Enter" }));
  assert.ok(!C.answerSendKey({ key: "Enter", ctrlKey: true, isComposing: true }));
  assert.ok(!C.answerSendKey({ key: "Enter", ctrlKey: true, shiftKey: true }));
});

test("nextCardId prefers the card after, then the one before", () => {
  assert.equal(C.nextCardId(["a", "b", "c"], "b"), "c");
  assert.equal(C.nextCardId(["a", "b", "c"], "c"), "b");
  assert.equal(C.nextCardId(["a"], "a"), null);
  assert.equal(C.nextCardId(["a", "b"], "zz"), "a");
});

test("missionEnding: a root lead ends by going idle with last_end, as the daemon records it", () => {
  const was = info("m", { title: "Mission", status: st({ phase: "running" }) });
  const idle = (last_end) => info("m", { title: "Mission", status: st({ phase: "idle", last_end }) });
  assert.equal(C.missionEnding(was, idle("finished")).outcome, "done");
  assert.equal(C.missionEnding(was, idle("error")).outcome, "failed");
  assert.equal(C.missionEnding(was, idle("budget_exhausted")).outcome, "budget_exhausted");
  assert.equal(C.missionEnding(was, idle("stopped")).outcome, "stopped");
  assert.equal(C.missionEnding(was, idle("yielded")), null, "every ordinary chat reply is a yield");
  assert.equal(C.missionEnding(was, idle("waiting")), null);
  assert.equal(C.missionEnding(was, idle("asked")), null);
  assert.equal(C.missionEnding(idle("finished"), idle("finished")), null, "already idle");
  assert.equal(C.missionEnding(was, idle("stopped"), { requested: new Set(["m"]) }), null);
});

test("planNotifications: a mission ending and its own Finished item are one notice that opens the session", () => {
  const end = C.noticeOfEnding({ session: "m", mission: "m-m", title: "Mission", outcome: "done", words: "done" }, 1000);
  const item = C.noticeOfInbox({ session: "m", title: "Mission", item: { item_id: "i1", item_kind: "finished", text: "All done", blocking: false, options: [] } }, 1100);
  const plan = C.planNotifications([end, item], { now: 7000 });
  assert.equal(plan.notification.target.hash, "#/s/m/chat");
  assert.equal(plan.notification.title, "Mission finished");
  assert.deepEqual(plan.notification.covers.sort(), ["end:m", "i1"]);
});

test("budgetUsed: active intervals and own steps since the budget was last granted, as the daemon counts them", () => {
  const store = C.createRecordStore("s");
  let seq = 0;
  const rec = (kind, ts_ms, more = {}) => C.applyRecord(store, { seq: seq++, kind, ts_ms, author: "harness", ...more });
  const min = 60000;
  rec("session_start", 0, { budget: { max_steps: 400, max_minutes: 480 } });
  rec("turn_start", 0, { trigger: "start" });
  rec("budget_clock", 0, { running: true });
  rec("model_request", 1 * min, { req_id: "a", step: 1, epoch: 0, est_tokens: 10, purpose: "step" });
  rec("model_request", 2 * min, { req_id: "b", step: 2, epoch: 0, est_tokens: 10, purpose: "summary" });
  rec("budget_clock", 10 * min, { running: false });
  rec("turn_end", 10 * min, { reason: "waiting" });
  // Parked for a day: the clock was paused, so only 10 active minutes count.
  assert.deepEqual(C.budgetUsed(store, 27 * 60 * min), { steps: 1, minutes: 10 });
  rec("turn_start", 27 * 60 * min, { trigger: "user" });
  rec("budget_clock", 27 * 60 * min, { running: true });
  assert.equal(C.budgetUsed(store, 27 * 60 * min + 5 * min).minutes, 15, "an open interval counts up to now");
  rec("turn_end", 27 * 60 * min + 6 * min, { reason: "budget_exhausted" });
  assert.equal(C.budgetUsed(store, 40 * 60 * min).minutes, 16, "closed at the end of the turn");
  rec("turn_start", 40 * 60 * min, { trigger: "user" });
  assert.deepEqual(C.budgetUsed(store, 40 * 60 * min), { steps: 0, minutes: 0 }, "a renewed budget starts again");
  const wall = C.createRecordStore("w");
  C.applyRecord(wall, { seq: 0, kind: "session_start", ts_ms: 1000, author: "harness" });
  assert.equal(C.budgetUsed(wall, 1000 + 7 * min).minutes, 7, "a log with no budget_clock keeps wall time");
  assert.equal(C.progressLine({ step: 450, minutes: 600, budget: { max_steps: 400, max_minutes: 480 } }).text, "budget 400 of 400 steps · 8h of 8h", "never above the limit");
});

test("cardResolution: an approved scope request does not read as dismissed", () => {
  const scope = { item_id: "i", item_kind: "approval", blocking: false, options: ["a.example", "B.example"], text: "" };
  const done = { seq: 9, ts: 1, answer: "" };
  assert.deepEqual(C.cardResolution(scope, done, { answer: "", approved: ["a.example"] }, null).approved, ["a.example"], "this tab's receipt wins over the record");
  assert.deepEqual(C.cardResolution(scope, done, undefined, ["A.example", "b.example"]).approved, ["a.example", "B.example"], "after a reload: the hosts are in the grants");
  assert.equal(C.cardResolution(scope, done, undefined, ["a.example"]).approved, undefined, "only some granted: not claimed");
  assert.equal(C.cardResolution(scope, done, undefined, null).approved, undefined, "grants unknown: not claimed");
  assert.equal(C.cardResolution(scope, { ...done, answer: "Refused: no" }, undefined, ["a.example", "b.example"]).approved, undefined);
  assert.deepEqual(C.cardResolution(scope, null, { answer: "x" }, null), { answer: "x" });
});

test("quietFor: nothing while the stream is down, and only the time the page has listened counts", () => {
  const now = 10 * 3600000;
  const run = info("a", { status: st({ phase: "running" }) });
  assert.equal(C.quietFor(run, { ts: now - 3 * 3600000 }, now, null), null, "disconnected");
  assert.equal(C.quietFor(run, { ts: now - 2 * 3600000 }, now, now - 2 * 60000), null, "reconnected 2 minutes ago, record 2 h old");
  const q = C.quietFor(run, { ts: now - 2 * 3600000 }, now, now - 11 * 60000);
  assert.equal(q.text, "no new record for 11m", "listened 11 minutes and heard nothing");
  assert.equal(C.quietFor(run, { ts: now - 30 * 60000 }, now, now - 3600000).text, "no new record for 30m", "a record heard since connecting keeps its own age");
  assert.equal(C.quietFor(run, { ts: now - 30 * 60000 }, now).text, "no new record for 30m", "since not given: as before");
});

test("record counts are honest: new and loaded records include the ones that make no block", () => {
  reset();
  const store = storeOf([start(), call("c1"), R("user_message", { text: "x" }, undefined, "user"), result("c1"), reply("r", "t")]);
  assert.equal(C.recordsAfter(store.blocks, 1, C.lastSeq(store)), 3);
  assert.equal(C.recordsAfter(store.blocks, 4, C.lastSeq(store)), 0);
  assert.equal(C.recordsAfter(store.blocks, 9, C.lastSeq(store)), 0);
  assert.equal(C.findInRecord(store.blocks, "x", "all", store.records.size).searched, store.records.size);
});

test("findSnippet and findHint: what matched is said in words, and the cut-output sentence stands apart", () => {
  reset();
  const r = C.findInRecord(storeOf([start(), reply("r", "the shutdown waits on the flush")]).blocks, "waits");
  assert.equal(C.findSnippet(r.hits[0]), "…the shutdown waits on the flush…");
  assert.equal(C.findHint({ query: "x", cutOutputs: 1 }), "1 output cut before the end: search it in the output viewer");
  assert.equal(C.findHint({ query: "x", cutOutputs: 0 }), "");
  assert.equal(C.findWords({ query: "x", searched: 5, count: 1, cutOutputs: 1 }, 0, false), "1 of 1 in 5 loaded records");
});

test("mergeInboxList: a record that landed while the snapshot was out outranks it", () => {
  const e = (id) => ({ session: "s", mission: "m", title: "t", opened_ms: 1, item: { item_id: id, item_kind: "question", text: id, options: [], blocking: true } });
  const touched = new Map([["gone", { rev: 5, entry: null }], ["new", { rev: 6, entry: e("new") }], ["old", { rev: 2, entry: null }]]);
  const ids = (l) => l.map((x) => x.item.item_id).sort();
  assert.deepEqual(ids(C.mergeInboxList([e("gone"), e("old"), e("kept")], touched, 4)), ["kept", "new", "old"], "a change from before the request is already in the snapshot");
  assert.deepEqual(ids(C.mergeInboxList([e("kept")], new Map(), 0)), ["kept"]);
});

// ---- workspace folders: picker, create flow, Files tab ----

test("byteSize and fsDirsUrl", () => {
  assert.equal(C.byteSize(812), "812 B");
  assert.equal(C.byteSize(1536), "1.5 KiB");
  assert.equal(C.byteSize(4 * 1024 * 1024), "4.0 MiB");
  assert.equal(C.byteSize(300 * 1024), "300 KiB");
  assert.equal(C.byteSize(-3), "0 B");
  assert.equal(C.fsDirsUrl(""), "/api/fs/dirs");
  assert.equal(C.fsDirsUrl("~/a b"), "/api/fs/dirs?path=~%2Fa%20b");
});

test("picker paths: join, parent, breadcrumbs", () => {
  assert.equal(C.joinPath("/", "x"), "/x");
  assert.equal(C.joinPath("/a/b", "c"), "/a/b/c");
  assert.equal(C.joinPath("/a/b/", "c"), "/a/b/c");
  assert.equal(C.parentPath("/a/b"), "/a");
  assert.equal(C.parentPath("/a"), "/");
  assert.equal(C.parentPath("/"), null);
  assert.equal(C.parentPath("rel"), null);
  assert.deepEqual(C.pathCrumbs("/Users/me/code"), [
    { name: "/", path: "/" }, { name: "Users", path: "/Users" }, { name: "me", path: "/Users/me" }, { name: "code", path: "/Users/me/code" },
  ]);
  assert.deepEqual(C.pathCrumbs("/"), [{ name: "/", path: "/" }]);
  assert.deepEqual(C.pathCrumbs("relative"), []);
});

test("recentWorkspaces: newest first, each once, activity counts", () => {
  const infos = [
    { id: "a", workspace: "/w/one", created_ms: 100 },
    { id: "b", workspace: "/w/two", created_ms: 300 },
    { id: "c", workspace: "/w/one", created_ms: 200 },
    { id: "d", workspace: "", created_ms: 900 },
    { id: "e", workspace: "/w/three", created_ms: 50 },
  ];
  assert.deepEqual(C.recentWorkspaces(infos), ["/w/two", "/w/one", "/w/three"]);
  // A record seen later in /w/three moves it up.
  assert.deepEqual(C.recentWorkspaces(infos, new Map([["e", { ts: 1000 }]])), ["/w/three", "/w/two", "/w/one"]);
  assert.deepEqual(C.recentWorkspaces(infos, new Map(), 2), ["/w/two", "/w/one"]);
  assert.deepEqual(C.recentWorkspaces([]), []);
});

test("visibleDirs hides dot folders unless asked", () => {
  const entries = [{ name: "src", hidden: false }, { name: ".git", hidden: true }];
  assert.deepEqual(C.visibleDirs(entries, false).map((e) => e.name), ["src"]);
  assert.deepEqual(C.visibleDirs(entries, true).map((e) => e.name), ["src", ".git"]);
});

test("checkFolderName validates a new folder's name", () => {
  assert.deepEqual(C.checkFolderName("  notes "), { name: "notes" });
  for (const bad of ["", "   ", ".", "..", "a/b", "a\\b", "bad\u0001name", "x".repeat(256)]) assert.ok(C.checkFolderName(bad).error, JSON.stringify(bad));
  assert.match(C.checkFolderName("src", ["src"]).error, /already exists/);
  assert.equal(C.checkFolderName("é".repeat(127)).name, "é".repeat(127));
  assert.ok(C.checkFolderName("é".repeat(128)).error);
});

test("creating a missing workspace: the flag, the detection and the question", () => {
  const base = { workspace: " /w/new ", message: "go", role: "lead", unattended: true };
  assert.equal("create_workspace" in C.buildNewSession(base).body, false);
  assert.equal(C.buildNewSession({ ...base, createWorkspace: true }).body.create_workspace, true);
  assert.equal(C.buildNewSession({ ...base, createWorkspace: true }).body.workspace, "/w/new");
  assert.ok(C.missingWorkspaceError("The workspace /w/new does not exist. Create it from the UI or run `loom run --create-workspace`."));
  assert.ok(!C.missingWorkspaceError("The workspace is inside the loom home."));
  assert.ok(!C.missingWorkspaceError("The workspace rel/x is a relative path that does not exist. Give an absolute path, or one that starts with ~/."));
  assert.equal(C.createWorkspaceQuestion("/w/new"), "/w/new does not exist. Create it and start the mission?");
});

test("relative paths of the Files tab", () => {
  assert.equal(C.relJoin("", "a"), "a");
  assert.equal(C.relJoin("a/b", "c"), "a/b/c");
  assert.equal(C.relParent("a/b"), "a");
  assert.equal(C.relParent("a"), "");
  assert.equal(C.relParent(""), null);
  assert.deepEqual(C.relCrumbs(""), [{ name: "workspace", path: "" }]);
  assert.deepEqual(C.relCrumbs("src/ui"), [{ name: "workspace", path: "" }, { name: "src", path: "src" }, { name: "ui", path: "src/ui" }]);
  assert.equal(C.filesUrl("s-1", ""), "/api/sessions/s-1/files");
  assert.equal(C.filesUrl("s-1", "a b/c"), "/api/sessions/s-1/files?path=a%20b%2Fc");
  assert.equal(C.fileLinesUrl("s-1", "a/b.txt", 1, 1000), "/api/sessions/s-1/files/lines?path=a%2Fb.txt&start=1&count=1000");
});

test("workspaceRelative: inside the workspace only", () => {
  const ws = "/w/proj";
  assert.equal(C.workspaceRelative(ws, "/w/proj/src/a.rs"), "src/a.rs");
  assert.equal(C.workspaceRelative(ws, "/w/proj"), "");
  assert.equal(C.workspaceRelative(ws + "/", "/w/proj/x"), "x");
  assert.equal(C.workspaceRelative(ws, "/w/proj/a/../b"), "b");
  assert.equal(C.workspaceRelative(ws, "/w/proj/../other/x"), null);
  assert.equal(C.workspaceRelative(ws, "/w/project/x"), null);
  assert.equal(C.workspaceRelative(ws, "/etc/hosts"), null);
  assert.equal(C.workspaceRelative(ws, "src/a.rs"), "src/a.rs");
  assert.equal(C.workspaceRelative(ws, "./src//a.rs"), "src/a.rs");
  assert.equal(C.workspaceRelative(ws, "../a"), null);
  assert.equal(C.workspaceRelative(ws, "a/../../b"), null);
  assert.equal(C.workspaceRelative(ws, "~/a"), null);
  assert.equal(C.workspaceRelative(ws, ""), null);
  assert.equal(C.workspaceRelative("relative", "a"), null);
});

test("openFileTarget follows path arguments of file tools", () => {
  const ws = "/w/proj";
  assert.equal(C.openFileTarget({ name: "read", args: { path: "src/a.rs" } }, ws), "src/a.rs");
  assert.equal(C.openFileTarget({ name: "edit", args: { file_path: "/w/proj/b.txt" } }, ws), "b.txt");
  assert.equal(C.openFileTarget({ name: "grep", args: { pattern: "x", path: "src" } }, ws), "src");
  assert.equal(C.openFileTarget({ name: "read", args: { path: "/etc/hosts" } }, ws), null);
  assert.equal(C.openFileTarget({ name: "bash", args: { command: "cat a" } }, ws), null);
  assert.equal(C.openFileTarget({ name: "read", args: null }, ws), null);
  assert.equal(C.openFileTarget({ name: "read", args: ["a"] }, ws), null);
  assert.equal(C.openFileTarget(null, ws), null);
});

test("Files rows: hidden, filter, harness entry, words", () => {
  const entries = [
    { name: "src", kind: "dir", size: 0, mtime_ms: 1 }, { name: ".loom", kind: "dir", size: 0, mtime_ms: 0, hidden: true, note: "harness files are not shown" },
    { name: ".env", kind: "file", size: 5, mtime_ms: 1 }, { name: "Readme.md", kind: "file", size: 5, mtime_ms: 1 },
    { name: "out", kind: "link", size: 0, mtime_ms: 1 }, { name: "locked", kind: "dir", error: "permission denied" },
  ];
  assert.deepEqual(C.fileRows(entries).map((e) => e.name), ["src", "Readme.md", "out", "locked"]);
  assert.deepEqual(C.fileRows(entries, { showHidden: true }).map((e) => e.name), ["src", ".loom", ".env", "Readme.md", "out", "locked"]);
  assert.deepEqual(C.fileRows(entries, { query: " READ" }).map((e) => e.name), ["Readme.md"]);
  assert.deepEqual(C.fileRows(null), []);
  assert.equal(C.isHarnessEntry(entries[1]), true);
  assert.equal(C.fileEntryOpens(entries[1]), false);
  assert.equal(C.fileEntryOpens(entries[0]), true);
  assert.equal(C.fileEntryOpens(entries[3]), true);
  assert.equal(C.fileEntryOpens(entries[4]), false);
  assert.equal(C.fileEntryOpens(entries[5]), false);
  assert.equal(C.fileEntryKind(entries[1]), "harness files are not shown");
  assert.equal(C.fileEntryKind(entries[4]), "link: not opened here");
  assert.equal(C.fileEntryKind(entries[5]), "permission denied");
  assert.equal(C.fileEntryKind(entries[0]), "folder");
  const listing = { entries, more: 12 };
  assert.match(C.fileListWords(listing, 4), /4 entries\. 2 hidden entries not shown\. 12 more are not listed/);
  assert.match(C.fileListWords({ entries: [], more: 0 }, 0), /empty/);
  assert.match(C.fileListWords(listing, 1, { query: "x" }), /1 of 6 entries match/);
});

test("Files tab state and roving rows", () => {
  const st = C.createFilesState("s-1", "/w/p");
  assert.equal(st.path, "");
  assert.equal(st.cache.size, 0);
  const rows = [{ name: "a" }, { name: "b" }, { name: "c" }];
  assert.equal(C.activeRowName(rows, "b"), "b");
  assert.equal(C.activeRowName(rows, "gone"), "a");
  assert.equal(C.activeRowName([], "x"), "");
  assert.equal(C.stepRowName(rows, "a", "ArrowDown"), "b");
  assert.equal(C.stepRowName(rows, "c", "ArrowDown"), "c");
  assert.equal(C.stepRowName(rows, "a", "ArrowUp"), "a");
  assert.equal(C.stepRowName(rows, "b", "End"), "c");
  assert.equal(C.stepRowName(rows, "b", "Home"), "a");
  assert.equal(C.stepRowName(rows, "b", "x"), null);
  assert.equal(C.stepRowName([], "b", "Home"), null);
});

test("file lines view accepts the daemon's shape", () => {
  const v = C.fileLinesView({ text: "a\nb\n", first: 1, last: 2, total_lines: 9, bytes: 4, binary: false });
  assert.deepEqual(v, { text: "a\nb\n", first: 1, last: 2, total: 9, bytes: 4, binary: false });
  assert.equal(C.fileLinesView({ text: "a\n", first: 1, last: 1, total: 3 }).total, 3);
  const bin = C.fileLinesView({ binary: true, bytes: 2048, total_lines: 0 });
  assert.equal(bin.binary, true);
  assert.equal(bin.text, "");
  assert.equal(bin.total, 0);
  // The loaded lines of a file page like a stored output.
  const viewer = C.createViewer("f", 0);
  assert.equal(C.applyLines(viewer, C.fileLinesView({ text: "a\nb\n", first: 1, last: 2, total_lines: 3 })), true);
  assert.equal(viewer.done, false);
  assert.equal(C.applyLines(viewer, C.fileLinesView({ text: "c\n", first: 3, last: 3, total_lines: 3 })), true);
  assert.equal(viewer.done, true);
  // An empty file is done at once.
  const empty = C.createViewer("f", 0);
  C.applyLines(empty, C.fileLinesView({ text: "", first: 0, last: 0, total_lines: 0 }));
  assert.equal(empty.done, true);
  assert.equal(C.fileMetaWords({ size: 2048, mtime_ms: 1000 }, 1000 + 3 * 3600 * 1000), "modified 3h ago · 2.0 KiB");
  assert.equal(C.fileMetaWords({ size: 5, mtime_ms: 1000 }, 1000), "modified just now · 5 B");
  assert.match(C.FILE_NOW_WORDS, /may have changed since the agent read it/);
});

test("the Files tab reads a folder once: the root's empty path counts as being read", () => {
  const st = C.createFilesState("s-1", "/w/p");
  assert.equal(C.filesNeedsLoad(st), true);
  st.loading = "";
  assert.equal(C.filesNeedsLoad(st), false, "a read of the root in flight is not started again");
  st.loading = "src";
  assert.equal(C.filesNeedsLoad(st), false);
  st.loading = null;
  st.cache.set("", { entries: [] });
  assert.equal(C.filesNeedsLoad(st), false);
  st.path = "src";
  assert.equal(C.filesNeedsLoad(st), true);
  st.error = "x";
  assert.equal(C.filesNeedsLoad(st), false);
});

test("Open file's accessible name begins with its visible label", () => {
  assert.ok(C.openFileLabel("notes/a.txt").startsWith("Open file"));
  assert.equal(C.openFileLabel(""), "Open file the workspace folder in the Files tab");
});
