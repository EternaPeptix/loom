import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as C from "./core.js";

const here = dirname(fileURLToPath(import.meta.url));

// ---- fixtures: one record of every kind, shaped like `one_of_each` in ferret-core/src/event.rs ----

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
  assert.equal(C.argsLine("grep", { pattern: "x", path: "." }), "x in .");
  assert.equal(C.argsLine("note", { kind: "decision", text: "y" }), '{"kind":"decision","text":"y"}');
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
  // When last and mean format to the same tok/s string, say "(N replies)" instead of repeating the speed twice.
  const same = C.sessionSpeed([r(99, 100, 1100), r(99, 100, 1100), r(99, 100, 1100)]);
  assert.equal(same.label, "98.0 tok/s (3 replies)");
  // Even slightly different raw floats that round to the same display string collapse cleanly.
  const roundedSame = C.sessionSpeed([r(99, 100, 1100.3), r(99, 100, 1099.7)]);
  assert.equal(roundedSame.label, "98.0 tok/s (2 replies)");
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
  assert.match(C.diskWarning({ free_bytes: 3 * GiB, total_bytes: 1000 * GiB }), /^Low disk space: 3\.0 GiB free of 1000\.0 GiB\..*ferret gc/);
  assert.match(C.diskWarning({ free_bytes: 40 * GiB, total_bytes: 1000 * GiB }), /Low disk space/);
  assert.equal(C.diskWarning({ free_bytes: 0, total_bytes: 0 }), null);
});

test("egressWarning: a sentence only when egress is unbounded", () => {
  assert.equal(C.egressWarning(null), null);
  assert.equal(C.egressWarning(undefined), null);
  assert.equal(C.egressWarning({ level: "bounded", reasons: [] }), null);
  assert.equal(C.egressWarning({ level: "unprobed", reasons: ["The first self-probe has not finished."] }), null);
  const one = C.egressWarning({ level: "unbounded", reasons: ["sandbox.allow_fetch_services is set."] });
  assert.match(one, /^Egress is unbounded: sandbox\.allow_fetch_services is set\. Commands may reach the network outside the egress proxy/);
  assert.doesNotMatch(one, /more\)/);
  assert.match(C.egressWarning({ level: "unbounded", reasons: ["a.", "b.", "c."] }), /a\. \(\+2 more\)/);
  assert.match(C.egressWarning({ level: "unbounded" }), /self-probe in `ferret status`/);
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
  assert.equal(C.pageTitle({ open: 0, blocking: 0 }), "ferret");
  assert.equal(C.pageTitle({ open: 2, blocking: 0 }), "(2) ferret");
  assert.equal(C.pageTitle({ open: 2, blocking: 1 }), "(1) needs you · ferret");
  assert.equal(C.pageTitle({ open: 5, blocking: 3 }), "(3) needs you · ferret");
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

test("composer keys on a coarse pointer: Enter adds a line, Ctrl or Cmd with Enter sends", () => {
  const e = { key: "Enter", shiftKey: false, isComposing: false, text: "hi" };
  assert.equal(C.composerAction({ ...e, coarse: true }), "none");
  assert.equal(C.composerAction({ ...e, coarse: true, mod: true }), "send");
  assert.equal(C.composerAction({ ...e, mod: true }), "send");
  assert.equal(C.composerAction({ ...e, mod: true, shiftKey: true }), "send");
  assert.equal(C.composerAction({ ...e, mod: true, text: " " }), "ignore");
  assert.equal(C.composerAction({ ...e, mod: true, isComposing: true }), "none");
  // a narrow window with a fine pointer keeps Enter-to-send: only `coarse` changes the key
  assert.equal(C.composerAction({ ...e, coarse: false }), "send");
});

test("composerHelp names the keys only for a fine pointer and keeps its note whole", () => {
  assert.deepEqual(C.composerHelp({ coarse: true }), { keys: "", note: "" });
  assert.equal(C.composerHelp({}).keys, "Enter sends · Shift+Enter adds a line.");
  const h = C.composerHelp({ coarse: true, paused: true, running: true, lead: true });
  assert.equal(h.note, "A message does not answer the open question. It reaches the lead between steps.");
  assert.equal(C.composerHelp({ running: true }).note, "It is read between steps.");
});

test("composerCaption: the phone composer's one line and its full name", () => {
  const line = C.progressLine({ plan: [{ status: "done", text: "a" }, { status: "doing", text: "b" }, { status: "todo", text: "c" }], step: 0, budget: null });
  const c = C.composerCaption({ line, stats: { context: "context 9% of 1M", cache: "cache 98%" } });
  assert.equal(c.text, "Plan 1 of 3 · context 9% · cache 98%");
  assert.equal(c.label, "Session details: Plan 1 of 3 done, context 9% of 1M, cache 98%");
  assert.deepEqual(C.composerCaption({ line: null, stats: { context: "", cache: "" } }), { text: "Session details", label: "Session details" });
  assert.equal(C.composerCaption({ line: null, stats: { context: "context 3% of 262k", cache: "" } }).text, "context 3%");
});

test("missionsLabel and jumpMode", () => {
  assert.equal(C.missionsLabel(0), "Missions");
  assert.equal(C.missionsLabel(1), "Missions, 1 needs you");
  assert.equal(C.missionsLabel(3), "Missions, 3 need you");
  assert.equal(C.jumpMode({ section: "overview", follow: false, needsOffscreen: true }), "hidden");
  assert.equal(C.jumpMode({ section: "chat", follow: true, needsOffscreen: false }), "hidden");
  assert.equal(C.jumpMode({ section: "chat", follow: false, needsOffscreen: false }), "latest");
  assert.equal(C.jumpMode({ section: "chat", follow: false, needsOffscreen: true }), "needs");
  assert.equal(C.jumpMode({ section: "chat", follow: true, needsOffscreen: true }), "needs");
  // while the question is on screen the button is hidden, so it never covers an answer
  assert.equal(C.jumpMode({ section: "chat", follow: false, needsOffscreen: false, cardShown: true }), "hidden");
});

test("groupLabel has a short form for a phone, with the same words in its long one", () => {
  const g = { toolCount: 8, startTs: 0, endTs: 163000, running: false };
  assert.equal(C.groupLabel(g, 0).short, "Worked 2m43s · 8 calls");
  assert.equal(C.groupLabel({ ...g, toolCount: 1, running: true }, 5000).short, "Worked 5.0s · 1 call · running");
  assert.match(C.groupLabel(g, 0).text, /^Worked for 2m43s · 8 tool calls$/);
});

test("a profile named for its model is said once", () => {
  const same = C.identityChips(infoOf("s", { profile: "dsv41", model: "dsv41", context_window: 1048576 }), null);
  assert.equal(same.model.text, "dsv41 · 1M");
  const other = C.identityChips(infoOf("s", { profile: "qwen", model: "qwen4-max-preview", context_window: 262144 }), null);
  assert.equal(other.model.text, "qwen · qwen4-max-preview · 262k");
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
  const m = C.meterModel({ inView: 150_000, windowSize: 1_000_000, floor: 180_000, target: 400_000 });
  assert.equal(m.inViewPct, 15);
  assert.equal(m.floorPct, 18);
  assert.equal(m.targetPct, 40);
  assert.equal(m.over, false);
  assert.equal(m.label, "150k of 1M");
  const unknown = C.meterModel({ inView: 500_000, windowSize: 0, floor: 180_000, target: 400_000 });
  assert.equal(unknown.known, false);
  assert.equal(unknown.over, true);
  assert.ok(unknown.inViewPct <= 100 && unknown.targetPct < 100);
  assert.equal(C.meterModel({ inView: 5e9, windowSize: 1000, floor: 0, target: 0 }).inViewPct, 100);
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
  assert.match(m.notices[0], /^2 ledger entries written by a newer ferret are not shown \(first: entry 4: op `x`\)/);
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
  assert.deepEqual(C.buildNewSession({ workspace: "/w", message: "x", role: "lead", agentModel: "fast", startsAgents: true }).body.role_models, { "*": "fast" });
  assert.equal(C.buildNewSession({ workspace: "/w", message: "x", role: "chat", agentModel: "fast" }).body.role_models, undefined);
  assert.equal(C.buildNewSession({ workspace: "/w", message: "x", role: "lead", agentModel: "", startsAgents: true }).body.role_models, undefined);
  // The choice follows the role's startsAgents, not its name.
  assert.equal(C.buildNewSession({ workspace: "/w", message: "x", role: "lead", agentModel: "fast", startsAgents: false }).body.role_models, undefined);
  assert.deepEqual(C.buildNewSession({ workspace: "/w", message: "x", role: "boss", agentModel: "fast", startsAgents: true }).body.role_models, { "*": "fast" });
  // The pack is sent unless it is core or empty.
  assert.equal("pack" in C.buildNewSession({ workspace: "/w", message: "x", pack: "core" }).body, false);
  assert.equal("pack" in C.buildNewSession({ workspace: "/w", message: "x", pack: "" }).body, false);
  assert.equal(C.buildNewSession({ workspace: "/w", message: "x", pack: "ctf", role: "solver" }).body.pack, "ctf");
});

test("roleGroups and packNote shape the new-mission form's Pack and Role menus", () => {
  const pack = {
    name: "ctf", description: " Capture the flag. ", default_role: "solver",
    roles: [
      { name: "solver", description: "Solves.", starts_agents: true, top_level: true },
      { name: "zed", description: "", starts_agents: false, top_level: true },
      { name: "scout", description: "Scouts.", starts_agents: false, top_level: false },
    ],
  };
  assert.deepEqual(C.roleGroups(pack), [
    { label: "Starts a mission", roles: [{ name: "solver", title: "Solves." }, { name: "zed", title: "" }] },
    { label: "Usually started by another role", roles: [{ name: "scout", title: "Scouts." }] },
  ]);
  const only = C.roleGroups({ roles: [{ name: "a", description: "A", top_level: false }] });
  assert.deepEqual(only, [{ label: "Usually started by another role", roles: [{ name: "a", title: "A" }] }]);
  assert.deepEqual(C.roleGroups({ roles: [{ name: "a", top_level: true }] }).map((g) => g.label), ["Starts a mission"]);
  assert.deepEqual(C.roleGroups({ roles: [] }), []);
  assert.deepEqual(C.roleGroups(null), []);
  assert.equal(C.packNote(pack), "Capture the flag.");
  assert.equal(C.packNote({ name: "x", description: "" }), "");
  assert.equal(C.packNote(null), "");
  const fb = C.fallbackPacks();
  assert.deepEqual(fb.map((p) => p.name), ["core"]);
  assert.deepEqual(fb[0].roles.map((r) => [r.name, r.starts_agents]), [["lead", true], ["chat", false]]);
  assert.equal(C.roleGroups(fb[0]).length, 1);
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

test("new session form: earlier missions to recall", () => {
  const form = (prior) => ({ workspace: "/w", message: "x", prior });
  // None named: no key at all, whatever the field held.
  for (const p of [undefined, null, "", "  ", " , ,\n"]) assert.equal("prior" in C.buildNewSession(form(p)).body, false, JSON.stringify(p));
  // Whitespace and commas separate; the order is kept and repeats are dropped (first kept).
  assert.deepEqual(C.buildNewSession(form(" m-b,m-a\n m-b\tm-c , m-a ")).body.prior, ["m-b", "m-a", "m-c"]);
  assert.deepEqual(C.buildNewSession(form("m-1")).body.prior, ["m-1"]);
  // The id rule: 1 to 128 of A-Z a-z 0-9 _ . -, not starting with a dot.
  const ok = "m-0123456789ABCDEF_x.y";
  assert.deepEqual(C.buildNewSession(form(ok)).body.prior, [ok]);
  assert.equal(C.buildNewSession(form("a".repeat(128))).body.prior.length, 1);
  for (const bad of ["a".repeat(129), ".hidden", "m-1/../x", "m-1;rm", "m-é", "m-1?x=2", "m-1:2"]) {
    const r = C.buildNewSession(form(bad));
    assert.match(r.error, /is not a mission id; mission ids look like m-…\.$/, bad);
  }
  assert.equal(C.buildNewSession(form("m-1 /etc/passwd")).error, '"/etc/passwd" is not a mission id; mission ids look like m-….');
  // At most 8 after repeats are dropped.
  const nine = Array.from({ length: 9 }, (_, i) => `m-${i}`);
  assert.equal(C.buildNewSession(form(nine.join(" "))).error, "Name at most 8 earlier missions to recall.");
  assert.equal(C.buildNewSession(form([...nine.slice(0, 8), "m-0", "m-1"].join(" "))).body.prior.length, 8);
  assert.equal(C.MAX_PRIOR, 8);
  // The workspace and the message are checked first.
  assert.match(C.buildNewSession({ workspace: "", message: "x", prior: ".bad" }).error, /Workspace/);
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

/** The text of a fake element: its own textContent, else its children's, in order. */
const textOf = (k) => (k.textContent !== undefined ? String(k.textContent) : (k.kids || []).map(textOf).join(" "));

/** Load a fresh copy of app.js at `hash` against a daemon that refuses every login code. */
async function loadSignedOutPage(t, hash) {
  const page = { shown: [], hashchange: [], reloads: 0, requests: [], replaced: [] };
  const fake = {
    document: {
      createElement: (tag) => ({ tag, kids: [], append(...k) { this.kids.push(...k); }, setAttribute(n, v) { this[n] = v; } }),
      createTextNode: (text) => ({ textContent: text }),
      body: { replaceChildren: (...kids) => (page.shown = kids.map(textOf)) },
    },
    window: { addEventListener: (type, fn) => type === "hashchange" && page.hashchange.push(fn) },
    location: { hash, pathname: "/", search: "", reload: () => page.reloads++ },
    history: { replaceState: (_state, _title, url) => page.replaced.push(url) },
    matchMedia: () => ({ matches: false, addEventListener() {} }),
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

test("app.js: with no code and no stored secret the page says to run ferret open, and a login address arriving in that tab loads it again", async (t) => {
  const page = await loadSignedOutPage(t, "");
  assert.deepEqual(page.requests, []);
  assert.equal(page.shown.length, 1);
  assert.match(page.shown[0], /not signed in/);
  assert.match(page.shown[0], /ferret open/);
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

test("app.js: a code the daemon refuses is sent once without credentials, leaves the address, and the page says to run ferret open", async (t) => {
  const code = "0123456789abcdef0123456789abcdef";
  const page = await loadSignedOutPage(t, "#code=" + code);
  assert.deepEqual(page.requests, [
    { url: "/api/web-sessions", method: "POST", credentials: "omit", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }) },
  ]);
  assert.deepEqual(page.replaced, ["/"]);
  assert.equal(page.shown.length, 1);
  assert.match(page.shown[0], /not signed in/);
  assert.match(page.shown[0], /ferret open/);
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
  assert.equal(C.workspaceName("/Users/me/code/ferret"), "ferret");
  assert.equal(C.workspaceName("/Users/me/code/ferret/"), "ferret");
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
  assert.equal(groups[2].rows[0].identity.text, "qwen · chat", "an unknown age is left out of the line");
  assert.equal(groups[2].rows[0].identity.age, C.ACTIVITY_UNKNOWN);
  assert.equal(groups[2].rows[0].recordedMs, null);
  assert.equal(groups[2].rows[0].identity.waiting, null);
  // with a loaded record the age comes from the record
  const loaded = C.workspaceGroups(sessionStore(list), inboxWith([]), {}, now, { activity: new Map([["mid", { seq: 4, ts: now - 120000 }]]) });
  assert.equal(loaded.flatMap((g) => g.rows).find((r) => r.info.id === "mid").identity.text, "qwen · chat · 2m");
  // the daemon's `last_ms` (its log's last write) ages and orders a row before it is opened; a later record wins
  const listed = list.map((i) => (i.id === "mid" ? { ...i, last_ms: now - 300000 } : i));
  const unopened = C.workspaceGroups(sessionStore(listed), inboxWith([]), {}, now).flatMap((g) => g.rows).find((r) => r.info.id === "mid");
  assert.equal(unopened.identity.text, "qwen · chat · 5m");
  assert.equal(unopened.recordedMs, now - 300000);
  const opened = C.workspaceGroups(sessionStore(listed), inboxWith([]), {}, now, { activity: new Map([["mid", { seq: 4, ts: now - 60000 }]]) });
  assert.equal(opened.flatMap((g) => g.rows).find((r) => r.info.id === "mid").recordedMs, now - 60000, "opening it does not move it unless a newer record arrived");
  // a session event (no last_ms) keeps the one the list gave
  const st = sessionStore(listed);
  C.applySessionEvent(st, { ...list.find((i) => i.id === "mid"), title: "renamed" });
  assert.equal(st.byId.get("mid").last_ms, now - 300000);
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
  assert.equal(chips.id.text, "session-ab…");
  assert.equal(chips.id.full, "session-abcdef-0123");
  assert.equal(chips.run.text, "Running · step 4 · 6s");
});

test("identityChips: an unreachable profile warns, an unknown one is not a warning, a missing window is dropped", () => {
  const info = infoOf("s", { profile: "necromicon", model: "necromicon", context_window: 0 });
  const down = C.identityChips(info, { models: [{ profile: "necromicon", base_url: "b", model: "necromicon", reachable: false, detail: "connection refused", context_window: 0 }] });
  assert.deepEqual(down.model.warn, { icon: "alert", word: "unreachable" });
  assert.equal(down.model.reachable, false);
  assert.equal(down.model.text, "necromicon");
  assert.match(down.model.tip, /unreachable: connection refused/);
  // other profiles' health does not matter; no status at all is not a warning
  assert.equal(C.identityChips(info, { models: [{ profile: "other", reachable: false }] }).model.warn, null);
  const none = C.identityChips(info, null);
  assert.equal(none.model.warn, null);
  assert.equal(none.model.reachable, null);
  // the window falls back to the daemon's figure
  assert.equal(C.identityChips(info, { models: [{ profile: "necromicon", reachable: true, context_window: 262144 }] }).model.text, "necromicon · 262k");
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
  assert.equal(C.shortId("0123456789abcdef"), "0123456789…");
  assert.equal(C.shortId("0123456789"), "0123456789");
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
  assert.equal(C.identityLine(i, null, null, 61000).text, "qwen · chat");
  assert.equal(C.identityLine(i, null, null, 61000).known, false);
  assert.equal(C.identityLine(i, null, null, 61000).parts[2], null);
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
  assert.equal(s.label, "Mission total, every session");
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

test("visibleRecordsAfter excludes hidden bookkeeping records unless details is true", () => {
  reset();
  const store = storeOf([
    start(),
    R("turn_start", { trigger: "user" }),
    R("budget_clock", { running: true }),
    R("model_request", { req_id: "r1", step: 1, epoch: 0, purpose: "step", est_tokens: 5 }),
    call("c1"),
    R("user_message", { text: "x" }, undefined, "user"),
    result("c1"),
    reply("r", "t"),
  ]); // 0..7
  assert.equal(C.recordsAfter(store.blocks, 0, C.lastSeq(store)), 7);
  assert.equal(C.visibleRecordsAfter(store.blocks, 0), 4, "excludes turn_start, budget_clock, model_request");
  assert.equal(C.visibleRecordsAfter(store.blocks, 0, true), 5, "details=true includes model_request");
  assert.equal(C.visibleRecordsAfter(store.blocks, 5), 2, "result (6) and reply (7)");
  assert.equal(C.visibleRecordsAfter(store.blocks, 7), 0);
  assert.equal(C.visibleRecordsAfter(store.blocks, null), 0);
  assert.equal(C.visibleRecordsAfter(store.blocks, undefined), 0);
  assert.equal(C.visibleRecordsAfter(null, 1), 0);
  // Also handles synthetic blocks with raw bookkeeping kinds or id-only blocks.
  const synthetic = [
    { id: 1, kind: "user" },
    { id: 2, kind: "turn_start" },
    { id: 3, kind: "budget_clock" },
    { id: 4, kind: "model_request" },
    { id: 5, kind: "response" },
  ];
  assert.equal(C.visibleRecordsAfter(synthetic, 1), 1);
  assert.equal(C.visibleRecordsAfter(synthetic, 1, true), 4);
  // chatItems unread divider uses visible records rather than raw lastSeq delta.
  const sinceItems = C.chatItems(store.blocks, { models: store.models, sinceSeq: 4, lastSeq: C.lastSeq(store) });
  const divider = sinceItems.find((i) => i.type === "since");
  assert.equal(divider.count, 3, "only user_message (5), result (6), reply (7)");
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

test("findFields and findInRecord include reasoning in all and messages scopes only", () => {
  reset();
  const store = storeOf([
    start(),
    R("user_message", { text: "find clue" }, undefined, "user"),
    reply("r1", "", { reasoning: "internal clue Alpha", tool_calls: [{ call_id: "c1", name: "bash", arguments: "{}", complete: true }] }),
    call("c1"),
    result("c1", "ok", { text: "done" }),
    reply("r2", "visible reply", { reasoning: "secret Beta", finish: "length" }),
  ]);
  const r2 = store.blocks[store.blocks.length - 1];
  assert.deepEqual(C.findFields(r2, "all").map((f) => f[0]), ["text", "reasoning"]);
  assert.deepEqual(C.findFields(r2, "messages").map((f) => f[0]), ["text", "reasoning"]);
  assert.deepEqual(C.findFields(r2, "tools").map((f) => f[0]), ["text"]);
  assert.deepEqual(C.findFields(r2, "failures").map((f) => f[0]), ["text"]);

  const allAlpha = C.findInRecord(store.blocks, "Alpha");
  assert.equal(allAlpha.count, 1);
  assert.equal(allAlpha.hits[0].field, "reasoning");
  assert.deepEqual(allAlpha.hits[0].snippet, { before: "internal clue ", match: "Alpha", after: "" });

  assert.equal(C.findInRecord(store.blocks, "Beta", "all").count, 1);
  assert.equal(C.findInRecord(store.blocks, "Beta", "messages").count, 1);
  assert.equal(C.findInRecord(store.blocks, "Beta", "tools").count, 0);
  assert.equal(C.findInRecord(store.blocks, "Beta", "failures").count, 0, "reasoning is not searched under failures");
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

test("compactConfirm names the session and says what a compaction does", () => {
  const q = C.compactConfirm("Fix the flaky test");
  assert.equal(q.text, "Compact Fix the flaky test's context now? The model writes a note and everything before the last few steps leaves its view; nothing is deleted.");
  assert.equal(q.yes, "Compact now");
  assert.match(C.compactConfirm().text, /^Compact the context of this session now\?/);
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

test("dedupeParkedError suppresses errors already present in the parked item text", () => {
  const err = "The model request failed after 3 attempts: connection refused on local port 8080";
  const itemText = "The session could not continue.\nThe model request failed after 3 attempts:\n  connection   refused on local port 8080\nNothing was lost: answer.";
  assert.equal(C.dedupeParkedError(itemText, err), null, "whitespace-normalized duplicate is suppressed");
  assert.equal(C.dedupeParkedError(itemText, null), null);
  assert.equal(C.dedupeParkedError(itemText, ""), null);
  assert.equal(C.dedupeParkedError(itemText, "   "), null);
  assert.equal(C.dedupeParkedError(itemText, "request timed out."), "request timed out.");
  const longPrefix = "The model request failed after 3 attempts because the upstream server closed the socket";
  assert.ok(longPrefix.length > 80);
  const longItem = `The session could not continue. ${longPrefix} while streaming chunk 99. Nothing was lost.`;
  const truncatedErr = `${longPrefix} while streaming…`;
  assert.equal(C.dedupeParkedError(longItem, truncatedErr), null, "matches first 80 normalized chars when longer than 80");
});

test("childBlockingItem finds the oldest child blocker when the open session is not itself blocked", () => {
  const sessions = [
    info("lead", { mission: "m-1", title: "Fleet Lead" }),
    info("w1", { mission: "m-1", parent: "lead", title: "Worker One" }),
    info("w2", { mission: "m-1", parent: "lead", title: "" }),
    info("other", { mission: "m-2", title: "Other Mission" }),
  ];
  const inboxArr = [
    { session: "other", mission: "m-2", opened_ms: 10, item: { item_id: "i0", blocking: true } },
    { session: "lead", mission: "m-1", opened_ms: 20, item: { item_id: "i1", blocking: false } },
    { session: "w1", mission: "m-1", opened_ms: 200, item: { item_id: "i2", blocking: true } },
    { session: "w2", mission: "m-1", opened_ms: 100, item: { item_id: "i3", blocking: true } },
  ];
  const hit = C.childBlockingItem(sessions, inboxArr, "lead");
  assert.ok(hit);
  assert.equal(hit.item.item.item_id, "i3");
  assert.equal(hit.session.id, "w2");
  assert.equal(hit.title, "w2", "falls back to session.id when session.title is empty");

  // Also works with SessionStore + Inbox store objects.
  const store = C.createSessionStore();
  C.applySessionList(store, sessions);
  const inbox = C.createInbox();
  C.applyInboxList(inbox, inboxArr);
  const storeHit = C.childBlockingItem(store, inbox, "lead");
  assert.equal(storeHit.item.item.item_id, "i3");
  assert.equal(storeHit.session.id, "w2");

  // Returns null if openSessionId itself already has a blocking item.
  const withOwnBlock = [...inboxArr, { session: "lead", mission: "m-1", opened_ms: 300, item: { item_id: "i4", blocking: true } }];
  assert.equal(C.childBlockingItem(sessions, withOwnBlock, "lead"), null);

  // Falls back to item.session when the blocked session is not in sessions, and handles flat blocking items.
  const flatHit = C.childBlockingItem(
    [{ id: "lead", mission: "m-1", title: "Lead" }],
    [{ session: "w-missing", mission: "m-1", blocking: true, opened_ms: 50 }],
    "lead",
  );
  assert.deepEqual(flatHit, { item: { session: "w-missing", mission: "m-1", blocking: true, opened_ms: 50 }, session: null, title: "w-missing" });
  assert.equal(C.childBlockingItem(sessions, inboxArr, "unknown"), null);
  assert.equal(C.childBlockingItem(null, null, "lead"), null);
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
  assert.ok(C.missingWorkspaceError("The workspace /w/new does not exist. Create it from the UI or run `ferret run --create-workspace`."));
  assert.ok(!C.missingWorkspaceError("The workspace is inside the ferret home."));
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
    { name: "src", kind: "dir", size: 0, mtime_ms: 1 }, { name: ".ferret", kind: "dir", size: 0, mtime_ms: 0, hidden: true, note: "harness files are not shown" },
    { name: ".env", kind: "file", size: 5, mtime_ms: 1 }, { name: "Readme.md", kind: "file", size: 5, mtime_ms: 1 },
    { name: "out", kind: "link", size: 0, mtime_ms: 1 }, { name: "locked", kind: "dir", error: "permission denied" },
  ];
  assert.deepEqual(C.fileRows(entries).map((e) => e.name), ["src", "Readme.md", "out", "locked"]);
  assert.deepEqual(C.fileRows(entries, { showHidden: true }).map((e) => e.name), ["src", ".ferret", ".env", "Readme.md", "out", "locked"]);
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

// ---- copying

test("copy texts: a reply's raw text, a message, reasoning, and a code block without its fence", () => {
  assert.equal(C.replyCopyText({ kind: "response", text: "**hi**\n```js\nx()\n```" }), "**hi**\n```js\nx()\n```");
  assert.equal(C.replyCopyText({ kind: "response", text: "" }), null);
  assert.equal(C.replyCopyText({ kind: "user", text: "x" }), null);
  assert.equal(C.messageCopyText({ kind: "user", text: "  keep my spaces\n" }), "  keep my spaces\n");
  assert.equal(C.messageCopyText({ kind: "response", text: "x" }), null);
  assert.equal(C.reasoningCopyText({ kind: "response", reasoning: "think" }), "think");
  assert.equal(C.reasoningCopyText({ kind: "response", reasoning: "" }), null);
  const tree = C.proseTree("before\n```rust\nfn a() {}\n\nfn b() {}\n```\nafter");
  const pre = tree.find((b) => b.type === "pre");
  assert.equal(C.codeCopyText(pre), "fn a() {}\n\nfn b() {}");
  assert.equal(C.codeCopyText(tree[0]), null);
  assert.equal(C.codeCopyText(null), null);
});

test("toolCommandCopy: the bash command, a file tool's path, else the arguments as pretty JSON", () => {
  assert.deepEqual(C.toolCommandCopy({ name: "bash", args: { command: "ls -la | wc -l" } }), { text: "ls -la | wc -l", what: "Command" });
  assert.deepEqual(C.toolCommandCopy({ name: "read", args: { path: "src/a.rs", start: 1 } }), { text: "src/a.rs", what: "Path" });
  assert.deepEqual(C.toolCommandCopy({ name: "edit", args: { file_path: "/w/x" } }), { text: "/w/x", what: "Path" });
  assert.deepEqual(C.toolCommandCopy({ name: "grep", args: { pattern: "a", path: "." } }), { text: '{\n  "pattern": "a",\n  "path": "."\n}', what: "Arguments" });
  assert.deepEqual(C.toolCommandCopy({ name: "weird", args: "raw text" }), { text: "raw text", what: "Arguments" });
  assert.deepEqual(C.toolCommandCopy({ name: "bash", args: { cmd: 1 } }), { text: '{\n  "cmd": 1\n}', what: "Arguments" });
  assert.equal(C.toolCommandCopy({ name: "bash", args: undefined }), null);
  assert.equal(C.toolCommandCopy({ name: "bash", args: null }), null);
  assert.equal(C.toolCommandCopy(null), null);
});

test("toolOutputCopy is all the recorded output, and null when there is none", () => {
  assert.equal(C.toolOutputCopy({ result: { text: "a\nb\nc" } }), "a\nb\nc");
  assert.equal(C.toolOutputCopy({ result: { text: "" } }), null);
  assert.equal(C.toolOutputCopy({ result: null }), null);
});

test("fullOutputPlan: only a cut output with a stored copy, and the cap is judged from the recorded size", () => {
  const id = "cd".repeat(32);
  assert.equal(C.fullOutputPlan({ result: { text: "x", cut: false } }), null);
  assert.equal(C.fullOutputPlan({ result: { text: "x", cut: true } }), null);
  assert.equal(C.fullOutputPlan({ result: null }), null);
  assert.deepEqual(C.fullOutputPlan({ result: { text: "x", cut: true, output: { id, bytes: 128000, lines: 5000 } } }), { blob: id, bytes: 128000, tooBig: false });
  assert.equal(C.fullOutputPlan({ result: { text: "x", cut: true, output: { id, bytes: C.COPY_FULL_CAP, lines: 5 } } }).tooBig, false);
  assert.equal(C.fullOutputPlan({ result: { text: "x", cut: true, output: { id, bytes: C.COPY_FULL_CAP + 1, lines: 5 } } }).tooBig, true);
  // a view of another blob: its size is not the output's, so it is found out when it is read
  assert.deepEqual(C.fullOutputPlan({ result: { text: "x", cut: true, output: { id: "ef".repeat(32), bytes: 9, lines: 1 }, meta: { of_blob: id } } }), { blob: id, bytes: null, tooBig: false });
  assert.equal(C.rawUrl("a b"), "/api/blobs/a%20b/raw");
  assert.match(C.COPY_FULL_BIG, /2 MiB/);
});

test("viewerLinesCopy: the loaded lines, or the whole lines the selection touches, without numbers", () => {
  const v = { first: 10, lines: ["ten", "eleven", "twelve", "thirteen"] };
  assert.deepEqual(C.viewerLinesCopy(v, null), { text: "ten\neleven\ntwelve\nthirteen", from: 10, to: 13, count: 4, selected: false });
  assert.deepEqual(C.viewerLinesCopy(v, { from: 11, to: 12 }), { text: "eleven\ntwelve", from: 11, to: 12, count: 2, selected: true });
  assert.deepEqual(C.viewerLinesCopy(v, { from: 12, to: 11 }), { text: "eleven\ntwelve", from: 11, to: 12, count: 2, selected: true });
  assert.deepEqual(C.viewerLinesCopy(v, { from: 12, to: 99 }), { text: "twelve\nthirteen", from: 12, to: 13, count: 2, selected: true });
  assert.equal(C.viewerLinesCopy(v, { from: 40, to: 50 }).selected, false);
  assert.equal(C.viewerLinesCopy({ first: 1, lines: [] }, null), null);
  assert.equal(C.viewerLinesCopy(null, null), null);
  assert.equal(C.viewerLinesWords(C.viewerLinesCopy(v, { from: 11, to: 12 })), "Copied the selected lines: lines 11–12.");
  assert.equal(C.viewerLinesWords(C.viewerLinesCopy(v, null)), "Copied the loaded lines: lines 10–13.");
});

test("evidence and inbox copy texts", () => {
  assert.equal(C.quoteCopyText({ quote: "full: None," }), "full: None,");
  assert.equal(C.quoteCopyText({ quote: "" }), null);
  assert.equal(C.inboxCopyText({ text: "Which branch?" }), "Which branch?");
  assert.equal(C.inboxCopyText({}), null);
});

test("copy words say what happened and how to finish by hand", () => {
  assert.equal(C.copiedChars(1), "Copied 1 character");
  assert.equal(C.copiedChars(1204), "Copied 1,204 characters");
  assert.equal(C.copyWords("Reply", "clipboard"), "Reply copied");
  assert.equal(C.copyWords("Reply", "command"), "Reply copied");
  assert.equal(C.copyWords("Session id", "selected"), "Session id selected; press Ctrl+C to copy it");
  assert.equal(C.copyWords("Session id", "selected", true), "Session id selected; press Cmd+C to copy it");
  assert.equal(C.copyWords("Reply", "none"), "Could not copy reply; this browser did not allow it");
});

test("copyOnSelectDecision copies only an enabled, new, non-empty selection inside the record, never while typing", () => {
  const base = { enabled: true, text: "abc", scoped: true, typing: false, same: false };
  assert.equal(C.copyOnSelectDecision(base), "copy");
  assert.equal(C.copyOnSelectDecision({ ...base, enabled: false }), "off");
  assert.equal(C.copyOnSelectDecision({ ...base, typing: true }), "typing");
  assert.equal(C.copyOnSelectDecision({ ...base, text: "" }), "empty");
  assert.equal(C.copyOnSelectDecision({ ...base, text: " \n " }), "empty");
  assert.equal(C.copyOnSelectDecision({ ...base, text: null }), "empty");
  assert.equal(C.copyOnSelectDecision({ ...base, scoped: false }), "outside");
  assert.equal(C.copyOnSelectDecision({ ...base, same: true }), "same");
  // off wins over everything, so nothing is read or said while the preference is off
  assert.equal(C.copyOnSelectDecision({ enabled: false, text: "", scoped: false, typing: true, same: true }), "off");
  // typing wins over an empty or foreign selection: the composer is never touched
  assert.equal(C.copyOnSelectDecision({ ...base, typing: true, scoped: false, text: "" }), "typing");
});

test("app.js copies only from a user gesture and only through copyText", () => {
  const app = stripComments(readFileSync(join(here, "app.js"), "utf8"));
  assert.equal([...app.matchAll(/navigator\.clipboard/g)].length, 1, "one clipboard call, inside copyText");
  assert.equal([...app.matchAll(/execCommand\("copy"\)/g)].length, 1, "one command fallback, inside copyText");
  assert.ok(!/execCommand\("(cut|paste)"\)/.test(app));
  assert.ok(app.includes('"ferret_copy_on_select"'));
});

test("viewerSelectionEdges: edge rows with none of their text selected are left out", () => {
  assert.deepEqual(C.viewerSelectionEdges({ from: 6, to: 7, startAt: "lead", endAt: "lead" }), { from: 6, to: 6 }); // triple-click
  assert.deepEqual(C.viewerSelectionEdges({ from: 5, to: 7, startAt: "tail", endAt: "text" }), { from: 6, to: 7 }); // drag from the blank space
  assert.deepEqual(C.viewerSelectionEdges({ from: 5, to: 7, startAt: "text", endAt: "tail" }), { from: 5, to: 7 });
  assert.deepEqual(C.viewerSelectionEdges({ from: 5, to: 6, startAt: "tail", endAt: "lead" }), { from: 6, to: 6 });
  assert.deepEqual(C.viewerSelectionEdges({ from: 5, to: 5, startAt: "tail", endAt: "lead" }), { from: 5, to: 5 });
});

// ---- the context card ----

const CARD_SEGMENTS = [
  { key: "system", chars: 18234, tokens: 4914 },
  { key: "tools", chars: 61230, tokens: 16503, count: 42 },
  { key: "rules", chars: 640, tokens: 172, count: 2 },
  { key: "assignment", chars: 0, tokens: 0, count: 0 },
  { key: "resume", chars: 5200, tokens: 1401 },
  { key: "conversation", chars: 172850, tokens: 46590, count: 96 },
  { key: "tool_output", chars: 229560, tokens: 61877, count: 128 },
  { key: "pinned", chars: 11575, tokens: 3120, count: 3 },
  { key: "agent_reports", chars: 16361, tokens: 4410, count: 2 },
  { key: "notes", chars: 3636, tokens: 980, count: 6 },
  { key: "stubs", chars: 36506, tokens: 9840, count: 57 },
  { key: "other", chars: 0, tokens: 0, count: 0 },
  { key: "framing", chars: 0, tokens: 770 },
  { key: "hud", chars: 2310, tokens: 623 },
];
function cardWindow(over = {}) {
  return {
    epoch: 3, items: [], est_tokens: 152340, target_tokens: 400000, floor_tokens: 180000, context_window: 262144,
    prompt_tokens: 148812, cached_tokens: 131072,
    breakdown: { basis: "scaled_to_measured", chars_per_token: 3.71, total_tokens: 151200, segments: CARD_SEGMENTS },
    measured_now: 151200,
    last_request: { req_id: "r-41", step: 41, epoch: 3, n_messages: 120, est_tokens: 150020, prompt_tokens: 148812, cached_tokens: 131072, hud_bytes: 2310 },
    fold_at: 209712, fold_to: 131072,
    ...over,
  };
}

test("segmentLayout: widths add up to the tokens, a small part is never inflated past what it takes from the large ones", () => {
  const sum = (l) => l.reduce((n, s) => n + s.pct, 0);
  const plain = C.segmentLayout([{ key: "a", tokens: 5000 }, { key: "b", tokens: 100 }, { key: "z", tokens: 0 }], 10000);
  assert.deepEqual(plain.map((s) => s.key), ["a", "b"]);
  assert.ok(Math.abs(sum(plain) - 51) < 0.01, String(sum(plain)));
  assert.ok(plain[1].pct >= 0.8 && plain[1].pct < 1.01, "widened to the minimum, and no more");
  // a card-like fill: every width is at least the minimum, the sum is the fill
  const card = C.segmentLayout(CARD_SEGMENTS.map((s) => ({ key: s.key, tokens: s.tokens })), 262144);
  const fill = (100 * 151200) / 262144;
  assert.ok(Math.abs(sum(card) - fill) < 0.01, `${sum(card)} vs ${fill}`);
  assert.ok(card.every((s) => s.pct >= 0.8 - 1e-9));
  // too small a fill to hold every minimum: the narrow parts become one sliver of their true width
  const tiny = C.segmentLayout([{ key: "a", tokens: 30 }, { key: "b", tokens: 20 }, { key: "c", tokens: 10 }], 1000000);
  assert.equal(tiny.length, 1);
  assert.deepEqual(tiny[0].merged, ["a", "b", "c"]);
  assert.ok(Math.abs(tiny[0].pct - 0.006) < 1e-6);
  // one large part and a few small, with room: nothing merges
  const some = C.segmentLayout([{ key: "big", tokens: 600000 }, { key: "s1", tokens: 1000 }, { key: "s2", tokens: 1200 }], 1000000);
  assert.deepEqual(some.map((s) => s.key), ["big", "s1", "s2"]);
  assert.ok(Math.abs(sum(some) - 60.22) < 0.01);
  assert.deepEqual(C.segmentLayout([], 100), []);
});

test("contextCardModel: the hero line, with ~ on estimates and the window in words", () => {
  const m = C.contextCardModel(cardWindow());
  assert.equal(m.parts, true);
  assert.equal(m.hero.figure, "~151k");
  assert.equal(m.hero.denominator, "of 262k tokens");
  assert.equal(m.hero.exact, "262,144 tokens");
  assert.equal(m.hero.percent, "58%");
  assert.equal(m.sub, "Last request 149k, counted by the server · about 2.4k added since");
  assert.equal(m.basis, "Parts estimated from characters and scaled to the total (3.71 characters a token).");
  // a figure that is exactly the server's count has no ~
  const exact = C.contextCardModel(cardWindow({ measured_now: 148812, breakdown: { basis: "scaled_to_measured", chars_per_token: 3.7, total_tokens: 148812, segments: CARD_SEGMENTS.map((s) => ({ ...s, tokens: Math.floor(s.tokens * 0.984) })) } }));
  assert.equal(exact.hero.approx, false);
  assert.equal(exact.sub, "Last request 149k, counted by the server");
  assert.equal(exact.hero.figure, "149k");
  // nothing counted yet: estimated, no server sentence, the default-ratio note
  const fresh = C.contextCardModel(cardWindow({ measured_now: null, last_request: null, prompt_tokens: 0, cached_tokens: 0, breakdown: { basis: "default_ratio", chars_per_token: 3.3, total_tokens: 152340, segments: CARD_SEGMENTS } }));
  assert.equal(fresh.hero.figure, "~152k");
  assert.equal(fresh.sub, "Estimated from characters; no request in this context epoch has been counted yet.");
  assert.equal(fresh.basis, "Parts estimated from characters at 3.3 a token; not yet checked against a server count.");
  assert.equal(fresh.cache, null);
  // 1,048,576 is "1.05M" tokens, never a bare "1M"
  assert.equal(C.contextCardModel(cardWindow({ context_window: 1048576 })).hero.denominator, "of 1.05M tokens");
  // a tiny share reads "<1%"
  assert.equal(C.percentWords(0.3), "<1%");
  assert.equal(C.percentWords(0), "0%");
  assert.equal(C.percentWords(57.6), "58%");
});

test("contextCardModel: rows and bar share their order, zero parts are dropped except Messages and replies, and the parts add up", () => {
  const m = C.contextCardModel(cardWindow());
  const keys = m.rows.map((r) => r.key);
  assert.deepEqual(keys, ["system", "tools", "rules", "resume", "notes", "conversation", "tool_output", "pinned", "agent_reports", "stubs", "framing", "hud"]);
  assert.deepEqual(m.bar.segments.map((s) => s.key), keys);
  assert.equal(m.rows.find((r) => r.key === "tools").label, "Tool definitions · 42");
  // images the daemon reports have their own row, counted, after the agent reports
  const pics = C.contextCardModel(cardWindow({ breakdown: { basis: "default_ratio", chars_per_token: 3.3, total_tokens: 6600, segments: [{ key: "system", chars: 1, tokens: 5000 }, { key: "conversation", chars: 1, tokens: 100 }, { key: "images", chars: 0, tokens: 1500, count: 2 }] } }));
  assert.deepEqual(pics.rows.map((r) => r.key), ["system", "conversation", "images"]);
  assert.equal(pics.rows.find((r) => r.key === "images").label, "Images · 2");
  assert.equal(m.rows.find((r) => r.key === "system").value, "~4.9k");
  assert.equal(m.rows.reduce((n, r) => n + r.tokens, 0), 151200);
  // an empty conversation still has its row; other zero parts do not
  const quiet = C.contextCardModel(cardWindow({ breakdown: { basis: "default_ratio", chars_per_token: 3.3, total_tokens: 5000, segments: [{ key: "system", chars: 1, tokens: 5000 }, { key: "conversation", chars: 0, tokens: 0, count: 0 }, { key: "tools", chars: 0, tokens: 0, count: 0 }] } }));
  assert.deepEqual(quiet.rows.map((r) => r.key), ["system", "conversation"]);
  // every row says which pattern and family it draws with, so the swatch is the segment
  for (const r of m.rows) assert.ok(r.family && r.pattern && r.group, r.key);
  // the legend colours are not the state colours: no row is in a state family
  assert.deepEqual([...new Set(m.rows.map((r) => r.family))].sort(), ["carry", "conv", "fold", "setup"]);
  assert.match(m.bar.label, /^Context use 58% of 262,144 tokens: System prompt 2%, Tool definitions 6%/);
  assert.match(m.bar.label, /, free 42%$/);
  // the bar's fill is what the tokens say
  const fill = m.bar.segments.reduce((n, s) => n + s.pct, 0);
  assert.ok(Math.abs(fill - (100 * 151200) / 262144) < 0.01);
  assert.ok(Math.abs(m.bar.free.pct - (100 - fill)) < 0.01);
  // a segment 18% wide or more also carries its short label
  assert.deepEqual(m.bar.segments.filter((s) => s.labelled).map((s) => s.key), ["tool_output"]);
  const wide = C.contextCardModel(cardWindow({ context_window: 160000 }));
  assert.ok(wide.bar.segments.find((s) => s.key === "tool_output").labelled);
});

test("contextCardModel: fold marks use the effective bounds, with their own shapes in words", () => {
  const m = C.contextCardModel(cardWindow());
  assert.equal(m.fold.text, "▼ folds at 210k · ▽ down to 131k");
  assert.equal(m.fold.past, null);
  const over = C.contextCardModel(cardWindow({ fold_at: 120000, fold_to: 60000 }));
  assert.equal(over.fold.past.text, "Past the fold mark: older output folds at the next step.");
  // the raw 400k target lies beyond a 262k window: nothing is drawn rather than a mark off the bar
  assert.equal(C.contextCardModel(cardWindow({ fold_at: 400000, fold_to: 180000 })).fold, null);
  assert.equal(C.contextCardModel(cardWindow({ fold_at: undefined, fold_to: undefined })).fold, null);
});

test("contextCardModel: the cache split, an unknown window and an answer from an older daemon", () => {
  const m = C.contextCardModel(cardWindow());
  assert.equal(m.cache.text, "Last request: 131k from the cache · 17.7k read anew");
  const none = C.contextCardModel(cardWindow({ last_request: { ...cardWindow().last_request, cached_tokens: 0 } }));
  assert.equal(none.cache.text, "No cached tokens reported. The server may not report caching.");
  const nowin = C.contextCardModel(cardWindow({ context_window: null }));
  assert.equal(nowin.hero.denominator, "tokens · limit unknown");
  assert.equal(nowin.hero.percent, "");
  assert.equal(nowin.bar.known, false);
  assert.equal(nowin.bar.scaleNote, "scale: fold mark + 25%");
  assert.equal(nowin.bar.free, null);
  const old = C.contextCardModel({ epoch: 1, items: [], est_tokens: 86000, target_tokens: 400000, floor_tokens: 180000, context_window: 1000000, prompt_tokens: 86000, cached_tokens: 84000 });
  assert.equal(old.parts, false);
  assert.equal(old.hero.figure, "~86k");
  assert.deepEqual(old.rows, []);
  assert.equal(old.basis, null);
});

test("contextCardModel: row notes carry the facts the parts' words depend on", () => {
  const m = C.contextCardModel(cardWindow());
  const notes = Object.fromEntries(m.notes.map((n) => [n.label, n.note]));
  assert.equal(notes["Rules and approvals"], "Yours, verbatim; never folded.");
  assert.match(notes["Re-weave brief"], /may include leads written by the model, not verified/);
  assert.match(notes["Harness state (as last sent)"], /never cached or folded/);
  assert.match(notes["Folded-out stubs"], /full output stays in the record/);
});

test("stopQuestion: only a root says it can be resumed", () => {
  const root = C.stopQuestion({ id: "s-1", title: "Net" });
  assert.match(root, /It can be resumed\./);
  const agent = C.stopQuestion({ id: "s-2", title: "Worker", parent: "s-1" });
  assert.doesNotMatch(agent, /can be resumed/);
  assert.match(agent, /cannot be resumed/);
});

test("archiveQuestion warns only when open inbox items remain", () => {
  assert.equal(C.archiveQuestion({ id: "s-1", title: "Net" }), null);
  assert.equal(C.archiveQuestion({ id: "s-1", title: "Net" }, 0), null);
  assert.equal(C.archiveQuestion({ id: "s-1", title: "Net" }, -2), null);
  assert.equal(C.archiveQuestion({ id: "s-1", title: "Net" }, 1), "Archive Net? It still has 1 open inbox item, which will be dismissed.");
  assert.equal(C.archiveQuestion({ id: "s-1", title: "" }, 3), "Archive s-1? It still has 3 open inbox items, which will be dismissed.");
  assert.equal(C.archiveQuestion({ id: "s-1" }, 1200), "Archive s-1? It still has 1,200 open inbox items, which will be dismissed.");
});

test("contextCardModel: a fold mark inside the scale is drawn even when it folds down to nothing", () => {
  const m = C.contextCardModel(cardWindow({ context_window: 16000, fold_at: 1, fold_to: 0 }));
  assert.ok(m.fold);
  assert.equal(m.fold.toPct, null);
  assert.match(m.fold.text, /folds at/);
  assert.doesNotMatch(m.fold.text, /down to/);
});

test("outputLineKinds marks the envelope and a unified diff, and nothing in plain output", () => {
  const text = "[edit · edited · /w/a.rs · 1 replacement · 7 lines]\n--- /w/a.rs\n+++ /w/a.rs\n@@ -1,3 +1,3 @@\n-timeout = 30\n+timeout = 60\n retries = 3\n[end of edit output · edited]";
  assert.deepEqual(C.outputLineKinds(text), ["meta", "file", "file", "hunk", "del", "add", "ctx", "meta"]);
  assert.deepEqual(C.outputLineKinds("total 4\n-rw-r--r-- a\n+ b"), ["", "", ""], "a line that only starts with - or + is not a diff");
  assert.deepEqual(C.diffStat(text), { added: 1, removed: 1, text: "+1 −1", words: "1 line added, 1 line removed" });
  assert.equal(C.diffStat("(new file)"), null);
});

test("fileChanges sums successful edit and write results per path, newest first", () => {
  const diff = (a, r) => "--- /w/x\n+++ /w/x\n@@ -1 +1 @@\n" + "-o\n".repeat(r) + "+n\n".repeat(a);
  const tool = (id, seq, path, text, status = "ok", cls = "write") => ({ id, seq, kind: "tool", cls, args: { path }, result: { seq: seq + 1, status, text, meta: {}, ts: seq * 1000 } });
  const blocks = [
    tool(1, 10, "/w/src/a.rs", diff(2, 1)),
    tool(2, 20, "/w/notes.txt", "[write · created · /w/notes.txt · 1 line]\n(new file)\n[end of write output · created]"),
    tool(3, 30, "/w/src/a.rs", diff(1, 0)),
    tool(4, 40, "/w/src/b.rs", diff(5, 5), "error"),
    tool(5, 50, "/w/src/c.rs", "file text", "ok", "read"),
  ];
  const rows = C.fileChanges(blocks, "/w");
  assert.deepEqual(rows.map(r => [r.rel, r.edits, r.added, r.removed, r.created, r.lastId]), [["src/a.rs", 2, 3, 1, false, 3], ["notes.txt", 1, 0, 0, true, 2]]);
});

test("mineStep walks the operator's own messages; [ and ] are the keys, never while typing", () => {
  const blocks = [{ kind: "user", seq: 1 }, { kind: "tool", seq: 2 }, { kind: "user", seq: 5 }, { kind: "response", seq: 6 }, { kind: "user", seq: 9 }];
  assert.equal(C.mineStep(blocks, 2, 1), 5);
  assert.equal(C.mineStep(blocks, 5, 1), 9);
  assert.equal(C.mineStep(blocks, 9, 1), null);
  assert.equal(C.mineStep(blocks, 6, -1), 5);
  assert.equal(C.mineStep(blocks, 1, -1), null);
  assert.equal(C.mineStep(blocks, null, -1), 9);
  assert.equal(C.mineStep([], 3, 1), null);
  assert.equal(C.shortcutFor({ key: "]" }), "mine-next");
  assert.equal(C.shortcutFor({ key: "[" }), "mine-prev");
  assert.equal(C.shortcutFor({ key: "]" }, { typing: true }), null);
});

test("splitAttachments takes the runtime's attachment block apart", () => {
  const head = "Attached files (saved read-only; read them with `read`):";
  const text = `Compare these.\n\n${head}\n- /ws/.ferret/uploads/report.csv (12.1 KiB, text/csv)\n- /ws/.ferret/uploads/my (1).png (226 KiB, image/png)\n\n\`/ws/.ferret/uploads/report.csv\`:\n\`\`\`csv\na,b\n\`\`\``;
  const r = C.splitAttachments(text);
  assert.equal(r.text, "Compare these.");
  assert.deepEqual(r.files, [
    { path: "/ws/.ferret/uploads/report.csv", name: "report.csv", size: "12.1 KiB", mime: "text/csv" },
    { path: "/ws/.ferret/uploads/my (1).png", name: "my (1).png", size: "226 KiB", mime: "image/png" },
  ]);
  assert.equal(r.inline, "`/ws/.ferret/uploads/report.csv`:\n```csv\na,b\n```");
  // Attachments without text, and a list with no inline copies.
  const bare = C.splitAttachments(`${head}\n- /ws/.ferret/uploads/a.bin (3 B, application/octet-stream)`);
  assert.equal(bare.text, "");
  assert.equal(bare.files.length, 1);
  assert.equal(bare.inline, "");
  // No block, a heading that is not at a line start, or a heading with no list: the text comes back whole.
  for (const plain of ["hello", `see ${head}\n- /a (1 B, x/y)`, `${head}\nnothing listed`, "", null]) {
    const r2 = C.splitAttachments(plain);
    assert.equal(r2.text, String(plain ?? ""));
    assert.deepEqual(r2.files, []);
  }
  // A quoted heading earlier in the text does not hide the real block.
  assert.equal(C.splitAttachments(`${head}\nnot a list\n\n${head}\n- /a/b.txt (1 B, text/plain)`).files[0].name, "b.txt");
});

test("Copy message copies only the text above the attachment block", () => {
  const text = "Look at this.\n\nAttached files (saved read-only; read them with `read`):\n- /ws/.ferret/uploads/a.txt (1 B, text/plain)";
  assert.equal(C.messageCopyText({ kind: "user", text }), "Look at this.");
  assert.equal(C.messageCopyText({ kind: "user", text: text.replace("Look at this.\n\n", "") }), null);
});

test("tool shapes: absolute_path and target_file are paths; description is the row label", () => {
  assert.equal(C.toolPathArg({ absolute_path: "/ws/a.rs" }), "/ws/a.rs");
  assert.equal(C.toolPathArg({ target_file: "src/b.rs" }), "src/b.rs");
  assert.equal(C.argsLine("read", { target_file: "src/b.rs" }), "src/b.rs");
  assert.equal(C.openFileTarget({ name: "read", args: { absolute_path: "/ws/a.rs" } }, "/ws"), "a.rs");
  const row = C.toolRow({ kind: "tool", name: "bash", state: "done", argsLine: "cargo test", args: { command: "cargo test", description: "Run the tests" }, result: null });
  assert.equal(row.label, "Run the tests");
  assert.equal(row.argsLine, "cargo test");
  assert.equal(C.toolRow({ kind: "tool", name: "bash", state: "done", argsLine: "ls", args: { command: "ls" }, result: null }).label, "");
  assert.equal(C.toolRow({ kind: "tool", name: "bash", state: "done", argsLine: "ls", args: { command: "ls", description: 7 }, result: null }).label, "");
});

test("a call sent under another harness's name shows the ferret tool that ran, and its path or pattern", () => {
  const store = C.createRecordStore("s-1");
  C.applyRecord(store, { seq: 0, ts_ms: 1, author: "model", kind: "tool_call", call_id: "c1", name: "Read", args: { file_path: "/ws/a.rs", offset: 1, limit: 5 }, class: "read" });
  C.applyRecord(store, { seq: 1, ts_ms: 2, author: "tool", kind: "tool_result", call_id: "c1", name: "read", status: "ok", text: "[read · ok]", class: "read", meta: {}, duration_ms: 3 });
  const b = store.blocks.find((x) => x.kind === "tool");
  const row = C.toolRow(b);
  assert.equal(row.name, "read");
  assert.equal(row.calledAs, "Read");
  assert.equal(row.argsLine, "/ws/a.rs");
  assert.equal(C.argsLine("grep", { pattern: "fn main", path: "src" }), "fn main in src");
  assert.equal(C.argsLine("web_fetch", { url: "https://example.invalid/x" }), "https://example.invalid/x");
  assert.equal(C.argsLine("job_wait", { job: "j2" }), "j2");
  assert.equal(C.toolRow({ ...b, ran: undefined, name: "read" }).calledAs, "");
});

// ---- images and queued messages (docs/CONTRACTS-2026-11-23.md D7, E5)

test("composerAction: Alt+Enter queues only while a turn runs", () => {
  const e = { key: "Enter", shiftKey: false, isComposing: false, text: "hi" };
  assert.equal(C.composerAction({ ...e, alt: true, running: true }), "queue");
  assert.equal(C.composerAction({ ...e, alt: true, running: false }), "send");
  assert.equal(C.composerAction({ ...e, running: true }), "send");
  assert.equal(C.composerAction({ ...e, alt: true, running: true, text: " " }), "ignore");
  assert.equal(C.composerAction({ ...e, alt: true, running: true, shiftKey: true }), "none");
  assert.equal(C.composerAction({ ...e, alt: true, running: true, isComposing: true }), "none");
  assert.equal(C.composerAction({ ...e, alt: true, running: true, coarse: true }), "none");
});

test("composerHelp names the queue key while running; composerCaption leads with the queue", () => {
  assert.equal(C.composerHelp({ running: true }).keys, "Enter sends now · Alt+Enter queues it for after this turn · Shift+Enter adds a line.");
  assert.match(C.composerHelp({ running: true, mac: true }).keys, /⌥Enter queues/);
  assert.equal(C.composerHelp({ running: true, coarse: true }).keys, "");
  const c = C.composerCaption({ line: null, stats: { context: "context 9% of 1M", cache: "" }, queued: 2 });
  assert.equal(c.text, "2 queued · context 9%");
  assert.equal(c.label, "Session details: 2 queued, context 9% of 1M");
  assert.equal(C.composerCaption({ line: null, stats: null, queued: 0 }).text, "Session details");
});

test("thumbSize fits 240 and never enlarges", () => {
  assert.deepEqual(C.thumbSize(640, 400), { width: 240, height: 150 });
  assert.deepEqual(C.thumbSize(400, 800), { width: 120, height: 240 });
  assert.deepEqual(C.thumbSize(100, 50), { width: 100, height: 50 });
  assert.deepEqual(C.thumbSize(10000, 1), { width: 240, height: 1 });
  assert.deepEqual(C.thumbSize(0, 0), { width: 240, height: 240 });
  assert.deepEqual(C.thumbSize(64, 64, 32), { width: 32, height: 32 });
});

test("imageList and imageUrl keep only hex blob ids and read from /api/images/", () => {
  const ok = { blob: "AB".repeat(8), mime: "image/png", bytes: 5, width: 3, height: 2, name: "a.png" };
  assert.deepEqual(C.imageList([ok, { blob: "../x" }, { blob: "https://evil/x.png" }, null, { blob: "" }]), [{ ...ok, blob: "ab".repeat(8) }]);
  assert.deepEqual(C.imageList(undefined), []);
  assert.equal(C.imageUrl("ab".repeat(32)), "/api/images/" + "ab".repeat(32));
  assert.equal(C.imageUrl("../etc/passwd"), null);
  assert.equal(C.imageUrl("http://x/y"), null);
  assert.equal(C.imageUrl(undefined), null);
});

test("image records reach the blocks: user message and tool result", () => {
  const img = { blob: "cd".repeat(16), mime: "image/png", bytes: 2048, width: 640, height: 400, name: "screen.png" };
  const store = C.createRecordStore("s-1");
  C.applyRecords(store, [
    { seq: 0, ts_ms: 1, kind: "user_message", text: "look", images: [img] },
    { seq: 1, ts_ms: 2, kind: "user_message", text: "none" },
    { seq: 2, ts_ms: 3, kind: "tool_call", call_id: "c1", name: "read", args: { path: "/w/screen.png" }, class: "read" },
    { seq: 3, ts_ms: 4, kind: "tool_result", call_id: "c1", name: "read", status: "ok", text: "[read · image]", class: "read", meta: {}, images: [img] },
  ]);
  const users = store.blocks.filter((b) => b.kind === "user");
  assert.deepEqual(users[0].images, [img]);
  assert.deepEqual(users[1].images, []);
  assert.deepEqual(store.blocks.find((b) => b.kind === "tool").result.images, [img]);
});

test("image words: alt, facts, path, count", () => {
  const img = { blob: "ab".repeat(8), mime: "image/png", bytes: 231424, width: 640, height: 400, name: "screen.png" };
  assert.equal(C.imageAlt(img, "read"), "screen.png");
  assert.equal(C.imageAlt({ ...img, name: "" }, "read"), "image from read");
  assert.equal(C.imageAlt({ ...img, name: "" }), "attached image");
  assert.equal(C.imageFacts(img), "640×400 · 226 KiB · image/png");
  assert.equal(C.imageFacts({ blob: "x", mime: "", bytes: 0, width: 0, height: 0, name: "" }), "");
  const files = [{ path: "/w/.ferret/uploads/screen.png", name: "screen.png" }, { path: "/w/.ferret/uploads/b.png", name: "b.png" }];
  assert.equal(C.imagePath(img, { files }), "/w/.ferret/uploads/screen.png");
  assert.equal(C.imagePath({ ...img, name: "" }, { files, args: { path: "/w/x.png" } }), "/w/x.png");
  assert.equal(C.imagePath({ ...img, name: "" }, { files: [files[1]] }), "/w/.ferret/uploads/b.png");
  assert.equal(C.imagePath({ ...img, name: "zzz.png" }, { files, args: { file_path: "/w/y.png" } }), "/w/y.png");
  assert.equal(C.imagePath(img, {}), null);
  assert.equal(C.imageCountLabel(1), "1 image");
  assert.equal(C.imageCountLabel(3), "3 images");
});

test("isImageFile and modelVision", () => {
  assert.equal(C.isImageFile({ name: "a.PNG", type: "" }), true);
  assert.equal(C.isImageFile({ name: "a.bin", type: "image/webp" }), true);
  assert.equal(C.isImageFile({ name: "a.png", type: "application/octet-stream" }), false);
  assert.equal(C.isImageFile({ name: "a.svg", type: "image/svg+xml" }), false);
  assert.equal(C.isImageFile({ name: "notes.txt", type: "" }), false);
  const models = [{ profile: "dsv41", vision: true }, { profile: "qwen", vision: false }, { profile: "old" }];
  assert.equal(C.modelVision(models, { profile: "dsv41" }), true);
  assert.equal(C.modelVision(models, { profile: "qwen" }), false);
  assert.equal(C.modelVision(models, { profile: "old" }), null);
  assert.equal(C.modelVision(models, null), null);
  assert.equal(C.modelVision(undefined, { profile: "qwen" }), null);
});

test("queued list words and routes", () => {
  assert.equal(C.queuedLabel(0), "0 queued");
  assert.equal(C.queuedLabel(3), "3 queued");
  assert.equal(C.queuedPreview("  a\n\n  b   c "), "a b c");
  const long = C.queuedPreview("x".repeat(300), 20);
  assert.equal(long.length, 20);
  assert.ok(long.endsWith("…"));
  const q = C.queuedList([{ id: "b", text: "2", created_ms: 20 }, { id: "a", text: "1", created_ms: 10, attachments: ["/p"] }, { text: "no id" }, null]);
  assert.deepEqual(q.map((x) => x.id), ["a", "b"]);
  assert.deepEqual(q[0].attachments, ["/p"]);
  assert.deepEqual(q[1].attachments, []);
  assert.equal(C.queuedUrl("s 1"), "/api/sessions/s%201/queued");
  assert.equal(C.queuedUrl("s1", "q/1"), "/api/sessions/s1/queued/q%2F1");
  assert.equal(C.queuedUrl("s1", "q1", "send"), "/api/sessions/s1/queued/q1/send");
  assert.deepEqual(C.SEND_CHOICES.map((c) => c.when), ["now", "after_turn"]);
});


// ---- compaction (docs/CONTRACTS-COMPACTION.md Part U) ----

const K1 = "e134a0f0b4bf46c1", K2 = "cc8752638528652e", K3 = "5a1c3e7d90b2f648";
const COMPACTION = {
  epoch: 2, upto_seq: 40, reason: "size", before_tokens: 312000, after_tokens_est: 38000,
  note: `## State\n- edited (out:${K2}); ran out:${K1}, again out:${K1}; short out:abc is not a key; out:${K3}.`,
  note_req: "r-9", table: `Outputs\nout:${K1} · bash · ls · exit 0\nout:${K2} · edit · a.rs\nout:${"f".repeat(64)} · bash · x`,
  keys: [K1, K2], dropped_keys: ["out:0123456789abcdef"], objections: null,
};

test("compactionHead: step, sizes and the reason in words", () => {
  assert.equal(C.compactionHead(COMPACTION, 412), "Context compacted · step 412 · 312k → 38k tokens · size");
  assert.match(C.compactionHead({ ...COMPACTION, reason: "fresh_start" }, 3), /fresh start$/);
  assert.equal(C.compactionHead({ reason: "operator" }, undefined), "Context compacted · operator");
});

test("extractOutKeys and splitOutKeys find 8-64 hex keys, once each, in order", () => {
  assert.deepEqual(C.extractOutKeys(COMPACTION.note, COMPACTION.table), [K2, K1, K3, "f".repeat(64)]);
  const parts = C.splitOutKeys(`a out:${K1} b`);
  assert.deepEqual(parts, [{ text: "a " }, { key: K1, text: "out:" + K1 }, { text: " b" }]);
  assert.deepEqual(C.splitOutKeys("no keys here out:xyz"), [{ text: "no keys here out:xyz" }]);
  assert.deepEqual(C.splitOutKeys(""), []);
});

test("compactionBlock: note keys, table keys, dropped keys, objections", () => {
  const b = C.compactionBlock(COMPACTION, 7);
  assert.equal(b.kind, "compaction");
  assert.equal(b.head, "Context compacted · step 7 · 312k → 38k tokens · size");
  assert.deepEqual(b.noteKeys, [K2, K1, K3]);
  assert.deepEqual(b.tableKeys, [K1, K2, "f".repeat(64)]);
  assert.deepEqual(b.droppedKeys, ["out:0123456789abcdef"]);
  assert.equal(b.objections, null);
  const fresh = C.compactionBlock({ ...COMPACTION, reason: "fresh_start", note: null, objections: "no run cited", dropped_keys: [] }, 9);
  assert.equal(fresh.note, null);
  assert.deepEqual(fresh.noteKeys, []);
  assert.equal(fresh.objections, "no run cited");
  assert.equal(C.compactionBlock({ reason: "size" }, 1).table, "");
});

test("a compaction record becomes a block, is found by Find, and refetches the window", () => {
  const store = C.createRecordStore("s-c");
  C.applyRecords(store, [
    rec("model_request", { req_id: "r", step: 12, epoch: 1, purpose: "step", n_messages: 1, stable_hash: "h", hud: BLOB, est_tokens: 9 }, "harness", 0),
    rec("compaction", COMPACTION, "harness", 1),
  ]);
  const b = store.blocks.find((x) => x.kind === "compaction");
  assert.ok(b);
  assert.match(b.head, /step 12/);
  const hits = C.findInRecord(store.blocks, K2.slice(0, 8), "all", 2).hits;
  assert.ok(hits.length >= 1, "Find searches the note and the table");
});

test("paging decisions: a page from the end, then earlier pages until the compaction's upto_seq is in", () => {
  assert.equal(C.recordsUrl("s-1", null, 1000, C.TAIL_BEFORE), `/api/sessions/s-1/records?before=${C.TAIL_BEFORE}&limit=1000`);
  assert.equal(C.pagesBackward({ records: [], prev_before: null }), true);
  assert.equal(C.pagesBackward({ records: [], next_after: null }), false, "an older daemon ignores before");
  const seqs = (from, to, extra = {}) => { const out = []; for (let i = from; i <= to; i++) out.push({ seq: i, kind: "note", ...(extra[i] || {}) }); return out; };
  // No compaction in view: the last page is all that loads.
  assert.equal(C.tailNeedsMore(seqs(500, 1499), 500), null);
  // A compaction whose upto_seq is inside the page: nothing more.
  assert.equal(C.tailNeedsMore(seqs(500, 1499, { 900: { kind: "compaction", upto_seq: 800 } }), 500), null);
  // upto_seq before the page: one more page, from prev_before.
  assert.deepEqual(C.tailNeedsMore(seqs(500, 1499, { 900: { kind: "compaction", upto_seq: 100 } }), 500), { before: 500, limit: 1000 });
  // The start of the log has been reached.
  assert.equal(C.tailNeedsMore(seqs(0, 999, { 900: { kind: "compaction", upto_seq: 0 } }), null), null);
});

test("a store started from the tail knows its earlier records, prepends them, and keeps what arrives by after", () => {
  seqCounter = 0;
  const all = [];
  for (let i = 0; i < 30; i++) all.push(rec(i % 2 ? "user_message" : "harness_note", i % 2 ? { text: "m" + i } : { note: "n", text: "t" + i }, i % 2 ? "user" : "harness", i));
  const store = C.createRecordStore("s-t");
  C.startTailStore(store, all.slice(20), 20, []);
  assert.equal(C.hasEarlier(store), true);
  assert.deepEqual(C.earlierRequest(store), { before: 20, limit: C.TAIL_LIMIT });
  assert.equal(C.lastSeq(store), 29);
  C.applyRecords(store, [rec("user_message", { text: "new" }, "user", 30)]);
  assert.equal(C.lastSeq(store), 30);
  const before = store.blocks.length;
  const added = C.prependRecords(store, all.slice(0, 20), null);
  assert.equal(added, store.blocks.length - before);
  assert.equal(store.blocks.length, 31);
  assert.equal(C.hasEarlier(store), false);
  assert.equal(C.earlierRequest(store), null);
  assert.equal(C.lastSeq(store), 30);
});

test("CTX_PARTS: a compaction segment replaces the re-weave brief and the stubs, and the threshold says compacts at", () => {
  const segs = [{ key: "system", tokens: 5000 }, { key: "compaction", tokens: 9000 }, { key: "resume", tokens: 700 }, { key: "stubs", tokens: 300, count: 4 }, { key: "conversation", tokens: 4000 }];
  const win = { context_window: 262144, compact_at: 104857, breakdown: { basis: "default_ratio", chars_per_token: 3.3, total_tokens: 19000, segments: segs }, measured_now: null };
  const m = C.contextCardModel(win);
  const labels = m.rows.map((r) => r.label);
  assert.ok(labels.includes("Compaction"));
  assert.ok(!labels.includes("Re-weave brief"));
  assert.ok(!labels.some((l) => l.startsWith("Folded-out stubs")));
  assert.match(m.fold.text, /compacts at/);
  const old = C.contextCardModel({ ...win, compact_at: undefined, fold_at: 210000, breakdown: { ...win.breakdown, segments: segs.filter((x) => x.key !== "compaction") } });
  const oldLabels = old.rows.map((r) => r.label);
  assert.ok(oldLabels.includes("Re-weave brief") && oldLabels.some((l) => l.startsWith("Folded-out stubs")));
  assert.match(old.fold.text, /folds at/);
});

test("runWords has a short form for the phone bar: the state alone, no step", () => {
  const w = C.runWords({ status: { phase: "idle", step: 9, last_end: "waiting" } });
  assert.equal(w.text, "Waiting for jobs or agents · step 9");
  assert.equal(w.short, "Waiting on jobs");
  const r = C.runWords({ status: { phase: "running", step: 142 } }, { now: 70000, startMs: 0 });
  assert.equal(r.short, "Running · 1m10s");
  assert.ok(!r.short.includes("step"));
  const e = C.runWords({ status: { phase: "ended", step: 48, outcome: "done", last_end: "finished" } });
  assert.ok(!e.short.includes("step") && e.short.startsWith("Ended"), e.short);
  const i = C.runWords({ status: { phase: "idle", step: 3 } });
  assert.equal(i.short, "Idle");
});

// ---------------------------------------------------------------------------------------------
// Full output opens where the model looked; repeated calls collapse; Expand all stays bounded

test("openAtLine: the first line the model saw past line 1, or the start of an omitted middle", () => {
  assert.equal(C.openAtLine([], 100), 1);
  assert.equal(C.openAtLine([[40, 60]], 100), 40);
  assert.equal(C.openAtLine([[1, 20]], 100), 21);
  assert.equal(C.openAtLine([[1, 20], [81, 100]], 100), 21);
  assert.equal(C.openAtLine([[1, 100]], 100), 1);
  assert.equal(C.openAtLine([[1, 20]], null), 1);
  assert.equal(C.openAtLine([[1, 10], [11, 20]], 100), 21, "adjacent ranges merge");
});

test("viewerPlan marks the seen ranges only for a partial view", () => {
  assert.deepEqual(C.viewerPlan({ ranges: [[1, 20], [81, 100]], total: 100, complete: false }), { start: 21, seenRanges: [[1, 20], [81, 100]] });
  assert.deepEqual(C.viewerPlan({ ranges: [[1, 100]], total: 100, complete: true }), { start: 1, seenRanges: [] });
  assert.deepEqual(C.viewerPlan({ ranges: [], total: 100 }), { start: 1, seenRanges: [] });
  assert.deepEqual(C.viewerPlan(null), { start: 1, seenRanges: [] });
});

test("viewerStanding keeps the evidence wording for citations only, and names the marks", () => {
  assert.doesNotMatch(C.viewerStanding({ seenRanges: [[1, 5]] }), /does not verify/);
  assert.match(C.viewerStanding({ seenRanges: [[1, 5]] }), /Lines the model was shown are marked\./);
  assert.match(C.viewerStanding({ citeStart: 3 }), /does not verify the claim/);
  assert.doesNotMatch(C.viewerStanding({}), /marked/);
  assert.equal(C.lineInRanges([[2, 4]], 4), true);
  assert.equal(C.lineInRanges([[2, 4]], 5), false);
  assert.equal(C.lineInRanges(undefined, 1), false);
});

test("shownOfTotal ranges drive the plan end to end", () => {
  const v = C.shownOfTotal({ text: "x", cut: true, output: { id: "ab".repeat(32), bytes: 10, lines: 100 }, meta: { shown: [[1, 20], [81, 100]] } });
  assert.deepEqual(C.viewerPlan(v), { start: 21, seenRanges: [[1, 20], [81, 100]] });
});

// A store of tool calls: `argsOf(i)` gives the arguments of call i; `statusOf(i)` its result status.
function callsStore(n, argsOf, statusOf = () => "ok", name = "bash") {
  reset();
  const recs = [start()];
  for (let i = 0; i < n; i++) {
    recs.push(R("tool_call", { call_id: "c" + i, req_id: "r" + i, name, args: argsOf(i), class: "exec" }, undefined, "model"));
    recs.push(R("tool_result", { call_id: "c" + i, name, status: statusOf(i), text: "out", class: "exec", meta: {}, duration_ms: 5 }, undefined, "tool"));
  }
  return storeOf(recs);
}
const groupsOf = (store, opts = {}) => C.chatItems(store.blocks, opts).filter((i) => i.type === "group");

test("callSignature ignores key order and result status", () => {
  const s = callsStore(2, (i) => (i ? { b: 1, a: { y: 2, x: 1 } } : { a: { x: 1, y: 2 }, b: 1 }), (i) => (i ? "error" : "ok"));
  const [a, b] = s.blocks.filter((x) => x.kind === "tool");
  assert.equal(C.callSignature(a), C.callSignature(b));
  assert.notEqual(C.callSignature(a), C.callSignature({ ...a, name: "read", args: a.args }));
});

test("a run of 3 identical calls collapses, 2 do not; status may differ", () => {
  const two = groupsOf(callsStore(2, () => ({ command: "ls" })))[0];
  assert.deepEqual(C.rowsOf(two).map((r) => r.type), ["block", "block"]);
  const three = groupsOf(callsStore(3, () => ({ command: "ls" }), (i) => (i === 1 ? "error" : "ok")))[0];
  const rows = C.rowsOf(three);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].type, "run");
  assert.equal(rows[0].count, 3);
  assert.equal(three.loop, 0);
});

test("a run is cut by a different call; runs of 10 or more flag the group as a loop", () => {
  const g = groupsOf(callsStore(25, (i) => ({ command: i === 12 ? "pwd" : "ls" })))[0];
  assert.deepEqual(C.rowsOf(g).map((r) => (r.type === "run" ? r.count : 1)), [12, 1, 12]);
  assert.equal(g.loop, 12);
  assert.equal(groupsOf(callsStore(9, () => ({ command: "ls" })))[0].loop, 0);
  assert.equal(groupsOf(callsStore(10, () => ({ command: "ls" })))[0].loop, 10);
});

test("pageOf and showMoreLabel", () => {
  const list = Array.from({ length: 120 }, (_, i) => i);
  const p1 = C.pageOf(list);
  assert.equal(p1.visible.length, 50);
  assert.equal(C.showMoreLabel(p1), "Show 50 more (70 hidden)");
  const p3 = C.pageOf(list, 3);
  assert.equal(p3.visible.length, 120);
  assert.equal(p3.hidden, 0);
  assert.equal(C.pageOf(list, 2).more, 20);
});

test("locateInGroup finds the page of a record, inside a run too", () => {
  const s = callsStore(130, (i) => ({ command: "ls dir" + i }));
  const g = groupsOf(s)[0];
  const tools = g.shown.filter((b) => b.kind === "tool");
  assert.equal(C.locateInGroup(g, tools[0].id).groupPages, 1);
  assert.equal(C.locateInGroup(g, tools[120].id).groupPages, 3);
  const loop = groupsOf(callsStore(120, () => ({ command: "cargo build" })))[0];
  const calls = loop.shown.filter((b) => b.kind === "tool");
  const at = C.locateInGroup(loop, calls[110].id);
  assert.equal(at.groupPages, 1);
  assert.equal(at.runPages, 3);
  assert.ok(at.runKey);
  assert.equal(C.locateInGroup(loop, -5), null);
});

test("Expand all on a 5,000-record store renders a bounded number of member rows", () => {
  const s = callsStore(2500, (i) => ({ command: "ls dir" + i }));
  const items = C.chatItems(s.blocks, { expandAll: true });
  const g = items.filter((i) => i.type === "group");
  assert.ok(g.length >= 1 && g.every((x) => x.open));
  assert.ok(g.reduce((a, x) => a + x.toolCount, 0) >= 2500);
  assert.ok(C.renderedRowCount(items) <= g.length * 51, "one page of rows and one button per group");
  assert.ok(C.renderedRowCount(items) < 200);
  // The same for a log that is one long loop, even with its run open.
  const loop = C.chatItems(callsStore(2500, () => ({ command: "cargo build" })).blocks, { expandAll: true });
  const lg = loop.find((i) => i.type === "group");
  assert.equal(C.rowsOf(lg).length, 1);
  assert.equal(C.renderedRowCount(loop, { openRuns: new Set(C.rowsOf(lg).map((r) => r.key)) }), 1 + 50 + 1);
  assert.equal(lg.loop, 2500);
});

// ---- MCP tools (contract M8)

test("mcpToolName / toolShownName: split at the first __ after the prefix; other names are not MCP", () => {
  assert.deepEqual(C.mcpToolName("mcp__github__search_issues"), { server: "github", tool: "search_issues" });
  assert.deepEqual(C.mcpToolName("mcp__docs__fetch__page"), { server: "docs", tool: "fetch__page" });
  assert.deepEqual(C.mcpToolName("mcp__lonely"), { server: "", tool: "lonely" });
  assert.equal(C.mcpToolName("bash"), null);
  assert.equal(C.mcpToolName("my_mcp__x__y"), null);
  assert.equal(C.mcpToolName(undefined), null);
  assert.equal(C.toolShownName("mcp__github__search_issues"), "github · search_issues");
  assert.equal(C.toolShownName("bash"), "bash");
  assert.equal(C.countMcpTools([{ name: "bash" }, { name: "mcp__a__b" }, "mcp__c__d", null]), 2);
  assert.equal(C.countMcpTools(undefined), 0);
});

test("toolRow: an MCP row reads server · tool with the badge and keeps the full name", () => {
  const row = C.toolRow({ kind: "tool", name: "mcp__docs__fetch_page", cls: "exec", state: "done", argsLine: "", result: { status: "error", meta: {}, duration_ms: 310 } });
  assert.equal(row.shown, "docs · fetch_page");
  assert.equal(row.name, "mcp__docs__fetch_page");
  assert.equal(row.mcp, true);
  const plain = C.toolRow({ kind: "tool", name: "bash", cls: "exec", state: "running", argsLine: "ls", result: null });
  assert.equal(plain.shown, "bash");
  assert.equal(plain.mcp, false);
});

test("Find reads an MCP call as server · tool", () => {
  const block = { kind: "tool", id: 1, seq: 3, callSeq: 3, name: "mcp__github__search_issues", argsLine: "retry", result: null };
  assert.equal(C.findInRecord([block], "github · search").count, 1);
  assert.equal(C.findInRecord([block], "mcp__").count, 0);
});

test("contextCardModel: the tools label says how many definitions are MCP, never more than the count", () => {
  const label = (opts) => C.contextCardModel(cardWindow(), opts).rows.find((r) => r.key === "tools").label;
  assert.equal(label(), "Tool definitions · 42");
  assert.equal(label({ mcpTools: 0 }), "Tool definitions · 42");
  assert.equal(label({ mcpTools: 4 }), "Tool definitions · 42 (4 MCP)");
  assert.equal(label({ mcpTools: 99 }), "Tool definitions · 42 (42 MCP)");
});

test("session_start keeps the number of MCP tools for the context label", () => {
  reset();
  const store = storeOf([R("session_start", { session: "s-a", mission: "m-a", parent: null, workspace: "/w", pack: "core", role: "lead", model: MODEL_A, tools: [{ name: "bash" }, { name: "mcp__a__b" }, { name: "mcp__a__c" }], budget: {} })]);
  assert.equal(store.start.tools, 3);
  assert.equal(store.start.mcpTools, 2);
});

test("mcpServersModel: null for nothing, else one row per server with its facts", () => {
  assert.equal(C.mcpServersModel([]), null);
  assert.equal(C.mcpServersModel(undefined), null);
  assert.equal(C.mcpServersModel({ error: "not found" }), null);
  const m = C.mcpServersModel([
    { server: "github", transport: "stdio", state: "running", tools: ["a", "b", "c"], error: null, stderr_tail: ["warn x"], list_changed: true, calls: 1, last_call_ms: 5 },
    { server: "docs", transport: "http", state: "failed", tools: [], error: "connection refused", stderr_tail: [], list_changed: false, calls: 0 },
    { server: "idle", transport: "stdio", state: "not started", tools: [], stderr_tail: [] },
  ]);
  assert.equal(m.length, 3);
  assert.deepEqual([m[0].name, m[0].transport, m[0].state, m[0].tone, m[0].toolCount, m[0].toolsWords, m[0].changed, m[0].hasDetail, m[0].callsWords], ["github", "stdio", "running", "ok", 3, "3 tools", true, true, "1 call"]);
  assert.deepEqual(m[0].stderr, ["warn x"]);
  assert.deepEqual([m[1].tone, m[1].error, m[1].hasDetail, m[1].changed, m[1].toolsWords, m[1].callsWords], ["bad", "connection refused", true, false, "0 tools", ""]);
  assert.deepEqual([m[2].tone, m[2].hasDetail, m[2].error], ["neutral", false, ""]);
});

// ---- captured exchanges and targets (docs/CONTRACTS-TRAFFIC-TARGETS.md, parts C, F, T, U) ----

const exRec = (id, fields = {}) => ({
  seq: seqCounter++, ts_ms: 5000 + seqCounter, kind: "exchange", id, call_id: "c-http", source: "tool", tool: "http_send", scheme: "https", tls: "tool",
  method: "get", host: "API.acme.test", port: 443, target: "/v1/users?id=1", status: 200, error: null,
  request: { id: "11".repeat(32), bytes: 120, lines: 4 }, response: { id: "22".repeat(32), bytes: 900, lines: 12 },
  request_bytes: 120, response_bytes: 2048, truncated: false, upstream_unverified: false, duration_ms: 240, ...fields,
});

test("an exchange record joins the tool row of its call and the store's list, once", () => {
  seqCounter = 0;
  const store = C.createRecordStore("s-a");
  C.applyRecords(store, [
    rec("tool_call", { call_id: "c-http", req_id: "r", name: "http_send", args: { url: "https://api.acme.test/v1/users" }, class: "net" }, "model"),
    rec("tool_result", { call_id: "c-http", name: "http_send", status: "ok", text: "ok", cut: false, class: "net", meta: {}, duration_ms: 5 }, "tool"),
    exRec("ex-aaaaaaaaaaaa"),
    exRec("ex-bbbbbbbbbbbb", { target: "/v1/other", status: null, error: "connection reset", response: null }),
    exRec("ex-cccccccccccc", { call_id: null, source: "proxy", tls: "plain", scheme: "http", port: 80 }),
  ]);
  assert.deepEqual(store.exchanges.map((x) => x.id), ["ex-aaaaaaaaaaaa", "ex-bbbbbbbbbbbb", "ex-cccccccccccc"]);
  const row = C.toolRow(store.blocks[0]);
  assert.equal(row.requests, "2 requests");
  assert.deepEqual(row.exchanges.map((x) => x.id), ["ex-aaaaaaaaaaaa", "ex-bbbbbbbbbbbb"]);
  assert.equal(C.toolRow({ ...store.blocks[0], exchanges: undefined }).requests, "");
  assert.equal(C.applyRecord(store, exRec("ex-aaaaaaaaaaaa", { seq: store.next })), true);
  assert.equal(store.exchanges.length, 3, "an id already held is not listed twice");
  assert.deepEqual(C.exchangesForCall(store.exchanges, "c-http").map((x) => x.id), ["ex-aaaaaaaaaaaa", "ex-bbbbbbbbbbbb"]);
  assert.deepEqual(C.exchangesForCall(store.exchanges, null), []);
});

test("the exchange list model: one line each, marks, filters and the count line", () => {
  const a = C.exchangeOf(exRec("ex-aaaaaaaaaaaa"));
  const e = C.exchangeOf(exRec("ex-eeeeeeeeeeee", { tls: "intercepted", upstream_unverified: true, truncated: true, source: "proxy", status: 503, host: "10.20.0.4", port: 8443, target: "/x" }));
  const n = C.exchangeOf(exRec("ex-nnnnnnnnnnnn", { status: null, error: "timed out", response: null, response_bytes: 0, host: "pay.acme.test", port: 80, scheme: "http", duration_ms: 30000 }));
  assert.equal(C.exchangeOf({ kind: "exchange" }), null);
  const r = C.exchangeRow(a);
  assert.equal(r.text, "GET API.acme.test/v1/users?id=1 · 200 · 2.0 KiB · 240ms");
  assert.equal(r.tone, "ok");
  assert.deepEqual(r.marks, []);
  const re = C.exchangeRow(e);
  assert.equal(re.where, "10.20.0.4:8443/x");
  assert.equal(re.tone, "bad");
  assert.deepEqual(re.marks.map((m) => m.key), ["intercepted", "unverified", "cut"]);
  const rn = C.exchangeRow(n);
  assert.equal(rn.text, "GET pay.acme.test/v1/users?id=1 · no response · 30s");
  assert.equal(rn.words, "timed out");
  assert.equal(C.exchangeRow(C.exchangeOf(exRec("ex-x", { status: 404, response_bytes: 0 }))).tone, "warn");
  assert.equal(C.exchangeWhere(C.exchangeOf(exRec("ex-x", { host: "::1", port: 8080, scheme: "http", target: "p" }))), "[::1]:8080/p");
  const list = [a, e, n];
  const opts = C.exchangeFilterOptions(list);
  assert.deepEqual(opts.hosts, ["10.20.0.4", "api.acme.test", "pay.acme.test"]);
  assert.deepEqual(opts.statuses.map((s) => s.label), ["2xx", "5xx", "no response"]);
  assert.deepEqual(C.filterExchanges(list, { host: "API.acme.test" }).map((x) => x.id), [a.id]);
  assert.deepEqual(C.filterExchanges(list, { status: "none" }).map((x) => x.id), [n.id]);
  assert.deepEqual(C.filterExchanges(list, { host: "all", status: "all" }), list);
  assert.deepEqual(C.filterExchanges(list, { host: "10.20.0.4", status: "ok" }), []);
  assert.equal(C.exchangeCountLine(1, 3), "1 request of 3");
  assert.equal(C.exchangeCountLine(3, 3), "3 requests");
  assert.equal(C.exchangeCountLine(0, 0), "No requests were captured for this session.");
  const merged = [];
  C.mergeExchange(merged, C.exchangeOf(exRec("ex-late", { ts_ms: 9000 })));
  C.mergeExchange(merged, C.exchangeOf(exRec("ex-early", { ts_ms: 100 })));
  assert.equal(C.mergeExchange(merged, C.exchangeOf(exRec("ex-early", { ts_ms: 100 }))), false);
  assert.deepEqual(merged.map((x) => x.id), ["ex-early", "ex-late"]);
});

test("a stored message splits into start line, headers and body, and secrets stay masked until revealed", () => {
  const msg = "POST /login HTTP/1.1\r\nHost: api.acme.test\r\nauthorization: Bearer abc\r\nCookie: sid=1\r\nX-Api-Key: k\r\nSet-Cookie: a=b\r\nProxy-Authorization: Basic x\r\nAccept: */*\r\nX-Long: one\r\n two\r\n\r\n{\"user\":\"a\"}\r\n\r\ntail";
  const v = C.messageView(msg);
  assert.equal(v.start, "POST /login HTTP/1.1");
  assert.equal(v.body, "{\"user\":\"a\"}\r\n\r\ntail");
  assert.equal(v.hasSecrets, true);
  assert.deepEqual(v.rows.map((r) => [r.name, r.sensitive]), [["Host", false], ["authorization", true], ["Cookie", true], ["X-Api-Key", true], ["Set-Cookie", true], ["Proxy-Authorization", true], ["Accept", false], ["X-Long", false]]);
  assert.equal(v.rows[1].shown, C.HEADER_MASK);
  assert.equal(v.rows[1].value, "Bearer abc", "the value is kept for the reveal");
  assert.equal(v.rows[0].shown, "api.acme.test");
  assert.equal(v.rows[7].shown, "one two");
  const shown = C.messageView(msg, { revealed: true });
  assert.equal(shown.rows[1].shown, "Bearer abc");
  assert.equal(shown.rows[5].shown, "Basic x");
  assert.equal(C.isSensitiveHeader(" COOKIE "), true);
  assert.equal(C.isSensitiveHeader("Accept"), false);
  const head = C.messageView("HTTP/1.1 204 No Content\r\nServer: x");
  assert.equal(head.bodyWords, "no body");
  assert.equal(head.hasSecrets, false);
  const big = C.messageView("HTTP/1.1 200 OK\n\n" + "x".repeat(C.EXCHANGE_BODY_CAP + 5));
  assert.equal(big.cut, true);
  assert.equal(big.body.length, C.EXCHANGE_BODY_CAP);
});

const tscope = (inc, exc = []) => C.parseScope(inc, exc);

test("scope entries parse and match as target.rs does (names, globs, IPs, CIDRs, exclude wins)", () => {
  const s = tscope(["acme.test", "*.acme.test", "10.20.0.0/24", "192.0.2.7", "2001:db8::/32"], ["admin.acme.test", "10.20.0.9"]);
  assert.deepEqual(s.errors, []);
  assert.ok(s.contains("acme.test") && s.contains("ACME.test.") && s.contains("api.acme.test") && s.contains("a.b.acme.test"));
  assert.ok(!s.contains("evilacme.test") && !s.contains("acme.test.evil"));
  assert.ok(s.contains("10.20.0.5") && !s.contains("10.20.1.5") && s.contains("192.0.2.7") && s.contains("[2001:db8::1]"));
  assert.ok(!s.contains("admin.acme.test") && !s.contains("10.20.0.9"));
  assert.ok(s.excluded("admin.acme.test"));
  assert.ok(!tscope(["*.acme.test"]).contains("acme.test"), "a glob does not include the bare domain");
  for (const bad of ["https://acme.test", "acme.test:443", "10.0.0.0/33", "*.", "", "a b"]) {
    const r = C.parseScopeEntry(bad);
    assert.ok(r.error && (r.error.includes("scope entry") || r.error.includes("CIDR")), `${bad}: ${r.error}`);
  }
  assert.deepEqual(tscope(["acme.test", "a b"]).errors.length, 1);
});

test("claim hosts: the same cases as claim_hosts in target.rs", () => {
  const s = tscope(["*.acme.test", "10.20.0.0/24"]);
  const text = "The login at https://User@Login.acme.test:8443/auth?x=1 leaks; api.acme.test and 10.20.0.4:22 too, not example.com or http://other.test/x.";
  assert.deepEqual(C.claimHosts(text, ["db.acme.test"], s), ["db.acme.test", "login.acme.test", "other.test", "api.acme.test", "10.20.0.4"]);
  assert.deepEqual(C.claimHosts(text, [], null), ["login.acme.test", "other.test"], "without a scope only URLs count");
  assert.deepEqual(C.claimHosts("see http://[::1]:8080/x", [], null), ["::1"]);
  assert.deepEqual(C.claimHosts("ftp://files.acme.test/x and no hosts", [], null), []);
  assert.deepEqual(C.claimHosts("seen on 10.20.1.4 and 10.20.0.4.", [], s), ["10.20.0.4"]);
  assert.equal(C.assetHost("api.acme.test:8443/tcp"), "api.acme.test");
  assert.equal(C.assetHost("GET https://Shop.acme.test:8443/cart/{id}"), "shop.acme.test");
  assert.equal(C.assetHost("file:/etc/passwd"), "");
  assert.equal(C.assetHost("a1b2c3d4"), "");
  assert.equal(C.assetHost("[::1]:80/tcp"), "::1");
});

test("a claim's host is reached by evidence that cites a call (or a stored message) that got a response, and by nothing else", () => {
  const ex = [
    C.exchangeOf(exRec("ex-aaaaaaaaaaaa", { call_id: "c1", host: "api.acme.test" })),
    C.exchangeOf(exRec("ex-bbbbbbbbbbbb", { call_id: "c2", host: "login.acme.test", status: null, response: null })),
    C.exchangeOf(exRec("ex-cccccccccccc", { call_id: "c3", host: "other.test", request: { id: "99".repeat(32), bytes: 1, lines: 1 } })),
  ];
  const ev = (id, f) => ({ id, supports: true, attested: true, call_id: null, blob: null, session: null, ...f });
  const s = tscope(["*.acme.test"]);
  const claim = { text: "api.acme.test and login.acme.test leak, see http://other.test/x and www.acme.test", assets: ["db.acme.test:5432/tcp", "file:/etc/x"], evidence: [ev("e1", { call_id: "c1" }), ev("e2", { call_id: "c2" }), ev("e3", { blob: "99".repeat(32) })] };
  assert.deepEqual(C.claimReach(claim, ex, s), [
    { host: "db.acme.test", reached: false, ids: [] },
    { host: "other.test", reached: true, ids: ["ex-cccccccccccc"] },
    { host: "api.acme.test", reached: true, ids: ["ex-aaaaaaaaaaaa"] },
    { host: "login.acme.test", reached: false, ids: [] },
    { host: "www.acme.test", reached: false, ids: [] },
  ]);
  const weak = { ...claim, evidence: [ev("e1", { call_id: "c1", attested: false }), ev("e2", { call_id: "c1", supports: false }), ev("e3", { call_id: "c1", session: "s-elsewhere" })] };
  assert.equal(C.claimReach(weak, [{ ...ex[0], session: "s-here" }], s).find((r) => r.host === "api.acme.test").reached, false);
  assert.equal(C.claimReach({ text: "a note with no host", evidence: [] }, ex, s).length, 0);
  assert.equal(C.reachWords({ host: "h.test", reached: true, ids: ["ex-1", "ex-2"] }), "h.test: reached by ex-1, ex-2");
  assert.match(C.reachWords({ host: "h.test", reached: false, ids: [] }), /not reached/);
});

const gnode = (id, kind, locator, status, parent = null, extra = {}) => C.nodeOf({ id, kind, locator, status, parent, missions: ["m-1"], evidence: [], findings: [], ...extra });

test("the target tree nests by parent, orders siblings, folds and filters with the path kept", () => {
  const nodes = [
    gnode("d1", "domain", "acme.test", "untested"),
    gnode("h1", "host", "www.acme.test", "finding", "d1", { findings: [{ claim: "c1", text: "XSS", status: "open", mission: "m-1", evidence: [] }] }),
    gnode("h2", "host", "api.acme.test", "tested", "d1"),
    gnode("i1", "ip", "10.20.0.4", "untested", "h2"),
    gnode("s1", "service", "10.20.0.4:443/tcp", "deferred", "i1"),
    gnode("e1", "endpoint", "GET https://api.acme.test:443/v1/users/{id}", "tested", "s1"),
    gnode("n1", "ip", "10.20.0.0/24", "not_seen"),
    gnode("o1", "host", "orphan.test", "untested", "missing-parent"),
    gnode("l1", "host", "loop-a.test", "untested", "l2"),
    gnode("l2", "host", "loop-b.test", "untested", "l1"),
  ];
  const all = C.targetTree(nodes);
  assert.deepEqual(all.rows.map((r) => [r.depth, r.node.locator]), [
    [0, "acme.test"], [1, "www.acme.test"], [1, "api.acme.test"], [2, "10.20.0.4"], [3, "10.20.0.4:443/tcp"], [4, "GET https://api.acme.test:443/v1/users/{id}"],
    [0, "loop-a.test"], [0, "loop-b.test"], [0, "orphan.test"], [0, "10.20.0.0/24"],
  ]);
  assert.equal(all.shown, 10);
  const folded = C.targetTree(nodes, {}, new Set(["h2", "d1"]));
  assert.deepEqual(folded.rows.filter((r) => r.hasKids).map((r) => [r.node.id, r.open]), [["d1", false]]);
  assert.equal(C.targetTree(nodes, {}, new Set(["h2"])).rows.find((r) => r.id === "h2").open, false);
  assert.equal(C.targetTree(nodes, {}, new Set(["h2"])).rows.some((r) => r.id === "i1"), false);
  const tested = C.targetTree(nodes, { status: "tested" }, new Set(["d1"]));
  assert.deepEqual(tested.rows.map((r) => [r.node.id, r.context]), [["d1", true], ["h2", false], ["i1", true], ["s1", true], ["e1", false]], "the path to a match is kept and opened");
  assert.equal(tested.shown, 2);
  assert.deepEqual(C.targetTree(nodes, { kind: "ip" }).rows.filter((r) => !r.context).map((r) => r.id), ["i1", "n1"]);
  assert.deepEqual(C.targetTree(nodes, { text: " WWW" }).rows.map((r) => r.id), ["d1", "h1"]);
  assert.deepEqual(C.targetTree(nodes, { text: "nothing like this" }).rows, []);
  assert.deepEqual(C.targetCounts(nodes), { finding: 1, tested: 2, deferred: 1, untested: 5, not_seen: 1 });
  assert.equal(C.countsWords({ finding: 1, tested: 2, deferred: 0, untested: 5, not_seen: 1 }), "1 finding · 2 tested · 5 not tested yet · 1 in scope, not seen");
  assert.equal(C.countsWords({}), "nothing seen yet");
  assert.equal(C.nodeStatusWords("not_seen"), "in scope, not seen");
  assert.equal(gnode("x", "weird", "x", "weird").kind, "host", "an unknown kind or status is drawn, not dropped");
  assert.equal(gnode("x", "weird", "x", "weird").status, "untested");
});

test("a long tree draws a window of rows; a short one draws all", () => {
  assert.deepEqual(C.treeWindow(1500, 9000, 600), { start: 0, end: 1500, before: 0, after: 0, virtual: false });
  const w = C.treeWindow(5000, 4000, 800, 40, 10);
  assert.deepEqual(w, { start: 90, end: 130, before: 3600, after: 194800, virtual: true });
  assert.equal(C.treeWindow(5000, 10 ** 9, 800).end, 5000);
});

test("findings, missions and the scope editor of a target", () => {
  const nodes = [
    gnode("h1", "host", "www.acme.test", "finding", null, { findings: [{ claim: "c1", text: "XSS", status: "open", mission: "m-1", evidence: ["out:aa"] }, { claim: "c0", text: "Old", status: "withdrawn", mission: "m-2", evidence: [] }], missions: ["m-1", "m-2"] }),
    gnode("h2", "host", "api.acme.test", "tested", null, { missions: ["m-2"] }),
  ];
  const f = C.targetFindings(nodes);
  assert.deepEqual(f.map((x) => [x.claim, x.open, x.locator]), [["c1", true, "www.acme.test"], ["c0", false, "www.acme.test"]]);
  const byId = new Map([["s-1", { id: "s-1", mission: "m-1", title: "Audit acme" }], ["s-1a", { id: "s-1a", mission: "m-1", parent: "s-1", title: "agent" }], ["s-2", { id: "s-2", mission: "m-2", title: "Fleet" }]]);
  const m = C.targetMissions(nodes, byId, "acme");
  assert.deepEqual(m.map((x) => [x.id, x.session, x.title, x.seen, x.tested, x.findings]), [["m-1", "s-1", "Audit acme", 1, 0, 1], ["m-2", "s-2", "Fleet", 2, 1, 0]]);
  assert.equal(m[1].words, "saw 2 nodes · tested 1");
  assert.equal(C.targetMissions(nodes, new Map(), "acme")[0].session, null);
  assert.equal(C.scopeText(["a.test", "*.a.test"]), "a.test\n*.a.test");
  assert.deepEqual(C.scopeFromText("a.test, *.a.test\n\n a.test \n10.0.0.0/8"), { entries: ["a.test", "*.a.test", "10.0.0.0/8"] });
  assert.match(C.scopeFromText("a.test\nhttps://x.test").error, /not a CIDR/);
  assert.match(C.scopeFromText("a.test\nx y").error, /not a scope entry/);
  const cfg = C.targetOf({ name: "acme", scope: ["a.test"], upstream_insecure: ["u.test"], notes: "n", counts: { tested: 2 } });
  assert.equal(cfg.words, "2 tested");
  assert.deepEqual(C.targetPut(cfg, "a.test\n*.a.test", "x.a.test").body, { scope: ["a.test", "*.a.test"], exclude: ["x.a.test"], upstream_insecure: ["u.test"], intercept_passthrough: [], notes: "n" });
  assert.match(C.targetPut(cfg, "", "").error, /at least one/);
  assert.match(C.targetPut(cfg, "a.test", "bad entry").error, /scope entry/);
});

test("targets have routes, a form field and an event; the new-mission body names the target only when one is chosen", () => {
  assert.deepEqual(C.parseRoute("#/targets"), { view: "targets" });
  assert.deepEqual(C.parseRoute("#/t/acme"), { view: "target", name: "acme" });
  assert.deepEqual(C.parseRoute(C.targetHash("a b")), { view: "target", name: "a b" });
  assert.equal(C.targetHash(""), "#/targets");
  assert.deepEqual(C.parseRoute("#/t/"), { view: "empty" });
  assert.deepEqual(C.parseRoute("#/t/a/b"), { view: "empty" });
  assert.equal(C.buildNewSession({ workspace: "/w", message: "go", target: "acme" }).body.target, "acme");
  assert.equal("target" in C.buildNewSession({ workspace: "/w", message: "go", target: " " }).body, false);
  const fx = C.planEvent({ type: "target", name: "acme" }, { openId: null, known: () => true, missionOf: () => null });
  assert.deepEqual(fx, [{ fx: "target_changed", name: "acme" }]);
});

test("graph nodes take their parent from the edges when a node does not name one; a bash row owns the proxy's calls made during it", () => {
  const g = { nodes: [{ id: "d", kind: "domain", locator: "a.test", status: "untested" }, { id: "h", kind: "host", locator: "w.a.test", status: "tested" }, { id: "i", kind: "ip", locator: "10.0.0.1", status: "untested" }, { id: "s", kind: "service", locator: "10.0.0.1:80/tcp", status: "untested", parent: "h" }],
    edges: [{ kind: "parent", from: "h", to: "d" }, { kind: "resolves", from: "h", to: "i" }, { kind: "runs", from: "i", to: "s" }] };
  assert.deepEqual(C.graphNodes(g).map((n) => [n.id, n.parent]), [["d", null], ["h", "d"], ["i", "h"], ["s", "h"]]);
  assert.deepEqual(C.graphNodes([{ id: "x", kind: "host", locator: "x", status: "tested" }]).map((n) => n.parent), [null]);
  assert.deepEqual(C.graphNodes(null), []);
  const block = { name: "bash", ts: 100, result: { ts: 200 } };
  const list = [{ id: "a", call_id: null, source: "proxy", ts: 150 }, { id: "b", call_id: null, source: "proxy", ts: 250 }, { id: "c", call_id: "z", source: "proxy", ts: 150 }];
  assert.deepEqual(C.callWindowExchanges(block, list).map((x) => x.id), ["a"]);
  assert.deepEqual(C.callWindowExchanges({ ...block, name: "read" }, list), []);
});

// ---- credential profiles (CONTRACTS-TRAFFIC-TARGETS S7, S10, U5) ----

test("credRowText leaves out a zero count, sorts and trims hosts, and shows an error instead of counts", () => {
  const now = 1_000_000_000;
  assert.equal(C.credRowText({ profile: "default", cookies: 2, headers: 0, hosts: ["acme.test"], recorded_ms: now - 5 * 60_000 }, now), "default · 2 cookies · acme.test · recorded 5m ago");
  assert.equal(C.credRowText({ profile: "admin", cookies: 1, headers: 1, hosts: ["b.test", "a.test"], recorded_ms: now - 1000 }, now), "admin · 1 cookie, 1 header · a.test, b.test · recorded just now");
  assert.equal(C.credRowText({ profile: "p", cookies: 0, headers: 3, hosts: ["e", "d", "c", "b", "a"], recorded_ms: now - 3 * 3600_000 }, now), "p · 3 headers · a, b, c and 2 more · recorded 3h ago");
  assert.equal(C.credRowText({ profile: "bad", cookies: 4, headers: 4, hosts: ["a"], recorded_ms: now - 86400_000 * 2, error: "does not open" }, now), "bad · does not open · recorded 2d ago");
  assert.equal(C.credRowText({ profile: "x", cookies: 0, headers: 0, hosts: [], recorded_ms: 0 }, now), "x");
});

test("credShow lists kind name and host, credCommands names the target, credsRefOf reads session_start", () => {
  const r = C.credShow({ summary: "default · 1 cookie · a.test", items: [{ kind: "cookie", name: "sid", host: "a.test" }, { kind: "header", name: "Authorization", host: "a.test" }] });
  assert.deepEqual(r.lines, ["cookie sid · a.test", "header Authorization · a.test"]);
  assert.equal(r.summary, "default · 1 cookie · a.test");
  assert.deepEqual(C.credShow(null), { summary: "", lines: [] });
  assert.equal(C.credCommands("acme")[0], "ferret creds record --target acme");
  assert.match(C.credCommands("acme")[1], /^ferret creds set --target acme --host .* --cookie '.*'$/);
  assert.deepEqual(C.credsRefOf({ creds: { profile: "default", summary: "s", dropped: 2 } }), { profile: "default", summary: "s", dropped: 2 });
  assert.equal(C.credsRefOf({}), null);
  assert.equal(C.credsRefOf(null), null);
});

test("buildNewSession sends creds only with a target and not for none", () => {
  const base = { workspace: "/w", message: "go" };
  assert.equal(C.buildNewSession({ ...base, target: "acme", creds: "default" }).body.creds, "default");
  assert.equal("creds" in C.buildNewSession({ ...base, target: "acme", creds: "" }).body, false);
  assert.equal("creds" in C.buildNewSession({ ...base, target: "acme", creds: "none" }).body, false);
  assert.equal("creds" in C.buildNewSession({ ...base, target: "", creds: "default" }).body, false);
});

// ---- Slice B usability fixes ----

test("isPendingReceipt unlocks Send after a message is held in the queue", () => {
  assert.equal(C.isPendingReceipt(null), false);
  assert.equal(C.isPendingReceipt({ accepted: false }), false);
  assert.equal(C.isPendingReceipt({ accepted: true, state: "queued" }), true);
  assert.equal(C.isPendingReceipt({ accepted: true, state: "held" }), false, "held after-turn message must not lock Send");
  assert.equal(C.isPendingReceipt({ accepted: true, state: "failed" }), false);
  assert.equal(C.isPendingReceipt({ accepted: true, state: "delivered", recordedSeq: 42 }), false);
});

test("canQueueSession allows any running operable root session regardless of pack role name", () => {
  const running = st({ phase: "running" });
  const idle = st({ phase: "idle" });
  const ended = st({ phase: "ended", outcome: "done" });
  assert.equal(C.canQueueSession(info("a", { role: "lead", status: running })), true);
  assert.equal(C.canQueueSession(info("b", { role: "researcher", status: running })), true);
  assert.equal(C.canQueueSession(info("c", { role: "commander", status: running })), true);
  assert.equal(C.canQueueSession(info("d", { role: "chat", status: running })), true);
  assert.equal(C.canQueueSession(info("e", { role: "worker", parent: "a", status: running })), false, "child agents cannot queue");
  assert.equal(C.canQueueSession(info("f", { role: "lead", status: idle })), false);
  assert.equal(C.canQueueSession(info("g", { role: "lead", status: ended })), false);
  assert.equal(C.canQueueSession(info("h", { role: "lead", archived: true, status: running })), false);
  assert.equal(C.canQueueSession(null), false);
});

test("cardResolution ignores empty approved arrays so parked answers do not read as approved host grants", () => {
  const item = { item_id: "i", item_kind: "parked", blocking: true, options: [], text: "budget exhausted" };
  const done = { seq: 5, ts: 1, answer: "Keep working on the goal." };
  assert.equal(C.cardResolution(item, done, { answer: done.answer, approved: [] }, null).approved, undefined);
  assert.deepEqual(C.cardResolution(item, done, { answer: "", approved: ["a.test"] }, null).approved, ["a.test"]);
});

test("defaultModelProfile picks daemon default over alphabetical order, else first reachable", () => {
  const models = [
    { profile: "alpha", reachable: false },
    { profile: "beta", reachable: true },
    { profile: "zeta", reachable: true },
  ];
  assert.equal(C.defaultModelProfile(models, "zeta"), "zeta");
  assert.equal(C.defaultModelProfile(models, "missing"), "beta", "falls back to first reachable");
  assert.equal(C.defaultModelProfile(models, ""), "beta");
  assert.equal(C.defaultModelProfile([{ profile: "only", reachable: false }], ""), "only");
  assert.equal(C.defaultModelProfile([], "zeta"), "");
});

test("proseTree renders tables, blockquotes, hr, heading levels, italics and safe http(s) links without unsafe schemes", () => {
  const md = [
    "# H1",
    "## H2",
    "### H3",
    "",
    "| Host | Status |",
    "| --- | --- |",
    "| `a.test` | **ok** |",
    "| b\\|c.test | *warn* |",
    "",
    "> Quoted *line* with [docs](https://example.com/a) and [bad](javascript:alert(1))",
    "> second quote line",
    "",
    "---",
    "",
    "Keep snake_case_name and 2*3*4 literal, but *italic* works.",
  ].join("\n");
  const blocks = C.proseTree(md);
  assert.deepEqual(blocks.map((b) => b.type), ["h", "h", "h", "table", "blockquote", "hr", "p"]);
  assert.deepEqual([blocks[0].level, blocks[1].level, blocks[2].level], [2, 3, 4]);
  assert.equal(blocks[3].headers.length, 2);
  assert.equal(blocks[3].rows.length, 2);
  assert.deepEqual(blocks[3].rows[0][0], [{ type: "code", text: "a.test" }]);
  assert.deepEqual(blocks[3].rows[0][1], [{ type: "strong", text: "ok" }]);
  assert.deepEqual(blocks[3].rows[1][0], [{ type: "text", text: "b|c.test" }]);
  assert.deepEqual(blocks[3].rows[1][1], [{ type: "em", text: "warn" }]);
  assert.ok(blocks[4].inline.some((p) => p.type === "a" && p.href === "https://example.com/a" && p.text === "docs"));
  assert.ok(!blocks[4].inline.some((p) => p.type === "a" && /javascript:/i.test(p.href)), "javascript: links stay inert text");
  assert.ok(blocks[4].inline.some((p) => p.type === "text" && p.text.includes("[bad](javascript:alert(1))")));
  const pInline = blocks[6].inline;
  assert.ok(pInline.some((p) => p.type === "text" && p.text.includes("snake_case_name") && p.text.includes("2*3*4")));
  assert.ok(pInline.some((p) => p.type === "em" && p.text === "italic"));
});

test("findFields and briefDetails expose all fields of child_spawned briefs", () => {
  const block = {
    kind: "child_spawned",
    seq: 12,
    role: "auditor",
    child: "s-child1",
    brief: {
      question: "Check auth middleware",
      hypothesis: "Missing CSRF token check",
      scope: "crates/web",
      do_not: "Do not modify prod config",
      return: "Finding summary",
      stop_when: "Verified or refuted",
      context: "Follow-up from PR #42",
    },
  };
  const fields = C.findFields(block, "all");
  const joined = fields.map((f) => f[1]).join(" | ");
  for (const needle of ["auditor", "s-child1", "Check auth middleware", "CSRF token", "crates/web", "prod config", "Finding summary", "refuted", "PR #42"]) {
    assert.ok(joined.includes(needle), `expected findFields to contain ${needle}`);
  }
  const details = C.briefDetails(block.brief);
  assert.deepEqual(details.map((d) => d.key), ["hypothesis", "scope", "do_not", "return", "stop_when", "context"]);
  assert.deepEqual(C.briefDetails({ question: "Only question" }), []);
});

test("packRoleSummary surfaces role description, intercept/restricted flags, and open-network warning", () => {
  const pack = {
    name: "vr",
    description: "Vulnerability research.",
    intercept: true,
    requires_restricted_network: true,
    roles: [{ name: "researcher", description: "Leads vulnerability analysis." }],
  };
  const open = C.packRoleSummary(pack, "researcher", "open");
  assert.equal(open.desc, "Vulnerability research.");
  assert.equal(open.roleDesc, "Leads vulnerability analysis.");
  assert.deepEqual(open.flags, ["MITM proxy intercept", "Requires restricted network"]);
  assert.match(open.warning, /restricted network/i);
  const restricted = C.packRoleSummary(pack, "researcher", "allowlist");
  assert.equal(restricted.warning, null);
});

test("resolvePriorInput maps known session ids to mission ids and flags unknown session ids", () => {
  const byId = new Map([
    ["s-111", { id: "s-111", mission: "m-aaa" }],
    ["s-222", { id: "s-222", mission: "m-bbb" }],
  ]);
  const r = C.resolvePriorInput("s-111 m-ccc s-111 s-unknown", byId);
  assert.equal(r.text, "m-aaa m-ccc s-unknown");
  assert.deepEqual(r.mapped, [{ from: "s-111", to: "m-aaa" }, { from: "s-111", to: "m-aaa" }]);
  assert.deepEqual(r.unknownSessions, ["s-unknown"]);
});

test("targetCreateBody and extended targetPut validate all target settings", () => {
  assert.match(C.targetCreateBody({ name: "", scope: "a.test" }).error, /name is required/i);
  assert.match(C.targetCreateBody({ name: "../bad", scope: "a.test" }).error, /must start/i);
  const created = C.targetCreateBody({
    name: "acme",
    scope: "*.acme.test\n10.0.0.0/24",
    exclude: "pay.acme.test",
    upstream_insecure: "lab.acme.test",
    intercept_passthrough: "pin.acme.test",
    notes: "Q4 pentest",
  });
  assert.deepEqual(created.body, {
    name: "acme",
    scope: ["*.acme.test", "10.0.0.0/24"],
    exclude: ["pay.acme.test"],
    upstream_insecure: ["lab.acme.test"],
    intercept_passthrough: ["pin.acme.test"],
    notes: "Q4 pentest",
  });
  const updated = C.targetPut(created.body, "*.acme.test", "", { upstream_insecure: "127.0.0.1", notes: "updated" });
  assert.deepEqual(updated.body.upstream_insecure, ["127.0.0.1"]);
  assert.deepEqual(updated.body.intercept_passthrough, ["pin.acme.test"]);
  assert.equal(updated.body.notes, "updated");
  assert.match(C.targetPut(created.body, "*.acme.test", "", { upstream_insecure: "https://bad" }).error, /upstream insecure/i);
});

test("export URLs and daemon report formatters (SARIF, HAR, reload, GC, MCP check, Signal)", () => {
  assert.equal(C.sarifUrl("m-1"), "/api/missions/m-1/sarif");
  assert.equal(C.harUrl("m-1"), "/api/missions/m-1/har");
  assert.equal(C.harUrl("m-1", { host: "a.test", limit: 50 }), "/api/missions/m-1/har?host=a.test&limit=50");
  assert.equal(C.harUrl("m-1", { host: "all" }), "/api/missions/m-1/har");
  assert.equal(C.formatHarImport({ imported: 12, skipped: 2, failed: 1, truncated: true }), "HAR import: 12 imported · 2 skipped · 1 failed · truncated.");
  assert.match(C.formatReloadReport({ added: ["fast"], changed: ["main"], removed: [], rebound: ["s-1"], default_model: "main", notes: [] }), /added: fast.*changed: main.*1 session rebound.*default: main/);
  assert.equal(C.formatReloadReport({}), "Profiles reloaded; no changes.");
  assert.match(C.formatGcReport({ examined: 10, kept: 7, collected: 3, collected_bytes: 2048, applied: false }), /GC preview: 3 blobs reclaimable/);
  assert.match(C.formatGcReport({ examined: 10, kept: 7, collected: 3, collected_bytes: 2048, applied: true }), /GC removed 3 blobs/);
  const mcpOk = C.formatMcpCheck({ server: "gh", protocol: "2025-03-26", server_name: "github", server_version: "1.0", tools: [{ name: "t1" }], error: null, stderr_tail: [] });
  assert.equal(mcpOk.ok, true);
  assert.match(mcpOk.summary, /OK · github 1\.0 · protocol 2025-03-26 · 1 tool/);
  const mcpErr = C.formatMcpCheck({ server: "gh", error: "connection refused", tools: [], stderr_tail: ["err line"] });
  assert.equal(mcpErr.ok, false);
  assert.match(mcpErr.summary, /Check failed: connection refused/);
  const sigOff = C.formatSignalStatus(null);
  assert.equal(sigOff.available, false);
  const sigOn = C.formatSignalStatus({ enabled: true, connected: true, account: "+1555", recipient: "+1666", last_event_ms: 99000, pending_sends: 1, dropped_events: 0 }, 100000);
  assert.equal(sigOn.state, "Connected");
  assert.equal(sigOn.tone, "ok");
  assert.ok(sigOn.rows.some(([k, v]) => k === "Account" && v === "+1555"));
  assert.ok(!sigOn.rows.some(([k]) => k === "Guests"));
  const sigGuests = C.formatSignalStatus({ enabled: true, connected: true, account: "+15550100", recipient: "+15550199", guests_enabled: true, guests_approved: 2, guests_pending: 1 }, 100000);
  assert.ok(sigGuests.rows.some(([k, v]) => k === "Guests" && v === "2 approved, 1 pending"));
});

test("rewriteRuleSummary and buildRewriteRule validate and format proxy rewrite rules", () => {
  assert.match(C.buildRewriteRule({ name: "" }).error, /name is required/i);
  assert.match(C.buildRewriteRule({ name: "r1", actionType: "set_header", headerName: "" }).error, /Header name/i);
  // set_status requires response phase and 200..=599 excluding 204 and 304 (matches crates/ferret-net/src/rewrite.rs).
  assert.match(C.buildRewriteRule({ name: "r1", phase: "request", actionType: "set_status", value: "200" }).error, /response phase/i);
  assert.match(C.buildRewriteRule({ name: "r1", phase: "response", actionType: "set_status", value: "100" }).error, /200 and 599/);
  assert.match(C.buildRewriteRule({ name: "r1", phase: "response", actionType: "set_status", value: "204" }).error, /204 and 304/);
  assert.match(C.buildRewriteRule({ name: "r1", phase: "response", actionType: "set_status", value: "304" }).error, /204 and 304/);
  assert.match(C.buildRewriteRule({ name: "r1", phase: "response", actionType: "set_status", value: "999" }).error, /200 and 599/);
  assert.equal(C.buildRewriteRule({ name: "r1", phase: "response", actionType: "set_status", value: "418" }).rule.actions[0].value, 418);
  const built = C.buildRewriteRule({
    name: "auth-hdr",
    phase: "request",
    priority: 10,
    host: "*.acme.test",
    methods: "get, post",
    url_regex: "/api/.*",
    actionType: "set_header",
    headerName: "X-Api-Key",
    value: "secret-val",
    sensitive: true,
    note: "staging key",
  });
  assert.equal(built.rule.enabled, false);
  assert.deepEqual(built.rule.matchers, { host: "*.acme.test", methods: ["GET", "POST"], url_regex: "/api/.*" });
  assert.deepEqual(built.rule.actions, [{ type: "set_header", name: "X-Api-Key", value: "secret-val", sensitive: true }]);
  assert.equal(C.rewriteRuleSummary(built.rule), "request · host=*.acme.test GET/POST url=//api/.*/ · set header X-Api-Key (secret)");

  // Editing an existing sensitive rule with blank value sends value: null so the daemon retains the stored secret,
  // and preserves extra matchers (headers, body_regex, resp_headers, resp_body_regex).
  const edited = C.buildRewriteRule({
    id: 7,
    name: "auth-hdr",
    enabled: true,
    phase: "request",
    host: "*.acme.test",
    extraMatchers: { headers: [{ name: "X-Env", value_regex: "stage" }], body_regex: "token=" },
    actionType: "set_header",
    headerName: "X-Api-Key",
    value: "",
    sensitive: true,
    hadSensitiveValue: true,
  });
  assert.equal(edited.rule.actions[0].value, null, "blank sensitive value on edit must send null to preserve secret");
  assert.deepEqual(edited.rule.matchers.headers, [{ name: "X-Env", value_regex: "stage" }]);
  assert.equal(edited.rule.matchers.body_regex, "token=");
  // Providing a new value overwrites it explicitly.
  const rotated = C.buildRewriteRule({
    id: 7, name: "auth-hdr", phase: "request", host: "*.acme.test",
    actionType: "set_header", headerName: "X-Api-Key", value: "new-secret", sensitive: true, hadSensitiveValue: true,
  });
  assert.equal(rotated.rule.actions[0].value, "new-secret");
  // Multi-action rules are rejected instead of silently truncated.
  assert.match(C.buildRewriteRule({ id: 9, name: "multi", extraActions: [{ type: "delete_header", name: "X-A" }], actionType: "set_header", headerName: "X-B", value: "1" }).error, /Multi-action/);
});

test("classifyAuthInput distinguishes ferret open URLs, hex codes/tokens, and bearer tokens", () => {
  assert.match(C.classifyAuthInput("  ").error, /Paste a login URL/);
  const code = "0123456789abcdef0123456789abcdef";
  assert.deepEqual(C.classifyAuthInput("http://127.0.0.1:7878/#code=" + code), { kind: "code", value: code });
  assert.deepEqual(C.classifyAuthInput("#code=" + code), { kind: "code", value: code });
  assert.deepEqual(C.classifyAuthInput(code), { kind: "code_or_token", value: code });
  assert.deepEqual(C.classifyAuthInput("bearer-tok-xyz"), { kind: "token", value: "bearer-tok-xyz" });
});

test("app.js: when #auth-overlay exists, lost() preserves the DOM non-destructively and sets document.title for ferret-desk KVO", async (t) => {
  let replacedBody = false;
  const makeNode = (id) => ({ id, hidden: true, textContent: "", value: "", dataset: {}, addEventListener() {}, focus() {}, setAttribute() {}, append() {} });
  const nodes = new Map(["auth-overlay", "auth-overlay-reason", "auth-overlay-error", "auth-overlay-form", "auth-overlay-input", "auth-overlay-submit", "auth-overlay-retry"].map((id) => [id, makeNode(id)]));
  const fake = {
    document: {
      title: "ferret",
      getElementById: (id) => nodes.get(id) || null,
      createElement: (tag) => ({ tag, kids: [], append(...k) { this.kids.push(...k); }, setAttribute() {} }),
      createTextNode: (text) => ({ textContent: text }),
      body: { replaceChildren: () => { replacedBody = true; } },
    },
    window: { addEventListener() {} },
    location: { hash: "", pathname: "/", search: "", reload() {} },
    history: { replaceState() {} },
    matchMedia: () => ({ matches: false, addEventListener() {} }),
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    fetch: async () => ({ ok: false, status: 401 }),
  };
  for (const [name, value] of Object.entries(fake)) {
    const before = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
    t.after(() => (before ? Object.defineProperty(globalThis, name, before) : delete globalThis[name]));
  }
  await import("./app.js?page=overlay-check");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(replacedBody, false, "non-destructive overlay must not wipe document.body");
  assert.equal(nodes.get("auth-overlay").hidden, false, "#auth-overlay must be shown");
  assert.equal(globalThis.document.title, "ferret · not signed in", "must preserve ferret-desk KVO title contract");
});

test("isEmbeddedDesk detects the FerretDesk/<version> UA token without JS injection", () => {
  assert.equal(C.isEmbeddedDesk("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 FerretDesk/0.1.0"), true);
  assert.equal(C.isEmbeddedDesk("FerretDesk/1.2.0-beta"), true);
  assert.equal(C.isEmbeddedDesk("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15"), false);
  assert.equal(C.isEmbeddedDesk("MyFerretDesk/0.1.0"), false);
  assert.equal(C.isEmbeddedDesk(""), false);
  assert.equal(C.isEmbeddedDesk(null), false);
});

test("healthDot and connectionWords surface Signal bridge disconnects and errors", () => {
  const okModels = [{ profile: "local", reachable: true }];
  assert.equal(C.healthDot({ connected: true, models: okModels, signal: { enabled: false, connected: false } }).state, "green");
  assert.equal(C.healthDot({ connected: true, models: okModels, signal: { enabled: true, connected: true } }).state, "green");

  const down = C.healthDot({ connected: true, models: okModels, signal: { enabled: true, connected: false, last_error: "socket refused" } });
  assert.equal(down.state, "amber");
  assert.match(down.tip, /Signal bridge: disconnected \(socket refused\)/);

  const err = C.healthDot({ connected: true, models: okModels, signal: { enabled: true, connected: true, last_error: "rate limited" } });
  assert.equal(err.state, "amber");
  assert.match(err.tip, /Signal bridge error: rate limited/);

  const words = C.connectionWords({ connected: true, everConnected: true, models: okModels, signal: { enabled: true, connected: false } });
  assert.equal(words.short, "Live");
  assert.match(words.tip, /Signal bridge: disconnected/);

  assert.equal(C.healthDot({ connected: false, models: okModels, signal: { enabled: true, connected: true } }).state, "red");
});

test("proseTree captures fenced code language tags and supports 4-backtick nested fences", () => {
  const plain = C.proseTree("```\nconst x = 1;\n```");
  assert.equal(plain.length, 1);
  assert.equal(plain[0].type, "pre");
  assert.equal("lang" in plain[0], false, "omits lang property when fence has no language tag");

  const tagged = C.proseTree("```diff\n-old\n+new\n```");
  assert.deepEqual(tagged, [{ type: "pre", text: "-old\n+new", lang: "diff" }]);

  const nested = C.proseTree("````markdown\nHere is a block:\n```js\nconsole.log(1);\n```\n````");
  assert.equal(nested.length, 1);
  assert.equal(nested[0].type, "pre");
  assert.equal(nested[0].lang, "markdown");
  assert.equal(nested[0].text, "Here is a block:\n```js\nconsole.log(1);\n```");
});

test("rewriteActionsForPhase and buildRewriteRule enforce request vs response phase constraints", () => {
  const reqActs = C.rewriteActionsForPhase("request").map(([v]) => v);
  const respActs = C.rewriteActionsForPhase("response").map(([v]) => v);
  assert.ok(reqActs.includes("set_method") && reqActs.includes("set_path_query") && reqActs.includes("replace_url"));
  assert.ok(!reqActs.includes("set_status"));
  assert.ok(respActs.includes("set_status"));
  assert.ok(!respActs.includes("set_method") && !respActs.includes("set_path_query") && !respActs.includes("replace_url"));

  assert.match(C.buildRewriteRule({ name: "r1", phase: "response", actionType: "set_method", value: "POST" }).error, /request phase/i);
  assert.match(C.buildRewriteRule({ name: "r1", phase: "response", actionType: "set_path_query", value: "/v2" }).error, /request phase/i);
  assert.match(C.buildRewriteRule({ name: "r1", phase: "response", actionType: "replace_url", regex: "a", value: "b" }).error, /request phase/i);

  const reqBuilt = C.buildRewriteRule({
    name: "r-req", phase: "request", status: "200, 404",
    extraMatchers: { headers: [{ name: "X-A", value_regex: "1" }], resp_headers: [{ name: "X-R", value_regex: "2" }], resp_body_regex: "err" },
    actionType: "set_header", headerName: "X-Test", value: "1",
  });
  assert.equal(reqBuilt.rule.matchers.status, undefined, "request phase drops response status matcher");
  assert.equal(reqBuilt.rule.matchers.resp_headers, undefined, "request phase drops resp_headers matcher");
  assert.equal(reqBuilt.rule.matchers.resp_body_regex, undefined, "request phase drops resp_body_regex matcher");
  assert.deepEqual(reqBuilt.rule.matchers.headers, [{ name: "X-A", value_regex: "1" }]);

  const respBuilt = C.buildRewriteRule({
    name: "r-resp", phase: "response", status: "200, 404",
    extraMatchers: { resp_headers: [{ name: "X-R", value_regex: "2" }], resp_body_regex: "err" },
    actionType: "set_header", headerName: "X-Test", value: "1",
  });
  assert.deepEqual(respBuilt.rule.matchers.status, ["200", "404"]);
  assert.deepEqual(respBuilt.rule.matchers.resp_headers, [{ name: "X-R", value_regex: "2" }]);
  assert.equal(respBuilt.rule.matchers.resp_body_regex, "err");
});

test("attachmentName derives MIME extensions and shouldPasteFiles distinguishes screenshots/Finder copies from rich text", () => {
  assert.equal(C.attachmentName({ name: "report.pdf", type: "application/pdf" }), "report.pdf");
  assert.equal(C.attachmentName({ name: "", type: "image/png" }), "pasted-image.png");
  assert.equal(C.attachmentName({ name: "  ", type: "image/jpeg; charset=binary" }), "pasted-image.jpg");
  assert.equal(C.attachmentName({ name: "", type: "text/plain" }), "pasted-file.txt");
  assert.equal(C.attachmentName({ name: "", type: "application/octet-stream" }), "pasted-file");

  assert.equal(C.shouldPasteFiles([], ""), false);
  assert.equal(C.shouldPasteFiles([{ name: "image.png", type: "image/png" }], ""), true);
  assert.equal(C.shouldPasteFiles([{ name: "capture.png" }], "capture.png"), true, "macOS Finder single-file copy attaches");
  assert.equal(C.shouldPasteFiles([{ name: "a.png" }, { name: "b.pdf" }], "a.png\nb.pdf"), true, "macOS Finder multi-file copy attaches");
  assert.equal(C.shouldPasteFiles([{ name: "image.png" }], "Col1\tCol2\n1\t2"), false, "spreadsheet cell text stays text paste");
});

test("switcherActions filters quick actions by query and context, and keySheet documents queue shortcut", () => {
  const base = C.switcherActions("", { targetsSupported: false, inSession: false }).map((a) => a.id);
  assert.ok(base.includes("new-mission") && base.includes("inbox") && base.includes("daemon-status") && base.includes("keys"));
  assert.ok(!base.includes("targets") && !base.includes("toggle-inspector"));

  const full = C.switcherActions("", { targetsSupported: true, inSession: true }).map((a) => a.id);
  assert.ok(full.includes("targets") && full.includes("toggle-inspector"));

  assert.deepEqual(C.switcherActions("signal", { targetsSupported: true, inSession: true }).map((a) => a.id), ["daemon-status"]);
  assert.deepEqual(C.switcherActions("inspector", { targetsSupported: true, inSession: true }).map((a) => a.id), ["toggle-inspector"]);

  const macRows = C.keySheet(true).flatMap((s) => s.rows);
  const winRows = C.keySheet(false).flatMap((s) => s.rows);
  assert.ok(macRows.some((r) => r.keys.join("+") === "Option+Enter" && /queue/i.test(r.text)));
  assert.ok(winRows.some((r) => r.keys.join("+") === "Alt+Enter" && /queue/i.test(r.text)));
});

test("style.css palette honors Cross-Layer Contract #2, Ferret favicon branding, and WCAG 2.1 AA (>= 4.5:1) contrast", () => {
  const css = readFileSync(join(here, "style.css"), "utf8");
  const svg = readFileSync(join(here, "favicon.svg"), "utf8");
  assert.ok(svg.includes("#111520"), "favicon.svg uses Ferret midnight-indigo backing");
  assert.ok(!svg.includes("#2557d6"), "favicon.svg replaces legacy cobalt loom mark");

  const parseVars = (block) => {
    const vars = {};
    for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;/g)) vars[m[1]] = m[2].toLowerCase();
    return vars;
  };
  const darkBlock = css.match(/:root\s*\{([^}]+)\}/);
  const lightBlock = css.match(/@media\s*\(prefers-color-scheme:\s*light\)\s*\{\s*:root\s*\{([^}]+)\}/);
  assert.ok(darkBlock && lightBlock, "dark and light :root token blocks exist");
  const dark = parseVars(darkBlock[1]);
  const light = parseVars(lightBlock[1]);

  // Cross-Layer Contract #2: exact backing surface hex shared with ferret-desk WKWebView.
  assert.equal(dark["--bg"], "#111520");
  assert.equal(light["--bg"], "#ffffff");

  const toRgb = (hex) => {
    const h = hex.slice(1);
    const full = h.length === 3 ? h.split("").map((c) => c + c).join("") : h.slice(0, 6);
    return [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16) / 255);
  };
  const relLum = (hex) => {
    const [r, g, b] = toRgb(hex).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const contrast = (fg, bg) => {
    const l1 = relLum(fg), l2 = relLum(bg);
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
  };

  for (const [mode, t] of [["dark", dark], ["light", light]]) {
    const surfaces = ["--bg", "--bg-side", "--bg-2", "--surface-card"];
    const textTokens = ["--strong", "--fg", "--dim", "--caption", "--accent", "--info", "--ok-soft", "--bad-soft", "--warn-soft", "--info-soft", "--attn-text"];
    for (const s of surfaces) {
      for (const f of textTokens) {
        const ratio = contrast(t[f], t[s]);
        assert.ok(ratio >= 4.5, `${mode}: ${f} (${t[f]}) on ${s} (${t[s]}) contrast ${ratio.toFixed(2)} < 4.5`);
      }
    }
    for (const [f, s] of [
      ["--on-accent-fill", "--accent-fill"],
      ["--on-accent-fill", "--accent-btn"],
      ["--on-attn", "--attn"],
      ["--bad", "--bg"],
      ["--bad", "--bg-2"],
      ["--attn-text", "--attn-bg"],
      ["--attn-text", "--attn-card"],
      ["--attn-dim", "--attn-card"],
      ["--strong", "--bubble"],
      ["--fg", "--bubble"],
      ["--strong", "--sel"],
      ["--fg", "--code-bg"],
      ["--strong", "--code-bg"],
    ]) {
      const ratio = contrast(t[f], t[s]);
      assert.ok(ratio >= 4.5, `${mode}: ${f} (${t[f]}) on ${s} (${t[s]}) contrast ${ratio.toFixed(2)} < 4.5`);
    }
  }
});

test("app.js: embedded FerretDesk UA adds body.embedded-desk and lost() closes open dialogs and marks shell inert", async (t) => {
  const classes = new Set();
  const makeNode = (id) => ({ id, hidden: true, inert: false, textContent: "", value: "", dataset: {}, addEventListener() {}, focus() {}, setAttribute() {}, append() {} });
  const ids = ["auth-overlay", "auth-overlay-reason", "auth-overlay-error", "auth-overlay-form", "auth-overlay-input", "auth-overlay-toggle", "auth-overlay-submit", "auth-overlay-retry", "left", "mid", "right"];
  const nodes = new Map(ids.map((id) => [id, makeNode(id)]));
  let closedDialogs = 0;
  const fakeDialog = { open: true, close() { this.open = false; closedDialogs++; } };
  const fake = {
    document: {
      title: "ferret",
      getElementById: (id) => nodes.get(id) || null,
      querySelectorAll: (sel) => (sel === "dialog[open]" ? [fakeDialog] : []),
      createElement: (tag) => ({ tag, kids: [], append(...k) { this.kids.push(...k); }, setAttribute() {} }),
      createTextNode: (text) => ({ textContent: text }),
      body: {
        classList: { toggle: (name, on) => (on ? classes.add(name) : classes.delete(name)), add: (name) => classes.add(name) },
        replaceChildren: () => {},
      },
    },
    navigator: { userAgent: "Mozilla/5.0 AppleWebKit/605.1.15 FerretDesk/0.1.0" },
    window: { addEventListener() {} },
    location: { hash: "", pathname: "/", search: "", reload() {} },
    history: { replaceState() {} },
    matchMedia: () => ({ matches: false, addEventListener() {} }),
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    fetch: async () => ({ ok: false, status: 401 }),
  };
  for (const [name, value] of Object.entries(fake)) {
    const before = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
    t.after(() => (before ? Object.defineProperty(globalThis, name, before) : delete globalThis[name]));
  }
  await import("./app.js?page=embedded-overlay-check");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(classes.has("embedded-desk"), true, "body.embedded-desk must be toggled from FerretDesk UA");
  assert.equal(closedDialogs, 1, "open dialogs must close when #auth-overlay opens");
  assert.equal(nodes.get("left").inert, true);
  assert.equal(nodes.get("mid").inert, true);
  assert.equal(nodes.get("right").inert, true);
  assert.equal(nodes.get("auth-overlay").hidden, false);
  assert.equal(globalThis.document.title, "ferret · not signed in");
});

test("Wave A helpers: sanitized HAR/SARIF URLs, scope revocation, and panic kill-switch formatting", () => {
  assert.equal(C.EXPORT_SANITIZED_NOTE, "Sanitized export — secrets redacted");
  assert.equal(C.sarifUrl("m-1"), "/api/missions/m-1/sarif");
  assert.equal(C.sarifUrl("m-1", { includeSecrets: true }), "/api/missions/m-1/sarif?sanitize=false");
  assert.equal(C.harUrl("m-1"), "/api/missions/m-1/har");
  assert.equal(C.harUrl("m-1", { host: "a.test", includeSecrets: true }), "/api/missions/m-1/har?host=a.test&sanitize=false");

  assert.deepEqual(C.scopeRevokeRequest("s-1", [" api.test ", "cdn.test"], "done"), {
    path: "/api/sessions/s-1/scope/revoke",
    body: { hosts: ["api.test", "cdn.test"], note: "done" },
  });
  assert.deepEqual(C.scopeRevokeRequest("s/1", ["a.test"]), {
    path: "/api/sessions/s%2F1/scope/revoke",
    body: { hosts: ["a.test"] },
  });
  assert.deepEqual(C.scopeRevokeRequest("s-1", [" ", ""]), { error: "Name the hosts to revoke." });

  assert.deepEqual(C.activeGrantedHosts({ scope: ["API.test", "cdn.test"] }, new Set(["api.test"])), [
    { host: "API.test", revoked: true },
    { host: "cdn.test", revoked: false },
  ]);
  assert.equal(
    C.formatScopeRevoke({ lead: "s-1", revoked: ["api.test"], connections_cut: 2 }),
    "Revoked api.test (2 connections cut).",
  );
  assert.equal(
    C.formatScopeRevoke({ lead: "s-1", revoked: ["api.test"], connections_cut: 1 }),
    "Revoked api.test (1 connection cut).",
  );

  assert.deepEqual(C.panicRequest(""), { path: "/api/panic", body: {} });
  assert.deepEqual(C.panicRequest("  out of scope  "), { path: "/api/panic", body: { reason: "out of scope" } });
  assert.equal(
    C.formatPanicReport({ connections_cut: 3, sessions_stopped: ["s-1", "s-2"], boxes_torn_down: 1, rewrites_disabled: 4 }),
    "Panic stop complete: 3 connections cut · 2 sessions stopped · 1 box torn down · 4 rewrite rules disabled.",
  );
  assert.equal(
    C.formatPanicReport({ connections_cut: 0, sessions_stopped: [], boxes_torn_down: 0, rewrites_disabled: 0 }),
    "Panic stop complete: 0 connections cut · 0 sessions stopped · 0 boxes torn down · 0 rewrite rules disabled.",
  );
  assert.equal(
    C.formatPanicReport({ connections_cut: 1, sessions_stopped: ["s-1"], boxes_torn_down: 0, rewrites_disabled: 0, processes_killed: 2, processes_left: 1 }),
    "Panic stop complete: 1 connection cut · 1 session stopped · 0 boxes torn down · 0 rewrite rules disabled · 2 processes left under the sandboxes stopped (1 could not be).",
  );
  assert.equal(
    C.formatScopeRevoke({ lead: "s-1", revoked: ["a.test", "x.b.test"], not_granted: ["x.b.test"], connections_cut: 0 }),
    "Revoked a.test, x.b.test (0 connections cut). Not granted by itself, refused from now on: x.b.test.",
  );
});

test("Wave B helpers: passive signal summarization, severity ranking, and principal formatting", () => {
  // Empty / invalid inputs produce a zeroed summary.
  assert.deepEqual(C.summarizePassiveSignals(null), {
    total: 0,
    maxSeverity: null,
    counts: { high: 0, medium: 0, low: 0, info: 0 },
    badge: "",
    tooltip: "",
    items: [],
  });
  assert.equal(C.summarizePassiveSignals([]).total, 0);

  // Mixed severities: ranked high > medium > low > info, unknown/case normalized cleanly.
  const mixed = C.summarizePassiveSignals([
    { kind: "missing_security_headers", severity: "info", summary: "Missing CSP header" },
    { kind: "cookie_insecure", severity: "LOW", summary: "Session cookie lacks HttpOnly" },
    { kind: "cors_misconfig", severity: "High", summary: "Reflected Origin with ACAC: true", detail: "Origin: https://evil.example" },
    { kind: "verbose_error", severity: "medium", summary: "Stack trace leaked in 500 body" },
    { kind: "custom_note", severity: "bogus", summary: "Normalized to info" },
    { kind: "secret_leak", severity: "high", summary: "AWS key prefix observed" },
  ]);
  assert.equal(mixed.total, 6);
  assert.equal(mixed.maxSeverity, "high");
  assert.deepEqual(mixed.counts, { high: 2, medium: 1, low: 1, info: 2 });
  assert.equal(mixed.badge, "2 high · 1 medium · 1 low · 2 info");
  assert.deepEqual(
    mixed.items.map((s) => `${s.severity}:${s.kind}`),
    [
      "high:cors_misconfig",
      "high:secret_leak",
      "medium:verbose_error",
      "low:cookie_insecure",
      "info:missing_security_headers",
      "info:custom_note",
    ],
  );
  assert.match(mixed.tooltip, /^\[HIGH\] cors_misconfig: Reflected Origin with ACAC: true\n\[HIGH\] secret_leak:/);

  // Single medium/low/info maxSeverity ranking checks.
  assert.equal(C.summarizePassiveSignals([{ kind: "a", severity: "medium", summary: "m" }]).maxSeverity, "medium");
  assert.equal(C.summarizePassiveSignals([{ kind: "a", severity: "low", summary: "l" }]).maxSeverity, "low");
  assert.equal(C.summarizePassiveSignals([{ kind: "a", severity: "info", summary: "i" }]).maxSeverity, "info");

  // Principal formatting.
  assert.equal(C.formatPrincipal(null), null);
  assert.equal(C.formatPrincipal("   "), null);
  assert.equal(C.formatPrincipal("profile:   "), null);
  assert.equal(C.formatPrincipal("auth:   "), null);
  assert.deepEqual(C.formatPrincipal("anon"), {
    raw: "anon",
    label: "anon",
    name: null,
    kind: "anon",
    tip: "Sent without mounted credentials (anonymous).",
  });
  assert.equal(C.formatPrincipal("ANONYMOUS").label, "anon");
  assert.deepEqual(C.formatPrincipal("auth:1a2b3c4d"), {
    raw: "auth:1a2b3c4d",
    label: "auth:1a2b3c4d",
    name: null,
    kind: "auth",
    tip: "Sent with ad-hoc request auth headers (not a mounted profile).",
  });
  assert.equal(C.formatPrincipal("AUTH:deadbeef").label, "auth:deadbeef");
  assert.equal(C.formatPrincipal("AUTH:deadbeef").kind, "auth");
  assert.deepEqual(C.formatPrincipal("profile:user_b"), {
    raw: "profile:user_b",
    label: "profile:user_b",
    name: "user_b",
    kind: "profile",
    tip: "Sent with credential profile user_b.",
  });
  assert.deepEqual(C.formatPrincipal("  admin  "), {
    raw: "admin",
    label: "profile:admin",
    name: "admin",
    kind: "profile",
    tip: "Sent with credential profile admin.",
  });

  // exchangeOf + exchangeRow preserve passive_signals and principal without altering legacy marks.
  const ex = C.exchangeOf(
    exRec("ex-waveb0000001", {
      principal: "profile:user_b",
      passive_signals: [
        { kind: "weak_jwt", severity: "medium", summary: "alg=none accepted", detail: "Header decoded alg=none" },
      ],
    }),
  );
  assert.equal(ex.principal, "profile:user_b");
  assert.equal(ex.passive_signals.length, 1);
  const row = C.exchangeRow(ex);
  assert.deepEqual(row.marks, []);
  assert.equal(row.principal.label, "profile:user_b");
  assert.equal(row.passive.maxSeverity, "medium");
  assert.equal(row.passive.badge, "1 medium");
});

test("Wave B helpers: multi-principal credsProfilesOf, buildNewSession creds_profiles, and webapp pack metadata", () => {
  // session_start stores creds and creds_profiles into store.start.
  const store = C.createRecordStore("s-1");
  C.applyRecord(store, {
    seq: 0,
    ts_ms: 10,
    kind: "session_start",
    creds: { profile: "user_a", summary: "user_a · 1 cookie", dropped: 0 },
    creds_profiles: [
      { profile: "user_a", summary: "user_a · 1 cookie", dropped: 0 },
      { profile: "user_b", summary: "user_b · 1 header", dropped: 0 },
    ],
    tools: [],
  });
  assert.deepEqual(
    C.credsProfilesOf(store.start).map((c) => c.profile),
    ["user_a", "user_b"],
  );
  // Merges start + SessionInfo cleanly without duplicates.
  assert.deepEqual(
    C.credsProfilesOf(null, {
      creds: { profile: "default", summary: "default · 1 cookie", dropped: 0 },
      creds_profiles: [
        { profile: "default", summary: "", dropped: 0 },
        { profile: "admin", summary: "admin · 1 header", dropped: 1 },
      ],
    }),
    [
      { profile: "default", summary: "default · 1 cookie", dropped: 0 },
      { profile: "admin", summary: "admin · 1 header", dropped: 1 },
    ],
  );
  assert.deepEqual(C.credsProfilesOf(null, null), []);

  // buildNewSession sends creds_profiles only with target and deduplicates.
  const base = { workspace: "/w", message: "test authz" };
  assert.deepEqual(
    C.buildNewSession({ ...base, target: "acme", creds: "user_a", credsProfiles: ["user_a", " user_b ", "user_a", "none", ""] }).body.creds_profiles,
    ["user_a", "user_b"],
  );
  assert.equal("creds_profiles" in C.buildNewSession({ ...base, target: "", credsProfiles: ["user_a"] }).body, false);
  assert.equal("creds_profiles" in C.buildNewSession({ ...base, target: "acme", credsProfiles: [] }).body, false);

  // webapp pack renders cleanly via packRoleSummary & roleGroups.
  const webapp = {
    name: "webapp",
    description: "Live bug-bounty and web AppSec assessments.",
    default_role: "lead",
    intercept: true,
    requires_restricted_network: true,
    roles: [
      { name: "lead", description: "Owns engagement", top_level: true, starts_agents: true },
      { name: "recon_mapper", description: "Maps attack surfaces", top_level: false, starts_agents: false },
      { name: "authz_tester", description: "Multi-principal authz", top_level: false, starts_agents: false },
      { name: "exploit_worker", description: "Reproduces vulns", top_level: false, starts_agents: false },
      { name: "triage_judge", description: "Read-only triage verifier", top_level: false, starts_agents: false },
    ],
  };
  const groups = C.roleGroups(webapp);
  assert.equal(groups.length, 2);
  assert.deepEqual(groups[0].roles.map((r) => r.name), ["lead"]);
  assert.deepEqual(groups[1].roles.map((r) => r.name), ["recon_mapper", "authz_tester", "exploit_worker", "triage_judge"]);
  const summary = C.packRoleSummary(webapp, "lead", "open");
  assert.deepEqual(summary.flags, ["MITM proxy intercept", "Requires restricted network"]);
  assert.match(summary.warning, /restricted network/i);
});

test("GUI zoom scaling: layoutQueries, clampInspectorWidth, and zoom-resilient CSS breakpoints", () => {
  // Embedded desktop keeps desktop shell across zoom levels; browser keeps mobile breakpoints.
  assert.deepEqual(C.layoutQueries(false), {
    narrow: "(max-width: 1099px)",
    phone: "(max-width: 699px)",
    compact: "(max-width: 699px), (max-height: 700px)",
  });
  assert.deepEqual(C.layoutQueries(true), {
    narrow: "(max-width: 860px)",
    phone: "(max-width: 560px)",
    compact: "(max-width: 560px), (max-height: 560px)",
  });

  // Inspector width clamping scales proportionally on zoom-out when un-dragged and clamps explicit widths on zoom-in.
  assert.deepEqual(C.clampInspectorWidth(null, 2133, true), { value: 520, min: 240, max: 600 });
  assert.deepEqual(C.clampInspectorWidth(null, 1707, true), { value: 461, min: 240, max: 600 });
  assert.deepEqual(C.clampInspectorWidth(null, 1280, true), { value: 360, min: 240, max: 537 });
  assert.deepEqual(C.clampInspectorWidth(480, 1440, true), { value: 480, min: 240, max: 600 });
  assert.deepEqual(C.clampInspectorWidth(700, 2400, true), { value: 600, min: 240, max: 600 });
  // At 130%-150% zoom on a laptop window (861..1099px CSS width), embedded inspector stays docked with 38% cap and 260px min.
  assert.deepEqual(C.clampInspectorWidth(480, 960, true), { value: 364, min: 260, max: 364 });
  assert.deepEqual(C.clampInspectorWidth(120, 960, true), { value: 260, min: 260, max: 364 });
  assert.deepEqual(C.clampInspectorWidth(NaN, 960, true), { value: 326, min: 260, max: 364 });
  // Standard browser at 1200px uses 240px min and 42% cap (504px).
  assert.deepEqual(C.clampInspectorWidth(600, 1200, false), { value: 504, min: 240, max: 504 });
  assert.deepEqual(C.clampInspectorWidth(100, 1200, false), { value: 240, min: 240, max: 504 });
  assert.deepEqual(C.clampInspectorWidth(undefined, 0, false), { value: 360, min: 240, max: 537 });

  // Style contract: fluid sidebar/chat/composer/gutters, symmetric prose, zoom-in compression, and zero @container rules (WebKit pageZoom quirk).
  const css = readFileSync(join(here, "style.css"), "utf8");
  assert.match(css, /--sidebar-width:\s*clamp\(188px,\s*19\.5vw,\s*380px\)/);
  assert.match(css, /--gutter-x:\s*clamp\(12px,\s*2vw,\s*28px\)/);
  assert.match(css, /\.show-right\s+\.layout\s*\{\s*grid-template-columns:\s*var\(--sidebar-width\)\s+minmax\(0,\s*1fr\)\s+clamp\(240px,\s*var\(--inspector-width,\s*clamp\(360px,\s*27vw,\s*520px\)\),\s*42vw\)/);
  assert.match(css, /\.scroller\s*>\s*\*\s*\{\s*width:\s*min\(100%,\s*clamp\(520px,\s*84%,\s*1040px\)\)/);
  assert.match(css, /\.composer\s*>\s*\*\s*\{\s*width:\s*min\(100%,\s*clamp\(520px,\s*84%,\s*1040px\)\)/);
  assert.match(css, /\.scroller\s+\.prose\s*\{\s*max-width:\s*none;\s*\}/);
  assert.match(css, /\.embedded-desk\s+\.lhead\s*\{\s*display:\s*grid;/);
  assert.match(css, /\.lnew\s+\.btn\s*\{[^}]*overflow:\s*hidden;[^}]*text-overflow:\s*ellipsis;/);
  assert.match(css, /@media\s*\(max-height:\s*680px\),\s*\(max-width:\s*1020px\)/);
  assert.match(css, /@media\s*\(max-width:\s*1099px\)\s*and\s*\(min-width:\s*861px\)[\s\S]*?body\.embedded-desk\.show-right\s+\.layout/);
  assert.match(css, /@media\s*\(max-width:\s*860px\)[\s\S]*?body\.embedded-desk\s+\.right/);
  assert.match(css, /@media\s*\(max-width:\s*560px\)[\s\S]*?body\.embedded-desk\s+\.bar/);
  assert.match(css, /@media\s*\(max-width:\s*560px\),\s*\(max-height:\s*560px\)[\s\S]*?body\.embedded-desk\s+\.view\.session/);
  const cssNoComments = css.replace(/\/\*[\s\S]*?\*\//g, "");
  assert.doesNotMatch(cssNoComments, /@container\b/, "avoid @container in style.css due to WebKit pageZoom physical-pixel evaluation");

  // Every brace in style.css must stay balanced.
  let depth = 0;
  for (const ch of css) {
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    assert.ok(depth >= 0, "unexpected closing brace in style.css");
  }
  assert.equal(depth, 0, "unclosed brace in style.css");
});
