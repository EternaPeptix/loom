// core.js: the pure half of the loom web UI. No DOM, no network, no clock (callers pass `now`).
// Everything that can be wrong lives here and is exercised by `node --test ui/`.
// app.js turns these results into DOM with textContent only.

// ---------------------------------------------------------------------------------------------
// Formatting

/** Thousands separators, always English style so output does not depend on the browser locale. */
export function num(n) {
  const v = Math.round(Number(n) || 0);
  const s = String(Math.abs(v)).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return v < 0 ? "-" + s : s;
}

function trimZeros(s) {
  return s.includes(".") ? s.replace(/0+$/, "").replace(/\.$/, "") : s;
}

/** Token counts: 812, 12.3k, 123k, 1.05M. */
export function tokens(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v < 1000) return String(Math.round(v));
  if (v < 999500) {
    const k = v / 1000;
    return (k < 100 ? trimZeros(k.toFixed(1)) : String(Math.round(k))) + "k";
  }
  return trimZeros((v / 1e6).toFixed(2)) + "M";
}

/** A duration given in milliseconds. */
export function seconds(ms) {
  const v = Math.max(0, Number(ms) || 0);
  if (v < 1000) return Math.round(v) + "ms";
  if (v < 10000) return (v / 1000).toFixed(1) + "s";
  const s = Math.round(v / 1000);
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m" + String(s % 60).padStart(2, "0") + "s";
  const h = Math.floor(m / 60);
  return h + "h" + String(m % 60).padStart(2, "0") + "m";
}

/** How long ago `then` was, as seen at `now` (both epoch milliseconds). */
export function age(now, then) {
  const s = Math.floor((Number(now) - Number(then)) / 1000);
  if (!(s >= 5)) return "now";
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h";
  return Math.floor(s / 86400) + "d";
}

/** Share of the prompt that came from the cache, as "80%"; empty when there was no prompt. */
export function cachedShare(cached, prompt) {
  if (!(prompt > 0)) return "";
  return Math.round((100 * Math.min(cached || 0, prompt)) / prompt) + "%";
}

/** Clamp to 0..100. */
export function pct(part, whole) {
  if (!(whole > 0) || !(part > 0)) return 0;
  return Math.min(100, (100 * part) / whole);
}

/** First `max` lines of `text`: {text, total, clipped}. A trailing newline does not add a line. */
export function clip(text, max) {
  const s = String(text ?? "");
  let total = 0;
  let cutAt = -1;
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) === 10) {
      if (total === max - 1 && cutAt < 0) cutAt = i;
      total++;
    }
  }
  if (s.length > 0 && s.charCodeAt(s.length - 1) !== 10) total++;
  else if (s.length === 0) total = 0;
  if (total <= max) return { text: s, total, clipped: false };
  return { text: s.slice(0, cutAt), total, clipped: true };
}

export function lineCount(text) {
  return clip(text, Number.MAX_SAFE_INTEGER).total;
}

/** One line, whitespace collapsed, cut to `max` characters with an ellipsis. */
export function oneLine(text, max = 160) {
  const flat = String(text ?? "").replace(/\s+/g, " ").trim();
  return flat.length > max ? flat.slice(0, Math.max(0, max - 1)) + "…" : flat;
}

const FILE_TOOLS = new Set(["read", "write", "edit", "multi_edit", "patch", "ls"]);

/** The arguments of a tool call on one line: bash shows its command, file tools their path. */
export function argsLine(name, args, max = 240) {
  if (args === null || args === undefined) return "";
  if (typeof args === "string") return oneLine(args, max);
  if (typeof args === "object" && !Array.isArray(args)) {
    if (name === "bash" && typeof args.command === "string") return oneLine(args.command, max);
    if (FILE_TOOLS.has(name)) {
      for (const k of ["path", "file_path", "file"]) {
        if (typeof args[k] === "string") return oneLine(args[k], max);
      }
    }
  }
  let json;
  try {
    json = JSON.stringify(args);
  } catch {
    json = String(args);
  }
  return oneLine(json ?? "", max);
}

/** Merge [[a,b],…] line ranges (1-based, inclusive) and return the merged list. */
export function mergeRanges(ranges) {
  const rs = (Array.isArray(ranges) ? ranges : [])
    .filter((r) => Array.isArray(r) && r.length === 2 && r[0] >= 1 && r[1] >= r[0])
    .map((r) => [r[0], r[1]])
    .sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const r of rs) {
    const last = out[out.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else out.push(r);
  }
  return out;
}

/**
 * What the model was shown of a tool result, and of how much.
 * Returns {blob, shown, total, cut, ranges, ofBlob, words}; `blob` is the id to open (or null),
 * `shown`/`total` are line counts or null when unknown, `words` is the sentence for the UI.
 * `meta.shown` refers to `meta.of_blob` when that is present, else to `output`.
 */
export function shownOfTotal(result) {
  const meta = (result && result.meta) || {};
  const output = (result && result.output) || null;
  const cut = !!(result && result.cut);
  const ofBlob = typeof meta.of_blob === "string" ? meta.of_blob : null;
  const blob = ofBlob || (output ? output.id : null);
  const ranges = mergeRanges(meta.shown);
  const shownFromRanges = ranges.length ? ranges.reduce((a, r) => a + (r[1] - r[0] + 1), 0) : null;
  const total = ofBlob ? null : output ? output.lines : null;
  let shown = shownFromRanges;
  if (shown === null && !cut && total !== null) shown = total;
  let words;
  if (!blob) {
    words = cut ? "Output was cut." : "";
  } else if (ofBlob) {
    words = shown !== null ? `Showing ${num(shown)} lines of a stored output.` : "A view of a stored output.";
  } else if (shown !== null && total !== null) {
    words = shown >= total && !cut
      ? `All ${num(total)} lines shown.`
      : `The model was shown ${num(shown)} of ${num(total)} lines${cut ? " (output cut)" : ""}.`;
  } else if (total !== null) {
    words = cut ? `Output was cut; the stored output has ${num(total)} lines.` : `${num(total)} lines stored.`;
  } else {
    words = cut ? "Output was cut." : "";
  }
  const complete = !cut && shown !== null && total !== null && shown >= total;
  if (meta.deferred_observation === true) {
    words = "Stored-action output: initially deferred; actor exposure is recorded separately in outputs_observed receipts.";
  }
  return { blob, shown, total, cut, ranges, ofBlob: !!ofBlob, words, complete };
}

/** Generation speed of a reply in tokens per second: the tokens after the first, over the time from
 *  the first streamed token to the end of the stream (so the wait for the first token, where the
 *  prompt is read, is left out). Null when the record cannot support a figure. */
export function tokensPerSecond(r) {
  const n = Number(r && r.usage && r.usage.completion_tokens) || 0;
  const t = (r && r.timing) || {};
  const first = Number(t.ttft_ms) || 0;
  const gen = (Number(t.total_ms) || 0) - first;
  if (n < 2 || first <= 0 || gen <= 0) return null;
  return (n - 1) / (gen / 1000);
}

/** "46.2 tok/s"; whole numbers from 100 up; "" for null. */
export function speedText(v) {
  if (v === null || v === undefined || !Number.isFinite(v)) return "";
  return (v >= 100 ? String(Math.round(v)) : v.toFixed(1)) + " tok/s";
}

/** Speed of a session for its header: the latest reply that has a figure, and the rate over the
 *  latest `span` such replies together (their tokens over their generation time). */
export function sessionSpeed(blocks, span = 10) {
  let last = null, tokens = 0, ms = 0, used = 0;
  for (let i = (blocks || []).length - 1; i >= 0 && used < span; i--) {
    const b = blocks[i];
    if (!b || b.kind !== "response") continue;
    const v = tokensPerSecond(b);
    if (v === null) continue;
    if (last === null) last = v;
    tokens += b.usage.completion_tokens - 1;
    ms += b.timing.total_ms - b.timing.ttft_ms;
    used++;
  }
  if (last === null) return { last: null, mean: null, replies: 0, label: "" };
  const mean = tokens / (ms / 1000);
  const label = used > 1 ? `${speedText(last)} · ${speedText(mean)} over ${used} replies` : speedText(last);
  return { last, mean, replies: used, label };
}

/** Footer line of a model response. */
export function responseFooter(r) {
  const u = r.usage || {};
  const parts = [];
  parts.push(`prompt ${tokens(u.prompt_tokens || 0)}`);
  const share = cachedShare(u.cached_tokens || 0, u.prompt_tokens || 0);
  if (share) parts.push(`${share} cached`);
  parts.push(`completion ${tokens(u.completion_tokens || 0)}`);
  const speed = speedText(tokensPerSecond(r));
  if (speed) parts.push(speed);
  const total = r.timing && r.timing.total_ms;
  if (total) parts.push(seconds(total));
  if ((r.attempts || 0) > 1) parts.push(`${r.attempts} attempts`);
  return parts.join(" · ");
}

/** A warning for a reply that did not end normally; null when it did. */
export function finishWarning(finish) {
  switch (finish) {
    case "length": return { level: "warn", text: "Reply cut by the output limit." };
    case "aborted": return { level: "warn", text: "Request was cancelled." };
    case "error": return { level: "bad", text: "The request failed after retries." };
    default: return null;
  }
}

const TURN_END_WORDS = {
  yielded: "turn ended: replied",
  finished: "turn ended: finished",
  asked: "turn ended: asked the operator",
  blocked: "turn ended: blocked",
  waiting: "turn ended: waiting for jobs or agents",
  stopped: "turn ended: stopped",
  parked: "turn ended: parked for the operator",
  budget_exhausted: "turn ended: budget exhausted",
  error: "turn ended: error",
};
export function turnEndWords(reason) {
  return TURN_END_WORDS[reason] || `turn ended: ${String(reason).replace(/_/g, " ")}`;
}

const OUTCOME_WORDS = {
  done: "done",
  stopped: "stopped",
  failed: "failed",
  budget_exhausted: "budget exhausted",
  returned: "returned",
  blocked: "blocked",
};
export function outcomeWords(o) {
  return OUTCOME_WORDS[o] || String(o).replace(/_/g, " ");
}

export function authorLabel(author) {
  if (author && typeof author === "object" && typeof author.agent === "string") return `agent ${author.agent}`;
  return typeof author === "string" ? author : "?";
}

/** The one-line summary of a re-weave. */
export function reweaveSummary(rw) {
  const n = (rw.evictions || []).length;
  return `context re-woven (${rw.reason}) — ${n} ${n === 1 ? "item" : "items"} folded out of view, about ${tokens(rw.before_tokens)} → ${tokens(rw.after_tokens_est)} tokens`;
}

export function evictionWords(e) {
  const a = e.action || {};
  if (a.stub !== undefined) return `stub: ${oneLine(a.stub && a.stub.text !== undefined ? a.stub.text : a.stub, 120)}`;
  if (a === "drop" || a.drop !== undefined) return "dropped";
  if (a === "drop_reasoning" || a.drop_reasoning !== undefined) return "reasoning dropped";
  // A fresh start takes a finish or conclude call out of the window together with its result.
  if (a === "remove" || a.remove !== undefined) return "call and result out of view";
  if (typeof a.type === "string") return a.type.replace(/_/g, " ");
  if (typeof a === "string") return a.replace(/_/g, " ");
  return "folded";
}

export const REWEAVE_NOTE = "Folded items stay in the record above and can be read back by the model.";

/** Where blob lines are read from. */
export function linesUrl(blob, start, end) {
  return `/api/blobs/${encodeURIComponent(blob)}/lines?start=${start}&end=${end}`;
}
export function recordsUrl(session, after, limit) {
  let u = `/api/sessions/${encodeURIComponent(session)}/records`;
  const q = [];
  if (after !== null && after !== undefined) q.push(`after=${after}`);
  if (limit) q.push(`limit=${limit}`);
  return q.length ? `${u}?${q.join("&")}` : u;
}

// ---------------------------------------------------------------------------------------------
// Sessions

export function createSessionStore() {
  return { byId: new Map() };
}

export function applySessionList(store, list) {
  store.byId = new Map((list || []).map((s) => [s.id, s]));
  return store;
}

/** A `session` event: {type:"session", info}. */
export function applySessionEvent(store, info) {
  if (info && info.id) store.byId.set(info.id, info);
  return store;
}

/** A `status` event. Returns false when the session is not known (the caller refetches the list). */
export function applyStatus(store, id, status) {
  const s = store.byId.get(id);
  if (!s) return false;
  store.byId.set(id, { ...s, status });
  return true;
}

/**
 * Rows for the left column: root sessions newest first, each followed by its descendants in
 * creation order, with a depth. A session whose parent is not in the store is a root.
 */
export function sessionRows(store, { showArchived = false } = {}) {
  const all = [...store.byId.values()];
  const kids = new Map();
  const roots = [];
  for (const s of all) {
    if (s.parent && store.byId.has(s.parent)) {
      if (!kids.has(s.parent)) kids.set(s.parent, []);
      kids.get(s.parent).push(s);
    } else roots.push(s);
  }
  roots.sort((a, b) => b.created_ms - a.created_ms || (a.id < b.id ? 1 : -1));
  const rows = [];
  const walk = (s, depth) => {
    rows.push({ info: s, depth });
    const cs = (kids.get(s.id) || []).slice().sort((a, b) => a.created_ms - b.created_ms || (a.id < b.id ? -1 : 1));
    for (const c of cs) walk(c, depth + 1);
  };
  for (const r of roots) {
    if (r.archived && !showArchived) continue;
    walk(r, 0);
  }
  return rows;
}

/** Open inbox items classified by operator action, without treating results as blockers. */
export function attentionFor(inbox, sessionId) {
  const attention = { open: 0, blocking: 0, questions: 0, results: 0 };
  for (const entry of inbox.items.values()) {
    if (entry.session !== sessionId) continue;
    attention.open++;
    if (entry.item.blocking) attention.blocking++;
    else if (entry.item.item_kind === "finished") attention.results++;
    else attention.questions++;
  }
  return attention;
}

/** "1 agent", "3 agents", "2 open claims": a count with the noun in the right number. */
export function count(n, one, many = one + "s") {
  return `${num(n)} ${Number(n) === 1 ? one : many}`;
}

/**
 * What is open for a set of sessions, with when the oldest item of each class was opened.
 * `blocking.kind` is the kind of that oldest blocking item, so a row can name what is waiting.
 */
export function waitingFor(inbox, sessionIds) {
  const ids = sessionIds instanceof Set ? sessionIds : new Set(sessionIds || []);
  const out = {
    blocking: { count: 0, since: null, kind: null },
    questions: { count: 0, since: null },
    results: { count: 0, since: null },
  };
  for (const entry of inbox.items.values()) {
    if (!ids.has(entry.session)) continue;
    const slot = entry.item.blocking ? out.blocking : entry.item.item_kind === "finished" ? out.results : out.questions;
    slot.count++;
    const opened = Number.isFinite(entry.opened_ms) ? entry.opened_ms : null;
    const older = opened !== null && (slot.since === null || opened < slot.since);
    if (older) slot.since = opened;
    if (slot === out.blocking && (older || slot.kind === null)) slot.kind = entry.item.item_kind;
  }
  return out;
}

/** How a session's execution stands in one word, whatever is waiting on the operator. */
export function executionWord(info) {
  const st = (info && info.status) || {};
  if (st.phase === "running") return "running";
  if (st.phase === "ended") {
    if (st.outcome === "stopped") return "stopped";
    return st.outcome === "failed" || st.outcome === "budget_exhausted" ? "failed" : "finished";
  }
  if (st.last_end === "waiting") return "waiting";
  if (st.last_end === "stopped") return "stopped";
  return "idle";
}

/**
 * Mission navigation, with stable creation order inside attention groups. Root rows carry
 * aggregate attention; child rows keep their own attention and appear only when expanded.
 */
export function missionGroups(store, inbox, { showArchived = false, expanded = new Set() } = {}) {
  const groups = [
    { key: "needs_answer", label: "Needs your answer", rows: [] },
    { key: "running", label: "Running", rows: [] },
    { key: "ready", label: "Ready to review", rows: [] },
    { key: "other", label: "Other missions", rows: [] },
  ];
  const byKey = new Map(groups.map((g) => [g.key, g]));
  const ordered = sessionRows(store, { showArchived });
  let mission = null;
  let members = [];
  const publish = () => {
    if (!mission) return;
    const attention = { open: 0, blocking: 0, questions: 0, results: 0 };
    for (const row of members) {
      const own = attentionFor(inbox, row.info.id);
      for (const key of Object.keys(attention)) attention[key] += own[key];
    }
    const executing = members.some(({ info }) => {
      const mark = stateMark(info, attentionFor(inbox, info.id));
      return mark === "running" || mark === "waiting";
    });
    const rootMark = stateMark(mission, attentionFor(inbox, mission.id));
    const key = attention.blocking ? "needs_answer" : executing ? "running"
      : attention.results || attention.questions || rootMark === "finished" || rootMark === "failed" ? "ready" : "other";
    const agentCount = members.length - 1;
    const agentsRunning = members.slice(1).filter(({ info }) => (info.status || {}).phase === "running").length;
    const waiting = waitingFor(inbox, members.map((row) => row.info.id));
    byKey.get(key).rows.push({ info: mission, depth: 0, mission: mission.id, agentCount, agentsRunning, expanded: expanded.has(mission.id), attention, waiting });
    if (expanded.has(mission.id)) {
      for (const row of members.slice(1)) {
        byKey.get(key).rows.push({ ...row, mission: mission.id, agentCount: 0, agentsRunning: 0, expanded: false, attention: attentionFor(inbox, row.info.id), waiting: waitingFor(inbox, [row.info.id]) });
      }
    }
  };
  for (const row of ordered) {
    if (row.depth === 0) {
      publish();
      mission = row.info;
      members = [];
    }
    members.push(row);
  }
  publish();
  return groups.filter((g) => g.rows.length);
}

/**
 * The state mark of a session: needs_you, running, waiting, stopped, finished, failed or idle.
 * Pass classified attention to distinguish nonblocking questions and available results. A numeric
 * count is retained for older callers, which cannot classify their open inbox items.
 */
export function stateMark(info, openInbox) {
  const st = (info && info.status) || {};
  const classified = openInbox && typeof openInbox === "object";
  const blocking = classified ? openInbox.blocking || 0 : typeof openInbox === "number" ? openInbox : st.open_inbox || 0;
  if (blocking > 0 && st.phase !== "ended") return "needs_you";
  if (st.phase === "running") return "running";
  if (st.phase === "ended") {
    if (st.outcome === "stopped") return "stopped";
    if (st.outcome === "failed" || st.outcome === "budget_exhausted") return "failed";
    if (classified && openInbox.results > 0) return "result_ready";
    return "finished";
  }
  if (classified && openInbox.questions > 0) return "question";
  if (classified && openInbox.results > 0) return "result_ready";
  switch (st.last_end) {
    case "waiting": return "waiting";
    case "stopped": return "stopped";
    case "finished": return "finished";
    case "error":
    case "budget_exhausted": return "failed";
    default: return "idle";
  }
}

const MARK_WORDS = {
  needs_you: "needs you",
  running: "running",
  waiting: "waiting for jobs or agents",
  stopped: "stopped",
  finished: "finished",
  failed: "failed",
  idle: "idle",
  result_ready: "result ready",
  question: "question — work can continue",
};
export function markWords(mark) {
  return MARK_WORDS[mark] || mark;
}

// One shape per state, so a mark is never told apart by colour alone. `icon` names a drawing in
// index.html; `tone` names a colour treatment in style.css.
const STANDING = {
  needs_you: { tone: "attention", icon: "diamond", text: "Needs your answer" },
  running: { tone: "running", icon: "dot", text: "Running" },
  waiting: { tone: "", icon: "half", text: "Waiting for jobs or agents" },
  stopped: { tone: "", icon: "square", text: "Stopped" },
  finished: { tone: "ok", icon: "check", text: "Finished" },
  failed: { tone: "bad", icon: "cross", text: "Failed" },
  idle: { tone: "", icon: "ring", text: "Idle" },
  result_ready: { tone: "ok", icon: "diamond-outline", text: "Result ready" },
  question: { tone: "info", icon: "question", text: "Question open · work can continue" },
};
export function markIcon(mark) {
  return (STANDING[mark] || STANDING.idle).icon;
}

/** What to call the session at the root of a mission: only a lead leads; a chat is just a session. */
export function rootNoun(info) {
  return info && info.role === "lead" ? "lead" : "session";
}

/**
 * The standing of a session as separate facts, in the order an operator needs them: what is
 * waiting on the operator, how execution stands, and how many agents of the mission are running.
 */
export function missionStanding(info, attention, agentsRunning = 0) {
  const mark = stateMark(info, attention);
  const pills = [{ ...(STANDING[mark] || { tone: "", icon: "ring", text: markWords(mark) }) }];
  if (mark === "needs_you") pills.push({ tone: "", icon: null, text: `${info.parent ? "Agent" : capitalized(rootNoun(info))} ${executionWord(info)}` });
  if (!info.parent && agentsRunning > 0) pills.push({ tone: "running", icon: "dot", text: `${count(agentsRunning, "agent")} running` });
  return { mark, pills };
}

/** Which buttons the transcript header offers. */
export function sessionActions(info) {
  const st = info.status || {};
  const root = !info.parent;
  const ended = st.phase === "ended";
  const running = st.phase === "running";
  const waiting = st.phase === "idle" && st.last_end === "waiting";
  return {
    stop: !info.archived && (running || waiting),
    resume: root && !info.archived && !ended && !running && st.last_end === "stopped",
    archive: root && !info.archived,
    unarchive: root && !!info.archived,
    send: root && !info.archived && !ended,
    running,
  };
}

/** The dim second line of a session row: role, step, context size, age. */
export function rowDetail(info, now) {
  const st = info.status || {};
  const parts = [info.role, `step ${st.step || 0}`];
  if (st.prompt_tokens) parts.push(tokens(st.prompt_tokens));
  parts.push(age(now, info.created_ms));
  return parts.join(" · ");
}

/** Human-readable activity from one recorded event; null for background bookkeeping. */
export function recordActivity(record) {
  if (!record) return null;
  const name = oneLine(record.name || "tool", 50);
  switch (record.kind) {
    case "user_message": return "Operator message received";
    case "model_request": return "Model request started";
    case "model_response": return record.finish === "length" ? "Model reply reached its output limit" : "Model replied";
    case "tool_call": return `${name} started${record.args && record.args.path ? ": " + oneLine(record.args.path, 90) : ""}`;
    case "tool_result": return `${name}: ${record.status === "ok" ? "completed" : oneLine(record.status || "result recorded", 50)}`;
    case "child_spawned": return `${oneLine(record.role || "Worker", 40)} agent started`;
    case "child_settled": return `Agent ${outcomeWords(record.outcome)}`;
    case "job_registered": return `Job ${oneLine(record.job_id, 30)} started`;
    case "job_settled": return `Job ${oneLine(record.job_id, 30)} settled${Number.isInteger(record.exit_code) ? " (exit " + record.exit_code + ")" : ""}`;
    case "job_matched": return `Job ${oneLine(record.job_id, 30)} wrote a line matching /${oneLine(record.pattern, 60)}/`;
    case "ledger": return "Mission state updated";
    case "inbox_opened": return record.blocking ? "Waiting for an operator answer" : record.item_kind === "finished" ? "Result ready to review" : "Nonblocking question opened";
    case "inbox_resolved": return "Operator answered an inbox item";
    case "interrupted": return "Execution interrupted";
    case "turn_end": return turnEndWords(record.reason);
    case "session_end": return `Session ${outcomeWords(record.outcome)}`;
    default: return null;
  }
}

/** A creation timestamp is never presented as proof of recent execution activity. */
export function rowActivity(info, lastRecord, now) {
  const activity = recordActivity(lastRecord);
  if (activity && Number.isFinite(lastRecord.ts_ms)) {
    const when = age(now, lastRecord.ts_ms);
    return `${activity} · ${when === "now" ? "just now" : when + " ago"}`;
  }
  return `${markWords(stateMark(info, { blocking: 0 }))} · activity not loaded`;
}

const WAITING_NOUN = { approval: "Approval", question: "Question", blocker: "Blocker", parked: "Parked session" };
const capitalized = (text) => text.charAt(0).toUpperCase() + text.slice(1);

/**
 * The second line of a row in the mission list. What waits on the operator comes first, with how
 * long it has waited; then recorded activity; then the plain state. A mission row ends with how its
 * root session stands; an agent row starts with its role. Ages come from recorded times, never
 * creation.
 */
export function rowSummary(row, lastRecord, now) {
  const info = row.info;
  const waiting = row.waiting || { blocking: { count: 0 }, questions: { count: 0 }, results: { count: 0 } };
  const agent = !!info.parent;
  const waited = (slot) => (Number.isFinite(slot.since) ? age(now, slot.since) : null);
  const base = markWords(stateMark(info, { blocking: 0 }));
  // Phrases written here follow the row: a sentence start for a mission, lower case after a role.
  // Recorded activity keeps the names it was recorded with.
  const own = (text) => (agent ? text.charAt(0).toLowerCase() + text.slice(1) : capitalized(text));
  let text;
  if (waiting.blocking.count > 0) {
    const a = waited(waiting.blocking);
    if (waiting.blocking.count > 1) text = `${waiting.blocking.count} requests waiting${a && a !== "now" ? " · oldest " + a : ""}`;
    else {
      const noun = WAITING_NOUN[waiting.blocking.kind] || "Request";
      text = own(a === "now" ? `${noun} just arrived` : `${noun} waiting${a ? " " + a : ""}`);
    }
    if (!agent) text += ` · ${rootNoun(info)} ${executionWord(info)}`;
  } else {
    const activity = recordActivity(lastRecord);
    if (activity && Number.isFinite(lastRecord.ts_ms)) {
      const when = age(now, lastRecord.ts_ms);
      text = `${activity} · ${when === "now" ? "just now" : when + " ago"}`;
    } else if (waiting.results.count > 0) {
      const a = waited(waiting.results);
      text = own(`Result ready${a && a !== "now" ? " " + a : ""} · ${base}`);
    } else if (waiting.questions.count > 0) {
      const a = waited(waiting.questions);
      text = own(`Question open${a && a !== "now" ? " " + a : ""} · work can continue`);
    } else text = agent ? base : `${capitalized(base)} · open it to load activity`;
  }
  return agent ? `${info.role || "agent"} · ${text}` : text;
}

/**
 * Recorded mission changes and ledger state; it does not infer semantic success from receipts.
 * Every change is listed. `fresh` marks those recorded after `sinceSeq` (the last record seen on
 * the previous visit); with no previous visit nothing is fresh. `tone` is "bad" for a tool result
 * that was not ok, an interruption, or a session that failed.
 */
export function missionOverview(records, ledgerState, inboxEntries, sinceSeq = null) {
  const source = records instanceof Map ? records.values() : records || [];
  const ordered = [...source].filter((r) => r && Number.isInteger(r.seq)).sort((a, b) => a.seq - b.seq);
  const ledger = ledgerState || {};
  const entries = [...(inboxEntries || [])];
  const pendingDecisions = entries.filter((e) => e.item && e.item.blocking);
  const changes = [];
  let lastActivity = null;
  let failedChecks = 0;
  for (const record of ordered) {
    const activity = recordActivity(record);
    if (activity) lastActivity = { seq: record.seq, ts: record.ts_ms, text: activity, kind: record.kind };
    let text = null;
    let tone = "";
    if (record.kind === "tool_result" && record.status !== "ok") {
      failedChecks++;
      tone = "bad";
      text = `${oneLine(record.name || "Tool", 50)} returned ${oneLine(record.status || "an unknown status", 50)}`;
    } else if (record.kind === "tool_result" && record.status === "ok" && record.class === "write") {
      text = `Write tool completed${record.meta && record.meta.path ? ": " + oneLine(record.meta.path, 100) : ""}`;
    } else if (record.kind === "ledger") {
      text = `Ledger updated${record.summary ? ": " + oneLine(record.summary, 200) : ""}`;
    } else if (["child_settled", "job_settled", "inbox_opened", "inbox_resolved", "interrupted", "session_end"].includes(record.kind)) {
      text = activity;
      const failed = record.outcome === "failed" || record.outcome === "budget_exhausted";
      if (record.kind === "interrupted" || ((record.kind === "session_end" || record.kind === "child_settled") && failed)) tone = "bad";
    }
    if (text) changes.push({ seq: record.seq, ts: record.ts_ms, text, kind: record.kind, tone, fresh: sinceSeq !== null && record.seq > sinceSeq });
  }
  const plan = ledger.plan || [];
  const claims = ledger.claims || [];
  return {
    activeSteps: plan.filter((s) => s.status === "doing"),
    changes,
    lastActivity,
    pendingDecisions,
    counts: {
      planTotal: plan.length,
      planDone: plan.filter((s) => s.status === "done").length,
      claimsOpen: claims.filter((c) => c.status === "open").length,
      claimsSupported: claims.filter((c) => c.status === "supported").length,
      openObligations: (ledger.obligations || []).filter((o) => o.outcome === null || o.outcome === undefined).length,
      pendingDecisions: pendingDecisions.length,
      failedChecks,
    },
  };
}

/**
 * The changes the overview lists: the latest `max`, newest first, split into those recorded since
 * the previous visit and the rest. `total` says how many were recorded, so a cut is never silent.
 */
export function recentChanges(changes, max = 10) {
  const all = changes || [];
  const shown = all.slice(-max).reverse();
  return { fresh: shown.filter((c) => c.fresh), earlier: shown.filter((c) => !c.fresh), shown: shown.length, total: all.length };
}

/** Progress over the steps still in the plan: a dropped step stays listed but is not counted. */
export function planProgress(plan) {
  const steps = (plan || []).filter((s) => s.status !== "dropped");
  const done = steps.filter((s) => s.status === "done").length;
  const doing = steps.filter((s) => s.status === "doing").length;
  const label = `${done} of ${count(steps.length, "step")} done`;
  return {
    total: steps.length,
    done,
    doing,
    segments: steps.map((s) => (s.status === "done" || s.status === "doing" ? s.status : "todo")),
    label,
    words: doing ? `${label}, ${doing} in progress` : label,
  };
}

const STEP_WORDS = { todo: "To do", doing: "In progress", done: "Done", dropped: "Dropped" };
export function stepWords(status) {
  return STEP_WORDS[status] || String(status);
}
const STEP_ICON = { todo: "ring", doing: "half", done: "check", dropped: "cross" };
export function stepIcon(status) {
  return STEP_ICON[status] || "ring";
}

// ---------------------------------------------------------------------------------------------
// Operator drafts and navigation

/** Drafts stay in memory and are namespaced by the caller, e.g. session:<id> / inbox:<item-id>. */
export function createDraftStore() { return new Map(); }
export function getDraft(store, key) { return store.get(key) || ""; }
export function setDraft(store, key, text) {
  const value = String(text ?? "");
  if (value) store.set(key, value);
  else store.delete(key);
  return value;
}
export function clearDraft(store, key) { return store.delete(key); }
/** A completed request must not discard text edited while it was in flight. */
export function clearDraftIfUnchanged(store, key, sentText) {
  if (getDraft(store, key) !== sentText) return false;
  store.delete(key);
  return true;
}

/** A missing HTTP acknowledgement cannot undo an independently recorded delivery receipt. */
export function sendFailure(state, message, { rejected = false } = {}) {
  const previous = state || {};
  const detail = oneLine(message || "The request did not return an acknowledgement.", 400);
  if (Number.isInteger(previous.recordedSeq) && previous.recordedSeq >= 0) {
    const delivered = previous.state === "delivered";
    return {
      ...previous,
      state: delivered ? "delivered" : "queued",
      text: `${delivered ? "Delivered to a model step" : "Message recorded"} · HTTP acknowledgement unavailable: ${detail}`,
    };
  }
  return {
    ...previous,
    accepted: false,
    state: rejected ? "failed" : "uncertain",
    text: rejected ? `Message rejected: ${detail}` : `Sending could not be confirmed. Check the record before retrying. ${detail}`,
  };
}

const SESSION_SECTIONS = new Set(["chat", "overview", "evidence"]);
/** Hash of a session view: `#/s/<id>/<chat|overview|evidence>`; "record" (the old name of chat) and unknown sections give chat. */
export function sessionHash(session, section = "chat") {
  return `#/s/${encodeURIComponent(session)}/${SESSION_SECTIONS.has(section) ? section : "chat"}`;
}
/** Decode identifiers after splitting the route so encoded punctuation remains part of an id. */
export function parseRoute(hash) {
  const parts = String(hash || "").replace(/^#/, "").split("/");
  if (parts[1] === "inbox" && parts.length === 2) return { view: "inbox" };
  if (parts[1] === "new" && parts.length === 2) return { view: "new" };
  if (parts[1] !== "s" || !parts[2] || parts.length > 4) return { view: "empty" };
  try {
    const session = decodeURIComponent(parts[2]);
    const section = parts[3] || "chat";
    // The old name of the chat tab keeps working; `rewrite` is the hash the page should replace it with.
    if (section === "record") return { view: "session", session, section: "chat", rewrite: sessionHash(session, "chat") };
    return SESSION_SECTIONS.has(section) ? { view: "session", session, section } : { view: "empty" };
  } catch {
    return { view: "empty" };
  }
}

/** The dot in the left header: green, amber or red, and what the tooltip says. */
export function healthDot({ connected, models }) {
  if (!connected) return { state: "red", tip: "The event stream is disconnected; reconnecting." };
  const bad = (models || []).filter((m) => !m.reachable);
  if (bad.length) {
    return { state: "amber", tip: bad.map((m) => `${m.profile}: ${m.detail || "not reachable"}`).join("\n") };
  }
  return { state: "green", tip: "Every model is reachable." };
}

/**
 * The connection in short words for the sidebar header, and its detail for the tooltip. `short` is one of "Live",
 * "Connecting…", "Reconnecting…", "Offline" (the stream failed `attempts` times in a row, 3 or more); the unreachable
 * model profiles, a failed status request and the time of the last update go in `tip` (one line each) and in the
 * Session/status views, not on the sidebar line. opts: {connected, everConnected, attempts, statusError, models,
 * lastUpdateText}.
 */
export function connectionWords(opts = {}) {
  const { connected = false, everConnected = false, attempts = 0, statusError = null, models = [], lastUpdateText = "" } = opts;
  const short = connected ? "Live" : attempts >= 3 ? "Offline" : everConnected ? "Reconnecting…" : "Connecting…";
  const tip = [];
  if (connected) tip.push("Live events are connected.");
  else tip.push(everConnected || attempts ? "The event stream is down; execution state unknown until it returns." : "Connecting to the event stream.");
  if (statusError) tip.push("Model status unavailable: " + statusError);
  for (const m of models || []) if (m && !m.reachable) tip.push(`${m.profile}: unreachable${m.detail ? " (" + m.detail + ")" : ""}`);
  if (lastUpdateText) tip.push(lastUpdateText);
  return { short, tip: tip.join("\n") };
}

/** Free space below which the status warns (`LOW_DISK_BYTES`, `LOW_DISK_PERCENT` of the daemon). */
const LOW_DISK_BYTES = 5 * 1024 ** 3;
const LOW_DISK_PERCENT = 5;

/**
 * The warning line for the `disk` of the daemon's status ({free_bytes, total_bytes}, or null when unknown):
 * a sentence when less than 5 GiB or 5 percent of the volume is free, else null.
 */
export function diskWarning(disk) {
  if (!disk || !(disk.total_bytes > 0)) return null;
  const free = disk.free_bytes;
  if (!(free < LOW_DISK_BYTES || free * 100 < disk.total_bytes * LOW_DISK_PERCENT)) return null;
  const gib = (n) => (n / 1024 ** 3).toFixed(1) + " GiB";
  return `Low disk space: ${gib(free)} free of ${gib(disk.total_bytes)}. Sessions will fail when the disk fills; run "loom gc" or free space.`;
}

// ---------------------------------------------------------------------------------------------
// Inbox

export function createInbox() {
  return { items: new Map() };
}

export function applyInboxList(inbox, list, answered) {
  // The daemon resolves a dismissal/answer asynchronously, so a refetch right after one can still
  // report the item as open. Drop anything the operator has already answered here (tracked in
  // `answered`) so it is not resurrected between the POST and the `inbox_resolved` event.
  inbox.items = new Map(
    (list || []).filter((e) => !(answered && answered.has(e.item.item_id))).map((e) => [e.item.item_id, e]),
  );
  return inbox;
}

const ITEM_FIELDS = ["item_id", "item_kind", "text", "options", "blocking", "call_id", "reference"];

/**
 * A live record of any session. `lookup(sessionId)` gives the session info (for mission and title).
 * Returns "opened" (a new item; announce it), "resolved", or null.
 */
export function applyInboxRecord(inbox, session, rec, lookup) {
  if (rec.kind === "inbox_opened") {
    if (inbox.items.has(rec.item_id)) return null;
    const info = (lookup && lookup(session)) || {};
    const item = {};
    for (const f of ITEM_FIELDS) if (rec[f] !== undefined) item[f] = rec[f];
    item.options = item.options || [];
    item.blocking = !!item.blocking;
    inbox.items.set(rec.item_id, {
      session,
      mission: info.mission || "",
      title: info.title || session,
      opened_ms: rec.ts_ms,
      item,
    });
    return "opened";
  }
  if (rec.kind === "inbox_resolved") {
    return inbox.items.delete(rec.item_id) ? "resolved" : null;
  }
  return null;
}

/** Blocking items first, each group oldest first. */
export function inboxSorted(inbox) {
  return [...inbox.items.values()].sort(
    (a, b) => (b.item.blocking ? 1 : 0) - (a.item.blocking ? 1 : 0) || a.opened_ms - b.opened_ms,
  );
}

export function inboxCounts(inbox) {
  let open = 0;
  let blocking = 0;
  for (const e of inbox.items.values()) {
    open++;
    if (e.item.blocking) blocking++;
  }
  return { open, blocking };
}

export function inboxCountFor(inbox, session) {
  let n = 0;
  for (const e of inbox.items.values()) if (e.session === session) n++;
  return n;
}

export function pageTitle({ open, blocking }) {
  if (!open) return "loom";
  return blocking ? `(${open}) needs you · loom` : `(${open}) loom`;
}

export function notificationFor(entry) {
  const kind = entry.item.item_kind;
  return {
    title: `loom: ${kind} — ${entry.title}`,
    body: oneLine(entry.item.text, 200),
    tag: entry.item.item_id,
  };
}

export function inboxKindWords(kind) {
  return { approval: "approval", question: "question", blocker: "blocker", parked: "parked", finished: "finished" }[kind] || kind;
}

/**
 * The hosts a scope request asks for, or null when the item is not one. A scope request is the
 * non-blocking approval item the `request_scope` tool opens: its options are the hosts, its text says why.
 */
export function scopeRequestHosts(item) {
  const hosts = Array.isArray(item && item.options) ? item.options.filter((h) => typeof h === "string" && h.trim()) : [];
  return item && item.item_kind === "approval" && !item.blocking && hosts.length ? hosts : null;
}

/** The kind label of an inbox card: a scope request reads as one, not as an approval. */
export function inboxCardKind(item) {
  return scopeRequestHosts(item) ? "scope request" : inboxKindWords(item.item_kind);
}

/** The operator's grant of hosts: `{ path, body }`, or `{ error }` when there are none. */
export function scopeRequest(session, hosts, note) {
  const list = (hosts || []).map((h) => String(h).trim()).filter(Boolean);
  if (!list.length) return { error: "Name the hosts to grant." };
  const body = { hosts: list };
  const n = String(note || "").trim();
  if (n) body.note = n;
  return { path: `/api/sessions/${encodeURIComponent(session)}/scope`, body };
}

/** What the card says once the grant is accepted, from the daemon's receipt. */
export function scopeNotice(receipt) {
  const r = receipt || {};
  const hosts = (r.hosts || []).join(", ");
  return r.ledger === false ? `Granted: ${hosts}. This mission keeps no ledger, so the grant is not listed.` : `Granted: ${hosts}.`;
}

/** The choice that closes a blocked session without the goal established. */
export const PARK_ACCEPT = "Accept as blocked and close";
const PARK_KEEP = "Keep working";
const PARK_MORE = "Keep working (more budget)";
const PARK_PROVIDE = "Provide what's missing";

/** Said under the park choices: how to answer so that the session does a next step. */
export const PARK_HELP = "To answer, point it at the next step, for example \"run the build and read the first error\". A yes or no question tends to end in a stop.";

/**
 * The choices for a blocking blocker or park, cheapest first; null for any other item. Each is
 * `{ label, action, answer? }`: `answer` sends `answer` as the operator's answer, `provide` opens the
 * answer box, `release` asks for a reason and closes the mission as blocked. The choices are always
 * the stock ones, whatever labels the item carries, so the wording the operator sees and sends is this
 * file's. "Keep working (more budget)" is offered for a park when the item's options name it or its text
 * says the budget is used up (the item has no field for the reason it parked).
 */
export function parkChoices(item) {
  if (!item || !item.blocking || (item.item_kind !== "blocker" && item.item_kind !== "parked")) return null;
  const out = [{ label: PARK_KEEP, action: "answer", answer: "Keep working on the goal." }];
  const budget = (item.options || []).some((o) => String(o).trim() === PARK_MORE) || /budget/i.test(item.text || "");
  if (item.item_kind === "parked" && budget) {
    out.push({ label: PARK_MORE, action: "answer", answer: "Keep working on the goal. Your budget is renewed." });
  }
  if (item.item_kind === "blocker") out.push({ label: PARK_PROVIDE, action: "provide" });
  out.push({ label: PARK_ACCEPT, action: "release" });
  return out;
}

/** Closing a mission as blocked: `{ path, body }`, or `{ error }` when no reason was typed. */
export function releaseRequest(session, reason) {
  const r = String(reason || "").trim();
  if (!r) return { error: "Write why the mission is closed without the goal established." };
  return { path: `/api/sessions/${encodeURIComponent(session)}/release`, body: { reason: r } };
}

/** The outcome a released mission shows, in place of "finished". */
export const RELEASED_WORDS = "Closed by operator, goal not established";

// ---------------------------------------------------------------------------------------------
// The record store of the open session

export function createRecordStore(session) {
  return {
    session,
    records: new Map(), // raw, applied records for source-linked operator views
    next: 0, // the seq expected next
    ahead: new Map(), // records that arrived before their turn
    blocks: [],
    calls: new Map(), // call_id -> tool block
    openCalls: new Set(), // tool blocks without a result yet
    raw: new Map(), // call_id -> arguments as the model wrote them
    cards: new Map(), // item_id -> inbox card block
    doneReqs: new Set(), // req_ids whose model_response is recorded
    dirty: new Set(), // block indexes created or changed since the last takeDirty
    pending: null, // the reply streaming now
    pendingRev: 0,
    ended: false,
    start: null, // facts from session_start / forked, for the Session tab
    models: [], // the model in effect over time: {seq, ts, profile, model, context_window}, ascending by seq
    turn: null, // {seq, ts} of the turn running now (latest turn_start with no turn_end/interrupt/end after it)
  };
}

export function lastSeq(store) {
  return store.next > 0 ? store.next - 1 : null;
}

/** If records arrived out of reach of the gap, the page to fetch: {after, upTo}. Otherwise null. */
export function missing(store) {
  if (store.ahead.size === 0) return null;
  let lo = Infinity;
  for (const k of store.ahead.keys()) if (k < lo) lo = k;
  return { after: store.next > 0 ? store.next - 1 : null, upTo: lo - 1 };
}

export function applyRecords(store, recs) {
  let n = 0;
  for (const r of recs) if (applyRecord(store, r)) n++;
  return n;
}

/**
 * Apply one record. Idempotent on `seq`: a seq already applied or already buffered is ignored.
 * A record beyond the next expected seq waits in `ahead` until the gap is filled.
 * Returns true when the record was new.
 */
export function applyRecord(store, rec) {
  const seq = rec && rec.seq;
  if (!Number.isInteger(seq) || seq < 0) return false;
  if (seq < store.next) return false;
  if (seq > store.next) {
    if (store.ahead.has(seq)) return false;
    store.ahead.set(seq, rec);
    return true;
  }
  step(store, rec);
  store.next = seq + 1;
  while (store.ahead.has(store.next)) {
    const r = store.ahead.get(store.next);
    store.ahead.delete(store.next);
    step(store, r);
    store.next++;
  }
  return true;
}

function push(store, block) {
  block.id = store.blocks.length;
  block.rev = 1;
  store.blocks.push(block);
  store.dirty.add(block.id);
  return block;
}

function touch(store, block) {
  block.rev++;
  store.dirty.add(block.id);
}

function lostCalls(store) {
  for (const b of store.openCalls) {
    b.state = "missing";
    touch(store, b);
  }
  store.openCalls.clear();
}

function base(rec) {
  return { seq: rec.seq, ts: rec.ts_ms, author: rec.author };
}

function step(store, rec) {
  store.records.set(rec.seq, rec);
  switch (rec.kind) {
    case "user_message":
      push(store, { ...base(rec), kind: "user", text: rec.text || "" });
      break;
    case "harness_note":
      push(store, { ...base(rec), kind: "note", note: rec.note, text: rec.text || "", open: rec.note === "assignment" });
      break;
    case "model_response": {
      const calls = rec.tool_calls || [];
      for (const c of calls) store.raw.set(c.call_id, c.arguments);
      store.doneReqs.add(rec.req_id);
      if (store.pending && store.pending.req_id === rec.req_id) {
        store.pending = null;
        store.pendingRev++;
      }
      push(store, {
        ...base(rec),
        kind: "response",
        req_id: rec.req_id,
        text: rec.text || "",
        reasoning: rec.reasoning || "",
        reasoningLines: rec.reasoning ? lineCount(rec.reasoning) : 0,
        finish: rec.finish,
        usage: rec.usage || {},
        timing: rec.timing || {},
        attempts: rec.attempts || 0,
        cutCalls: calls.filter((c) => c.complete === false).map((c) => c.name),
        footer: responseFooter(rec),
        warning: finishWarning(rec.finish),
      });
      break;
    }
    case "tool_call": {
      let b = store.calls.get(rec.call_id);
      if (b && b.callSeq === undefined) {
        // the result got here first (only possible with a damaged order): complete the block
        b.callSeq = rec.seq;
        b.args = rec.args;
        touch(store, b);
      } else {
        b = push(store, { ...base(rec), kind: "tool", callSeq: rec.seq, call_id: rec.call_id, name: rec.name, args: rec.args, cls: rec.class, state: "running", result: null });
        store.calls.set(rec.call_id, b);
        store.openCalls.add(b);
      }
      if (rec.args === null || rec.args === undefined) b.rawArgs = store.raw.get(rec.call_id) ?? null;
      b.argsLine = rec.args === null || rec.args === undefined
        ? oneLine(b.rawArgs ?? "", 240)
        : argsLine(rec.name, rec.args);
      b.argsInvalid = rec.args === null || rec.args === undefined;
      break;
    }
    case "tool_result": {
      let b = store.calls.get(rec.call_id);
      if (!b) {
        b = push(store, { ...base(rec), kind: "tool", call_id: rec.call_id, name: rec.name, args: undefined, argsLine: "", cls: rec.class, state: "done", result: null });
        store.calls.set(rec.call_id, b);
      }
      b.result = {
        seq: rec.seq,
        status: rec.status,
        text: rec.text || "",
        output: rec.output || null,
        cut: !!rec.cut,
        meta: rec.meta || {},
        duration_ms: rec.duration_ms || 0,
        shown: shownOfTotal(rec),
        lines: lineCount(rec.text || ""),
        ts: rec.ts_ms,
      };
      b.state = "done";
      store.openCalls.delete(b);
      touch(store, b);
      break;
    }
    case "child_spawned":
      push(store, { ...base(rec), kind: "child_spawned", child: rec.child, role: rec.role, mode: rec.mode, brief: rec.brief || {}, budget: rec.budget || {} });
      break;
    case "child_settled":
      push(store, { ...base(rec), kind: "child_settled", child: rec.child, outcome: rec.outcome, report: rec.report || "", full: rec.full || null, steps: rec.steps || 0, inline: !!rec.inline });
      break;
    case "job_registered":
      push(store, { ...base(rec), kind: "line", sub: "job", tone: "dim", text: `job ${rec.job_id} started: ${oneLine(rec.command, 200)}` });
      break;
    case "job_settled": {
      const code = rec.exit_code === null || rec.exit_code === undefined ? "no exit code" : `exit ${rec.exit_code}`;
      push(store, { ...base(rec), kind: "line", sub: "job", tone: rec.exit_code === 0 ? "dim" : "warn", text: `job ${rec.job_id} settled (${code})${rec.detail ? ": " + oneLine(rec.detail, 200) : ""}`, blob: rec.output || null });
      break;
    }
    case "job_matched": {
      const n = Number.isInteger(rec.matches) ? rec.matches : 0;
      push(store, { ...base(rec), kind: "line", sub: "job", tone: "warn", text: `job ${rec.job_id} wrote ${n} line${n === 1 ? "" : "s"} matching /${oneLine(rec.pattern, 120)}/`, blob: rec.output || null });
      break;
    }
    case "ledger":
      push(store, { ...base(rec), kind: "line", sub: "ledger", tone: "dim", text: `ledger #${rec.n}: ${oneLine(rec.summary, 300)}` });
      break;
    case "reweave":
      push(store, {
        ...base(rec),
        kind: "reweave",
        summary: reweaveSummary(rec),
        epoch: rec.epoch,
        upto_seq: rec.upto_seq,
        evictions: (rec.evictions || []).map((e) => ({ seq: e.seq, words: evictionWords(e) })),
        brief: rec.brief || "",
        digest: rec.digest || null,
      });
      break;
    case "inbox_opened": {
      const item = {};
      for (const f of ITEM_FIELDS) if (rec[f] !== undefined) item[f] = rec[f];
      item.options = item.options || [];
      item.blocking = !!item.blocking;
      const b = push(store, { ...base(rec), kind: "inbox", item, resolved: null });
      store.cards.set(rec.item_id, b);
      break;
    }
    case "inbox_resolved": {
      const b = store.cards.get(rec.item_id);
      if (b) {
        b.resolved = { seq: rec.seq, ts: rec.ts_ms, answer: rec.answer || "" };
        touch(store, b);
      } else {
        push(store, { ...base(rec), kind: "line", tone: "dim", text: `inbox item ${rec.item_id} answered: ${oneLine(rec.answer, 200)}` });
      }
      break;
    }
    case "cache_break":
      push(store, { ...base(rec), kind: "line", sub: "cache", tone: "warn", text: `cache break at message ${rec.first_diff_message}: ${oneLine(rec.detail, 300)}` });
      break;
    case "model_switched": {
      // The session's requests go to another model from here on (the operator switched it, or its
      // profile was reloaded). Not shown to the model; one line for the operator.
      const side = (m) => {
        const win = m && m.context_window ? `, ${tokens(m.context_window)} context` : "";
        return `${oneLine((m && m.profile) || "?", 80)} (${oneLine((m && m.model) || "?", 80)}${win})`;
      };
      const reason = rec.reason ? ` · ${oneLine(rec.reason, 120)}` : "";
      const to = modelEntry(rec, rec.to);
      store.models.push(to);
      push(store, {
        ...base(rec), kind: "line", sub: "switch", tone: "dim",
        text: `model switched: ${side(rec.from)} → ${side(rec.to)}${reason}`,
        switch: { from: modelEntry(rec, rec.from), to, reason: rec.reason || "" },
      });
      break;
    }
    case "interrupted":
      push(store, { ...base(rec), kind: "line", sub: "interrupted", tone: "warn", text: `interrupted: ${oneLine(rec.reason, 300)}` });
      store.turn = null;
      lostCalls(store);
      clearPending(store);
      break;
    case "turn_end":
      push(store, { ...base(rec), kind: "divider", text: turnEndWords(rec.reason), reason: rec.reason });
      store.turn = null;
      lostCalls(store);
      clearPending(store);
      break;
    case "session_end":
      push(store, { ...base(rec), kind: "end", outcome: rec.outcome, text: `session ended: ${outcomeWords(rec.outcome)}${rec.detail ? " — " + oneLine(rec.detail, 300) : ""}` });
      store.ended = true;
      store.turn = null;
      lostCalls(store);
      clearPending(store);
      break;
    case "model_request":
      push(store, { ...base(rec), kind: "line", sub: "request", detail: true, tone: "dim", text: `request ${rec.req_id}: step ${rec.step}, epoch ${rec.epoch}, about ${tokens(rec.est_tokens)} tokens${rec.purpose && rec.purpose !== "step" ? " (" + rec.purpose + ")" : ""}` });
      break;
    case "session_start":
      store.start = { budget: rec.budget || {}, tools: (rec.tools || []).length, termination: rec.termination, reasoning_replay: rec.reasoning_replay, model: rec.model ? modelEntry(rec, rec.model) : null };
      if (rec.model) store.models.push(modelEntry(rec, rec.model));
      break;
    case "turn_start":
      store.turn = { seq: rec.seq, ts: rec.ts_ms };
      break;
    case "forked":
      store.start = { ...(store.start || {}), budget: rec.budget || {}, termination: rec.termination, forked_from: rec.parent, upto_seq: rec.upto_seq };
      break;
    default:
      // pin, unpin, net and kinds this build does not know.
      break;
  }
}

function modelEntry(rec, m) {
  return { seq: rec.seq, ts: rec.ts_ms, profile: (m && m.profile) || "", model: (m && m.model) || "", context_window: (m && m.context_window) || 0 };
}

function clearPending(store) {
  if (store.pending) {
    store.pending = null;
    store.pendingRev++;
  }
}

/** Indexes of blocks created or changed since the last call, ascending. */
export function takeDirty(store) {
  const out = [...store.dirty].sort((a, b) => a - b);
  store.dirty.clear();
  return out;
}

/** A streaming `delta` event for the open session. */
export function applyDelta(store, reqId, delta) {
  if (store.doneReqs.has(reqId)) return false;
  if (!store.pending || store.pending.req_id !== reqId) {
    store.pending = { req_id: reqId, attempt: 1, text: "", reasoning: "", calls: [], retrying: null };
  }
  const p = store.pending;
  switch (delta.delta) {
    case "attempt_start":
      p.attempt = delta.attempt;
      p.text = "";
      p.reasoning = "";
      p.calls = [];
      p.retrying = null;
      break;
    case "text": p.text += delta.text; break;
    case "reasoning": p.reasoning += delta.text; break;
    case "tool_call_start": {
      const existing = p.calls.find((c) => c.index === delta.index);
      if (existing) existing.name = delta.name;
      else p.calls.push({ index: delta.index, name: delta.name, args: "" });
      break;
    }
    case "tool_call_args": {
      let c = p.calls.find((x) => x.index === delta.index);
      if (!c) {
        c = { index: delta.index, name: "", args: "" };
        p.calls.push(c);
      }
      c.args += delta.text;
      break;
    }
    case "retrying":
      p.retrying = { attempt: delta.attempt, after_ms: delta.after_ms, reason: delta.reason };
      break;
    default:
      return false;
  }
  store.pendingRev++;
  return true;
}

export function retryingWords(r) {
  return `retrying (attempt ${r.attempt}): ${r.reason}`;
}

/** Keep only the tail of a long streaming string. */
export function tail(text, max) {
  const s = String(text ?? "");
  return s.length > max ? "…" + s.slice(s.length - max) : s;
}

// ---------------------------------------------------------------------------------------------
// Windowing the transcript

export const CHUNK = 300;
export const MAX_RENDERED = 1500;

/** The first block index to render when a transcript of `total` blocks opens. */
export function initialFrom(total, chunk = CHUNK) {
  return Math.max(0, total - chunk);
}
/** After "show earlier". */
export function earlierFrom(from, chunk = CHUNK) {
  return Math.max(0, from - chunk);
}
/** While following the end: drop the oldest rendered blocks past `max`. */
export function trimFrom(total, from, max = MAX_RENDERED) {
  return total - from > max ? total - max : from;
}

/** At the end of a scroller (so the view keeps following)? */
export function atEnd(scrollTop, clientHeight, scrollHeight, slack = 48) {
  return scrollHeight - (scrollTop + clientHeight) <= slack;
}

/** What a key press in the composer does. */
export function composerAction({ key, shiftKey, isComposing, text }) {
  if (key !== "Enter" || shiftKey || isComposing) return "none";
  return String(text ?? "").trim() ? "send" : "ignore";
}

// ---------------------------------------------------------------------------------------------
// Blob viewer (paged lines of a stored output)

export const LINES_PAGE = 1000;

export function createViewer(blob, total) {
  return { blob, chunks: [], first: 0, last: 0, total: total || 0, done: false };
}

/** Add a `LinesView` ({text, first, last, total}); pages must arrive in order. */
export function applyLines(viewer, view) {
  if (view.first !== viewer.last + 1 && viewer.chunks.length > 0) return false;
  if (viewer.chunks.length === 0) viewer.first = view.first;
  viewer.chunks.push(view.text);
  viewer.last = view.last;
  viewer.total = view.total;
  viewer.done = view.last >= view.total || view.last < view.first;
  return true;
}

/** The next range to ask for, or null when everything is loaded. */
export function nextRange(viewer, page = LINES_PAGE) {
  if (viewer.done) return null;
  const start = viewer.chunks.length === 0 ? 1 : viewer.last + 1;
  return { start, end: start + page - 1 };
}

/** The page before the loaded lines, or null when the output is loaded from its first line. */
export function earlierRange(viewer, page = LINES_PAGE) {
  if (viewer.chunks.length === 0 || viewer.first <= 1) return null;
  return { start: Math.max(1, viewer.first - page), end: viewer.first - 1 };
}

/** Add the page that ends right before the loaded lines; any other page is refused. */
export function applyEarlierLines(viewer, view) {
  if (viewer.chunks.length === 0 || view.last !== viewer.first - 1 || view.first > view.last) return false;
  viewer.chunks.unshift(view.text);
  viewer.first = view.first;
  viewer.total = view.total;
  return true;
}

/** The lines of a `LinesView` text. The newline that ends the last line does not add a line. */
export function splitLines(text) {
  const s = String(text ?? "");
  if (s === "") return [];
  const lines = s.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

/** "line 1596" for one line, "lines 212–214" for several. */
export function sourceRangeWords(start, end) {
  return end > start ? `lines ${start}–${end}` : `line ${start}`;
}

/** What a "Go to line" entry means: {line}, or {error} with the sentence to show. */
export function lineTarget(value, total) {
  const text = String(value ?? "").trim();
  const line = Number(text);
  const max = total > 0 ? total : null;
  if (!text || !Number.isSafeInteger(line) || line < 1 || (max !== null && line > max)) {
    return { error: max !== null ? `Choose a line from 1 to ${num(max)}.` : "Choose a line number of 1 or more." };
  }
  return { line };
}

/**
 * Literal search of line texts without regard to case: one {index, at, length} per matching line.
 * Only the text of a line is searched, never its number. `at` is where the first match starts,
 * or -1 when lower-casing changed the length of the line and the place cannot be given exactly.
 * Case is folded without regard to the browser's language, so a search finds the same lines for
 * every operator.
 */
export function findInLines(lines, query) {
  const q = String(query ?? "").toLowerCase();
  if (!q) return [];
  const out = [];
  (lines || []).forEach((line, index) => {
    const text = String(line);
    const lower = text.toLowerCase();
    const at = lower.indexOf(q);
    if (at >= 0) out.push({ index, at: lower.length === text.length ? at : -1, length: q.length });
  });
  return out;
}

/** The match after (`delta` 1) or before (-1) `current` among `total`, wrapping; -1 with none. */
export function stepMatch(total, current, delta) {
  if (!(total > 0)) return -1;
  if (!(current >= 0 && current < total)) return delta < 0 ? total - 1 : 0;
  return (current + (delta < 0 ? -1 : 1) + total) % total;
}

/**
 * What "Copy reference" copies: the line the operator jumped to, else the cited range, else the
 * loaded range, with the producing session and call when they are known.
 */
export function viewerReference(viewer) {
  const s = viewer.source || {};
  const [first, last] = viewer.target ? [viewer.target, viewer.target]
    : s.citeStart ? [s.citeStart, s.citeEnd || s.citeStart]
      : [viewer.first, viewer.last];
  const from = s.session ? ` (${s.session}${s.call ? ", call " + s.call : ""})` : "";
  return `out:${viewer.blob} ${sourceRangeWords(first, last)}${from}`;
}

// ---------------------------------------------------------------------------------------------
// Context view

/** Bar numbers: how full the view is against the window, with marks for floor and target. */
export function meterModel({ inView, windowSize, floor, target }) {
  const known = windowSize > 0;
  const scale = known ? windowSize : Math.max(target * 1.25, inView * 1.1, 1);
  return {
    scale,
    known,
    inViewPct: pct(inView, scale),
    floorPct: floor > 0 ? pct(floor, scale) : null,
    targetPct: target > 0 ? pct(target, scale) : null,
    over: target > 0 && inView > target,
    label: known ? `${tokens(inView)} of ${tokens(windowSize)}` : `${tokens(inView)}`,
  };
}

export function windowMeter(w) {
  return meterModel({ inView: w.est_tokens, windowSize: w.context_window || 0, floor: w.floor_tokens, target: w.target_tokens });
}

/** The small meter in the transcript header, from the session status alone. */
export function statusMeter(info) {
  const st = info.status || {};
  return meterModel({ inView: st.prompt_tokens || 0, windowSize: info.context_window || 0, floor: 0, target: 0 });
}

export function windowSummary(w) {
  const counts = { live: 0, stubbed: 0, reasoning_dropped: 0, dropped: 0 };
  let pinned = 0;
  for (const it of w.items || []) {
    if (counts[it.state] !== undefined) counts[it.state]++;
    if (it.pinned) pinned++;
  }
  const folded = counts.stubbed + counts.dropped + counts.reasoning_dropped;
  return { counts, folded, pinned, total: (w.items || []).length, cached: cachedShare(w.cached_tokens, w.prompt_tokens) };
}

export function windowRows(w, { hideFolded = false } = {}) {
  return (w.items || [])
    .filter((it) => !(hideFolded && (it.state === "dropped" || it.state === "stubbed")))
    .map((it) => ({
      seq: it.seq,
      kind: it.kind,
      state: it.state,
      stateWords: it.state.replace(/_/g, " "),
      size: `${tokens(it.chars)} chars`,
      pinned: !!it.pinned,
      preview: it.preview || "",
      folded: it.state !== "live",
    }));
}

// ---------------------------------------------------------------------------------------------
// Ledger and network

export function ledgerModel(view) {
  const s = (view && view.state) || {};
  const evById = new Map((s.evidence || []).map((e) => [e.id, e]));
  const range = (e) => (Array.isArray(e.lines) && e.lines[0] >= 1 && e.lines[1] >= e.lines[0] ? [e.lines[0], e.lines[1]] : null);
  const lines = (e) => (range(e) ? sourceRangeWords(...range(e)) : "");
  const n = (view && view.skipped) || 0;
  const ahead = (view && view.ahead_of_head) || 0;
  const notices = [];
  if (n > 0) {
    const detail = view.skipped_detail ? ` (first: ${view.skipped_detail})` : "";
    notices.push(`${n} ledger ${n === 1 ? "entry" : "entries"} written by a newer loom ${n === 1 ? "is" : "are"} not shown${detail}. Upgrade loom to see ${n === 1 ? "it" : "them"}.`);
  }
  if (view && view.torn_tail) notices.push("The ledger ends in an interrupted write, which is ignored; the next entry written removes it.");
  if (ahead > 0) notices.push(`${ahead} ledger ${ahead === 1 ? "entry is" : "entries are"} not vouched for by the ledger's head record, so removing ${ahead === 1 ? "it" : "them"} would go unnoticed.`);
  return {
    notices,
    empty: !s.entries,
    goal: s.goal || null,
    constraints: (s.constraints || []).map((c) => ({ id: c.id, text: c.text, retired: c.retired || null })),
    approvals: (s.approvals || []).map((a) => ({ id: a.id, text: a.text, scope: a.scope || "", usedFor: a.used_for || null })),
    plan: (s.plan || []).map((p) => ({ id: p.id, text: p.text, status: p.status, note: p.note || "" })),
    claims: (s.claims || []).map((c) => ({
      id: c.id,
      text: c.text,
      status: c.status,
      note: c.note || "",
      evidence: (c.evidence || []).map((id) => evById.get(id)).filter(Boolean).map((e) => ({
        id: e.id,
        supports: !!e.supports,
        kind: e.kind,
        attested: !!e.attested,
        quote: e.quote || "",
        blob: e.blob || null,
        range: range(e),
        lines: lines(e),
        note: e.note || "",
        call_id: e.call_id,
        session: e.session || null,
      })),
    })),
    obligations: (s.obligations || []).filter((o) => o.outcome === null || o.outcome === undefined).map((o) => ({ id: o.id, kind: o.kind, text: o.text })),
    decisions: (s.decisions || []).map((d) => ({ id: d.id, text: d.text, reason: d.reason })),
    deadEnds: (s.dead_ends || []).map((d) => ({ id: d.id, what: d.what, why: d.why })),
    questions: (s.questions || []).map((q) => ({ id: q.id, text: q.text, blocking: !!q.blocking, answer: q.answer ?? null })),
    scope: grantedHosts(s.scope_grants),
    outcome: outcomeOf(s),
  };
}

/** Every host the operator granted, each once (ignoring case), in the order first granted. */
export function grantedHosts(grants) {
  const seen = new Set();
  const out = [];
  for (const g of grants || []) {
    for (const h of g.hosts || []) {
      const key = String(h).toLowerCase();
      if (!seen.has(key)) {
        seen.add(key);
        out.push(h);
      }
    }
  }
  return out;
}

/**
 * How the mission stands on its goal, for the operator: a release (the operator closed it, goal not
 * established) wins, then the model's claim that the goal is met or cannot be met. Null while open.
 */
export function outcomeOf(state) {
  const s = state || {};
  if (s.release) return { words: RELEASED_WORDS, detail: s.release.reason || "" };
  const g = s.goal_met;
  if (g && g.status === "supported") return { words: "Goal met (claimed by the model)", detail: g.note || "" };
  if (g && g.status === "refuted") return { words: "Goal shown unreachable (claimed by the model)", detail: g.note || "" };
  return null;
}

/** The line the Network tab shows above the decisions. */
export function scopeLine(model) {
  const hosts = (model && model.scope) || [];
  return hosts.length ? `Hosts granted by the operator: ${hosts.join(", ")}` : "No hosts granted by the operator.";
}

/**
 * What the rules control lists under its inputs: the rules in force (the ones that can be
 * withdrawn) and every approval, a used one marked so that it does not read as still available.
 * `asking` is the rule whose withdrawal the operator was asked to confirm; it is kept only while
 * that rule is still in force.
 */
export function ruleLists(model, asking) {
  const m = model || {};
  const rules = (m.constraints || []).filter((c) => !c.retired).map((c) => ({ id: c.id, text: c.text }));
  return {
    rules,
    asking: rules.some((r) => r.id === asking) ? asking : null,
    approvals: (m.approvals || []).map((a) => ({
      id: a.id,
      text: a.text,
      used: !!a.usedFor,
      note: a.usedFor ? `used for: ${a.usedFor}` : a.scope ? `scope: ${a.scope}` : "",
    })),
  };
}

/**
 * Operator rule requests: `{ path, body }` for `api("POST", path, body)`, or `{ error }` when the
 * input is blank. A child's id is fine: the daemon routes it to the lead of its mission. The scope
 * of an approval and the reason of a withdrawal may be blank: a mission's ledger records a stock one.
 */
export function ruleRequest(session, text) {
  const t = String(text || "").trim();
  if (!t) return { error: "Write the rule to set." };
  return { path: `/api/sessions/${encodeURIComponent(session)}/rules`, body: { text: t } };
}
export function approvalRequest(session, text, scope) {
  const t = String(text || "").trim();
  if (!t) return { error: "Write what is approved." };
  return { path: `/api/sessions/${encodeURIComponent(session)}/approvals`, body: { text: t, scope: String(scope || "").trim() } };
}
export function withdrawRequest(session, ruleId, reason) {
  if (!ruleId) return { error: "Choose the rule to withdraw." };
  const path = `/api/sessions/${encodeURIComponent(session)}/rules/${encodeURIComponent(ruleId)}/withdraw`;
  return { path, body: { reason: String(reason || "").trim() } };
}

/**
 * What the rules control says once the daemon accepted a request, from its receipt (`queued`: the
 * lead was in a turn; `ledger`: the mission keeps one). Nothing when the lists are about to show it;
 * otherwise why they do not yet, or never will, so that the operator does not send it twice.
 */
export function ruleNotice(receipt) {
  const r = receipt || {};
  const said = [];
  if (r.queued) said.push("Sent, not recorded yet: the lead was in a turn and records this at its next step, not while a tool call is running.");
  if (r.ledger === false) said.push("This mission keeps no ledger: the lead gets this as a note that stays in its context, and nothing is listed here.");
  else if (r.queued) said.push("It shows here once it is recorded; there is no need to send it again.");
  return said.join(" ");
}

/** The line under the rules control while the mission has no ledger to list rules and approvals from. */
export function rulesHint(ledgerError) {
  if (!String(ledgerError || "").startsWith("No ledger")) return "";
  return "Nothing is listed while this mission has no ledger. A lead that keeps none still gets every rule and approval as a note that stays in its context.";
}

const STEP_MARK = { todo: "○", doing: "◐", done: "●", dropped: "✕" };
export function stepMark(status) {
  return STEP_MARK[status] || "?";
}

const CLAIM_WORDS = { open: "Open", supported: "Supported", refuted: "Refuted", withdrawn: "Withdrawn" };
export function claimStatusWords(status) {
  return CLAIM_WORDS[status] || String(status);
}

/** The filters of the Evidence view, each with its count. Withdrawn is offered only when used. */
export function claimFilters(claims) {
  const list = claims || [];
  const n = (status) => list.filter((c) => c.status === status).length;
  const filters = [{ key: "all", label: "All", count: list.length }];
  for (const status of ["open", "supported", "refuted"]) filters.push({ key: status, label: CLAIM_WORDS[status], count: n(status) });
  if (n("withdrawn")) filters.push({ key: "withdrawn", label: CLAIM_WORDS.withdrawn, count: n("withdrawn") });
  return filters;
}
/** The claims a filter shows. A filter that is no longer offered shows every claim. */
export function filterClaims(claims, key) {
  const list = claims || [];
  return claimFilters(list).some((f) => f.key === key && f.key !== "all") ? list.filter((c) => c.status === key) : [...list];
}

/**
 * The two facts an evidence item carries, kept apart: whether the runtime found its quote in the
 * stored output, and which way the agent says it points. Neither is verification. The runtime
 * refuses a quote that does not match, so an unattested item is one it did not check.
 */
export function evidenceStanding(evidence) {
  const quote = !evidence.quote ? { tone: "dim", icon: null, text: "No quote recorded" }
    : evidence.attested ? { tone: "ok", icon: "check", text: "Quote matches stored output" }
      : { tone: "warn", icon: "alert", text: "Quote not checked against stored output" };
  const direction = evidence.supports ? { tone: "", text: "Supports" } : { tone: "bad", text: "Undermines" };
  return { quote, direction };
}

export function netRow(e) {
  return {
    ts: e.ts_ms,
    verdict: e.allowed ? "allowed" : "refused",
    method: e.method,
    target: `${e.host}:${e.port}`,
    rule: e.rule,
    resolved: e.resolved || "",
  };
}

/** Live `net` event: append unless it repeats one of the last few exactly (fetch/stream overlap). */
export function applyNet(list, entry, keep = 2000) {
  const key = (e) => `${e.ts_ms}|${e.host}|${e.port}|${e.method}|${e.allowed}|${e.rule}`;
  const k = key(entry);
  for (let i = list.length - 1; i >= 0 && i >= list.length - 20; i--) if (key(list[i]) === k) return list;
  list.push(entry);
  if (list.length > keep) list.splice(0, list.length - keep);
  return list;
}

// ---------------------------------------------------------------------------------------------
// The event stream

/**
 * What to do about one event of `/api/events`. `ctx`:
 *   openId       the session shown in the middle column (or null)
 *   ledgerMission the mission whose ledger the right column holds (or null)
 *   known(id)    is this session in the store
 *   missionOf(id) its mission or null
 * Returns a list of effects for app.js to carry out, each {fx, ...}.
 */
export function planEvent(ev, ctx) {
  const out = [];
  switch (ev && ev.type) {
    case "session": {
      out.push({ fx: "session", info: ev.info });
      // Archiving a mission drops its open inbox items on the daemon without an `inbox_resolved`
      // record, and a session that just gained an item may carry it in its status: in both cases
      // pull the authoritative inbox so it is not left stale. Mirrors the macOS shell.
      const open = (ev.info && ev.info.status && ev.info.status.open_inbox) || 0;
      if (ev.info && (ev.info.archived || open > 0)) out.push({ fx: "refetch_inbox" });
      break;
    }
    case "status":
      out.push({ fx: "status", session: ev.session, status: ev.status });
      if (!ctx.known(ev.session)) out.push({ fx: "refetch_sessions" });
      if (ev.session === ctx.openId) out.push({ fx: "header" });
      break;
    case "record": {
      const r = ev.record;
      if (!r) break;
      if (r.kind === "inbox_opened" || r.kind === "inbox_resolved") out.push({ fx: "inbox_record", session: ev.session, record: r });
      if (ev.session === ctx.openId) {
        out.push({ fx: "apply_record", record: r });
        if (r.kind === "turn_end" || r.kind === "reweave") out.push({ fx: "refetch_window" });
      }
      if (r.kind === "ledger" && ctx.ledgerMission && ctx.missionOf(ev.session) === ctx.ledgerMission) {
        out.push({ fx: "refetch_ledger", mission: ctx.ledgerMission });
      }
      break;
    }
    case "delta":
      if (ev.session === ctx.openId) out.push({ fx: "apply_delta", req_id: ev.req_id, delta: ev.delta });
      break;
    case "net":
      if (ev.session === ctx.openId) out.push({ fx: "net", entry: ev.entry });
      break;
    case "settled":
      break;
    case "error":
      out.push({ fx: "notice", text: ev.message || "Error.", session: ev.session || null });
      break;
    case "lagged":
      out.push({ fx: "refetch_sessions" }, { fx: "refetch_inbox" });
      if (ctx.openId) out.push({ fx: "refetch_records" });
      break;
    default:
      break;
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// New session form

export const ROLES = ["lead", "chat"];

/** Validate the form; returns {body} for POST /api/sessions or {error}. */
export function buildNewSession(form) {
  const workspace = String(form.workspace || "").trim();
  const message = String(form.message || "").trim();
  if (!workspace) return { error: "Workspace is required." };
  if (!message) return { error: "A first message is required." };
  const role = form.role || "lead";
  const body = { workspace, message, role, unattended: !!form.unattended };
  if (form.model) body.model = form.model;
  const title = String(form.title || "").trim();
  if (title) body.title = title;
  return { body };
}

/** Parse an API error body into the sentence to show; falls back to the status line. */
export function errorSentence(status, bodyText) {
  try {
    const j = JSON.parse(bodyText);
    if (j && typeof j.error === "string") return j.error;
  } catch {
    // not JSON
  }
  return bodyText && bodyText.trim() ? oneLine(bodyText, 300) : `The request failed (${status}).`;
}

export const LOST_TOKEN = 'This page is not signed in. Run "loom open" again.';

/** The login code of a URL fragment (`#code=<hex>`), or null. Anything else in the fragment is not a code. */
export function codeFromHash(hash) {
  const m = /^#code=([0-9a-f]{16,128})$/.exec(String(hash || ""));
  return m ? m[1] : null;
}

/** Milliseconds to wait before reconnecting a dropped stream: 1 s, doubling, at most 15 s. */
export function reconnectDelayMs(attempt) {
  const n = Math.max(0, Math.min(Number.isFinite(attempt) ? Math.floor(attempt) : 0, 10));
  return Math.min(1000 * 2 ** n, 15000);
}

/**
 * A server-sent-events parser for text arriving in arbitrary chunks. `feed(text)` returns the events
 * completed by it, each `{data, id}` (`id` is the last `id:` field seen, or null). Lines end in LF,
 * CRLF or CR; lines starting with `:` are comments; several `data:` lines join with a newline;
 * an event with no `data:` line is not delivered.
 */
export function createSseParser() {
  let pieces = []; // the unfinished line, in the pieces it arrived in; joined once, when it ends
  let heldCr = false;
  let data = [];
  let id = null;
  return {
    feed(chunk) {
      let text = (heldCr ? "\r" : "") + String(chunk);
      // A CR at the very end may be half of a CRLF: wait for the next chunk to know.
      heldCr = text.endsWith("\r");
      if (heldCr) text = text.slice(0, -1);
      // Only the new text is searched for line ends, so a long line costs its length once.
      const lines = text.replace(/\r\n?/g, "\n").split("\n");
      const rest = lines.pop();
      if (lines.length) {
        pieces.push(lines[0]);
        lines[0] = pieces.join("");
        pieces = [];
      }
      if (rest) pieces.push(rest);
      const out = [];
      for (const line of lines) {
        if (line === "") {
          if (data.length) out.push({ data: data.join("\n"), id });
          data = [];
          continue;
        }
        if (line.startsWith(":")) continue;
        const colon = line.indexOf(":");
        const field = colon < 0 ? line : line.slice(0, colon);
        let value = colon < 0 ? "" : line.slice(colon + 1);
        if (value.startsWith(" ")) value = value.slice(1);
        if (field === "data") data.push(value);
        else if (field === "id" && !value.includes("\0")) id = value;
      }
      return out;
    },
  };
}

/**
 * Hand the JSON object in each parsed event to `handle`. Data that is not JSON is skipped. What
 * `handle` throws goes to `report` and the events after it are still delivered: an event the page
 * cannot show is not a dropped connection.
 */
export function deliverEvents(events, handle, report) {
  for (const m of events) {
    let ev;
    try {
      ev = JSON.parse(m.data);
    } catch {
      continue;
    }
    try {
      handle(ev);
    } catch (e) {
      report(e);
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Chat-first redesign: model identity, chat items, sidebar rows, identity chips, stats
// ---------------------------------------------------------------------------------------------

/** "1M", "262k", "128k", "4k", "800": a context window in tokens; "" when unknown. Binary sizes read as their round name. */
export function formatWindow(n) {
  const v = Number(n);
  if (!(v > 0)) return "";
  if (v < 1000) return String(Math.round(v));
  if (v >= 1e6) {
    const bin = v / 1048576;
    if (Math.abs(bin - Math.round(bin)) < 0.005) return Math.round(bin) + "M";
    return trimZeros((v / 1e6).toFixed(1)) + "M";
  }
  return Math.round(v / 1000) + "k";
}

/** The model that served a record: `store.models` (ascending by seq) entry in effect at `seq`; null when none is known yet.
 *  Shape of an entry: {seq, ts, profile, model, context_window}. */
export function modelAt(store, seq) {
  let found = null;
  for (const m of (store && store.models) || []) {
    if (m.seq <= seq) found = m;
    else break;
  }
  return found;
}

/** The model in effect now: the live session info wins (it updates on a `session` frame), else the latest in the
 *  record store. Returns {profile, model, context_window} or null when neither knows. */
export function currentModel(store, info) {
  if (info && info.profile) return { profile: info.profile, model: info.model || "", context_window: info.context_window || 0 };
  const list = (store && store.models) || [];
  if (!list.length) return null;
  const m = list[list.length - 1];
  return { profile: m.profile, model: m.model, context_window: m.context_window };
}

const isWorkLine = (b) => b.kind === "line" && (b.sub === "job" || b.sub === "ledger" || b.sub === "cache");
const isTextless = (b) => b.kind === "response" && !String(b.text || "").trim();
const isGroupMember = (b) => b.kind === "tool" || isTextless(b) || isWorkLine(b);
// What starts a new assistant segment, so the next assistant item names its model again.
const isBoundary = (b) => b.kind === "user" || b.kind === "note" || b.kind === "inbox" || b.kind === "divider"
  || b.kind === "child_spawned" || b.kind === "child_settled" || b.kind === "end";

/** The group key of a group whose first block has `seq`: stable while the group grows at its end. */
const groupKey = (firstBlock) => "g" + firstBlock.seq;

/** A member that is itself a warning: a cut, aborted or failed reply, a job that exited non-zero, a cache break. */
const isWarningBlock = (b) => !b.detail && ((b.kind === "response" && ((b.cutCalls && b.cutCalls.length > 0) || b.warning)) || (b.kind === "line" && b.tone === "warn"));

function makeGroup(blocks) {
  let toolCount = 0, failed = 0, missing = 0, warnings = 0, records = 0, running = false;
  let startTs = blocks[0].ts, endTs = blocks[0].ts;
  for (const b of blocks) {
    if (!b.detail) records++;
    if (isWarningBlock(b)) warnings++;
    if (b.detail) continue;
    if (Number.isFinite(b.ts)) {
      if (!Number.isFinite(startTs) || b.ts < startTs) startTs = b.ts;
      if (!Number.isFinite(endTs) || b.ts > endTs) endTs = b.ts;
    }
    if (b.kind !== "tool") continue;
    toolCount++;
    if (b.state === "running") running = true;
    else if (b.state === "missing") missing++;
    else if (b.result && b.result.status !== "ok") failed++;
    if (b.result && Number.isFinite(b.result.ts) && b.result.ts > endTs) endTs = b.result.ts;
  }
  return { type: "group", key: groupKey(blocks[0]), blocks, shown: blocks, earlier: 0, records, toolCount, failed, missing, warnings, running, startTs, endTs, open: false, last: false };
}

/**
 * The chat as a render list from `blocks` (a record store's blocks). Items, in order:
 *   {type:"block", block, last, model?, differs?}   a block shown as itself; for a model reply `model` is {profile, model}
 *                                                   serving it and `differs` says it is not the segment chip's model
 *   {type:"group", key, blocks, toolCount, failed, missing, running, startTs, endTs, open, last}
 *                                                   a maximal run of tool blocks, text-less replies and job/ledger/cache lines
 *   {type:"model", profile, model, context_window, seq, reason:"start"|"switch"}   chip before the first assistant item of a
 *                                                   segment (after a user message, note, inbox card, divider, child card or
 *                                                   model switch)
 * `open` of a group: opts.expandAll, a running call, the last item, or opts.open (Set of keys). Request-detail lines
 * are dropped unless opts.details. opts.models is `store.models`; without it no chips are emitted.
 */
export function chatItems(blocks, opts = {}) {
  const { expandAll = false, details = false } = opts;
  const open = opts.open instanceof Set ? opts.open : new Set(opts.open || []);
  const store = { models: opts.models || [] };
  const items = [];
  let run = null;
  let needChip = true;
  let chip = null;
  const chipFor = (seq) => {
    if (!store.models.length) return;
    const m = modelAt(store, seq) || store.models[0];
    if (needChip) {
      const reason = chip ? "switch" : "start";
      items.push({ type: "model", profile: m.profile, model: m.model, context_window: m.context_window, seq, reason });
      chip = m;
      needChip = false;
    }
  };
  const flush = () => {
    if (!run) return;
    chipFor(run[0].seq);
    items.push(makeGroup(run));
    run = null;
  };
  // Request-detail lines never start, end or split a run: one inside a run joins the group (shown when it is open), one
  // outside stands alone. So the group runs, and with them their keys, are the same with details on and off.
  let held = [];
  const standAlone = (b) => items.push({ type: "block", block: b, last: false });
  for (const b of blocks || []) {
    if (!b) continue;
    if (b.detail && !details) continue;
    if (b.detail) {
      held.push(b);
      continue;
    }
    if (isGroupMember(b)) {
      if (run) run.push(...held); else for (const d of held) standAlone(d);
      held = [];
      (run || (run = [])).push(b);
      continue;
    }
    flush();
    for (const d of held) standAlone(d);
    held = [];
    if (b.kind === "response") {
      chipFor(b.seq);
      const m = modelAt(store, b.seq);
      const item = { type: "block", block: b, last: false };
      if (m) {
        item.model = { profile: m.profile, model: m.model };
        item.differs = !!chip && (chip.profile !== m.profile || chip.model !== m.model);
      }
      items.push(item);
      continue;
    }
    items.push({ type: "block", block: b, last: false });
    if (b.sub === "switch") needChip = true;
    else if (isBoundary(b)) needChip = true;
  }
  flush();
  for (const d of held) standAlone(d);
  // "Last" ignores detail lines, so a trailing request line does not fold the group that is still running.
  let last = null;
  for (const it of items) if (!(it.type === "block" && it.block.detail)) last = it;
  if (last) last.last = true;
  for (const it of items) if (it.type === "group") it.open = !!(expandAll || it.running || it.last || open.has(it.key));
  return items;
}

/** The key of the group of `items` that holds record `seq` (a block's own seq, a tool's call or result seq); null when none. */
export function groupKeyForSeq(items, seq) {
  for (const it of items || []) {
    if (it.type !== "group") continue;
    for (const b of it.blocks) {
      if (b.seq === seq || b.callSeq === seq || (b.result && b.result.seq === seq)) return it.key;
    }
  }
  return null;
}

/** The header words of a work group: {text, spoken, duration, tools, failed, missing, warnings, running} where text is
 *  "Worked for 12s · 4 tool calls · 1 failed · running" (the running group's duration runs to `now`). `spoken` is the
 *  accessible name: the same without the duration while the group runs, so a ticking clock is not read out every second. */
export function groupLabel(group, now) {
  const end = group.running && Number.isFinite(now) ? now : group.endTs;
  const ms = Math.max(0, (Number(end) || 0) - (Number(group.startTs) || 0));
  const duration = ms < 1000 ? "under 1s" : seconds(ms);
  const rest = [count(group.toolCount, "tool call")];
  if (group.failed) rest.push(`${group.failed} failed`);
  if (group.missing) rest.push(`${group.missing} without a result`);
  if (group.warnings) rest.push(count(group.warnings, "warning"));
  if (group.running) rest.push("running");
  return {
    text: [`Worked for ${duration}`, ...rest].join(" · "),
    spoken: [group.running ? "Work in progress" : `Worked for ${duration}`, ...rest].join(" · "),
    duration, tools: group.toolCount, failed: group.failed, missing: group.missing, warnings: group.warnings || 0, running: group.running,
  };
}

/**
 * The part of `items` (chatItems output) inside the window that starts at block index `from` (a block's `id` is its
 * index). A block or a group whose last member is below `from` goes; a group that crosses `from` stays, with `shown` the
 * members inside the window and `earlier` how many of its (non-detail) members are left out, so a long open group is not
 * rendered in full. A model chip stays whenever the item after it stays, so a segment keeps its attribution.
 */
export function windowItems(items, from) {
  if (!(from > 0)) return items;
  const keeps = (it) => !!it && (it.type === "group" ? it.blocks[it.blocks.length - 1].id >= from : it.type === "block" ? it.block.id >= from : false);
  const out = [];
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    if (it.type === "model") {
      if (keeps(items[i + 1])) out.push(it);
    } else if (it.type === "group") {
      if (!keeps(it)) continue;
      const shown = it.blocks.filter((b) => b.id >= from);
      out.push({ ...it, shown, earlier: it.blocks.filter((b) => b.id < from && !b.detail).length });
    } else if (keeps(it)) out.push(it);
  }
  return out;
}

/** "Thought · 3 lines" for a reply that has reasoning; "" otherwise. */
export function thoughtLabel(block) {
  const n = (block && block.reasoningLines) || 0;
  return n > 0 ? `Thought · ${count(n, "line")}` : "";
}

/** The icon (a name in the icons template) for a tool block: terminal for exec, file for read, pencil for write/edit,
 *  search for nav, list for state/ledger, people for agent tools. */
export function toolIcon(block) {
  const name = String((block && block.name) || "").toLowerCase();
  if (/^(agent|delegate|spawn|child)/.test(name) || /(^|_)agents?(_|$)/.test(name)) return "tool-agent";
  if (/^(edit|write|patch|apply)/.test(name)) return "tool-write";
  switch (block && block.cls) {
    case "exec": return "tool-exec";
    case "read": return "tool-read";
    case "write": return "tool-write";
    case "nav": return "tool-nav";
    case "state":
    case "terminal": return "tool-state";
    default: return "tool-exec";
  }
}

/** One tool row in a group: {icon, name, argsLine, capsule, duration, state}. `capsule` is {text, tone, icon} or null
 *  (tone "ok" | "bad" | "warn" | "running"; icon is a template name with its own shape: check / cross / alert / dot). */
export function toolRow(block) {
  const r = block.result;
  let capsule = null;
  if (block.state === "running") capsule = { text: "running", tone: "running", icon: "dot" };
  else if (block.state === "missing") capsule = { text: "no result", tone: "warn", icon: "alert" };
  else if (r) {
    const code = r.meta && Number.isInteger(r.meta.exit_code) ? r.meta.exit_code : null;
    if (r.status === "ok") capsule = { text: code === null ? "ok" : `exit ${code}`, tone: "ok", icon: "check" };
    else capsule = { text: code !== null && code !== 0 ? `exit ${code}` : oneLine(r.status || "error", 24), tone: "bad", icon: "cross" };
  }
  const duration = r && r.duration_ms ? seconds(r.duration_ms) : "";
  return { icon: toolIcon(block), name: block.name, argsLine: block.argsLine || "", capsule, duration, state: block.state };
}

/** Footer of a reply, quiet: [profile ·] tok/s · seconds · cache N%. Pass `profile` only when the reply's model differs
 *  from the segment chip. Empty parts are left out. */
export function replyMeta(block, profile = "") {
  const parts = [];
  if (profile) parts.push(profile);
  const speed = speedText(tokensPerSecond(block));
  if (speed) parts.push(speed);
  const total = block.timing && block.timing.total_ms;
  if (total) parts.push(seconds(total));
  const share = cachedShare((block.usage || {}).cached_tokens || 0, (block.usage || {}).prompt_tokens || 0);
  if (share) parts.push(`cache ${share}`);
  return parts.join(" · ");
}

/** The model-switched line in full: {from, to, text} with each side "profile · model · window" and `reason`. */
export function switchLine(block) {
  const sw = block && block.switch;
  if (!sw) return null;
  const side = (m) => [m.profile || "?", m.model || "?", formatWindow(m.context_window)].filter(Boolean).join(" · ");
  return { from: side(sw.from), to: side(sw.to), reason: sw.reason, text: block.text };
}

// ---- sidebar

/** Last path component of a workspace path ("/a/b/" is "b"); "no workspace" for empty. */
export function workspaceName(path) {
  const parts = String(path || "").split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : "no workspace";
}

const getMark = (m, id) => (m instanceof Map ? m.get(id) : m && typeof m === "object" ? m[id] : undefined);

const ROW_MARKS = {
  needs_you: { icon: "diamond", tone: "attention", words: "needs you" },
  running: { icon: "dot", tone: "running", words: "running" },
  waiting: { icon: "half", tone: "running", words: "waiting for jobs or agents" },
  new: { icon: "new", tone: "info", words: "new since your last visit" },
  failed: { icon: "cross", tone: "bad", words: "ended: failed" },
  stopped: { icon: "square", tone: "", words: "ended: stopped" },
  idle: { icon: "ring", tone: "", words: "idle" },
  ended: { icon: "check", tone: "", words: "ended" },
};

/**
 * The one status mark of a sidebar row, strict precedence needs-you > running > new > failed > stopped > idle/ended.
 * `info` the session (root or agent); `attention` from attentionFor (aggregate over the mission for a root);
 * opts.running / opts.waiting override the execution state with the mission's aggregate; opts.fresh says records are
 * newer than the stored watermark. Returns {mark, icon, tone, words}; each mark has its own icon shape.
 */
export function rowMark(info, attention, opts = {}) {
  const st = (info && info.status) || {};
  const blocking = (attention && attention.blocking) || 0;
  let mark;
  if (blocking > 0 && st.phase !== "ended") mark = "needs_you";
  else if (opts.running || st.phase === "running") mark = "running";
  else if (opts.waiting || (st.phase !== "ended" && st.last_end === "waiting")) mark = "waiting";
  else if (opts.fresh) mark = "new";
  else if (st.phase === "ended") mark = st.outcome === "failed" || st.outcome === "budget_exhausted" ? "failed" : st.outcome === "stopped" ? "stopped" : "ended";
  else mark = st.last_end === "error" || st.last_end === "budget_exhausted" ? "failed" : "idle";
  return { mark, ...ROW_MARKS[mark] };
}

/**
 * What waits on the operator as short words for the row's own line, or null. `waiting` is waitingFor(). A blocking request
 * is urgent (amber diamond); a nonblocking question or an available result is said too, in its own words and shape, without
 * the urgent treatment.
 */
export function waitingReason(waiting, now) {
  const b = waiting && waiting.blocking;
  if (b && b.count > 0) {
    if (b.count > 1) return { text: `${b.count} requests waiting`, icon: "diamond", tone: "attention" };
    const noun = WAITING_NOUN[b.kind] || "Request";
    const a = Number.isFinite(b.since) ? age(now, b.since) : null;
    return { text: a === "now" ? `${noun} just arrived` : `${noun} waiting${a ? " " + a : ""}`, icon: "diamond", tone: "attention" };
  }
  const soft = (slot, noun, plural, iconName, tone) => {
    if (!slot || !(slot.count > 0)) return null;
    const a = Number.isFinite(slot.since) ? age(now, slot.since) : null;
    const text = slot.count > 1 ? `${slot.count} ${plural}` : `${noun}${a && a !== "now" ? " " + a : ""}`;
    return { text, icon: iconName, tone };
  };
  return soft(waiting && waiting.questions, "Question open", "questions open", "question", "info")
    || soft(waiting && waiting.results, "Result ready", "results ready", "diamond-outline", "ok");
}

/** The words that stand for an age that was never recorded: the page has not loaded that session's records. */
export const ACTIVITY_UNKNOWN = "activity not loaded";

/**
 * The identity line of a row. `activityMs` is the time of the latest RECORD seen (null when none has been loaded: then the
 * line says so, a creation time is never shown as an age). Returns {text, parts, age, waiting}: `parts` is
 * [profile, role, tail] where tail is the age, or ACTIVITY_UNKNOWN; `text` is "profile · role · tail", or just
 * "profile · role" while something waits (the waiting reason `waiting` is then its own line, so the model stays readable).
 */
export function identityLine(info, activityMs, waiting, now) {
  const reason = waitingReason(waiting, now);
  const when = Number.isFinite(activityMs) ? age(now, activityMs) : ACTIVITY_UNKNOWN;
  const head = [info.profile || "?", info.role || "session"];
  return { text: (reason ? head : [...head, when]).join(" · "), parts: [...head, when], age: when, waiting: reason };
}

/**
 * The sidebar: root sessions grouped by workspace, groups and rows by most recent activity, with a "Needs you" group
 * pinned on top holding the roots (any of whose sessions) blocks on the operator. `store` is the session store;
 * `watermarks` maps session id to the last seq seen on the last visit (Map or object; no entry means never visited, so
 * never "new"); opts.activity is a Map id -> {seq, ts} of the latest record known per session (a session without one
 * has an unknown age: its creation time only orders it); opts.expanded is the Set of missions whose agents are listed, opts.showArchived includes archived roots.
 * Groups: {key:"needs_you"|"ws:<path>", label, tip, workspace, activityMs, rows}. Rows: {info, depth, mission, agentCount,
 * agentsRunning, expanded, attention, waiting, mark:{mark,icon,tone,words}, identity:{text,parts,age,waiting}, activityMs
 * (the sort key), recordedMs (the latest recorded time, null when unknown)}.
 */
export function workspaceGroups(store, inbox, watermarks, now, opts = {}) {
  const { showArchived = false, expanded = new Set(), activity = new Map() } = opts;
  // `recorded`: the time of the latest record seen, or null. The creation time only orders rows that have none; it is never shown.
  const recorded = (info) => {
    const a = activity.get(info.id);
    return a && Number.isFinite(a.ts) ? a.ts : null;
  };
  const lastMs = (info) => recorded(info) ?? (Number(info.created_ms) || 0);
  const isFresh = (info) => {
    const a = activity.get(info.id);
    const seen = getMark(watermarks, info.id);
    return !!a && Number.isInteger(seen) && Number.isInteger(a.seq) && a.seq > seen;
  };
  const ordered = sessionRows(store, { showArchived });
  const missions = [];
  for (const row of ordered) {
    if (row.depth === 0) missions.push([row]);
    else if (missions.length) missions[missions.length - 1].push(row);
  }
  const groups = new Map();
  const needs = { key: "needs_you", label: "Needs you", tip: "Sessions waiting on you", workspace: null, activityMs: 0, rows: [] };
  const rowOf = (info, depth, mission, extra) => {
    const attention = extra.attention;
    const ms = extra.activityMs;
    const known = extra.recordedMs;
    return {
      info, depth, mission, agentCount: extra.agentCount, agentsRunning: extra.agentsRunning, expanded: extra.expanded,
      attention, waiting: extra.waiting,
      mark: rowMark(info, attention, { running: extra.running, waiting: extra.waitingExec, fresh: extra.fresh }),
      identity: identityLine(info, known, extra.waiting, now),
      activityMs: ms, recordedMs: known,
    };
  };
  for (const rows of missions) {
    const root = rows[0].info;
    const ids = rows.map((r) => r.info.id);
    const attention = { open: 0, blocking: 0, questions: 0, results: 0 };
    let running = false, waitingExec = false, fresh = false, newest = 0, newestRecorded = null;
    for (const r of rows) {
      const own = attentionFor(inbox, r.info.id);
      for (const k of Object.keys(attention)) attention[k] += own[k];
      const st = r.info.status || {};
      if (st.phase === "running") running = true;
      else if (st.phase !== "ended" && st.last_end === "waiting") waitingExec = true;
      if (isFresh(r.info)) fresh = true;
      newest = Math.max(newest, lastMs(r.info));
      const rec = recorded(r.info);
      if (rec !== null) newestRecorded = Math.max(newestRecorded ?? 0, rec);
    }
    const agents = rows.slice(1);
    const rootRow = rowOf(root, 0, root.id, {
      agentCount: agents.length,
      agentsRunning: agents.filter((r) => (r.info.status || {}).phase === "running").length,
      expanded: expanded.has(root.id), attention, waiting: waitingFor(inbox, ids),
      running, waitingExec, fresh, activityMs: newest, recordedMs: newestRecorded,
    });
    const out = [rootRow];
    if (expanded.has(root.id)) {
      for (const r of agents) {
        out.push(rowOf(r.info, r.depth, root.id, {
          agentCount: 0, agentsRunning: 0, expanded: false,
          attention: attentionFor(inbox, r.info.id), waiting: waitingFor(inbox, [r.info.id]),
          running: false, waitingExec: false, fresh: isFresh(r.info), activityMs: lastMs(r.info), recordedMs: recorded(r.info),
        }));
      }
    }
    let group;
    if (rootRow.mark.mark === "needs_you") group = needs;
    else {
      const key = "ws:" + (root.workspace || "");
      if (!groups.has(key)) groups.set(key, { key, label: workspaceName(root.workspace), tip: root.workspace || "no workspace recorded", workspace: root.workspace || "", activityMs: 0, rows: [], blocks: [] });
      group = groups.get(key);
    }
    (group.blocks || (group.blocks = [])).push(out);
    group.activityMs = Math.max(group.activityMs, newest);
  }
  const flatten = (g) => {
    const blocks = (g.blocks || []).sort((a, b) => b[0].activityMs - a[0].activityMs || (a[0].info.id < b[0].info.id ? 1 : -1));
    g.rows = blocks.flat();
    delete g.blocks;
    return g;
  };
  const list = [...groups.values()].map(flatten).sort((a, b) => b.activityMs - a.activityMs || (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
  return needs.blocks && needs.blocks.length ? [flatten(needs), ...list] : list;
}

// ---- identity bar

/** The first 10 characters of a session id, for the id button. */
export function shortId(id) {
  return String(id || "").slice(0, 10);
}

/**
 * The run state in words with its shape: {text, mark, icon, tone, running}.
 *   needs you -> "Waiting for you"; running -> "Running · step N · <elapsed>" (elapsed only when opts.startMs, the
 *   start of this run, is known: store.turn.ts); idle -> "Idle · step N"; stopped / waiting for jobs likewise;
 *   ended -> "Ended · done|failed|stopped|…". opts.attention is attentionFor() output, opts.now epoch ms.
 */
export function runWords(info, opts = {}) {
  const st = (info && info.status) || {};
  const mark = stateMark(info, opts.attention);
  const step = st.step > 0 ? ` · step ${st.step}` : "";
  const shape = (STANDING[mark] || STANDING.idle);
  let text;
  let running = false;
  switch (mark) {
    case "needs_you": text = "Waiting for you"; break;
    case "running": {
      running = true;
      const ms = Number.isFinite(opts.startMs) && Number.isFinite(opts.now) ? Math.max(0, opts.now - opts.startMs) : null;
      const whole = ms === null ? 0 : Math.floor(ms / 1000);
      text = `Running${step}${ms === null ? "" : " · " + (whole < 10 ? whole + "s" : seconds(whole * 1000))}`;
      break;
    }
    case "waiting": text = `Waiting for jobs or agents${step}`; break;
    case "stopped": text = st.phase === "ended" ? "Ended · stopped" : `Stopped${step}`; break;
    case "finished":
    case "failed":
    case "result_ready": {
      const ended = `Ended · ${st.outcome ? outcomeWords(st.outcome) : mark === "failed" ? "failed" : "done"}`;
      // A result waiting to be reviewed is said in words, not only by its shape.
      text = st.phase === "ended" ? ended + (mark === "result_ready" ? " · result ready" : "")
        : mark === "failed" ? `Failed${step}` : `Idle${step}${mark === "result_ready" ? " · result ready" : ""}`;
      break;
    }
    case "question": text = `Idle${step} · question open`; break;
    default: text = `Idle${step}`;
  }
  return { text, mark, icon: shape.icon, tone: shape.tone, running };
}

/**
 * The chips of the session header. `info` is the session, `status` the daemon status ({models:[{profile, base_url, model,
 * reachable, detail, context_window}]} or null), opts: {current (currentModel(), used when info has no profile), now,
 * startMs, attention, mission (the mission root's info, for "agent of")}. Returns
 *   model {text:"profile · model · window", profile, model, contextWindow, tip, reachable:true|false|null, warn:{icon:"alert", word:"unreachable"}|null}
 *   role  {text:"pack / role", tip}
 *   id    {text: shortId, full, label}
 *   run   runWords(...)
 */
export function identityChips(info, status, opts = {}) {
  const cur = currentModel(null, info) || opts.current || { profile: "", model: "", context_window: 0 };
  const health = ((status && status.models) || []).find((m) => m.profile === cur.profile) || null;
  const win = cur.context_window || (health && health.context_window) || 0;
  const modelId = cur.model || (health && health.model) || "";
  const textParts = [cur.profile || "unknown profile", modelId, formatWindow(win)].filter(Boolean);
  const reachable = health ? !!health.reachable : null;
  const tip = [`${cur.profile} · ${modelId}`.trim()];
  if (health && health.base_url) tip.push(health.base_url);
  if (health) tip.push(reachable ? "reachable" : `unreachable${health.detail ? ": " + health.detail : ""}`);
  if (win) tip.push(`context limit ${num(win)} tokens`);
  const role = info.role || "session";
  const pack = info.pack || "";
  const roleTip = [info.parent && opts.mission ? `agent of ${opts.mission.title || opts.mission.id}` : info.parent ? "agent" : (role === "lead" ? "lead of its mission" : "session")];
  return {
    model: { text: textParts.join(" · "), profile: cur.profile, model: modelId, contextWindow: win, tip: tip.join("\n"), reachable, warn: reachable === false ? { icon: "alert", word: "unreachable" } : null },
    role: { text: pack ? `${pack} / ${role}` : role, tip: roleTip.join("\n") },
    id: { text: shortId(info.id), full: info.id, label: "Copy session id" },
    run: runWords(info, opts),
  };
}

/** Breadcrumbs of a session, root first: [{id, label, tip, current, ellipsis}]. Ancestors beyond the root and the parent
 *  collapse into one {ellipsis:true, tip: the hidden titles}; the last crumb is the session itself (title, or its id). */
export function breadcrumbs(store, id) {
  const info = store.byId.get(id);
  if (!info) return [{ id, label: id, tip: id, current: true, ellipsis: false }];
  const chain = [];
  const seen = new Set([id]);
  let p = info.parent ? store.byId.get(info.parent) : null;
  while (p && !seen.has(p.id)) {
    chain.unshift(p);
    seen.add(p.id);
    p = p.parent ? store.byId.get(p.parent) : null;
  }
  const crumb = (s, current) => ({ id: s.id, label: s.title || s.id, tip: s.id, current, ellipsis: false });
  const out = [];
  if (chain.length > 2) {
    out.push(crumb(chain[0], false));
    out.push({ id: null, label: "…", tip: chain.slice(1, -1).map((s) => s.title || s.id).join(" / "), current: false, ellipsis: true });
    out.push(crumb(chain[chain.length - 1], false));
  } else for (const s of chain) out.push(crumb(s, false));
  out.push(crumb(info, true));
  return out;
}

// ---- stats line

/**
 * The stats under the composer, each a label or "" (omitted, never zero): speed (sessionSpeed label, "" without a
 * measured reply), cache ("cache 92%": cached/prompt of the latest status), context ("context 31% of 1M": latest prompt
 * tokens over the window), step ("step 214"). `info` is the session (status, context_window); `blocks` the record blocks.
 */
export function sessionStats(info, blocks) {
  const st = (info && info.status) || {};
  const prompt = Number(st.prompt_tokens) || 0;
  const share = cachedShare(st.cached_tokens || 0, prompt);
  const win = Number(info && info.context_window) || 0;
  const context = prompt > 0 && win > 0 ? `context ${Math.max(1, Math.round(pct(prompt, win)))}% of ${formatWindow(win)}` : "";
  return {
    speed: sessionSpeed(blocks).label,
    cache: share ? `cache ${share}` : "",
    context,
    step: st.step > 0 ? `step ${st.step}` : "",
  };
}

// ---------------------------------------------------------------------------------------------
// Composer model seat

/**
 * The choices of the model seat: the configured profiles (`GET /api/models` `models`), in the daemon's order, each
 * {value, label, unreachable}. A profile that is unreachable says so in words. When the session's own profile is no
 * longer configured it is still listed, so the select can show the truth.
 */
export function seatOptions(models, current) {
  const out = (Array.isArray(models) ? models : []).filter(m => m && m.profile).map(m => ({
    value: m.profile,
    label: m.profile + (m.reachable === false ? " (not reachable)" : ""),
    unreachable: m.reachable === false,
  }));
  if (current && current.profile && !out.some(o => o.value === current.profile)) {
    out.push({ value: current.profile, label: current.profile + " (not configured)", unreachable: false });
  }
  return out;
}

/** The inline question for switching to `target` (a profile name): {text, yes, no}; null when there is nothing to ask. */
export function seatConfirm(models, current, target) {
  const entry = (Array.isArray(models) ? models : []).find(m => m && m.profile === target);
  if (!entry || (current && current.profile === target)) return null;
  const unreachable = entry.reachable === false
    ? ` ${entry.profile} is not reachable now; the next step fails until it answers.` : "";
  return {
    text: `Switch this session to ${entry.profile} (${entry.model}) from its next step? The next request re-reads the whole prompt once.${unreachable}`,
    yes: "Switch",
    no: current && current.profile ? "Keep " + current.profile : "Keep current",
  };
}

/** The sentence for a switch receipt `{session, model, live}`. */
export function seatReceipt(receipt) {
  const m = (receipt && receipt.model) || {};
  const name = m.profile ? `${m.profile}${m.model ? " (" + m.model + ")" : ""}` : "the new model";
  return receipt && receipt.live === false
    ? `Switched to ${name}. The session records the switch and uses it when it next runs.`
    : `Switched to ${name}; takes effect at the next step.`;
}

/**
 * Whether the model seat of `info` can be used, and why not. The daemon refuses to re-seat a finished session, so the seat
 * says so up front instead of asking the operator to confirm a switch that cannot happen. `busy` is the id of the session a
 * switch is in flight for (or null): only that session's seat waits, not every session's.
 */
export function seatAvailability(info, busy, optionCount = 1) {
  if (!info) return { disabled: true, reason: "No session is open." };
  if (info.status && info.status.phase === "ended") return { disabled: true, reason: "This session has ended; its model no longer changes." };
  if (busy && busy === info.id) return { disabled: true, reason: "Switching the model…" };
  if (!(optionCount > 0)) return { disabled: true, reason: "No model profiles are configured." };
  return { disabled: false, reason: "" };
}

/**
 * Whether a switch receipt may be written over the session held now. `before` is {profile, model} captured before the
 * request; when a session frame has since changed them (another tab or the CLI switched too), the stream's value is newer and wins.
 */
export function receiptApplies(held, before) {
  if (!held || !before) return false;
  return (held.profile || "") === (before.profile || "") && (held.model || "") === (before.model || "");
}

/**
 * The one sentence of the composer's status line (an aria-live region). Loading comes first while the record is not fully
 * loaded; otherwise the NEWER of the model-switch note and the message state wins, so a receipt or a failure that settles
 * after a switch is never hidden by the switch's sentence. `seat` and `message` are {text, at} (`at` an increasing counter) or null.
 */
export function sendStateText({ loaded = true, seat = null, message = null } = {}) {
  if (!loaded) return "Loading the record before messages can be sent.";
  const s = seat && seat.text ? seat : null;
  const m = message && message.text ? message : null;
  if (s && m) return (Number(s.at) || 0) > (Number(m.at) || 0) ? s.text : m.text;
  return (s || m || { text: "" }).text;
}
