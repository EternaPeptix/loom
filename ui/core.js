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
  return { blob, shown, total, cut, ranges, ofBlob: !!ofBlob, words, complete };
}

/** Footer line of a model response. */
export function responseFooter(r) {
  const u = r.usage || {};
  const parts = [];
  parts.push(`prompt ${tokens(u.prompt_tokens || 0)}`);
  const share = cachedShare(u.cached_tokens || 0, u.prompt_tokens || 0);
  if (share) parts.push(`${share} cached`);
  parts.push(`completion ${tokens(u.completion_tokens || 0)}`);
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
    byKey.get(key).rows.push({ info: mission, depth: 0, mission: mission.id, agentCount, expanded: expanded.has(mission.id), attention });
    if (expanded.has(mission.id)) {
      for (const row of members.slice(1)) byKey.get(key).rows.push({ ...row, mission: mission.id, agentCount: 0, expanded: false, attention: attentionFor(inbox, row.info.id) });
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

/** Recorded mission changes and ledger state; it does not infer semantic success from receipts. */
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
    if (record.kind === "tool_result" && record.status !== "ok") {
      failedChecks++;
      text = `${oneLine(record.name || "Tool", 50)} returned ${oneLine(record.status || "an unknown status", 50)}`;
    } else if (record.kind === "tool_result" && record.status === "ok" && record.class === "write") {
      text = `Write tool completed${record.meta && record.meta.path ? ": " + oneLine(record.meta.path, 100) : ""}`;
    } else if (record.kind === "ledger") {
      text = `Ledger updated${record.summary ? ": " + oneLine(record.summary, 200) : ""}`;
    } else if (["child_settled", "job_settled", "inbox_opened", "inbox_resolved", "interrupted", "session_end"].includes(record.kind)) {
      text = activity;
    }
    if (text && (sinceSeq === null || record.seq > sinceSeq)) changes.push({ seq: record.seq, ts: record.ts_ms, text, kind: record.kind });
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

const SESSION_SECTIONS = new Set(["overview", "record", "evidence"]);
export function sessionHash(session, section = "overview") {
  return `#/s/${encodeURIComponent(session)}/${SESSION_SECTIONS.has(section) ? section : "overview"}`;
}
/** Decode identifiers after splitting the route so encoded punctuation remains part of an id. */
export function parseRoute(hash) {
  const parts = String(hash || "").replace(/^#/, "").split("/");
  if (parts[1] === "inbox" && parts.length === 2) return { view: "inbox" };
  if (parts[1] === "new" && parts.length === 2) return { view: "new" };
  if (parts[1] !== "s" || !parts[2] || parts.length > 4) return { view: "empty" };
  try {
    const session = decodeURIComponent(parts[2]);
    const section = parts[3] || "overview";
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

// ---------------------------------------------------------------------------------------------
// Inbox

export function createInbox() {
  return { items: new Map() };
}

export function applyInboxList(inbox, list) {
  inbox.items = new Map((list || []).map((e) => [e.item.item_id, e]));
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
      push(store, { ...base(rec), kind: "line", tone: "dim", text: `job ${rec.job_id} started: ${oneLine(rec.command, 200)}` });
      break;
    case "job_settled": {
      const code = rec.exit_code === null || rec.exit_code === undefined ? "no exit code" : `exit ${rec.exit_code}`;
      push(store, { ...base(rec), kind: "line", tone: rec.exit_code === 0 ? "dim" : "warn", text: `job ${rec.job_id} settled (${code})${rec.detail ? ": " + oneLine(rec.detail, 200) : ""}`, blob: rec.output || null });
      break;
    }
    case "ledger":
      push(store, { ...base(rec), kind: "line", tone: "dim", text: `ledger #${rec.n}: ${oneLine(rec.summary, 300)}` });
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
      push(store, { ...base(rec), kind: "line", tone: "warn", text: `cache break at message ${rec.first_diff_message}: ${oneLine(rec.detail, 300)}` });
      break;
    case "interrupted":
      push(store, { ...base(rec), kind: "line", tone: "warn", text: `interrupted: ${oneLine(rec.reason, 300)}` });
      lostCalls(store);
      clearPending(store);
      break;
    case "turn_end":
      push(store, { ...base(rec), kind: "divider", text: turnEndWords(rec.reason), reason: rec.reason });
      lostCalls(store);
      clearPending(store);
      break;
    case "session_end":
      push(store, { ...base(rec), kind: "end", outcome: rec.outcome, text: `session ended: ${outcomeWords(rec.outcome)}${rec.detail ? " — " + oneLine(rec.detail, 300) : ""}` });
      store.ended = true;
      lostCalls(store);
      clearPending(store);
      break;
    case "model_request":
      push(store, { ...base(rec), kind: "line", detail: true, tone: "dim", text: `request ${rec.req_id}: step ${rec.step}, epoch ${rec.epoch}, about ${tokens(rec.est_tokens)} tokens${rec.purpose && rec.purpose !== "step" ? " (" + rec.purpose + ")" : ""}` });
      break;
    case "session_start":
      store.start = { budget: rec.budget || {}, tools: (rec.tools || []).length, termination: rec.termination, reasoning_replay: rec.reasoning_replay };
      break;
    case "forked":
      store.start = { ...(store.start || {}), budget: rec.budget || {}, termination: rec.termination, forked_from: rec.parent, upto_seq: rec.upto_seq };
      break;
    default:
      // turn_start, pin, unpin, net and kinds this build does not know.
      break;
  }
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
  const lines = (e) => (Array.isArray(e.lines) ? `lines ${e.lines[0]}–${e.lines[1]}` : "");
  return {
    empty: !s.entries,
    goal: s.goal || null,
    constraints: (s.constraints || []).map((c) => ({ id: c.id, text: c.text, retired: c.retired || null })),
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
  };
}

const STEP_MARK = { todo: "○", doing: "◐", done: "●", dropped: "✕" };
export function stepMark(status) {
  return STEP_MARK[status] || "?";
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
    case "session":
      out.push({ fx: "session", info: ev.info });
      break;
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

export const LOST_TOKEN = 'This page lost its access token. Run "loom open" again.';
