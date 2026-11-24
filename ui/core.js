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
// Tool output is shown raw; these only choose a look for each line, never change its text.
// Every stored result starts "[tool · facts]" and ends "[end of tool output · outcome]" (crates/loom-core admit.rs).
const ENVELOPE_HEAD = /^\[[a-z][a-z0-9_]* · .*\]$/;
const ENVELOPE_FOOT = /^\[end of [a-z][a-z0-9_]* output · .*\]$/;

/** Where a unified diff starts in `lines`: a "--- " line directly followed by "+++ " and then "@@ " (-1 when none). */
function diffStart(lines) {
  for (let i = 0; i + 2 < lines.length; i++) {
    if (lines[i].startsWith("--- ") && lines[i + 1].startsWith("+++ ") && lines[i + 2].startsWith("@@ ")) return i;
  }
  return -1;
}

/**
 * The look of each line of a tool output, parallel to `text.split("\n")`: "meta" for the harness's own first and last
 * lines, and inside a unified diff "file", "hunk", "add", "del" or "ctx"; "" for anything else.
 */
export function outputLineKinds(text) {
  const lines = String(text ?? "").split("\n");
  const kinds = lines.map(() => "");
  let last = lines.length - 1;
  while (last > 0 && lines[last] === "") last--;
  if (lines.length > 1 && ENVELOPE_HEAD.test(lines[0])) kinds[0] = "meta";
  if (last > 0 && ENVELOPE_FOOT.test(lines[last])) kinds[last] = "meta";
  const start = diffStart(lines);
  if (start < 0) return kinds;
  let inHunk = false;
  for (let i = start; i < lines.length; i++) {
    if (kinds[i] === "meta") continue;
    const l = lines[i];
    if ((l.startsWith("--- ") && i + 1 < lines.length && lines[i + 1].startsWith("+++ ")) || (l.startsWith("+++ ") && i > 0 && lines[i - 1].startsWith("--- "))) { kinds[i] = "file"; inHunk = false; }
    else if (l.startsWith("@@ ")) { kinds[i] = "hunk"; inHunk = true; }
    else if (!inHunk) continue;
    else if (l.startsWith("+")) kinds[i] = "add";
    else if (l.startsWith("-")) kinds[i] = "del";
    else if (l.startsWith(" ") || l === "") kinds[i] = "ctx";
    else if (l.startsWith("\\")) kinds[i] = "meta";
    else inHunk = false;
  }
  return kinds;
}

/** Lines added and removed by the unified diff in a tool output, or null when it holds none. */
export function diffStat(text) {
  const kinds = outputLineKinds(text);
  if (!kinds.includes("hunk")) return null;
  let added = 0, removed = 0;
  for (const k of kinds) { if (k === "add") added++; else if (k === "del") removed++; }
  return { added, removed, text: `+${added} −${removed}`, words: `${count(added, "line")} added, ${count(removed, "line")} removed` };
}

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
const PATH_KEYS = ["path", "file_path", "absolute_path", "target_file", "file"];
const firstString = (args, keys) => { for (const k of keys) if (typeof args[k] === "string" && args[k]) return args[k]; return ""; };

/** The arguments of a tool call on one line: bash shows its command, file tools their path, search tools their
 *  pattern (and where), web_fetch its URL, job tools their job. `name` is the tool that ran (see `tool_result`). */
export function argsLine(name, args, max = 240) {
  if (args === null || args === undefined) return "";
  if (typeof args === "string") return oneLine(args, max);
  if (typeof args === "object" && !Array.isArray(args)) {
    if (name === "bash" && typeof args.command === "string") return oneLine(args.command, max);
    if (FILE_TOOLS.has(name)) {
      const p = firstString(args, PATH_KEYS);
      if (p) return oneLine(p, max);
    }
    if (name === "grep" || name === "glob" || name === "out_grep") {
      const pat = firstString(args, ["pattern", "query", "regex", "glob"]);
      const where = firstString(args, [...PATH_KEYS, "dir", "directory", "handle"]);
      if (pat) return oneLine(where ? `${pat} in ${where}` : pat, max);
    }
    if (name === "web_fetch" && typeof args.url === "string") return oneLine(args.url, max);
    if ((name === "job_wait" || name === "job_kill") && typeof args.job === "string") return oneLine(args.job, max);
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

/**
 * Where "open full output" starts reading, given the ranges the model was shown (1-based, inclusive) and the stored line count
 * (null when unknown). A tail-only or middle view opens at its first line; a head plus tail (a cut) opens at the start of the
 * omitted middle; a head alone opens just after it when the stored output is known to go on. Otherwise line 1.
 */
export function openAtLine(ranges, total) {
  const rs = mergeRanges(ranges);
  if (!rs.length) return 1;
  if (rs[0][0] > 1) return rs[0][0];
  if (rs.length > 1) return rs[0][1] + 1;
  const end = rs[0][1];
  return Number.isInteger(total) && end < total ? end + 1 : 1;
}

/** Is line `n` inside one of `ranges` ([[start, end], ...], inclusive)? */
export function lineInRanges(ranges, n) {
  for (const r of ranges || []) if (n >= r[0] && n <= r[1]) return true;
  return false;
}

/**
 * How the viewer opens a tool result's stored output: {start, seenRanges}. `start` is openAtLine; `seenRanges` are the lines the
 * model was shown, marked in the viewer, and empty when it was shown everything or the ranges are unknown.
 */
export function viewerPlan(shown) {
  const ranges = (shown && shown.ranges) || [];
  const partial = ranges.length > 0 && !(shown && shown.complete);
  return { start: openAtLine(ranges, shown ? shown.total : null), seenRanges: partial ? ranges : [] };
}

/** The standing sentence of the viewer: evidence wording for a cited range, and a note on the marked lines when there are any. */
export function viewerStanding(source) {
  const s = source || {};
  const base = s.citeStart
    ? "Opening this stored snapshot is an operator action. It does not change what the model has observed, and it does not verify the claim."
    : "This is a stored output snapshot. Opening it here does not change what the model has observed.";
  return s.seenRanges && s.seenRanges.length ? base + " Lines the model was shown are marked." : base;
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
  const lastText = speedText(last);
  const meanText = speedText(mean);
  const label = used > 1
    ? (lastText === meanText ? `${lastText} (${used} replies)` : `${lastText} · ${meanText} over ${used} replies`)
    : lastText;
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

// ---- compaction (docs/CONTRACTS-COMPACTION.md Part K and U)

const COMPACT_REASONS = { size: "size", refused: "refused", stall: "stall", operator: "operator", fresh_start: "fresh start" };
export function compactionReasonWords(reason) {
  return COMPACT_REASONS[reason] || String(reason || "unknown").replace(/_/g, " ");
}

/** An `out:` key in text: 8 to 64 hex characters after `out:` (the handle, or a prefix of one). */
const OUT_KEY = /\bout:([0-9a-f]{8,64})(?![0-9a-zA-Z])/g;

/** Every distinct `out:` key in the texts, in the order first seen, without the `out:` prefix. */
export function extractOutKeys(...texts) {
  const seen = new Set();
  const keys = [];
  for (const t of texts) {
    if (typeof t !== "string") continue;
    for (const m of t.matchAll(OUT_KEY)) if (!seen.has(m[1])) { seen.add(m[1]); keys.push(m[1]); }
  }
  return keys;
}

/** Text cut into [{text}] and [{key, text}] parts, so each `out:` key can be a button. The parts join back to the text. */
export function splitOutKeys(text) {
  const s = String(text ?? "");
  const out = [];
  let at = 0;
  for (const m of s.matchAll(OUT_KEY)) {
    if (m.index > at) out.push({ text: s.slice(at, m.index) });
    out.push({ key: m[1], text: m[0] });
    at = m.index + m[0].length;
  }
  if (at < s.length) out.push({ text: s.slice(at) });
  return out;
}

/** The divider's head line: "Context compacted · step 412 · 305k → 41k tokens · size". */
export function compactionHead(rec, step) {
  const bits = ["Context compacted"];
  if (Number.isInteger(step)) bits.push(`step ${num(step)}`);
  if (rec.before_tokens > 0 || rec.after_tokens_est > 0) bits.push(`${tokens(rec.before_tokens || 0)} → ${tokens(rec.after_tokens_est || 0)} tokens`);
  bits.push(compactionReasonWords(rec.reason));
  return bits.join(" · ");
}

/**
 * The card model of a `compaction` record: the head, the note (null when the note request failed), the key table, the keys each cites
 * (every key a button), the keys the daemon dropped from the note, and for a fresh start what the verifier objected to.
 */
export function compactionBlock(rec, step) {
  const note = typeof rec.note === "string" && rec.note.trim() ? rec.note : null;
  const table = typeof rec.table === "string" ? rec.table : "";
  return {
    kind: "compaction",
    head: compactionHead(rec, step),
    epoch: rec.epoch,
    upto_seq: rec.upto_seq,
    reason: rec.reason,
    note,
    noteKeys: extractOutKeys(note),
    table,
    tableKeys: extractOutKeys(table),
    droppedKeys: Array.isArray(rec.dropped_keys) ? rec.dropped_keys.map(String) : [],
    objections: typeof rec.objections === "string" && rec.objections.trim() ? rec.objections : null,
  };
}

export const COMPACT_NO_NOTE = "No note was written (the note request failed). The key table below is still exact.";
export const COMPACT_NOTE_LABEL = "Written by the model, not verified: check a key before relying on it.";
export const COMPACT_DROPPED_LABEL = "Keys the note cited that do not exist in this session; they were removed from it:";

// ---- loading a long session from the end (U4)

export const TAIL_LIMIT = 1000;
export const TAIL_BEFORE = Number.MAX_SAFE_INTEGER;

/** The latest `compaction` record among `recs`, or null. */
export function latestCompaction(recs) {
  let best = null;
  for (const r of recs || []) if (r && r.kind === "compaction" && (!best || r.seq > best.seq)) best = r;
  return best;
}

/**
 * After a page from the end: the request for the next earlier page when the records after the latest compaction's `upto_seq` are
 * not all in `recs` yet, else null. Without a compaction in view the last page is all that loads (a log that was never compacted
 * pages backward on request).
 */
export function tailNeedsMore(recs, prevBefore) {
  if (prevBefore === null || prevBefore === undefined || !recs || !recs.length) return null;
  const c = latestCompaction(recs);
  if (!c || !Number.isInteger(c.upto_seq)) return null;
  return recs[0].seq > c.upto_seq + 1 ? { before: prevBefore, limit: TAIL_LIMIT } : null;
}

/** True when the page answer comes from a daemon that pages backward (it carries `prev_before`, null or a seq). */
export function pagesBackward(page) {
  return !!page && Object.hasOwn(page, "prev_before");
}

const PRELUDE_KINDS = new Set(["session_start", "forked"]);

/**
 * The store starts at the first record of the tail: `recs` are the last pages oldest first, `prevBefore` the seq to ask for the
 * records before them (null when there are none), `prelude` the session's first records (their start facts fill the Session tab).
 */
export function startTailStore(store, recs, prevBefore, prelude = []) {
  const first = recs.length ? recs[0].seq : 0;
  store.next = first;
  store.prevBefore = prevBefore === undefined ? null : prevBefore;
  store.prelude = [];
  if (first > 0) for (const r of prelude) if (r && PRELUDE_KINDS.has(r.kind) && r.seq < first) applyPrelude(store, r);
  applyRecords(store, recs);
  return store;
}

function applyPrelude(store, rec) {
  store.prelude.push(rec);
  step(store, rec);
  store.records.delete(rec.seq);
}

/** Whether records before the loaded ones remain on the daemon. */
export function hasEarlier(store) {
  return !!store && store.prevBefore !== null && store.prevBefore !== undefined;
}

/** The next request for earlier records, {before, limit}, or null. */
export function earlierRequest(store) {
  return hasEarlier(store) ? { before: store.prevBefore, limit: TAIL_LIMIT } : null;
}

/**
 * Put earlier records (oldest first) in front of the store's. The blocks are built again from the first record, in place (the store
 * object stays); a streaming reply and each block's open/closed state are kept. Returns how many blocks were added in front.
 */
export function prependRecords(store, older, prevBefore) {
  const all = new Map();
  for (const r of older || []) if (r && Number.isInteger(r.seq)) all.set(r.seq, r);
  for (const [seq, r] of store.records) all.set(seq, r);
  const sorted = [...all.values()].sort((a, b) => a.seq - b.seq);
  const fresh = createRecordStore(store.session);
  fresh.next = sorted.length ? sorted[0].seq : store.next;
  fresh.prelude = [];
  if (fresh.next > 0) for (const r of store.prelude || []) if (r.seq < fresh.next) applyPrelude(fresh, r);
  applyRecords(fresh, sorted);
  for (const r of store.ahead.values()) applyRecord(fresh, r);
  const ui = new Map();
  for (const b of store.blocks) if (b.ui && Object.keys(b.ui).length && Number.isInteger(b.seq)) ui.set(b.kind + ":" + b.seq, b.ui);
  for (const b of fresh.blocks) { const u = ui.get(b.kind + ":" + b.seq); if (u) b.ui = u; }
  const added = fresh.blocks.length - store.blocks.length;
  const pending = store.pending;
  const rev = store.pendingRev;
  Object.assign(store, fresh);
  store.pending = pending;
  store.pendingRev = rev + 1;
  store.prevBefore = prevBefore === undefined ? null : prevBefore;
  return Math.max(0, added);
}

/** One line on the Overview of a session whose earlier records are not loaded. */
export const OVERVIEW_PARTIAL_WORDS = "This summary reads the records loaded so far. Load earlier records in the Chat tab to include the rest.";

/** The words under Find when records before the loaded ones are not searched yet. */
export const FIND_EARLIER_WORDS = "Earlier records are not loaded. Press Enter to load and search them.";

/** Where blob lines are read from. */
export function linesUrl(blob, start, end) {
  return `/api/blobs/${encodeURIComponent(blob)}/lines?start=${start}&end=${end}`;
}
export function recordsUrl(session, after, limit, before = null) {
  let u = `/api/sessions/${encodeURIComponent(session)}/records`;
  const q = [];
  if (after !== null && after !== undefined) q.push(`after=${after}`);
  if (before !== null && before !== undefined) q.push(`before=${before}`);
  if (limit) q.push(`limit=${limit}`);
  return q.length ? `${u}?${q.join("&")}` : u;
}

// ---------------------------------------------------------------------------------------------
// Sessions

export function createSessionStore() {
  // `rev` counts changes made by events; `changed` maps an id to the rev of its last event, so a snapshot that was
  // requested before an event cannot overwrite what the event said.
  return { byId: new Map(), rev: 0, changed: new Map() };
}

/**
 * applySessionList(store, list, {sinceRev}): a session-list snapshot. Without `sinceRev` it replaces everything. With
 * `sinceRev` (store.rev read when the request was sent) it keeps every session an event changed after that point,
 * including one the snapshot does not list yet, and takes the snapshot for the rest. Returns the store.
 */
export function applySessionList(store, list, opts = {}) {
  const since = opts && Number.isFinite(opts.sinceRev) ? opts.sinceRev : null;
  const next = new Map((list || []).map((s) => [s.id, s]));
  if (since !== null && store.changed) {
    for (const [id, rev] of store.changed) {
      if (rev > since && store.byId.has(id)) next.set(id, store.byId.get(id));
    }
    for (const [id, rev] of [...store.changed]) if (rev <= since) store.changed.delete(id);
  } else if (store.changed) store.changed.clear();
  store.byId = next;
  return store;
}

function sessionChanged(store, id) {
  store.rev = (store.rev || 0) + 1;
  if (!store.changed) store.changed = new Map();
  store.changed.set(id, store.rev);
}

/** A `session` event: {type:"session", info}. */
export function applySessionEvent(store, info) {
  if (info && info.id) {
    store.byId.set(info.id, info);
    sessionChanged(store, info.id);
  }
  return store;
}

/** A `status` event. Returns false when the session is not known (the caller refetches the list). */
export function applyStatus(store, id, status) {
  const s = store.byId.get(id);
  if (!s) return false;
  store.byId.set(id, { ...s, status });
  sessionChanged(store, id);
  return true;
}

/**
 * Rows for the left column: root sessions newest first, each followed by its descendants in
 * creation order, with a depth. A session whose parent is not in the store is a root.
 */
function sessionRows(store, { showArchived = false } = {}) {
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

/** The question the Stop confirmation asks. Only a root can be resumed; an agent just ends. */
export function stopQuestion(info) {
  const name = info.title || info.id;
  return info.parent
    ? `Stop ${name}? It and its tracked jobs stop. An agent cannot be resumed; its lead can start a new one.`
    : `Stop ${name}? It, its agents and their tracked jobs stop. It can be resumed.`;
}

/** The question the Archive confirmation asks when a mission still has open inbox items; null when none. */
export function archiveQuestion(info, openInboxCount = 0) {
  if (!(openInboxCount > 0)) return null;
  const name = (info && (info.title || info.id)) || "this mission";
  return `Archive ${name}? It still has ${count(openInboxCount, "open inbox item")}, which will be dismissed.`;
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
/** What waits, in the sidebar's noun: "Approval waiting". */
export function waitingNoun(kind) {
  return `${WAITING_NOUN[kind] || "Request"} waiting`;
}
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

const SESSION_SECTIONS = new Set(["chat", "overview", "agents", "evidence"]);
/** Hash of a session view: `#/s/<id>/<chat|overview|agents|evidence>`; "record" (the old name of chat) and unknown sections give chat. */
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

/**
 * mergeInboxList(list, touched, since): a `/api/inbox` snapshot with what inbox records changed after it was asked for put back.
 * `touched` maps item id -> {rev, entry} (entry null when the record resolved it); a change newer than `since` wins over the snapshot,
 * so an item resolved while the request was out stays gone and one opened meanwhile stays.
 */
export function mergeInboxList(list, touched, since) {
  const out = new Map((list || []).map((e) => [e.item.item_id, e]));
  for (const [id, t] of touched || []) {
    if (!(t.rev > since)) continue;
    if (t.entry) out.set(id, t.entry); else out.delete(id);
  }
  return [...out.values()];
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

export function pageTitle({ open, blocking }) {
  if (!open) return "loom";
  return blocking ? `(${blocking}) needs you · loom` : `(${open}) loom`;
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

/**
 * What an inbox card shows as its resolution. The record's `inbox_resolved` says only that the item closed with an empty answer, so an
 * approved scope request would read as dismissed. The operator's own receipt (this tab) carries the approved hosts; failing that, an
 * empty-answer scope request whose every host is among the mission's granted hosts is read as approved. `granted` is null when unknown.
 */
export function cardResolution(item, resolved, receipt, granted) {
  if (!resolved) return receipt || null;
  if (receipt && receipt.approved) return { ...resolved, approved: receipt.approved };
  const hosts = scopeRequestHosts(item);
  if (hosts && resolved.answer === "" && Array.isArray(granted)) {
    const have = new Set(granted.map((h) => String(h).toLowerCase()));
    if (hosts.every((h) => have.has(String(h).toLowerCase()))) return { ...resolved, approved: hosts };
  }
  return resolved;
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

/**
 * The budget as the daemon counts it (session.rs): own model steps and the active clock since the budget was last granted. A
 * budget is granted at the start, and again by the turn_start (trigger user, inbox_answer or resume) after a budget_exhausted
 * turn. Time is the sum of the budget_clock intervals; a log with none keeps the wall clock from the grant.
 */
function trackBudget(store, rec) {
  const b = store.budgetUse || (store.budgetUse = { steps: 0, fromMs: null, startMs: null, accrued: 0, open: null, clock: false, lastEnd: null });
  const ts = Number.isFinite(rec.ts_ms) ? rec.ts_ms : null;
  switch (rec.kind) {
    case "session_start":
      if (ts !== null) b.startMs = ts;
      break;
    case "model_request":
      if (!rec.purpose || rec.purpose === "step") b.steps++;
      break;
    case "budget_clock":
      if (ts === null) break;
      if (!b.clock) { b.clock = true; b.accrued = Math.max(0, ts - (b.fromMs ?? b.startMs ?? ts)); }
      if (b.open !== null) b.accrued += Math.max(0, ts - b.open);
      b.open = rec.running ? ts : null;
      break;
    case "turn_start":
      if (["user", "inbox_answer", "resume"].includes(rec.trigger) && b.lastEnd === "budget_exhausted") {
        b.steps = 0; b.fromMs = ts; b.accrued = 0; b.open = null;
      }
      break;
    case "turn_end":
      b.lastEnd = rec.reason;
      if (b.open !== null && ts !== null) { b.accrued += Math.max(0, ts - b.open); b.open = null; }
      break;
    default:
      break;
  }
}

/** budgetUsed(store, now): {steps, minutes|null} counted since the budget was granted, as the daemon counts them. */
export function budgetUsed(store, now) {
  const b = store && store.budgetUse;
  if (!b) return { steps: 0, minutes: null };
  let ms = null;
  if (b.clock) ms = b.accrued + (b.open !== null && Number.isFinite(now) ? Math.max(0, now - b.open) : 0);
  else if (Number.isFinite(now) && (b.fromMs ?? b.startMs) !== null) ms = Math.max(0, now - (b.fromMs ?? b.startMs));
  return { steps: b.steps, minutes: ms === null ? null : Math.floor(ms / 60000) };
}

function step(store, rec) {
  store.records.set(rec.seq, rec);
  trackBudget(store, rec);
  switch (rec.kind) {
    case "user_message":
      push(store, { ...base(rec), kind: "user", text: rec.text || "", images: imageList(rec.images) });
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
        images: imageList(rec.images),
      };
      // A call sent under another harness's name (`Read`, `shell`, …) runs as a loom tool; the result names that
      // tool. The row shows the tool that ran and keeps the sent name for its tooltip (TOOL-SHAPES §3).
      if (rec.name && b.name && rec.name !== b.name) {
        b.ran = rec.name;
        if (b.args && typeof b.args === "object") b.argsLine = argsLine(rec.name, b.args);
      }
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
    case "compaction":
      push(store, { ...base(rec), ...compactionBlock(rec, store.lastStep) });
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
        const profile = oneLine((m && m.profile) || "?", 80);
        const model = oneLine((m && m.model) || "?", 80);
        return model === profile ? `${profile}${win ? " (" + win.slice(2) + ")" : ""}` : `${profile} (${model}${win})`;
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
      push(store, { ...base(rec), kind: "line", sub: "interrupted", tone: "warn", reason: String(rec.reason || ""), text: `interrupted: ${oneLine(rec.reason, 300)}` });
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
      if ((!rec.purpose || rec.purpose === "step") && Number.isInteger(rec.step)) store.lastStep = rec.step;
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

/**
 * What a key press in the composer does. Ctrl/Cmd+Enter (`mod`) sends everywhere. A plain Enter sends with a fine pointer and
 * adds a line with a coarse one (a phone's Return key), where Send is the button.
 */
export function composerAction({ key, shiftKey, isComposing, text, coarse = false, mod = false, alt = false, running = false }) {
  if (key !== "Enter" || isComposing) return "none";
  if (!mod && (shiftKey || coarse)) return "none";
  if (!String(text ?? "").trim()) return "ignore";
  // Alt+Enter holds the message until the lead's turn ends; with nothing running there is no turn to wait for.
  return alt && running ? "queue" : "send";
}

/**
 * The help under the message box: {keys, note}. `keys` names the keys and is empty on a coarse pointer, which has no
 * Enter-to-send to teach; `note` says what a message does and is kept whole. While a turn runs the keys also name the queue key
 * (`mac` says ⌥ for Alt).
 */
export function composerHelp({ coarse = false, paused = false, running = false, lead = false, mac = false } = {}) {
  const note = [];
  if (paused) note.push("A message does not answer the open question.");
  if (running) note.push(lead ? "It reaches the lead between steps." : "It is read between steps.");
  const keys = running ? `Enter sends now · ${mac ? "⌥Enter" : "Alt+Enter"} queues it for after this turn · Shift+Enter adds a line.` : "Enter sends · Shift+Enter adds a line.";
  return { keys: coarse ? "" : keys, note: note.join(" ") };
}

/**
 * The one-line caption on the phone composer: {text, label}. `line` is progressLine() output and `stats` sessionStats(); the
 * text is "Plan 1 of 3 · context 9% · cache 98%" (ellipsized by the page), the label the full sentence for its button.
 */
export function composerCaption({ line, stats, queued = 0 } = {}) {
  const parts = [];
  const spoken = [];
  if (queued > 0) { parts.push(queuedLabel(queued)); spoken.push(queuedLabel(queued)); }
  const plan = line && line.parts.find((p) => p.key === "plan");
  if (plan) { parts.push(plan.text.replace(/ done$/, "")); spoken.push(plan.text); }
  const context = stats && stats.context;
  if (context) { parts.push(context.replace(/ of \S+$/, "")); spoken.push(context); }
  if (stats && stats.cache) { parts.push(stats.cache); spoken.push(stats.cache); }
  return { text: parts.join(" · ") || "Session details", label: "Session details" + (spoken.length ? ": " + spoken.join(", ") : "") };
}

/** The label of the Missions button on a phone: how many missions need the operator, said in words. */
export function missionsLabel(blocking) {
  const n = Number(blocking) || 0;
  return n > 0 ? `Missions, ${n} ${n === 1 ? "needs" : "need"} you` : "Missions";
}

/**
 * Which button the chat shows over its foot: "needs" while the session's own question is off screen (it says what waits and
 * takes the operator to it), "latest" while the chat is scrolled away from the end, else "hidden". It is hidden while that
 * question is on screen (`cardShown`), so it never covers an answer.
 */
export function jumpMode({ section, follow, needsOffscreen, cardShown = false }) {
  if (section !== "chat" || cardShown) return "hidden";
  if (needsOffscreen) return "needs";
  return follow ? "hidden" : "latest";
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
// Copying: what each copy button copies, and when copy on select copies. Text only; the page does the clipboard.

/** The most a button fetches from a stored output to copy it (2 MiB); beyond it the viewer's Copy lines is the way. */
export const COPY_FULL_CAP = 2 * 1024 * 1024;
export const COPY_FULL_BIG = "This stored output is over 2 MiB, too much to copy in one go. Open the full output and use Copy lines for the part you need.";

/** Where a whole stored output is read from. */
export function rawUrl(blob) {
  return `/api/blobs/${encodeURIComponent(blob)}/raw`;
}

// ---- Images (docs/CONTRACTS-2026-11-23.md D7) and queued messages (E5)

/** The images of a record, as the page uses them: only well-formed refs whose blob is a hex id (the route's key). */
export function imageList(images) {
  if (!Array.isArray(images)) return [];
  return images.filter((i) => i && typeof i === "object" && /^[0-9a-f]{8,128}$/i.test(String(i.blob || ""))).map((i) => ({
    blob: String(i.blob).toLowerCase(), mime: typeof i.mime === "string" ? i.mime : "", bytes: Number(i.bytes) || 0,
    width: Number(i.width) || 0, height: Number(i.height) || 0, name: typeof i.name === "string" && i.name ? i.name : "",
  }));
}

/** Where an image's bytes are read from: the daemon's images route, nowhere else. Null for anything but a hex blob id. */
export function imageUrl(blob) {
  return /^[0-9a-f]{8,128}$/i.test(String(blob || "")) ? `/api/images/${String(blob).toLowerCase()}` : null;
}

/** A thumbnail's size: the image scaled to fit `max` x `max`, never enlarged; unknown sizes give a square placeholder. */
export function thumbSize(width, height, max = 240) {
  const w = Number(width), h = Number(height);
  if (!(w > 0) || !(h > 0)) return { width: max, height: max };
  const k = Math.min(1, max / w, max / h);
  return { width: Math.max(1, Math.round(w * k)), height: Math.max(1, Math.round(h * k)) };
}

/** The words that name an image: its alt text and its facts line. `tool` is the tool of a result's row. */
export function imageAlt(img, tool) {
  return img.name || (tool ? `image from ${tool}` : "attached image");
}
export function imageFacts(img) {
  const dims = img.width > 0 && img.height > 0 ? `${img.width}×${img.height}` : "";
  return [dims, img.bytes > 0 ? byteSize(img.bytes) : "", img.mime].filter(Boolean).join(" · ");
}

/** The path of an image's file: the attachment list entry of the same name, else the call's path argument; null if unknown. */
export function imagePath(img, { files = [], args = null } = {}) {
  const hit = img.name ? files.find((f) => f.name === img.name) : files.length === 1 ? files[0] : null;
  if (hit) return hit.path;
  return toolPathArg(args);
}

/** How the head of a collapsed tool row says it carries images: "1 image" / "2 images". */
export function imageCountLabel(n) {
  return `${n} ${n === 1 ? "image" : "images"}`;
}

const IMAGE_EXT = /\.(png|jpe?g|gif|webp)$/i;
/** Whether a file the operator attached is an image (by its type, else its name). */
export function isImageFile(file) {
  if (!file) return false;
  if (typeof file.type === "string" && file.type) return /^image\/(png|jpeg|gif|webp)$/.test(file.type);
  return IMAGE_EXT.test(String(file.name || ""));
}

/** The vision flag of the session's profile: true, false, or null when the profile list does not say. */
export function modelVision(models, current) {
  const m = (Array.isArray(models) ? models : []).find((x) => x && current && x.profile === current.profile);
  return m && typeof m.vision === "boolean" ? m.vision : null;
}
export const NO_VISION_NOTE = "This model does not take images; it gets the file path.";

/** "1 queued" / "3 queued". */
export function queuedLabel(n) {
  return `${Number(n) || 0} queued`;
}

/** A queued message in one line for the list: spaces collapsed, cut at `max` with an ellipsis. */
export function queuedPreview(text, max = 140) {
  const one = String(text ?? "").replace(/\s+/g, " ").trim();
  return one.length > max ? one.slice(0, max - 1).trimEnd() + "…" : one;
}

/** The queue as the page keeps it: oldest first, only well-formed entries. */
export function queuedList(items) {
  return (Array.isArray(items) ? items : []).filter((q) => q && typeof q.id === "string")
    .map((q) => ({ id: q.id, text: String(q.text ?? ""), attachments: Array.isArray(q.attachments) ? q.attachments : [], created_ms: Number(q.created_ms) || 0 }))
    .sort((a, b) => a.created_ms - b.created_ms);
}

/** The route of one queued message (no id: the list); `action` "send" sends it now. */
export function queuedUrl(session, qid, action) {
  const base = `/api/sessions/${encodeURIComponent(session)}/queued`;
  return qid ? `${base}/${encodeURIComponent(qid)}${action ? "/" + action : ""}` : base;
}

/** What the send button's menu offers while a turn runs. The plain button is the first. */
export const SEND_CHOICES = [{ when: "now", label: "Send now" }, { when: "after_turn", label: "Queue for after this turn" }];

const copyText = (value) => (typeof value === "string" && value !== "" ? value : null);

/** "Copy reply": the exact raw text of a model reply, the same text the raw response shows. Null when it has none. */
export function replyCopyText(block) {
  return block && block.kind === "response" ? copyText(block.text) : null;
}
/** "Copy message": an operator or agent message as it was written. */
export function messageCopyText(block) {
  return block && block.kind === "user" && typeof block.text === "string" ? copyText(splitAttachments(block.text).text) : null;
}

const ATTACH_HEAD = "Attached files (saved read-only; read them with `read`):";
const ATTACH_ITEM = /^- (.+) \(([^()]*?), ([^(),]*)\)$/;
/**
 * The attachment block the runtime appends to an operator message (docs/UPLOADS.md), taken apart:
 * {text, files:[{path, name, size, mime}], inline}. `text` is what the operator wrote (above the block); `size` is the words
 * the block gives ("12.1 KiB"); `inline` is the text after the list (the inline copies), "" when there is none. A text with
 * no such block comes back whole, with no files.
 */
export function splitAttachments(text) {
  const whole = { text: String(text ?? ""), files: [], inline: "" };
  const src = whole.text;
  let from = 0;
  for (;;) {
    const at = src.indexOf(ATTACH_HEAD + "\n", from);
    if (at < 0) return whole;
    from = at + 1;
    if (at !== 0 && src[at - 1] !== "\n") continue;
    const lines = src.slice(at + ATTACH_HEAD.length + 1).split("\n");
    const files = [];
    let i = 0;
    for (; i < lines.length; i++) {
      const m = ATTACH_ITEM.exec(lines[i]);
      if (!m) break;
      files.push({ path: m[1], name: m[1].split("/").filter(Boolean).pop() || m[1], size: m[2], mime: m[3] });
    }
    if (!files.length) continue;
    return { text: src.slice(0, at).replace(/\s+$/, ""), files, inline: lines.slice(i).join("\n").trim() };
  }
}
/** "Copy reasoning": the reasoning of a reply, as recorded. */
export function reasoningCopyText(block) {
  return block && block.kind === "response" ? copyText(block.reasoning) : null;
}
/** "Copy code": one fenced block of a reply (a `pre` of proseTree), without its fence lines. */
export function codeCopyText(codeBlock) {
  return codeBlock && codeBlock.type === "pre" ? copyText(codeBlock.text) : null;
}

/**
 * "Copy command" of a tool call: the command for bash, the path for the file tools, otherwise the arguments as pretty JSON.
 * Returns {text, what} (`what` names it for the confirmation) or null when the call has no arguments.
 */
export function toolCommandCopy(block) {
  if (!block || block.args === undefined || block.args === null) return null;
  const args = block.args;
  if (typeof args === "string") return args === "" ? null : { text: args, what: "Arguments" };
  if (typeof args === "object" && !Array.isArray(args)) {
    if (block.name === "bash" && typeof args.command === "string" && args.command !== "") return { text: args.command, what: "Command" };
    if (FILE_TOOLS.has(block.name)) {
      const path = toolPathArg(args);
      if (path !== null) return { text: path, what: "Path" };
    }
  }
  let json;
  try { json = JSON.stringify(args, null, 2); } catch { json = String(args); }
  return copyText(json) === null ? null : { text: json, what: "Arguments" };
}

/** "Copy output": the output the row records (what the model was shown), all of it and not only the folded lines. */
export function toolOutputCopy(block) {
  return block && block.result ? copyText(block.result.text) : null;
}

/**
 * "Copy full output…": null when the output was not cut or has no stored copy; else {blob, bytes, tooBig}. `bytes` is the stored
 * size when the record says it, and `tooBig` is true when that already exceeds the cap (nothing is fetched then).
 */
export function fullOutputPlan(block) {
  const result = block && block.result;
  if (!result) return null;
  const shown = shownOfTotal(result);
  if (!shown.cut || !shown.blob) return null;
  const bytes = !shown.ofBlob && result.output && Number.isFinite(result.output.bytes) ? result.output.bytes : null;
  return { blob: shown.blob, bytes, tooBig: bytes !== null && bytes > COPY_FULL_CAP };
}

/** "Copy quote" of an evidence card. */
export function quoteCopyText(evidence) {
  return evidence ? copyText(evidence.quote) : null;
}
/** "Copy text" of an inbox card. */
export function inboxCopyText(item) {
  return item ? copyText(item.text) : null;
}

/**
 * "Copy lines" of the stored-output or file viewer. `viewer` has `first` (the number of the first loaded line) and `lines` (the
 * loaded lines' text). `selected` is the {from, to} line numbers the operator's selection touches, or null. Whole lines are
 * copied, joined by newlines, without line numbers. Returns {text, from, to, count, selected} or null when nothing is loaded.
 */
export function viewerLinesCopy(viewer, selected) {
  const lines = (viewer && viewer.lines) || [];
  if (!lines.length) return null;
  const first = viewer.first;
  const last = first + lines.length - 1;
  let from = first, to = last, chosen = false;
  if (selected && Number.isFinite(selected.from) && Number.isFinite(selected.to)) {
    from = Math.max(first, Math.min(selected.from, selected.to));
    to = Math.min(last, Math.max(selected.from, selected.to));
    chosen = from <= to;
    if (!chosen) { from = first; to = last; }
  }
  const text = lines.slice(from - first, to - first + 1).join("\n");
  return { text, from, to, count: to - from + 1, selected: chosen };
}

/**
 * The rows a selection touches, trimmed to the rows it really takes text from. `startAt` and `endAt` say where the two
 * boundaries lie in their rows: "lead" (in the number or before the text), "text" or "tail" (after the text, in the newline).
 * A selection that ends at the lead of a later row does not take that row; one that starts in the tail of an earlier row
 * does not take that row (a triple-click, or a drag from the blank space right of a line).
 */
export function viewerSelectionEdges({ from, to, startAt, endAt }) {
  if (!(from < to)) return { from, to };
  if (startAt === "tail") from += 1;
  if (endAt === "lead" && to > from) to -= 1;
  return { from, to };
}

/** What the viewer says after "Copy lines". */
export function viewerLinesWords(copy) {
  const range = sourceRangeWords(copy.from, copy.to);
  return copy.selected ? `Copied the selected lines: ${range}.` : `Copied the loaded lines: ${range}.`;
}

/** "Copied 1 character" / "Copied 1,204 characters". */
export function copiedChars(n) {
  return `Copied ${num(n)} ${n === 1 ? "character" : "characters"}`;
}

/** What is said when copying finished: `how` is "clipboard" or "command" (done), "selected" (left selected) or "none". */
export function copyWords(what, how, mac = false) {
  const keys = mac ? "Cmd+C" : "Ctrl+C";
  if (how === "clipboard" || how === "command") return `${what} copied`;
  if (how === "selected") return `${what} selected; press ${keys} to copy it`;
  return `Could not copy ${what.toLowerCase()}; this browser did not allow it`;
}

/**
 * Whether a selection should be copied now, with copy on select. Returns "copy" or the reason it is not copied:
 * "off" (the preference), "typing" (a field is focused: never copy while composing or answering), "empty" (nothing, or only
 * blanks, is selected), "outside" (the selection is not wholly inside the transcript or a viewer), "same" (this very
 * selection was copied already).
 */
export function copyOnSelectDecision({ enabled, text, scoped, typing, same }) {
  if (!enabled) return "off";
  if (typing) return "typing";
  if (typeof text !== "string" || text.trim() === "") return "empty";
  if (!scoped) return "outside";
  if (same) return "same";
  return "copy";
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
 *   ledgerPending a ledger load is in flight (optional; stops a repeated load_ledger)
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
      // The open session's ledger is not held yet (the page opened it before it knew the session): load it now.
      if (ev.info && ev.info.id === ctx.openId && ev.info.mission && ctx.ledgerMission !== ev.info.mission && !ctx.ledgerPending) {
        out.push({ fx: "load_ledger", mission: ev.info.mission });
      }
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
        if (r.kind === "turn_end" || r.kind === "reweave" || r.kind === "compaction") out.push({ fx: "refetch_window" });
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
      out.push({ fx: "refetch_sessions" }, { fx: "refetch_inbox" }, { fx: "refetch_status" });
      if (ctx.ledgerMission) out.push({ fx: "refetch_ledger", mission: ctx.ledgerMission });
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

/** The most earlier missions one new mission may name (the daemon's `prior::MAX_PRIOR`). */
export const MAX_PRIOR = 8;

/**
 * Validate the form; returns {body} for POST /api/sessions or {error}.
 * `form.prior` (optional text): earlier missions for the new one to recall. Split on whitespace and commas;
 * each must be a mission id as the daemon names them (1 to 128 of A-Z a-z 0-9 _ . -, not starting with `.`),
 * else `"{word}" is not a mission id; mission ids look like m-….`; repeats dropped (first kept); more than 8 →
 * `Name at most 8 earlier missions to recall.` A non-empty list is sent as `body.prior`, in order; none sends no
 * `prior` key.
 */
export function buildNewSession(form) {
  const workspace = String(form.workspace || "").trim();
  const message = String(form.message || "").trim();
  if (!workspace) return { error: "Workspace is required." };
  if (!message) return { error: "A first message is required." };
  const role = form.role || "lead";
  const body = { workspace, message, role, unattended: !!form.unattended };
  if (form.model) body.model = form.model;
  // Only a lead starts agents: the choice for every role goes with it, before its first agent.
  if (form.agentModel && role === "lead") body.role_models = { "*": form.agentModel };
  const title = String(form.title || "").trim();
  if (title) body.title = title;
  const prior = [];
  for (const word of String(form.prior || "").split(/[\s,]+/)) {
    if (!word) continue;
    if (!/^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/.test(word)) {
      return { error: `"${oneLine(word, 40)}" is not a mission id; mission ids look like m-….` };
    }
    if (!prior.includes(word)) prior.push(word);
  }
  if (prior.length > MAX_PRIOR) return { error: `Name at most ${MAX_PRIOR} earlier missions to recall.` };
  if (prior.length) body.prior = prior;
  // Only after the operator chose to create a folder that does not exist (the picker's New folder, or the confirmation).
  if (form.createWorkspace) body.create_workspace = true;
  return { body };
}

// ---------------------------------------------------------------------------------------------
// Models of a mission (the Models tab)

/** What the pack chooses for a role's agents when the operator chose nothing. */
export function packChoiceWords(r) {
  let words;
  if (r.alloy_models && r.alloy_models.length) words = "rotates " + r.alloy_models.join(", ");
  else if (r.pack_model) words = r.pack_model;
  else words = "the lead's";
  if (r.escalation_model) words += `, ${r.escalation_model} after a failed agent`;
  return words;
}

/** The label of a role's "no choice of its own" option: what applies then. */
export function roleDefaultLabel(r, anyRole) {
  if (anyRole && !r.verifier) return `Every role's choice (${anyRole})`;
  return `As the pack says (${packChoiceWords(r)})`;
}

/** The body of POST /api/sessions/{id}/role-model for a select's value ("" clears; clearing moves nobody). */
export function roleModelBody(role, value, now) {
  const profile = value ? String(value) : null;
  return { role, profile, now: !!(now && profile) };
}

/** One line about a role's agents that have not ended. */
export function runningAgentsWords(agents) {
  if (!agents || !agents.length) return "No agent of this role is running.";
  return "Running: " + agents.map((a) => `${a.session} on ${a.profile}${a.forked ? " (forked)" : ""}`).join(", ");
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

/**
 * How a finished tool call ended, by the daemon's ToolStatus (never merged into one "failed"):
 * "ok" | "exit" (the tool ran and exited non-zero) | "failed" (the tool ran and reported failure without an exit code) |
 * "denied" (refused by policy) | "invalid" (arguments failed validation, nothing ran) | "timeout" | "interrupted" (cut off,
 * effects unknown). `exit` is the code for "exit".
 */
export function toolOutcome(result) {
  if (!result) return { kind: "ok", exit: null };
  const code = result.meta && Number.isInteger(result.meta.exit_code) ? result.meta.exit_code : null;
  switch (result.status) {
    case "ok": return { kind: "ok", exit: code };
    case "error": return code !== null && code !== 0 ? { kind: "exit", exit: code } : { kind: "failed", exit: code };
    case "denied": return { kind: "denied", exit: code };
    case "invalid": return { kind: "invalid", exit: code };
    case "timeout": return { kind: "timeout", exit: code };
    case "interrupted": return { kind: "interrupted", exit: code };
    default: return { kind: "failed", exit: code };
  }
}

/**
 * Whether the model saw only part of a finished call's output: {words} (the shownOfTotal sentence) or null. A view of a stored
 * output the model asked for (`of_blob`) is a request, not a cut, so it is not partial.
 */
export function partialView(result) {
  if (!result) return null;
  const v = result.shown || shownOfTotal(result);
  if (v.ofBlob || v.complete) return null;
  const part = v.cut || (v.shown !== null && v.total !== null && v.shown < v.total);
  return part && v.words ? { words: v.words, shown: v.shown, total: v.total, cut: !!v.cut } : null;
}

// ---- repeated calls and paging of a group's rows

/** A run of this many identical consecutive calls is collapsed into one row; fewer stay as they are. */
export const RUN_MIN = 3;
/** A run this long marks its group with a loop warning. */
export const LOOP_MIN = 10;
/** Rows an open group (or an open run) renders before "Show more". */
export const GROUP_PAGE = 50;

function canonicalJson(v) {
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (v && typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
  const j = JSON.stringify(v);
  return j === undefined ? "null" : j;
}

const sigCache = new WeakMap();
/** What makes two calls "the same call": the tool name and the arguments' canonical JSON (the result may differ). Null for a call whose arguments are unknown. */
export function callSignature(b) {
  if (!b || b.kind !== "tool") return null;
  const hit = sigCache.get(b);
  if (hit && hit.args === b.args && hit.name === b.name) return hit.sig;
  let sig = null;
  if (b.args !== undefined && b.args !== null) sig = (b.name || "") + "\u0000" + canonicalJson(b.args);
  else if (b.argsInvalid && typeof b.rawArgs === "string") sig = (b.name || "") + "\u0000raw:" + b.rawArgs;
  sigCache.set(b, { args: b.args, name: b.name, sig });
  return sig;
}

// Between two calls of a run only the steps' own text-less replies and request-detail lines may stand; anything that says something breaks it.
const isPassive = (b) => !!b && (b.detail || (isTextless(b) && !isWarningBlock(b)));

/**
 * The rows of a group's `blocks`: {type:"block", block} for a block shown as itself, and {type:"run", key, name, count, entries,
 * first, last} for RUN_MIN or more consecutive calls of one tool with identical arguments. `entries` is [{call, before}] where
 * `before` are the passive blocks (text-less replies, detail lines) that stood in front of that call.
 */
export function groupRows(blocks) {
  const rows = [];
  const list = blocks || [];
  let i = 0;
  while (i < list.length) {
    const b = list[i];
    const sig = callSignature(b);
    if (sig === null) { rows.push({ type: "block", block: b }); i++; continue; }
    const entries = [{ call: b, before: [] }];
    let j = i + 1, pending = [], end = i;
    while (j < list.length) {
      const c = list[j];
      if (c.kind === "tool") {
        if (callSignature(c) !== sig) break;
        entries.push({ call: c, before: pending });
        pending = [];
        end = j;
      } else if (isPassive(c)) pending.push(c);
      else break;
      j++;
    }
    if (entries.length >= RUN_MIN) {
      rows.push({ type: "run", key: "run" + b.id, name: b.ran || b.name, count: entries.length, entries, first: b, last: entries[entries.length - 1].call });
      i = end + 1;
    } else {
      rows.push({ type: "block", block: b });
      i++;
    }
  }
  return rows;
}

/** The longest run among a group's blocks when it is LOOP_MIN or more, else 0. */
export function longestLoop(blocks) {
  let best = 0;
  for (const r of groupRows(blocks)) if (r.type === "run" && r.count > best) best = r.count;
  return best >= LOOP_MIN ? best : 0;
}

/** The rows of a group item (`it.shown`), computed once per shown list. */
export function rowsOf(it) {
  if (it._rowsFor !== it.shown) { it._rows = groupRows(it.shown); it._rowsFor = it.shown; }
  return it._rows;
}

/** The first `pages` pages of `list`: {visible, hidden, more} where `more` is how many the next page adds. */
export function pageOf(list, pages = 1, size = GROUP_PAGE) {
  const n = Math.max(1, pages) * size;
  const hidden = Math.max(0, list.length - n);
  return { visible: hidden ? list.slice(0, n) : list, hidden, more: Math.min(size, hidden) };
}

/** "Show 50 more (120 hidden)". */
export function showMoreLabel(page) {
  return `Show ${num(page.more)} more (${num(page.hidden)} hidden)`;
}

/**
 * Where block `id` sits in the rows of group `it`: {row, runKey, entry, groupPages, runPages}, or null. `groupPages` is the page
 * count of the group that shows its row, and `runPages` that of the run (0 for a row of its own) that shows the call.
 */
export function locateInGroup(it, id, size = GROUP_PAGE) {
  const rows = rowsOf(it);
  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    if (row.type === "block") {
      if (row.block.id === id) return { row: r, runKey: null, entry: null, groupPages: Math.floor(r / size) + 1, runPages: 0 };
    } else {
      for (let e = 0; e < row.entries.length; e++) {
        const en = row.entries[e];
        if (en.call.id === id || en.before.some((x) => x.id === id)) return { row: r, runKey: row.key, entry: e, groupPages: Math.floor(r / size) + 1, runPages: Math.floor(e / size) + 1 };
      }
    }
  }
  return null;
}

/**
 * How many member rows an item list renders: for each open group the rows of its visible pages plus its "Show more" button; an
 * open run adds its visible calls. `state` is {groupPages: Map, openRuns: Set, runPages: Map}.
 */
export function renderedRowCount(items, state = {}) {
  const gp = state.groupPages || new Map(), openRuns = state.openRuns || new Set(), rp = state.runPages || new Map();
  let total = 0;
  for (const it of items) {
    if (it.type !== "group" || !it.open) continue;
    const page = pageOf(rowsOf(it), gp.get(it.key) || 1);
    total += page.visible.length + (page.hidden ? 1 : 0);
    for (const row of page.visible) {
      if (row.type === "run" && openRuns.has(row.key)) {
        const inner = pageOf(row.entries, rp.get(row.key) || 1);
        total += inner.visible.length + (inner.hidden ? 1 : 0);
      }
    }
  }
  return total;
}

function makeGroup(blocks) {
  let toolCount = 0, exited = 0, failed = 0, denied = 0, invalid = 0, timedOut = 0, interrupted = 0, partial = 0;
  let missing = 0, warnings = 0, records = 0, running = false;
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
    else if (b.result) {
      switch (toolOutcome(b.result).kind) {
        case "exit": exited++; break;
        case "failed": failed++; break;
        case "denied": denied++; break;
        case "invalid": invalid++; break;
        case "timeout": timedOut++; break;
        case "interrupted": interrupted++; break;
        default: break;
      }
      if (partialView(b.result)) partial++;
    }
    if (b.result && Number.isFinite(b.result.ts) && b.result.ts > endTs) endTs = b.result.ts;
  }
  return { type: "group", key: groupKey(blocks[0]), blocks, shown: blocks, earlier: 0, records, toolCount, exited, failed, denied, invalid, timedOut, interrupted, partial, missing, warnings, running, startTs, endTs, open: false, last: false, loop: longestLoop(blocks) };
}

/**
 * The chat as a render list from `blocks` (a record store's blocks). Items, in order:
 *   {type:"block", block, last, model?, differs?}   a block shown as itself; for a model reply `model` is {profile, model}
 *                                                   serving it and `differs` says it is not the segment chip's model
 *   {type:"group", key, blocks, toolCount, failed, missing, running, startTs, endTs, open, last}
 *                                                   a maximal run of tool blocks, text-less replies and job/ledger/cache lines
 *   {type:"since", seq, count, straddles, text}   (opts.sinceSeq, the last seq seen on the previous visit) the divider "New since
 *                                                   your last visit · N records", before the first item with a newer record;
 *                                                   `straddles` when that item is a group that began before it
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
  if (Number.isInteger(opts.sinceSeq)) placeSince(items, blocks, opts.sinceSeq, details);
  return items;
}

/** The record seqs a block stands for: a tool block holds its call and its result. */
function blockSeqs(b) {
  if (b.kind === "tool") {
    const out = [];
    if (Number.isInteger(b.callSeq)) out.push(b.callSeq);
    if (b.result && Number.isInteger(b.result.seq)) out.push(b.result.seq);
    return out.length ? out : [b.seq];
  }
  return [b.seq];
}

const HIDDEN_RECORD_KINDS = new Set(["turn_start", "budget_clock", "model_request"]);

/**
 * recordsAfter(blocks, seq, lastSeq): how many records were recorded after `seq`. With `lastSeq` (the store's last seq, as lastSeq()
 * gives) every record counts, bookkeeping ones included; without it the blocks are counted (not request-detail lines; a tool block counts
 * its call and its result on their own). The number of "new" records for the divider and for Jump to latest.
 */
export function recordsAfter(blocks, seq, lastSeq) {
  if (!Number.isInteger(seq)) return 0;
  // Seqs are contiguous: when the last one is known the count is a subtraction, and it counts bookkeeping records too (O(1)).
  if (Number.isInteger(lastSeq)) return Math.max(0, lastSeq - seq);
  let n = 0;
  for (const b of blocks || []) {
    if (!b || b.detail) continue;
    for (const q of blockSeqs(b)) if (Number.isInteger(q) && q > seq) n++;
  }
  return n;
}

/**
 * visibleRecordsAfter(blocks, afterSeq, details = false): like recordsAfter, counts visible chat records recorded after `afterSeq`,
 * excluding hidden bookkeeping kinds (`turn_start`, `budget_clock`, `model_request`) and request-detail lines when `!details`.
 */
export function visibleRecordsAfter(blocks, afterSeq, details = false) {
  if (!blocks || afterSeq == null || !Number.isInteger(afterSeq)) return 0;
  let n = 0;
  for (const b of blocks) {
    if (!b) continue;
    if (!details && (b.detail || HIDDEN_RECORD_KINDS.has(b.kind))) continue;
    const seqs = blockSeqs(b);
    const ids = seqs.some(Number.isInteger) ? seqs : (Number.isInteger(b.id) ? [b.id] : []);
    for (const q of ids) if (Number.isInteger(q) && q > afterSeq) n++;
  }
  return n;
}

/** The label of the Jump button: "Jump to latest" or "Jump to latest · 12 new". */
export function jumpLabel(newCount) {
  return newCount > 0 ? `Jump to latest · ${num(newCount)} new` : "Jump to latest";
}

// Put the "since your last visit" item before the first item that holds a record after `sinceSeq`. Nothing is put when every
// item is new (a first sight has no watermark) or none is.
function placeSince(items, blocks, sinceSeq, details = false) {
  const newIn = (it) => {
    if (it.type === "block") return blockSeqs(it.block).some((q) => q > sinceSeq);
    if (it.type === "group") return it.blocks.some((b) => !b.detail && blockSeqs(b).some((q) => q > sinceSeq));
    if (it.type === "model") return it.seq > sinceSeq;
    return false;
  };
  const at = items.findIndex(newIn);
  const count = visibleRecordsAfter(blocks, sinceSeq, details);
  if (at <= 0 || !count) return;
  const first = items[at];
  const head = first.type === "group" ? first.blocks.find((b) => !b.detail) : null;
  const straddles = !!head && Math.min(...blockSeqs(head)) <= sinceSeq;
  items.splice(at, 0, { type: "since", seq: sinceSeq, count, straddles, text: `New since your last visit · ${count === 1 ? "1 record" : num(count) + " records"}` });
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

/** The header words of a work group: {text, head, spoken, duration, tools, exited, failed, denied, invalid, timedOut, interrupted, partial,
 *  missing, warnings, running} where text is "Worked for 4m · 12 calls · 2 exited non-zero · 1 denied by policy · 1 without a result ·
 *  running" (each non-ok ToolStatus counted on its own; the running group's duration runs to `now`). `spoken` is the
 *  accessible name: the same without the duration while the group runs, so a ticking clock is not read out every second. */
export function groupLabel(group, now) {
  const end = group.running && Number.isFinite(now) ? now : group.endTs;
  const ms = Math.max(0, (Number(end) || 0) - (Number(group.startTs) || 0));
  const duration = ms < 1000 ? "under 1s" : seconds(ms);
  const rest = [count(group.toolCount, "tool call")];
  if (group.exited) rest.push(`${group.exited} exited non-zero`);
  if (group.failed) rest.push(`${group.failed} failed`);
  if (group.denied) rest.push(`${group.denied} denied by policy`);
  if (group.invalid) rest.push(`${group.invalid} invalid`);
  if (group.timedOut) rest.push(`${group.timedOut} timed out`);
  if (group.interrupted) rest.push(`${group.interrupted} interrupted`);
  if (group.missing) rest.push(`${group.missing} without a result`);
  if (group.warnings) rest.push(count(group.warnings, "warning"));
  if (group.running) rest.push("running");
  // The header's visible words when the outcome counts are drawn as their own marks beside it: no count said twice.
  const head = [`Worked for ${duration}`, count(group.toolCount, "tool call"), ...(group.missing ? [`${group.missing} without a result`] : []), ...(group.running ? ["running"] : [])];
  return {
    text: [`Worked for ${duration}`, ...rest].join(" · "),
    head: head.join(" · "),
    spoken: [group.running ? "Work in progress" : `Worked for ${duration}`, ...rest].join(" · "),
    short: [`Worked ${duration}`, count(group.toolCount, "call"), ...(group.running ? ["running"] : [])].join(" · "),
    duration, tools: group.toolCount, failed: group.failed || 0, exited: group.exited || 0, denied: group.denied || 0, invalid: group.invalid || 0,
    timedOut: group.timedOut || 0, interrupted: group.interrupted || 0, partial: group.partial || 0, missing: group.missing, warnings: group.warnings || 0, running: group.running,
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
    if (it.type === "model" || it.type === "since") {
      let j = i + 1;
      while (items[j] && (items[j].type === "model" || items[j].type === "since")) j++;
      if (keeps(items[j])) out.push(it);
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

/** The look of each way a call can end: its capsule words are `text`, `tone` "ok" | "neutral" | "bad" | "warn" | "running", `icon` a
 *  template name with its own shape per outcome (check, exit, cross, lock, invalid, clock, interrupted, alert, dot). */
export const TOOL_OUTCOME_LOOK = {
  exit: { tone: "neutral", icon: "exit" },
  failed: { tone: "bad", icon: "cross" },
  denied: { tone: "warn", icon: "lock" },
  invalid: { tone: "neutral", icon: "invalid" },
  timeout: { tone: "warn", icon: "clock" },
  interrupted: { tone: "warn", icon: "interrupted" },
};
const TOOL_OUTCOME_WORDS = {
  exit: (o) => `The tool ran and exited with code ${o.exit}.`,
  failed: () => "The tool ran and reported failure.",
  denied: () => "Refused by policy (sandbox, scope or approval).",
  invalid: () => "The arguments failed validation or the tool does not exist; nothing ran.",
  timeout: () => "The call timed out.",
  interrupted: () => "Cut off; its effects are unknown.",
};

/** One tool row in a group: {icon, name, calledAs, label, argsLine, capsule, duration, state, outcome, words, partial}. `capsule` is {text, tone, icon}
 *  or null (see TOOL_OUTCOME_LOOK); `outcome` is toolOutcome().kind ("running" / "missing" while there is no result), `words` the
 *  sentence for its tooltip, `partial` {words, shown, total, cut} when the model saw only part of the output, else null. */
export function toolRow(block) {
  const r = block.result;
  let capsule = null;
  let outcome = block.state === "running" ? "running" : block.state === "missing" ? "missing" : "ok";
  let words = "";
  if (block.state === "running") capsule = { text: "running", tone: "running", icon: "dot" };
  else if (block.state === "missing") { capsule = { text: "no result", tone: "warn", icon: "alert" }; words = "No result was recorded for this call."; }
  else if (r) {
    const o = toolOutcome(r);
    outcome = o.kind;
    if (o.kind === "ok") capsule = { text: o.exit === null ? "ok" : `exit ${o.exit}`, tone: "ok", icon: "check" };
    else {
      const look = TOOL_OUTCOME_LOOK[o.kind];
      const text = o.kind === "exit" ? `exit ${o.exit}` : o.kind === "failed" ? oneLine(r.status || "error", 24) : o.kind;
      capsule = { text, tone: look.tone, icon: look.icon };
      words = TOOL_OUTCOME_WORDS[o.kind](o);
    }
  }
  const duration = r && r.duration_ms ? seconds(r.duration_ms) : "";
  const d = block.args && typeof block.args === "object" && !Array.isArray(block.args) ? block.args.description : null;
  const label = typeof d === "string" && d.trim() ? oneLine(d, 160) : "";
  const calledAs = block.ran ? block.name : "";
  return { icon: toolIcon(block.ran ? { ...block, name: block.ran } : block), name: block.ran || block.name, calledAs, label, argsLine: block.argsLine || "", capsule, duration, state: block.state, outcome, words, partial: partialView(r) };
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
 * The identity line of a row. `activityMs` is the time of the latest RECORD seen (null when none has been loaded: a
 * creation time is never shown as an age). Returns {text, parts, age, waiting, known}: `parts` is [profile, role, tail]
 * where tail is the age, or null when unknown; `age` is the age or ACTIVITY_UNKNOWN (for a tooltip); `text` is
 * "profile · role · age", or just "profile · role" while something waits (the waiting reason `waiting` is then its own
 * line, so the model stays readable) or while the age is unknown (repeating "not loaded" on every row is noise).
 */
export function identityLine(info, activityMs, waiting, now) {
  const reason = waitingReason(waiting, now);
  const known = Number.isFinite(activityMs);
  const when = known ? age(now, activityMs) : ACTIVITY_UNKNOWN;
  const head = [info.profile || "?", info.role || "session"];
  return { text: (reason || !known ? head : [...head, when]).join(" · "), parts: [...head, known ? when : null], age: when, waiting: reason, known };
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

/** The first 10 characters of a session id, for the id button; an ellipsis says when it was cut. */
export function shortId(id) {
  const s = String(id || "");
  return s.length > 10 ? s.slice(0, 10) + "…" : s;
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
  // A profile named for its model says it once ("dsv41 · 1M", not "dsv41 · dsv41 · 1M").
  const textParts = [cur.profile || "unknown profile", modelId === cur.profile ? "" : modelId, formatWindow(win)].filter(Boolean);
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

// ---------------------------------------------------------------------------------------------
// Pass 2: prose, switcher, quiet indicator, endings and notifications, agents, find, progress, inbox triage

/**
 * proseTree(text): the prose subset as a tree, in one pass over the lines (a fenced block is collected, not re-read per line).
 * Returns blocks: {type:"p"|"h", inline} | {type:"ul"|"ol", items: inline[]} | {type:"pre", text}; `inline` is a list of
 * {type:"text"|"strong"|"code", text}. Nothing here is HTML: the caller makes elements and text nodes.
 */
export function proseTree(text) {
  const out = [];
  let paragraph = [], list = null, code = null;
  const inline = (value) => {
    const parts = [];
    let from = 0;
    for (const m of value.matchAll(/(\*\*[^*\n]+\*\*|`[^`\n]+`)/g)) {
      if (m.index > from) parts.push({ type: "text", text: value.slice(from, m.index) });
      const bold = m[0].startsWith("**");
      parts.push({ type: bold ? "strong" : "code", text: m[0].slice(bold ? 2 : 1, bold ? -2 : -1) });
      from = m.index + m[0].length;
    }
    if (from < value.length) parts.push({ type: "text", text: value.slice(from) });
    return parts;
  };
  const flush = () => {
    if (paragraph.length) { out.push({ type: "p", inline: inline(paragraph.join("\n")) }); paragraph = []; }
  };
  for (const line of String(text ?? "").split("\n")) {
    if (/^\s*```/.test(line)) {
      flush(); list = null;
      if (code) { out.push({ type: "pre", text: code.join("\n") }); code = null; } else code = [];
    } else if (code) code.push(line);
    else if (/^#{1,6}\s+/.test(line)) {
      flush(); list = null;
      out.push({ type: "h", inline: inline(line.replace(/^#{1,6}\s+/, "")) });
    } else if (/^\s*(?:[-*+]\s+|\d+[.)]\s+)/.test(line)) {
      flush();
      const type = /^\s*\d/.test(line) ? "ol" : "ul";
      if (!list || list.type !== type) { list = { type, items: [] }; out.push(list); }
      list.items.push(inline(line.replace(/^\s*(?:[-*+]\s+|\d+[.)]\s+)/, "")));
    } else if (!line.trim()) { flush(); list = null; }
    else { list = null; paragraph.push(line); }
  }
  flush();
  if (code) out.push({ type: "pre", text: code.join("\n") }); // a fence left open runs to the end, as it is read
  return out;
}

// ---- switcher

/** The quiet threshold: a running session with no new record for longer than this says so. */
export const QUIET_MS = 10 * 60 * 1000;

/**
 * quietFor(info, activity, now): for a RUNNING session whose latest known record (`activity` is {ts} or a time) is older than
 * QUIET_MS: {text:"no new record for 41m", icon:"hourglass", tone:"", ms, tip}; otherwise null, including when the age is
 * unknown. Factual and neutral: never "stalled", never amber. `since` (optional) is the time the page's event stream connected, or null
 * while it is down: the note is null with no stream, and counts only the time the page has been listening.
 */
export function quietFor(info, activity, now, since) {
  if (!info || !info.status || info.status.phase !== "running") return null;
  let ts = activity && typeof activity === "object" ? activity.ts : activity;
  if (!Number.isFinite(ts) || !Number.isFinite(now)) return null;
  // `since`: when this page's stream last (re)connected. With the stream down (null) nothing is known; otherwise only the time since
  // it connected is known to be silent, so a record age from before that (a restored watermark) cannot drive the note.
  if (since !== undefined) {
    if (!Number.isFinite(since)) return null;
    ts = Math.max(ts, since);
  }
  const ms = now - ts;
  if (!(ms > QUIET_MS)) return null;
  return {
    text: `no new record for ${age(now, ts)}`, icon: "hourglass", tone: "", ms,
    tip: "Nothing was recorded for this session for a while. That can be normal: a cold prompt of a million tokens takes minutes to read, requests queue, and a model may be given up to 240 seconds before a stall is declared.",
  };
}

/** What a row says on its own line: what waits on the operator, else the quiet note, else null. {text, icon, tone}. */
export function rowReason(waiting, info, activity, now, since) {
  return waitingReason(waiting, now) || quietFor(info, activity, now, since);
}

/**
 * switcherRows(store, inbox, query, opts): the rows of the Ctrl/Cmd+K switcher, every session (roots and agents; archived ones
 * only with opts.showArchived). opts: {now, activity (Map id -> {seq, ts}), showArchived, since (the stream's connect time, or null: see quietFor)}. Order with no query: Needs you
 * (oldest wait first), Running, then the rest by latest record (creation time when none). A non-empty `query` keeps rows
 * where it is a plain, case-insensitive substring of the title, the profile, the role or the workspace name, or a prefix of the id.
 * Row: {id, info, mission, root, title, workspace, group:"needs_you"|"running"|"other", mark, identity, reason, matched}.
 */
export function switcherRows(store, inbox, query, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const activity = opts.activity instanceof Map ? opts.activity : new Map();
  const q = String(query ?? "").trim().toLowerCase();
  const rows = [];
  for (const info of store.byId.values()) {
    if (info.archived && !opts.showArchived) continue;
    const ws = workspaceName(info.workspace);
    const title = info.title || info.id;
    let matched = null;
    if (q) {
      if (title.toLowerCase().includes(q)) matched = "title";
      else if (String(info.id).toLowerCase().startsWith(q)) matched = "id";
      else if (ws.toLowerCase().includes(q)) matched = "workspace";
      else if (String(info.profile || "").toLowerCase().includes(q)) matched = "profile";
      else if (String(info.role || "").toLowerCase().includes(q)) matched = "role";
      if (!matched) continue;
    }
    const attention = attentionFor(inbox, info.id);
    const waiting = waitingFor(inbox, [info.id]);
    const a = activity.get(info.id);
    const recordedMs = a && Number.isFinite(a.ts) ? a.ts : null;
    const st = info.status || {};
    const group = attention.blocking > 0 && st.phase !== "ended" ? "needs_you" : st.phase === "running" ? "running" : "other";
    rows.push({
      id: info.id, info, mission: info.mission || info.id, root: !info.parent, title, workspace: ws, group,
      mark: rowMark(info, attention), identity: identityLine(info, recordedMs, waiting, now),
      reason: rowReason(waiting, info, a, now, opts.since), matched,
      sort: recordedMs ?? (Number(info.created_ms) || 0), since: waiting.blocking.since,
    });
  }
  const rank = { needs_you: 0, running: 1, other: 2 };
  rows.sort((x, y) => rank[x.group] - rank[y.group]
    || (x.group === "needs_you" ? (x.since ?? Infinity) - (y.since ?? Infinity) : 0)
    || y.sort - x.sort || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  return rows.map(({ sort, since, ...row }) => row);
}

/**
 * nextNeedsYou(store, inbox, currentId, dir): the next mission waiting on the operator, cycling (dir 1 forward, -1 back). Missions are
 * ordered by their oldest blocking item. Returns {id (the session holding that oldest item), mission, index (1-based), total,
 * words:"2 of 3 needing you"}, or null when nothing blocks. A session of the current mission counts as being at it.
 */
export function nextNeedsYou(store, inbox, currentId, dir = 1) {
  const byMission = new Map();
  for (const e of inbox.items.values()) {
    if (!e.item.blocking) continue;
    const info = store.byId.get(e.session);
    if (info && info.status && info.status.phase === "ended") continue;
    const m = (info && info.mission) || e.mission || e.session;
    const opened = Number.isFinite(e.opened_ms) ? e.opened_ms : Infinity;
    const cur = byMission.get(m);
    if (!cur || opened < cur.opened) byMission.set(m, { mission: m, id: e.session, opened });
  }
  const list = [...byMission.values()].sort((a, b) => a.opened - b.opened || (a.mission < b.mission ? -1 : 1));
  if (!list.length) return null;
  const here = store.byId.get(currentId);
  const at = list.findIndex((m) => m.mission === (here ? here.mission : currentId));
  const step = dir < 0 ? -1 : 1;
  const i = at < 0 ? (step > 0 ? 0 : list.length - 1) : (at + step + list.length) % list.length;
  return { id: list[i].id, mission: list[i].mission, index: i + 1, total: list.length, words: `${i + 1} of ${list.length} needing you` };
}

// ---- keyboard

const NON_TEXT_INPUTS = new Set(["checkbox", "radio", "button", "submit", "reset", "range", "color", "file", "image"]);

/** Whether a key press aimed at `target` ({tagName, type, isContentEditable}) is typing text: no single-key shortcut may fire. */
export function typingTarget(target) {
  if (!target) return false;
  if (target.isContentEditable) return true;
  const tag = String(target.tagName || "").toLowerCase();
  if (tag === "textarea" || tag === "select") return true;
  return tag === "input" && !NON_TEXT_INPUTS.has(String(target.type || "text").toLowerCase());
}

/**
 * shortcutFor(event, {typing, mac}): the page's keyboard action for a key press, or null. `event` is {key, ctrlKey, metaKey, altKey,
 * shiftKey, isComposing}. Ctrl/Cmd+K (the switcher) works anywhere; every other key is ignored while `typing`, while composing
 * text, and with a modifier it does not use. Escape and Stop have no entry here: Escape only closes surfaces, and no key stops a session.
 * Actions: "switch", "row-next", "row-prev" (Alt+Down/Up), "needs-next", "needs-prev" (Alt+Shift+Down/Up), "find" (/), "keys" (?).
 */
export function shortcutFor(e, opts = {}) {
  if (!e || e.isComposing) return null;
  const mod = !!(e.ctrlKey || e.metaKey);
  // On a Mac Ctrl+K is the system's delete-to-end-of-line, so the switcher takes Cmd only there; elsewhere Ctrl only.
  const chord = opts.mac === undefined ? mod : opts.mac ? !!e.metaKey : !!e.ctrlKey;
  if (chord && !e.altKey && !e.shiftKey && (e.key === "k" || e.key === "K")) return "switch";
  if (opts.typing || mod) return null;
  if (e.altKey) {
    if (e.key === "ArrowDown") return e.shiftKey ? "needs-next" : "row-next";
    if (e.key === "ArrowUp") return e.shiftKey ? "needs-prev" : "row-prev";
    return null;
  }
  if (e.key === "?") return "keys";
  if (e.key === "/") return "find"; // on layouts where / needs Shift the key is still "/"
  if (e.key === "[") return "mine-prev";
  if (e.key === "]") return "mine-next";
  return null;
}

/**
 * mineStep(blocks, fromSeq, dir): the seq of the operator's own message one step from `fromSeq` (the record nearest the top of
 * the view) in `dir` (1 later, -1 earlier), or null at an end. Long records are read prompt by prompt this way.
 */
export function mineStep(blocks, fromSeq, dir) {
  const mine = (blocks || []).filter((b) => b.kind === "user" && Number.isFinite(b.seq)).map((b) => b.seq);
  if (!mine.length) return null;
  if (!Number.isFinite(fromSeq)) return dir > 0 ? mine[0] : mine[mine.length - 1];
  if (dir > 0) return mine.find((q) => q > fromSeq) ?? null;
  for (let i = mine.length - 1; i >= 0; i--) if (mine[i] < fromSeq) return mine[i];
  return null;
}

/**
 * stepIndex(length, current, dir): the index one step from `current` (-1 or out of range: none) within a list, not wrapping; null
 * at an end or for an empty list. With no current, forward gives the first and back the last.
 */
export function stepIndex(length, current, dir) {
  if (!(length > 0)) return null;
  const step = dir < 0 ? -1 : 1;
  if (!Number.isInteger(current) || current < 0 || current >= length) return step > 0 ? 0 : length - 1;
  const next = current + step;
  return next < 0 || next >= length ? null : next;
}

/**
 * keySheet(mac): the shortcut sheet as groups [{title, rows:[{keys:[cap...], text}]}]; `mac` writes Cmd and Option for Ctrl and Alt.
 * It lists only keys the page binds, and says that no key stops a session.
 */
export function keySheet(mac = false) {
  const ctrl = mac ? "Cmd" : "Ctrl";
  const alt = mac ? "Option" : "Alt";
  return [
    { title: "Move between missions", rows: [
      { keys: [ctrl, "K"], text: "Switch to a mission or agent by name, workspace, profile or role" },
      { keys: [alt, "↓"], text: "Next mission in the sidebar" },
      { keys: [alt, "↑"], text: "Previous mission in the sidebar" },
      { keys: [alt, "Shift", "↓"], text: "Next mission that needs you" },
      { keys: [alt, "Shift", "↑"], text: "Previous mission that needs you" },
    ] },
    { title: "In a record", rows: [
      { keys: ["/"], text: "Find in this record" },
      { keys: ["["], text: "Your previous message in this record" },
      { keys: ["]"], text: "Your next message in this record" },
      { keys: ["Enter"], text: "In Find: next match" },
      { keys: ["Shift", "Enter"], text: "In Find: previous match" },
      { keys: ["Enter"], text: "In the message box: send" },
      { keys: ["Shift", "Enter"], text: "In the message box: new line" },
    ] },
    { title: "Answering", rows: [
      { keys: [ctrl, "Enter"], text: "Send the answer you are writing in an inbox card, then go to the next open card" },
    ] },
    { title: "Everywhere", rows: [
      { keys: ["?"], text: "This sheet" },
      { keys: ["Esc"], text: "Close the open dialog, drawer or Find. It never stops anything." },
    ] },
  ];
}

// ---- endings and notifications

/**
 * missionEnding(prev, next, opts): a root session that has just ended (phase "ended", or running to idle with last_end finished,
 * error, budget_exhausted or stopped: the daemon never sets "ended" on a root), seen as two infos (the one held
 * and the one a `session` or `status` frame brings; for a status frame pass {...prev, status}). null when it is not a root, was
 * not seen before, was already ended, or was stopped by this tab (opts.requested: Set of session ids this tab asked to stop).
 * Returns {session, mission, title, outcome, words}.
 */
export function missionEnding(prev, next, opts = {}) {
  if (!prev || !next || next.parent) return null;
  const was = prev.status && prev.status.phase;
  const now = next.status && next.status.phase;
  let outcome = null;
  if (now === "ended" && was !== "ended" && was) outcome = next.status.outcome || "done";
  else if (was === "running" && now === "idle") {
    // A root lead never reaches phase "ended": it goes back to idle and records how its turn ended. A yield (every chat
    // reply), a wait and an ask are not endings.
    outcome = { finished: "done", error: "failed", budget_exhausted: "budget_exhausted", stopped: "stopped" }[next.status.last_end] || null;
  }
  if (!outcome) return null;
  if (outcome === "stopped" && opts.requested && opts.requested.has(next.id)) return null;
  return { session: next.id, mission: next.mission || next.id, title: next.title || next.id, outcome, words: outcomeWords(outcome) };
}

/** How a mission ending is said in a count line. */
const ENDING_COUNT = { done: "finished", failed: "failed", budget_exhausted: "ran out of budget", stopped: "stopped", returned: "returned", blocked: "blocked" };
const ENDING_NOUN = { done: "Mission finished", failed: "Mission failed", budget_exhausted: "Mission ran out of budget", stopped: "Mission stopped", returned: "Mission returned", blocked: "Mission blocked" };

/**
 * noticeOfInbox(entry, at): the notice for an open inbox entry: {tag, session, title, kind:"needs_you"|"result", noun, text, at}, or
 * null for a nonblocking item that is not a result. The noun is the sidebar's ("Approval waiting"), not the item kind.
 */
export function noticeOfInbox(entry, at) {
  const item = entry && entry.item;
  if (!item) return null;
  const result = item.item_kind === "finished";
  if (!item.blocking && !result) return null;
  return {
    tag: item.item_id, session: entry.session, title: entry.title || entry.session, at,
    kind: item.blocking ? "needs_you" : "result",
    noun: item.blocking ? `${WAITING_NOUN[item.item_kind] || "Request"} waiting` : "Result ready",
    text: oneLine(item.text || "", 200),
  };
}

/** noticeOfEnding(ending, at): the notice for a missionEnding() result: {tag:"end:<session>", kind:"ended", noun, outcome, ...}. */
export function noticeOfEnding(ending, at) {
  if (!ending) return null;
  return {
    tag: "end:" + ending.session, session: ending.session, title: ending.title, at, kind: "ended", outcome: ending.outcome,
    noun: ENDING_NOUN[ending.outcome] || `Mission ${ending.words}`, text: "",
  };
}

/** Events that arrive within this long of the first waiting one are shown as one notification. */
export const NOTIFY_WINDOW_MS = 5000;

/**
 * planNotifications(pending, {now, windowMs, visible}): `pending` are notices (noticeOfInbox / noticeOfEnding) not yet shown, each with
 * its arrival time `at`. Returns {due, wait, notification, rest}: while the oldest is younger than the window, {due:false, wait: ms
 * left, notification:null, rest: pending}; after it, {due:true, wait:0, rest:[], notification} with everything combined, or
 * notification null when `visible` (the page is shown and focused: the badge and title already say it).
 * notification: {tag, title, body, target:{hash, session}, covers: tags, sessions, counts:{needs, results, ended}}, e.g. title "2 need you · 1 finished".
 * One notice: its noun as the title, its mission and text as the body, target its session. Several: target "#/inbox".
 */
export function planNotifications(pending, opts = {}) {
  const list = (pending || []).filter(Boolean);
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const windowMs = Number.isFinite(opts.windowMs) ? opts.windowMs : NOTIFY_WINDOW_MS;
  if (!list.length) return { due: false, wait: null, notification: null, rest: [] };
  const oldest = Math.min(...list.map((n) => (Number.isFinite(n.at) ? n.at : now)));
  if (now - oldest < windowMs) return { due: false, wait: windowMs - (now - oldest), notification: null, rest: list };
  if (opts.visible) return { due: true, wait: 0, notification: null, rest: [] };
  const seen = new Set();
  const all = list.filter((n) => (seen.has(n.tag) ? false : (seen.add(n.tag), true)));
  // A mission that ends also opens its Finished or Parked item: one ending, one notice, so the item notice folds into it.
  const ended = new Set(all.filter((n) => n.kind === "ended").map((n) => n.session));
  const batch = all.filter((n) => n.kind === "ended" || !ended.has(n.session));
  const counts = { needs: 0, results: 0, ended: 0 };
  const endWords = new Map();
  for (const n of batch) {
    if (n.kind === "needs_you") counts.needs++;
    else if (n.kind === "result") counts.results++;
    else { counts.ended++; const w = ENDING_COUNT[n.outcome] || outcomeWords(n.outcome || "ended"); endWords.set(w, (endWords.get(w) || 0) + 1); }
  }
  const sessions = [...new Set(batch.map((n) => n.session))];
  const covers = all.map((n) => n.tag);
  if (batch.length === 1) {
    const n = batch[0];
    return {
      due: true, wait: 0, rest: [],
      notification: {
        tag: n.tag, title: n.noun, body: oneLine(n.text ? `${n.title}: ${n.text}` : n.title, 200),
        target: { hash: sessionHash(n.session), session: n.session }, covers, sessions, counts,
      },
    };
  }
  const parts = [];
  if (counts.needs) parts.push(`${counts.needs} ${counts.needs === 1 ? "needs" : "need"} you`);
  if (counts.results) parts.push(`${counts.results} ${counts.results === 1 ? "result" : "results"} ready`);
  for (const [w, n] of endWords) parts.push(`${n} ${w}`);
  const lines = batch.slice(0, 4).map((n) => `${n.noun}: ${oneLine(n.title, 60)}`);
  if (batch.length > 4) lines.push(`and ${batch.length - 4} more`);
  return {
    due: true, wait: 0, rest: [],
    notification: {
      tag: `batch:${oldest}:${batch.length}`, title: parts.join(" · "), body: lines.join("\n"),
      target: { hash: "#/inbox", session: null }, covers, sessions, counts,
    },
  };
}

/**
 * closableNotifications(shown, ctx): which shown notifications (planNotifications().notification objects) to close. ctx: {openItems: Set
 * of item ids still open, opened: {session, inbox}} (what the operator just opened). A notification closes when its session
 * was opened (one session), when the inbox was opened (several), or when every item it covers has been resolved (a notification that
 * covers a mission ending has nothing to resolve and closes only on opening). Returns the tags to close.
 */
export function closableNotifications(shown, ctx = {}) {
  const open = ctx.openItems instanceof Set ? ctx.openItems : new Set(ctx.openItems || []);
  const opened = ctx.opened || {};
  const out = [];
  for (const n of shown || []) {
    const items = (n.covers || []).filter((t) => !String(t).startsWith("end:"));
    const allItems = items.length === (n.covers || []).length && items.length > 0;
    const byOpen = (opened.session && n.target && n.target.session === opened.session) || (opened.inbox && n.target && n.target.hash === "#/inbox");
    if (byOpen || (allItems && items.every((t) => !open.has(t)))) out.push(n.tag);
  }
  return out;
}

// ---- agents

const AGENT_GROUPS = [
  ["needs_you", "Needs you"], ["running", "Running"], ["waiting", "Waiting"], ["idle", "Idle"], ["ended", "Ended"],
];

/** The cells of a score row: [key in the card, singular, plural]. */
const SCORE_CELLS = [
  ["calls", "call", "calls"], ["malformed_calls", "malformed call", "malformed calls"], ["quote_refusals", "quote refusal", "quote refusals"],
  ["finish_refusals", "finish refusal", "finish refusals"], ["verifier_accepts", "verifier accept", "verifier accepts"],
  ["verifier_rejections", "verifier reject", "verifier rejects"], ["hand_offs", "hand-off", "hand-offs"], ["asks", "ask", "asks"],
];
export const SCORE_TOTAL_LABEL = "Mission total, every session";
export const SCORE_FINEPRINT = "Run numbers describe effort, not completion.";

function scoreCard(card) {
  const c = card || {};
  const n = (k) => (Number.isFinite(c[k]) ? c[k] : 0);
  const cells = SCORE_CELLS.map(([key, one, many]) => ({ key, label: many, value: n(key), text: count(n(key), one, many) }));
  const shown = cells.filter((x) => x.value > 0);
  return {
    steps: n("steps"), finished: !!c.finished, stepsToFinish: Number.isFinite(c.steps_to_finish) ? c.steps_to_finish : null,
    unrecorded: !!c.unrecorded, cells,
    text: shown.length ? shown.map((x) => x.text).join(" · ") : "no calls recorded",
  };
}

/**
 * scoreRows(view): `GET /api/missions/{id}/score` ({mission, sessions:[{session, role, parent, card}], total}) as rows. Returns
 * {mission, rows, bySession: Map id -> row, total, label, fineprint} or null for anything else. A row is {session, role, parent,
 * steps, finished, stepsToFinish, unrecorded, cells:[{key, label, value, text}] (calls, malformed calls, quote refusals, finish
 * refusals, verifier accepts and rejects, hand-offs, asks: all eight, zeros included), text (the non-zero ones)}.
 */
export function scoreRows(view) {
  if (!view || !Array.isArray(view.sessions) || !view.total || typeof view.total !== "object") return null;
  const rows = view.sessions.filter((s) => s && s.session).map((s) => ({ session: s.session, role: s.role || "", parent: s.parent || null, ...scoreCard(s.card) }));
  return {
    mission: view.mission || null, rows, bySession: new Map(rows.map((r) => [r.session, r])),
    total: { session: null, role: "", parent: null, ...scoreCard(view.total) }, label: SCORE_TOTAL_LABEL, fineprint: SCORE_FINEPRINT,
  };
}

/** Score refresh cadence: at most this often while the Agents tab is shown and an agent runs. */
export const SCORE_EVERY_MS = 120000;

/**
 * scoreDue({shown, lastMs, running, now, force}): whether to fetch /score now. Always on `force` (opening the tab, Refresh); while the
 * tab is shown and nothing was fetched yet, even when nothing runs; after that only while something runs, and not within SCORE_EVERY_MS of the last fetch.
 */
export function scoreDue({ shown, lastMs, running, now, force } = {}) {
  if (force) return true;
  if (!shown) return false;
  if (!Number.isFinite(lastMs)) return true; // a finished mission is read once too: reviewing it is the common case
  return !!running && now - lastMs >= SCORE_EVERY_MS;
}

/** The seq of each child's `child_spawned` block, for the "where it was spawned" link: Map child session id -> seq. */
export function spawnSeqs(blocks) {
  const m = new Map();
  for (const b of blocks || []) if (b && b.kind === "child_spawned" && b.child) m.set(b.child, b.seq);
  return m;
}

/**
 * agentGroups(store, inbox, missionId, opts): the Agents tab. opts: {now, activity (Map id -> {seq, ts}), since (see quietFor), score (scoreRows() or null),
 * spawns (spawnSeqs())}. Groups in fixed order: Needs you, Running, Waiting, Idle, Ended (folded); inside a group, creation order, never
 * by activity. Returns {groups:[{key, label, folded, rows}], total, running, badge:"3 running"|""}. Row: {id, info, depth, indent (depth up
 * to 3), crumbs (ancestor titles, root first, only when deeper than 3), title, role, roleLine "role · profile", mark, step, ageText
 * ("12m ago", "just now", or null while unknown), recordedMs, quiet, generated ("1.2M generated" or ""), outcome (ended agents,
 * in words), waiting, score (scoreRows row or null), spawnSeq (number or null)}.
 */
export function agentGroups(store, inbox, missionId, opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const activity = opts.activity instanceof Map ? opts.activity : new Map();
  const members = [...store.byId.values()].filter((s) => (s.mission || s.id) === missionId);
  const ids = new Set(members.map((s) => s.id));
  const depthOf = (info) => {
    const chain = [];
    const seen = new Set([info.id]);
    for (let p = info.parent && store.byId.get(info.parent); p && ids.has(p.id) && !seen.has(p.id); p = p.parent && store.byId.get(p.parent)) {
      chain.unshift(p);
      seen.add(p.id);
    }
    return chain;
  };
  const groups = new Map(AGENT_GROUPS.map(([key, label]) => [key, { key, label, folded: key === "ended", rows: [] }]));
  let running = 0;
  const ordered = members.slice().sort((a, b) => (Number(a.created_ms) || 0) - (Number(b.created_ms) || 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  for (const info of ordered) {
    const st = info.status || {};
    const attention = attentionFor(inbox, info.id);
    const waiting = waitingFor(inbox, [info.id]);
    const key = st.phase === "ended" ? "ended" : attention.blocking > 0 ? "needs_you" : st.phase === "running" ? "running" : st.last_end === "waiting" ? "waiting" : "idle";
    if (st.phase === "running") running++;
    const chain = depthOf(info);
    const depth = chain.length;
    const a = activity.get(info.id);
    const recordedMs = a && Number.isFinite(a.ts) ? a.ts : null;
    const when = recordedMs === null ? null : age(now, recordedMs);
    groups.get(key).rows.push({
      id: info.id, info, depth, indent: Math.min(depth, 3), crumbs: depth > 3 ? chain.map((p) => p.title || p.id) : [],
      title: info.title || info.id, role: info.role || "session", roleLine: `${info.role || "session"} · ${info.profile || "?"}`,
      mark: rowMark(info, attention), step: Number(st.step) || 0,
      ageText: when === null ? null : when === "now" ? "just now" : `${when} ago`, recordedMs,
      quiet: quietFor(info, a, now, opts.since),
      generated: st.completion_tokens_total > 0 ? `${tokens(st.completion_tokens_total)} generated` : "",
      outcome: st.phase === "ended" ? (st.outcome ? outcomeWords(st.outcome) : "ended") : "",
      waiting: waitingReason(waiting, now),
      score: (opts.score && opts.score.bySession.get(info.id)) || null,
      spawnSeq: opts.spawns && opts.spawns.has(info.id) ? opts.spawns.get(info.id) : null,
    });
  }
  // `agents` and `agentsRunning` leave the lead out, as the sidebar's "12 agents · 4 running" does; `total` and `running`
  // count every session of the mission.
  const agents = members.filter((s) => s.parent).length;
  const agentsRunning = members.filter((s) => s.parent && s.status && s.status.phase === "running").length;
  const leadRunning = running - agentsRunning > 0;
  const summary = agents === 0 ? "No agents yet" + (leadRunning ? " · the lead is running" : "")
    : count(agents, "agent") + (agentsRunning ? ` · ${agentsRunning} running` : "") + (leadRunning ? " · the lead is running" : "");
  return { groups: [...groups.values()].filter((g) => g.rows.length), total: members.length, running, agents, agentsRunning, summary, badge: running ? `${running} running` : "" };
}

// ---- find in the record

const FIND_KINDS = new Set(["all", "messages", "tools", "failures"]);
const FIND_CAP = 2000;

// The searchable pieces of a block: [field, text]; `seq` is the record that holds the text (for the jump).
export function findFields(b, kind = "all") {
  if (!b) return [];
  switch (b.kind) {
    case "user": return [["text", b.text, b.seq]];
    case "note": return [["text", b.text, b.seq]];
    case "response": {
      const fields = [["text", b.text, b.seq]];
      if (kind === "all" || kind === "messages" || !FIND_KINDS.has(kind)) {
        fields.push(["reasoning", b.reasoning, b.seq]);
      }
      return fields;
    }
    case "inbox": return [["text", b.item && b.item.text, b.seq], ["answer", b.resolved && b.resolved.answer, b.resolved && b.resolved.seq]];
    case "child_settled": return [["text", b.report, b.seq]];
    case "child_spawned": return [["text", typeof b.brief === "string" ? b.brief : b.brief && (b.brief.task || b.brief.text || b.brief.goal), b.seq]];
    case "tool": return [["call", `${b.name || ""} ${b.argsLine || ""}`, Number.isInteger(b.callSeq) ? b.callSeq : b.seq], ["result", b.result && b.result.text, b.result && b.result.seq]];
    case "reweave": return [["text", b.summary, b.seq]];
    case "compaction": return [["text", b.head, b.seq], ["note", b.note, b.seq], ["table", b.table, b.seq]];
    case "line": case "divider": case "end": return [["text", b.text, b.seq]];
    default: return [];
  }
}

const isFailureBlock = (b) => (b.kind === "tool" && (b.state === "missing" || (b.result && toolOutcome(b.result).kind !== "ok"))) || isWarningBlock(b) || (b.kind === "end" && (b.outcome === "failed" || b.outcome === "budget_exhausted")) || (b.kind === "line" && b.sub === "interrupted");
const FIND_IN = {
  all: () => true,
  messages: (b) => b.kind === "user" || b.kind === "note" || b.kind === "response" || b.kind === "inbox" || b.kind === "child_settled" || b.kind === "child_spawned",
  tools: (b) => b.kind === "tool" || (b.kind === "line" && b.sub === "job"),
  failures: isFailureBlock,
};

/**
 * findInRecord(blocks, query, kind, loaded): a literal, case-insensitive search of every loaded block (folded groups and blocks outside the
 * rendered window included; request-detail lines are not searched; reasoning is searched in "all" and "messages"). kind: "all" | "messages" | "tools" (calls, outputs,
 * jobs) | "failures" (calls that did not end ok, warnings, failed ends). Returns {query, kind, hits, count, capped, searched, cutOutputs}:
 * a hit is {id (block id), seq (the record holding the text), field, snippet:{before, match, after}}, one per block, in record
 * order; `searched` the number of loaded records (whatever the kind; `loaded`, the store's record count, when given); `cutOutputs` how many results are longer than the text held here, which the output viewer
 * searches instead.
 */
export function findInRecord(blocks, query, kind = "all", loaded) {
  const k = FIND_KINDS.has(kind) ? kind : "all";
  const needle = String(query ?? "").trim().toLowerCase();
  const out = { query: String(query ?? "").trim(), kind: k, hits: [], count: 0, capped: false, searched: 0, cutOutputs: 0 };
  const inKind = FIND_IN[k];
  for (const b of blocks || []) {
    if (!b || b.detail) continue;
    out.searched += blockSeqs(b).length;
    if (!needle || !inKind(b)) continue;
    if (b.kind === "tool" && b.result && (b.result.cut || (b.result.output && b.result.output.lines > b.result.lines))) out.cutOutputs++;
    if (out.hits.length >= FIND_CAP) { out.capped = true; continue; }
    for (const [field, text, seq] of findFields(b, k)) {
      if (!text) continue;
      const s = String(text);
      const at = s.toLowerCase().indexOf(needle);
      if (at < 0) continue;
      const clean = (t) => t.replace(/\s+/g, " ");
      out.hits.push({
        id: b.id, seq: Number.isInteger(seq) ? seq : b.seq, field,
        snippet: { before: clean(s.slice(Math.max(0, at - 40), at)), match: clean(s.slice(at, at + needle.length)), after: clean(s.slice(at + needle.length, at + needle.length + 60)) },
      });
      break;
    }
  }
  if (Number.isInteger(loaded) && loaded >= 0) out.searched = loaded; // every loaded record, bookkeeping ones too
  out.count = out.hits.length;
  return out;
}

/**
 * findWords(result, current): the count line, honest about scope: "3 of 17 in 12,480 loaded records" (`current` is the 0-based hit
 * shown), "17 matches in 12,480 loaded records", "No match in 12,480 loaded records", "" for an empty query. A capped search says
 * "2,000+"; a result with cut outputs adds that their full text is searched in the output viewer.
 */
export function findWords(result, current = null, withHint = true) {
  if (!result || !result.query) return "";
  const of = `${num(result.searched)} loaded ${result.searched === 1 ? "record" : "records"}`;
  const n = result.count ? `${num(result.count)}${result.capped ? "+" : ""}` : "";
  let text;
  if (!result.count) text = `No match in ${of}`;
  else if (Number.isInteger(current) && current >= 0 && current < result.count) text = `${num(current + 1)} of ${n} in ${of}`;
  else text = `${n} ${result.count === 1 && !result.capped ? "match" : "matches"} in ${of}`;
  const hint = findHint(result);
  if (withHint && hint) text += `. ${hint}`;
  return text;
}

/** The sentence about outputs cut before their end, which only the output viewer searches in full; "" when none. */
export function findHint(result) {
  if (!result || !result.query || !result.cutOutputs) return "";
  return `${count(result.cutOutputs, "output")} cut before the end: search ${result.cutOutputs === 1 ? "it" : "them"} in the output viewer`;
}

/** A hit's words for a screen reader and the count line: "…text before MATCH text after…". */
export function findSnippet(hit) {
  const sn = hit && hit.snippet;
  if (!sn) return "";
  return `…${sn.before}${sn.match}${sn.after}…`.replace(/\s+/g, " ");
}

// ---- progress line

const fmtMinutes = (m) => (m < 60 ? `${m}m` : m % 60 === 0 ? `${m / 60}h` : `${Math.floor(m / 60)}h${String(m % 60).padStart(2, "0")}m`);

/**
 * progressLine({plan, step, budget, minutes}): the line above the composer, or null when nothing is known. `plan` is
 * ledgerModel().plan, `step` the own steps and `minutes` the active minutes counted since the budget was granted (budgetUsed), `budget`
 * start.budget ({max_steps, max_minutes}). A step count above the limit (a renewed budget) is shown as the limit. Returns
 * {text, parts:[{key:"plan"|"now"|"budget", text}], label}: "Plan 3 of 9 done · now: <doing step> · budget 214 of 400 steps · 3h12m of 8h".
 * Budget is a limit, not a measure of completion, and `label` (the accessible name) says so.
 */
export function progressLine({ plan, step, budget, minutes } = {}) {
  const parts = [];
  const steps = (plan || []).filter((s) => s.status !== "dropped");
  if (steps.length) {
    parts.push({ key: "plan", text: `Plan ${steps.filter((s) => s.status === "done").length} of ${steps.length} done` });
    const doing = steps.find((s) => s.status === "doing");
    if (doing) parts.push({ key: "now", text: `now: ${oneLine(doing.text, 80)}` });
  }
  const b = budget || {};
  const bits = [];
  if (Number.isFinite(b.max_steps) && b.max_steps > 0) bits.push(`${num(Math.min(Number(step) || 0, b.max_steps))} of ${num(b.max_steps)} steps`);
  if (Number.isFinite(b.max_minutes) && b.max_minutes > 0 && Number.isFinite(minutes)) {
    bits.push(`${fmtMinutes(Math.min(Math.max(0, minutes), b.max_minutes))} of ${fmtMinutes(b.max_minutes)}`);
  }
  if (bits.length) parts.push({ key: "budget", text: `budget ${bits.join(" · ")}` });
  if (!parts.length) return null;
  const text = parts.map((p) => p.text).join(" · ");
  return { text, parts, label: parts.some((p) => p.key === "budget") ? `${text}. The budget is a limit, not a measure of progress.` : text };
}

// ---- inbox triage

// ---------------------------------------------------------------------------------------------
// Pass 2, part 4: ways out, inbox triage

/**
 * compactConfirm(title): the question before compacting a session's context, {text, yes, no}. One wording for the Context tab, the
 * session sheet and the "Ways out" row of a parked or blocker card; `title` is the session's name (omit it for "this session").
 */
export function compactConfirm(title) {
  const who = title ? `${oneLine(title, 80)}'s context` : "the context of this session";
  return {
    text: `Compact ${who} now? The model writes a note and everything before the last few steps leaves its view; nothing is deleted.`,
    yes: "Compact now",
    no: "Keep as it is",
  };
}

/** The receipt line after a compaction was asked for. */
export const COMPACT_RECEIPT = "Compacting now. The view updates when it is done.";

/**
 * lastRecordedError(blocks): the error sentence of the latest failed request or turn of a session, as the daemon recorded it, or null.
 * The daemon records a failure in two places: the Parked item a failed turn opens (`The session could not continue. <why> Nothing was
 * lost: ...`) and the answer of a model-unavailable notice whose request ended (`Answered automatically: the request ended without a
 * reply at <time>: <why> The session handles that ...`). Never composed: it is the record's own text, cut.
 */
export function lastRecordedError(blocks) {
  const list = Array.isArray(blocks) ? blocks : [];
  for (let i = list.length - 1; i >= 0; i--) {
    const b = list[i];
    if (!b || b.kind !== "inbox" || !b.item) continue;
    const answer = b.resolved && typeof b.resolved.answer === "string" ? b.resolved.answer : "";
    const failed = /^Answered automatically: the request ended without a reply at [^:]*(?::\d\d)*[^:]*: ([\s\S]*?)(?: The session handles that as any failed request\.)?$/.exec(answer);
    if (failed && failed[1].trim()) return oneLine(failed[1], 400);
    const text = typeof b.item.text === "string" ? b.item.text : "";
    const parked = /^The session could not continue\. ([\s\S]*?) Nothing was lost:/.exec(text);
    if (b.item.item_kind === "parked" && parked && parked[1].trim() && !/budget is used up/i.test(parked[1])) return oneLine(parked[1], 400);
  }
  return null;
}

/**
 * dedupeParkedError(itemText, lastError): normalize whitespace on both strings; return null when `!lastError` or
 * when normalized `itemText` already includes normalized `lastError` (or its first 80 chars if longer than 80);
 * otherwise return `lastError`.
 */
export function dedupeParkedError(itemText, lastError) {
  if (!lastError) return null;
  const normErr = String(lastError).replace(/\s+/g, " ").trim();
  if (!normErr) return null;
  const normItem = String(itemText ?? "").replace(/\s+/g, " ").trim();
  if (normItem.includes(normErr) || (normErr.length > 80 && normItem.includes(normErr.slice(0, 80)))) return null;
  return lastError;
}

function sessionMapFrom(sessions) {
  if (!sessions) return new Map();
  if (sessions.byId instanceof Map) return sessions.byId;
  if (sessions instanceof Map) return sessions;
  if (Array.isArray(sessions)) {
    const map = new Map();
    for (const s of sessions) if (s && s.id) map.set(s.id, s);
    return map;
  }
  return new Map();
}

function inboxEntriesFrom(inbox) {
  if (!inbox) return [];
  if (inbox.items instanceof Map) return [...inbox.items.values()];
  if (inbox instanceof Map) return [...inbox.values()];
  if (Array.isArray(inbox)) return inbox;
  return [];
}

/**
 * childBlockingItem(sessions, inbox, openSessionId): when `openSessionId` itself has no blocking open inbox item,
 * find the oldest/first open blocking inbox item belonging to another session in the same mission.
 * Returns `{ item, session, title }` or null.
 */
export function childBlockingItem(sessions, inbox, openSessionId) {
  if (!openSessionId) return null;
  const byId = sessionMapFrom(sessions);
  const open = byId.get(openSessionId);
  if (!open || !open.mission) return null;
  const entries = inboxEntriesFrom(inbox);
  const isBlocking = (e) => !!(e && !e.resolved && (e.item ? e.item.blocking : e.blocking));
  if (entries.some((e) => e && e.session === openSessionId && isBlocking(e))) return null;
  let best = null;
  let bestSession = null;
  let bestOpened = Infinity;
  for (const e of entries) {
    if (!isBlocking(e) || !e.session || e.session === openSessionId) continue;
    const sess = byId.get(e.session) || null;
    const mission = (sess && sess.mission) || e.mission || "";
    if (mission !== open.mission) continue;
    const opened = Number.isFinite(e.opened_ms) ? e.opened_ms : Infinity;
    if (!best || opened < bestOpened) {
      best = e;
      bestSession = sess;
      bestOpened = opened;
    }
  }
  if (!best) return null;
  const title = (bestSession && (bestSession.title || bestSession.id)) || best.session;
  return { item: best, session: bestSession, title };
}

/**
 * inboxGroups(inbox, titleOf): the inbox grouped by mission, missions that block work first (then by the oldest blocking item), the
 * rest by their oldest item. Items inside a group keep inboxSorted order. `titleOf(mission, entries)` names a group (default: the
 * title of its first entry). Returns [{key, mission, title, open, blocking, entries}].
 */
export function inboxGroups(inbox, titleOf) {
  const groups = new Map();
  for (const e of inboxSorted(inbox)) {
    const key = e.mission || "session:" + e.session;
    if (!groups.has(key)) groups.set(key, { key, mission: e.mission || "", entries: [], open: 0, blocking: 0, oldest: e.opened_ms || 0, oldestBlocking: Infinity });
    const g = groups.get(key);
    g.entries.push(e);
    g.open++;
    if (e.item.blocking) { g.blocking++; g.oldestBlocking = Math.min(g.oldestBlocking, e.opened_ms || 0); }
  }
  const out = [...groups.values()];
  for (const g of out) {
    g.title = (typeof titleOf === "function" && titleOf(g.mission, g.entries)) || g.entries[0].title || g.entries[0].session;
  }
  out.sort((a, b) => (b.blocking > 0) - (a.blocking > 0) || (a.blocking ? a.oldestBlocking - b.oldestBlocking : a.oldest - b.oldest));
  return out.map(({ oldest, oldestBlocking, ...g }) => g);
}

/** The words that open a refusal answer; the daemon starts a turn that delivers any non-empty answer to the agent. */
export const REFUSED_PREFIX = "Refused: ";

/** refusalAnswer(reason): {answer} for a refused scope request, or {error} when no reason was written. */
export function refusalAnswer(reason) {
  const r = String(reason || "").trim();
  if (!r) return { error: "Write why the request is refused; the agent reads it." };
  return { answer: REFUSED_PREFIX + r };
}

/** Whether a sent answer was a refusal (for the receipt). */
export function isRefusal(answer) {
  return typeof answer === "string" && answer.startsWith(REFUSED_PREFIX);
}

/** answerSendKey(e): true for Ctrl/Cmd+Enter (alone, not composing): the key that sends from an answer field. */
export function answerSendKey(e) {
  return !!e && !e.isComposing && e.key === "Enter" && !!(e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey;
}

/** nextCardId(ids, from): the open card after `from` in `ids` (page order), else the one before it, else null. */
export function nextCardId(ids, from) {
  const list = (ids || []).filter((x) => x !== from);
  const at = (ids || []).indexOf(from);
  if (!list.length) return null;
  if (at < 0) return list[0];
  return (ids || [])[at + 1] !== undefined ? ids[at + 1] : ids[at - 1] !== undefined ? ids[at - 1] : null;
}

// ---------------------------------------------------------------------------------------------
// Workspace folders: the picker of the New mission form, creating a missing workspace, and the Files tab

/** The most workspaces the picker offers as "Recent" shortcuts. */
export const RECENT_WORKSPACES = 8;

/** A byte count in words: "812 B", "12.3 KiB", "4.0 MiB". */
export function byteSize(n) {
  const v = Math.max(0, Number(n) || 0);
  if (v < 1024) return `${Math.round(v)} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i += 1; }
  return `${x >= 100 ? Math.round(x) : x.toFixed(1)} ${units[i]}`;
}

/** The absolute path `GET /api/fs/dirs` lists; no path means the daemon's default (the home directory). */
export function fsDirsUrl(path) {
  const p = String(path ?? "").trim();
  return p ? `/api/fs/dirs?path=${encodeURIComponent(p)}` : "/api/fs/dirs";
}

/** Join a folder path and one name without doubling the slash ("/" + "x" is "/x"). */
export function joinPath(base, name) {
  const b = String(base ?? "");
  return b.endsWith("/") ? b + name : b + "/" + name;
}

/** The folder above an absolute path; "/" has none (null). */
export function parentPath(path) {
  const p = String(path ?? "").replace(/\/+$/, "");
  if (!p.startsWith("/") || p === "") return null;
  const cut = p.lastIndexOf("/");
  return cut <= 0 ? "/" : p.slice(0, cut);
}

/** Breadcrumb buttons for an absolute path: [{name:"/", path:"/"}, {name:"Users", path:"/Users"}, …]. */
export function pathCrumbs(path) {
  const p = String(path ?? "");
  if (!p.startsWith("/")) return [];
  const out = [{ name: "/", path: "/" }];
  let at = "";
  for (const part of p.split("/").filter(Boolean)) {
    at += "/" + part;
    out.push({ name: part, path: at });
  }
  return out;
}

/**
 * Workspaces of the sessions the page knows, most recent first, each once. `infos` are session infos
 * ({id, workspace, created_ms}); `activity` maps a session id to {ts} (the latest record seen). The time
 * a workspace was used is its newest session's.
 */
export function recentWorkspaces(infos, activity = new Map(), limit = RECENT_WORKSPACES) {
  const latest = new Map();
  for (const info of infos || []) {
    const ws = typeof info.workspace === "string" ? info.workspace.trim() : "";
    if (!ws) continue;
    const at = Math.max(Number(info.created_ms) || 0, Number(activity && activity.get && activity.get(info.id)?.ts) || 0);
    if (!latest.has(ws) || at > latest.get(ws)) latest.set(ws, at);
  }
  return [...latest.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, Math.max(0, limit)).map(([path]) => path);
}

/** The folders the picker lists: hidden (dot) folders only when asked for. */
export function visibleDirs(entries, showHidden) {
  return (entries || []).filter((e) => e && typeof e.name === "string" && (showHidden || !e.hidden));
}

/** Check the name typed for a new folder: {name} (trimmed) or {error} with a sentence. `existing` are the names already there. */
export function checkFolderName(text, existing = []) {
  const name = String(text ?? "").trim();
  if (!name) return { error: "Type a name for the new folder." };
  if (name === "." || name === "..") return { error: `"${name}" is not a folder name; choose another.` };
  if (name.includes("/") || name.includes("\\")) return { error: "A folder name cannot contain a slash; to make a nested folder, make one level at a time." };
  if (/[\u0000-\u001f\u007f]/.test(name)) return { error: "A folder name cannot contain control characters." };
  if (new TextEncoder().encode(name).length > 255) return { error: "That name is too long; use 255 bytes or fewer." };
  if ((existing || []).some((n) => n === name)) return { error: `"${name}" already exists here. Open it, or choose another name.` };
  return { name };
}

/** Whether a daemon error on POST /api/sessions says the workspace is missing (and so can be offered "Create it"). */
export function missingWorkspaceError(message) {
  return /does not exist\. Create it/i.test(String(message ?? ""));
}

/** The question the form asks when the workspace is missing. */
export function createWorkspaceQuestion(path) {
  return `${path} does not exist. Create it and start the mission?`;
}

/** The sentence after a mission started in a folder it made. */
export const CREATED_WORKSPACE_RECEIPT = "The workspace folder did not exist and was created.";

/** `/api/sessions/{id}/files?path=` for a workspace-relative folder ("" is the root). */
export function filesUrl(session, path) {
  const p = String(path ?? "");
  return `/api/sessions/${encodeURIComponent(session)}/files` + (p ? `?path=${encodeURIComponent(p)}` : "");
}

/** `/api/sessions/{id}/files/lines?path=&start=&count=` for a workspace-relative file. */
export function fileLinesUrl(session, path, start, count) {
  return `/api/sessions/${encodeURIComponent(session)}/files/lines?path=${encodeURIComponent(path)}&start=${start}&count=${count}`;
}

/** Join a workspace-relative folder and a name ("" is the root). */
export function relJoin(dir, name) {
  return dir ? `${dir}/${name}` : String(name);
}

/** The workspace-relative folder above `path`; the root ("") has none (null). */
export function relParent(path) {
  const p = String(path ?? "");
  if (!p) return null;
  const cut = p.lastIndexOf("/");
  return cut < 0 ? "" : p.slice(0, cut);
}

/** Breadcrumbs of a workspace-relative folder, starting at the workspace itself: [{name, path}]. */
export function relCrumbs(path) {
  const out = [{ name: "workspace", path: "" }];
  let at = "";
  for (const part of String(path ?? "").split("/").filter(Boolean)) {
    at = relJoin(at, part);
    out.push({ name: part, path: at });
  }
  return out;
}

/** Normalise "a/./b//c" without ever stepping above the start; null when the path would leave it. */
function squash(parts) {
  const out = [];
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") { if (!out.length) return null; out.pop(); continue; }
    out.push(part);
  }
  return out;
}

/**
 * The workspace-relative form of a path a tool was given, or null when it is not inside the workspace:
 * an absolute path under `workspace`, or a relative path that does not climb out of it. "" is the workspace itself.
 * This only reads the text; the daemon decides what may be opened.
 */
export function workspaceRelative(workspace, text) {
  const raw = String(text ?? "").trim();
  const ws = String(workspace ?? "").replace(/\/+$/, "");
  if (!raw || raw.includes("\u0000") || raw.startsWith("~") || !ws.startsWith("/")) return null;
  if (raw.startsWith("/")) {
    const root = squash(ws.split("/"));
    const parts = squash(raw.split("/"));
    if (!root || !parts || parts.length < root.length || root.some((p, i) => parts[i] !== p)) return null;
    return parts.slice(root.length).join("/");
  }
  const parts = squash(raw.split("/"));
  return parts ? parts.join("/") : null;
}

/**
 * fileChanges(blocks, workspace): the files this session's edit and write tools changed, most recent first, one row per path:
 * {path, rel, edits, added, removed, created, lastSeq, lastId, lastTs}. Counts come from the diffs in the recorded results, so a
 * result without a diff ("(new file)") counts as an edit with `created` set and no line counts. Only calls that succeeded are
 * counted; shell commands and agents' edits are not seen here (the caller says so).
 */
export function fileChanges(blocks, workspace = "") {
  const rows = new Map();
  for (const b of blocks || []) {
    if (!b || b.kind !== "tool" || b.cls !== "write" || !b.result || b.result.status !== "ok") continue;
    const path = (b.result.meta && typeof b.result.meta.path === "string" && b.result.meta.path) || toolPathArg(b.args);
    if (!path) continue;
    const stat = diffStat(b.result.text);
    const row = rows.get(path) || { path, rel: workspaceRelative(workspace, path), edits: 0, added: 0, removed: 0, created: false, lastSeq: 0, lastId: null, lastTs: 0 };
    row.edits++;
    if (stat) { row.added += stat.added; row.removed += stat.removed; }
    if (/\n\(new file\)\n|^\(new file\)$/m.test(b.result.text || "")) row.created = true;
    const seq = b.result.seq ?? b.seq ?? 0;
    if (seq >= row.lastSeq) { row.lastSeq = seq; row.lastId = b.id; row.lastTs = b.result.ts || b.ts || 0; }
    rows.set(path, row);
  }
  return [...rows.values()].sort((a, b) => b.lastSeq - a.lastSeq);
}

/** The path a tool call names, from its arguments (`path`, `file_path`, `absolute_path`, `target_file` or `file`), or null. */
export function toolPathArg(args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return null;
  for (const k of ["path", "file_path", "absolute_path", "target_file", "file"]) if (typeof args[k] === "string" && args[k].trim()) return args[k];
  return null;
}

/** Tools whose path argument "Open file" may follow into the Files tab. */
const OPEN_FILE_TOOLS = new Set(["read", "write", "edit", "multi_edit", "patch", "ls", "grep", "glob"]);

/** The workspace-relative path "Open file" opens for a tool block, or null when there is none inside the workspace. */
export function openFileTarget(block, workspace) {
  if (!block || !OPEN_FILE_TOOLS.has(block.name)) return null;
  const arg = toolPathArg(block.args);
  return arg === null ? null : workspaceRelative(workspace, arg);
}

/** Is this entry the workspace's closed harness folder? The daemon marks it with a `note` (only the root's `.loom`; a nested `.loom` is an ordinary folder). */
export function isHarnessEntry(entry) {
  return !!entry && typeof entry.note === "string" && entry.note !== "";
}

/** Is this entry hidden? The daemon's `hidden` flag, else a leading dot. */
export function isHiddenEntry(entry) {
  return !!entry && (typeof entry.hidden === "boolean" ? entry.hidden : String(entry.name || "").startsWith("."));
}

/** Words for one Files entry: what it is, said without colour. */
export function fileEntryKind(entry) {
  if (isHarnessEntry(entry)) return entry.note;
  if (entry.error) return String(entry.error);
  if (entry.kind === "dir") return "folder";
  if (entry.kind === "link") return "link: not opened here";
  if (entry.kind === "other") return "not a regular file";
  return "file";
}

/** Whether a Files entry can be opened (a folder is entered, a file read). */
export function fileEntryOpens(entry) {
  if (!entry || isHarnessEntry(entry) || entry.error) return false;
  return entry.kind === "dir" || entry.kind === "file";
}

/**
 * The rows the Files tab shows for a listing: hidden (dot) entries only when asked for, then those whose name holds
 * `query` (literal, ignoring case). Order is the daemon's (folders first). `.loom` counts as hidden, so it appears only
 * with Show hidden, as a closed entry.
 */
export function fileRows(entries, { query = "", showHidden = false } = {}) {
  const q = String(query ?? "").trim().toLowerCase();
  return (entries || []).filter((e) => e && typeof e.name === "string"
    && (showHidden || !isHiddenEntry(e))
    && (!q || e.name.toLowerCase().includes(q)));
}

/** The line under the Files list: how much is shown and what is not. */
export function fileListWords(listing, shown, { query = "", showHidden = false } = {}) {
  const total = ((listing && listing.entries) || []).length;
  const parts = [];
  const hiddenCount = ((listing && listing.entries) || []).filter((e) => isHiddenEntry(e)).length;
  if (!total) parts.push("This folder is empty.");
  else if (String(query).trim()) parts.push(`${num(shown)} of ${count(total, "entry", "entries")} match.`);
  else parts.push(`${count(shown, "entry", "entries")}.`);
  if (!showHidden && hiddenCount) parts.push(`${count(hiddenCount, "hidden entry", "hidden entries")} not shown.`);
  if (listing && listing.more > 0) parts.push(`${num(listing.more)} more are not listed; this folder has too many entries to list at once.`);
  return parts.join(" ");
}

/**
 * Files-tab state for one session: the folders read so far (lazily, one request per folder), the folder shown and its
 * filter. `cache` maps a relative folder path to its listing; Refresh drops it.
 */
export function createFilesState(session, workspace) {
  return { session, workspace, path: "", cache: new Map(), query: "", showHidden: false, active: "", loading: null, error: "", seq: 0 };
}

/**
 * Whether the Files tab still has to read its current folder. `loading` is the path being read, and the workspace
 * root's path is the empty string, so it is compared with null: a redraw during the first read of the root must not
 * start a second read that throws the first one (and its focus, pick and mark) away.
 */
export function filesNeedsLoad(st) {
  return !st.cache.has(st.path) && st.loading === null && !st.error;
}

/** The accessible name of a tool row's Open file button: it starts with the visible words (WCAG 2.5.3). */
export function openFileLabel(rel) {
  return `Open file ${rel || "the workspace folder"} in the Files tab`;
}

/** Keep the roving stop on a row that exists: `active` when it is among `rows`, else the first. */
export function activeRowName(rows, active) {
  return (rows || []).some((r) => r.name === active) ? active : ((rows || [])[0] || {}).name || "";
}

/** The next row name for Arrow/Home/End among `rows` (no wrapping), or null when the key is not a move. */
export function stepRowName(rows, active, key) {
  const list = rows || [];
  if (!list.length) return null;
  const at = Math.max(0, list.findIndex((r) => r.name === active));
  if (key === "ArrowDown") return list[Math.min(list.length - 1, at + 1)].name;
  if (key === "ArrowUp") return list[Math.max(0, at - 1)].name;
  if (key === "Home") return list[0].name;
  if (key === "End") return list[list.length - 1].name;
  return null;
}

/**
 * A file's lines, as the viewer pages them: the daemon's `GET …/files/lines` answers like a stored output's lines
 * ({text, first, last, total}), with `total_lines`, `bytes` and `binary` as well. Returns {text, first, last, total, bytes, binary}.
 */
export function fileLinesView(view) {
  const v = view || {};
  const total = Number.isFinite(Number(v.total_lines)) ? Number(v.total_lines) : Number(v.total) || 0;
  const binary = v.binary === true;
  return {
    text: binary ? "" : String(v.text ?? ""),
    first: Number(v.first) || (total > 0 && !binary ? 1 : 0),
    last: binary ? 0 : Number(v.last) || 0,
    total: binary ? 0 : total,
    bytes: Number(v.bytes) || 0,
    binary,
  };
}

/** The line a file's viewer says about where it is: "Modified 3h ago · 12.3 KiB". */
export function fileMetaWords(entry, now) {
  const parts = [];
  if (entry && Number.isFinite(Number(entry.mtime_ms)) && Number(entry.mtime_ms) > 0) {
    const ago = age(now, entry.mtime_ms);
    parts.push(ago === "now" ? "modified just now" : `modified ${ago} ago`);
  }
  if (entry && Number.isFinite(Number(entry.size))) parts.push(byteSize(entry.size));
  return parts.join(" · ");
}

/** The sentence the file viewer carries: this is the file now, not what the agent read. */
export const FILE_NOW_WORDS = "File in the workspace now — it may have changed since the agent read it.";

// ---------------------------------------------------------------------------------------------
// Context card: what the model's request is made of (GET /api/sessions/{id}/window)

/**
 * The parts of a request, in the order the bar and the rows share. `family` picks the colour token (setup, carry, conv,
 * fold), `pattern` the fill (a solid, hatched, dotted, outlined or crossed segment, so a part is told apart by its pattern as
 * well as its colour), `group` the caption its row sits under, `counted` whether its label carries the number of things in it.
 */
export const CTX_PARTS = [
  { key: "system", label: "System prompt", family: "setup", pattern: "solid", group: "setup" },
  { key: "tools", label: "Tool definitions", family: "setup", pattern: "hatch", group: "setup", counted: true },
  { key: "rules", label: "Rules and approvals", family: "setup", pattern: "dots", group: "setup", note: "Yours, verbatim; never folded." },
  { key: "assignment", label: "Assignment from parent", family: "setup", pattern: "outline", group: "setup" },
  { key: "compaction", label: "Compaction", family: "carry", pattern: "cross", group: "carry", note: "What replaced everything before the last few steps: the head, your messages, the ledger, pins, the key table and the model's note. The note is written by the model and is not verified." },
  { key: "resume", label: "Re-weave brief", family: "carry", pattern: "hatch", group: "carry", note: "Written when older context was folded; may include leads written by the model, not verified." },
  { key: "notes", label: "Harness notes", family: "carry", pattern: "dots", group: "carry", counted: true },
  { key: "conversation", label: "Messages and replies", family: "conv", pattern: "solid", group: "conv", always: true },
  { key: "tool_output", label: "Tool output", family: "conv", pattern: "hatch", group: "conv", counted: true },
  { key: "pinned", label: "Pinned output", family: "conv", pattern: "dots", group: "conv", counted: true },
  { key: "agent_reports", label: "Agent reports", family: "conv", pattern: "cross", group: "conv", counted: true },
  { key: "images", label: "Images", family: "conv", pattern: "outline", group: "conv", counted: true, note: "Estimated from each image's size; only a model that takes images is sent them." },
  { key: "stubs", label: "Folded-out stubs", family: "fold", pattern: "dashed", group: "fold", counted: true, note: "The full output stays in the record." },
  { key: "other", label: "Other records", family: "fold", pattern: "light", group: "fold" },
  { key: "framing", label: "Message framing", family: "fold", pattern: "light", group: "fold" },
  { key: "hud", label: "Harness state (as last sent)", family: "carry", pattern: "solid", group: "sent", note: "Sent fresh at the end of each request; never cached or folded; size as last sent." },
];
export const CTX_GROUPS = { setup: "Setup", carry: "Carried over", conv: "Conversation", fold: "Folded and framing", sent: "This request only" };

/** Widths below this share of the window are widened to it, and parts too small to hold it are merged into one sliver. */
export const CTX_MIN_PCT = 0.8;

/**
 * Bar widths for `segments` ([{key, tokens}]) against `scale` tokens, in percent. A nonzero part narrower than `minPct` is
 * widened to it, the excess taken in proportion from the parts at least four times as wide; when the bar is too small to
 * hold every minimum, the narrow parts become one sliver ({key: "small", merged: [keys]}) of their true width. The widths
 * always add up to what the tokens say, so a small part never inflates the fill. Returns [{key, pct, merged?}].
 */
export function segmentLayout(segments, scale, { minPct = CTX_MIN_PCT } = {}) {
  const base = (segments || []).filter((s) => s && s.tokens > 0).map((s) => ({ key: s.key, pct: scale > 0 ? (100 * s.tokens) / scale : 0 }));
  const tiny = base.filter((s) => s.pct < minPct);
  if (!tiny.length) return base;
  const donors = base.filter((s) => s.pct >= 4 * minPct);
  const need = tiny.reduce((sum, s) => sum + (minPct - s.pct), 0);
  const pool = donors.reduce((sum, s) => sum + s.pct, 0);
  if (donors.length && pool - need >= donors.length * 3 * minPct) {
    return base.map((s) => {
      if (s.pct < minPct) return { key: s.key, pct: minPct };
      return donors.includes(s) ? { key: s.key, pct: s.pct - (need * s.pct) / pool } : s;
    });
  }
  const sliver = { key: "small", pct: tiny.reduce((sum, s) => sum + s.pct, 0), merged: tiny.map((s) => s.key) };
  const out = [];
  let placed = false;
  for (const s of base) {
    if (s.pct >= minPct) out.push(s);
    else if (!placed) { out.push(sliver); placed = true; }
  }
  return out;
}

function ctxPercent(part, whole) {
  if (!(whole > 0) || !(part > 0)) return 0;
  return (100 * part) / whole;
}

/** "58%", "<1%" for a share above 0 and under a half, "0%" for none. */
export function percentWords(share) {
  if (!(share > 0)) return "0%";
  return share < 0.5 ? "<1%" : Math.round(share) + "%";
}

/**
 * The context card from a `/window` answer: {parts, hero, sub, basis, bar, rows, fold, cache, notes} or, for an answer without a
 * breakdown (an older daemon), {parts: false, hero, ...} with only what that answer holds.
 *
 *   hero  {figure:"~151k", approx, denominator:"of 262k tokens", exact:"262,144 tokens", percent:"58%", share, windowKnown}
 *   sub   one sentence on where the figure comes from
 *   basis one sentence on how the parts were estimated (null without parts)
 *   bar   {scale, scaleNote, segments:[{key,label,tokens,pct,family,pattern,labelled}], free:{pct,tokens}|null, label (for aria)}
 *   rows  [{key,label,count,value:"~4.9k",tokens,share,family,pattern,group,note}], dropping a zero part except Messages and replies
 *   fold  {at, to, text, past:{text}|null} marks drawn only when both are known and inside the scale
 *   cache {cached, fresh, of, text, none} of the last counted request, or null
 *   notes [{label, note}] the row notes, behind one disclosure
 */
export function contextCardModel(w) {
  const win = Number(w && w.context_window) || 0;
  const b = w && w.breakdown;
  const segs = b && Array.isArray(b.segments) ? b.segments : [];
  const parts = segs.length > 0;
  const total = parts ? Number(b.total_tokens) || 0 : Number(w && w.est_tokens) || 0;
  const last = (w && w.last_request) || null;
  const counted = last && last.prompt_tokens > 0 ? last.prompt_tokens : 0;
  const measured = Number(w && w.measured_now) > 0 ? Number(w.measured_now) : 0;
  const approx = !(measured > 0 && measured === counted && total === measured);
  const share = ctxPercent(total, win);
  const hero = {
    figure: (approx ? "~" : "") + tokens(total),
    approx,
    tokens: total,
    denominator: win ? `of ${tokens(win)} tokens` : "tokens · limit unknown",
    exact: win ? `${num(win)} tokens` : "",
    percent: win ? percentWords(share) : "",
    share,
    windowKnown: win > 0,
  };
  let sub;
  if (measured && counted) {
    const added = Math.max(0, measured - counted);
    sub = `Last request ${tokens(counted)}, counted by the server${added > 0 ? ` · about ${tokens(added)} added since` : ""}`;
  } else if (measured) {
    sub = "Counted by the server at the last answered request, plus an estimate of what was added since.";
  } else {
    sub = "Estimated from characters; no request in this context epoch has been counted yet.";
  }
  let basis = null;
  if (parts) {
    const cpt = Number(b.chars_per_token) || 0;
    basis = b.basis === "scaled_to_measured"
      ? `Parts estimated from characters and scaled to the total (${cpt.toFixed(2)} characters a token).`
      : `Parts estimated from characters at ${trimZeros(cpt.toFixed(1))} a token; not yet checked against a server count.`;
  }
  const byKey = new Map(segs.map((s) => [s.key, s]));
  const rows = [];
  const barParts = [];
  // A session that has been compacted shows the Compaction part; the re-weave parts stay for sessions that have none.
  const compacted = Number(byKey.get("compaction") && byKey.get("compaction").tokens) > 0;
  for (const def of parts ? CTX_PARTS : []) {
    if (compacted && (def.key === "resume" || def.key === "stubs")) continue;
    const seg = byKey.get(def.key);
    const t = seg ? Number(seg.tokens) || 0 : 0;
    if (!(t > 0) && !def.always) continue;
    const n = seg && Number.isFinite(seg.count) && def.counted ? seg.count : null;
    const label = n === null ? def.label : `${def.label} · ${num(n)}`;
    rows.push({ key: def.key, label, count: n, value: "~" + tokens(t), tokens: t, share: ctxPercent(t, total), family: def.family, pattern: def.pattern, group: def.group, note: def.note || "" });
    barParts.push({ key: def.key, tokens: t });
  }
  // `compact_at` (the compaction threshold) replaces the fold bounds when the daemon sends it.
  const compactAt = Number(w && w.compact_at) || 0;
  const foldAt = compactAt || Number(w && w.fold_at) || 0;
  const foldTo = compactAt ? 0 : Number(w && w.fold_to) || 0;
  const known = win > 0;
  const scale = known ? win : Math.max(foldAt * 1.25, total * 1.1, 1);
  const layout = segmentLayout(barParts, scale);
  const defs = new Map(CTX_PARTS.map((d) => [d.key, d]));
  const segments = layout.map((l) => {
    if (l.merged) return { key: "small", label: "Small parts", tokens: l.merged.reduce((sum, k) => sum + (byKey.get(k) ? Number(byKey.get(k).tokens) || 0 : 0), 0), pct: l.pct, family: "fold", pattern: "light", labelled: false, merged: l.merged };
    const d = defs.get(l.key);
    const row = rows.find((r) => r.key === l.key);
    return { key: l.key, label: d.label, tokens: row ? row.tokens : 0, pct: l.pct, family: d.family, pattern: d.pattern, labelled: l.pct >= 18 };
  });
  const filled = layout.reduce((sum, s) => sum + s.pct, 0);
  const freePct = known ? Math.max(0, 100 - filled) : 0;
  const spoken = rows.filter((r) => r.tokens > 0).map((r) => `${r.label.replace(/ · \d.*$/, "")} ${percentWords(ctxPercent(r.tokens, known ? win : total))}`);
  if (known) spoken.push(`free ${percentWords(freePct)}`);
  const barLabel = known
    ? `Context use ${hero.percent} of ${num(win)} tokens: ${spoken.join(", ")}`
    : `Context use about ${tokens(total)} tokens, limit unknown: ${spoken.join(", ")}`;
  const inside = (v) => v > 0 && v <= scale;
  const foldInfo = foldAt > 0 && inside(foldAt) ? {
    at: foldAt, to: foldTo, atPct: ctxPercent(foldAt, scale), toPct: foldTo > 0 && inside(foldTo) ? ctxPercent(foldTo, scale) : null,
    word: compactAt ? "compacts" : "folds",
    text: foldTo > 0 ? `▼ folds at ${tokens(foldAt)} · ▽ down to ${tokens(foldTo)}` : `▼ ${compactAt ? "compacts" : "folds"} at ${tokens(foldAt)}`,
    past: total > foldAt ? { text: compactAt ? "Past the compaction mark: the context compacts at the next step." : "Past the fold mark: older output folds at the next step." } : null,
  } : null;
  let cache = null;
  if (last && counted > 0) {
    const cached = Math.min(Math.max(0, Number(last.cached_tokens) || 0), counted);
    cache = {
      cached, fresh: counted - cached, of: counted, none: cached === 0,
      text: cached === 0 ? "No cached tokens reported. The server may not report caching."
        : `Last request: ${tokens(cached)} from the cache · ${tokens(counted - cached)} read anew`,
    };
  }
  return {
    parts, hero, sub, basis,
    bar: { scale, known, scaleNote: known ? "" : "scale: fold mark + 25%", segments, free: known ? { pct: freePct, tokens: Math.max(0, win - total) } : null, label: barLabel },
    rows, fold: foldInfo, cache,
    notes: [...rows.filter((r) => r.note).map((r) => ({ label: r.label.replace(/ · \d.*$/, ""), note: r.note }))],
  };
}
