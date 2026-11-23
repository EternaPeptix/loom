// app.js: the DOM and the network. Every decision that can be wrong lives in core.js.
// Text from records, tools and the network is only ever put into the page with textContent or
// text nodes. Prose formatting creates a small set of semantic elements; source HTML stays inert.

import * as C from "./core.js";

const $ = (id) => document.getElementById(id);

// Layout follows the width; input behaviour follows the pointer, so a narrow window with a mouse keeps Enter-to-send.
const PHONE = matchMedia("(max-width: 699px)");
const COMPACT = matchMedia("(max-width: 699px), (max-height: 700px)"); // the whole session scrolls as one
const COARSE = matchMedia("(pointer: coarse)");
/** The one element that scrolls the chat: the session view where it scrolls as a whole, else the record's own scroller. */
// Phones scroll the whole session as one, but only the Chat tab follows the stream: other tabs write to the hidden chat scroller.
const chatScroller = () => (COMPACT.matches && S.section === "chat" ? $("view-session") : $("scroller"));

// ---------------------------------------------------------------------------------------------
// State

const S = {
  sessions: C.createSessionStore(),
  inbox: C.createInbox(),
  status: null,
  connected: false,
  connectedSince: null, // when the event stream last connected: the quiet note counts only the time the page has listened
  everConnected: false,
  lastUpdate: 0,
  lastStatus: 0,
  statusError: null,
  showArchived: false,
  expanded: new Set(),
  latest: new Map(),
  drafts: C.createDraftStore(),
  sending: new Set(),
  answering: new Set(),
  answered: new Map(),
  messageState: new Map(),
  actionState: new Map(),
  stopAsked: new Set(), // sessions this tab asked to stop: their ending is not announced
  notes: { pending: [], shown: new Map(), timer: 0 },
  requests: { ledger: 0, window: 0, net: 0, inbox: 0, status: 0, models: 0 },
  inboxRevision: 0,
  inboxTouched: new Map(), // item id -> {rev, entry|null}: what inbox records changed, kept over an older snapshot
  sinceSeq: null,
  jumpFrom: null, // the last record seq held when the operator scrolled away from the end (the count behind Jump to latest)
  ask: null, // an inline confirmation waiting in the inspector: {kind:"compact"} | {kind:"lead", lead, value} | {kind:"role", lead, role, value}
  headAsk: null, // an inline confirmation waiting in the session header: {kind:"stop"|"archive", session}
  section: "chat",
  profiles: null, // GET /api/models for the model seat: {default_model, models: [...]} (null until fetched)
  seat: null, // a model switch waiting for the operator's answer: {session, profile}
  seatBusy: new Set(), // ids of the sessions a model switch is in flight for (a switch holds only its own session's seat)
  seatNote: new Map(), // session id -> {text, at}: the sentence the last switch ended with
  stamp: 0, // an increasing counter: the newer of a switch note and a message state is the one the status line shows
  attempts: 0, // failed attempts to open the event stream in a row
  workState: new Map(), // work group key -> true (operator opened it) | false (operator folded it)
  openGroups: new Set(), // work groups kept expanded while scrolled away from the end
  expandAll: false,
  details: false,
  activity: new Map(), // session id -> {seq, ts} of the latest record seen on the stream
  watermarks: new Map(), // session id -> last seq seen on the last visit (from sessionStorage, kept live for the open one)
  watermarkRead: new Set(),
  goalOpen: false,
  runTimer: 0,
  claimFilter: "all", // which claims the Evidence view lists
  view: "empty", // empty | session | inbox | new
  openId: null,
  inspectorPref: false, // desktop inspector open preference across non-session routes
  childBlocker: null,
  newForm: { model: null, agentModel: null },
  rec: null, // record store of the open session
  r: null, // what is rendered of it: {from, end, nodes, fresh}
  follow: true,
  scrollAt: {}, // the session view's scroll position per section, kept in memory while it scrolls as a whole
  jumpNeed: null,
  sheet: { open: false, notesOpen: false, ask: null, opener: null, sig: "", say: "", restore: true }, // the session details sheet
  tab: "ledger",
  score: { mission: null, view: null, error: null, lastMs: null, loading: false }, // GET /api/missions/{id}/score of the open mission (Agents tab)
  agentsEnded: false, // the Ended group of the Agents tab is open (this page only)
  agentsActive: null, // the agent row that holds the roving tab stop
  ledger: { mission: null, model: null, state: null, error: null, stale: true },
  // The Models tab: the open mission's models (`GET /api/sessions/{id}/models`).
  models: { view: null, error: "", loading: false, busy: false, now: false },
  win: { data: null, error: null, stale: true, hideFolded: false, from: null, notesOpen: false },
  rules: null, // the rules form of the open session: {session, box, note, hint, lists, reason, asking, shown}
  net: [],
  netError: null,
  viewer: null,
  copyOnSelect: false, // the "Copy on select" preference (localStorage, off until turned on)
  files: null, // the Files tab of the open session (C.createFilesState + its DOM), made on first need
  liveEl: null,
  now: Date.now(),
};

// ---------------------------------------------------------------------------------------------
// Small DOM helpers (text only)

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function add(parent, ...kids) {
  for (const k of kids) if (k) parent.append(k);
  return parent;
}
function btn(label, cls, onClick) {
  const b = el("button", "btn " + (cls || ""), label);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}
function clear(node) {
  node.replaceChildren();
}
function link(text, hash) {
  const a = el("a", "", text);
  a.setAttribute("href", hash);
  return a;
}

// Icons are drawings kept in index.html and cloned here, so no markup is built from strings.
function icon(name) {
  const drawing = $("icons").content.querySelector(`[data-icon="${name}"]`);
  return drawing ? drawing.cloneNode(true) : document.createTextNode("");
}
function markEl(mark) {
  const m = add(el("span", "mark mark-" + mark), icon(C.markIcon(mark)));
  m.title = C.markWords(mark);
  return m;
}
/** A small labelled fact. `tone` picks the colour; the icon and the words carry the meaning. */
function pill(text, tone, iconName, cls = "pill") {
  const p = el("span", cls + (tone ? ` ${cls}-${tone}` : ""));
  if (iconName) p.append(icon(iconName));
  p.append(document.createTextNode(text));
  return p;
}
const chip = (text, tone, iconName) => pill(text, tone, iconName, "chip");
/** The mark of a plan step: a drawing whose name is the status in words. */
function stepMarkEl(status) {
  const mark = add(el("span", "step-mark"), icon(C.stepIcon(status)));
  mark.setAttribute("role", "img");
  mark.setAttribute("aria-label", C.stepWords(status));
  return mark;
}
function heading(tag, text, ...aside) {
  return add(el("div", "section-heading"), el(tag, "", text), ...aside);
}
const clock = (ms) => new Date(ms).toLocaleTimeString();
const ago = (ms) => { const age = C.age(Date.now(), ms); return age === "now" ? "just now" : age + " ago"; };

function remember(key, value) {
  try { sessionStorage.setItem("loom.ui." + key, JSON.stringify(value)); } catch { /* private browsing may refuse storage */ }
}

function recalled(key, fallback) {
  try { return JSON.parse(sessionStorage.getItem("loom.ui." + key)) ?? fallback; } catch { return fallback; }
}

function preserveFocus(container, render) {
  const active = document.activeElement;
  const key = container.contains(active) ? active.dataset.focusKey || active.dataset.draftKey : null;
  const selection = key && typeof active.selectionStart === "number" ? [active.selectionStart, active.selectionEnd] : null;
  const inside = container.contains(active) && active !== container;
  render();
  // Moving a node in the list blurs it even though it is still there: give the focus back to the same element.
  if (!key && inside && active.isConnected && document.activeElement !== active) { active.focus({ preventScroll: true }); return; }
  if (!key || document.activeElement === active) return;
  const target = [...container.querySelectorAll("[data-focus-key], [data-draft-key]")]
    .find((n) => n.dataset.focusKey === key || n.dataset.draftKey === key);
  if (target) {
    target.focus({ preventScroll: true });
    if (selection && typeof target.setSelectionRange === "function") target.setSelectionRange(...selection);
  }
}

function setDraft(key, text, origin) {
  C.setDraft(S.drafts, key, text);
  for (const input of document.querySelectorAll("[data-draft-key]")) {
    if (input !== origin && input.dataset.draftKey === key) input.value = text;
  }
}

/** Every `out:<hex>` in the text nodes under `root` becomes a button that opens that stored output. */
function linkOutKeys(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) if (n.nodeValue.includes("out:")) nodes.push(n);
  for (const node of nodes) {
    const parts = C.splitOutKeys(node.nodeValue);
    if (!parts.some((p) => p.key)) continue;
    node.replaceWith(...parts.map((p) => (p.key ? outKeyButton(p.key) : document.createTextNode(p.text))));
  }
  return root;
}

function outKeyButton(key) {
  const b = btn("out:" + key, "link mono keylink", (e) => openViewer(key, "Output out:" + key, null, {}, e.currentTarget));
  b.title = "Open the stored output out:" + key;
  return b;
}

/** Monospace text whose `out:` keys are buttons. */
function keyedText(text, cls = "txt out") {
  const box = el("pre", cls);
  box.append(...C.splitOutKeys(text).map((p) => (p.key ? outKeyButton(p.key) : document.createTextNode(p.text))));
  return box;
}

function prose(text) {
  const root = el("div", "prose");
  const inline = (target, parts) => {
    for (const part of parts) target.append(part.type === "text" ? document.createTextNode(part.text) : el(part.type, "", part.text));
  };
  for (const block of C.proseTree(text)) {
    if (block.type === "pre") {
      const pre = add(el("pre", "out"), el("code", "", block.text));
      root.append(add(el("div", "codeblock reveal-copy"), pre, copyButton("Copy code", () => C.codeCopyText(block), { what: "Code", source: pre })));
    }
    else if (block.type === "ul" || block.type === "ol") {
      const list = el(block.type);
      for (const item of block.items) { const li = el("li"); inline(li, item); list.append(li); }
      root.append(list);
    } else {
      const node = el(block.type === "h" ? "h3" : "p");
      inline(node, block.inline);
      root.append(node);
    }
  }
  return root;
}

// ---------------------------------------------------------------------------------------------
// Network

// The page signs in with a single-use code from the URL fragment, trades it for a web-session
// secret and sends that as a bearer on every request. No cookie is involved.
const SECRET_KEY = "loom_web_secret";
let secret = null; // also kept in sessionStorage when the browser allows it
let streamCtl = null;
let streamStopped = false;

function storedSecret() {
  try {
    return sessionStorage.getItem(SECRET_KEY);
  } catch {
    return null;
  }
}
function keepSecret(value) {
  secret = value;
  try {
    if (value) sessionStorage.setItem(SECRET_KEY, value);
    else sessionStorage.removeItem(SECRET_KEY);
  } catch {
    // storage is blocked; the secret stays in memory for this page load
  }
}

/** Exchange the code in the fragment (if any) for a secret; true when the page has one. */
async function signIn() {
  const code = C.codeFromHash(location.hash);
  if (code) {
    try {
      history.replaceState(null, "", location.pathname + location.search);
    } catch {
      // the fragment stays visible; the code is single use anyway
    }
    try {
      const r = await fetch("/api/web-sessions", {
        method: "POST",
        credentials: "omit",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      if (r.ok) {
        const j = await r.json();
        if (j && typeof j.secret === "string") keepSecret(j.secret);
      }
    } catch {
      // unreachable or refused: fall back to a stored secret, else the "run loom open" page
    }
  }
  if (!secret) secret = storedSecret();
  return !!secret;
}

function authHeaders(extra) {
  return { ...(extra || {}), Authorization: "Bearer " + secret };
}

function lost() {
  streamStopped = true;
  if (streamCtl) streamCtl.abort();
  keepSecret(null);
  document.body.replaceChildren(el("p", "pad", C.LOST_TOKEN));
}

async function api(method, path, body) {
  const init = { method, credentials: "omit", headers: authHeaders() };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const r = await fetch(path, init);
  if (r.status === 401) {
    lost();
    throw new Error(C.LOST_TOKEN);
  }
  const text = await r.text();
  if (!r.ok) { const error = new Error(C.errorSentence(r.status, text)); error.status = r.status; throw error; }
  return text ? JSON.parse(text) : null;
}

function notice(text) {
  $("notice-text").textContent = text;
  $("notice").hidden = false;
}

async function act(promise) {
  try {
    return await promise;
  } catch (e) {
    notice(e.message);
    return undefined;
  }
}

// ---------------------------------------------------------------------------------------------
// Scheduling DOM work

const needs = { list: false, header: false, blocks: false, live: false, right: false, overview: false, sheet: false };
let raf = 0;
function want(...keys) {
  for (const k of keys) needs[k] = true;
  if (!raf) raf = requestAnimationFrame(flush);
}
function flush() {
  raf = 0;
  const n = { ...needs };
  for (const k of Object.keys(needs)) needs[k] = false;
  S.now = Date.now();
  if (n.list) renderList();
  if (n.header) renderHeader();
  if (n.blocks) renderBlocks();
  if (n.live) renderLive();
  if (n.right) renderRight();
  if (n.overview) renderOverview();
  if (n.sheet) renderSheet();
}

// ---------------------------------------------------------------------------------------------
// Left column

function inboxCount(id) {
  return C.attentionFor(S.inbox, id);
}

function loadWatermarks() {
  for (const id of S.sessions.byId.keys()) {
    if (S.watermarkRead.has(id)) continue;
    S.watermarkRead.add(id);
    const seen = recalled("seen." + id, null);
    if (Number.isInteger(seen) && !S.watermarks.has(id)) S.watermarks.set(id, seen);
    // The latest record seen on an earlier page load: ages and "new" marks survive a reload instead of starting unknown.
    const last = recalled("activity." + id, null);
    if (last && Number.isInteger(last.seq) && Number.isFinite(last.ts) && !S.activity.has(id)) S.activity.set(id, { seq: last.seq, ts: last.ts });
  }
}

const activityDirty = new Set();
let activityTimer = 0;
/** Keep the latest record seen per session beside the watermarks, at most once a second. */
function persistActivity(session) {
  activityDirty.add(session);
  if (activityTimer) return;
  activityTimer = setTimeout(() => {
    activityTimer = 0;
    for (const id of activityDirty) { const a = S.activity.get(id); if (a) remember("activity." + id, a); }
    activityDirty.clear();
  }, 1000);
}

/**
 * The identity line of a row, mono: "profile · role · age". The profile never shrinks or truncates; the rest may be cut.
 * When something waits on the operator the reason is its own line below (amber, with its own shape for a blocking
 * request; blue and green for a question and a ready result).
 */
function identityEl(identity) {
  const line = el("span", "ident");
  const [profile, role, tail] = identity.parts;
  const rest = identity.waiting || !tail ? role : `${role} · ${tail}`;
  const head = add(el("span", "ident-line"), el("span", "ident-profile", profile), el("span", "ident-text", " · " + rest));
  // An unknown age is left out of the line; the tooltip says why there is none.
  if (!identity.known && !identity.waiting) head.title = "Last activity: not loaded yet (open the mission to load its records)";
  add(line, head);
  if (identity.waiting) {
    const w = identity.waiting;
    const note = add(el("span", "ident-wait tone-" + (w.tone || "quiet")), icon(w.icon), el("span", "ident-text", w.text));
    if (w.tip) note.title = w.tip;
    add(line, note);
  }
  return line;
}

function renderList() {
  const box = $("sessions");
  loadWatermarks();
  const groups = C.workspaceGroups(S.sessions, S.inbox, S.watermarks, S.now, { showArchived: S.showArchived, expanded: S.expanded, activity: S.activity });
  const frag = document.createDocumentFragment();
  for (const group of groups) {
    if (!group.rows.length) continue;
    const section = el("section", "mission-group" + (group.key === "needs_you" ? " needs-group" : ""));
    section.setAttribute("aria-label", group.label);
    const missions = group.rows.filter((row) => !row.depth).length;
    // The space is not drawn between the two ends of the heading; it keeps them two words when read out.
    const head = add(el("h2", "group-title"), el("span", "", group.label), document.createTextNode(" "), el("span", "group-count", String(missions)));
    head.title = group.tip;
    section.append(head);
    for (const row of group.rows) {
      const { info, depth, agentCount, agentsRunning, expanded, mark } = row;
      const wrap = el("div", "mission-row");
      const a = el("a", `row d${Math.min(depth, 2)}${mark.mark === "needs_you" ? " needs" : ""}${info.id === S.openId && S.view === "session" ? " sel" : ""}${info.archived ? " arch" : ""}`);
      a.setAttribute("href", C.sessionHash(info.id));
      a.dataset.focusKey = "session:" + info.id;
      if (info.id === S.openId) a.setAttribute("aria-current", "page");
      const m = add(el("span", "mark mark-" + (mark.tone || "dim")), icon(mark.icon), el("span", "sr-only", mark.words + ": "));
      // What waits on the operator is the row's reason; failing that, a running session with no new record for a while says so.
      const quiet = row.identity.waiting ? null : C.quietFor(info, row.recordedMs, S.now, S.connectedSince);
      const identity = quiet ? { ...row.identity, waiting: quiet } : row.identity;
      const main = add(el("span", "row-main"), el("span", "name", info.title || info.id), identityEl(identity));
      add(a, m, main);
      // Everything the old second line said stays reachable as the row's description.
      a.title = C.rowSummary(row, S.latest.get(info.id), S.now);
      wrap.append(a);
      if (!depth && agentCount) {
        const toggle = btn("", "link agent-toggle", () => {
          if (S.expanded.has(info.id)) S.expanded.delete(info.id); else S.expanded.add(info.id);
          want("list");
        });
        const agents = C.count(agentCount, "agent") + (agentsRunning ? ` · ${agentsRunning} running` : "");
        add(toggle, icon("chevron"), document.createTextNode(agents));
        toggle.setAttribute("aria-expanded", String(expanded));
        // The name starts with the visible words, so speech input can target what is on screen.
        toggle.setAttribute("aria-label", `${agents} of ${info.title || info.id}`);
        toggle.dataset.focusKey = "agents:" + info.id;
        wrap.append(toggle);
      }
      section.append(wrap);
    }
    frag.append(section);
  }
  if (!frag.childNodes.length) frag.append(el("p", "dim pad", "No missions yet. Start a mission with New mission."));
  preserveFocus(box, () => box.replaceChildren(frag));
}

function renderDot() {
  const models = (S.status && S.status.models) || [];
  const d = C.healthDot({ connected: S.connected, models });
  const dot = $("dot");
  dot.className = "dot dot-" + d.state;
  dot.title = d.tip;
  const state = $("connection-state");
  // The sidebar line stays short ("Live", "Reconnecting…", "Offline"); the detail is its tooltip.
  const words = C.connectionWords({
    connected: S.connected, everConnected: S.everConnected, attempts: S.attempts, statusError: S.statusError, models,
    lastUpdateText: S.lastUpdate ? `Last update ${ago(S.lastUpdate)}` : "Waiting for first update",
  });
  if (state) {
    state.textContent = words.short;
    state.title = words.tip;
  }
  const wrap = $("connection-wrap");
  if (wrap) wrap.title = words.tip;
  // The bar speaks the loss of the connection only where the sidebar is a closed drawer (under 700px); beside the open sidebar it would be said twice.
  const bar = $("bar-connection");
  if (bar) bar.textContent = !S.connected && PHONE.matches ? `${words.short} · execution state unknown` : "";
  $("bar-offline").hidden = S.connected || S.view !== "session";
  // A run chip counts up only while the stream is up: it changes with the connection.
  if (S.view === "session") want("header");
}

function renderDiskWarning() {
  const box = $("disk-warning");
  const text = C.diskWarning(S.status && S.status.disk);
  box.textContent = text || "";
  box.hidden = !text;
}

function updateInboxBadge() {
  const c = C.inboxCounts(S.inbox);
  const b = $("btn-inbox");
  const n = $("inbox-count");
  n.textContent = String(c.open);
  n.hidden = c.open === 0;
  b.classList.toggle("urgent", c.blocking > 0);
  const inboxLabel = c.open === 0
    ? "Inbox: nothing waiting"
    : c.blocking > 0
      ? `Inbox: ${c.open} open, ${c.blocking} ${c.blocking === 1 ? "needs" : "need"} you`
      : `Inbox: ${c.open} open`;
  // The red "urgent" tint is the only on-screen signal that some items block work; give the same
  // information in text so it does not depend on colour (a screen reader reads this label).
  b.setAttribute("aria-label", inboxLabel);
  const eb = $("empty-inbox");
  const en = $("empty-inbox-count");
  en.textContent = String(c.open);
  eb.hidden = c.open === 0;
  eb.classList.toggle("urgent", c.blocking > 0);
  eb.setAttribute("aria-label", inboxLabel);
  document.title = C.pageTitle(c);
  // The Missions button on a phone says how many need the operator: a diamond and a number, and the same in words.
  $("bar-needs").hidden = c.blocking === 0;
  $("bar-needs-n").textContent = String(c.blocking);
  $("open-left").setAttribute("aria-label", C.missionsLabel(c.blocking));
  if (S.view === "inbox") renderInbox();
  want("list", "header", "overview");
}

// ---------------------------------------------------------------------------------------------
// Navigation

function route() {
  const r = C.parseRoute(location.hash);
  setDrawer("left", false);
  if (r.view === "session") {
    // The old name of the chat tab (/record) is rewritten in place, so Back does not return to it.
    if (r.rewrite) { try { history.replaceState(null, "", r.rewrite); } catch { /* the old address still works */ } }
    setSection(r.section, false);
    return openSession(r.session);
  }
  if (r.view === "inbox") return showInbox();
  if (r.view === "new") return showNew();
  setView("empty");
}

function setView(v) {
  const was = S.view;
  S.view = v;
  if (was === "session" && v !== "session") {
    saveSeen();
    if (!matchMedia("(max-width: 1099px)").matches) S.inspectorPref = document.body.classList.contains("show-right");
    if (document.body.classList.contains("show-right")) setDrawer("right", false);
  }
  if (v !== "session") { renderStats(); stopRunTimer(); hideBarIdentity(); $("child-blocker").hidden = true; want("right"); }
  $("view-empty").hidden = v !== "empty";
  $("view-session").hidden = v !== "session";
  $("view-inbox").hidden = v !== "inbox";
  $("view-new").hidden = v !== "new";
  if (v === "session") {
    markRead();
    if (was !== "session" && !matchMedia("(max-width: 1099px)").matches && S.inspectorPref && !document.body.classList.contains("show-right")) {
      setDrawer("right", true);
    }
  }
  want("list");
}

function openSession(id) {
  closeNotes({ session: id });
  if (S.openId === id && S.rec) {
    if (S.view !== "session") {
      S.sinceSeq = recalled("seen." + id, null);
      if (!toastKeep) dismissToast();
    }
    toastKeep = false;
    setView("session");
    markRead(); // what happened while the operator was elsewhere is on screen now: the row is no longer "new"
    want("header", "blocks", "right", "overview");
    return;
  }
  if (!toastKeep) dismissToast();
  toastKeep = false;
  saveSeen();
  S.openId = id;
  S.headAsk = null;
  hideHeadConfirm();
  S.seatNote.delete(id); // a switch sentence from an earlier visit is not news
  let ancestor = S.sessions.byId.get(id)?.parent;
  const walked = new Set();
  while (ancestor && !walked.has(ancestor)) { walked.add(ancestor); S.expanded.add(ancestor); ancestor = S.sessions.byId.get(ancestor)?.parent; }
  S.sinceSeq = recalled("seen." + id, null);
  S.rec = C.createRecordStore(id);
  S.rec.initialComplete = false;
  S.r = { from: 0, end: 0, nodes: new Map(), items: [], forced: new Set(), fresh: true, landed: false };
  S.workState = new Map();
  S.openGroups = new Set();
  S.scrollAt = {};
  S.seat = null;
  S.follow = true;
  S.goalOpen = false;
  S.net = [];
  S.netError = null;
  S.liveEl = null;
  S.win = { ...S.win, data: null, error: null, stale: true, from: null, notesOpen: false };
  S.ledger = { mission: null, model: null, state: null, error: null, stale: true };
  S.rules = null;
  S.ask = null;
  S.jumpFrom = null;
  S.childBlocker = null;
  $("child-blocker").hidden = true;
  closeFind(false);
  const opened = S.sessions.byId.get(id);
  S.ledger.mission = opened ? opened.mission : null;
  clear($("blocks"));
  clear($("live"));
  $("loading").hidden = false;
  $("earlier").hidden = true;
  setView("session");
  clear($("mission-overview"));
  clear($("mission-agents"));
  clear($("mission-evidence"));
  if (!opened || S.score.mission !== opened.mission) S.score = { mission: null, view: null, error: null, lastMs: null, loading: false };
  S.agentsActive = null;
  $("msg").value = C.getDraft(S.drafts, "message:" + id);
  $("msg").dataset.draftKey = "message:" + id;
  renderChips(attachCtx.composer);
  want("header", "blocks", "live", "right", "overview");
  loadProfiles();
  S.queued = { session: null, items: [], error: "", editing: null, editText: "", busy: new Set() };
  renderQueue();
  loadQueued();
  loadRecords(S.rec, 0);
  loadNet();
  loadLedger();
  if (S.tab !== "ledger") loadTab();
}

/**
 * Loads the tail of a long session first: the records after the latest compaction (or the last 1,000), then whatever arrived since by
 * `after`. Records before them load on "Load earlier records" or when Find asks. A daemon without `before` paging is read from the start.
 */
async function loadTail(store) {
  const page = await api("GET", C.recordsUrl(store.session, null, C.TAIL_LIMIT, C.TAIL_BEFORE));
  if (S.rec !== store) return;
  if (!C.pagesBackward(page)) {
    // An older daemon ignores `before` and answers the first page: apply it and let the forward loop go on.
    C.applyRecords(store, page.records);
    for (const record of page.records) noteActivity(store.session, record);
    store.prevBefore = null;
    return;
  }
  let recs = page.records;
  let prev = page.prev_before ?? null;
  for (let more = C.tailNeedsMore(recs, prev); more; more = C.tailNeedsMore(recs, prev)) {
    const earlier = await api("GET", C.recordsUrl(store.session, null, more.limit, more.before));
    if (S.rec !== store) return;
    recs = [...earlier.records, ...recs];
    prev = earlier.prev_before ?? null;
  }
  let prelude = [];
  if (recs.length && recs[0].seq > 0) {
    // The session's own first records carry the start facts of the Session tab.
    const head = await api("GET", C.recordsUrl(store.session, null, 3));
    if (S.rec !== store) return;
    prelude = head.records || [];
  }
  C.startTailStore(store, recs, prev, prelude);
  for (const record of recs) noteActivity(store.session, record);
}

async function loadRecords(store, tries) {
  if (store.loading) return;
  store.loading = true;
  try {
    if (!store.tailed) {
      await loadTail(store);
      if (S.rec !== store) return;
      store.tailed = true;
      updateDelivery(store.session);
      want("blocks", "header", "overview", "list");
    }
    let after = C.lastSeq(store);
    for (;;) {
      const page = await api("GET", C.recordsUrl(store.session, after, 500));
      if (S.rec !== store) return;
      C.applyRecords(store, page.records);
      for (const record of page.records) noteActivity(store.session, record);
      updateDelivery(store.session);
      want("blocks", "header", "overview", "list");
      if (page.next_after === null || page.next_after === undefined) break;
      after = page.next_after;
    }
    $("loading").hidden = true;
    // Where the session scrolls as a whole (a phone, a short window) it opens at its latest message and composer.
    if (!store.landed && matchMedia("(max-width: 699px), (max-height: 700px)").matches) {
      store.landed = true;
      requestAnimationFrame(() => requestAnimationFrame(() => {
        if (S.rec === store && S.section === "chat" && S.follow) $("view-session").scrollTop = $("view-session").scrollHeight;
      }));
    }
    store.initialComplete = !C.missing(store);
    store.error = null;
  } catch (e) {
    store.error = e.message;
    if (S.rec === store) {
      $("loading").hidden = false;
      $("loading").textContent = "Could not load the record: " + e.message;
    }
    store.loading = false;
    want("header", "overview");
    return;
  }
  store.loading = false;
  want("header", "overview");
  if (S.rec === store && C.missing(store) && tries < 5) loadRecords(store, tries + 1);
}

/**
 * Load the records before the loaded ones: one page, or every page with `all` (Find). The blocks are built again with the earlier ones in
 * front and the transcript keeps the reader where they were.
 */
async function loadEarlier(store, { all = false } = {}) {
  if (store.earlierLoading) return store.earlierLoading;
  if (!C.hasEarlier(store)) return;
  const run = (async () => {
    $("btn-earlier").disabled = true;
    $("btn-earlier").textContent = "Loading earlier records…";
    try {
      do {
        const req = C.earlierRequest(store);
        const page = await api("GET", C.recordsUrl(store.session, null, req.limit, req.before));
        if (S.rec !== store) return;
        const scroller = chatScroller();
        const bottom = scroller.scrollHeight - scroller.scrollTop;
        const added = C.prependRecords(store, page.records, page.prev_before ?? null);
        for (const entry of S.r.nodes.values()) entry.node.remove();
        S.r.nodes.clear();
        S.r.from = C.earlierFrom(added);
        S.r.forced.clear();
        syncChat();
        if (!S.follow) scroller.scrollTop = scroller.scrollHeight - bottom;
        want("overview");
      } while (all && C.hasEarlier(store));
    } catch (e) {
      toast("Could not load earlier records: " + e.message);
    } finally {
      store.earlierLoading = null;
      $("btn-earlier").disabled = false;
      if (S.rec === store) syncChat();
    }
  })();
  store.earlierLoading = run;
  return run;
}

/** The open session is being read: its watermark moves to the latest record, so its row is not "new". */
function markRead() {
  const last = S.rec && !S.rec.loading ? C.lastSeq(S.rec) : null;
  if (last === null || last === undefined || !S.openId) return;
  S.watermarks.set(S.openId, last);
  remember("seen." + S.openId, last);
  want("list");
}

function saveSeen() {
  if (S.openId && S.rec && !S.rec.loading && C.lastSeq(S.rec) !== null) {
    remember("seen." + S.openId, C.lastSeq(S.rec));
    S.watermarks.set(S.openId, C.lastSeq(S.rec));
  }
}

function noteActivity(session, record) {
  if (Number.isInteger(record.seq)) {
    const was = S.activity.get(session);
    if (!was || record.seq >= was.seq) { S.activity.set(session, { seq: record.seq, ts: record.ts_ms }); persistActivity(session); }
    // The open session is being read, so it is never "new since your last visit".
    if (session === S.openId && S.view === "session") S.watermarks.set(session, record.seq);
  }
  if (!C.recordActivity(record)) return;
  const last = S.latest.get(session);
  if (!last || record.seq >= last.seq) S.latest.set(session, record);
}

const SECTION_PANEL = { chat: "mission-record", overview: "mission-overview", agents: "mission-agents", evidence: "mission-evidence" };
function setSection(section, navigate = true) {
  const previous = S.section;
  if (COMPACT.matches && previous) S.scrollAt[previous] = $("view-session").scrollTop;
  S.section = Object.hasOwn(SECTION_PANEL, section) ? section : "chat";
  for (const tab of document.querySelectorAll("#mission-tabs [data-view]")) {
    const selected = tab.dataset.view === S.section;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  }
  for (const [name, id] of Object.entries(SECTION_PANEL)) $(id).hidden = name !== S.section;
  $("composer").classList.toggle("off-chat", S.section !== "chat");
  updateJump();
  updateChildBlocker();
  if (navigate && S.openId) location.hash = C.sessionHash(S.openId, S.section);
  if (COMPACT.matches && previous !== S.section) {
    // One scroller serves every tab: each comes back where it was left, Chat at the end while it follows.
    requestAnimationFrame(() => {
      const view = $("view-session");
      const tabs = $("mission-tabs").getBoundingClientRect().top - view.getBoundingClientRect().top + view.scrollTop;
      const saved = S.scrollAt[S.section];
      view.scrollTop = S.section === "chat" && S.follow ? view.scrollHeight : saved ?? Math.min(view.scrollTop, tabs);
    });
  }
  if (S.section === "chat") want("blocks", "live");
  if (S.section === "evidence" && S.ledger.stale) loadLedger();
  if (S.section === "agents") loadScore(true);
  want("overview");
}

// ---------------------------------------------------------------------------------------------
// Event stream

function ctx() {
  return {
    openId: S.openId,
    ledgerMission: S.ledger.mission,
    ledgerPending: S.ledger.pending === true,
    known: (id) => S.sessions.byId.has(id),
    missionOf: (id) => (S.sessions.byId.get(id) || {}).mission || null,
  };
}

function handleEvent(ev) {
  S.lastUpdate = Date.now();
  if (ev.type === "queued") { if (ev.session === S.openId) loadQueued(); return; }
  if (ev.type === "record" && ev.record) noteActivity(ev.session, ev.record);
  for (const f of C.planEvent(ev, ctx())) {
    switch (f.fx) {
      case "session": {
        const before = f.info && S.sessions.byId.get(f.info.id);
        const was = before && { ...before, status: before.status };
        C.applySessionEvent(S.sessions, f.info);
        if (was) announceEnding(was, f.info);
        want("list", "header", "overview");
        // A model switched, a choice made, or an agent started in the mission the Models tab shows.
        if (S.tab === "models" && S.models.view && f.info && f.info.mission === S.models.view.mission) loadModels();
        break;
      }
      case "status": {
        const before = S.sessions.byId.get(f.session);
        const was = before && { ...before, status: before.status };
        C.applyStatus(S.sessions, f.session, f.status);
        if (was) announceEnding(was, { ...was, status: f.status });
        want("list", "header", "overview");
        break;
      }
      case "header":
        want("header");
        break;
      case "refetch_sessions":
        loadSessions();
        break;
      case "refetch_inbox":
        loadInbox();
        break;
      case "refetch_status":
        loadStatus();
        break;
      case "load_ledger":
        loadLedger();
        break;
      case "refetch_records":
        if (S.rec) loadRecords(S.rec, 0);
        break;
      case "inbox_record": {
        S.inboxRevision++;
        const res = C.applyInboxRecord(S.inbox, f.session, f.record, (id) => S.sessions.byId.get(id));
        if (res) S.inboxTouched.set(f.record.item_id, { rev: S.inboxRevision, entry: res === "opened" ? S.inbox.items.get(f.record.item_id) : null });
        if (res === "opened") announce(S.inbox.items.get(f.record.item_id));
        updateInboxBadge();
        closeNotes();
        break;
      }
      case "apply_record":
        if (C.applyRecord(S.rec, f.record)) {
          want("blocks", "live", "header", "overview");
          updateDelivery(ev.session);
          if (!S.rec.loading && C.missing(S.rec)) loadRecords(S.rec, 0);
        }
        break;
      case "apply_delta":
        if (C.applyDelta(S.rec, f.req_id, f.delta)) want("live");
        break;
      case "refetch_window":
        S.win.stale = true;
        if (S.tab === "context" || S.sheet.open) loadWindow();
        break;
      case "refetch_ledger":
        S.ledger.stale = true;
        // The header shows the goal and the current step on every tab, so a session view always reloads it.
        if (S.view === "session" || S.tab === "ledger" || S.section !== "chat") loadLedger();
        break;
      case "net":
        C.applyNet(S.net, f.entry);
        if (S.tab === "network") want("right");
        break;
      case "notice":
        notice(f.text);
        break;
      default:
        break;
    }
  }
}

// EventSource cannot send an Authorization header, so the stream is read with fetch.
async function connect() {
  let attempt = 0;
  while (!streamStopped) {
    streamCtl = new AbortController();
    // The daemon sends a keep-alive every 15 s; silence for 45 s means the connection is dead.
    let idle = 0;
    const watch = () => {
      clearTimeout(idle);
      idle = setTimeout(() => streamCtl.abort(), 45000);
    };
    try {
      watch();
      const r = await fetch("/api/events?deltas=true", {
        credentials: "omit",
        headers: authHeaders({ Accept: "text/event-stream" }),
        signal: streamCtl.signal,
      });
      if (r.status === 401) return lost();
      if (!r.ok || !r.body) throw new Error("The event stream answered " + r.status + ".");
      const again = S.everConnected;
      S.connected = true;
      S.connectedSince = Date.now();
      S.everConnected = true;
      S.attempts = 0;
      S.lastUpdate = Date.now();
      attempt = 0;
      renderDot();
      if (again) refetchAll();
      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      const parser = C.createSseParser();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        watch();
        C.deliverEvents(parser.feed(decoder.decode(value, { stream: true })), handleEvent, (e) => console.error(e));
      }
    } catch {
      // dropped or aborted: reconnect below
    }
    clearTimeout(idle);
    // However the read ended, let go of the connection before another is opened.
    streamCtl.abort();
    // After lost() the page is the sign-in sentence: there is no dot to update.
    if (streamStopped) return;
    S.connected = false;
    S.connectedSince = null;
    want("list", "header", "overview"); // the quiet notes go with the stream
    S.attempts++;
    renderDot();
    await new Promise((resolve) => setTimeout(resolve, C.reconnectDelayMs(attempt++)));
  }
}

function refetchAll() {
  loadSessions();
  loadInbox();
  loadStatus();
  if (S.rec) loadRecords(S.rec, 0);
  // Ledger records missed while the stream was down are not in the records the open session refetches by seq: read the ledger again.
  if (S.openId) {
    S.ledger.stale = true;
    loadLedger();
    if (S.tab === "network") loadNet();
  }
}

// One request in flight and one queued: a request that arrives while one is out runs after it, so a busy stream cannot starve the list.
let sessionsLoading = false;
let sessionsQueued = false;
async function loadSessions() {
  if (sessionsLoading) { sessionsQueued = true; return; }
  sessionsLoading = true;
  try {
    do {
      sessionsQueued = false;
      const sinceRev = S.sessions.rev || 0; // sessions an event changed after this point survive the snapshot
      try {
        const sessions = await api("GET", "/api/sessions?archived=true");
        const held = new Map(S.sessions.byId);
        C.applySessionList(S.sessions, sessions, { sinceRev });
        // An ending that landed while the stream was down or lagged is only in this snapshot.
        for (const [id, now] of S.sessions.byId) if (held.has(id) && held.get(id) !== now) announceEnding(held.get(id), now);
        S.lastUpdate = Date.now();
        want("list", "header", "overview");
        // The open session may only now be known: its ledger was not loaded before.
        const open = S.openId && S.sessions.byId.get(S.openId);
        if (open && open.mission && (S.ledger.mission !== open.mission || (!S.ledger.model && S.ledger.stale && !S.ledger.pending))) loadLedger();
      } catch (e) {
        notice(e.message);
      }
    } while (sessionsQueued);
  } finally {
    sessionsLoading = false;
  }
}
async function loadInbox() {
  const request = ++S.requests.inbox;
  const since = S.inboxRevision; // what inbox records change after this point outranks the snapshot
  try {
    const inbox = C.mergeInboxList(await api("GET", "/api/inbox"), S.inboxTouched, since);
    if (request !== S.requests.inbox) return;
    C.applyInboxList(S.inbox, inbox, S.answered);
    for (const [id, t] of [...S.inboxTouched]) if (t.rev <= since) S.inboxTouched.delete(id);
    S.lastUpdate = Date.now();
    updateInboxBadge();
    closeNotes();
  } catch (e) {
    if (request === S.requests.inbox) notice(e.message);
  }
}
async function loadStatus() {
  const request = ++S.requests.status;
  try {
    const status = await api("GET", "/api/status");
    if (request !== S.requests.status) return;
    S.status = status;
    S.lastStatus = Date.now();
    S.statusError = null;
    renderDot();
    renderDiskWarning();
  } catch (e) {
    if (request !== S.requests.status) return;
    S.statusError = e.message;
    renderDot();
  }
}

// ---------------------------------------------------------------------------------------------
// Notifications

function notificationsAvailable() {
  return typeof Notification !== "undefined";
}
/** Desktop notifications: only when the page is hidden or unfocused, combined within 5 s, closed when what they say is dealt with. */
function pageSeen() {
  return document.visibilityState === "visible" && (typeof document.hasFocus !== "function" || document.hasFocus());
}
function queueNotice(notice) {
  if (!notice || !notificationsAvailable() || Notification.permission !== "granted") return;
  const N = S.notes;
  if (N.pending.some((n) => n.tag === notice.tag)) return;
  N.pending.push(notice);
  flushNotes();
}
function announce(entry) {
  queueNotice(C.noticeOfInbox(entry, Date.now()));
}
function announceEnding(prev, next) {
  queueNotice(C.noticeOfEnding(C.missionEnding(prev, next, { requested: S.stopAsked }), Date.now()));
}
/** The notices still true when the window closes: an item answered meanwhile, or a session now open and seen, is dropped. */
function liveNotice(n) {
  if (n.kind === "ended") return true;
  return S.inbox.items.has(n.tag);
}
function flushNotes() {
  const N = S.notes;
  clearTimeout(N.timer);
  N.timer = 0;
  N.pending = N.pending.filter(liveNotice);
  const plan = C.planNotifications(N.pending, { now: Date.now(), visible: pageSeen() });
  if (!plan.due) {
    if (plan.wait !== null) N.timer = setTimeout(flushNotes, plan.wait + 20);
    return;
  }
  N.pending = plan.rest;
  const n = plan.notification;
  if (!n) return;
  try {
    const note = new Notification(n.title, { body: n.body, tag: n.tag });
    N.shown.set(n.tag, { note, n });
    note.addEventListener("click", () => {
      window.focus();
      location.hash = n.target.hash;
      note.close();
    });
    note.addEventListener("close", () => N.shown.delete(n.tag));
  } catch {
    // some browsers refuse outside a user gesture; the badge and title still show it
  }
}
/** Close what the operator has dealt with: items now resolved, the session just opened, or the inbox just opened. */
function closeNotes(opened = {}) {
  const N = S.notes;
  const tags = C.closableNotifications([...N.shown.values()].map((x) => x.n), { openItems: new Set(S.inbox.items.keys()), opened });
  for (const tag of tags) {
    const shown = N.shown.get(tag);
    N.shown.delete(tag);
    try { if (shown) shown.note.close(); } catch { /* already gone */ }
  }
}

// ---------------------------------------------------------------------------------------------
// Session header

/** The stats line under the composer: each part is its own span; blank parts are omitted. */
function renderStats() {
  const info = S.sessions.byId.get(S.openId);
  const stats = info && S.view === "session" && S.rec ? C.sessionStats(info, S.rec.blocks) : { speed: "", cache: "", context: "", step: "" };
  $("s-speed").textContent = stats.speed;
  $("s-cache").textContent = stats.cache;
  $("s-context").textContent = stats.context;
  $("s-step").textContent = stats.step;
  renderCaption(info, stats);
  if (S.sheet.open) want("sheet");
}

/** The phone composer's caption ("Plan 1 of 3 · context 9% · cache 98%"): one line that opens the session's details. */
function renderCaption(info, stats) {
  const node = $("s-caption");
  if (!info || S.view !== "session") { node.hidden = true; return; }
  const cap = C.composerCaption({ line: progressLineFor(info), stats: stats || C.sessionStats(info, S.rec ? S.rec.blocks : []), queued: queuedCount() });
  const text = $("s-caption-text");
  if (text.textContent !== cap.text) text.textContent = cap.text;
  node.setAttribute("aria-label", cap.label);
  node.title = cap.label;
}

function chipContent(node, ...kids) {
  node.replaceChildren(...kids.filter(Boolean));
}

/** The run chip: shape + words. The elapsed time of a running turn ticks once a second, only while running and only while the stream is up. */
function renderRun(info) {
  const live = S.connected;
  const run = C.runWords(info, { now: Date.now(), startMs: live && S.rec && S.rec.turn ? S.rec.turn.ts : null, attention: inboxCount(info.id) });
  // With the stream down nothing says the run still goes on: show the last known state, as that, without a clock.
  // A running session with no new record for a while says so, as a fact and in neutral words; nothing while the age is unknown or the stream is down.
  const quiet = live && run.running ? C.quietFor(info, S.activity.get(info.id), Date.now(), S.connectedSince) : null;
  const text = live ? run.text + (quiet ? " · " + quiet.text : "") : "Last known · " + run.text;
  for (const node of [$("s-run"), $("bar-run")]) {
    node.title = quiet ? quiet.tip : "";
    node.className = (node.id === "s-run" ? "id-chip id-run" : "id-chip id-run bar-chip") + (run.tone ? " tone-" + run.tone : "");
    chipContent(node, icon(run.icon), document.createTextNode(text));
    node.hidden = node.id === "bar-run" && S.view !== "session";
  }
  if (run.running && live && !S.runTimer) S.runTimer = setInterval(() => {
    const current = S.sessions.byId.get(S.openId);
    if (!current || S.view !== "session") return stopRunTimer();
    renderRun(current);
    S.now = Date.now();
    tickGroups();
    renderProgress(current);
  }, 1000);
  else if (!run.running || !live) stopRunTimer();
}
/** Below 1100px the top bar carries the model and the run state, so they are in view without scrolling the header. On a phone
 *  it is one button: the title over the model and run state, which opens the session's details. */
function renderBar(info, chips) {
  const node = $("bar-model");
  if (!info || !chips || S.view !== "session") { hideBarIdentity(); return; }
  const m = chips.model;
  node.className = "id-chip id-model bar-chip" + (m.warn ? " unreachable" : "");
  node.title = m.text; // the full model text: profile · model id · context window
  chipContent(node, document.createTextNode(m.profile || "unknown"), m.warn ? add(el("span", "id-warn"), icon(m.warn.icon), el("span", "id-warn-word", m.warn.word)) : null);
  node.hidden = false;
  $("bar-title").textContent = info.title || info.id;
  $("bar-details").hidden = false;
  $("bar-find").hidden = false;
  $("bar-offline").hidden = S.connected;
}
function hideBarIdentity() {
  $("bar-model").hidden = true;
  $("bar-run").hidden = true;
  $("bar-details").hidden = true;
  $("bar-find").hidden = true;
  $("bar-offline").hidden = true;
}
function stopRunTimer() {
  if (S.runTimer) clearInterval(S.runTimer);
  S.runTimer = 0;
}

function renderCrumbs(info) {
  const trail = $("s-crumb-trail");
  const crumbs = C.breadcrumbs(S.sessions, info.id).filter((c) => !c.current);
  // The trail is rebuilt only when it changed, so a link the operator is on keeps focus and its tooltip through the frequent no-op renders.
  const sig = JSON.stringify(crumbs.map((c) => [c.id, c.label, c.tip, c.ellipsis]));
  if (trail.dataset.sig === sig) return;
  trail.dataset.sig = sig;
  preserveFocus($("s-crumbs"), () => {
    trail.replaceChildren();
    for (const c of crumbs) {
      if (c.ellipsis) {
        const gap = el("span", "crumb crumb-gap", "…");
        gap.title = c.tip;
        gap.setAttribute("role", "img");
        gap.setAttribute("aria-label", "Between: " + c.tip);
        trail.append(gap);
      } else {
        const a = link(c.label, C.sessionHash(c.id));
        a.className = "crumb";
        a.title = c.tip;
        a.dataset.focusKey = "crumb:" + c.id;
        trail.append(a);
      }
      trail.append(el("span", "crumb-sep", "/"));
      trail.lastChild.setAttribute("aria-hidden", "true");
    }
  });
}

function renderGoal(info) {
  const goal = $("s-goal");
  const toggle = $("s-goal-toggle");
  goal.textContent = S.ledger.state?.goal || (info.parent ? "Agent assignment · messages go to the mission lead." : "Mission goal has not been recorded yet.");
  goal.classList.toggle("open", S.goalOpen);
  // Measured while clamped: an overflowing one-line goal gets the toggle. Hidden pages measure zero and keep it as it was.
  if (!S.goalOpen && goal.clientWidth > 0) toggle.hidden = goal.scrollWidth <= goal.clientWidth;
  else if (S.goalOpen) toggle.hidden = false;
  toggle.textContent = S.goalOpen ? "Show less" : "Show all";
  toggle.setAttribute("aria-expanded", String(S.goalOpen));
}

function renderIdentity(info) {
  const mission = info.parent ? [...S.sessions.byId.values()].find((s) => !s.parent && s.mission === info.mission) || null : null;
  const chips = C.identityChips(info, S.status, { current: C.currentModel(S.rec, info), now: Date.now(), startMs: S.rec && S.rec.turn ? S.rec.turn.ts : null, attention: inboxCount(info.id), mission });
  const m = chips.model;
  for (const id of ["s-model", "s-role", "s-id"]) $(id).hidden = false;
  const model = $("s-model");
  model.className = "id-chip id-model" + (m.warn ? " unreachable" : "");
  model.title = m.tip;
  const kids = [document.createTextNode(m.text)];
  if (m.warn) kids.push(add(el("span", "id-warn"), icon(m.warn.icon), document.createTextNode(m.warn.word)));
  chipContent(model, ...kids);
  $("s-role").textContent = chips.role.text;
  $("s-role").title = chips.role.tip;
  const id = $("s-id");
  // The "Copied" and "selected" states belong to the session they were made on: another session takes the normal render at once.
  if (id.dataset.copying && id.dataset.copying !== chips.id.full) { delete id.dataset.copying; $("s-copied").textContent = ""; }
  if (!id.dataset.copying) {
    chipContent(id, icon("copy"), document.createTextNode(chips.id.text));
    id.title = chips.id.full;
    id.setAttribute("aria-label", `${chips.id.label}: ${chips.id.text}`);
    id.dataset.full = chips.id.full;
  }
  renderRun(info);
  renderBar(info, chips);
}

// ---------------------------------------------------------------------------------------------
// Copying. Every copy is a user's click or key; nothing copies on load or on arrival.

/** Say something about a copy where a screen reader hears it and, for a failure, where the operator sees it. */
function announceCopy(text, failed = false) {
  if (failed) { toast(text); return; }
  const live = $("copy-live");
  live.textContent = "";
  setTimeout(() => { live.textContent = text; }, 30);
}

function selectContents(node) {
  const range = document.createRange();
  range.selectNodeContents(node);
  const selection = getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

/** The browser's own copy command on the current selection; false when it is not offered or refuses. */
function commandCopy() {
  try { return document.execCommand("copy"); } catch { return false; }
}

/**
 * The one way text reaches the clipboard: `navigator.clipboard.writeText`, else the text is selected and copied with the
 * browser's own copy command, else it stays selected for Ctrl+C. `source` is a visible element (or a function that makes
 * one) holding exactly `text`, or "selection" to copy what is already selected without touching it; with none, the text goes
 * through a scratch field that is removed again. `say(text, failed)` receives the words; `copied` replaces the success words.
 * Returns "clipboard", "command", "selected" or "none".
 */
async function copyText(text, { label = "Text", source = null, say = announceCopy, copied = "" } = {}) {
  const done = (how) => {
    const ok = how === "clipboard" || how === "command";
    say(ok && copied ? copied : C.copyWords(label, how, MAC), !ok);
    return how;
  };
  // `text` may be a promise (a fetch in flight). The clipboard write is then started at once, in the click that asked for it,
  // with the promise inside the item: WebKit only accepts a write made while the click is still being handled.
  const pending = text && typeof text.then === "function" ? text : null;
  const clipboard = navigator.clipboard;
  let write = null;
  try {
    if (pending && clipboard && clipboard.write && typeof ClipboardItem !== "undefined") {
      const blob = pending.then((t) => {
        if (t === null || t === undefined || t === "") throw new Error("Nothing to copy");
        return new Blob([t], { type: "text/plain" });
      });
      blob.catch(() => {});
      write = clipboard.write([new ClipboardItem({ "text/plain": blob })]);
      if (write && typeof write.catch === "function") write.catch(() => {});
    }
  } catch {
    write = null;
  }
  if (pending) {
    try {
      text = await pending;
    } catch (e) {
      if (write) write.catch(() => {});
      throw e;
    }
    if (text === null || text === undefined || text === "") {
      if (write) write.catch(() => {});
      throw new Error("Nothing to copy");
    }
    if (write) {
      try {
        await write;
        return done("clipboard");
      } catch {
        // refused: fall through to the plain write and the selection
      }
    }
  }
  try {
    if (clipboard && clipboard.writeText) {
      await clipboard.writeText(text);
      return done("clipboard");
    }
  } catch {
    // refused (no focus, no permission, or not offered): fall through to the selection
  }
  const asked = typeof source === "function" ? source() : source;
  if (asked === "selection") {
    return done(commandCopy() ? "command" : "none");
  }
  const before = document.activeElement;
  const scratch = asked ? null : el("textarea", "copy-scratch");
  if (scratch) {
    scratch.value = text;
    scratch.readOnly = true;
    scratch.setAttribute("aria-hidden", "true");
    scratch.tabIndex = -1;
    // Inside the open dialog when there is one: the page behind a modal dialog is inert and cannot be selected.
    (document.querySelector("dialog[open]") || document.body).append(scratch);
    scratch.select();
  } else selectContents(asked);
  const ok = commandCopy();
  // What was selected only to be copied is let go again once it has been; kept only when it is the way to copy by hand.
  if (ok && !scratch) getSelection().removeAllRanges();
  if (scratch) {
    scratch.remove();
    if (before && before.focus) before.focus({ preventScroll: true });
  }
  return done(ok ? "command" : asked ? "selected" : "none");
}

/** Show "Copied" in a button for a moment, then put back what it held. */
const RESTING = new WeakMap();
/** Keep a text button as wide as it is while its label is swapped, so its neighbours do not move under the pointer. */
function holdWidth(button) {
  if (!button.style.minWidth) button.style.minWidth = button.offsetWidth + "px";
}
function releaseWidth(button) {
  button.style.minWidth = "";
}
/** Drop a pending "Copied" at once (the button is about to be given another label). */
function cancelFlash(button) {
  delete button.dataset.flash;
  button.classList.remove("done");
  RESTING.delete(button);
  releaseWidth(button);
}
function flashCopied(button) {
  // The resting label is saved by the first flash only; a second click during the flash must not save "Copied" as the label.
  if (button.dataset.flash === undefined || !RESTING.has(button)) {
    RESTING.set(button, [...button.childNodes]);
    holdWidth(button);
  }
  const token = String(Date.now() + Math.random());
  button.dataset.flash = token;
  button.classList.add("done");
  button.replaceChildren(icon("check"), document.createTextNode("Copied"));
  setTimeout(() => {
    if (button.dataset.flash !== token) return;
    const saved = RESTING.get(button);
    delete button.dataset.flash;
    button.classList.remove("done");
    if (saved) button.replaceChildren(...saved);
    RESTING.delete(button);
    releaseWidth(button);
  }, 1500);
}

/**
 * A copy button: the copy drawing, an accessible name and a tooltip; with `text` the name is also shown beside the drawing.
 * `getText` returns the text (or a promise of it, or null when there is nothing), and may throw a sentence to be said.
 * `what` names what was copied for the confirmation. `key` lets focus find the button again after a live update.
 */
function copyButton(label, getText, { what = "Text", text = false, cls = "", source = null, say = announceCopy, key = null, tip = "", busy = "" } = {}) {
  const b = el("button", "btn small copy-btn " + (text ? "with-icon" : "icon-only") + (cls ? " " + cls : ""));
  b.type = "button";
  b.setAttribute("aria-label", label);
  b.title = tip || label;
  if (key) b.dataset.focusKey = key;
  b.append(icon("copy"));
  if (text) b.append(document.createTextNode(label));
  // After a refused fetched copy the text is kept here and the button says "Copy now": that click copies it at once.
  let held = null;
  const resting = () => {
    b.replaceChildren(icon("copy"), ...(text ? [document.createTextNode(label)] : []));
    b.setAttribute("aria-label", label);
  };
  b.addEventListener("click", async () => {
    if (b.getAttribute("aria-busy") === "true") return;
    if (held !== null) {
      const how = await copyText(held, { label: what, source, say });
      if (how === "clipboard" || how === "command") {
        held = null;
        resting();
        flashCopied(b);
      }
      return;
    }
    if (busy) {
      holdWidth(b);
      b.setAttribute("aria-busy", "true");
      b.replaceChildren(icon("refresh"), document.createTextNode(busy));
    }
    const rest = () => {
      if (!busy) return;
      b.removeAttribute("aria-busy");
      resting();
      releaseWidth(b);
    };
    if (busy) {
      // Started inside the click, before any await, and handed to the clipboard as a promise.
      let fetched = null;
      let got;
      try {
        got = Promise.resolve(getText());
      } catch (e) {
        got = Promise.reject(e);
      }
      got = got.then((t) => { fetched = t; return t; });
      const speak = (words, failed) => say(failed && fetched ? "Could not copy it from here; press Copy now to try again." : words, failed);
      let how;
      try {
        how = await copyText(got, { label: what, source, say: speak });
      } catch (e) {
        rest();
        say(e.message, true);
        return;
      }
      rest();
      if (how === "clipboard" || how === "command") flashCopied(b);
      else if (fetched) {
        held = fetched;
        b.replaceChildren(icon("copy"), document.createTextNode("Copy now"));
        b.setAttribute("aria-label", "Copy now");
      }
      return;
    }
    let value;
    try {
      value = await getText();
    } catch (e) {
      say(e.message, true);
      return;
    }
    if (value === null || value === undefined || value === "") { say("Nothing to copy", true); return; }
    const how = await copyText(value, { label: what, source, say });
    if (how === "clipboard" || how === "command") flashCopied(b);
  });
  return b;
}

async function copySessionId() {
  const id = $("s-id");
  const full = id.dataset.full;
  if (!full) return;
  const say = (text) => { $("s-copied").textContent = text; };
  // Only the session that was copied is cleared when the timer ends; if the operator moved on, the header already did it.
  const finish = (ms) => setTimeout(() => {
    if (id.dataset.copying !== full) return;
    delete id.dataset.copying;
    say("");
    want("header");
  }, ms);
  // No clipboard access: the whole id is shown selected, to be copied by hand.
  const show = () => {
    if (id.dataset.full !== full) return null;
    id.dataset.copying = full;
    chipContent(id, document.createTextNode(full));
    return id;
  };
  const how = await copyText(full, { label: "Session id", source: show, say });
  if (id.dataset.full !== full) return; // another session was opened while the clipboard answered
  if (how === "clipboard" || how === "command") {
    id.dataset.copying = full;
    chipContent(id, icon("check"), document.createTextNode("Copied"));
    finish(1500);
  } else finish(6000);
}

function hideHeadConfirm() {
  S.headAsk = null;
  const box = $("shead-confirm");
  if (box) box.hidden = true;
}

function cancelHeadConfirm(restore = true) {
  const ask = S.headAsk;
  hideHeadConfirm();
  if (restore && ask && ask.opener && document.contains(ask.opener) && !ask.opener.hidden) {
    ask.opener.focus({ preventScroll: true });
  }
}

function askHeaderConfirm(kind, info, opener) {
  if (!info) return;
  let text = null;
  if (kind === "stop") text = C.stopQuestion(info);
  else if (kind === "archive") {
    text = C.archiveQuestion(info, missionEntries().length);
    if (!text) { sessionAction("archive", { archived: true }); return; }
  }
  if (!text) return;
  S.headAsk = { kind, session: info.id, opener };
  $("shead-confirm-text").textContent = text;
  const yes = $("shead-confirm-yes");
  yes.textContent = kind === "stop" ? "Stop it" : "Archive";
  yes.className = kind === "stop" ? "btn small danger" : "btn small primary";
  $("shead-confirm-cancel").textContent = kind === "stop" ? "Keep running" : "Keep open";
  $("shead-confirm").hidden = false;
  $("shead-confirm-cancel").focus({ preventScroll: true });
}

function updateChildBlocker() {
  const bar = $("child-blocker");
  if (!bar) return;
  if (S.view !== "session" || S.section !== "chat" || !S.openId) {
    bar.hidden = true;
    S.childBlocker = null;
    return;
  }
  const hit = C.childBlockingItem([...S.sessions.byId.values()], [...S.inbox.items.values()], S.openId);
  if (!hit) {
    bar.hidden = true;
    S.childBlocker = null;
    return;
  }
  S.childBlocker = hit;
  $("child-blocker-text").textContent = `${hit.title} needs your answer`;
  bar.hidden = false;
}

function renderHeader() {
  const info = S.sessions.byId.get(S.openId);
  if (!info) {
    // A session this page does not hold (yet): show only what is known, never the previous session's identity.
    $("s-title").textContent = S.openId || "";
    $("s-title").title = S.openId || "";
    $("s-crumb-trail").replaceChildren();
    delete $("s-crumb-trail").dataset.sig;
    for (const id of ["s-model", "s-role", "s-run", "s-standing", "s-id"]) { $(id).replaceChildren(); $(id).hidden = true; }
    for (const id of ["s-model", "s-role", "s-run"]) $(id).title = "";
    $("s-model").className = "id-chip id-model";
    const idChip = $("s-id");
    delete idChip.dataset.full;
    delete idChip.dataset.copying;
    idChip.removeAttribute("title");
    idChip.removeAttribute("aria-label");
    $("s-copied").textContent = "";
    $("b-files").hidden = true;
    $("s-goal").textContent = "";
    $("s-goal-toggle").hidden = true;
    hideHeadConfirm();
    $("agent-bar").hidden = true;
    $("closed-note").hidden = true;
    document.querySelector(".composer-card")?.classList.remove("is-agent");
    $("child-blocker").hidden = true;
    hideBarIdentity();
    stopRunTimer();
    $("model-confirm").hidden = true;
    const seat = $("model-seat");
    seat.disabled = true;
    seat.title = "The model is shown once the session is known.";
    renderStats();
    return;
  }
  renderCrumbs(info);
  // Leave the title alone while the operator is editing it inline (see renameSession).
  if ($("s-title").dataset.editing !== "true") $("s-title").textContent = info.title || info.id;
  $("s-title").title = info.id;
  // Only a mission (lead) is renamed; an agent is named by the question that started it.
  $("b-rename").hidden = !!info.parent || $("s-title").dataset.editing === "true";
  $("b-files").hidden = !info.workspace;
  renderGoal(info);
  renderIdentity(info);
  const currentStep = S.ledger.state?.plan?.find(step => step.status === "doing");
  const standing = C.missionStanding(info, inboxCount(info.id), info.parent ? 0 : missionAgents(info).filter(agent => agent.status?.phase === "running").length);
  // The first pill is the run state, which the run chip above already says.
  $("s-standing").replaceChildren(
    ...standing.pills.slice(1).map(p => pill(p.text, p.tone, p.icon)),
    el("span", "dim", currentStep ? "Current step: " + currentStep.text : C.rowActivity(info, S.latest.get(info.id), S.now)),
  );
  const openClaims = (S.ledger.state?.claims || []).filter(claim => claim.status === "open").length;
  $("evidence-count").textContent = `${openClaims} open`;
  $("evidence-count").hidden = openClaims === 0;
  // Agents only, as the sidebar counts them: the lead's own state is the run chip in the header.
  const running = [...S.sessions.byId.values()].filter(s => s.mission === info.mission && s.parent && s.status?.phase === "running").length;
  $("agents-count").textContent = `${running} running`;
  $("agents-count").title = `${C.count(running, "agent")} running (the lead is not counted)`;
  $("agents-count").hidden = running === 0;
  renderProgress(info);
  renderStats();
  const a = C.sessionActions(info);
  $("b-stop").hidden = !a.stop;
  // While it runs, Stop also sits beside Send, where the eyes are when it goes wrong; it asks in the header like the header button.
  $("c-stop").hidden = !(a.stop && a.running && a.send);
  $("b-resume").hidden = !a.resume;
  $("b-archive").hidden = !a.archive;
  $("b-unarchive").hidden = !a.unarchive;
  if (S.headAsk && (S.headAsk.session !== info.id || (S.headAsk.kind === "stop" && !a.stop) || (S.headAsk.kind === "archive" && !a.archive))) {
    hideHeadConfirm();
  }
  // The text box and Send go with the ability to send; the model seat stays, so an ended session can still be re-seated.
  $("msg").hidden = !a.send;
  $("send").hidden = !a.send;
  const isAgent = !!info.parent;
  document.querySelector(".composer-card")?.classList.toggle("is-agent", isAgent);
  $("agent-bar").hidden = !isAgent;
  $("agent-note").hidden = !isAgent;
  const leadSession = isAgent ? [...S.sessions.byId.values()].find(s => !s.parent && s.mission === info.mission) || (info.parent ? { id: info.parent } : null) : null;
  $("agent-go-lead").hidden = !isAgent || !leadSession;
  $("agent-go-lead").dataset.lead = leadSession ? leadSession.id : "";
  const closed = $("closed-note");
  closed.hidden = !!info.parent || a.send;
  closed.textContent = info.archived ? "This session is archived; unarchive it to send messages." : "This session has ended. Its record, ledger and files stay as they are.";
  // An ended session's model no longer changes: the seat would only offer a choice that cannot be made.
  const seatLabel = $("model-seat").closest(".seat");
  if (seatLabel) seatLabel.hidden = !a.send && !info.archived && info.status?.phase === "ended";
  // A message is not an answer: say so while a question of this mission waits on the operator.
  const paused = missionEntries().some(entry => entry.item.blocking);
  const lead = C.rootNoun(info) === "lead";
  const help = C.composerHelp({ coarse: COARSE.matches, paused, running: a.running && lead, lead, mac: MAC });
  $("composer-help").textContent = [help.keys, help.note].filter(Boolean).join(" ");
  $("composer-help").hidden = !a.send;
  $("msg").enterKeyHint = COARSE.matches ? "enter" : "send";
  $("composer").classList.toggle("off-chat", S.section !== "chat");
  $("composer-go").hidden = !a.send;
  $("composer-go").textContent = lead ? "Message the lead…" : "Message this session…";
  $("s-caption").hidden = false;
  let action = S.actionState.get(info.id);
  if (action?.accepted && ((action.name === "stop" && !a.stop) || (action.name === "resume" && a.running) || (action.name === "archive" && info.archived === action.archived))) {
    S.actionState.delete(info.id); action = null;
  }
  for (const [id, label, name] of [["b-stop", "Stop", "stop"], ["b-resume", "Resume", "resume"], ["b-archive", "Archive", "archive"], ["b-unarchive", "Unarchive", "archive"]]) {
    const button = $(id);
    button.disabled = !!action;
    button.textContent = action?.name === name ? action.label : label;
  }
  $("composer-recipient").textContent = a.send ? `Message to ${lead ? "the lead of " : ""}${info.title || info.id}` : "";
  const sending = S.sending.has(info.id);
  const message = S.messageState.get(info.id);
  // A message held for after the turn is on disk and listed above; it must not lock Send until the turn ends.
  const pendingReceipt = message?.accepted && message.recordedSeq === undefined && message.state !== "failed" && message.state !== "held";
  $("msg").disabled = sending;
  const att = attachState("message:" + info.id);
  $("attach-bar").hidden = !a.send;
  $("attach-btn").hidden = !a.send;
  $("attach-btn").disabled = sending;
  $("send").disabled = sending || pendingReceipt || !S.rec?.initialComplete || (!$("msg").value.trim() && !att.paths.length) || att.busy || att.failed;
  // The button is an icon; its accessible name says the state, and send-state (live) says it in words.
  const sendLabel = sending ? "Sending…" : pendingReceipt ? "Awaiting receipt…" : "Send";
  $("send").setAttribute("aria-label", sendLabel);
  $("send").title = att.busy ? "Waiting for the uploads to finish" : att.failed ? "Remove the attachment that failed to upload first" : sendLabel === "Send" ? (COARSE.matches ? "Send" : "Send (Enter)") : sendLabel;
  $("send").setAttribute("aria-busy", String(sending || !!pendingReceipt));
  const canQueue = a.send && a.running && lead;
  $("send-more").hidden = !canQueue;
  $("send-more").disabled = $("send").disabled;
  if (!canQueue) closeSendMenu();
  if (canQueue && !COARSE.matches && sendLabel === "Send" && !att.busy && !att.failed) $("send").title = "Send now (Enter) · Queue for after this turn (" + (MAC ? "⌥Enter" : "Alt+Enter") + ")";
  renderQueue();
  const question = renderSeat(info);
  $("send-state").textContent = question ? "" : C.sendStateText({ loaded: !!S.rec?.initialComplete, seat: S.seatNote.get(info.id), message });
  updateChildBlocker();
  growMsg();
  if (S.sheet.open) want("sheet");
}

function missionEntries() {
  const info = S.sessions.byId.get(S.openId);
  return [...S.inbox.items.values()].filter(e => e.mission === info?.mission || e.session === S.openId);
}

/** The agents of a mission, oldest first. */
function missionAgents(info) {
  return [...S.sessions.byId.values()]
    .filter(s => s.mission === info.mission && s.parent)
    .sort((a, b) => a.created_ms - b.created_ms || (a.id < b.id ? -1 : 1));
}

function renderOverview() {
  if (S.view !== "session" || !S.rec) return;
  // Hidden panels are not kept current: setSection asks for a render when one is shown.
  if (S.section === "agents") { loadScore(false); renderAgents(); return; }
  if (S.section !== "overview" && S.section !== "evidence") return;
  const panel = $("mission-overview");
  if (!panel.firstElementChild) {
    const main = add(el("div", "overview-main"), el("div", "overview-decisions"), el("section", "overview-section overview-plan"), el("section", "overview-section overview-files"), el("section", "overview-section overview-changes"));
    const rail = el("aside", "overview-rail");
    rail.setAttribute("aria-label", "Mission standing");
    panel.append(add(el("div", "overview-layout"), main, rail));
  }
  const entries = missionEntries();
  const model = C.missionOverview(S.rec.records.values(), S.ledger.state, entries, S.sinceSeq);
  // A long session loads from the end: what the overview reads is the loaded records, and it says so.
  let partial = panel.querySelector(".overview-partial");
  if (C.hasEarlier(S.rec)) {
    if (!partial) { partial = el("p", "dim overview-partial", C.OVERVIEW_PARTIAL_WORDS); panel.querySelector(".overview-main").prepend(partial); }
  } else if (partial) partial.remove();
  reconcileInbox(panel.querySelector(".overview-decisions"), entries.filter(e => e.item.item_kind !== "finished"), "overview");
  for (const [selector, build] of [[".overview-plan", planSection], [".overview-files", filesSection], [".overview-changes", changesSection], [".overview-rail", railSection]]) {
    const box = panel.querySelector(selector);
    const body = build(model);
    preserveFocus(box, () => box.replaceChildren(body));
  }
  if (S.section === "evidence") renderEvidence($("mission-evidence"));
}

function planSection() {
  const body = document.createDocumentFragment();
  const steps = S.ledger.state?.plan || [];
  const progress = C.planProgress(steps);
  body.append(heading("h2", "Plan", progress.total ? el("span", "dim", progress.label) : null));
  if (S.rec.error) {
    body.append(el("p", "error", "The record could not be loaded: " + S.rec.error));
    const retry = btn("Retry loading the record", "", () => loadRecords(S.rec, 0));
    retry.dataset.focusKey = "retry-record"; body.append(retry);
  }
  if (S.ledger.error) body.append(el("p", "error", "Mission state could not be refreshed: " + S.ledger.error));
  if (S.ledger.stale && S.ledger.state) body.append(el("p", "warn", "Showing the last recorded mission state; refreshing…"));
  if (!steps.length) {
    body.append(el("p", "dim", S.ledger.model ? "No plan has been recorded yet." : "Loading mission state…"));
    return body;
  }
  if (progress.total) {
    const bar = el("div", "plan-progress");
    bar.setAttribute("role", "img");
    bar.setAttribute("aria-label", progress.words);
    for (const segment of progress.segments) bar.append(el("span", "seg seg-" + segment));
    body.append(bar);
  }
  const list = el("ol", "plan-list");
  for (const step of steps) {
    const line = add(el("div", "step-text"), el("span", "", step.text), step.status === "doing" ? pill("Now", "info") : null);
    list.append(add(el("li", "plan-step step-" + step.status), stepMarkEl(step.status), add(el("div"), line, step.note ? el("p", "dim", step.note) : null)));
  }
  body.append(list);
  return body;
}

function changesSection(model) {
  const body = document.createDocumentFragment();
  const record = link("Open the chat", C.sessionHash(S.openId, "chat"));
  record.dataset.focusKey = "overview-record";
  body.append(heading("h2", "Recent activity", record));
  const recent = C.recentChanges(model.changes);
  if (S.rec.loading) body.append(el("p", "dim", "Loading the record…"));
  else if (!recent.total) body.append(el("p", "dim", "No activity has been recorded yet."));
  else if (S.sinceSeq !== null && !recent.fresh.length) body.append(el("p", "dim", "Nothing new has been recorded since your last visit."));
  const group = (label, changes) => {
    if (!changes.length) return;
    if (label) body.append(el("h3", "change-group" + (changes[0].fresh ? " fresh" : ""), label));
    const list = el("ul", "change-list");
    for (const change of changes) {
      const when = el("time", "dim", change.ts ? ago(change.ts) : "");
      if (change.ts) when.dateTime = new Date(change.ts).toISOString();
      const jump = btn(change.text, "link", () => jumpToRecord(change.seq));
      jump.dataset.focusKey = "change:" + change.seq;
      list.append(add(el("li", "change-item" + (change.tone ? " " + change.tone : "")), when, jump));
    }
    body.append(list);
  };
  group(recent.fresh.length ? "New since your last visit" : null, recent.fresh);
  group(recent.fresh.length && recent.earlier.length ? "Earlier" : null, recent.earlier);
  if (recent.total > recent.shown) body.append(el("p", "dim fineprint", `Showing the latest ${recent.shown} of ${C.num(recent.total)} recorded changes.`));
  body.append(el("p", "dim fineprint", "Activity is derived from recorded events. Completed steps and matching quotes do not by themselves establish a claim."));
  return body;
}

// Files this session changed through its edit and write tools: what a reviewer looks at first. Each row jumps to the latest
// change in the chat and opens the file as it is now. Commands and agents can change files too; the note says so.
function filesSection() {
  const body = document.createDocumentFragment();
  const info = S.sessions.byId.get(S.openId);
  const rows = S.rec && !S.rec.loading ? C.fileChanges(S.rec.blocks, info ? info.workspace : "") : [];
  if (!rows.length) return body; // the section is empty, and an empty section is not shown
  const added = rows.reduce((n, r) => n + r.added, 0), removed = rows.reduce((n, r) => n + r.removed, 0);
  const total = el("span", "diffstat");
  add(total, el("span", "ds-add", "+" + C.num(added)), el("span", "ds-del", "−" + C.num(removed)));
  total.title = `${C.count(added, "line")} added, ${C.count(removed, "line")} removed, from the recorded diffs`;
  body.append(heading("h2", "Files changed", add(el("span", "dim files-count", C.count(rows.length, "file") + " · "), total)));
  const list = el("ul", "file-list");
  for (const r of rows.slice(0, 50)) {
    const shown = r.rel !== null && r.rel !== "" ? r.rel : r.path;
    const jump = btn("", "link mono file-jump", () => jumpToRecord(r.lastSeq));
    jump.textContent = shown;
    jump.title = `Show the latest change to ${shown} in the chat`;
    jump.dataset.focusKey = "file:" + r.path;
    const stat = el("span", "diffstat");
    if (r.created) add(stat, el("span", "ds-new", "new"));
    if (r.added || r.removed) add(stat, el("span", "ds-add", "+" + C.num(r.added)), el("span", "ds-del", "−" + C.num(r.removed)));
    const meta = el("span", "dim", r.edits > 1 ? `${r.edits} edits` : "");
    const li = add(el("li", "file-item"), jump, stat, meta);
    if (r.rel !== null) {
      const open = btn("Open", "small ghost", (e) => showFiles(e.currentTarget, r.rel));
      open.title = "Show the file as it is in the workspace now";
      open.dataset.focusKey = "file-open:" + r.path;
      li.append(open);
    }
    list.append(li);
  }
  body.append(list);
  if (rows.length > 50) body.append(el("p", "dim fineprint", `Showing the 50 most recent of ${C.num(rows.length)} files.`));
  body.append(el("p", "dim fineprint", "From this session's edit and write calls. Changes made by shell commands or by agents are not listed here."));
  return body;
}

function sessionLink(s) {
  const mark = C.stateMark(s, inboxCount(s.id));
  const a = el("a", "rail-session");
  a.setAttribute("href", C.sessionHash(s.id));
  a.dataset.focusKey = "rail:" + s.id;
  return add(a, markEl(mark), add(el("span", "rail-session-text"), el("span", "name", s.title || s.id), el("span", "dim", `${s.role} · ${C.markWords(mark)} · step ${s.status?.step || 0}`)));
}

/** The right rail of the overview: who is working, what is unsettled, and what the run has used. */
function railSection(model) {
  const body = document.createDocumentFragment();
  const info = S.sessions.byId.get(S.openId);
  if (!info) return body;
  const card = (title, ...kids) => add(el("section", "rail-card"), el("h3", "", title), ...kids);
  if (info.parent) {
    const lead = [...S.sessions.byId.values()].find(s => s.mission === info.mission && !s.parent);
    if (lead) body.append(card("Part of", sessionLink(lead)));
  } else {
    const agents = missionAgents(info);
    if (agents.length) {
      const all = link(`All agents (${agents.length})`, C.sessionHash(S.openId, "agents"));
      all.className = "rail-all";
      body.append(card("Agents", ...agents.map(sessionLink), all));
    }
  }
  if (S.ledger.state) {
    const stats = el("dl", "rail-stats");
    for (const [value, label] of [
      [model.counts.claimsOpen, model.counts.claimsOpen === 1 ? "open claim" : "open claims"],
      [model.counts.claimsSupported, "supported"],
      [model.counts.openObligations, model.counts.openObligations === 1 ? "open obligation" : "open obligations"],
    ]) stats.append(add(el("div", "stat"), el("dt", "", label), el("dd", "", C.num(value))));
    const inspect = btn("Review claims and evidence", "link", () => setSection("evidence"));
    inspect.dataset.focusKey = "overview-evidence";
    body.append(card("Claims and obligations", stats, inspect));
  }
  const st = info.status || {};
  const meter = C.statusMeter(info);
  const bar = add(el("span", "meter"), el("span", "fill"));
  bar.firstElementChild.style.setProperty("width", meter.inViewPct + "%");
  bar.setAttribute("role", "img");
  bar.setAttribute("aria-label", `Last prompt ${meter.label} tokens`);
  const row = (label, value) => add(el("div", "rail-row"), el("span", "dim", label), el("span", "", value));
  body.append(card("Run",
    row("Last prompt", meter.label), bar,
    row("Cached prefix", C.cachedShare(st.cached_tokens || 0, st.prompt_tokens || 0) || "n/a"),
    row(info.parent ? "Agent step" : C.rootNoun(info) === "lead" ? "Lead step" : "Step", C.num(st.step || 0)),
    el("p", "dim fineprint", "Run numbers describe effort, not completion.")));
  return body;
}

// ---------------------------------------------------------------------------------------------
// Session details sheet (the bar's button and the composer's caption open it; a phone's way to the run, the context, the model
// and the session's own actions, which the header shows only while it is in view)

/** A row of a sheet card: the label, the value, and optionally a control that takes the whole row. */
function srow(label, value, { mono = false, full = null, cls = "" } = {}) {
  const row = el("div", "srow " + cls);
  row.append(el("span", "sk", label));
  if (value instanceof Node) row.append(add(el("span", "sv"), value));
  else if (value !== null && value !== undefined) row.append(el("span", "sv" + (mono ? " mono" : ""), value));
  if (full) row.append(add(el("div", "sfull"), full));
  return row;
}

function sheetSection(key, title, ...kids) {
  const sec = el("section", "sheet-section");
  const h = el("h3", "", title);
  h.id = "sheet-h-" + key;
  h.tabIndex = -1;
  h.dataset.focusKey = "sheet:h:" + key;
  sec.setAttribute("aria-labelledby", h.id);
  return add(sec, h, ...kids);
}

function sheetCard(...kids) {
  return add(el("div", "sheet-card"), ...kids);
}

/** The base URL's host, as text (never a link). */
function endpointHost(profile) {
  const entry = ((S.status && S.status.models) || []).find((m) => m.profile === profile);
  if (!entry || !entry.base_url) return "";
  try { return new URL(entry.base_url).host; } catch { return ""; }
}

function setExpandAll(on) {
  S.expandAll = on;
  $("expand-work").checked = on;
  syncChat();
  want("sheet");
}

function setDetails(on) {
  S.details = on;
  $("details").checked = on;
  $("blocks").classList.toggle("hide-details", !on);
  syncChat();
  want("sheet");
}

function sheetCheck(label, id, checked, onChange, key) {
  const row = el("div", "srow check-row");
  const l = el("label");
  const cb = el("input");
  cb.type = "checkbox";
  cb.id = id;
  cb.checked = checked;
  cb.dataset.focusKey = key;
  cb.addEventListener("change", () => onChange(cb.checked));
  add(l, cb, document.createTextNode(label));
  return add(row, l);
}

function buildSheet(info) {
  const out = [];
  const a = C.sessionActions(info);
  const live = S.connected;
  const run = C.runWords(info, { now: Date.now(), startMs: live && S.rec && S.rec.turn ? S.rec.turn.ts : null, attention: inboxCount(info.id) });
  const words = add(el("span", "runwords"), icon(run.icon), document.createTextNode(live ? run.text : "Last known · " + run.text));

  // RUN
  const line = progressLineFor(info);
  const action = S.actionState.get(info.id);
  const runCard = sheetCard(srow("Run", words));
  if (line) {
    const p = el("p", "scope", line.text);
    runCard.append(srow("Progress", null, { full: add(el("div"), p, line.parts.some((x) => x.key === "budget") ? el("p", "scope", "A budget is a limit, not a measure of progress.") : null) }));
  }
  if (a.stop || a.resume) {
    const holder = el("div");
    if (a.stop) {
      const stop = btn(action?.name === "stop" ? action.label : "Stop…", "danger", () => { S.sheet.ask = { kind: "stop", focus: true }; want("sheet"); });
      stop.dataset.focusKey = "sheet:stop";
      stop.disabled = !!action;
      stop.setAttribute("aria-label", action?.name === "stop" ? action.label : "Stop this session");
      add(holder, stop, el("p", "scope", "Stops this session, its agents and their tracked jobs."));
    } else {
      const resume = btn(action?.name === "resume" ? action.label : "Resume", "", () => sessionAction("resume"));
      resume.dataset.focusKey = "sheet:resume";
      resume.disabled = !!action;
      add(holder, resume, el("p", "scope", "Starts this session again from its record."));
    }
    runCard.append(srow("", null, { full: holder, cls: "run-actions" }));
    if (S.sheet.ask && S.sheet.ask.kind === "stop") {
      const q = { text: C.stopQuestion(info), yes: "Stop it", no: "Keep running" };
      runCard.append(confirmRow(q, () => { S.sheet.ask = null; want("sheet"); sessionAction("stop"); requestAnimationFrame(() => focusKey("sheet:h:run")); }, () => { S.sheet.ask = null; want("sheet"); requestAnimationFrame(() => focusKey("sheet:stop")); }, "sheet:"));
    }
  }
  out.push(sheetSection("run", "Run", runCard));

  // CONTEXT
  const w = S.win.data;
  const ctxBody = S.win.error && !w ? el("p", "dim", S.win.error) : !w ? el("p", "dim", "Loading…") : contextCard(w, "sheet", S.sheet.ask);
  out.push(sheetSection("context", "Context", add(sheetCard(), ctxBody)));
  out[out.length - 1].lastChild.classList.add("roomy");

  // MODEL
  const current = C.currentModel(S.rec, info) || { profile: info.profile, model: info.model, context_window: info.context_window };
  const health = ((S.status && S.status.models) || []).find((m) => m.profile === current.profile) || null;
  const reach = health ? add(el("span", "runwords"), icon(health.reachable ? "check" : "alert"), document.createTextNode(health.reachable ? "reachable" : "unreachable")) : null;
  const win = current.context_window || (S.win.data && S.win.data.context_window) || 0;
  const profileWin = !win && health && health.context_window ? health.context_window : 0;
  const modelCard = sheetCard(srow("Profile", current.profile || "unknown"));
  if (reach) modelCard.append(srow("Reachability", reach));
  if (current.model && current.model !== current.profile) modelCard.append(srow("Model id", current.model, { mono: true }));
  modelCard.append(srow("Context limit", win ? `${C.num(win)} tokens` : profileWin ? `unknown for this session (the profile reports ${C.num(profileWin)} tokens)` : "unknown"));
  const host = endpointHost(current.profile);
  if (host) modelCard.append(srow("Endpoint", host, { mono: true }));
  const seat = $("model-seat");
  const change = btn("Change model…", "", () => { closeSheet(false); if (S.section !== "chat") setSection("chat"); requestAnimationFrame(() => { seat.focus(); }); });
  change.dataset.focusKey = "sheet:change-model";
  change.disabled = seat.disabled;
  if (seat.disabled && seat.title) change.title = seat.title;
  modelCard.append(srow("", null, { full: change }));
  out.push(sheetSection("model", "Model", modelCard));

  // VIEW
  out.push(sheetSection("view", "View", sheetCard(
    sheetCheck("Expand all work", "sheet-expand-work", S.expandAll, setExpandAll, "sheet:expand"),
    sheetCheck("Show request details", "sheet-details", S.details, setDetails, "sheet:details"),
  )));

  // SESSION
  const copied = el("p", "scope", S.sheet.say || "");
  copied.setAttribute("role", "status");
  const copy = copyButton("Copy session id", () => info.id, { what: "Session id", text: true, key: "sheet:copy-id", say: (t) => { S.sheet.say = t; want("sheet"); } });
  const inspector = btn("Open inspector", "", () => { closeSheet(false); nextOpener = $("bar-details"); setDrawer("right", true); });
  inspector.dataset.focusKey = "sheet:inspector";
  inspector.title = "Ledger, Network, Models, Session and Files";
  const rows = [];
  if (!info.parent) {
    const rename = btn("Rename…", "", () => { closeSheet(false); requestAnimationFrame(() => { $("s-title").scrollIntoView({ block: "nearest" }); renameSession(); }); });
    rename.dataset.focusKey = "sheet:rename";
    rows.push(srow("Title", null, { full: rename }));
  }
  if (a.archive || a.unarchive) {
    const arch = btn(action?.name === "archive" ? action.label : a.archive ? "Archive" : "Unarchive", "", () => sessionAction("archive", { archived: !!a.archive }));
    arch.dataset.focusKey = "sheet:archive";
    arch.disabled = !!action;
    rows.push(srow("Mission", null, { full: arch }));
  }
  rows.push(srow("Session id", null, { full: add(el("div"), copy, copied) }), srow("Inspector", null, { full: inspector }));
  out.push(sheetSection("session", "Session", sheetCard(...rows)));
  return out;
}

function renderSheet() {
  const dialog = $("session-sheet");
  if (!S.sheet.open || !dialog.open) return;
  const info = S.sessions.byId.get(S.openId);
  const body = $("session-sheet-body");
  if (!info || S.view !== "session") { closeSheet(false); return; }
  const frag = document.createDocumentFragment();
  frag.append(...buildSheet(info));
  // Rebuild only what changed, so a tap is never lost to a redraw and a question being read keeps its place.
  const sig = [...frag.querySelectorAll("*")].map((n) => n.tagName + (n.getAttribute("class") || "") + (n.getAttribute("data-icon") || "") + [...n.childNodes].filter((c) => c.nodeType === 3).map((c) => c.data).join("") + (n.getAttribute("style") || "") + (n.disabled ? "d" : "") + (n.checked ? "c" : "") + (n.getAttribute("aria-label") || "")).join("|");
  if (S.sheet.sig !== sig) {
    S.sheet.sig = sig;
    preserveFocus(body, () => body.replaceChildren(frag));
  }
  if (S.sheet.ask && S.sheet.ask.focus) {
    S.sheet.ask.focus = false;
    const safe = body.querySelector('[data-focus-key="sheet:ask:no"]');
    if (safe) safe.focus({ preventScroll: true });
  }
}

/** Open the sheet and put the keyboard on the heading of `section` ("run" or "context"). */
function openSheet(section = "run", opener = null) {
  if (S.view !== "session" || !S.openId) return;
  const dialog = $("session-sheet");
  if (dialog.open) return;
  if (document.querySelector("dialog[open]")) return;
  S.sheet.opener = opener || document.activeElement;
  S.sheet.open = true;
  S.sheet.ask = null;
  S.sheet.say = "";
  S.sheet.sig = "";
  dialog.showModal();
  renderSheet();
  loadWindow();
  const h = $("sheet-h-" + section);
  if (h) h.focus({ preventScroll: true });
}

function closeSheet(restore = true) {
  const dialog = $("session-sheet");
  S.sheet.restore = restore;
  if (dialog.open) dialog.close();
  else S.sheet.open = false;
}

function wireSheet() {
  const dialog = $("session-sheet");
  $("bar-details").addEventListener("click", () => openSheet("run", $("bar-details")));
  $("s-caption").addEventListener("click", () => openSheet("context", $("s-caption")));
  $("session-sheet-close").addEventListener("click", () => closeSheet());
  dialog.addEventListener("click", (e) => { if (e.target === dialog) closeSheet(); }); // the backdrop
  dialog.addEventListener("close", () => {
    const opener = S.sheet.opener;
    S.sheet.open = false;
    S.sheet.ask = null;
    S.sheet.opener = null;
    // Focus goes back to what opened the sheet, unless the sheet closed to send the operator somewhere else.
    if (S.sheet.restore !== false) {
      const target = opener && document.contains(opener) && !opener.hidden ? opener : $("bar-details").hidden ? null : $("bar-details");
      if (target) target.focus({ preventScroll: true });
    }
    S.sheet.restore = true;
  });
}

// ---------------------------------------------------------------------------------------------
// Agents tab

/**
 * GET /api/missions/{id}/score, for the Agents tab. Forced when the tab opens or Refresh is pressed; otherwise only while the tab is
 * shown and an agent runs, and at most every SCORE_EVERY_MS (C.scoreDue). Events never fetch it on their own: they only ask for a
 * render, and the render asks here, where the throttle decides.
 */
async function loadScore(force) {
  const info = S.sessions.byId.get(S.openId);
  if (!info || S.view !== "session") return;
  const mission = info.mission;
  if (S.score.mission !== mission) S.score = { mission, view: null, error: null, lastMs: null, loading: false };
  if (S.score.loading) return;
  const running = [...S.sessions.byId.values()].some(s => s.mission === mission && s.status?.phase === "running");
  if (!C.scoreDue({ shown: S.section === "agents", lastMs: S.score.lastMs, running, now: Date.now(), force })) return;
  const score = S.score;
  score.loading = true;
  score.lastMs = Date.now(); // a failed fetch also waits out the interval
  want("overview");
  try {
    const v = await api("GET", "/api/missions/" + encodeURIComponent(mission) + "/score");
    if (S.score !== score) return;
    const rows = C.scoreRows(v);
    score.view = rows;
    score.error = rows ? null : "The daemon sent a scorecard this page cannot read.";
  } catch (e) {
    if (S.score !== score) return;
    score.error = e.message;
  }
  score.loading = false;
  want("overview");
}

function agentRow(row, active) {
  const li = el("li", "agent-row indent-" + row.indent);
  li.dataset.agent = row.id;
  const a = el("a", "agent-main");
  a.setAttribute("href", C.sessionHash(row.id));
  a.dataset.focusKey = "agent:" + row.id;
  a.tabIndex = active ? 0 : -1;
  const text = el("span", "agent-text");
  text.append(el("span", "agent-title", row.title));
  const meta = [row.roleLine, `step ${C.num(row.step)}`];
  if (row.ageText) meta.push(`last record ${row.ageText}`);
  if (row.generated) meta.push(row.generated);
  text.append(el("span", "dim agent-meta", meta.join(" · ")));
  if (row.crumbs.length) text.append(el("span", "dim agent-meta", "Under " + row.crumbs.join(" › ")));
  const reason = row.waiting || row.quiet;
  if (reason) text.append(add(el("span", "sw-reason tone-" + (reason.tone || "quiet")), icon(reason.icon), el("span", "", reason.text)));
  if (row.outcome) text.append(el("span", "agent-outcome", "Ended: " + row.outcome));
  if (row.score) text.append(el("span", "dim agent-score", row.score.text + (row.score.unrecorded ? " · verifier counts not recorded" : "")));
  const mk = add(el("span", "mark mark-" + (row.mark.tone || "dim")), icon(row.mark.icon), el("span", "sr-only", row.mark.words + ": "));
  mk.title = row.mark.words;
  add(a, mk, text);
  li.append(a);
  if (row.spawnSeq !== null) {
    const jump = btn("Where it was spawned", "link small agent-spawn", () => jumpToRecord(row.spawnSeq, { focus: true }));
    jump.tabIndex = active ? 0 : -1;
    jump.dataset.focusKey = "agent-spawn:" + row.id;
    li.append(jump);
  }
  return li;
}

function renderAgents() {
  const panel = $("mission-agents");
  const info = S.sessions.byId.get(S.openId);
  if (!info || !S.rec) return;
  const score = S.score.mission === info.mission ? S.score : null;
  const model = C.agentGroups(S.sessions, S.inbox, info.mission, {
    now: S.now, activity: S.activity, since: S.connectedSince, score: score && score.view, spawns: C.spawnSeqs(S.rec.blocks),
  });
  const frag = document.createDocumentFragment();
  const refresh = btn(score && score.loading ? "Refreshing…" : "Refresh scores", "small", () => loadScore(true));
  refresh.dataset.focusKey = "agents-refresh";
  if (score && score.loading) refresh.setAttribute("aria-disabled", "true");
  frag.append(heading("h2", "Agents", el("span", "dim", model.summary), refresh));
  const note = score && score.error ? el("p", "error", "Scores could not be read: " + score.error)
    : score && score.lastMs && !score.view ? el("p", "dim", "Reading the scores…")
    : null;
  if (note) frag.append(note);
  if (score && score.view) {
    const total = score.view.total;
    // A grid of numbers: the steps, then every count that is not zero. The sentence form is the section's label.
    const grid = el("dl", "score-grid");
    const cell = (value, label, tone = "") => add(grid, add(el("div", "score-cell" + (tone ? " tone-" + tone : "")), el("dt", "", label), el("dd", "", C.num(value))));
    cell(total.steps, "steps");
    for (const c of total.cells) if (c.value > 0) cell(c.value, c.label, /malformed|refusal|reject/.test(c.key) ? "warn" : "");
    const section = add(el("section", "agents-total"), add(el("h3", "", score.view.label), el("span", "dim score-age", ` · read ${ago(score.lastMs)}`)), grid);
    section.setAttribute("aria-label", `${score.view.label}: ${C.num(total.steps)} steps · ${total.text}`);
    section.title = "Scores refresh when this tab opens, on Refresh, and at most every 2 minutes while an agent runs.";
    if (total.unrecorded) section.append(el("p", "dim fineprint", "Verifier counts were not recorded for some logs."));
    section.append(el("p", "dim fineprint", score.view.fineprint));
    frag.append(section);
  }
  if (!model.groups.length) frag.append(el("p", "dim", "No agents in this mission yet."));
  const first = model.groups[0] && model.groups[0].rows[0];
  const active = S.agentsActive && model.groups.some(g => g.rows.some(r => r.id === S.agentsActive) && (!g.folded || S.agentsEnded)) ? S.agentsActive : first && first.id;
  for (const group of model.groups) {
    const section = el("section", "agent-group");
    const label = `${group.label} · ${C.num(group.rows.length)}`;
    const open = !group.folded || S.agentsEnded;
    if (group.folded) {
      const head = el("h3");
      const toggle = btn(`${C.num(group.rows.length)} ended`, "small agent-fold", () => { S.agentsEnded = !S.agentsEnded; renderAgents(); });
      toggle.setAttribute("aria-expanded", String(open));
      toggle.dataset.focusKey = "agents-ended";
      section.append(add(head, toggle));
    } else section.append(el("h3", "", label));
    if (open) {
      const list = el("ul", "agent-list");
      list.setAttribute("aria-label", group.label);
      for (const row of group.rows) list.append(agentRow(row, row.id === active));
      section.append(list);
    }
    frag.append(section);
  }
  preserveFocus(panel, () => panel.replaceChildren(frag));
}

/** Roving tab stop across the agent rows: arrows, Home and End move between them; Enter opens the one in focus. */
function agentsKeys(e) {
  if (e.altKey || e.ctrlKey || e.metaKey) return; // Alt+Up/Down belongs to the mission stepper
  if (e.target.closest && e.target.closest(".agent-spawn")) return;
  const rows = [...$("mission-agents").querySelectorAll(".agent-main")];
  const at = rows.indexOf(e.target);
  if (at < 0) return;
  let next = null;
  if (e.key === "ArrowDown") next = Math.min(rows.length - 1, at + 1);
  else if (e.key === "ArrowUp") next = Math.max(0, at - 1);
  else if (e.key === "Home") next = 0;
  else if (e.key === "End") next = rows.length - 1;
  if (next === null) return;
  e.preventDefault();
  setAgentsActive(rows, next);
}
function setAgentsActive(rows, index) {
  rows.forEach((r, i) => {
    r.tabIndex = i === index ? 0 : -1;
    const spawn = r.parentElement.querySelector(".agent-spawn");
    if (spawn) spawn.tabIndex = i === index ? 0 : -1;
  });
  S.agentsActive = rows[index].parentElement.dataset.agent;
  rows[index].focus();
}

// ---------------------------------------------------------------------------------------------
// Progress line above the composer

/** The progress line's content (plan, step, budget) for `info`, or null: the plan is the mission's, an agent shows only its own budget. */
function progressLineFor(info) {
  const ended = !info || info.status?.phase === "ended";
  // The budget is counted from the record as the daemon counts it: active time and own steps since it was last granted.
  const used = S.rec ? C.budgetUsed(S.rec, Date.now()) : { steps: 0, minutes: null };
  return ended || S.view !== "session" ? null : C.progressLine({
    plan: info.parent ? [] : S.ledger.model?.plan, step: used.steps, minutes: used.minutes,
    budget: S.rec && S.rec.start ? S.rec.start.budget : null,
  });
}

function renderProgress(info) {
  const node = $("s-progress");
  const line = progressLineFor(info);
  const sig = line ? line.text : "";
  if (node.dataset.sig === sig) return;
  node.dataset.sig = sig;
  node.hidden = !line;
  renderCaption(info);
  if (!line) { node.replaceChildren(); renderMiniPlan(info); return; }
  const parts = line.parts.map(p => {
    if (p.key !== "plan") return el("span", "progress-part progress-" + p.key, p.text);
    // The plan count opens the steps above the composer, so the plan can be read without leaving the chat.
    const b = btn(p.text, "progress-part progress-plan link", () => { S.planOpen = !S.planOpen; renderMiniPlan(info); });
    b.setAttribute("aria-controls", "s-plan");
    b.setAttribute("aria-expanded", String(!!S.planOpen));
    b.title = S.planOpen ? "Hide the plan" : "Show the plan's steps";
    return b;
  });
  node.replaceChildren(...parts, el("span", "sr-only", line.parts.some(p => p.key === "budget") ? ". The budget is a limit, not a measure of progress." : ""));
  renderMiniPlan(info);
}

/** The plan's steps above the composer, open while S.planOpen; the Overview tab keeps the full view with notes. */
function renderMiniPlan(info) {
  const list = $("s-plan");
  const steps = info && !info.parent ? (S.ledger.model?.plan || []).filter(st => st.status !== "dropped") : [];
  const open = !!S.planOpen && steps.length > 0;
  const toggle = $("s-progress").querySelector(".progress-plan");
  if (toggle) { toggle.setAttribute("aria-expanded", String(open)); toggle.title = open ? "Hide the plan" : "Show the plan's steps"; }
  const sig = open ? JSON.stringify(steps.map(st => [st.status, st.text])) : "";
  if (list.dataset.sig === sig && list.hidden === !open) return;
  list.dataset.sig = sig;
  list.hidden = !open;
  list.replaceChildren(...(open ? steps.map(st => add(el("li", "mini-step step-" + st.status), stepMarkEl(st.status), el("span", "step-text", st.text))) : []));
}

/**
 * Go to the block that holds record `seq`, highlight it, and (with `focus`) put the keyboard on it, so a screen reader reads it and the
 * next Tab continues from there. `done(node)` is called once it is shown. While the jump settles `S.jumping` keeps the scroll handler
 * from deciding that the chat is following the end again (widening the window keeps the bottom offset and would say so).
 */
function jumpToRecord(seq, { focus = false, highlight = true, done = null } = {}) {
  setSection("chat");
  S.jumping = true;
  requestAnimationFrame(() => {
    const block = S.rec?.blocks.find(b => b.seq === seq || b.callSeq === seq || b.result?.seq === seq || b.resolved?.seq === seq);
    if (!block && S.rec && C.hasEarlier(S.rec)) {
      // The record is before the loaded ones: load them, then go there.
      S.jumping = false;
      loadEarlier(S.rec, { all: true }).then(() => jumpToRecord(seq, { focus, highlight, done }));
      return;
    }
    if (!block || !S.r) { S.jumping = false; return; }
    S.follow = false;
    while (block.id < S.r.from && S.r.from > 0) showEarlier();
    // A folded group holding the record opens, and so does the call's own row.
    const key = C.groupKeyForSeq(S.r.items, block.seq);
    if (key) S.workState.set(key, true);
    if (block.kind === "tool") block.ui = { ...(block.ui || {}), open: true };
    if (key || block.kind === "tool") { S.r.forced.add(block.id); syncChat(); }
    // One more frame: a pending render may still replace the node.
    requestAnimationFrame(() => {
      const node = $("blocks").querySelector(`[data-bid="${block.id}"]`);
      S.jumping = false;
      if (node) {
        node.scrollIntoView({ block: jumpBlock(node) });
        if (highlight) {
          node.classList.add("record-highlight");
          setTimeout(() => node.classList.remove("record-highlight"), 2500);
        }
        node.tabIndex = -1;
        if (focus) node.focus({ preventScroll: true });
        if (done) done(node);
      }
      const s = chatScroller();
      S.follow = C.atEnd(s.scrollTop, s.clientHeight, s.scrollHeight);
      updateJump();
    });
  });
}

/** Where a jump lands: the middle, unless the node is taller than the band between the sticky tabs and composer (then its top). */
function jumpBlock(node) {
  if (!COMPACT.matches) return "center";
  const top = $("mission-tabs").getBoundingClientRect().bottom;
  const bottom = $("composer").getBoundingClientRect().top;
  return node.classList.contains("block-inbox") || node.getBoundingClientRect().height > bottom - top ? "start" : "center";
}

function renderEvidence(panel) {
  const frag = document.createDocumentFragment();
  const claims = S.ledger.model?.claims || [];
  const filters = el("div", "filters");
  filters.setAttribute("role", "group");
  filters.setAttribute("aria-label", "Filter claims by recorded status");
  if (claims.length) {
    for (const filter of C.claimFilters(claims)) {
      const chosen = filter.key === S.claimFilter;
      const b = btn("", "small filter", () => { S.claimFilter = filter.key; renderEvidence(panel); });
      add(b, document.createTextNode(filter.label + " "), el("span", "dim", C.num(filter.count)));
      b.setAttribute("aria-pressed", String(chosen));
      b.dataset.focusKey = "claim-filter:" + filter.key;
      filters.append(b);
    }
  }
  frag.append(heading("h2", "Claims and source evidence", claims.length ? filters : null));
  const about = el("p", "dim evidence-about");
  add(about, document.createTextNode("Two separate checks appear below. "), el("strong", "", "Quote match"),
    document.createTextNode(" means the runtime found the quoted text in the stored output. "), el("strong", "", "Claim status"),
    document.createTextNode(" is what the agent recorded. Neither is independent verification."));
  frag.append(about);
  if (S.ledger.error) frag.append(el("p", "error", S.ledger.error));
  if (!S.ledger.model) frag.append(el("p", "dim", "Loading mission evidence…"));
  else if (!claims.length) frag.append(el("p", "dim", "No claims have been recorded yet."));
  const shown = C.filterClaims(claims, S.claimFilter);
  if (claims.length && !shown.length) frag.append(el("p", "dim", "No claims have this status."));
  for (const claim of shown) {
    const section = el("article", "evidence-claim");
    section.append(add(el("div", "chips"),
      chip(C.claimStatusWords(claim.status), "status-" + claim.status), el("span", "mono dim", claim.id), el("span", "dim", "status recorded by the agent")));
    section.append(el("h3", "", claim.text));
    if (claim.note) section.append(el("p", "claim-note", claim.note));
    if (!claim.evidence.length) section.append(el("p", "dim", "No source evidence attached."));
    for (const evidence of claim.evidence) section.append(evidenceCard(evidence));
    frag.append(section);
  }
  const obligations = S.ledger.model?.obligations || [];
  if (obligations.length) {
    const section = el("section", "overview-section");
    section.append(heading("h2", "Open obligations"));
    const list = el("ul", "obligation-list");
    for (const o of obligations) list.append(add(el("li"), el("span", "mono dim", o.id), chip(o.kind.replace(/_/g, " "), "dim"), el("span", "", o.text)));
    section.append(list);
    frag.append(section);
  }
  preserveFocus(panel, () => panel.replaceChildren(frag));
}

/** One evidence item, in the Evidence view and in the inspector's ledger. */
function evidenceCard(evidence) {
  const card = el("div", "ev" + (evidence.supports ? "" : " no"));
  const standing = C.evidenceStanding(evidence);
  card.append(add(el("div", "chips"),
    chip(standing.quote.text, standing.quote.tone, standing.quote.icon), chip(standing.direction.text, standing.direction.tone), chip(evidence.kind, "dim")));
  let copyQuote = null;
  if (evidence.quote) {
    const quote = textBox(evidence.quote, "txt out");
    card.append(quote);
    copyQuote = copyButton("Copy quote", () => C.quoteCopyText(evidence), { what: "Quote", text: true, cls: "ghost", source: quote, key: "copy-quote:" + evidence.id });
  }
  const producer = evidence.session ? S.sessions.byId.get(evidence.session) : null;
  const tool = evidence.session === S.openId ? S.rec?.calls.get(evidence.call_id)?.name : null;
  const from = el("span", "dim ev-from");
  if (evidence.session) {
    add(from, document.createTextNode("from "), tool ? el("code", "", tool) : document.createTextNode(evidence.call_id ? "call " + evidence.call_id : "a call"),
      document.createTextNode(" in "), link(producer?.title || evidence.session, C.sessionHash(evidence.session, "chat")));
  }
  if (evidence.blob) {
    const [start, end] = evidence.range || [1, 1];
    const source = btn("", "small evidence-source", (e) => openViewer(evidence.blob, "Source evidence", null, {
      start: Math.max(1, start - 3), end: Math.max(end + 3, start + 12),
      citeStart: evidence.range ? start : null, citeEnd: evidence.range ? end : null,
      session: evidence.session, call: evidence.call_id, tool, producer: producer?.title || null,
    }, e.currentTarget));
    add(source, icon("source"), document.createTextNode(evidence.range ? "Open source at " + evidence.lines : "Open stored source"));
    source.dataset.focusKey = "evidence:" + evidence.id;
    card.append(add(el("div", "ev-source"), source, copyQuote, evidence.session ? from : null));
  } else {
    card.append(add(el("div", "ev-source"), el("span", "dim", "No stored source is attached to this item."), copyQuote, evidence.session ? from : null));
  }
  if (evidence.note) card.append(el("p", "ev-note", evidence.note));
  return card;
}

// ---------------------------------------------------------------------------------------------
// Transcript blocks

function textBox(text, cls) {
  return el("pre", cls || "txt", text);
}

/**
 * Tool output, raw, with a look per line (C.outputLineKinds): the harness's own first and last lines muted, a unified
 * diff in green and red. Only spans are added; the text, and what a selection copies, stay exactly as recorded.
 * `kinds` may cover more lines than `text` (a clipped view of a longer output).
 */
function outputBox(text, kinds) {
  if (!kinds || !kinds.some(Boolean)) return textBox(text, "txt out");
  const pre = el("pre", "txt out");
  const lines = text.split("\n");
  let plain = "";
  const flush = () => { if (plain) { pre.append(document.createTextNode(plain)); plain = ""; } };
  lines.forEach((line, i) => {
    const nl = i < lines.length - 1 ? "\n" : "";
    if (!kinds[i]) { plain += line + nl; return; }
    flush();
    // The line break stays outside the span, so a full-width diff line never carries an extra blank line.
    pre.append(el("span", "ol ol-" + kinds[i], line));
    plain = nl;
  });
  flush();
  if (kinds.includes("hunk")) pre.classList.add("has-diff");
  return pre;
}

const modelChip = (m, extra = "") => {
  const chip = el("span", "model-chip" + extra, m.profile || "model");
  chip.title = [m.model, m.context_window ? C.formatWindow(m.context_window) + " context" : ""].filter(Boolean).join(" · ") || "model";
  return chip;
};

/** A details row keeps its open state in `b.ui`, so a rebuilt block (a live update in its group) does not close it again. */
function remembered(details, b, key) {
  details.open = !!(b.ui && b.ui[key]);
  details.addEventListener("toggle", () => {
    b.ui = b.ui || {};
    b.ui[key] = details.open;
  });
}

/** `ctx` carries the chat item a block is shown as: {differs, model}. */
/** A link to an agent: its title when the page knows it (the id stays the tooltip), else the id. */
function childLink(id) {
  const info = S.sessions.byId.get(id);
  const a = link(info && info.title ? info.title : id, "#/s/" + encodeURIComponent(id));
  a.title = id;
  return a;
}

/** The attachment block of an operator message (docs/UPLOADS.md): file chips that open in the Files tab, the inline copies folded. */
function attachedFiles(b, sp) {
  const box = el("div", "attached");
  const list = el("ul", "attach-chips");
  list.setAttribute("aria-label", "Attached files");
  const ws = (S.sessions.byId.get(S.openId) || {}).workspace || "";
  for (const f of sp.files) {
    const chip = el("button", "attach-chip attach-open");
    chip.type = "button";
    chip.title = "Open " + f.path + " in the Files tab";
    add(chip, icon("source"), el("span", "attach-name", f.name), el("span", "attach-size", f.size));
    chip.addEventListener("click", () => {
      const rel = C.workspaceRelative(ws, f.path);
      if (rel === null) toast(f.path + " is outside this session's workspace.");
      else showFiles(chip, rel);
    });
    add(list, add(el("li"), chip));
  }
  add(box, list);
  if (sp.inline) {
    const d = el("details", "attach-inline");
    add(d, el("summary", "", "Inline copies"));
    remembered(d, b, "inline");
    add(d, textBox(sp.inline, "txt out"));
    add(box, d);
  }
  return box;
}


// ---------------------------------------------------------------------------------------------
// Images (docs/CONTRACTS-2026-11-23.md D7): thumbnails, the viewer dialog, composer chip thumbnails

const imageCache = new Map(); // blob id -> Promise<data URL>; the bytes come only from /api/images/ and are cached for the page
const lazyImages = typeof IntersectionObserver === "function"
  ? new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { lazyImages.unobserve(e.target); fillImage(e.target); }
  }, { rootMargin: "200px" })
  : null;

/** The image bytes need the bearer header, which an img tag cannot send: fetch them, then show them as a data URL (the CSP allows data:). */
function imageData(blob) {
  if (!imageCache.has(blob)) {
    const p = (async () => {
      const r = await fetch(C.imageUrl(blob), { credentials: "omit", headers: authHeaders() });
      if (r.status === 401) { lost(); throw new Error(C.LOST_TOKEN); }
      if (!r.ok) throw new Error("The image could not be loaded (" + r.status + ").");
      const data = await r.blob();
      return await new Promise((resolve, reject) => {
        const fr = new FileReader();
        fr.addEventListener("load", () => resolve(String(fr.result)));
        fr.addEventListener("error", () => reject(new Error("The image could not be read.")));
        fr.readAsDataURL(data);
      });
    })();
    p.catch(() => imageCache.delete(blob));
    imageCache.set(blob, p);
  }
  return imageCache.get(blob);
}

function fillImage(img) {
  imageData(img.dataset.blob).then(
    (url) => { img.src = url; img.classList.add("loaded"); },
    (e) => { img.closest(".thumb")?.classList.add("broken"); img.alt = img.alt + " (not loaded: " + e.message + ")"; img.title = e.message; },
  );
}

/** One thumbnail button (max 240x240) that opens the viewer. `tool` is the tool name for a tool result's image. */
function thumb(image, { tool = "", files = [], args = null } = {}) {
  if (!C.imageUrl(image.blob)) return null;
  const size = C.thumbSize(image.width, image.height);
  const alt = C.imageAlt(image, tool);
  const b = el("button", "thumb");
  b.type = "button";
  b.setAttribute("aria-label", "Open image: " + alt + (C.imageFacts(image) ? ", " + C.imageFacts(image) : ""));
  b.title = alt;
  const img = el("img");
  img.alt = alt;
  img.loading = "lazy";
  img.decoding = "async";
  img.width = size.width;
  img.height = size.height;
  img.dataset.blob = image.blob;
  add(b, img);
  b.addEventListener("click", () => openImage(image, { tool, files, args, opener: b }));
  if (lazyImages) lazyImages.observe(img); else fillImage(img);
  return b;
}

function thumbRow(images, opts) {
  const list = el("ul", "thumbs");
  list.setAttribute("aria-label", C.imageCountLabel(images.length));
  for (const image of images) { const t = thumb(image, opts); if (t) add(list, add(el("li"), t)); }
  return list.children.length ? list : null;
}

let imageOpener = null;
function openImage(image, { tool = "", files = [], args = null, opener = document.activeElement } = {}) {
  const dialog = $("imgview");
  imageOpener = opener;
  const alt = C.imageAlt(image, tool);
  $("imgview-title").textContent = image.name || alt;
  $("imgview-info").textContent = C.imageFacts(image);
  const big = $("imgview-img");
  big.alt = alt;
  big.removeAttribute("src");
  imageData(image.blob).then((url) => { if (imageOpener === opener) big.src = url; }, (e) => { $("imgview-error").textContent = e.message; $("imgview-error").hidden = false; });
  $("imgview-error").hidden = true;
  const path = C.imagePath(image, { files, args });
  const copy = $("imgview-copy");
  copy.hidden = !path;
  copy.dataset.path = path || "";
  $("imgview-path").textContent = path || "";
  if (!dialog.open) dialog.showModal();
  $("imgview-close").focus({ preventScroll: true });
}
function closeImage() {
  const dialog = $("imgview");
  if (dialog.open) dialog.close();
}

/** A small thumbnail of a local image file for a composer chip, read from the File itself (never from a URL). */
function chipThumb(file, name) {
  const img = el("img", "chip-thumb");
  img.alt = "";
  img.width = 20;
  img.height = 20;
  // A file named .png that is not a decodable image keeps the plain file icon, never a broken-image glyph.
  const wrap = el("span", "chip-thumb-wrap");
  wrap.append(icon("source"));
  img.addEventListener("load", () => wrap.replaceChildren(img));
  const fr = new FileReader();
  fr.addEventListener("load", () => { img.src = String(fr.result); });
  fr.readAsDataURL(file);
  img.title = name;
  return wrap;
}

function buildBlock(b, ctx = {}) {
  const root = el("div", "block " + b.kind + (b.detail ? " detail" : ""));
  b.ui = b.ui || {};
  root.dataset.bid = String(b.id);
  switch (b.kind) {
    case "user": {
      if (b.author !== "user") add(root, el("div", "label", C.authorLabel(b.author)));
      const sp = C.splitAttachments(b.text);
      if (sp.text || !sp.files.length) {
        const bubble = textBox(sp.text, "txt bubble");
        root.classList.add("reveal-copy");
        add(root, bubble, copyButton("Copy message", () => C.messageCopyText(b), { what: "Message", source: bubble, key: "copy-msg:" + b.id }));
      }
      if (sp.files.length) add(root, attachedFiles(b, sp));
      if (b.images && b.images.length) add(root, thumbRow(b.images, { files: sp.files }));
      break;
    }
    case "note": {
      root.classList.add(b.note);
      add(root, el("div", "label", b.note.replace(/_/g, " ")));
      const open = b.ui.open ?? b.open;
      const c = C.clip(b.text, 3);
      if (open || !c.clipped) add(root, textBox(b.text));
      else add(root, textBox(c.text + "\n…", "txt clipped"));
      if (c.clipped) {
        add(root, btn(open ? "hide" : `show (${c.total} lines)`, "link", () => {
          b.ui.open = !open;
          refresh(b);
        }));
      }
      break;
    }
    case "response": {
      const thought = C.thoughtLabel(b);
      // A step that only called tools has nothing to read but its speed line; inside work it is request detail, shown
      // with "Show request details" (the tool rows keep their own durations).
      if (ctx.inGroup && !b.text && !b.reasoning && !(b.cutCalls || []).length && !b.warning) root.classList.add("detail", "step-stats");
      if (b.reasoning) {
        const d = el("details", "reasoning thought");
        const sum = el("summary", "", thought || "Thought");
        sum.dataset.focusKey = "thought:" + b.id;
        remembered(d, b, "thought");
        const thinking = textBox(b.reasoning);
        add(d, sum, add(el("div", "copy-row"), copyButton("Copy reasoning", () => C.reasoningCopyText(b), { what: "Reasoning", text: true, source: thinking, key: "copy-thought:" + b.id })), thinking);
        add(root, d);
      }
      if (b.text) {
        add(root, prose(b.text));
        const raw = el("details", "raw-response");
        const sum = el("summary", "", "Raw response");
        sum.dataset.focusKey = "raw:" + b.id;
        remembered(raw, b, "raw");
        add(raw, sum, textBox(b.text));
        add(root, raw);
      }
      for (const n of b.cutCalls) add(root, el("div", "warn", `The reply was cut inside a call to ${n}; the call was not run.`));
      if (b.warning) add(root, el("div", b.warning.level === "bad" ? "bad" : "warn", b.warning.text));
      const foot = el("div", "foot");
      const meta = el("span", "foot-text", C.replyMeta(b, ctx.differs && ctx.model ? ctx.model.profile : "") || b.footer);
      meta.title = b.footer;
      add(foot, meta);
      if (C.replyCopyText(b) !== null) {
        root.classList.add("reveal-copy");
        add(foot, copyButton("Copy reply", () => C.replyCopyText(b), { what: "Reply", key: "copy-reply:" + b.id, tip: "Copy the reply's exact text, as the raw response shows it." }));
      }
      add(root, foot);
      break;
    }
    case "tool":
      buildTool(root, b);
      break;
    case "child_spawned": {
      root.classList.add("card");
      const h = el("div", "ch");
      const modeEl = el("span", "dim", b.mode === "fork" ? "forked" : b.mode);
      if (b.mode === "fresh") modeEl.title = "Starts from its brief alone, without the lead's conversation.";
      else if (b.mode === "fork") modeEl.title = "Starts from a copy of the lead's conversation.";
      add(h, icon("tool-agent"), el("strong", "", `agent started: ${b.role}`), modeEl, childLink(b.child));
      add(root, h, textBox(b.brief.question || "", "txt"));
      break;
    }
    case "child_settled": {
      if (b.inline) {
        root.classList.add("line");
        root.textContent = `agent ${b.child} ${C.outcomeWords(b.outcome)} (${b.steps} steps); its report is the result of the call above`;
        break;
      }
      root.classList.add("card");
      const h = el("div", "ch");
      add(h, icon("tool-agent"), el("strong", "", `agent ${C.outcomeWords(b.outcome)}`), childLink(b.child), el("span", "dim", `${b.steps} steps`));
      add(root, h);
      // A report is the agent's written reply: shown as formatted text, like a reply, clipped until asked for.
      add(root, collapsible(b, "report", b.report, 24, { prose: true }));
      if (b.full) add(root, keyed(btn("open full report", "link", (e) => openViewer(b.full.id, "Full report", null, {}, e.currentTarget)), "report:" + b.id));
      break;
    }
    case "line": {
      root.classList.add(b.tone === "warn" ? "warn" : "dimline");
      if (b.sub === "switch") {
        root.classList.add("model-switch");
        add(root, icon("diamond-outline"), el("span", "", b.text));
      } else {
        root.textContent = b.text;
      }
      if (b.blob) add(root, keyed(btn("open output", "link", (e) => openViewer(b.blob.id, "Job output", null, {}, e.currentTarget)), "output:" + b.id));
      break;
    }
    case "compaction": {
      root.classList.add("card");
      const h = el("div", "ch compaction-head");
      add(h, icon("diamond-outline"), el("strong", "", b.head));
      add(root, h);
      if (b.objections) add(root, el("div", "dim compaction-objections", "The verifier objected to: " + b.objections));
      const note = el("details", "compaction-part compaction-note");
      add(note, el("summary", "", b.note ? "Note" : "Note (none written)"));
      remembered(note, b, "note");
      if (b.note) {
        add(note, el("div", "dim", C.COMPACT_NOTE_LABEL), add(el("div", "report-prose"), linkOutKeys(prose(b.note))));
        if (b.droppedKeys.length) {
          const dropped = el("div", "compaction-dropped");
          add(dropped, el("div", "dim", C.COMPACT_DROPPED_LABEL));
          add(dropped, el("code", "", b.droppedKeys.join(" ")));
          add(note, dropped);
        }
      } else add(note, el("div", "dim", C.COMPACT_NO_NOTE));
      add(root, note);
      const table = el("details", "compaction-part compaction-table");
      add(table, el("summary", "", b.table ? `Key table · ${C.count(b.tableKeys.length, "output", "outputs")}` : "Key table (empty)"));
      remembered(table, b, "table");
      if (b.table) add(table, keyedText(b.table));
      add(root, table);
      break;
    }
    case "reweave": {
      const d = el("details");
      add(d, el("summary", "", b.summary));
      const inner = el("div", "inner");
      add(inner, el("div", "dim", C.REWEAVE_NOTE));
      const ul = el("ul");
      for (const e of b.evictions) add(ul, el("li", "", `#${e.seq}  ${e.words}`));
      add(inner, ul);
      if (b.digest) add(inner, el("div", "label", "digest (written by the model, unverified)"), textBox(b.digest));
      add(inner, el("div", "label", "brief put in view"), textBox(b.brief));
      add(d, inner);
      add(root, d);
      break;
    }
    case "inbox": {
      root.classList.add("block-inbox", b.item.blocking ? "decision-card" : "informational");
      if (b.resolved) root.classList.add("done");
      add(root, inboxCard({ session: S.openId, title: S.sessions.byId.get(S.openId)?.title, item: b.item, opened_ms: b.ts }, C.cardResolution(b.item, b.resolved, S.answered.get(b.item.item_id), S.ledger.model ? S.ledger.model.scope : null), "record"));
      break;
    }
    case "divider":
      root.textContent = b.text;
      break;
    case "end":
      root.textContent = b.text;
      break;
    default:
      root.textContent = b.kind;
  }
  return root;
}

/** A control a live update may replace: its key lets focus (and the viewer's return) find the new one. */
function keyed(node, key) {
  node.dataset.focusKey = key;
  return node;
}

function collapsible(b, key, text, max, opts = {}) {
  const wrap = el("div");
  const all = !!b.ui[key];
  const c = C.clip(text, max);
  const shown = all ? text : c.text;
  add(wrap, opts.prose ? add(el("div", "report-prose"), prose(shown)) : opts.styled ? outputBox(shown, C.outputLineKinds(text)) : textBox(shown, "txt out"));
  if (c.clipped) {
    add(wrap, keyed(btn(all ? "show less" : `show all ${C.num(c.total)} lines`, "link", () => {
      b.ui[key] = !all;
      refresh(b);
    }), `showall:${b.id}:${key}`));
  }
  return wrap;
}

/** One tool call as a one-line row; the row opens to today's full output UI. */
function buildTool(root, b) {
  const res = b.result;
  const row = C.toolRow(b);
  const open = !!b.ui.open;
  root.classList.add("trow", "out-" + row.outcome);
  // Red is for a call that reported failure; an exit code, a refusal or a timeout each have their own look.
  if (row.outcome === "failed") root.classList.add("bad");
  const head = el("button", "thead");
  head.type = "button";
  head.setAttribute("aria-expanded", String(open));
  head.dataset.focusKey = "tool:" + b.id;
  const nameEl = el("span", "name", row.name);
  if (row.calledAs) nameEl.title = `Called as ${row.calledAs}; ran ${row.name}`;
  add(head, icon("chevron"), icon(row.icon), nameEl);
  // A call that says what it is for (bash's `description`) leads with that; the command stays beside it, dimmer.
  if (row.label) add(head, el("span", "tlabel", row.label));
  const args = el("span", row.label ? "args sub" : "args", row.argsLine);
  if (b.argsInvalid) args.title = "The model's arguments were not valid JSON; this is what it wrote.";
  add(head, args);
  if (row.capsule) {
    const cap = el("span", "capsule tone-" + row.capsule.tone);
    add(cap, icon(row.capsule.icon), document.createTextNode(row.capsule.text));
    if (row.words) cap.title = row.words;
    add(head, cap);
  }
  if (row.partial) {
    // An outline mark, in words: the model saw only part of this output.
    const mark = el("span", "partial-mark");
    add(mark, icon("half"), document.createTextNode("partial"));
    mark.title = row.partial.words;
    add(head, mark);
  }
  // A file change says how big it was, as the diff it returned counts it.
  const stat = res && b.cls === "write" ? C.diffStat(res.text) : null;
  if (stat) {
    const chip = el("span", "diffstat");
    add(chip, el("span", "ds-add", "+" + C.num(stat.added)), el("span", "ds-del", "−" + C.num(stat.removed)));
    chip.title = stat.words;
    add(head, chip);
  }
  if (res && res.images && res.images.length) {
    const n = el("span", "img-count");
    add(n, icon("image"), document.createTextNode(String(res.images.length)));
    n.title = C.imageCountLabel(res.images.length);
    n.setAttribute("aria-label", C.imageCountLabel(res.images.length));
    add(head, n);
  }
  if (row.duration) add(head, el("span", "dur", row.duration));
  else if (row.state === "running" && Number.isFinite(b.ts)) {
    // A call still out counts up, so a long build reads as working, not stuck (tickGroups moves it each second).
    const live = el("span", "dur live-dur", C.seconds(Math.max(0, Date.now() - b.ts)));
    live.dataset.since = String(b.ts);
    live.title = "Running for this long so far";
    add(head, live);
  }
  head.addEventListener("click", () => {
    b.ui.open = !open;
    refresh(b);
  });
  add(root, head);
  if (!open) return;
  const body = el("div", "tbody");
  add(body, toolOpenRow(b), toolCopyRow(b));
  if (b.args !== undefined && b.args !== null) {
    add(body, keyed(btn(b.ui.args ? "Hide arguments" : "Show arguments", "small link targs", () => {
      b.ui.args = !b.ui.args;
      refresh(b);
    }), "args:" + b.id));
  }
  if (b.ui.args) add(body, textBox(JSON.stringify(b.args, null, 2), "txt out"));
  if (res) {
    if (res.images && res.images.length) add(body, thumbRow(res.images, { tool: b.ran || b.name, args: b.args }));
    if (res.text === "") add(body, el("div", "dim", "(no output)"));
    else add(body, collapsible(b, "all", res.text, 24, { styled: true }));
    const s = res.shown;
    if (s.words || s.blob) {
      const note = el("div", "tnote" + (s.cut ? " cutline" : ""));
      add(note, document.createTextNode(s.words ? s.words + " " : ""));
      if (s.blob) add(note, keyed(btn("open full output", "link", (e) => openViewer(s.blob, `Full output of ${b.ran || b.name}`, s.total, {}, e.currentTarget)), "full:" + b.id));
      add(body, note);
    }
  } else if (b.state === "missing") {
    add(body, el("div", "tnote warn", "no result recorded"));
  } else {
    add(body, el("div", "tnote", "running…"));
  }
  add(root, body);
}

/** The copy buttons of an open tool row: its command (or path, or arguments), its recorded output, and the full stored output. */
function toolCopyRow(b) {
  const command = C.toolCommandCopy(b);
  const output = C.toolOutputCopy(b);
  const plan = C.fullOutputPlan(b);
  if (!command && output === null && !plan) return null;
  const row = el("div", "copy-row");
  if (command) add(row, copyButton("Copy " + command.what.toLowerCase(), () => command.text, { what: command.what, text: true, cls: "ghost", key: "copy-cmd:" + b.id, tip: `Copy this call's ${command.what.toLowerCase()}.` }));
  if (output !== null) add(row, copyButton("Copy output", () => output, { what: "Output", text: true, cls: "ghost", key: "copy-out:" + b.id, tip: "Copy the output recorded in this row: every line the model was shown, not only the folded part." }));
  if (plan) {
    add(row, copyButton("Copy full output…", async () => {
      if (plan.tooBig) throw new Error(C.COPY_FULL_BIG);
      return fetchStoredText(plan.blob);
    }, { what: "Full output", text: true, key: "copy-full:" + b.id, busy: "Fetching…", tip: "Fetch the whole stored output (up to 2 MiB) and copy it." }));
  }
  return row;
}

/** The whole stored output as text, read through the blob route; refused above the copy cap without keeping it. */
async function fetchStoredText(blob) {
  const r = await fetch(C.rawUrl(blob), { credentials: "omit", headers: authHeaders() });
  if (r.status === 401) { lost(); throw new Error(C.LOST_TOKEN); }
  if (!r.ok) throw new Error(C.errorSentence(r.status, await r.text()));
  const length = Number(r.headers.get("content-length"));
  if (length > C.COPY_FULL_CAP) { if (r.body) r.body.cancel().catch(() => {}); throw new Error(C.COPY_FULL_BIG); }
  if (!r.body || !r.body.getReader) {
    const text = await r.text();
    if (new TextEncoder().encode(text).length > C.COPY_FULL_CAP) throw new Error(C.COPY_FULL_BIG);
    return text;
  }
  const reader = r.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > C.COPY_FULL_CAP) { reader.cancel().catch(() => {}); throw new Error(C.COPY_FULL_BIG); }
    chunks.push(value);
  }
  const decoder = new TextDecoder();
  return chunks.map((c) => decoder.decode(c, { stream: true })).join("") + decoder.decode();
}

// ---- the chat: items (blocks, work groups, model chips) reconciled into #blocks

function groupHeadText(it) {
  // Only ledger, job or cache lines, no calls: say that instead of "0 tool calls".
  if (!it.toolCount) {
    return `Activity · ${C.count(it.records, "record")}` + (it.warnings ? ` · ${C.count(it.warnings, "warning")}` : "") + (it.running ? " · running" : "");
  }
  const words = C.groupLabel(it, Date.now());
  // The outcome counts and warnings are drawn as labelled marks after the words, so the words leave them out.
  return words.head;
}

/** The header's words in both lengths: the sentence, and on a phone the short form ("Worked 2m43s · 8 calls"). Both are hidden from assistive technology; the button's own name is the long sentence. */
function fillGroupLabel(label, it) {
  const long = groupHeadText(it);
  const short = it.toolCount ? C.groupLabel(it, Date.now()).short : long;
  if (!label.firstChild) label.append(el("span", "gl-long"), el("span", "gl-short"));
  if (label.firstChild.textContent !== long) label.firstChild.textContent = long;
  if (label.lastChild.textContent !== short) label.lastChild.textContent = short;
}

/** The accessible name of a group header: the same words without a clock that runs while the group does. */
function groupSpoken(it) {
  if (!it.toolCount) return groupHeadText(it);
  return C.groupLabel(it, Date.now()).spoken;
}

function toggleGroup(it) {
  if (it.open) S.openGroups.delete(it.key);
  S.workState.set(it.key, !it.open);
  syncChat();
}

function pinOpenGroups() {
  if (!S.r || S.follow) return;
  for (const it of S.r.items || []) {
    if (it.type === "group" && it.open && S.workState.get(it.key) !== false) {
      S.openGroups.add(it.key);
    }
  }
}

// The group's counts, in the order the header words say them: [field, outcome kind, words].
// The fourth entry is the mark's visible word (left out on a phone, where the mark is its shape and number).
const GROUP_MARKS = [
  ["exited", "exit", "exited non-zero", "exited"], ["failed", "failed", "failed", "failed"], ["denied", "denied", "denied by policy", "denied"],
  ["invalid", "invalid", "invalid", "invalid"], ["timedOut", "timeout", "timed out", "timed out"], ["interrupted", "interrupted", "interrupted", "interrupted"],
];

/** The frame of a work group: its header button and, while it is open, its body. Members are kept between updates. */
function newGroupEntry(it) {
  const root = el("div", "work-group");
  root.dataset.group = it.key;
  const head = el("button", "group-head");
  head.type = "button";
  head.dataset.focusKey = "group:" + it.key;
  const entry = { group: true, node: root, head, label: null, body: null, members: new Map(), earlierRow: null, headSig: "", item: it, sig: "" };
  head.addEventListener("click", () => toggleGroup(entry.item));
  add(root, head);
  return entry;
}

/** Bring a group's node up to date with `it`: the header in place, and (when open) only the members that are new or dirty. */
function updateGroup(entry, it, dirty) {
  const { node, head } = entry;
  node.className = "work-group" + (it.open ? " open" : "") + (it.failed ? " has-failed" : "") + (it.warnings ? " has-warn" : "");
  const counts = GROUP_MARKS.map(([field]) => it[field] || 0);
  head.setAttribute("aria-expanded", String(it.open));
  head.title = it.open ? "Fold this work away; every call stays in the record." : "Show the calls in this work.";
  const headSig = [it.toolCount, ...counts, it.partial || 0, it.missing, it.warnings, it.running, it.records, it.running ? "" : it.endTs].join("|");
  if (entry.headSig !== headSig) {
    entry.headSig = headSig;
    const label = el("span", "group-label");
    fillGroupLabel(label, it);
    label.dataset.groupLabel = "1";
    // The visible clock ticks; the name that is spoken does not, so a screen reader is not told a new number every second.
    label.setAttribute("aria-hidden", "true");
    entry.label = label;
    head.setAttribute("aria-label", groupSpoken(it));
    head.replaceChildren(icon("chevron"), label);
    // Each way a call can end has its own small shape and number, so a refusal is not read as a failure.
    const marks = el("span", "group-marks");
    marks.setAttribute("aria-hidden", "true");
    GROUP_MARKS.forEach(([, kind, noun, word], i) => {
      if (!counts[i]) return;
      const look = C.TOOL_OUTCOME_LOOK[kind];
      const mark = el("span", "group-mark tone-" + look.tone);
      mark.title = `${counts[i]} ${noun}`;
      add(mark, icon(look.icon), el("span", "group-mark-n", String(counts[i])), el("span", "group-mark-w", word));
      marks.append(mark);
    });
    if (it.warnings) {
      const warn = el("span", "group-mark group-warn");
      warn.title = C.count(it.warnings, "warning");
      add(warn, icon("alert"), el("span", "group-mark-n", String(it.warnings)), el("span", "group-mark-w", it.warnings === 1 ? "warning" : "warnings"));
      marks.append(warn);
    }
    if (marks.childElementCount) head.append(marks);
  }
  if (!it.open) {
    if (entry.body) { entry.body.remove(); entry.body = null; entry.members.clear(); entry.earlierRow = null; }
    return;
  }
  if (!entry.body) { entry.body = el("div", "group-body"); node.append(entry.body); }
  const keep = new Set(it.shown.map((b) => b.id));
  for (const [id, member] of entry.members) if (!keep.has(id)) { member.remove(); entry.members.delete(id); }
  const order = [];
  if (it.earlier > 0) {
    if (!entry.earlierRow) {
      entry.earlierRow = btn("", "link group-earlier", showEarlier);
      entry.earlierRow.dataset.focusKey = "earlier:" + it.key;
    }
    entry.earlierRow.textContent = `${C.num(it.earlier)} earlier in this work`;
    order.push(entry.earlierRow);
  } else if (entry.earlierRow) {
    entry.earlierRow.remove();
    entry.earlierRow = null;
  }
  for (const b of it.shown) {
    let member = entry.members.get(b.id);
    if (!member || dirty.has(b.id)) {
      const built = buildBlock(b, { inGroup: true });
      if (member && member.parentNode === entry.body) member.replaceWith(built);
      member = built;
      entry.members.set(b.id, member);
    }
    order.push(member);
  }
  placeInOrder(entry.body, order);
}

/** Put `nodes` under `parent` in that order, moving only what is out of place. */
function placeInOrder(parent, nodes) {
  let cursor = parent.firstChild;
  for (const n of nodes) {
    if (n === cursor) cursor = cursor.nextSibling;
    else parent.insertBefore(n, cursor);
  }
}

function buildItem(it) {
  if (it.type === "model") {
    const row = el("div", "model-row");
    add(row, modelChip(it));
    return row;
  }
  if (it.type === "since") {
    const line = el("div", "block divider since");
    line.setAttribute("role", "separator");
    add(line, el("span", "", it.text));
    if (it.straddles) line.title = "The work group below began before your last visit and has grown since.";
    return line;
  }
  return buildBlock(it.block, { differs: it.differs, model: it.model });
}

const itemKey = (it) => it.type === "model" ? `m${it.seq}${it.reason}` : it.type === "since" ? "since" : it.type === "group" ? it.key : "b" + it.block.id;

function itemSig(it) {
  if (it.type === "model") return it.profile + "|" + it.model;
  if (it.type === "since") return it.text + "|" + it.straddles;
  return (it.differs ? "d" : "") + (it.model ? it.model.profile : "");
}

function itemDirty(it, dirty) {
  return it.type === "block" && dirty.size > 0 && dirty.has(it.block.id);
}

/** The chat items of the open record under the operator's folds, windowed to what is shown. */
function chatView() {
  const store = S.rec;
  const open = new Set([...S.openGroups, ...[...S.workState].filter(([, v]) => v).map(([k]) => k)]);
  const items = C.chatItems(store.blocks, { expandAll: S.expandAll, details: S.details, open, models: store.models, sinceSeq: S.sinceSeq, lastSeq: C.lastSeq(store) });
  if (!S.expandAll) for (const it of items) if (it.type === "group" && S.workState.has(it.key)) it.open = S.workState.get(it.key);
  // A group that crosses the window start keeps only its members inside it, so a long open run is not rendered in full.
  return C.windowItems(items, S.r.from);
}

function syncChat() {
  const store = S.rec;
  const R = S.r;
  if (!store || !R || S.view !== "session") return;
  if (!S.follow) pinOpenGroups();
  const holder = $("blocks");
  const dirty = new Set([...C.takeDirty(store), ...R.forced]);
  R.forced.clear();
  const items = chatView();
  R.items = items;
  preserveFocus(holder, () => {
    // Nodes that left the window go first, so the ones that stay are never moved past them.
    const keep = new Set(items.map(itemKey));
    for (const [key, entry] of R.nodes) {
      if (!keep.has(key)) {
        entry.node.remove();
        R.nodes.delete(key);
      }
    }
    const order = [];
    for (const it of items) {
      const key = itemKey(it);
      let entry = R.nodes.get(key);
      if (it.type === "group") {
        if (!entry) { entry = newGroupEntry(it); R.nodes.set(key, entry); }
        updateGroup(entry, it, dirty);
        entry.item = it;
      } else {
        const sig = itemSig(it);
        if (!entry || entry.sig !== sig || itemDirty(it, dirty)) {
          const node = buildItem(it);
          if (entry && entry.node.parentNode === holder) entry.node.replaceWith(node);
          entry = { node, sig, item: it };
          R.nodes.set(key, entry);
        } else {
          entry.item = it;
        }
      }
      order.push(entry.node);
    }
    placeInOrder(holder, order);
  });
  $("earlier").hidden = R.from === 0 && !C.hasEarlier(S.rec);
  if (!S.rec.earlierLoading) $("btn-earlier").textContent = R.from > 0 ? `Show earlier (${C.num(R.from)} more)` : "Load earlier records";
  tickGroups();
}

/** Running groups count up to now; called by the run timer and on every sync. Only the visible words change. */
function tickGroups() {
  const R = S.r;
  if (!R) return;
  const now = Date.now();
  for (const n of document.querySelectorAll("#blocks .live-dur[data-since]")) n.textContent = C.seconds(Math.max(0, now - Number(n.dataset.since)));
  for (const [, entry] of R.nodes) {
    const it = entry.item;
    if (it.type !== "group" || !it.running || !entry.label) continue;
    fillGroupLabel(entry.label, it);
  }
}

function refresh(b) {
  const R = S.r;
  if (!R) return;
  R.forced.add(b.id);
  syncChat();
}

function renderBlocks() {
  const store = S.rec;
  const R = S.r;
  if (!store || !R || S.view !== "session") return;
  renderStats();
  const scroller = chatScroller();
  const total = store.blocks.length;
  if (total > R.end) {
    if (S.follow) R.from = R.fresh ? C.initialFrom(total) : Math.max(R.from, C.trimFrom(total, R.from, C.MAX_RENDERED));
    R.fresh = false;
    R.end = total;
  }
  syncChat();
  // Landing on a session that has its own open question: show the question, not the end of the record.
  if (!R.landed && store.initialComplete) {
    R.landed = true;
    const need = S.section === "chat" ? ownBlockingBlock() : null;
    if (need) {
      S.follow = false;
      jumpToRecord(need.seq, { highlight: false });
      updateJump();
      updateChildBlocker();
      return;
    }
  }
  if (S.follow) scroller.scrollTop = scroller.scrollHeight;
  updateJump();
  updateChildBlocker();
}

/** The open session's own blocking question: the block that holds it, or null. */
function ownBlockingBlock() {
  const blocks = S.rec ? S.rec.blocks : [];
  for (let i = blocks.length - 1; i >= 0; i--) {
    const b = blocks[i];
    if (b.kind === "inbox" && b.item && b.item.blocking && !b.resolved) return b;
  }
  return null;
}

/** Is the card of `block` inside the chat's visible band (between the sticky tabs and the composer)? */
function cardOnScreen(block) {
  const node = $("blocks").querySelector(`[data-bid="${block.id}"]`);
  if (!node) return false;
  const view = chatScroller().getBoundingClientRect();
  const r = node.getBoundingClientRect();
  const top = COMPACT.matches ? Math.max(view.top, $("mission-tabs").getBoundingClientRect().bottom) : view.top;
  const bottom = COMPACT.matches ? Math.min(view.bottom, $("composer").getBoundingClientRect().top) : view.bottom;
  const visible = Math.min(r.bottom, bottom) - Math.max(r.top, top);
  return visible >= Math.min(r.height * 0.25, 120);
}

/**
 * The button over the chat's foot. "needs": the session's own question is off screen, and the button says what waits and takes
 * the operator to it (amber: it is the one thing here that needs them). "latest": the chat is scrolled away from the end, with the
 * count of records since. Hidden while the card is on screen, so it never covers the question.
 */
function updateJump() {
  const jump = $("jump");
  const block = S.section === "chat" && S.rec ? ownBlockingBlock() : null;
  const shown = !!block && cardOnScreen(block);
  const mode = C.jumpMode({ section: S.section, follow: S.follow, needsOffscreen: !!block && !shown, cardShown: shown });
  if (S.follow) S.jumpFrom = null;
  S.jumpNeed = mode === "needs" ? block : null;
  jump.hidden = mode === "hidden" || !S.rec;
  jump.classList.toggle("needs", mode === "needs");
  if (jump.hidden) return;
  if (mode === "needs") {
    const noun = C.waitingNoun(block.item.item_kind);
    const label = `${noun} · Show`;
    if (jump.dataset.label !== label) { jump.dataset.label = label; jump.replaceChildren(icon("diamond"), document.createTextNode(label)); }
    return;
  }
  if (S.jumpFrom === null) S.jumpFrom = C.lastSeq(S.rec);
  const label = C.jumpLabel(S.jumpFrom === null || S.jumpFrom === undefined ? 0 : C.visibleRecordsAfter(S.rec.blocks, S.jumpFrom, S.details));
  if (jump.dataset.label !== label) { jump.dataset.label = label; jump.replaceChildren(document.createTextNode(label)); }
}

function showEarlier() {
  const store = S.rec;
  const R = S.r;
  if (!store) return;
  if (R.from === 0) { loadEarlier(store); return; }
  const scroller = chatScroller();
  const before = scroller.scrollHeight;
  R.from = C.earlierFrom(R.from);
  R.forced.clear();
  syncChat();
  scroller.scrollTop += scroller.scrollHeight - before;
}

// ---- the reply that is streaming now

function renderLive() {
  const holder = $("live");
  const p = S.rec && S.rec.pending;
  if (!p) {
    if (S.liveEl) {
      clear(holder);
      S.liveEl = null;
    }
    return;
  }
  let L = S.liveEl;
  if (!L || L.req !== p.req_id) {
    clear(holder);
    const root = el("div", "live");
    const chipRow = el("div", "model-row");
    const label = el("div", "label dim", "");
    const retry = el("div", "warn");
    const reasoning = el("pre", "txt dim");
    const text = el("pre", "txt");
    const calls = el("div");
    add(root, chipRow, label, retry, reasoning, text, calls);
    holder.append(root);
    L = S.liveEl = { req: p.req_id, chipRow, label, retry, reasoning, text, calls };
  }
  const lastItem = S.r && S.r.items[S.r.items.length - 1];
  const segmentChipShown = lastItem && (lastItem.type === "group" || lastItem.type === "model" || (lastItem.type === "block" && lastItem.block.kind === "response"));
  const cur = C.currentModel(S.rec, S.sessions.byId.get(S.openId));
  L.chipRow.replaceChildren(...(cur && !segmentChipShown ? [modelChip(cur)] : []));
  L.chipRow.hidden = !L.chipRow.firstChild;
  L.label.textContent = p.attempt > 1 ? `model is writing (attempt ${p.attempt})` : "model is writing";
  L.retry.textContent = p.retrying ? C.retryingWords(p.retrying) : "";
  L.retry.hidden = !p.retrying;
  L.reasoning.textContent = C.tail(p.reasoning, 4000);
  L.reasoning.hidden = !p.reasoning;
  L.text.textContent = p.text;
  L.text.hidden = !p.text;
  const streamingText = !!p.text || (!p.reasoning && p.calls.length === 0);
  L.text.classList.toggle("streaming", !!p.text);
  L.reasoning.classList.toggle("streaming", !p.text && !!p.reasoning && p.calls.length === 0);
  L.calls.replaceChildren(...p.calls.map((c, i) => {
    const row = el("div", "tool-live");
    add(row, el("strong", "", c.name || "(call)"), el("span", "mono dim", " " + C.tail(oneLineArgs(c.args), 300)));
    if (i === p.calls.length - 1 && !streamingText) row.classList.add("streaming");
    return row;
  }));
  if (S.follow) chatScroller().scrollTop = chatScroller().scrollHeight;
}

function oneLineArgs(s) {
  return C.oneLine(s, 100000);
}

// ---------------------------------------------------------------------------------------------
// Inbox cards and view

/** Keycaps for a button that has keys: a run of <kbd>, hidden from assistive technology (the button carries aria-keyshortcuts). */
function keycaps(keys) {
  const caps = el("span", "keycaps");
  caps.setAttribute("aria-hidden", "true");
  keys.forEach((k, i) => { if (i) caps.append(document.createTextNode(" ")); caps.append(el("kbd", "", k)); });
  return caps;
}

/**
 * After an answer is sent: focus the next open card of the same list (its answer field, else the card itself, so one more Enter never
 * lands on a button that grants something), else the receipt of the one just sent, else the list itself when the receipt went with the item.
 */
function focusCard(id, receipt, scope) {
  const root = scope && scope.isConnected ? scope : document;
  const shown = (n) => n.getClientRects().length > 0;
  const next = id && [...root.querySelectorAll(`[data-answer-item="${CSS.escape(id)}"]`)].find(shown);
  if (next) {
    const field = [...next.querySelectorAll("textarea:not([disabled])")].find(shown);
    if (field) { field.focus({ preventScroll: false }); return; }
    next.tabIndex = -1;
    next.focus({ preventScroll: false });
    return;
  }
  const given = receipt && receipt.isConnected && receipt.querySelector(".given");
  if (given) { given.tabIndex = -1; given.focus({ preventScroll: true }); return; }
  const stable = root.querySelector(".inbox-empty") || (root !== document && shown(root) ? root : null);
  if (stable) { stable.tabIndex = -1; stable.focus({ preventScroll: true }); }
}

/**
 * "Ways out" of a blocker or park: fold the context, or switch the model. Both confirm first and nothing runs on its own. The latest
 * recorded error is shown when this card's session is the open one, because only its record is loaded.
 */
function waysOut(entry, context) {
  const box = el("div", "ways-out");
  box.setAttribute("role", "group");
  box.setAttribute("aria-label", "Ways out");
  const info = S.sessions.byId.get(entry.session);
  const title = (info && info.title) || entry.title || entry.session;
  add(box, el("div", "ways-head", "Ways out"));
  const rawErr = entry.session === S.openId && S.rec ? C.lastRecordedError(S.rec.blocks) : null;
  const known = C.dedupeParkedError(entry.item.text, rawErr);
  if (known) {
    const line = el("p", "ways-error");
    add(line, el("span", "label", "Last recorded error "), el("span", "txt", known));
    box.append(line);
  }
  const confirm = el("div", "model-confirm");
  confirm.setAttribute("role", "group");
  confirm.hidden = true;
  const q = C.compactConfirm(title);
  const qid = "fold-q-" + entry.item.item_id;
  const text = el("p", "model-confirm-text", q.text);
  text.id = qid;
  confirm.setAttribute("aria-labelledby", qid);
  const receipt = el("p", "dim ways-receipt");
  receipt.setAttribute("role", "status");
  const failure = el("p", "error");
  failure.setAttribute("role", "alert");
  failure.hidden = true;
  const fold = btn("Compact the context…", "", () => {
    confirm.hidden = !confirm.hidden;
    fold.setAttribute("aria-expanded", String(!confirm.hidden));
    receipt.textContent = "";
    failure.hidden = true;
    if (!confirm.hidden) keep.focus();
  });
  fold.setAttribute("aria-expanded", "false");
  fold.dataset.focusKey = "fold:" + entry.item.item_id;
  const yes = btn(q.yes, "small primary", async () => {
    yes.disabled = true;
    failure.hidden = true;
    try {
      await api("POST", "/api/sessions/" + encodeURIComponent(entry.session) + "/compact");
      confirm.hidden = true;
      fold.setAttribute("aria-expanded", "false");
      receipt.textContent = C.COMPACT_RECEIPT;
      fold.focus();
    } catch (e) {
      fail(failure, e.message);
    } finally {
      yes.disabled = false;
    }
  });
  noRepeat(yes);
  const keep = btn(q.no, "small", () => { confirm.hidden = true; fold.setAttribute("aria-expanded", "false"); fold.focus(); });
  add(confirm, text, add(el("span", "model-confirm-actions"), yes, keep));
  const sw = btn("Switch model…", "", () => {
    const go = () => {
      const seat = $("model-seat");
      if (!seat) return;
      if (seat.disabled) { notice(seat.title || "This session's model cannot be changed now."); return; }
      seat.focus();
    };
    if (location.hash === C.sessionHash(entry.session) && S.view === "session" && S.openId === entry.session) { go(); return; }
    location.hash = C.sessionHash(entry.session);
    // The route opens the session and draws its seat; focus it once that has happened.
    let tries = 0;
    const wait = () => { if (S.openId === entry.session && S.view === "session" && $("model-seat").options.length) go(); else if (tries++ < 40) setTimeout(wait, 50); };
    wait();
  });
  add(box, add(el("div", "ways-actions"), fold, sw), confirm, receipt, failure);
  return box;
}

/**
 * One inbox item. `context` is where the card is shown: "inbox" (every mission), "overview" (the
 * open mission) or "record" (the open session). Nothing is sent until the operator presses the
 * submit button: a suggested answer only fills the draft.
 */
function inboxCard(entry, resolved, context = "inbox") {
  const item = entry.item;
  const key = "inbox:" + item.item_id;
  const result = item.item_kind === "finished";
  const card = el("div", "inbox-card");
  card.dataset.answerItem = item.item_id;
  card.setAttribute("role", "group");
  card.setAttribute("aria-label", `${result ? "Result ready" : C.inboxCardKind(item)}${entry.title ? ": " + entry.title : ""}`);
  const h = el("div", "ih");
  add(h, el("span", "kind", result ? "Result ready" : C.inboxCardKind(item)));
  add(h, el("span", item.blocking ? "state" : "dim", item.blocking ? "Needs your answer" : result ? "Review when ready" : "Work can continue"));
  // A card shown inside its own session needs no link back to where the operator already is.
  if (entry.title && (context === "inbox" || entry.session !== S.openId)) add(h, link(entry.title, C.sessionHash(entry.session)));
  if (entry.opened_ms) {
    const asker = S.sessions.byId.get(entry.session);
    const time = el("time", "", ago(entry.opened_ms));
    time.dataset.opened = String(entry.opened_ms);
    time.dateTime = new Date(entry.opened_ms).toISOString();
    add(h, add(el("span", "dim"), document.createTextNode(result ? "" : "asked "), time,
      document.createTextNode(result || !asker ? "" : asker.parent ? " by an agent" : C.rootNoun(asker) === "lead" ? " by the lead" : "")));
  }
  const itemText = textBox(item.text, "txt prose-text item-text");
  const copyItem = copyButton("Copy text", () => C.inboxCopyText(item), { what: "Request text", text: true, cls: "ghost", source: itemText, key: "copy-item:" + context + ":" + item.item_id });
  add(card, h, itemText, add(el("div", "copy-row"), copyItem));
  if (resolved) {
    const given = el("div", "given");
    // A scope request the operator approved is not "Dismissed": the hosts were granted first.
    add(given, el("div", "label", resolved.approved ? "Approved · hosts granted: " + resolved.approved.join(", ") : C.isRefusal(resolved.answer) ? "Refused" : resolved.answer === "" ? (C.scopeRequestHosts(item) ? "Closed" : "Dismissed") : "Answered"));
    if (resolved.answer !== "") given.append(textBox(resolved.answer, "txt prose-text"));
    card.append(given);
    return card;
  }
  const err = el("p", "error");
  err.setAttribute("role", "alert");
  err.hidden = true;
  const form = el("div", "answer");
  form.dataset.blocking = String(!!item.blocking);
  const send = async (answer, approved = null) => {
    if (S.answering.has(item.item_id)) return;
    // Focus in this card moves on to the next open card once this one has turned into its receipt.
    const hadFocus = card.contains(document.activeElement);
    // The cards of this list only: the session's copy of a card is hidden while the Inbox shows it, and the other way round.
    const scope = card.closest("#inbox-list, #mission-overview, #blocks") || document;
    const next = C.nextCardId([...new Set([...scope.querySelectorAll("[data-answer-item]")].filter((c) => !c.querySelector(".given")).map((c) => c.dataset.answerItem))], item.item_id);
    S.answering.add(item.item_id);
    syncAnswerState(item.item_id);
    err.hidden = true;
    try {
      await api("POST", "/api/inbox/" + encodeURIComponent(item.item_id), { answer });
      const receipt = approved ? { answer, approved } : { answer };
      S.answered.set(item.item_id, receipt);
      S.inbox.items.delete(item.item_id);
      if (C.clearDraftIfUnchanged(S.drafts, key, answer)) setDraft(key, "");
      updateInboxBadge();
      await loadInbox();
      let shown = card;
      if (document.contains(card)) { shown = inboxCard(entry, receipt, context); card.replaceWith(shown); }
      if (hadFocus) focusCard(next, shown, scope);
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    } finally {
      S.answering.delete(item.item_id);
      syncAnswerState(item.item_id);
    }
  };
  const scopeHosts = C.scopeRequestHosts(item);
  const park = C.parkChoices(item);
  const foot = el("div", "answer-foot");
  const words = el("div", "answer-words");
  if (result) {
    add(words, el("span", "dim", "Dismissing removes it from the inbox; the result stays in the record."));
    add(foot, words, btn("Dismiss result", "answer-submit", () => send("")));
  } else if (scopeHosts) {
    // The operator grants; the agent only asked. Approving grants the hosts, then dismisses the item.
    add(form, el("div", "hosts", "Hosts: " + scopeHosts.join(", ")));
    add(words, el("span", "dim", "Approving grants these hosts to the mission and dismisses the request."));
    const approve = btn("Approve hosts", "primary", async () => {
      if (S.answering.has(item.item_id)) return;
      const req = C.scopeRequest(entry.session, scopeHosts, "approved from the inbox");
      if (req.error) return fail(err, req.error);
      S.answering.add(item.item_id);
      syncAnswerState(item.item_id);
      err.hidden = true;
      try {
        await api("POST", req.path, req.body);
      } catch (e) {
        S.answering.delete(item.item_id);
        syncAnswerState(item.item_id);
        return fail(err, e.message);
      }
      S.answering.delete(item.item_id);
      await send("", scopeHosts);
    });
    const refusal = ruleInput("Why it is refused (the agent reads it)");
    refusal.setAttribute("aria-label", "Reason for refusing");
    const refuseRow = el("div", "rule-row refuse-row");
    refuseRow.hidden = true;
    const refuse = btn("Refuse…", "", () => {
      refuseRow.hidden = !refuseRow.hidden;
      refuse.setAttribute("aria-expanded", String(!refuseRow.hidden));
      if (!refuseRow.hidden) refusal.focus();
    });
    refuse.setAttribute("aria-expanded", "false");
    refuse.dataset.focusKey = "refuse:" + item.item_id;
    const sendRefusal = btn("Send refusal", "small", () => {
      const r = C.refusalAnswer(refusal.value);
      if (r.error) return fail(err, r.error);
      send(r.answer);
    });
    refusal.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); sendRefusal.click(); }
      else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); refuseRow.hidden = true; refuse.setAttribute("aria-expanded", "false"); refuse.focus(); }
    });
    add(refuseRow, refusal, sendRefusal, btn("Cancel", "small", () => { refuseRow.hidden = true; refuse.setAttribute("aria-expanded", "false"); refuse.focus(); }));
    add(form, refuseRow);
    add(words, el("span", "dim", "Refusing sends your reason to the agent and grants nothing."));
    add(foot, words, approve, btn("Dismiss", "", () => send("")), refuse);
  } else {
    const options = park ? [] : item.options || [];
    const ta = el("textarea");
    ta.rows = 2;
    ta.dataset.draftKey = key;
    ta.value = C.getDraft(S.drafts, key);
    ta.placeholder = options.length ? "Write your own answer…" : "Write your answer…";
    ta.setAttribute("aria-label", "Answer for " + (entry.title || entry.session));
    const sync = () => {
      setDraft(key, ta.value, ta);
      syncAnswerState(item.item_id);
    };
    ta.addEventListener("input", sync);
    // Ctrl/Cmd+Enter sends, the same as the button; an empty draft sends nothing (Enter alone still adds a line).
    ta.addEventListener("keydown", (e) => {
      if (!C.answerSendKey(e)) return;
      e.preventDefault();
      if (ta.value.trim() && !ta.disabled) send(ta.value);
    });
    const own = add(el("div", "answer-own"), ta);
    if (options.length) {
      // Suggested answers are toggles over the one draft: the pressed one is the draft as it stands.
      const opts = el("div", "opts");
      opts.setAttribute("role", "group");
      opts.setAttribute("aria-label", "Suggested answers");
      options.forEach((option, i) => {
        const b = btn("", "option", () => { ta.value = ta.value === option ? "" : option; sync(); });
        add(b, icon("check"), document.createTextNode(option));
        b.dataset.option = option;
        b.dataset.focusKey = `option:${item.item_id}:${i}`;
        opts.append(b);
      });
      const write = btn("Write your own…", "option write-own", () => {
        own.hidden = !own.hidden;
        syncAnswerState(item.item_id);
        if (!own.hidden) ta.focus();
      });
      write.dataset.focusKey = "write-own:" + item.item_id;
      form.append(add(opts, write));
      own.hidden = true;
    }
    if (park) add(form, parkControls(entry, park, ta, sync, send, err));
    form.append(own);
    if (park) add(form, el("p", "dim", C.PARK_HELP));
    if (park) add(form, waysOut(entry, context));
    add(words, el("span", "answer-hint"), el("span", "dim answer-recipient", "Reply to: " + (entry.title || entry.session)));
    const submit = btn("", "primary answer-submit", () => send(ta.value));
    submit.setAttribute("aria-keyshortcuts", "Control+Enter Meta+Enter");
    add(submit, el("span", "submit-label"), keycaps(MAC ? ["⌘", "Enter"] : ["Ctrl", "Enter"]));
    add(foot, words, submit);
  }
  add(card, add(form, foot), err);
  syncAnswerCard(card, S.answering.has(item.item_id));
  return card;
}

function fail(err, text) {
  err.textContent = text;
  err.hidden = false;
}

/**
 * The choices of a blocked or parked session. "Accept as blocked and close" takes two steps: it opens a
 * row asking for the reason, and only the row's own button records the release.
 */
function parkControls(entry, choices, ta, sync, send, err) {
  const box = el("div", "park");
  const opts = el("div", "opts");
  const reason = ruleInput("Why it is closed without the goal established (required)");
  const confirm = el("div", "rule-row");
  confirm.hidden = true;
  let acceptBtn = null;
  let pendingChoice = null;
  const draftConfirm = el("div", "model-confirm");
  draftConfirm.setAttribute("role", "group");
  draftConfirm.hidden = true;
  const draftText = el("p", "model-confirm-text");
  const draftYes = btn("Replace and send", "small primary", () => {
    const choice = pendingChoice;
    pendingChoice = null;
    draftConfirm.hidden = true;
    if (!choice) return;
    ta.value = choice.answer;
    sync();
    send(ta.value, []);
  });
  noRepeat(draftYes);
  const draftNo = btn("Keep draft", "small", () => {
    pendingChoice = null;
    draftConfirm.hidden = true;
    ta.focus();
  });
  draftConfirm.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); draftNo.click(); }
  });
  add(draftConfirm, draftText, add(el("span", "model-confirm-actions"), draftYes, draftNo));

  const close = btn("Close as blocked", "small", async () => {
    const req = C.releaseRequest(entry.session, reason.value);
    if (req.error) return fail(err, req.error);
    close.disabled = true;
    err.hidden = true;
    try {
      await api("POST", req.path, req.body);
      // The release closes the mission and its open items; the lists are read again to show it.
      toast(C.RELEASED_WORDS + ".");
      loadInbox();
      loadLedger();
      loadSessions();
    } catch (e) {
      close.disabled = false;
      fail(err, e.message);
    }
  });
  reason.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); close.click(); }
    else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); confirm.hidden = true; acceptBtn?.focus(); }
  });
  add(confirm, reason, close, btn("Keep it open", "small", () => {
    confirm.hidden = true;
    acceptBtn?.focus();
  }));
  for (const c of choices) {
    const b = btn(c.label, "", () => {
      err.hidden = true;
      if (c.action === "answer") {
        if (ta.value.trim() && ta.value.trim() !== c.answer.trim()) {
          pendingChoice = c;
          draftText.textContent = `Replace your typed draft with "${c.answer}" and send?`;
          draftConfirm.hidden = false;
          draftNo.focus();
          return;
        }
        pendingChoice = null;
        draftConfirm.hidden = true;
        ta.value = c.answer;
        sync();
        send(ta.value, []);
      } else if (c.action === "provide") {
        ta.focus();
      } else {
        confirm.hidden = false;
        reason.focus();
      }
    });
    if (c.action === "release") acceptBtn = b;
    add(opts, b);
  }
  add(box, opts, draftConfirm, confirm);
  return box;
}

/** Bring one card in line with its draft: pressed suggestion, what will be sent, what Send does. */
function syncAnswerCard(card, busy) {
  const ta = card.querySelector("textarea");
  const blocking = card.querySelector(".answer")?.dataset.blocking === "true";
  const draft = ta ? ta.value : "";
  const options = [...card.querySelectorAll("button[data-option]")];
  if (ta) ta.disabled = busy;
  for (const option of options) option.setAttribute("aria-pressed", String(option.dataset.option === draft));
  const own = card.querySelector(".answer-own");
  const write = card.querySelector(".write-own");
  if (own && write) {
    // A draft that is not one of the suggestions is the operator's own text: keep it in view.
    if (draft && !options.some(option => option.dataset.option === draft)) own.hidden = false;
    write.setAttribute("aria-expanded", String(!own.hidden));
  }
  for (const button of card.querySelectorAll("button")) {
    const submit = button.classList.contains("answer-submit");
    button.disabled = busy || (submit && blocking && !!ta && !draft.trim());
    if (submit) {
      const text = busy ? "Sending…" : !ta ? "Dismiss result" : !blocking && !draft.trim() ? "Dismiss" : "Send answer";
      const label = button.querySelector(".submit-label");
      if (label) label.textContent = text; else button.textContent = text;
      // The keys send a non-empty draft only, so the caps show only then.
      const caps = button.querySelector(".keycaps");
      if (caps) caps.hidden = busy || !draft.trim();
    }
  }
  const hint = card.querySelector(".answer-hint");
  if (hint) {
    hint.classList.toggle("has-answer", !!draft.trim());
    hint.textContent = draft.trim() ? "Your answer: " + C.oneLine(draft, 120)
      : options.length ? "Pick an option or write your own. Nothing is sent until you press Send answer."
        : blocking ? "Nothing is sent until you press Send answer." : "Answer it, or dismiss it without an answer.";
  }
}

function syncAnswerState(id) {
  const busy = S.answering.has(id);
  for (const card of document.querySelectorAll("[data-answer-item]")) {
    if (card.dataset.answerItem === id) syncAnswerCard(card, busy);
  }
}

function reconcileInbox(box, entries, context, groups = null) {
  if (!box.cardNodes) box.cardNodes = new Map();
  const cards = box.cardNodes;
  const keep = new Set(entries.map(e => e.item.item_id));
  for (const key of [...cards.keys()]) if (!key.startsWith("group:") && !keep.has(key)) cards.delete(key);
  const cardNode = (entry) => {
    const id = entry.item.item_id;
    // The open session's last error and seat are part of what the card shows, so a change in them redraws it.
    const rawErr = entry.session === S.openId && S.rec && C.parkChoices(entry.item) ? C.lastRecordedError(S.rec.blocks) : null;
    const known = C.dedupeParkedError(entry.item.text, rawErr);
    const signature = JSON.stringify([entry.session, entry.title, entry.item, S.answered.get(id), known, S.sessions.byId.get(entry.session)?.title]);
    let saved = cards.get(id);
    if (!saved || saved.signature !== signature) {
      const wrap = el("div", "block inbox" + (entry.item.blocking ? " decision-card" : " informational"));
      wrap.append(inboxCard(entry, S.answered.get(id), context));
      saved = { signature, node: wrap };
      cards.set(id, saved);
    }
    return saved.node;
  };
  const nodes = [];
  if (groups) {
    // One heading per mission, missions that block work first; the heading says how many items block.
    const seenGroups = new Set();
    for (const g of groups) {
      const key = "group:" + g.key;
      seenGroups.add(key);
      const text = `${g.open} open${g.blocking ? `, ${g.blocking} ${g.blocking === 1 ? "needs" : "need"} you` : ""}`;
      const signature = JSON.stringify([g.title, text, g.mission, g.root || g.entries[0].session]);
      let saved = cards.get(key);
      if (!saved || saved.signature !== signature) {
        const h = el("h2", "inbox-group" + (g.blocking ? " blocking" : ""));
        add(h, link(g.title, C.sessionHash(g.root || g.entries[0].session)), el("span", "dim inbox-group-count", " · " + text));
        saved = { signature, node: h };
        cards.set(key, saved);
      }
      nodes.push(saved.node);
      for (const entry of g.entries) nodes.push(cardNode(entry));
    }
    for (const key of [...cards.keys()]) if (key.startsWith("group:") && !seenGroups.has(key)) cards.delete(key);
  } else {
    for (const entry of entries) nodes.push(cardNode(entry));
  }
  if (!nodes.length && context === "inbox") nodes.push(emptyInbox);
  preserveFocus(box, () => {
    nodes.forEach((node, i) => { if (box.children[i] !== node) box.insertBefore(node, box.children[i] || null); });
    while (box.children.length > nodes.length) box.lastElementChild.remove();
  });
  for (const entry of entries) syncAnswerState(entry.item.item_id);
}

// One node, so the focus placed on it survives the redraws.
const emptyInbox = el("p", "dim inbox-empty", "Nothing is waiting for you.");
emptyInbox.tabIndex = -1;

function showInbox() {
  closeNotes({ inbox: true });
  setView("inbox");
  renderInbox();
}

function renderInbox() {
  const rootOf = (mission) => {
    if (!mission) return null;
    for (const i of S.sessions.byId.values()) if (i.mission === mission && !i.parent) return i;
    return null;
  };
  const rootTitle = (mission) => { const r = rootOf(mission); return r ? r.title || r.id : null; };
  const rootId = (mission) => { const r = rootOf(mission); return r ? r.id : null; };
  const groups = C.inboxGroups(S.inbox, rootTitle);
  for (const g of groups) g.root = rootId(g.mission);
  reconcileInbox($("inbox-list"), groups.flatMap(g => g.entries), "inbox", groups);
  const granted = notificationsAvailable() && Notification.permission === "granted";
  // When they are off, say why: a phone browser often offers none, and a refusal is changed in the browser's site settings.
  const why = !notificationsAvailable() ? "this browser does not offer page notifications here" : Notification.permission === "denied" ? "blocked in this browser's site settings" : "";
  $("notif-state").textContent = "Notifications: " + (granted ? "on" : why ? "off, " + why : "off");
  $("notif-btn").hidden = !notificationsAvailable() || Notification.permission !== "default";
}

// ---------------------------------------------------------------------------------------------
// New session form

function showNew() {
  setView("new");
  const role = $("f-role");
  if (role.options.length === 0) {
    for (const r of C.ROLES) role.append(new Option(r, r));
    // Only a lead starts agents: a chat has no agents' model to choose.
    role.addEventListener("change", () => { $("f-agent-model").disabled = role.value !== "lead"; });
  }
  const model = $("f-model");
  const prevModel = model.options.length ? model.value : S.newForm.model;
  model.replaceChildren();
  const models = (S.status && S.status.models) || [];
  for (const m of models) model.append(new Option(m.profile + (m.reachable ? "" : " (not reachable)"), m.profile));
  if (models.length === 0) model.append(new Option("default", ""));
  if (prevModel !== null && prevModel !== undefined && [...model.options].some(o => o.value === prevModel)) model.value = prevModel;
  S.newForm.model = model.value;
  // The model the mission's agents start on, before the lead's first one; empty: as the pack says.
  const agents = $("f-agent-model");
  const prevAgentModel = agents.options.length ? agents.value : S.newForm.agentModel;
  agents.replaceChildren(new Option("As the pack says", ""));
  for (const m of models) agents.append(new Option(m.profile, m.profile));
  if (prevAgentModel !== null && prevAgentModel !== undefined && [...agents.options].some(o => o.value === prevAgentModel)) agents.value = prevAgentModel;
  S.newForm.agentModel = agents.value;
  agents.disabled = role.value !== "lead";
  $("f-error").hidden = true;
  hideCreateAsk();
  $("f-receipt").hidden = true;
  workspaceNote();
}

async function submitNew(ev, create = false) {
  if (ev) ev.preventDefault();
  const workspace = $("f-workspace").value.trim();
  const r = C.buildNewSession({
    workspace: $("f-workspace").value,
    message: $("f-message").value,
    role: $("f-role").value,
    model: $("f-model").value,
    agentModel: $("f-agent-model").value,
    title: $("f-title").value,
    prior: $("f-prior").value,
    unattended: $("f-unattended").checked,
    // Only for a folder the operator chose to make: the picker's New folder, or the answer to the question below.
    createWorkspace: create || (pickerCreate !== null && workspace === pickerCreate),
  });
  const err = $("f-error");
  hideCreateAsk();
  if (r.error) {
    err.textContent = r.error;
    err.hidden = false;
    return;
  }
  const att = attachState("new");
  if (att.busy || att.failed) {
    err.textContent = att.busy ? "Wait for the attached files to finish uploading." : "Remove the attached file that failed to upload, then start the mission.";
    err.hidden = false;
    return;
  }
  if (att.paths.length) r.body.attachments = att.paths;
  err.hidden = true;
  $("f-submit").disabled = true;
  $("f-create-yes").disabled = true;
  try {
    const answer = await api("POST", "/api/sessions", r.body);
    // `created` is the receipt of a folder the daemon made; the rest is the session as ever.
    const { created, ...info } = answer;
    C.applySessionEvent(S.sessions, info);
    $("f-message").value = "";
    attachments.delete("new");
    renderChips(attachCtx.start);
    $("f-title").value = "";
    $("f-prior").value = "";
    pickerCreate = null;
    workspaceNote();
    location.hash = "#/s/" + encodeURIComponent(info.id);
    if (created === true) toast(`Created ${info.workspace || workspace} and started the mission.`, { keep: true });
  } catch (e) {
    // The daemon is the authority on whether the folder exists; when it says not, ask before making it.
    if (!r.body.create_workspace && C.missingWorkspaceError(e.message)) askCreate(workspace);
    else { err.textContent = e.message; err.hidden = false; }
  } finally {
    $("f-submit").disabled = false;
    $("f-create-yes").disabled = false;
  }
}

// ---------------------------------------------------------------------------------------------
// Right column

function setTab(t) {
  S.tab = t;
  S.ask = null;
  for (const b of document.querySelectorAll("#tabs .tab")) {
    const selected = b.dataset.tab === t;
    b.classList.toggle("sel", selected);
    b.setAttribute("aria-selected", String(selected));
    b.tabIndex = selected ? 0 : -1;
  }
  $("panel").setAttribute("aria-labelledby", "tab-" + t);
  loadTab();
  want("right");
}

function loadTab() {
  if (S.tab === "ledger") loadLedger();
  else if (S.tab === "models") loadModels();
  else if (S.tab === "context") loadWindow();
  else if (S.tab === "network") {
    if (S.net.length === 0) loadNet();
    if (S.ledger.stale || !S.ledger.model) loadLedger();
  }
}

async function loadLedger() {
  const info = S.sessions.byId.get(S.openId);
  if (!info) return;
  S.ledger.mission = info.mission;
  S.ledger.pending = true;
  const mission = info.mission;
  const request = ++S.requests.ledger;
  try {
    const v = await api("GET", "/api/missions/" + encodeURIComponent(mission) + "/ledger");
    if (request !== S.requests.ledger || S.ledger.mission !== mission) return;
    S.ledger = { mission, model: C.ledgerModel(v), state: v.state, error: null, stale: false, pending: false };
  } catch (e) {
    if (request !== S.requests.ledger || S.ledger.mission !== mission) return;
    S.ledger = { ...S.ledger, error: e.message, stale: false, pending: false };
  }
  if (S.tab === "ledger" || S.tab === "network") want("right");
  want("header", "overview");
}

async function loadWindow() {
  const id = S.openId;
  if (!id) return;
  const request = ++S.requests.window;
  try {
    const w = await api("GET", "/api/sessions/" + encodeURIComponent(id) + "/window");
    if (S.openId !== id || request !== S.requests.window) return;
    S.win.data = w;
    S.win.error = null;
    S.win.stale = false;
  } catch (e) {
    if (S.openId !== id || request !== S.requests.window) return;
    S.win.error = e.message;
  }
  if (S.tab === "context") want("right");
  if (S.sheet.open) want("sheet");
}

async function loadNet() {
  const id = S.openId;
  if (!id) return;
  const request = ++S.requests.net;
  try {
    const list = await api("GET", "/api/sessions/" + encodeURIComponent(id) + "/net?limit=500");
    if (S.openId !== id || request !== S.requests.net) return;
    const live = S.net;
    S.net = [];
    for (const e of list) C.applyNet(S.net, e);
    for (const e of live) C.applyNet(S.net, e);
    S.netError = null;
  } catch (e) {
    if (S.openId !== id || request !== S.requests.net) return;
    S.netError = e.message;
  }
  if (S.tab === "network") want("right");
}

function h2(text) {
  return el("h2", "", text);
}
function ul(...items) {
  const u = el("ul");
  for (const i of items) add(u, i);
  return u;
}
function li(...kids) {
  return add(el("li"), ...kids);
}

function renderRight() {
  renderRightBody();
  // A question that has just been raised takes the focus once, so the keyboard lands on its answer.
  if (S.ask && S.ask.focus) {
    S.ask.focus = false;
    // The safe answer takes the focus, so a held or doubled Enter cannot confirm what the operator has not yet read.
    const safe = document.querySelector('#panel [data-focus-key="ask:no"]');
    if (safe) safe.focus({ preventScroll: true });
  }
}

function renderRightBody() {
  const p = $("panel");
  for (const b of document.querySelectorAll("#tabs .tab")) b.classList.toggle("sel", b.dataset.tab === S.tab);
  const info = S.sessions.byId.get(S.openId);
  if (!info || S.view !== "session") {
    p.replaceChildren(el("p", "dim", "Open a session to see its state."));
    return;
  }
  if (S.tab === "ledger") return renderLedger(p);
  if (S.tab === "context") return renderContext(p);
  if (S.tab === "network") return renderNetwork(p);
  if (S.tab === "models") return renderModels(p, info);
  if (S.tab === "files") return renderFiles(p, info);
  return renderSessionTab(p, info);
}

// ---------------------------------------------------------------------------------------------
// Models tab: the mission's lead model, and the model its agents of each role start on

async function loadModels() {
  const id = S.openId;
  if (!id) return;
  const request = ++S.requests.models;
  S.models.loading = true;
  try {
    const view = await api("GET", "/api/sessions/" + encodeURIComponent(id) + "/models");
    if (request !== S.requests.models || id !== S.openId) return;
    S.models.view = view;
    S.models.error = "";
  } catch (e) {
    if (request !== S.requests.models) return;
    S.models.error = e.message;
  } finally {
    if (request === S.requests.models) S.models.loading = false;
  }
  if (S.tab === "models") want("right");
}

/** A select of the live profiles; `first` labels an empty first option (no choice), or null for none. */
function modelSelect(label, profiles, value, first, choose, focusKey = "") {
  const s = el("select");
  s.setAttribute("aria-label", label);
  if (focusKey) s.dataset.focusKey = focusKey;
  if (first !== null) s.append(new Option(first, ""));
  for (const p of profiles) s.append(new Option(p, p));
  s.value = value || "";
  s.disabled = S.models.busy;
  s.addEventListener("change", () => choose(s.value));
  return s;
}

/** Run one model change, one at a time, then read the mission's models again. */
async function changeModels(work) {
  if (S.models.busy) return;
  S.models.busy = true;
  want("right");
  try {
    await work();
  } catch (e) {
    notice(e.message);
  } finally {
    S.models.busy = false;
    await loadModels();
  }
}

/** The inline question before a Models-tab change; the same words as the model seat, and nothing is sent until the operator answers. */
function modelAsk(ask) {
  if (ask.kind === "compact") {
    const open = S.sessions.byId.get(S.openId);
    return C.compactConfirm(open && open.title);
  }
  const models = seatModels();
  if (ask.kind === "lead") {
    const q = C.seatConfirm(models, S.models.view && S.models.view.lead_model, ask.value);
    if (!q) return null;
    return { ...q, text: q.text.replace("Switch this session to", "Switch the lead to") };
  }
  const who = ask.role === "*" ? "every role" : ask.role;
  if (!ask.value) return { text: `Clear the choice for ${who}? New agents of it use the pack's setting again.`, yes: "Clear the choice", no: "Keep it" };
  const entry = models.find((m) => m && m.profile === ask.value);
  const down = entry && entry.reachable === false ? ` ${ask.value} is not reachable now; the next step fails until it answers.` : "";
  const moved = ask.now
    ? " The running agents of it move too; each one's next request re-reads its whole prompt once."
    : " Agents already running keep their model.";
  return { text: `New agents of ${who} start on ${ask.value}.${moved}${down}`, yes: "Use it", no: "Keep it" };
}

/** A held key must not confirm: an auto-repeated Enter on the affirmative button is ignored. */
function noRepeat(button) {
  button.addEventListener("keydown", (e) => { if (e.repeat) e.preventDefault(); });
}

/** A question with two buttons, placed where the operator is looking. Focus lands on the question, and returns to `opener` when it closes. */
function confirmRow(q, onYes, onNo, prefix = "") {
  const box = el("div", "model-confirm");
  box.setAttribute("role", "group");
  const text = el("p", "model-confirm-text", q.text);
  text.id = prefix.replace(/\W/g, "") + "ask-text";
  box.setAttribute("aria-labelledby", text.id);
  const yes = btn(q.yes, "small primary", onYes);
  yes.dataset.focusKey = prefix + "ask:yes";
  noRepeat(yes);
  const no = btn(q.no, "small", onNo);
  no.dataset.focusKey = prefix + "ask:no";
  add(box, text, add(el("span", "model-confirm-actions"), yes, no));
  return box;
}

function askClose(opener) {
  S.ask = null;
  want("right");
  if (opener) requestAnimationFrame(() => { const t = document.querySelector(`[data-focus-key="${opener}"]`); if (t) t.focus({ preventScroll: true }); });
}

function setLeadModel(lead, profile) {
  return changeModels(async () => {
    const r = await api("POST", "/api/sessions/" + encodeURIComponent(lead) + "/model", { profile });
    toast(`The lead now uses ${r.model.profile}, ${r.live ? "from its next step" : "when it next runs"}.`);
  });
}

function setRoleModel(lead, role, value, now) {
  return changeModels(async () => {
    const body = C.roleModelBody(role, value, now);
    const r = await api("POST", "/api/sessions/" + encodeURIComponent(lead) + "/role-model", body);
    S.models.view = r.models;
    const who = role === "*" ? "every role" : role;
    const moved = r.switched.length ? ` Moved now: ${r.switched.join(", ")}.` : "";
    toast(body.profile ? `New agents of ${who} start on ${body.profile}.${moved}` : `The choice for ${who} is cleared: the pack chooses again.`);
  });
}

let askSaid = null;
function renderModels(p, info) {
  const m = S.models.view;
  if (S.models.error) {
    p.replaceChildren(el("p", "error", S.models.error), btn("Try again", "", () => loadModels()));
    return;
  }
  // Nothing yet, or the view of another mission than the open session's.
  if (!m || m.mission !== info.mission) {
    p.replaceChildren(el("p", "dim", "Loading the mission's models…"));
    if (!S.models.loading) loadModels();
    return;
  }
  // Stacked rows (name, a full-width select, a note): the inspector is narrow, and a two-column grid
  // squeezed the selects until their labels were cut.
  const kv = el("div", "model-rows");
  // The question of a change sits right after the row that raised it, so Tab from the select reaches its buttons.
  const row = (k, kind, role, ...v) => {
    kv.append(add(el("div", "models-row"), el("div", "model-name", k), ...v));
    if (q && ask.kind === kind && ask.role === role) {
      const done = ask.kind === "lead" ? () => setLeadModel(ask.lead, ask.value) : () => setRoleModel(ask.lead, ask.role, ask.value, ask.now);
      const opener = ask.kind === "lead" ? "ask:lead" : "ask:role:" + ask.role;
      kv.append(confirmRow(q, () => { askClose(opener); done(); }, () => askClose(opener)));
    }
  };
  const lead = m.lead_model;
  const ask = S.ask && S.ask.kind !== "compact" && S.ask.lead === m.lead ? S.ask : null;
  const q = ask ? modelAsk(ask) : null;
  if (ask && !q) S.ask = null;
  const pending = (kind, role) => q && ask.kind === kind && ask.role === role ? ask.value : null;
  row(
    "lead", "lead", undefined,
    modelSelect("Model of the lead", m.profiles, pending("lead") ?? lead.profile, null, (v) => {
      S.ask = v === lead.profile ? null : { kind: "lead", lead: m.lead, value: v };
      want("right");
    }, "ask:lead"),
    el("div", "dim", `${lead.model} · context ${lead.context_window ? C.tokens(lead.context_window) : "unknown"}`),
  );
  if (m.roles.length) {
    row(
      "every role", "role", "*",
      modelSelect("Model for agents of every role", m.profiles, pending("role", "*") ?? m.any_role, "As each role's pack setting says", (v) => {
        S.ask = v === (m.any_role || "") ? null : { kind: "role", lead: m.lead, role: "*", value: v, now: S.models.now };
        want("right");
      }, "ask:role:*"),
    );
    for (const r of m.roles) {
      row(
        r.verifier ? `${r.role} (finish gate)` : r.role, "role", r.role,
        modelSelect(`Model for ${r.role} agents`, m.profiles, pending("role", r.role) ?? r.chosen, C.roleDefaultLabel(r, m.any_role), (v) => {
          S.ask = v === (r.chosen || "") ? null : { kind: "role", lead: m.lead, role: r.role, value: v, now: S.models.now };
          want("right");
        }, "ask:role:" + r.role),
        el("div", "dim", C.runningAgentsWords(r.agents)),
      );
    }
  }
  const parts = [];
  parts.push(kv);
  if (m.roles.length) {
    const now = el("input");
    now.type = "checkbox";
    now.checked = S.models.now;
    now.disabled = S.models.busy;
    now.dataset.focusKey = "models:now";
    now.addEventListener("change", () => { S.models.now = now.checked; });
    parts.push(add(el("label", "check"), now, document.createTextNode(" Also move the running agents of a role when choosing for it (read when a choice is made)")));
  }
  const refresh = btn("Refresh", "", () => loadModels());
  refresh.dataset.focusKey = "models:refresh";
  parts.push(
    el("p", "dim", m.roles.length
      ? "A choice is used for agents started from then on; a forked agent shares the lead's model. Profiles are the config's [models] (loom models reload)."
      : "This lead starts no agents."),
    refresh,
  );
  // The question is read out once when it opens; focus stays on the select.
  if (q && askSaid !== q.text) toast(q.text);
  askSaid = q ? q.text : null;
  preserveFocus(p, () => p.replaceChildren(...parts));
}

function ruleInput(placeholder) {
  const i = el("input", "rule-in");
  i.type = "text";
  i.placeholder = placeholder;
  return i;
}

/**
 * Send an operator rule request of `form`. `b`, the button pressed, is disabled until the daemon has
 * answered, so a double click sends once. When the daemon accepted the request, `inputs` are emptied
 * and the form's note says what its receipt means: a lead in a turn has only queued it, a mission
 * without a ledger never lists it. True when it was accepted.
 */
async function sendRule(form, b, req, inputs = []) {
  if (req.error) {
    form.note.className = "rule-note error";
    form.note.setAttribute("role", "alert");
    form.note.textContent = req.error;
    return false;
  }
  b.disabled = true;
  form.note.className = "rule-note warn";
  form.note.setAttribute("role", "status");
  form.note.textContent = "";
  let receipt;
  try {
    receipt = await api("POST", req.path, req.body);
  } catch (e) {
    b.disabled = false;
    form.note.className = "rule-note error";
    form.note.setAttribute("role", "alert");
    form.note.textContent = e.message;
    return false;
  }
  b.disabled = false;
  if (!receipt) return false;
  for (const i of inputs) i.value = "";
  form.note.textContent = C.ruleNotice(receipt);
  loadLedger();
  return true;
}

/**
 * The operator's controls for the mission of the open session: set a rule, record an approval and,
 * in `lists`, withdraw a rule in force. Built once per open session and kept: the ledger is redrawn
 * on every entry a running mission writes, and nodes that stay in the page keep the focus, the caret
 * and the text being typed. Opening another session starts an empty form.
 */
function rulesForm() {
  const id = S.openId;
  if (S.rules && S.rules.session === id) return S.rules;
  const form = { session: id, box: el("div", "rules"), note: el("div", "rule-note warn"), hint: el("div", "rule-note dim"), lists: el("div"), reason: ruleInput("Why it is withdrawn (optional)"), asking: null, shown: "" };
  form.note.setAttribute("role", "status");
  const rule = ruleInput("Standing rule for this mission");
  const addRule = btn("Add rule", "small", () => sendRule(form, addRule, C.ruleRequest(id, rule.value), [rule]));
  rule.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); addRule.click(); } });
  const appr = ruleInput("Approve something");
  const scope = ruleInput("What it covers (optional)");
  const addAppr = btn("Approve", "small", () => sendRule(form, addAppr, C.approvalRequest(id, appr.value, scope.value), [appr, scope]));
  for (const input of [appr, scope]) {
    input.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); addAppr.click(); } });
  }
  form.reason.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); form.lists.querySelector(".withdraw-go")?.click(); }
    else if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      const target = form.asking;
      form.asking = null;
      form.reason.value = "";
      renderRuleLists(form, S.ledger.model);
      if (target) form.lists.querySelector(`[data-focus-key="withdraw:${CSS.escape(target)}"]`)?.focus({ preventScroll: true });
    }
  });
  add(form.box, h2("Rules and approvals"), add(el("div", "rule-row rule-add"), rule, addRule), add(el("div", "rule-row approval-add"), appr, scope, addAppr), form.note, form.hint, form.lists);
  S.rules = form;
  return form;
}

/**
 * Under the form: the rules in force and the approvals. Withdrawing a rule takes two steps, so that
 * a stray click lifts nothing: `Withdraw` opens a row asking for the reason (`form.asking` is that
 * rule), and only the row's `Withdraw k<n>` sends; `Keep` closes the row.
 */
function renderRuleLists(form, model) {
  const lists = C.ruleLists(model, form.asking);
  form.asking = lists.asking;
  const shown = JSON.stringify(lists);
  if (form.shown === shown) return;
  form.shown = shown;
  const ask = (ruleId, restoreKey = null) => {
    form.asking = ruleId;
    form.reason.value = "";
    renderRuleLists(form, S.ledger.model);
    if (ruleId) form.reason.focus();
    else if (restoreKey) form.lists.querySelector(`[data-focus-key="${CSS.escape(restoreKey)}"]`)?.focus({ preventScroll: true });
  };
  // The reason field is one node that outlives the redraws, so the text typed in it is kept.
  const typing = document.activeElement === form.reason;
  const nodes = [];
  if (lists.rules.length) {
    nodes.push(ul(...lists.rules.map((r) => {
      const item = li(el("span", "k", r.id), document.createTextNode(r.text + " "));
      if (r.id !== lists.asking) {
        const w = btn("Withdraw", "small", () => ask(r.id));
        w.dataset.focusKey = "withdraw:" + r.id;
        return add(item, w);
      }
      const go = btn("Withdraw " + r.id, "small withdraw-go", async () => {
        if (await sendRule(form, go, C.withdrawRequest(form.session, r.id, form.reason.value))) ask(null);
      });
      return add(item, add(el("div", "rule-row"), form.reason, go, btn("Keep", "small", () => ask(null, "withdraw:" + r.id))));
    })));
  }
  if (lists.approvals.length) {
    nodes.push(ul(...lists.approvals.map((a) => li(el("span", "k", a.id), el("span", a.used ? "retired" : "", a.text), a.note ? el("span", "dim", ` (${a.note})`) : null))));
  }
  form.lists.replaceChildren(...nodes);
  if (typing && lists.asking) form.reason.focus();
}

/** Fill the ledger tab: the rules form, then `nodes`. A form already in place is not taken out. */
function showLedger(p, ...nodes) {
  const form = rulesForm();
  form.hint.textContent = C.rulesHint(S.ledger.error);
  renderRuleLists(form, S.ledger.model);
  if (p.firstChild !== form.box) p.replaceChildren(form.box);
  while (form.box.nextSibling) form.box.nextSibling.remove();
  p.append(...nodes);
}

function renderLedger(p) {
  const L = S.ledger;
  if (L.error) return showLedger(p, el("p", "dim", L.error));
  if (!L.model) return showLedger(p, el("p", "dim", "loading…"));
  const m = L.model;
  if (m.empty) {
    const empty = document.createDocumentFragment();
    for (const n of m.notices) empty.append(el("p", "warn", n));
    empty.append(el("p", "dim", "This mission has no ledger entries yet."));
    return showLedger(p, empty);
  }
  const frag = document.createDocumentFragment();
  for (const n of m.notices) frag.append(el("p", "warn", n));
  frag.append(h2("Goal"), el("div", "", m.goal || "(not set)"));
  if (m.outcome) frag.append(el("p", "warn", m.outcome.words + (m.outcome.detail ? ": " + m.outcome.detail : "")));
  frag.append(h2("Hosts granted"), el("div", m.scope.length ? "" : "dim", m.scope.length ? m.scope.join(", ") : "None. A tool that needs one asks you through the inbox."));
  if (m.constraints.length) {
    frag.append(h2("Constraints"), ul(...m.constraints.map((c) => li(el("span", "k", c.id), el("span", c.retired ? "retired" : "", c.text), c.retired ? el("span", "dim", ` (retired: ${c.retired})`) : null))));
  }
  if (m.plan.length) {
    frag.append(h2("Plan"), ul(...m.plan.map((s) => add(el("li", "ledger-step step-" + s.status),
      stepMarkEl(s.status), el("span", "k", s.id), add(el("div"), el("span", "", s.text), s.note ? el("div", "dim", s.note) : null)))));
  }
  if (m.claims.length) {
    frag.append(h2("Claims"));
    const u = el("ul");
    for (const c of m.claims) {
      const item = li(el("span", "k", c.id), el("strong", "", c.status + " "), document.createTextNode(c.text));
      if (c.note) add(item, el("div", "dim", c.note));
      for (const e of c.evidence) {
        add(item, evidenceCard(e));
      }
      add(u, item);
    }
    frag.append(u);
  }
  if (m.obligations.length) frag.append(h2("Open obligations"), ul(...m.obligations.map((o) => li(el("span", "k", o.id), el("span", "dim", o.kind + " "), document.createTextNode(o.text)))));
  if (m.decisions.length) frag.append(h2("Decisions"), ul(...m.decisions.map((d) => li(el("span", "k", d.id), document.createTextNode(d.text), el("div", "dim", d.reason)))));
  if (m.deadEnds.length) frag.append(h2("Dead ends"), ul(...m.deadEnds.map((d) => li(el("span", "k", d.id), document.createTextNode(d.what), el("div", "dim", d.why)))));
  if (m.questions.length) frag.append(h2("Questions"), ul(...m.questions.map((q) => li(el("span", "k", q.id), document.createTextNode(q.text + (q.blocking ? " (blocking)" : "")), q.answer !== null ? el("div", "okc", "answer: " + q.answer) : el("div", "warn", "unanswered")))));
  showLedger(p, frag);
}

/**
 * The context card (the inspector's Context tab, and the CONTEXT section of the phone's details sheet): the figure and the
 * share of the window, one bar whose segments are also the legend's swatches, the fold marks in words, the rows by group, how much
 * of the last request came from the cache, and what each part means. `where` is "panel" or "sheet" (it keeps ids and focus keys
 * apart); `ask` is the open question of that place, if any. Text nodes only; the fills are classes.
 */
function contextCard(w, where, ask) {
  const m = C.contextCardModel(w);
  const box = el("div", "ctx");
  const hero = el("div", "ctx-hero");
  const figure = el("span", "ctx-figure");
  if (m.hero.approx) add(figure, el("span", "sr-only", "about "), el("span", "", "~"));
  if (m.hero.approx) figure.lastChild.setAttribute("aria-hidden", "true");
  figure.append(document.createTextNode(m.hero.figure.replace(/^~/, "")));
  const denominator = el("span", "ctx-denominator", m.hero.denominator);
  if (m.hero.exact) denominator.title = m.hero.exact;
  add(hero, figure, denominator, m.hero.exact ? el("span", "sr-only", ` (${m.hero.exact})`) : null, m.hero.percent ? el("span", "ctx-percent", m.hero.percent) : null);
  box.append(hero, el("p", "ctx-sub", m.sub));
  if (!m.parts) {
    box.append(el("p", "ctx-legacy", "This daemon does not report what the request is made of."));
  } else {
    const wrap = el("div", "ctx-barwrap");
    const bar = el("div", "ctx-bar");
    bar.setAttribute("role", "img");
    bar.setAttribute("aria-label", m.bar.label);
    const labels = el("div", "ctx-labels");
    labels.setAttribute("aria-hidden", "true");
    let at = 0;
    for (const seg of m.bar.segments) {
      const node = el("div", `ctx-seg fam-${seg.family} pat-${seg.pattern}`);
      node.style.setProperty("width", seg.pct + "%");
      bar.append(node);
      if (seg.labelled) {
        const label = el("span", "", seg.label);
        label.style.setProperty("left", at + "%");
        label.style.setProperty("width", seg.pct + "%");
        labels.append(label);
      }
      at += seg.pct;
    }
    wrap.append(bar);
    if (m.fold) {
      for (const [cls, pct] of [["at", m.fold.atPct], ["to", m.fold.toPct]]) {
      if (pct == null) continue;
        const tick = el("span", "ctx-tick " + cls);
        tick.setAttribute("aria-hidden", "true");
        tick.style.setProperty("left", pct + "%");
        wrap.append(tick);
      }
    }
    box.append(wrap, labels);
    if (m.bar.scaleNote) box.append(el("p", "ctx-scale", m.bar.scaleNote));
    if (m.fold) box.append(el("p", "ctx-foldline", m.fold.text + (m.fold.past ? " · " + m.fold.past.text : "")));
    else if (m.parts && (w.compact_at || w.fold_at)) box.append(el("p", "ctx-foldline", w.compact_at ? `Compacts at ${C.tokens(w.compact_at)}, beyond this scale.` : `Folds at ${C.tokens(w.fold_at)}, beyond this scale.`));
    let group = "";
    let list = null;
    for (const r of m.rows) {
      if (r.group !== group) {
        group = r.group;
        box.append(el("p", "ctx-group", C.CTX_GROUPS[group]));
        list = el("ul", "ctx-rows");
        box.append(list);
      }
      const li = el("li", "ctx-row");
      const swatch = el("span", `ctx-swatch fam-${r.family} pat-${r.pattern}`);
      swatch.setAttribute("aria-hidden", "true");
      add(li, swatch, el("span", "ctx-name", r.label), add(el("span", "ctx-value"), el("span", "sr-only", "about "), add(el("span", "", "~"), null)));
      li.lastChild.lastChild.setAttribute("aria-hidden", "true");
      li.lastChild.append(document.createTextNode(r.value.slice(1)));
      list.append(li);
    }
    box.append(el("p", "ctx-basis", m.basis));
    if (m.cache) {
      const cache = el("div", "ctx-cache");
      const split = el("div", "ctx-cachebar");
      split.setAttribute("role", "img");
      split.setAttribute("aria-label", m.cache.text);
      const a = el("span", "from-cache");
      a.style.setProperty("width", (100 * m.cache.cached) / m.cache.of + "%");
      const b = el("span", "read-anew");
      b.style.setProperty("width", (100 * m.cache.fresh) / m.cache.of + "%");
      split.append(a, b);
      add(cache, el("p", "ctx-group", "Cache"), split, el("p", "ctx-cachetext", m.cache.text), el("p", "ctx-basis", "Harness state is always read anew."));
      box.append(cache);
    }
    if (m.notes.length) {
      const d = el("details", "ctx-notes");
      const dl = el("dl");
      for (const n of m.notes) add(dl, el("dt", "", n.label), el("dd", "", n.note));
      const sum = el("summary", "", "What these mean");
      const prefix = where === "sheet" ? "sheet:" : "panel:";
      sum.dataset.focusKey = prefix + "notes";
      if (where === "sheet") {
        d.open = !!S.sheet.notesOpen;
        d.addEventListener("toggle", () => { S.sheet.notesOpen = d.open; });
      } else {
        d.open = !!S.win.notesOpen;
        d.addEventListener("toggle", () => { S.win.notesOpen = d.open; });
      }
      add(d, sum, dl);
      box.append(d);
    }
  }
  const actions = el("div", "ctx-actions");
  const prefix = where === "sheet" ? "sheet:" : "";
  const fold = btn("Compact now…", "", () => {
    if (where === "sheet") { S.sheet.ask = { kind: "compact", focus: true }; want("sheet"); } else { S.ask = { kind: "compact", focus: true }; want("right"); }
  });
  fold.dataset.focusKey = prefix + "ask:fold";
  fold.setAttribute("aria-label", "Compact now");
  fold.title = "Compact the context now: the model writes a note and everything before the last few steps leaves its view. Asks first.";
  const refresh = btn("Refresh", "", loadWindow);
  refresh.dataset.focusKey = prefix + "ctx-refresh";
  add(actions, fold, refresh);
  if (ask && ask.kind === "compact") {
    // Compacting is silent until a later record lands, so say it was asked for and pull the view.
    actions.append(confirmRow(modelAsk(ask), async () => {
      if (where === "sheet") { S.sheet.ask = null; want("sheet"); requestAnimationFrame(() => focusKey("sheet:ask:fold")); } else askClose("ask:fold");
      if (await act(api("POST", "/api/sessions/" + encodeURIComponent(S.openId) + "/compact")) !== undefined) {
        toast(C.COMPACT_RECEIPT);
        loadWindow();
      }
    }, () => { if (where === "sheet") { S.sheet.ask = null; want("sheet"); requestAnimationFrame(() => focusKey("sheet:ask:fold")); } else askClose("ask:fold"); }, prefix));
  }
  box.append(actions);
  return box;
}

function focusKey(key) {
  const t = document.querySelector(`[data-focus-key="${key}"]`);
  if (t) t.focus({ preventScroll: true });
}

function renderContext(p) {
  const w = S.win.data;
  if (S.win.error && !w) { preserveFocus(p, () => p.replaceChildren(el("p", "dim", S.win.error))); return; }
  if (!w) { preserveFocus(p, () => p.replaceChildren(el("p", "dim", "loading…"))); return; }
  const frag = document.createDocumentFragment();
  const sum = C.windowSummary(w);
  frag.append(contextCard(w, "panel", S.ask));
  const bar = el("div", "nums");
  frag.append(el("div", "dim", `${sum.counts.live} live · ${sum.counts.stubbed} stubbed · ${sum.counts.reasoning_dropped} reasoning dropped · ${sum.counts.dropped} dropped · ${sum.pinned} pinned`));
  const hide = el("label", "dim");
  const cb = el("input");
  cb.type = "checkbox";
  cb.checked = S.win.hideFolded;
  cb.dataset.focusKey = "ctx:hide-folded";
  cb.addEventListener("change", () => {
    S.win.hideFolded = cb.checked;
    S.win.from = null;
    want("right");
  });
  add(hide, cb, document.createTextNode(" hide folded out"));
  bar.append(hide);
  frag.append(bar);
  frag.append(h2("In the model's window"));
  const rows = C.windowRows(w, { hideFolded: S.win.hideFolded });
  if (S.win.from === null) S.win.from = C.initialFrom(rows.length);
  if (S.win.from > 0) {
    const earlier = btn(`Show earlier (${C.num(S.win.from)} more)`, "", () => {
      S.win.from = C.earlierFrom(S.win.from);
      want("right");
    });
    earlier.dataset.focusKey = "ctx:earlier";
    frag.append(earlier);
  }
  for (const r of rows.slice(S.win.from)) {
    const row = el("div", "wrow" + (r.folded ? " folded" : ""));
    const pv = el("span", "pv");
    if (r.pinned) add(pv, icon("pin"), el("span", "sr-only", "Pinned: "));
    pv.append(document.createTextNode(r.preview));
    add(row, el("span", "k", "#" + r.seq), pv);
    add(row, el("span", "meta", `${r.kind.replace(/_/g, " ")} · `));
    row.lastChild.append(el("span", "st-" + r.state, r.stateWords), document.createTextNode(` · ${r.size}${r.pinned ? " · pinned" : ""}`));
    frag.append(row);
  }
  preserveFocus(p, () => p.replaceChildren(frag));
}

function renderNetwork(p) {
  const sel = getSelection();
  if (sel && !sel.isCollapsed && sel.rangeCount && p.contains(sel.getRangeAt(0).commonAncestorContainer)) return;
  // A failed load (a damaged audit log among them) stays in view next to the decisions that arrive live.
  const error = S.netError ? [el("p", "error", S.netError)] : [];
  const granted = S.ledger.model ? [el("p", "dim", C.scopeLine(S.ledger.model))] : [];
  if (S.net.length === 0) {
    preserveFocus(p, () => p.replaceChildren(...granted, ...(error.length ? error : [el("p", "dim", "No network decisions recorded for this session.")])));
    return;
  }
  const t = el("table", "net");
  for (const e of S.net.slice(-500).reverse().map(C.netRow)) {
    const tr = el("tr", e.verdict);
    add(tr, el("td", "", clock(e.ts)), el("td", "", e.verdict), el("td", "", e.method), el("td", "", e.target), el("td", "", e.rule));
    t.append(tr);
  }
  preserveFocus(p, () => p.replaceChildren(...granted, ...error, t));
}

function budgetWords(b) {
  const parts = [];
  if (b.max_steps) parts.push(`${b.max_steps} steps`);
  if (b.max_minutes) parts.push(`${b.max_minutes} minutes`);
  return parts.length ? parts.join(", ") : "none set";
}

function renderSessionTab(p, info) {
  const kv = el("dl", "kv");
  const row = (k, v) => {
    add(kv, el("dt", "", k));
    const dd = el("dd");
    if (v instanceof Node) dd.append(v);
    else dd.textContent = v;
    kv.append(dd);
  };
  row("id", info.id);
  row("mission", info.mission);
  row("role", info.role);
  row("pack", info.pack);
  row("model", `${info.model} (${info.profile})`);
  row("workspace", info.workspace);
  row("created", new Date(info.created_ms).toLocaleString());
  const b = S.rec && S.rec.start ? S.rec.start.budget : null;
  row("budget", b ? budgetWords(b) : "loading\u2026");
  row("unattended", info.unattended ? "yes" : "no");
  row("context window", info.context_window ? C.tokens(info.context_window) : "unknown");
  if (info.parent) row("parent", link(info.parent, "#/s/" + encodeURIComponent(info.parent)));
  const kids = [...S.sessions.byId.values()].filter((s) => s.parent === info.id).sort((a, b2) => a.created_ms - b2.created_ms);
  if (kids.length) {
    const d = el("div");
    for (const k of kids) {
      const line = el("div");
      add(line, markEl(C.stateMark(k, inboxCount(k.id))), link(` ${k.title || k.id} (${k.role})`, "#/s/" + encodeURIComponent(k.id)));
      d.append(line);
    }
    row("agents", d);
  }
  const pref = el("div", "copy-pref");
  const label = el("label", "check");
  const box = el("input");
  box.type = "checkbox";
  box.id = "copy-on-select";
  box.checked = S.copyOnSelect;
  box.setAttribute("aria-describedby", "copy-on-select-note");
  box.addEventListener("change", () => setCopyOnSelect(box.checked));
  add(label, box, document.createTextNode(" Copy on select"));
  add(pref, label, el("p", "dim", "Off by default. When on, text you select in the chat, a tool output or the viewer is copied as you let go of the mouse or key, and a short note says how much. Nothing is copied while you type in a field."));
  pref.lastChild.id = "copy-on-select-note";
  p.replaceChildren(kv, pref);
}

// ---------------------------------------------------------------------------------------------
// Copy on select: a preference kept in this browser, off until the operator turns it on.

const COPY_SELECT_KEY = "loom_copy_on_select";

function storedCopyOnSelect() {
  try { return localStorage.getItem(COPY_SELECT_KEY) === "1"; } catch { return false; }
}

function setCopyOnSelect(on) {
  S.copyOnSelect = !!on;
  lastCopiedSelection = null;
  try {
    if (on) localStorage.setItem(COPY_SELECT_KEY, "1");
    else localStorage.removeItem(COPY_SELECT_KEY);
  } catch {
    // storage is blocked: the choice holds for this page load only
  }
  for (const box of document.querySelectorAll("#copy-on-select")) box.checked = S.copyOnSelect;
  announceCopy(S.copyOnSelect ? "Copy on select is on" : "Copy on select is off");
}

let lastCopiedSelection = null; // where the last copied selection was, so the same one is not copied twice
let selectTimer = 0;

/** A mouse or key gesture ended: copy what is selected when the preference, the place and the focus allow it. */
function copySelection() {
  if (!S.copyOnSelect) return;
  clearTimeout(selectTimer);
  // The selection settles just after the event (a double click selects a word on its second press).
  selectTimer = setTimeout(async () => {
    if (!S.copyOnSelect) return;
    const selection = getSelection();
    const range = selection && selection.rangeCount ? selection.getRangeAt(0) : null;
    const text = selection ? String(selection) : "";
    const scoped = !!range && ["blocks", "viewer-text"].some((id) => $(id).contains(range.commonAncestorContainer));
    const same = !!range && !!lastCopiedSelection && lastCopiedSelection.text === text
      && lastCopiedSelection.sc === range.startContainer && lastCopiedSelection.so === range.startOffset
      && lastCopiedSelection.ec === range.endContainer && lastCopiedSelection.eo === range.endOffset;
    const decision = C.copyOnSelectDecision({ enabled: S.copyOnSelect, text, scoped, typing: C.typingTarget(document.activeElement), same });
    if (decision === "empty") lastCopiedSelection = null;
    if (decision !== "copy") return;
    const mark = { text, sc: range.startContainer, so: range.startOffset, ec: range.endContainer, eo: range.endOffset };
    const inViewer = $("viewer").open;
    // The selection is already on the page, so the copy command takes it as it is; nothing is moved or reselected.
    const how = await copyText(text, {
      label: "Selection", source: "selection",
      say: (words, failed) => { if (inViewer) viewerStatus(words); else if (failed) toast(words); },
    });
    if (how !== "clipboard" && how !== "command") return;
    lastCopiedSelection = mark;
    const words = C.copiedChars(text.length);
    if (inViewer) viewerStatus(words); else toast(words);
  }, 0);
}

// ---------------------------------------------------------------------------------------------
// Stored output viewer

const viewerStatus = (text) => { $("viewer-error").textContent = text; };

/**
 * Open the dialog on a stored output. `source` may carry where to start (`start`, `end`), the
 * cited lines (`citeStart`, `citeEnd`) and where the output came from (`session`, `call`, `tool`,
 * `producer`). Focus goes to the lines themselves, so the keyboard scrolls them at once and Enter
 * is not sitting on Close. `opener` is the control that asked, which gets focus back on close; a
 * click does not focus a button in every browser, so callers pass it.
 */
function openViewer(blob, title, total, source = {}, opener = document.activeElement) {
  const dialog = $("viewer");
  setViewerMode(null);
  $("viewer-title").textContent = title || "Stored output";
  const provenance = $("viewer-provenance");
  provenance.replaceChildren();
  if (source.session) {
    const producer = link(source.producer || source.session, C.sessionHash(source.session, "chat"));
    producer.addEventListener("click", closeViewer);
    add(provenance, document.createTextNode("From "), source.tool ? el("code", "", source.tool) : document.createTextNode("a call"),
      document.createTextNode(" in "), producer, document.createTextNode((source.call ? " · call " + source.call : "") + " · snapshot "));
  } else provenance.append(document.createTextNode("Snapshot "));
  provenance.append(el("span", "mono", "out:" + blob));
  $("viewer-standing").textContent = source.citeStart
    ? "Opening this stored snapshot is an operator action. It does not change what the model has observed, and it does not verify the claim."
    : "This is a stored output snapshot. Opening it here does not change what the model has observed.";
  $("viewer-find").value = "";
  $("viewer-start").value = String(source.citeStart || Math.max(1, source.start || 1));
  if (!dialog.open) dialog.showModal();
  $("viewer-scroll").focus({ preventScroll: true });
  loadViewer(blob, total, source, { opener });
}

/** Show a range of `blob` in the open dialog. Focus and the element that opened it are kept. */
function loadViewer(blob, total, source, { opener = null, target = null } = {}) {
  const first = Math.max(1, source.start || 1);
  S.viewer = {
    ...C.createViewer(blob, total), source, opener, target,
    nextStart: first, nextEnd: source.end || first + C.LINES_PAGE - 1,
    lines: [], query: "", matches: [], match: -1, matchLine: null,
  };
  $("viewer-text").replaceChildren();
  $("viewer-info").textContent = "";
  $("viewer-find-count").textContent = "";
  $("viewer-earlier").hidden = true;
  $("viewer-more").hidden = true;
  viewerStatus("");
  return viewerPage(1);
}

function sourceLine(v, number, text) {
  const cited = !!v.source.citeStart && number >= v.source.citeStart && number <= (v.source.citeEnd || v.source.citeStart);
  const row = el("span", "source-line" + (cited ? " cited-line" : "") + (number === v.target ? " target-line" : ""));
  row.dataset.line = String(number);
  return add(row, el("span", "line-number", String(number)), el("span", "line-text", text), document.createTextNode("\n"));
}

const viewerRow = (v, line) => $("viewer-text").children[line - v.first] || null;

function closeViewer() {
  const v = S.viewer;
  S.viewer = null;
  if ($("viewer").open) $("viewer").close();
  const replacement = v?.opener?.dataset.focusKey ? [...document.querySelectorAll("[data-focus-key]")]
    .find(n => n.dataset.focusKey === v.opener.dataset.focusKey && n.getClientRects().length && !n.closest("[inert]")) : null;
  const target = v?.opener && document.contains(v.opener) ? v.opener : replacement || $("mission-tab-" + S.section);
  if (target) target.focus({ preventScroll: true });
}

/** Load the page after the loaded lines (`direction` 1) or before them (-1). */
async function viewerPage(direction) {
  const v = S.viewer;
  if (!v || v.busy) return;
  const range = direction < 0 ? C.earlierRange(v) : v.chunks.length ? C.nextRange(v) : { start: v.nextStart, end: v.nextEnd };
  if (!range) return;
  const opening = !v.chunks.length;
  v.busy = true;
  $("viewer-more").disabled = true;
  $("viewer-earlier").disabled = true;
  viewerStatus("Loading stored lines…");
  try {
    const file = v.source.file || null;
    const raw = await api("GET", file ? C.fileLinesUrl(file.session, file.path, range.start, range.end - range.start + 1) : C.linesUrl(v.blob, range.start, range.end));
    if (S.viewer !== v) return;
    const fv = file ? C.fileLinesView(raw) : null;
    if (fv && fv.binary) {
      // No lines: a binary file is said to be one, with its size, and nothing of it is drawn.
      v.done = true;
      $("viewer-info").textContent = `Binary file · ${C.byteSize(fv.bytes)}`;
      viewerStatus(`This is a binary file (${C.byteSize(fv.bytes)}); it is not shown as text.`);
      return;
    }
    const view = fv || raw;
    const joined = direction < 0 ? C.applyEarlierLines(v, view) : C.applyLines(v, view);
    if (joined) {
      const texts = C.splitLines(view.text);
      const rows = texts.map((text, i) => sourceLine(v, view.first + i, text));
      if (direction < 0) {
        // Keep the lines being read where they are while earlier ones arrive above them.
        const scroll = $("viewer-scroll");
        const before = scroll.scrollHeight;
        v.lines.unshift(...texts);
        $("viewer-text").prepend(...rows);
        scroll.scrollTop += scroll.scrollHeight - before;
      } else {
        v.lines.push(...texts);
        $("viewer-text").append(...rows);
      }
      // What is loaded changed, so the matches of the current search did too.
      if (v.query) {
        v.matches = C.findInLines(v.lines, v.query);
        v.match = v.matches.findIndex(m => v.first + m.index === v.matchLine);
        $("viewer-find-count").textContent = v.match >= 0 ? `${C.num(v.match + 1)} of ${C.num(v.matches.length)}` : C.count(v.matches.length, "match", "matches");
      }
    }
    $("viewer-info").textContent = fv ? fileInfoWords(v, fv) : v.last >= v.first ? `Lines ${C.num(v.first)}–${C.num(v.last)} of ${C.num(v.total)}` : "No lines stored";
    $("viewer-start").max = String(Math.max(1, v.total));
    // A page that does not meet the loaded lines is not shown, and that is said rather than hidden.
    viewerStatus(joined ? "" : "The lines returned do not join the loaded ones. Close this output and open it again.");
    // Paging further must not pull the view back to a line the operator went to earlier.
    if (opening && v.target) showTarget(v);
  } catch (e) {
    if (S.viewer === v) viewerStatus(e.message);
  } finally {
    v.busy = false;
    if (S.viewer === v) {
      const focused = document.activeElement;
      $("viewer-more").disabled = false;
      $("viewer-earlier").disabled = false;
      $("viewer-more").hidden = v.done || !v.chunks.length;
      $("viewer-earlier").hidden = !C.earlierRange(v);
      // A paging button that has nothing left to load goes away; do not let focus go with it.
      if ((focused === $("viewer-more") || focused === $("viewer-earlier")) && focused.hidden) $("viewer-scroll").focus({ preventScroll: true });
    }
  }
}

function showTarget(v) {
  for (const old of $("viewer-text").querySelectorAll(".target-line")) old.classList.remove("target-line");
  const row = viewerRow(v, v.target);
  if (!row) return;
  row.classList.add("target-line");
  row.scrollIntoView({ block: "center" });
}

/** Go to line: scroll when the line is loaded, otherwise load the range around it. Focus stays put. */
async function viewerJump() {
  const v = S.viewer;
  if (!v || v.busy) return;
  const target = C.lineTarget($("viewer-start").value, v.total);
  if (target.error) { viewerStatus(target.error); return; }
  if (v.chunks.length && target.line >= v.first && target.line <= v.last) {
    v.target = target.line;
    showTarget(v);
  } else {
    await loadViewer(v.blob, v.total, { ...v.source, start: Math.max(1, target.line - 3), end: target.line + C.LINES_PAGE - 4 }, { opener: v.opener, target: target.line });
    if (S.viewer?.target !== target.line || !viewerRow(S.viewer, target.line)) return;
  }
  viewerStatus(v.source.file ? `At line ${C.num(target.line)}.` : `At line ${C.num(target.line)}. Copy reference now gives this line.`);
}

function clearMatch() {
  const old = $("viewer-text").querySelector(".find-match");
  if (!old) return;
  old.classList.remove("find-match");
  const text = old.querySelector(".line-text");
  text.replaceChildren(document.createTextNode(text.textContent)); // drops the mark
}

/** Find the next (`delta` 1) or previous (-1) loaded line whose text holds the query. */
function viewerFind(delta) {
  const v = S.viewer;
  if (!v) return;
  const query = $("viewer-find").value;
  clearMatch();
  if (!query) {
    v.query = ""; v.matches = []; v.match = -1; v.matchLine = null;
    $("viewer-find-count").textContent = "";
    viewerStatus("");
    return;
  }
  if (query !== v.query) { v.query = query; v.matches = C.findInLines(v.lines, query); v.match = -1; }
  v.match = C.stepMatch(v.matches.length, v.match, delta);
  if (v.match < 0) {
    v.matchLine = null;
    $("viewer-find-count").textContent = "No matches";
    viewerStatus(`No match in the loaded lines ${C.num(v.first)}–${C.num(v.last)}. Load more lines or go to another line to search there.`);
    return;
  }
  const found = v.matches[v.match];
  const row = $("viewer-text").children[found.index];
  row.classList.add("find-match");
  if (found.at >= 0) {
    const full = v.lines[found.index];
    row.querySelector(".line-text").replaceChildren(
      document.createTextNode(full.slice(0, found.at)), el("mark", "", full.slice(found.at, found.at + found.length)), document.createTextNode(full.slice(found.at + found.length)));
  }
  row.scrollIntoView({ block: "center" });
  v.matchLine = v.first + found.index;
  $("viewer-find-count").textContent = `${C.num(v.match + 1)} of ${C.num(v.matches.length)}`;
  viewerStatus(`Line ${C.num(v.matchLine)} · ${C.num(v.match + 1)} of ${C.count(v.matches.length, "matching line")} · only the loaded lines are searched.`);
}

async function copyViewerReference() {
  const v = S.viewer;
  if (!v) return;
  const button = $("viewer-copy");
  const [what, text, done, hand] = v.source.file
    ? ["Path", C.joinPath(v.source.file.workspace, v.source.file.path), "Copied path: ", "Copy this path: "]
    : ["Reference", C.viewerReference(v), "Copied: ", "Copy this reference: "];
  const how = await copyText(text, { label: what, say: viewerStatus, copied: done + text });
  if (how === "clipboard" || how === "command") flashCopied(button);
  else if (how === "none") viewerStatus(hand + text);
}

/** The line numbers the selection in the viewer's lines touches ({from, to}), or null when nothing there is selected. */
function viewerSelection() {
  const selection = getSelection();
  const root = $("viewer-text");
  if (!selection || selection.isCollapsed || !selection.rangeCount) return null;
  const range = selection.getRangeAt(0);
  if (!root.contains(range.commonAncestorContainer)) return null;
  // A boundary in the lines' container itself points between rows: the row after it starts, the row before it ends.
  // Where in its row a boundary lies: "lead" (in the number, or before the text), "tail" (after the text: the row's newline) or "text".
  const lineAt = (node, offset, end) => {
    if (node === root) {
      const row = root.children[end ? Math.max(0, offset - 1) : offset] || root.lastElementChild;
      return row ? { line: Number(row.dataset.line), kind: end ? "tail" : "lead" } : null;
    }
    const row = (node.nodeType === 1 ? node : node.parentElement)?.closest(".source-line");
    if (!row) return null;
    const text = row.querySelector(".line-text");
    const at = document.createRange();
    at.setStart(node, offset);
    at.collapse(true);
    const span = document.createRange();
    span.selectNodeContents(text);
    const atStart = span.compareBoundaryPoints(Range.START_TO_START, at) >= 0;
    const atEnd = span.compareBoundaryPoints(Range.END_TO_END, at) <= 0;
    // An empty line has both; a start there counts as its end and an end as its start, so an edge row with nothing chosen drops out.
    const kind = end ? (atStart ? "lead" : atEnd ? "tail" : "text") : (atEnd ? "tail" : atStart ? "lead" : "text");
    return { line: Number(row.dataset.line), kind };
  };
  const start = lineAt(range.startContainer, range.startOffset, false);
  const stop = lineAt(range.endContainer, range.endOffset, true);
  if (!start || !stop) return null;
  const { from, to } = C.viewerSelectionEdges({ from: start.line, to: stop.line, startAt: start.kind, endAt: stop.kind });
  return Number.isFinite(from) && Number.isFinite(to) ? { from, to } : null;
}

/** "Copy lines": the lines the selection touches, else every loaded line; whole lines, without their numbers. */
async function copyViewerLines() {
  const v = S.viewer;
  if (!v) return;
  const picked = C.viewerLinesCopy(v, viewerSelection());
  if (!picked) { viewerStatus("No lines are loaded to copy."); return; }
  const how = await copyText(picked.text, { label: "Lines", say: viewerStatus, copied: C.viewerLinesWords(picked) });
  if (how === "clipboard" || how === "command") flashCopied($("viewer-copy-lines"));
}

function updateDelivery(id) {
  const state = S.messageState.get(id);
  if (!state || !S.rec || S.rec.session !== id || state.state === "failed") return;
  const records = [...S.rec.records.values()];
  const user = records.find(r => r.seq > state.afterSeq && r.kind === "user_message" && (r.text === state.sentText || (state.attached && C.splitAttachments(r.text).text === state.sentText.trimEnd())));
  if (!user) return;
  state.recordedSeq = user.seq;
  const request = records.find(r => r.seq > user.seq && r.kind === "model_request" && (!r.purpose || r.purpose === "step"));
  const text = request ? "Delivered to a model step." : "Message recorded · queued for the next model step.";
  if (state.text !== text) state.at = ++S.stamp; // a receipt that lands after a model switch is newer than the switch note
  state.state = request ? "delivered" : "queued";
  state.text = text;
}

// ---------------------------------------------------------------------------------------------
// Attachments (docs/UPLOADS.md): each file uploads at once and shows as a chip; Send carries the saved paths.

/** Kept in memory with the drafts: draft key -> [{id, name, size, state: "uploading"|"done"|"failed", path, error, ws}]. */
const attachments = new Map();
let attachSeq = 0;
const attachCtx = {
  composer: {
    chips: "attach-chips",
    key: () => (S.openId ? "message:" + S.openId : null),
    workspace: () => (S.sessions.byId.get(S.openId) || {}).workspace || "",
    changed: () => renderHeader(),
  },
  start: {
    chips: "f-attach-chips",
    key: () => "new",
    workspace: () => $("f-workspace").value.trim(),
    changed: () => {},
  },
};
const attachList = (key) => attachments.get(key) || [];
/** What Send needs to know: the saved paths, and whether an upload is still going or has failed. */
function attachState(key) {
  const list = attachList(key);
  return {
    paths: list.filter(a => a.state === "done").map(a => a.path),
    busy: list.some(a => a.state === "uploading"),
    failed: list.some(a => a.state === "failed"),
  };
}

function renderChips(c) {
  const key = c.key();
  const list = key ? attachList(key) : [];
  const box = $(c.chips);
  box.replaceChildren();
  box.hidden = !list.length;
  for (const a of list) {
    const chip = el("li", "attach-chip " + a.state);
    add(chip, a.file && a.state !== "failed" && C.isImageFile(a.file) ? chipThumb(a.file, a.name) : icon(a.state === "failed" ? "alert" : "source"), el("span", "attach-name", a.name));
    if (a.state === "uploading") add(chip, el("span", "attach-size", "Uploading…"));
    else if (a.state === "failed") add(chip, el("span", "attach-error", a.error));
    else add(chip, el("span", "attach-size", C.byteSize(a.size)));
    const x = btn("×", "attach-x", () => {
      attachments.set(key, attachList(key).filter(o => o !== a));
      if (!attachList(key).length) attachments.delete(key);
      renderChips(c);
    });
    x.setAttribute("aria-label", "Remove " + a.name);
    x.title = "Remove " + a.name;
    add(chip, x);
    if (a.state === "failed") chip.setAttribute("role", "alert");
    add(box, chip);
    if (a.state !== "failed" && a.file && C.isImageFile(a.file) && c.key() && c.key() !== "new" && visionOff()) {
      const note = el("li", "attach-note dim", C.NO_VISION_NOTE);
      add(box, note);
    } else if (a.state !== "failed" && a.file && C.isImageFile(a.file) && c.key() === "new" && newVisionOff()) {
      add(box, el("li", "attach-note dim", C.NO_VISION_NOTE));
    }
  }
  c.changed();
}

function addFiles(c, files) {
  const key = c.key();
  const ws = c.workspace();
  if (!key || !files.length) return;
  if (!ws) { toast("Enter a workspace first: attached files are saved in it."); return; }
  const list = attachList(key);
  attachments.set(key, list);
  for (const file of files) {
    const a = { id: ++attachSeq, name: file.name || "pasted-file", size: file.size, state: "uploading", path: "", error: "", ws, file };
    list.push(a);
    uploadOne(c, key, a, file);
  }
  renderChips(c);
}

async function uploadOne(c, key, a, file) {
  try {
    const r = await fetch("/api/uploads?workspace=" + encodeURIComponent(a.ws) + "&name=" + encodeURIComponent(a.name), {
      method: "POST",
      credentials: "omit",
      headers: authHeaders({ "Content-Type": file.type || "application/octet-stream" }),
      body: file,
    });
    if (r.status === 401) { lost(); return; }
    const text = await r.text();
    if (!r.ok) throw new Error(C.errorSentence(r.status, text));
    const v = JSON.parse(text);
    a.path = v.path;
    a.name = v.name || a.name;
    a.size = Number.isFinite(v.bytes) ? v.bytes : a.size;
    a.state = "done";
  } catch (e) {
    a.state = "failed";
    a.error = e.message;
  }
  if (attachList(key).includes(a) && c.key() === key) renderChips(c);
}

/** Wire one attach button, file input, drop zones and paste target to a context. */
function wireAttach(c, { button, input, drops, paste, canDrop = () => true }) {
  $(button).addEventListener("click", () => $(input).click());
  $(input).addEventListener("change", () => { addFiles(c, [...$(input).files]); $(input).value = ""; });
  const hasFiles = (e) => e.dataTransfer && [...(e.dataTransfer.types || [])].includes("Files");
  for (const id of drops) {
    const zone = $(id);
    zone.addEventListener("dragover", (e) => {
      if (!hasFiles(e) || !canDrop()) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = "copy";
      zone.classList.add("drop-on");
    });
    zone.addEventListener("dragleave", (e) => { if (!zone.contains(e.relatedTarget)) zone.classList.remove("drop-on"); });
    zone.addEventListener("drop", (e) => {
      zone.classList.remove("drop-on");
      if (!hasFiles(e) || !canDrop()) return;
      e.preventDefault();
      addFiles(c, [...e.dataTransfer.files]);
    });
  }
  $(paste).addEventListener("paste", (e) => {
    const files = [...((e.clipboardData && e.clipboardData.files) || [])];
    // Text that arrives with a file (a copied cell also brings its picture) pastes as text.
    if (!files.length || (e.clipboardData.getData("text/plain") || "") !== "") return;
    e.preventDefault();
    addFiles(c, files);
  });
}

/** The new-mission form: attaching waits for a workspace, and a changed workspace drops the files saved in the old one. */
function syncNewAttach() {
  const ws = $("f-workspace").value.trim();
  $("f-attach").disabled = !ws;
  $("f-attach").title = ws ? "Attach files; they are saved in the workspace" : "Enter a workspace first: attached files are saved in it.";
  const list = attachList("new");
  const note = $("f-attach-note");
  if (list.some(a => a.ws !== ws)) {
    attachments.delete("new");
    renderChips(attachCtx.start);
    note.textContent = "The workspace changed, so the attached files were cleared. Attach them again.";
    note.hidden = false;
  } else if (!list.length && ws) note.hidden = true;
}

async function sendMessage(when = S.sendWhen || "now") {
  S.sendWhen = "now";
  const id = S.openId;
  const key = "message:" + id;
  const text = $("msg").value;
  const previous = S.messageState.get(id);
  const att = attachState(key);
  if (!id || (!text.trim() && !att.paths.length) || att.busy || att.failed || S.sending.has(id)) return;
  if (!S.rec?.initialComplete) {
    toast("Wait for the session record to finish loading before sending.");
    return;
  }
  if (previous?.accepted && previous.recordedSeq === undefined && previous.state !== "failed") {
    toast("Waiting for the previous message to be recorded…");
    return;
  }
  const info = S.sessions.byId.get(id);
  if (!info || !C.sessionActions(info).send) return;
  C.setDraft(S.drafts, key, text);
  S.seatNote.delete(id);
  S.sending.add(id);
  S.messageState.set(id, { state: "sending", accepted: false, sentText: text, attached: att.paths.length > 0, afterSeq: C.lastSeq(S.rec) ?? -1, text: "Sending to " + (info.title || id) + "…", at: ++S.stamp });
  renderHeader();
  try {
    const reply = await api("POST", "/api/sessions/" + encodeURIComponent(id) + "/messages", { ...(att.paths.length ? { text, attachments: att.paths } : { text }), ...(queueNow(id, when) ? { when: "after_turn" } : {}) });
    const sent = new Set(att.paths);
    const rest = attachList(key).filter(a => !sent.has(a.path));
    if (rest.length) attachments.set(key, rest); else attachments.delete(key);
    renderChips(attachCtx.composer);
    const state = S.messageState.get(id);
    state.accepted = true;
    // A message held for after the turn answers {queued: {...}}; an idle lead took it at once and answers {}.
    if (reply && reply.queued) { state.state = "held"; state.text = "Queued for after this turn; edit or send it now above."; state.at = ++S.stamp; }
    else if (state.state !== "delivered") { state.state = "queued"; state.text = "Message accepted · awaiting its recorded delivery."; state.at = ++S.stamp; }
    if (C.clearDraftIfUnchanged(S.drafts, key, text)) setDraft(key, "");
    if (S.openId === id) { updateDelivery(id); S.follow = true; }
  } catch (e) {
    const state = { ...C.sendFailure(S.messageState.get(id), e.message, { rejected: e.status >= 400 && e.status < 500 }), at: ++S.stamp };
    S.messageState.set(id, state);
    if (state.recordedSeq !== undefined && C.clearDraftIfUnchanged(S.drafts, key, text)) setDraft(key, "");
  } finally {
    S.sending.delete(id);
    if (S.openId === id) { renderHeader(); if (S.view === "session") $("msg").focus({ preventScroll: true }); }
  }
}

// ---------------------------------------------------------------------------------------------
// Model seat (composer)

/** The configured profiles: the live list from GET /api/models, else the ones /api/status reported. */
function seatModels() {
  return (S.profiles && S.profiles.models) || (S.status && S.status.models) || [];
}
async function loadProfiles() {
  try { S.profiles = await api("GET", "/api/models"); } catch { /* /api/status still names the profiles */ }
  if (S.view === "session") want("header");
}


// ---------------------------------------------------------------------------------------------
// Queued messages (docs/CONTRACTS-2026-11-23.md E5)

S.queued = { session: null, items: [], error: "", editing: null, editText: "", busy: new Set() };

async function loadQueued() {
  const id = S.openId;
  if (!id) return;
  try {
    const items = C.queuedList(await api("GET", C.queuedUrl(id)));
    if (S.openId !== id) return;
    S.queued.session = id;
    S.queued.items = items;
    S.queued.error = "";
    if (S.queued.editing && !items.some(i => i.id === S.queued.editing)) S.queued.editing = null;
  } catch (e) {
    if (S.openId !== id) return;
    // A daemon without the route says nothing: the list stays empty and the composer keeps working.
    S.queued.session = id;
    S.queued.items = [];
    S.queued.error = e.status === 404 ? "" : e.message;
  }
  renderQueue();
  renderCaption(S.sessions.byId.get(id));
}

function queuedCount() {
  return S.queued.session === S.openId ? S.queued.items.length : 0;
}

async function queueAct(item, what) {
  const id = S.openId;
  const busy = S.queued.busy;
  if (busy.has(item.id)) return;
  busy.add(item.id);
  S.queued.error = "";
  try {
    if (what === "remove") await api("DELETE", C.queuedUrl(id, item.id));
    else if (what === "send") await api("POST", C.queuedUrl(id, item.id, "send"));
    else if (what === "save") {
      await api("PUT", C.queuedUrl(id, item.id), { text: S.queued.editText });
      S.queued.editing = null;
    }
  } catch (e) {
    // 404: it was just sent or removed elsewhere; the list below is the truth.
    S.queued.error = e.status === 404 ? "That message is no longer queued; it may have just been sent." : e.message;
    if (e.status === 404 && S.queued.editing === item.id) S.queued.editing = null;
  } finally {
    busy.delete(item.id);
  }
  await loadQueued();
}

function renderQueue() {
  const box = $("queue-box");
  const items = S.queued.session === S.openId && S.view === "session" ? S.queued.items : [];
  const editing = S.queued.editing;
  // An edit in progress keeps its textarea (and focus) while the list refreshes around it.
  const keep = editing && box.querySelector("textarea.queue-edit");
  if (keep && items.some(i => i.id === editing) && !S.queued.error) {
    return;
  }
  const hadFocus = box.contains(document.activeElement) ? document.activeElement.dataset.focusKey : null;
  box.replaceChildren();
  box.hidden = !items.length && !S.queued.error;
  if (!items.length && !S.queued.error) return;
  const head = el("h2", "queue-head", "Queued for after this turn · " + items.length);
  head.id = "queue-head";
  add(box, head);
  if (S.queued.error) {
    const err = el("p", "error", S.queued.error);
    err.setAttribute("role", "alert");
    add(box, err);
  }
  const list = el("ul", "queue-list");
  list.setAttribute("aria-labelledby", "queue-head");
  for (const item of items) {
    const li = el("li", "queue-item");
    const busy = S.queued.busy.has(item.id);
    if (S.queued.editing === item.id) {
      const ta = el("textarea", "queue-edit");
      ta.value = S.queued.editText;
      ta.rows = 3;
      ta.setAttribute("aria-label", "Edit queued message");
      ta.dataset.focusKey = "q-edit:" + item.id;
      ta.addEventListener("input", () => { S.queued.editText = ta.value; });
      ta.addEventListener("keydown", (e) => {
        if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); S.queued.editing = null; renderQueue(); focusQueue("q-editbtn:" + item.id); }
      });
      const save = btn("Save", "small primary", () => queueAct(item, "save"));
      save.disabled = busy || !S.queued.editText.trim();
      const cancel = btn("Cancel", "small", () => { S.queued.editing = null; renderQueue(); focusQueue("q-editbtn:" + item.id); });
      add(li, ta, add(el("div", "queue-actions"), save, cancel));
    } else {
      const preview = el("p", "queue-text", C.queuedPreview(item.text) || "(files only)");
      preview.title = item.text;
      if (item.attachments.length) add(preview, el("span", "dim", " · " + item.attachments.length + (item.attachments.length === 1 ? " file" : " files")));
      const edit = btn("Edit", "small", () => { S.queued.editing = item.id; S.queued.editText = item.text; renderQueue(); focusQueue("q-edit:" + item.id); });
      edit.dataset.focusKey = "q-editbtn:" + item.id;
      edit.setAttribute("aria-label", "Edit queued message: " + C.queuedPreview(item.text, 40));
      const now = btn("Send now", "small", () => queueAct(item, "send"));
      now.dataset.focusKey = "q-send:" + item.id;
      now.setAttribute("aria-label", "Send now: " + C.queuedPreview(item.text, 40));
      const rm = btn("Remove", "small", () => queueAct(item, "remove"));
      rm.dataset.focusKey = "q-rm:" + item.id;
      rm.setAttribute("aria-label", "Remove queued message: " + C.queuedPreview(item.text, 40));
      for (const b of [edit, now, rm]) b.disabled = busy;
      add(li, preview, add(el("div", "queue-actions"), edit, now, rm));
    }
    add(list, li);
  }
  add(box, list);
  if (hadFocus) focusQueue(hadFocus);
}
function focusQueue(key) {
  const node = [...$("queue-box").querySelectorAll("[data-focus-key]")].find(n => n.dataset.focusKey === key);
  if (node) node.focus({ preventScroll: true });
}

/** Send now (the default) or queue for after the turn: only a running lead can queue. */
async function sendChoice(when) {
  S.sendWhen = when;
  closeSendMenu();
  await sendMessage();
}
function closeSendMenu(refocus = false) {
  const menu = $("send-menu");
  if (menu.hidden) return;
  menu.hidden = true;
  $("send-more").setAttribute("aria-expanded", "false");
  if (refocus) $("send-more").focus({ preventScroll: true });
}
function openSendMenu() {
  const menu = $("send-menu");
  menu.hidden = false;
  $("send-more").setAttribute("aria-expanded", "true");
  menu.querySelector("button").focus({ preventScroll: true });
}

/** Does the open session's model take no images (its profile says vision: false)? Unknown counts as "takes them". */
function visionOff() {
  const info = S.sessions.byId.get(S.openId);
  return !!info && C.modelVision(seatModels(), C.currentModel(S.rec, info)) === false;
}
function newVisionOff() {
  const want = S.newForm && S.newForm.model;
  const models = seatModels();
  const profile = want || (S.profiles && S.profiles.default_model) || "";
  return !!profile && C.modelVision(models, { profile }) === false;
}
/** Queue only a running lead's message that was asked to wait; anything else is sent now. */
function queueNow(id, when) {
  const info = S.sessions.byId.get(id);
  return when === "after_turn" && !!info && C.sessionActions(info).running && C.rootNoun(info) === "lead";
}

/** The select shows the session's profile; another choice waits behind an inline confirmation. */
function renderSeat(info) {
  const sel = $("model-seat");
  const current = C.currentModel(S.rec, info);
  const models = seatModels();
  const options = C.seatOptions(models, current);
  const sig = info.id + "|" + (current ? "" : "?") + options.map(o => o.value + "=" + o.label).join(",");
  if (sel.dataset.sig !== sig) {
    sel.replaceChildren();
    if (!current) { const none = new Option("model unknown", ""); none.disabled = true; sel.append(none); }
    for (const o of options) sel.append(new Option(o.label, o.value));
    sel.dataset.sig = sig;
  }
  if (S.seat && (S.seat.session !== info.id || (current && current.profile === S.seat.profile))) S.seat = null;
  sel.value = S.seat ? S.seat.profile : current ? current.profile : "";
  // The daemon refuses to re-seat a finished session, so say that here rather than ask for a confirmation that cannot succeed.
  const avail = C.seatAvailability(info, S.seatBusy.has(info.id) ? info.id : null, options.length);
  if (avail.disabled && info.status && info.status.phase === "ended") S.seat = null;
  sel.disabled = avail.disabled;
  sel.title = avail.reason || "The model this session runs on. Choosing another asks first.";
  const unreachable = !!options.find(o => o.value === sel.value && o.unreachable);
  sel.classList.toggle("unreachable", unreachable);
  sel.setAttribute("aria-label", "Model for this session" + (unreachable ? ", not reachable" : "") + (avail.reason && avail.disabled ? ". " + avail.reason : ""));
  const q = S.seat ? C.seatConfirm(models, current, S.seat.profile) : null;
  if (S.seat && !q) S.seat = null;
  $("model-confirm").hidden = !q;
  const busy = S.seatBusy.has(info.id);
  if (q) {
    if ($("model-confirm-text").textContent !== q.text) $("model-confirm-text").textContent = q.text;
    $("model-confirm-yes").textContent = q.yes;
    $("model-confirm-no").textContent = q.no;
    sel.setAttribute("aria-describedby", "model-confirm-text");
  } else {
    sel.removeAttribute("aria-describedby");
    $("model-confirm-text").textContent = "";
  }
  $("model-confirm-yes").disabled = busy;
  $("model-confirm-no").disabled = busy;
  return q;
}
/** The text box grows with its text up to 40% of the window (CSS max-height), then scrolls. */
function growMsg() {
  const msg = $("msg");
  const key = msg.value + "|" + msg.clientWidth;
  if (msg.dataset.grown === key || msg.hidden) return;
  msg.dataset.grown = key;
  msg.style.setProperty("height", "auto");
  msg.style.setProperty("height", msg.scrollHeight + "px");
}
function cancelSeat() {
  if (!S.seat || S.seatBusy.has(S.seat.session)) return;
  S.seat = null;
  renderHeader();
  $("model-seat").focus({ preventScroll: true });
}
/** Focus goes back to the select only when it is not somewhere the operator has gone on to (the message box, say). */
function focusIsFree() {
  const active = document.activeElement;
  return !active || active === document.body || $("model-confirm").contains(active) || active === $("model-seat");
}
async function applySeat() {
  const pending = S.seat;
  if (!pending || S.seatBusy.has(pending.session)) return;
  S.seatBusy.add(pending.session);
  S.seatNote.set(pending.session, { text: `Switching to ${pending.profile}…`, at: ++S.stamp });
  // What the session was on before: a newer session frame (another tab, the CLI) must not be overwritten by this receipt.
  const was = S.sessions.byId.get(pending.session);
  const before = was ? { profile: was.profile, model: was.model } : null;
  renderHeader();
  try {
    const receipt = await api("POST", "/api/sessions/" + encodeURIComponent(pending.session) + "/model", { profile: pending.profile });
    S.seatNote.set(pending.session, { text: C.seatReceipt(receipt), at: ++S.stamp });
    const info = S.sessions.byId.get(pending.session);
    // The `session` frame confirms it; show the new seat now so the select does not flicker back.
    if (info && receipt && receipt.model && C.receiptApplies(info, before)) {
      C.applySessionEvent(S.sessions, { ...info, profile: receipt.model.profile, model: receipt.model.model, context_window: receipt.model.context_window });
    }
  } catch (e) {
    S.seatNote.set(pending.session, { text: e.message, at: ++S.stamp });
  } finally {
    if (S.seat === pending) S.seat = null; // a question the operator has since raised on another session stays
    S.seatBusy.delete(pending.session);
    if (S.openId === pending.session) {
      const free = focusIsFree();
      renderHeader();
      if (S.view === "session" && free) $("model-seat").focus({ preventScroll: true });
    }
    // The list shows the model too, and a seat held for this session is let go whichever session is open now.
    want("list", "header");
  }
}

function renameSession() {
  const id = S.openId;
  const info = id && S.sessions.byId.get(id);
  if (!info || info.parent) return;
  const h = $("s-title");
  if (h.dataset.editing === "true") return;
  h.dataset.editing = "true";
  $("b-rename").hidden = true;
  const current = info.title || "";
  const input = el("input", "stitle-edit");
  input.type = "text";
  input.value = current;
  input.maxLength = 200;
  input.setAttribute("aria-label", "Mission title");
  const restore = (refocus = false) => {
    h.dataset.editing = "";
    const cur = S.sessions.byId.get(id) || info;
    h.textContent = cur.title || id;
    $("b-rename").hidden = !!cur.parent || S.openId !== id;
    if (refocus && !$("b-rename").hidden) $("b-rename").focus({ preventScroll: true });
  };
  const submit = async () => {
    const title = input.value.trim();
    if (!title || title === current) return restore(true);
    input.disabled = true;
    try {
      await api("POST", "/api/sessions/" + encodeURIComponent(id) + "/rename", { title });
      const cur = S.sessions.byId.get(id);
      if (cur) S.sessions.byId.set(id, { ...cur, title });
      restore(true);
      want("list", "header", "overview");
    } catch (e) { input.disabled = false; notice(e.message); }
  };
  const row = el("div", "rename-row");
  add(row, input, btn("Save", "primary small", submit), btn("Cancel", "small", () => restore(true)));
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); submit(); }
    else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); restore(true); }
  });
  h.replaceChildren(row);
  input.focus();
  input.select();
}

async function sessionAction(name, body) {
  const id = S.openId;
  if (!id || S.actionState.has(id)) return;
  const label = name === "stop" ? "Stopping…" : name === "resume" ? "Resuming…" : body?.archived ? "Archiving…" : "Unarchiving…";
  if (name === "stop") S.stopAsked.add(id);
  else if (name === "resume") S.stopAsked.delete(id);
  S.actionState.set(id, { name, label, archived: body?.archived, accepted: false });
  renderHeader();
  try {
    await api("POST", "/api/sessions/" + encodeURIComponent(id) + "/" + name, body);
    const action = S.actionState.get(id);
    action.accepted = true;
    action.label = name === "stop" ? "Stop requested" : name === "resume" ? "Resume requested" : label;
    await loadSessions();
    // Archiving a mission drops its open inbox items on the daemon without emitting a resolve
    // record, so pull the authoritative inbox to clear them here too (and bring them back on undo).
    if (name === "archive") loadInbox();
  } catch (e) { S.actionState.delete(id); S.stopAsked.delete(id); notice(e.message); }
  if (S.openId === id) renderHeader();
}

let drawerOpener = null;
let nextOpener = null; // the button that asked for a drawer (a click does not focus it in every browser)
function setDrawer(side, open) {
  const panel = $(side);
  const narrow = matchMedia("(max-width: 1099px)").matches;
  const mobile = matchMedia("(max-width: 699px)").matches;
  const asked = nextOpener;
  nextOpener = null;
  if (open) drawerOpener = asked || document.activeElement;
  document.body.classList.toggle("show-" + side, open);
  const rightOpen = document.body.classList.contains("show-right");
  if (side === "right" && !narrow && S.view === "session") S.inspectorPref = rightOpen;
  const leftOpen = document.body.classList.contains("show-left");
  $("right").inert = !rightOpen || (mobile && leftOpen);
  $("left").inert = (mobile && !leftOpen) || (narrow && rightOpen);
  $("mid").inert = (narrow && rightOpen) || (mobile && leftOpen);
  for (const id of ["toggle-inspector", "open-right"]) $(id).setAttribute("aria-expanded", String(rightOpen));
  $("open-left").setAttribute("aria-expanded", String(leftOpen));
  for (const [node, modal] of [[$("right"), narrow && rightOpen], [$("left"), mobile && leftOpen]]) {
    if (modal) { node.setAttribute("role", "dialog"); node.setAttribute("aria-modal", "true"); }
    else { node.removeAttribute("role"); node.removeAttribute("aria-modal"); }
  }
  if (open && ((side === "right" && narrow) || (side === "left" && mobile))) {
    panel.querySelector("button, a, input")?.focus();
  } else if (!open && drawerOpener && panel.contains(document.activeElement) && document.contains(drawerOpener)) drawerOpener.focus({ preventScroll: true });
}

function tabKeys(event, tabs, activate) {
  const index = tabs.indexOf(event.currentTarget);
  let next = null;
  if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
  if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
  if (event.key === "Home") next = 0;
  if (event.key === "End") next = tabs.length - 1;
  if (next === null) return;
  event.preventDefault(); activate(tabs[next]); tabs[next].focus();
}

function resizeInspector(width) {
  const max = Math.max(280, Math.min(560, Math.floor(innerWidth * 0.45)));
  const value = Math.max(280, Math.min(max, width));
  $("app").style.setProperty("--inspector-width", value + "px");
  $("inspector-resize").setAttribute("aria-valuenow", String(value));
  $("inspector-resize").setAttribute("aria-valuemax", String(max));
  remember("inspector-width", value);
}

// ---------------------------------------------------------------------------------------------
// Wiring

// ---------------------------------------------------------------------------------------------
// Keyboard: the switcher, the shortcut sheet, stepping through missions

const MAC = /Mac|iPhone|iPad/.test((typeof navigator === "object" && (navigator.platform || navigator.userAgent)) || "");
let toastTimer = 0;
let toastKeep = false;
function dismissToast() {
  clearTimeout(toastTimer);
  toastTimer = 0;
  toastKeep = false;
  const t = $("keys-live");
  if (t) t.textContent = "";
}
/** A short line for everyone: shown for a few seconds and read out politely. Never an alert. */
function toast(text, { keep = false } = {}) {
  const t = $("keys-live");
  t.textContent = text;
  toastKeep = keep;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastTimer = 0;
    toastKeep = false;
    t.textContent = "";
  }, 4000);
}

const SW_SHOWN = 60;
const SW = { rows: [], active: 0, opener: null, chose: false };

function openSwitcher() {
  const dialog = $("switcher");
  if (dialog.open) { $("switcher-q").focus(); return; }
  if (document.querySelector("dialog[open]")) return;
  SW.opener = document.activeElement;
  SW.chose = false;
  SW.active = 0;
  $("switcher-q").value = "";
  renderSwitcher();
  dialog.showModal();
  $("switcher-q").focus();
}

function renderSwitcher() {
  const q = $("switcher-q").value;
  S.now = Date.now();
  SW.rows = C.switcherRows(S.sessions, S.inbox, q, { now: S.now, activity: S.activity, since: S.connectedSince, showArchived: S.showArchived });
  SW.active = Math.max(0, Math.min(SW.active, Math.min(SW.rows.length, SW_SHOWN) - 1));
  const list = $("switcher-list");
  const frag = document.createDocumentFragment();
  SW.rows.slice(0, SW_SHOWN).forEach((row, i) => {
    const li = el("li", "sw-row" + (i === SW.active ? " active" : ""));
    li.id = "sw-" + i;
    li.setAttribute("role", "option");
    li.setAttribute("aria-selected", String(i === SW.active));
    const m = add(el("span", "mark mark-" + (row.mark.tone || "dim")), icon(row.mark.icon), el("span", "sr-only", row.mark.words + ": "));
    const main = add(el("span", "sw-main"),
      add(el("span", "sw-line"), el("span", "sw-name", row.title), row.root ? null : el("span", "sw-kind dim", "agent")),
      el("span", "sw-ident mono dim", row.identity.text));
    if (row.reason) {
      const why = add(el("span", "sw-reason tone-" + (row.reason.tone || "quiet")), icon(row.reason.icon), el("span", "", row.reason.text));
      if (row.reason.tip) why.title = row.reason.tip;
      main.append(why);
    }
    add(li, m, main);
    li.addEventListener("click", () => chooseSwitcher(i));
    frag.append(li);
  });
  list.replaceChildren(frag);
  const input = $("switcher-q");
  if (SW.rows.length) input.setAttribute("aria-activedescendant", "sw-" + SW.active); else input.removeAttribute("aria-activedescendant");
  const more = SW.rows.length > SW_SHOWN ? `, first ${SW_SHOWN} shown: type to narrow` : "";
  $("switcher-status").textContent = SW.rows.length
    ? `${C.count(SW.rows.length, "session")}${q.trim() ? (SW.rows.length === 1 ? " matches" : " match") : ""}${more}`
    : `No session matches "${q.trim()}"`;
  list.querySelector(".active")?.scrollIntoView({ block: "nearest" });
}

function moveSwitcher(delta) {
  const n = Math.min(SW.rows.length, SW_SHOWN);
  if (!n) return;
  SW.active = (SW.active + delta + n) % n;
  renderSwitcher();
}

function chooseSwitcher(i = SW.active) {
  const row = SW.rows[i];
  if (!row) return;
  SW.chose = true;
  $("switcher").close();
  const hash = C.sessionHash(row.id);
  if (location.hash === hash) route(); else location.hash = hash;
  // The record is on screen now: focus lands on its selected tab, so the keyboard goes on from there.
  setTimeout(() => document.querySelector('#mission-tabs [aria-selected="true"]')?.focus({ preventScroll: true }), 60);
}

let keysOpener = null;
function openKeys() {
  if (document.querySelector("dialog[open]")) return;
  keysOpener = document.activeElement;
  const body = $("keys-body");
  body.replaceChildren();
  for (const group of C.keySheet(MAC)) {
    const list = el("dl", "keys-list");
    for (const row of group.rows) {
      const caps = el("dt", "keys-caps");
      row.keys.forEach((k, i) => { if (i) caps.append(document.createTextNode(" ")); caps.append(el("kbd", "", k)); });
      add(list, caps, el("dd", "", row.text));
    }
    add(body, el("h3", "keys-group", group.title), list);
  }
  add(body, el("p", "dim keys-note", "No key stops a session or interrupts work: Stop is a button, with its scope stated. Shortcuts without a modifier do nothing while you type in a field."));
  $("keys").showModal();
}

/** Alt+Down / Alt+Up: the next or previous row of the sidebar, without wrapping. */
/** After a step to another mission the focused control may have gone with the view it was in: the selected mission tab takes the focus. */
function rescueFocus() {
  setTimeout(() => {
    const a = document.activeElement;
    if (a && a !== document.body && a.isConnected && a.getClientRects().length) return;
    const tab = document.querySelector('#mission-tabs [role="tab"][aria-selected="true"]') || $("mission-tab-chat");
    if (tab && tab.getClientRects().length) tab.focus({ preventScroll: true });
  }, 150);
}

function stepRow(dir) {
  const rows = [...document.querySelectorAll("#sessions a.row")];
  const at = rows.findIndex(a => a.getAttribute("aria-current") === "page");
  const i = C.stepIndex(rows.length, at, dir);
  if (i === null) { toast(rows.length ? (dir > 0 ? "Last row of the sidebar" : "First row of the sidebar") : "No missions listed"); return; }
  const a = rows[i];
  const inList = !!document.activeElement?.closest?.("#sessions");
  location.hash = a.getAttribute("href");
  toast(`${a.querySelector(".name")?.textContent || "Mission"}, row ${i + 1} of ${rows.length}`);
  if (inList) setTimeout(() => document.querySelector(`[data-focus-key="${a.dataset.focusKey}"]`)?.focus({ preventScroll: true }), 0);
  else rescueFocus();
}

/** Alt+Shift+Down / Up: the next mission that blocks on the operator, cycling; said aloud as "2 of 3 needing you". */
function stepNeeds(dir) {
  const next = C.nextNeedsYou(S.sessions, S.inbox, S.view === "session" ? S.openId : null, dir);
  if (!next) { toast("Nothing needs you"); return; }
  const info = S.sessions.byId.get(next.id);
  toast(`${next.words}: ${info?.title || next.id}`);
  const hash = C.sessionHash(next.id);
  if (location.hash === hash) route(); else location.hash = hash;
  rescueFocus();
}

function keyboard(e) {
  if (e.defaultPrevented) return; // a widget that handled the key itself (the agent rows) keeps it
  const action = C.shortcutFor(e, { typing: C.typingTarget(e.target), mac: MAC });
  if (!action) return;
  const modal = document.querySelector("dialog[open]");
  if (action === "switch") {
    e.preventDefault(); // browsers bind Ctrl+K to their own search; the button does the same
    if (!modal || modal === $("switcher")) openSwitcher();
    return;
  }
  if (modal) return;
  // A modal drawer makes the main column inert: global navigation, shortcut sheet and Find must not fire behind it.
  if (document.querySelector('#left[aria-modal="true"], #right[aria-modal="true"]')) return;
  e.preventDefault();
  if (action === "row-next") stepRow(1);
  else if (action === "row-prev") stepRow(-1);
  else if (action === "needs-next") stepNeeds(1);
  else if (action === "needs-prev") stepNeeds(-1);
  else if (action === "keys") openKeys();
  else if (action === "find") openFind();
  else if (action === "mine-next") stepMine(1);
  else if (action === "mine-prev") stepMine(-1);
}

/** [ and ]: the operator's own previous or next message, from the record nearest the top of the transcript. */
function stepMine(dir) {
  if (S.view !== "session" || !S.rec) return;
  if (S.section !== "chat") setSection("chat");
  // The record at the top of the visible transcript: the first rendered block whose bottom is below the scroller's top edge.
  const edge = chatScroller().getBoundingClientRect().top + 8;
  const byId = new Map(S.rec.blocks.map(b => [String(b.id), b]));
  let top = null;
  for (const n of $("blocks").querySelectorAll("[data-bid]")) {
    if (n.getBoundingClientRect().bottom <= edge) continue;
    const b = byId.get(n.dataset.bid);
    if (b && Number.isFinite(b.seq)) { top = b.seq; break; }
  }
  const seq = C.mineStep(S.rec.blocks, top, dir);
  if (seq === null) { toast(dir > 0 ? "No later message of yours" : "No earlier message of yours"); return; }
  jumpToRecord(seq, { highlight: true });
}

// ---------------------------------------------------------------------------------------------
// Find in the record

const FIND = { result: null, cur: -1, timer: 0, node: null };

function openFind() {
  if (S.view !== "session" || !S.rec) return false;
  if (S.section !== "chat") setSection("chat");
  $("find-bar").hidden = false;
  $("btn-find").setAttribute("aria-expanded", "true");
  $("bar-find").setAttribute("aria-expanded", "true");
  const q = $("find-q");
  q.focus();
  q.select();
  if (q.value.trim()) findRun(false);
  return true;
}

function closeFind(restore = true) {
  clearTimeout(FIND.timer);
  FIND.result = null;
  FIND.cur = -1;
  FIND.node = null;
  findSaid = "";
  $("find-hint").textContent = "";
  const was = !$("find-bar").hidden;
  $("find-bar").hidden = true;
  $("btn-find").setAttribute("aria-expanded", "false");
  $("bar-find").setAttribute("aria-expanded", "false");
  $("find-count").textContent = "";
  if (was && restore) (PHONE.matches ? $("bar-find") : $("btn-find")).focus({ preventScroll: true });
}

let findSaid = "";
function renderFind() {
  const r = FIND.result;
  let text = r ? C.findWords(r, FIND.cur, false) : "";
  const hit = r && FIND.cur >= 0 ? r.hits[FIND.cur] : null;
  // What matched is said in words too, not only drawn: the snippet of the current hit follows the count.
  if (hit) text += ": " + C.findSnippet(hit);
  if (text && S.rec && !S.rec.initialComplete) text += " (the record is still loading)";
  // The live region is written only when its words change, so typing does not repeat itself.
  if (text !== findSaid) { findSaid = text; $("find-count").textContent = text; }
  const unloaded = S.rec && C.hasEarlier(S.rec) && $("find-q").value.trim() ? C.FIND_EARLIER_WORDS : "";
  const hint = [r ? C.findHint(r) : "", unloaded].filter(Boolean).join(" ");
  if ($("find-hint").textContent !== hint) $("find-hint").textContent = hint;
  $("find-go").disabled = !hit;
}

/** Search the whole loaded record. `jump` goes to the first match; without it nothing becomes current, except a hit kept by id. */
function findRun(jump) {
  if (!S.rec) return;
  const kept = FIND.result && FIND.cur >= 0 ? FIND.result.hits[FIND.cur]?.id : undefined;
  const result = C.findInRecord(S.rec.blocks, $("find-q").value, $("find-kind").value, S.rec.records.size);
  let cur = jump && result.count ? 0 : -1;
  if (!jump && kept !== undefined) { const at = result.hits.findIndex(h => h.id === kept); if (at >= 0) cur = at; }
  FIND.result = result;
  FIND.cur = cur;
  renderFind();
  if (jump && cur >= 0) jumpToRecord(result.hits[cur].seq, { done: (node) => { FIND.node = node; } });
}

async function findStep(dir) {
  if (!$("find-q").value.trim()) return;
  if (S.rec && C.hasEarlier(S.rec)) { await loadEarlier(S.rec, { all: true }); if (!S.rec || $("find-bar").hidden) return; }
  findRun(false); // the record may have grown since the last search
  const r = FIND.result;
  if (!r || !r.count) return;
  // With no current hit (Enter before the search ran, or Find reopened) the first Enter lands on the first hit, the last for Shift+Enter.
  FIND.cur = FIND.cur < 0 ? (dir > 0 ? 0 : r.count - 1) : (FIND.cur + (dir < 0 ? -1 : 1) + r.count) % r.count;
  renderFind();
  jumpToRecord(r.hits[FIND.cur].seq, { done: (node) => { FIND.node = node; } });
}

function wireFind() {
  $("btn-find").addEventListener("click", () => { if ($("find-bar").hidden) openFind(); else closeFind(); });
  $("bar-find").addEventListener("click", () => { if ($("find-bar").hidden) openFind(); else closeFind(); });
  $("find-close").addEventListener("click", () => closeFind());
  $("find-go").addEventListener("click", () => {
    if (FIND.node && FIND.node.isConnected) { FIND.node.focus(); return; }
    const hit = FIND.result && FIND.cur >= 0 ? FIND.result.hits[FIND.cur] : null;
    if (hit) jumpToRecord(hit.seq, { focus: true, done: (node) => { FIND.node = node; } });
  });
  $("find-next").addEventListener("click", () => findStep(1));
  $("find-prev").addEventListener("click", () => findStep(-1));
  $("find-q").addEventListener("input", () => {
    clearTimeout(FIND.timer);
    FIND.cur = -1; // a hit kept from a shorter query is not stepped past when Enter beats the timer
    if (!$("find-q").value.trim()) { FIND.result = null; renderFind(); return; }
    // Typing only counts (after a pause); Enter, Next and Previous go to a match.
    FIND.timer = setTimeout(() => findRun(false), 350);
  });
  $("find-kind").addEventListener("change", async () => {
    if (S.rec && C.hasEarlier(S.rec) && $("find-q").value.trim()) await loadEarlier(S.rec, { all: true });
    findRun(true);
  });
  $("find-bar").addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeFind(); }
    else if (e.key === "Enter" && e.target === $("find-q")) { e.preventDefault(); clearTimeout(FIND.timer); findStep(e.shiftKey ? -1 : 1); }
  });
}

function wireKeyboard() {
  $("switch-cap").textContent = MAC ? "⌘K" : "Ctrl+K";
  $("btn-switch").setAttribute("aria-keyshortcuts", MAC ? "Meta+K" : "Control+K");
  $("btn-switch").addEventListener("click", openSwitcher);
  $("btn-keys").addEventListener("click", openKeys);
  const sw = $("switcher");
  const q = $("switcher-q");
  q.addEventListener("input", () => { SW.active = 0; renderSwitcher(); });
  q.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); moveSwitcher(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); moveSwitcher(-1); }
    else if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); chooseSwitcher(); }
  });
  $("switcher-close").addEventListener("click", () => sw.close());
  $("keys-close").addEventListener("click", () => $("keys").close());
  for (const d of [sw, $("keys")]) d.addEventListener("click", (e) => { if (e.target === d) d.close(); }); // the backdrop
  sw.addEventListener("close", () => {
    if (!SW.chose && SW.opener && document.contains(SW.opener)) SW.opener.focus({ preventScroll: true });
    SW.opener = null;
  });
  $("keys").addEventListener("close", () => {
    if (keysOpener && document.contains(keysOpener)) keysOpener.focus({ preventScroll: true });
    keysOpener = null;
  });
  document.addEventListener("keydown", keyboard);
  wireFind();
}

// ---------------------------------------------------------------------------------------------
// New mission: creating a missing workspace, and the folder picker

/** The folder the picker marked "New folder": the create flag goes with the workspace field only while it still holds exactly this path. */
let pickerCreate = null;

function workspaceNote() {
  const note = $("f-workspace-note");
  const value = $("f-workspace").value.trim();
  const pending = pickerCreate !== null && value === pickerCreate;
  if (!pending) pickerCreate = null;
  note.textContent = pending ? "This folder does not exist yet. It is created when the mission starts." : "";
  note.hidden = !pending;
  syncNewAttach();
}

function hideCreateAsk() {
  $("f-create").hidden = true;
  $("f-submit").hidden = false;
}

/** The daemon says the workspace is missing: ask once, inline, before anything is made. Focus goes to the safe button. */
function askCreate(path) {
  $("f-create-q").textContent = C.createWorkspaceQuestion(path);
  $("f-create").hidden = false;
  $("f-submit").hidden = true;
  $("f-create").dataset.path = path;
  $("f-create-no").focus();
}

// ---- the picker (GET /api/fs/dirs)

const PK = { path: "", listing: null, error: "", showHidden: false, query: "", active: "", choice: null, seq: 0, loading: false, opener: null, naming: false };

function pickerSay(text, bad = false) {
  const s = $("picker-status");
  s.textContent = text;
  s.classList.toggle("bad", bad);
}

function openPicker(opener = $("f-browse")) {
  if (document.querySelector("dialog[open]")) return;
  PK.opener = opener;
  PK.naming = false;
  PK.choice = null;
  PK.listing = null;
  PK.error = "";
  PK.query = "";
  $("picker-filter").value = "";
  $("picker-hidden").checked = PK.showHidden;
  $("picker-newrow").hidden = true;
  $("picker-new").setAttribute("aria-expanded", "false");
  $("picker").showModal();
  const typed = $("f-workspace").value.trim();
  pickerLoad(typed.startsWith("/") || typed.startsWith("~") ? typed : "", { initial: true, focus: true });
  renderPicker();
}

function closePicker(restore = null) {
  PK.seq += 1;
  if ($("picker").open) $("picker").close();
  const target = restore || (PK.opener && document.contains(PK.opener) ? PK.opener : $("f-workspace"));
  target.focus({ preventScroll: true });
}

/**
 * List `path` (empty: the daemon's default, the home folder). On the first load a path that cannot be listed (a
 * folder the operator is about to create, say) falls back to the nearest folder above it that can.
 */
async function pickerLoad(path, { initial = false, focus = false, pick = "" } = {}) {
  const seq = ++PK.seq;
  PK.loading = true;
  PK.query = "";
  $("picker-filter").value = "";
  pickerSay("Loading folders…");
  let ask = path;
  let first = "";
  for (let tries = 0; tries < 12; tries++) {
    try {
      const view = await api("GET", C.fsDirsUrl(ask));
      if (seq !== PK.seq) return;
      PK.loading = false;
      PK.listing = view;
      PK.error = "";
      PK.choice = { path: view.path, create: false };
      PK.active = pick || "";
      renderPicker({ focus });
      if (initial && first) pickerSay(`${first} Showing ${view.path}.`, false);
      return;
    } catch (e) {
      if (seq !== PK.seq) return;
      if (!first) first = e.message;
      const up = initial && ask.startsWith("/") ? C.parentPath(ask) : null;
      if (up !== null && up !== ask) { ask = up; continue; }
      if (initial && ask !== "") { ask = ""; continue; }
      PK.loading = false;
      PK.error = e.message;
      renderPicker({ focus });
      pickerSay(e.message, true);
      return;
    }
  }
}

function pickerRows() {
  const rows = PK.listing ? C.visibleDirs(PK.listing.entries, PK.showHidden) : [];
  const q = PK.query.trim().toLowerCase();
  return q ? rows.filter((e) => e.name.toLowerCase().includes(q)) : rows;
}

function renderPicker({ focus = false } = {}) {
  const listing = PK.listing;
  const crumbs = $("picker-crumbs");
  crumbs.replaceChildren();
  if (listing) {
    const parts = C.pathCrumbs(listing.path);
    parts.forEach((c, i) => {
      if (i > 1) crumbs.append(el("span", "crumb-sep", "/"));
      const b = btn(c.name, "link", () => pickerLoad(c.path, { focus: true, pick: i + 1 < parts.length ? parts[i + 1].name : "" }));
      if (i === parts.length - 1) b.setAttribute("aria-current", "location");
      b.title = c.path;
      crumbs.append(b);
    });
  }
  $("picker-up").disabled = !listing || !listing.parent;
  const recent = C.recentWorkspaces([...S.sessions.byId.values()], S.activity);
  const rlist = $("picker-recent");
  rlist.replaceChildren();
  for (const path of recent) {
    const b = btn(path, "small", () => pickerLoad(path, { focus: true }));
    b.title = "Show " + path;
    rlist.append(add(el("li"), b));
  }
  $("picker-recent-wrap").hidden = recent.length === 0;
  const rows = pickerRows();
  PK.active = C.activeRowName(rows, PK.active);
  const hadFocus = $("picker-list").contains(document.activeElement);
  const list = $("picker-list");
  list.replaceChildren();
  for (const entry of rows) {
    const b = el("button", "dir-row" + (entry.hidden ? " hid" : ""));
    b.type = "button";
    b.dataset.name = entry.name;
    b.tabIndex = entry.name === PK.active ? 0 : -1;
    add(b, icon(entry.link ? "link" : "folder"), el("span", "nm", entry.name));
    if (entry.link) add(b, el("span", "tag", "link"));
    add(b, el("span", "sr-only", entry.link ? ", folder link" : ", folder"));
    b.title = entry.path || entry.name;
    b.addEventListener("click", () => pickerLoad(entry.path || C.joinPath(listing.path, entry.name), { focus: true }));
    list.append(add(el("li"), b));
  }
  if (listing && !PK.loading) {
    const allVisible = C.visibleDirs(listing.entries, PK.showHidden);
    const hiddenCount = listing.entries.filter((e) => e.hidden).length;
    const q = PK.query.trim();
    const words = q
      ? [rows.length ? `${C.count(rows.length, "matching folder")} of ${C.num(allVisible.length)} in ${listing.path}.` : `No folder matches "${q}" in ${listing.path}.`]
      : [rows.length ? `${C.count(rows.length, "folder")} in ${listing.path}.` : `No folders in ${listing.path}.`];
    if (!PK.showHidden && hiddenCount) words.push(`${C.count(hiddenCount, "hidden folder")} not shown.`);
    if (listing.more > 0) words.push(`${C.num(listing.more)} more are not listed.`);
    if (!PK.error) pickerSay(words.join(" "));
  }
  const choice = PK.choice;
  $("picker-choice").textContent = choice ? (choice.create ? `New folder: ${choice.path} (made when the mission starts)` : choice.path) : "";
  $("picker-use").disabled = !choice;
  if (focus || hadFocus) {
    const row = list.querySelector('[tabindex="0"]');
    if (row) { row.focus({ preventScroll: true }); row.scrollIntoView({ block: "nearest" }); }
    else if (focus) $("picker-up").disabled ? $("picker-close").focus() : $("picker-up").focus();
  }
}

function pickerUp() {
  const listing = PK.listing;
  if (!listing || !listing.parent) return;
  const from = listing.path.slice(listing.path.lastIndexOf("/") + 1);
  pickerLoad(listing.parent, { focus: true, pick: from });
}

function pickerListKeys(e) {
  const row = e.target.closest && e.target.closest(".dir-row");
  if (!row) return;
  if (e.key === "ArrowRight" && !e.altKey) { e.preventDefault(); row.click(); return; }
  if ((e.key === "ArrowLeft" && !e.altKey) || e.key === "Backspace" || (e.key === "ArrowUp" && e.altKey)) { e.preventDefault(); pickerUp(); return; }
  if (e.altKey || e.ctrlKey || e.metaKey) return;
  const next = C.stepRowName(pickerRows(), row.dataset.name, e.key);
  if (next === null) return;
  e.preventDefault();
  PK.active = next;
  for (const r of $("picker-list").querySelectorAll(".dir-row")) r.tabIndex = r.dataset.name === next ? 0 : -1;
  const target = [...$("picker-list").querySelectorAll(".dir-row")].find((r) => r.dataset.name === next);
  if (target) { target.focus(); target.scrollIntoView({ block: "nearest" }); }
}

/** With no folder row to hold the keys, Backspace and Alt+Up still go up (not from a text field, except Alt+Up). */
function pickerEmptyKeys(e) {
  if ($("picker-list").querySelector(".dir-row")) return;
  const typing = e.target.matches && e.target.matches("input, textarea");
  const up = (e.key === "ArrowUp" && e.altKey) || (!typing && !e.altKey && !e.ctrlKey && !e.metaKey && e.key === "Backspace");
  if (!up || $("picker-up").disabled) return;
  e.preventDefault();
  pickerUp();
}

function pickerNaming(on) {
  PK.naming = on;
  $("picker-newrow").hidden = !on;
  $("picker-new").setAttribute("aria-expanded", String(on));
  if (on) { $("picker-newname").value = ""; $("picker-newname").focus(); }
  else $("picker-new").focus();
}

function pickerAcceptName() {
  if (!PK.listing) return;
  const names = PK.listing.entries.map((e) => e.name);
  const r = C.checkFolderName($("picker-newname").value, names);
  if (r.error) { pickerSay(r.error, true); $("picker-newname").focus(); return; }
  PK.choice = { path: C.joinPath(PK.listing.path, r.name), create: true };
  pickerNaming(false);
  renderPicker();
  pickerSay(`${PK.choice.path} will be created when the mission starts. Nothing was made.`);
  $("picker-use").focus();
}

function usePicker() {
  const choice = PK.choice;
  if (!choice) return;
  $("f-workspace").value = choice.path;
  pickerCreate = choice.create ? choice.path : null;
  hideCreateAsk();
  workspaceNote();
  closePicker($("f-workspace"));
}

// ---------------------------------------------------------------------------------------------
// Files: the workspace of the open session, in the inspector (GET /api/sessions/{id}/files)

const FILES_NOTE = "The folder as it is now, read by you. Opening a file here does not change what the model has seen.";

/** The Files state of the open session, made (with its DOM) on first need; a different session or workspace starts over. */
function ensureFiles(info) {
  if (S.files && S.files.session === info.id && S.files.workspace === info.workspace) return S.files;
  const st = C.createFilesState(info.id, info.workspace);
  const box = el("div", "files-box");
  const note = el("p", "files-note dim", FILES_NOTE);
  note.title = info.workspace;
  const crumbs = el("nav", "files-crumbs");
  crumbs.setAttribute("aria-label", "Folder path in the workspace");
  const tools = el("div", "files-tools");
  const filter = el("input");
  filter.type = "search";
  filter.id = "files-filter";
  filter.setAttribute("aria-label", "Filter the entries shown");
  filter.placeholder = "Filter loaded entries";
  filter.autocomplete = "off";
  const hidden = el("input");
  hidden.type = "checkbox";
  hidden.id = "files-hidden";
  const hiddenLabel = el("label", "check dim");
  add(hiddenLabel, hidden, document.createTextNode(" Show hidden"));
  const refresh = btn("Refresh", "small with-icon", () => { st.cache.clear(); filesOpen(st, st.path, { force: true, focus: true, said: "Refreshed. " }); });
  refresh.prepend(icon("refresh"));
  refresh.title = "Read this folder again. The list does not update by itself.";
  add(tools, filter, hiddenLabel, refresh);
  const status = el("p", "files-status dim");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const list = el("ul", "file-list");
  list.setAttribute("aria-label", "Entries in this folder");
  add(box, note, crumbs, tools, status, list);
  st.dom = { box, crumbs, filter, hidden, status, list };
  filter.addEventListener("input", () => { st.query = filter.value; filesSync(st); });
  filter.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && filter.value) { e.preventDefault(); e.stopPropagation(); filter.value = ""; st.query = ""; filesSync(st); }
    else if (e.key === "ArrowDown") { e.preventDefault(); list.querySelector('[tabindex="0"]')?.focus(); }
  });
  hidden.addEventListener("change", () => { st.showHidden = hidden.checked; filesSync(st); });
  list.addEventListener("keydown", (e) => filesKeys(st, e));
  box.addEventListener("keydown", (e) => filesEmptyKeys(st, e));
  S.files = st;
  return st;
}

function filesRows(st) {
  const listing = st.cache.get(st.path);
  return listing ? C.fileRows(listing.entries, { query: st.query, showHidden: st.showHidden }) : [];
}

/** Show a folder: from the cache, else read it (one request per folder, never polled). `pick` selects an entry; `focus` moves the keyboard to it. */
async function filesOpen(st, path, { force = false, focus = false, pick = "", mark = false, said = "" } = {}) {
  const apply = () => {
    st.path = path;
    st.error = "";
    st.loading = null;
    const listing = st.cache.get(path);
    if (pick && listing) {
      const hit = listing.entries.find((e) => e.name === pick);
      if (hit) {
        if (pick.startsWith(".") && !st.showHidden) { st.showHidden = true; st.dom.hidden.checked = true; }
        st.query = "";
        st.dom.filter.value = "";
        st.active = pick;
        st.picked = mark ? pick : "";
      } else st.missed = pick;
    }
    if (!pick || !mark) st.picked = "";
    filesSync(st, { focus, said });
  };
  if (!force && st.cache.has(path)) { apply(); return; }
  const seq = ++st.seq;
  st.loading = path;
  filesSync(st, { loading: true });
  try {
    const view = await api("GET", C.filesUrl(st.session, path));
    if (st.seq !== seq || S.files !== st) return;
    st.cache.set(path, view);
    apply();
  } catch (e) {
    if (st.seq !== seq || S.files !== st) return;
    st.loading = null;
    st.error = e.message;
    filesSync(st, { focus });
  }
}

function filesSay(st, text, bad = false) {
  st.dom.status.textContent = text;
  st.dom.status.classList.toggle("bad", bad);
}

function filesSync(st, { focus = false, loading = false, said = "" } = {}) {
  const d = st.dom;
  d.crumbs.replaceChildren();
  const parts = C.relCrumbs(st.path);
  parts.forEach((c, i) => {
    if (i > 1) d.crumbs.append(el("span", "crumb-sep", "/"));
    const b = btn(c.name, "link", () => filesOpen(st, c.path, { focus: true, pick: i + 1 < parts.length ? parts[i + 1].name : "" }));
    if (i === parts.length - 1) b.setAttribute("aria-current", "location");
    b.title = c.path || "The workspace folder";
    d.crumbs.append(b);
  });
  const rows = filesRows(st);
  st.active = C.activeRowName(rows, st.active);
  const hadFocus = d.list.contains(document.activeElement);
  const now = Date.now();
  d.list.replaceChildren();
  for (const entry of rows) {
    const opens = C.fileEntryOpens(entry);
    const b = el("button", "file-row" + (C.isHiddenEntry(entry) ? " hid" : "") + (entry.name === st.picked ? " picked" : ""));
    b.type = "button";
    b.dataset.name = entry.name;
    b.dataset.focusKey = "file:" + C.relJoin(st.path, entry.name);
    b.tabIndex = entry.name === st.active ? 0 : -1;
    if (!opens) b.setAttribute("aria-disabled", "true");
    add(b, icon(entry.kind === "dir" ? "folder" : entry.kind === "link" ? "link" : "tool-read"), el("span", "nm", entry.name));
    if (opens && entry.kind === "dir") add(b, el("span", "sr-only", ", folder"));
    else if (opens) add(b, el("span", "meta", [C.byteSize(entry.size), Number(entry.mtime_ms) > 0 ? C.age(now, entry.mtime_ms) : ""].filter(Boolean).join(" · ")));
    else add(b, el("span", "tag", C.fileEntryKind(entry)));
    b.addEventListener("click", () => filesActivate(st, entry, b));
    d.list.append(add(el("li"), b));
  }
  const listing = st.cache.get(st.path);
  if (loading) filesSay(st, "Loading…");
  else if (st.error) filesSay(st, st.error, true);
  else if (listing) {
    let words = said + C.fileListWords(listing, rows.length, { query: st.query, showHidden: st.showHidden });
    if (st.missed) { words = `${st.missed} is not in this folder any more; it may have been moved or deleted. ` + words; st.missed = ""; }
    filesSay(st, words);
  }
  if ((focus || hadFocus) && !loading) {
    const row = d.list.querySelector('[tabindex="0"]');
    if (row) { row.focus({ preventScroll: true }); row.scrollIntoView({ block: st.picked ? "center" : "nearest" }); }
    else if (focus) {
      // No row to hold the keys for going up: a filter that hides everything keeps the focus, otherwise the current crumb does.
      const here = st.query ? null : d.crumbs.querySelector("[aria-current]");
      (here || d.filter).focus();
    }
  }
}

function filesActivate(st, entry, row) {
  if (!C.fileEntryOpens(entry)) {
    filesSay(st, C.isHarnessEntry(entry) ? ".loom holds the harness's own files; they are not shown here." : `${entry.name}: ${C.fileEntryKind(entry)}.`);
    return;
  }
  st.active = entry.name;
  const rel = C.relJoin(st.path, entry.name);
  if (entry.kind === "dir") filesOpen(st, rel, { focus: true });
  else openFileViewer(st, rel, entry, row);
}

function filesUp(st) {
  const up = C.relParent(st.path);
  if (up === null) return;
  const from = st.path.slice(st.path.lastIndexOf("/") + 1);
  filesOpen(st, up, { focus: true, pick: from });
}

/** With no row to focus, the keys for going up work from anywhere in the box that is not a text field (Alt+Up from the filter too). */
function filesEmptyKeys(st, e) {
  if (st.dom.list.querySelector(".file-row")) return;
  const typing = e.target.matches && e.target.matches("input, textarea");
  const up = (e.key === "ArrowUp" && e.altKey) || (!typing && !e.altKey && !e.ctrlKey && !e.metaKey && (e.key === "Backspace" || e.key === "ArrowLeft"));
  if (!up || C.relParent(st.path) === null) return;
  e.preventDefault();
  filesUp(st);
}

function filesKeys(st, e) {
  const row = e.target.closest && e.target.closest(".file-row");
  if (!row) return;
  if (e.key === "ArrowRight" && !e.altKey) { e.preventDefault(); if (row.getAttribute("aria-disabled") !== "true") row.click(); return; }
  if ((e.key === "ArrowLeft" && !e.altKey) || e.key === "Backspace" || (e.key === "ArrowUp" && e.altKey)) { e.preventDefault(); filesUp(st); return; }
  if (e.altKey || e.ctrlKey || e.metaKey) return;
  const rows = filesRows(st);
  const next = C.stepRowName(rows, row.dataset.name, e.key);
  if (next === null) return;
  e.preventDefault();
  st.active = next;
  const all = [...st.dom.list.querySelectorAll(".file-row")];
  for (const r of all) r.tabIndex = r.dataset.name === next ? 0 : -1;
  const target = all.find((r) => r.dataset.name === next);
  if (target) { target.focus(); target.scrollIntoView({ block: "nearest" }); }
}

function renderFiles(p, info) {
  const st = ensureFiles(info);
  if (p.firstChild !== st.dom.box || p.childNodes.length !== 1) p.replaceChildren(st.dom.box);
  if (C.filesNeedsLoad(st)) filesOpen(st, st.path);
}

/** Open the inspector on the Files tab (the header's Files button). `rel`, when given, is shown with that entry selected. */
function showFiles(opener, rel = null) {
  const info = S.sessions.byId.get(S.openId);
  if (!info) return;
  setDrawer("left", false);
  nextOpener = opener;
  setDrawer("right", true);
  setTab("files");
  const st = ensureFiles(info);
  // Attached now, so a folder already read can take the focus at once instead of waiting for the next redraw.
  if ($("panel").firstChild !== st.dom.box || $("panel").childNodes.length !== 1) $("panel").replaceChildren(st.dom.box);
  if (rel === null || rel === "") filesOpen(st, rel === "" ? "" : st.path, { focus: true });
  else {
    const parent = C.relParent(rel);
    filesOpen(st, parent, { focus: true, mark: true, pick: rel.slice(parent ? parent.length + 1 : 0) });
  }
}

// ---- a file in the viewer dialog

/** The viewer dialog reads a file of the workspace: its path, size and age in the header, no citations, "Copy path". */
function openFileViewer(st, rel, entry, opener) {
  const dialog = $("viewer");
  const file = { session: st.session, workspace: st.workspace, path: rel, entry };
  setViewerMode(file);
  $("viewer-title").textContent = rel;
  $("viewer-provenance").replaceChildren(el("span", "viewer-file-note", C.FILE_NOW_WORDS));
  $("viewer-standing").textContent = "Reading it here is an operator action. It does not change what the model has observed, and it is not evidence.";
  $("viewer-find").value = "";
  $("viewer-start").value = "1";
  if (!dialog.open) dialog.showModal();
  $("viewer-scroll").focus({ preventScroll: true });
  loadViewer(rel, 0, { file, start: 1 }, { opener });
}

/** Words and labels of the dialog for a file (`file` set) or a stored output (null). */
function setViewerMode(file) {
  for (const id of ["viewer-copy", "viewer-copy-lines"]) cancelFlash($(id));
  $("viewer-copy").textContent = file ? "Copy path" : "Copy reference";
  $("viewer-copy-lines").textContent = "Copy lines";
  $("viewer-controls").setAttribute("aria-label", file ? "Move through the file" : "Move through the stored output");
  $("viewer-scroll").setAttribute("aria-label", file ? "File lines" : "Stored output lines");
}

/** What the viewer's info line says about a file's lines. */
function fileInfoWords(v, fv) {
  const meta = C.fileMetaWords({ size: v.source.file.entry ? v.source.file.entry.size : fv.bytes, mtime_ms: v.source.file.entry && v.source.file.entry.mtime_ms }, Date.now());
  const lines = v.total === 0 ? "Empty file" : v.last >= v.first ? `Lines ${C.num(v.first)}–${C.num(v.last)} of ${C.num(v.total)}` : "No lines read";
  return meta ? `${lines} · ${meta}` : lines;
}

// ---- a tool row's "Open file"

function toolOpenRow(b) {
  const info = S.sessions.byId.get(S.openId);
  const rel = info ? C.openFileTarget(b, info.workspace) : null;
  if (rel === null) return null;
  const open = btn("Open file", "small link", (e) => showFiles(e.currentTarget, rel));
  open.dataset.focusKey = "openfile:" + b.id;
  open.title = "Show this path in the Files tab, as it is in the workspace now.";
  open.setAttribute("aria-label", C.openFileLabel(rel));
  return add(el("div", "tool-open"), open, el("span", "mono", rel || "."));
}

function wire() {
  wireKeyboard();
  wireSheet();
  $("btn-inbox").addEventListener("click", () => {
    if (location.hash === "#/inbox") route();
    else location.hash = "#/inbox";
  });
  $("btn-new").addEventListener("click", () => {
    if (location.hash === "#/new") route();
    else location.hash = "#/new";
  });
  $("empty-new").addEventListener("click", () => {
    if (location.hash === "#/new") route();
    else location.hash = "#/new";
  });
  $("empty-inbox").addEventListener("click", () => {
    if (location.hash === "#/inbox") route();
    else location.hash = "#/inbox";
  });
  $("empty-missions").addEventListener("click", (e) => {
    if (matchMedia("(max-width: 699px)").matches) {
      setDrawer("right", false);
      nextOpener = e.currentTarget;
      setDrawer("left", true);
    } else {
      const target = $("sessions").querySelector("a.row") || $("btn-new");
      if (target) target.focus({ preventScroll: true });
    }
  });
  $("keys-live").addEventListener("click", dismissToast);
  $("show-archived").addEventListener("change", (e) => {
    S.showArchived = e.target.checked;
    want("list");
  });
  $("open-left").addEventListener("click", (e) => { setDrawer("right", false); nextOpener = e.currentTarget; setDrawer("left", true); });
  $("close-left").addEventListener("click", () => setDrawer("left", false));
  const inspector = (e) => { setDrawer("left", false); nextOpener = e.currentTarget; setDrawer("right", !document.body.classList.contains("show-right")); };
  $("open-right").addEventListener("click", inspector);
  $("toggle-inspector").addEventListener("click", inspector);
  $("close-right").addEventListener("click", () => setDrawer("right", false));
  $("scrim").addEventListener("click", () => { setDrawer("left", false); setDrawer("right", false); });
  $("notice-close").addEventListener("click", () => {
    $("notice").hidden = true;
  });
  const tabs = [...document.querySelectorAll("#tabs .tab")];
  for (const b of tabs) {
    b.addEventListener("click", () => setTab(b.dataset.tab));
    b.addEventListener("keydown", e => tabKeys(e, tabs, tab => setTab(tab.dataset.tab)));
  }
  $("mission-agents").addEventListener("keydown", agentsKeys);
  $("mission-agents").addEventListener("focusin", (e) => {
    const main = e.target.closest && e.target.closest(".agent-main");
    if (!main) return;
    const rows = [...$("mission-agents").querySelectorAll(".agent-main")];
    const at = rows.indexOf(main);
    rows.forEach((r, i) => {
      r.tabIndex = i === at ? 0 : -1;
      const spawn = r.parentElement.querySelector(".agent-spawn");
      if (spawn) spawn.tabIndex = i === at ? 0 : -1;
    });
    S.agentsActive = main.parentElement.dataset.agent;
  });
  // Events never fetch the scores: this is the one clock, and scoreDue keeps it to once in two minutes.
  setInterval(() => { if (S.view === "session" && S.section === "agents" && !document.hidden) loadScore(false); }, 15000);
  const missionTabs = [...document.querySelectorAll("#mission-tabs [data-view]")];
  for (const b of missionTabs) {
    b.addEventListener("click", () => setSection(b.dataset.view));
    b.addEventListener("keydown", e => tabKeys(e, missionTabs, tab => setSection(tab.dataset.view)));
  }

  const onScroll = (e) => {
    const s = chatScroller();
    if (e.currentTarget !== s || S.jumping || S.section !== "chat") return;
    const was = S.follow;
    S.follow = C.atEnd(s.scrollTop, s.clientHeight, s.scrollHeight);
    if (!S.follow && was) pinOpenGroups();
    else if (S.follow && !was) S.openGroups.clear();
    updateJump();
    if (S.follow && !was) want("blocks");
  };
  $("scroller").addEventListener("scroll", onScroll);
  $("view-session").addEventListener("scroll", onScroll);
  const layoutChanged = () => { if (S.view === "session") want("blocks", "header"); };
  COMPACT.addEventListener("change", layoutChanged);
  COARSE.addEventListener("change", layoutChanged);
  PHONE.addEventListener("change", layoutChanged);
  $("jump").addEventListener("click", () => {
    const need = S.jumpNeed;
    if (need) { jumpToRecord(need.seq, { focus: true }); return; }
    S.follow = true;
    S.openGroups.clear();
    want("blocks");
  });
  $("btn-earlier").addEventListener("click", showEarlier);
  $("details").addEventListener("change", (e) => {
    S.details = e.target.checked;
    $("blocks").classList.toggle("hide-details", !S.details);
    syncChat();
  });
  $("expand-work").addEventListener("change", (e) => {
    S.expandAll = e.target.checked;
    syncChat();
  });

  // The composer's height, for what has to sit above it when it overlays the page (the jump button on a phone).
  if (typeof ResizeObserver === "function") {
    new ResizeObserver(() => document.body.style.setProperty("--composer-h", Math.round($("composer").getBoundingClientRect().height) + "px")).observe($("composer"));
    new ResizeObserver(() => document.body.style.setProperty("--find-h", Math.round($("find-bar").getBoundingClientRect().height) + "px")).observe($("find-bar"));
    new ResizeObserver(() => document.body.style.setProperty("--tabs-h", Math.round($("mission-tabs").getBoundingClientRect().height) + "px")).observe($("mission-tabs"));
  }
  $("composer-go").addEventListener("click", () => { setSection("chat"); requestAnimationFrame(() => $("msg").focus()); });
  $("s-id").addEventListener("click", copySessionId);
  $("s-goal-toggle").addEventListener("click", () => { S.goalOpen = !S.goalOpen; renderHeader(); });
  $("b-rename").addEventListener("click", renameSession);
  $("b-rename").title = "Rename this mission.";
  $("b-stop").addEventListener("click", (e) => askHeaderConfirm("stop", S.sessions.byId.get(S.openId), e.currentTarget));
  $("c-stop").addEventListener("click", (e) => askHeaderConfirm("stop", S.sessions.byId.get(S.openId), e.currentTarget));
  $("b-stop").title = "Stop this session and cancel its descendant agents and tracked jobs.";
  $("b-resume").addEventListener("click", () => sessionAction("resume"));
  $("b-archive").addEventListener("click", (e) => askHeaderConfirm("archive", S.sessions.byId.get(S.openId), e.currentTarget));
  $("b-unarchive").addEventListener("click", () => sessionAction("archive", { archived: false }));
  noRepeat($("shead-confirm-yes"));
  $("shead-confirm-yes").addEventListener("click", () => {
    const ask = S.headAsk;
    if (!ask || ask.session !== S.openId) { hideHeadConfirm(); return; }
    hideHeadConfirm();
    if (ask.kind === "stop") sessionAction("stop");
    else if (ask.kind === "archive") sessionAction("archive", { archived: true });
  });
  $("shead-confirm-cancel").addEventListener("click", () => cancelHeadConfirm());
  $("shead-confirm").addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); cancelHeadConfirm(); }
  });
  $("agent-go-lead").addEventListener("click", () => {
    const id = $("agent-go-lead").dataset.lead;
    if (!id) return;
    const hash = C.sessionHash(id);
    if (location.hash === hash) route(); else location.hash = hash;
    rescueFocus();
  });
  $("child-blocker-go").addEventListener("click", () => {
    const hit = S.childBlocker;
    const id = hit && (hit.item?.session || hit.session?.id);
    if (!id) return;
    const hash = C.sessionHash(id);
    if (location.hash === hash) route(); else location.hash = hash;
    rescueFocus();
  });

  $("model-seat").addEventListener("change", (e) => {
    const info = S.sessions.byId.get(S.openId);
    if (!info) return;
    const current = C.currentModel(S.rec, info);
    S.seatNote.delete(info.id);
    S.seat = e.target.value && e.target.value !== (current && current.profile) ? { session: info.id, profile: e.target.value } : null;
    renderHeader();
  });
  $("model-confirm-yes").addEventListener("click", applySeat);
  $("model-confirm-no").addEventListener("click", cancelSeat);
  if (!MAC) $("f-message-note").textContent = "Ctrl+Enter starts the mission.";
  // ⌘Enter (Ctrl+Enter elsewhere) starts the mission from the message box; Enter alone adds a line.
  $("f-message").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && !e.isComposing) { e.preventDefault(); $("new-form").requestSubmit(); }
  });
  $("composer").addEventListener("keydown", (e) => { if (e.key === "Escape" && S.seat && !S.seatBusy.has(S.seat.session)) { e.preventDefault(); cancelSeat(); } });
  const msg = $("msg");
  msg.addEventListener("input", () => { if (S.openId) C.setDraft(S.drafts, "message:" + S.openId, msg.value); renderHeader(); });
  $("send").addEventListener("click", () => sendMessage("now"));
  $("send-more").addEventListener("click", () => ($("send-menu").hidden ? openSendMenu() : closeSendMenu(true)));
  for (const choice of C.SEND_CHOICES) {
    const item = $("send-menu").querySelector(`[data-when="${choice.when}"]`);
    item.textContent = choice.label;
    item.addEventListener("click", () => { closeSendMenu(); sendMessage(choice.when); });
  }
  $("send-menu").addEventListener("keydown", (e) => {
    const items = [...$("send-menu").querySelectorAll("button")];
    const at = items.indexOf(document.activeElement);
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeSendMenu(true); }
    else if (e.key === "ArrowDown") { e.preventDefault(); items[(at + 1) % items.length].focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(at + items.length - 1) % items.length].focus(); }
    else if (e.key === "Tab") closeSendMenu();
  });
  document.addEventListener("click", (e) => { if (!$("send-menu").hidden && !e.target.closest("#send-group")) closeSendMenu(); });
  $("imgview-close").addEventListener("click", closeImage);
  $("imgview-copy").addEventListener("click", async () => {
    const path = $("imgview-copy").dataset.path;
    await copyText(path, { label: "Path" });
  });
  $("imgview").addEventListener("close", () => { const o = imageOpener; imageOpener = null; if (o && document.contains(o)) o.focus({ preventScroll: true }); $("imgview-img").removeAttribute("src"); });
  $("imgview").addEventListener("click", (e) => { if (e.target === $("imgview")) closeImage(); });
  wireAttach(attachCtx.composer, {
    button: "attach-btn", input: "attach-file", drops: ["composer", "scroller"], paste: "msg",
    canDrop: () => !$("attach-btn").hidden && !$("msg").disabled,
  });
  wireAttach(attachCtx.start, { button: "f-attach", input: "f-file", drops: ["new-form"], paste: "f-message" });
  msg.addEventListener("keydown", (e) => {
    const info = S.sessions.byId.get(S.openId);
    const act = C.composerAction({ key: e.key, shiftKey: e.shiftKey, isComposing: e.isComposing, text: msg.value || (attachState("message:" + S.openId).paths.length ? "attached" : ""), coarse: COARSE.matches, mod: e.ctrlKey || e.metaKey, alt: e.altKey, running: !!info && C.sessionActions(info).running && C.rootNoun(info) === "lead" });
    if (act !== "none") {
      e.preventDefault();
      if (act !== "ignore") sendMessage(act === "queue" ? "after_turn" : "now");
    }
  });

  $("new-form").addEventListener("submit", submitNew);
  $("f-model").addEventListener("change", (e) => { S.newForm.model = e.target.value; });
  $("f-agent-model").addEventListener("change", (e) => { S.newForm.agentModel = e.target.value; });
  $("f-workspace").addEventListener("input", () => { workspaceNote(); hideCreateAsk(); });
  $("f-browse").addEventListener("click", (e) => openPicker(e.currentTarget));
  $("f-create-yes").addEventListener("click", () => submitNew(null, true));
  noRepeat($("f-create-yes"));
  $("f-create-no").addEventListener("click", () => { hideCreateAsk(); $("f-workspace").focus(); });
  $("f-create").addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); hideCreateAsk(); $("f-workspace").focus(); } });
  $("b-files").addEventListener("click", (e) => showFiles(e.currentTarget));
  $("picker").addEventListener("click", (e) => { if (e.target === $("picker")) closePicker(); });
  $("picker-close").addEventListener("click", () => closePicker());
  $("picker-cancel").addEventListener("click", () => closePicker());
  $("picker").addEventListener("cancel", (e) => { e.preventDefault(); if (PK.naming) pickerNaming(false); else closePicker(); });
  $("picker-filter").addEventListener("input", (e) => { PK.query = e.target.value; renderPicker(); });
  $("picker-filter").addEventListener("keydown", (e) => {
    if (e.key === "Escape" && $("picker-filter").value) {
      e.preventDefault();
      e.stopPropagation();
      $("picker-filter").value = "";
      PK.query = "";
      renderPicker();
    } else if (e.key === "ArrowDown") {
      const row = $("picker-list").querySelector('[tabindex="0"], .dir-row');
      if (row) { e.preventDefault(); row.focus({ preventScroll: true }); }
    }
  });
  $("picker-up").addEventListener("click", pickerUp);
  $("picker-home").addEventListener("click", () => pickerLoad("", { focus: true }));
  $("picker-hidden").addEventListener("change", (e) => { PK.showHidden = e.target.checked; renderPicker(); });
  $("picker-new").addEventListener("click", () => pickerNaming(!PK.naming));
  $("picker-newok").addEventListener("click", pickerAcceptName);
  $("picker-newcancel").addEventListener("click", () => pickerNaming(false));
  $("picker-newname").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); pickerAcceptName(); }
    else if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); pickerNaming(false); }
  });
  $("picker-list").addEventListener("keydown", pickerListKeys);
$("picker").addEventListener("keydown", pickerEmptyKeys);
  $("picker-use").addEventListener("click", usePicker);
  // Coming back to the page is opening what it shows: the notifications about it are withdrawn.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") closeNotes(S.view === "inbox" ? { inbox: true } : S.view === "session" ? { session: S.openId } : {});
  });
  $("notif-btn").addEventListener("click", async () => {
    try {
      await Notification.requestPermission();
    } catch {
      // refused or unsupported; the view says "off"
    }
    renderInbox();
  });
  $("viewer").addEventListener("click", (e) => { if (e.target === $("viewer")) closeViewer(); });
  $("viewer-close").addEventListener("click", closeViewer);
  $("viewer").addEventListener("cancel", e => { e.preventDefault(); closeViewer(); });
  $("viewer-jump").addEventListener("click", viewerJump);
  $("viewer-find-next").addEventListener("click", () => viewerFind(1));
  $("viewer-find-prev").addEventListener("click", () => viewerFind(-1));
  $("viewer-copy").addEventListener("click", copyViewerReference);
  $("viewer-copy-lines").addEventListener("click", copyViewerLines);
  // Pressing these must not collapse the selection in the lines, which Copy lines reads.
  for (const id of ["viewer-copy", "viewer-copy-lines"]) $(id).addEventListener("mousedown", (e) => e.preventDefault());
  S.copyOnSelect = storedCopyOnSelect();
  document.addEventListener("mouseup", copySelection);
  document.addEventListener("keyup", copySelection);
  // Two fields share the dialog, so the browser submits neither on Enter: each handles its own.
  $("viewer-start").addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); viewerJump(); }
  });
  $("viewer-find").addEventListener("keydown", e => {
    if (e.key === "Enter" && !e.isComposing) { e.preventDefault(); viewerFind(e.shiftKey ? -1 : 1); }
  });
  $("viewer-find").addEventListener("input", () => { if (!$("viewer-find").value) viewerFind(1); });
  $("viewer-more").addEventListener("click", () => viewerPage(1));
  $("viewer-earlier").addEventListener("click", () => viewerPage(-1));
  window.addEventListener("hashchange", route);
  window.addEventListener("pagehide", saveSeen);
  window.addEventListener("resize", () => {
    if (S.view === "session") want("header");
    renderDot();
    setDrawer("left", document.body.classList.contains("show-left"));
    setDrawer("right", document.body.classList.contains("show-right"));
  });
  const resize = $("inspector-resize");
  resize.addEventListener("keydown", e => {
    const current = Number(resize.getAttribute("aria-valuenow"));
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") { e.preventDefault(); resizeInspector(current + (e.key === "ArrowLeft" ? 16 : -16)); }
    if (e.key === "Home" || e.key === "End") { e.preventDefault(); resizeInspector(e.key === "Home" ? 280 : 560); }
  });
  resize.addEventListener("pointerdown", e => {
    if (e.button !== 0) return;
    e.preventDefault();
    const move = event => resizeInspector(innerWidth - event.clientX);
    const done = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", done); window.removeEventListener("pointercancel", done); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", done);
    window.addEventListener("pointercancel", done);
  });
  document.addEventListener("keydown", (e) => {
    if (document.querySelector("dialog[open]")) return;
    const side = matchMedia("(max-width: 1099px)").matches && document.body.classList.contains("show-right") ? "right"
      : matchMedia("(max-width: 699px)").matches && document.body.classList.contains("show-left") ? "left" : null;
    if (e.key === "Escape" && side) { e.preventDefault(); setDrawer(side, false); return; }
    if (e.key === "Escape" && !side && !e.defaultPrevented && S.view === "session") {
      if (!$("shead-confirm").hidden) { e.preventDefault(); cancelHeadConfirm(); return; }
      if (!$("find-bar").hidden) { e.preventDefault(); closeFind(); return; }
    }
    if (e.key === "Tab" && side) {
      const focusable = [...$(side).querySelectorAll("button:not([disabled]):not([tabindex='-1']), a:not([tabindex='-1']), input:not([disabled]):not([tabindex='-1']), textarea:not([disabled]):not([tabindex='-1']), select:not([disabled]):not([tabindex='-1']), summary:not([tabindex='-1']), [tabindex='0']")].filter(n => n.getClientRects().length);
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (!first) return;
      if (e.shiftKey && (document.activeElement === first || !$(side).contains(document.activeElement))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (document.activeElement === last || !$(side).contains(document.activeElement))) { e.preventDefault(); first.focus(); }
    }
  });
}

async function start() {
  // A login address opened in a tab that already has the page changes only the fragment: load the
  // page again, so that the code is exchanged and leaves the address bar. Also on the lost() page.
  window.addEventListener("hashchange", () => {
    if (C.codeFromHash(location.hash)) location.reload();
  });
  if (!(await signIn())) {
    lost();
    return;
  }
  wire();
  setTab("ledger");
  setSection("chat", false);
  setDrawer("left", false);
  setDrawer("right", false);
  resizeInspector(Number(recalled("inspector-width", 396)) || 396);
  renderDot();
  connect();
  await Promise.all([loadSessions(), loadInbox(), loadStatus()]);
  route();
  setInterval(() => {
    S.now = Date.now();
    for (const time of document.querySelectorAll("time[data-opened]")) time.textContent = ago(Number(time.dataset.opened));
    renderDot();
    want("list", "header", "overview");
  }, 30000);
  setInterval(loadStatus, 60000);
  // The inbox is also read again on a timer, so a missed record cannot leave an item standing or missing.
  setInterval(loadInbox, 60000);
}

start();
