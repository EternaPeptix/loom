// app.js: the DOM and the network. Every decision that can be wrong lives in core.js.
// Text from records, tools and the network is only ever put into the page with textContent or
// text nodes. Prose formatting creates a small set of semantic elements; source HTML stays inert.

import * as C from "./core.js";

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------------------------
// State

const S = {
  sessions: C.createSessionStore(),
  inbox: C.createInbox(),
  status: null,
  connected: false,
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
  requests: { ledger: 0, window: 0, net: 0, inbox: 0, sessions: 0, status: 0 },
  inboxRevision: 0,
  sessionsRevision: 0,
  sinceSeq: null,
  section: "overview",
  view: "empty", // empty | session | inbox | new
  openId: null,
  rec: null, // record store of the open session
  r: null, // what is rendered of it: {from, end, nodes, fresh}
  follow: true,
  tab: "ledger",
  ledger: { mission: null, model: null, state: null, error: null, stale: true },
  win: { data: null, error: null, stale: true, hideFolded: false, from: null },
  net: [],
  netError: null,
  viewer: null,
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

const MARKS = { running: "●", waiting: "◔", needs_you: "◆", result_ready: "◇", question: "?", stopped: "■", finished: "✓", failed: "✕", idle: "○" };
function markEl(mark) {
  const m = el("span", "mark mark-" + mark, MARKS[mark] || "?");
  m.title = C.markWords(mark);
  return m;
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
  render();
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

function prose(text) {
  const root = el("div", "prose");
  const lines = String(text).split("\n");
  let paragraph = [], list = null, code = null;
  const inline = (target, value) => {
    const re = /(\*\*[^*\n]+\*\*|`[^`\n]+`)/g;
    let from = 0;
    for (const match of value.matchAll(re)) {
      target.append(document.createTextNode(value.slice(from, match.index)));
      const bold = match[0].startsWith("**");
      target.append(el(bold ? "strong" : "code", "", match[0].slice(bold ? 2 : 1, bold ? -2 : -1)));
      from = match.index + match[0].length;
    }
    target.append(document.createTextNode(value.slice(from)));
  };
  const flush = () => {
    if (paragraph.length) { const p = el("p"); inline(p, paragraph.join("\n")); root.append(p); paragraph = []; }
  };
  for (const line of lines) {
    if (/^\s*```/.test(line)) {
      flush(); list = null;
      if (code) code = null;
      else { code = el("code"); root.append(add(el("pre", "out"), code)); }
    } else if (code) code.append(document.createTextNode((code.textContent ? "\n" : "") + line));
    else if (/^#{1,6}\s+/.test(line)) {
      flush(); list = null; const h = el("h3"); inline(h, line.replace(/^#{1,6}\s+/, "")); root.append(h);
    } else if (/^\s*(?:[-*+]\s+|\d+[.)]\s+)/.test(line)) {
      flush(); const ordered = /^\s*\d/.test(line);
      if (!list || list.tagName !== (ordered ? "OL" : "UL")) { list = el(ordered ? "ol" : "ul"); root.append(list); }
      const item = el("li"); inline(item, line.replace(/^\s*(?:[-*+]\s+|\d+[.)]\s+)/, "")); list.append(item);
    } else if (!line.trim()) { flush(); list = null; }
    else { list = null; paragraph.push(line); }
  }
  flush();
  return root;
}

// ---------------------------------------------------------------------------------------------
// Network

let es = null;

function lost() {
  if (es) es.close();
  document.body.replaceChildren(el("p", "pad", C.LOST_TOKEN));
}

async function api(method, path, body) {
  const init = { method, credentials: "same-origin", headers: {} };
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

const needs = { list: false, header: false, blocks: false, live: false, right: false, overview: false };
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
}

// ---------------------------------------------------------------------------------------------
// Left column

function inboxCount(id) {
  return C.attentionFor(S.inbox, id);
}

function renderList() {
  const box = $("sessions");
  const groups = C.missionGroups(S.sessions, S.inbox, { showArchived: S.showArchived, expanded: S.expanded });
  const frag = document.createDocumentFragment();
  for (const group of groups) {
    if (!group.rows.length) continue;
    const section = el("section", "mission-group");
    section.setAttribute("aria-label", group.label);
    section.append(el("h2", "group-title", group.label));
    for (const { info, depth, agentCount, expanded, attention } of group.rows) {
      const mark = C.stateMark(info, attention || inboxCount(info.id));
      const wrap = el("div", "mission-row");
      const a = el("a", `row d${Math.min(depth, 2)}${mark === "needs_you" ? " needs" : ""}${info.id === S.openId && S.view === "session" ? " sel" : ""}${info.archived ? " arch" : ""}`);
      a.setAttribute("href", C.sessionHash(info.id));
      a.dataset.focusKey = "session:" + info.id;
      if (info.id === S.openId) a.setAttribute("aria-current", "page");
      const t = el("div", "t");
      add(t, markEl(mark), el("span", "name", info.title || info.id));
      const last = S.latest.get(info.id);
      add(a, t, el("div", "sub", C.rowActivity(info, last, S.now)));
      a.title = info.title || info.id;
      wrap.append(a);
      if (!depth && agentCount) {
        const toggle = btn(`${expanded ? "▾" : "▸"} ${agentCount} ${agentCount === 1 ? "agent" : "agents"}`, "link agent-toggle", () => {
          if (S.expanded.has(info.id)) S.expanded.delete(info.id); else S.expanded.add(info.id);
          want("list");
        });
        toggle.setAttribute("aria-expanded", String(expanded));
        toggle.setAttribute("aria-label", `${expanded ? "Collapse" : "Expand"} agents of ${info.title || info.id}`);
        toggle.dataset.focusKey = "agents:" + info.id;
        wrap.append(toggle);
      }
      section.append(wrap);
    }
    frag.append(section);
  }
  if (!frag.childNodes.length) frag.append(el("p", "dim pad", "No missions yet. Start a mission with New."));
  preserveFocus(box, () => box.replaceChildren(frag));
}

function renderDot() {
  const d = C.healthDot({ connected: S.connected, models: (S.status && S.status.models) || [] });
  const dot = $("dot");
  dot.className = "dot dot-" + d.state;
  dot.title = d.tip;
  const state = $("connection-state");
  const updated = $("connection-updated");
  if (state) state.textContent = S.connected ? (S.statusError ? "Live events · model status unavailable" : d.state === "amber" ? "Live · model unavailable" : "Live") : "Reconnecting · execution state unknown";
  if (updated) updated.textContent = S.lastUpdate ? `Last update ${ago(S.lastUpdate)}` : "Waiting for first update";
}

function updateInboxBadge() {
  const c = C.inboxCounts(S.inbox);
  const b = $("btn-inbox");
  const n = $("inbox-count");
  n.textContent = String(c.open);
  n.hidden = c.open === 0;
  b.classList.toggle("urgent", c.blocking > 0);
  document.title = C.pageTitle(c);
  if (S.view === "inbox") renderInbox();
  want("list", "header", "overview");
}

// ---------------------------------------------------------------------------------------------
// Navigation

function route() {
  const r = C.parseRoute(location.hash);
  setDrawer("left", false);
  if (r.view === "session") { setSection(r.section, false); return openSession(r.session); }
  if (r.view === "inbox") return showInbox();
  if (r.view === "new") return showNew();
  setView(S.openId ? "session" : "empty");
}

function setView(v) {
  if (S.view === "session" && v !== "session") saveSeen();
  S.view = v;
  $("view-empty").hidden = v !== "empty";
  $("view-session").hidden = v !== "session";
  $("view-inbox").hidden = v !== "inbox";
  $("view-new").hidden = v !== "new";
  want("list");
}

function openSession(id) {
  if (S.openId === id && S.rec) {
    if (S.view !== "session") S.sinceSeq = recalled("seen." + id, null);
    setView("session");
    want("header", "blocks", "right", "overview");
    return;
  }
  saveSeen();
  S.openId = id;
  let ancestor = S.sessions.byId.get(id)?.parent;
  const walked = new Set();
  while (ancestor && !walked.has(ancestor)) { walked.add(ancestor); S.expanded.add(ancestor); ancestor = S.sessions.byId.get(ancestor)?.parent; }
  S.sinceSeq = recalled("seen." + id, null);
  S.rec = C.createRecordStore(id);
  S.rec.initialComplete = false;
  S.r = { from: 0, end: 0, nodes: new Map(), fresh: true };
  S.follow = true;
  S.net = [];
  S.netError = null;
  S.liveEl = null;
  S.win = { ...S.win, data: null, error: null, stale: true, from: null };
  S.ledger = { mission: null, model: null, state: null, error: null, stale: true };
  const opened = S.sessions.byId.get(id);
  S.ledger.mission = opened ? opened.mission : null;
  clear($("blocks"));
  clear($("live"));
  $("loading").hidden = false;
  $("earlier").hidden = true;
  setView("session");
  clear($("mission-overview"));
  clear($("mission-evidence"));
  $("msg").value = C.getDraft(S.drafts, "message:" + id);
  $("msg").dataset.draftKey = "message:" + id;
  want("header", "blocks", "live", "right", "overview");
  loadRecords(S.rec, 0);
  loadNet();
  loadLedger();
  if (S.tab !== "ledger") loadTab();
}

async function loadRecords(store, tries) {
  if (store.loading) return;
  store.loading = true;
  try {
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

function saveSeen() {
  if (S.openId && S.rec && !S.rec.loading && C.lastSeq(S.rec) !== null) remember("seen." + S.openId, C.lastSeq(S.rec));
}

function noteActivity(session, record) {
  if (!C.recordActivity(record)) return;
  const last = S.latest.get(session);
  if (!last || record.seq >= last.seq) S.latest.set(session, record);
}

function setSection(section, navigate = true) {
  S.section = ["overview", "record", "evidence"].includes(section) ? section : "overview";
  for (const tab of document.querySelectorAll("#mission-tabs [data-view]")) {
    const selected = tab.dataset.view === S.section;
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  }
  for (const name of ["overview", "record", "evidence"]) $("mission-" + name).hidden = name !== S.section;
  $("jump").hidden = S.section !== "record" || S.follow;
  if (navigate && S.openId) location.hash = C.sessionHash(S.openId, S.section);
  if (S.section === "record") want("blocks", "live");
  if (S.section === "evidence" && S.ledger.stale) loadLedger();
  want("overview");
}

// ---------------------------------------------------------------------------------------------
// Event stream

function ctx() {
  return {
    openId: S.openId,
    ledgerMission: S.ledger.mission,
    known: (id) => S.sessions.byId.has(id),
    missionOf: (id) => (S.sessions.byId.get(id) || {}).mission || null,
  };
}

function handleEvent(ev) {
  S.lastUpdate = Date.now();
  if (ev.type === "record" && ev.record) noteActivity(ev.session, ev.record);
  for (const f of C.planEvent(ev, ctx())) {
    switch (f.fx) {
      case "session":
        S.sessionsRevision++;
        C.applySessionEvent(S.sessions, f.info);
        want("list", "header", "overview");
        break;
      case "status":
        S.sessionsRevision++;
        C.applyStatus(S.sessions, f.session, f.status);
        want("list", "header", "overview");
        break;
      case "header":
        want("header");
        break;
      case "refetch_sessions":
        loadSessions();
        break;
      case "refetch_inbox":
        loadInbox();
        break;
      case "refetch_records":
        if (S.rec) loadRecords(S.rec, 0);
        break;
      case "inbox_record": {
        S.inboxRevision++;
        const res = C.applyInboxRecord(S.inbox, f.session, f.record, (id) => S.sessions.byId.get(id));
        if (res === "opened") announce(S.inbox.items.get(f.record.item_id));
        updateInboxBadge();
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
        if (S.tab === "context") loadWindow();
        break;
      case "refetch_ledger":
        S.ledger.stale = true;
        if (S.tab === "ledger" || S.section !== "record") loadLedger();
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

function connect() {
  es = new EventSource("/api/events?deltas=true");
  es.addEventListener("open", () => {
    const again = S.everConnected;
    S.connected = true;
    S.everConnected = true;
    S.lastUpdate = Date.now();
    renderDot();
    if (again) refetchAll();
  });
  es.addEventListener("message", (m) => {
    let ev;
    try {
      ev = JSON.parse(m.data);
    } catch {
      return;
    }
    handleEvent(ev);
  });
  es.addEventListener("error", () => {
    S.connected = false;
    renderDot();
    if (es.readyState === 2) {
      // The browser gave up; the likely reason is a missing token.
      fetch("/api/status", { credentials: "same-origin" }).then((r) => {
        if (r.status === 401) lost();
        else setTimeout(connect, 3000);
      }).catch(() => setTimeout(connect, 3000));
    }
  });
}

function refetchAll() {
  loadSessions();
  loadInbox();
  loadStatus();
  if (S.rec) loadRecords(S.rec, 0);
}

async function loadSessions() {
  const request = ++S.requests.sessions;
  const revision = S.sessionsRevision;
  try {
    const sessions = await api("GET", "/api/sessions?archived=true");
    if (request !== S.requests.sessions) return;
    if (revision !== S.sessionsRevision) return loadSessions();
    C.applySessionList(S.sessions, sessions);
    S.lastUpdate = Date.now();
    want("list", "header", "overview");
  } catch (e) {
    if (request === S.requests.sessions) notice(e.message);
  }
}
async function loadInbox() {
  const request = ++S.requests.inbox;
  const revision = S.inboxRevision;
  try {
    const inbox = await api("GET", "/api/inbox");
    if (request !== S.requests.inbox) return;
    if (revision !== S.inboxRevision) return loadInbox();
    C.applyInboxList(S.inbox, inbox);
    S.lastUpdate = Date.now();
    updateInboxBadge();
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
function announce(entry) {
  if (!entry || !entry.item.blocking) return;
  if (!notificationsAvailable() || Notification.permission !== "granted") return;
  try {
    const n = C.notificationFor(entry);
    const note = new Notification(n.title, { body: n.body, tag: n.tag });
    note.addEventListener("click", () => {
      window.focus();
      location.hash = "#/inbox";
    });
  } catch {
    // some browsers refuse outside a user gesture; the badge and title still show it
  }
}

// ---------------------------------------------------------------------------------------------
// Session header

function renderHeader() {
  const info = S.sessions.byId.get(S.openId);
  if (!info) {
    $("s-title").textContent = S.openId || "";
    return;
  }
  const mark = C.stateMark(info, inboxCount(info.id));
  $("s-title").textContent = info.title || info.id;
  $("s-title").title = info.id;
  $("s-goal").textContent = S.ledger.state?.goal || (info.parent ? "Agent assignment · messages go to the mission lead." : "Mission goal has not been recorded yet.");
  const currentStep = S.ledger.state?.plan?.find(step => step.status === "doing");
  $("s-activity").textContent = currentStep ? "Current step: " + currentStep.text : C.rowActivity(info, S.latest.get(info.id), S.now);
  const m = $("s-mark");
  m.className = "mark mark-" + mark;
  m.textContent = MARKS[mark];
  let standing = C.markWords(mark);
  if (mark === "needs_you") {
    const phase = info.status?.phase === "running" ? "running" : info.status?.last_end === "stopped" ? "stopped" : info.status?.last_end === "waiting" ? "waiting" : "idle";
    standing = `Needs your answer · ${info.parent ? "agent" : "lead"} ${phase}`;
  }
  if (!info.parent) {
    const working = [...S.sessions.byId.values()].filter(child => child.mission === info.mission && child.parent && child.status?.phase === "running").length;
    if (working) standing += ` · ${working} ${working === 1 ? "agent" : "agents"} running`;
  }
  $("s-words").textContent = standing;
  $("s-step").textContent = `step ${(info.status && info.status.step) || 0}`;
  const meter = C.statusMeter(info);
  $("s-meter").firstElementChild.style.setProperty("width", meter.inViewPct + "%");
  $("s-meter-label").textContent = meter.label;
  const a = C.sessionActions(info);
  $("b-stop").hidden = !a.stop;
  $("b-resume").hidden = !a.resume;
  $("b-archive").hidden = !a.archive;
  $("b-unarchive").hidden = !a.unarchive;
  $("composer-row").hidden = !a.send;
  $("agent-note").hidden = !info.parent;
  const closed = $("closed-note");
  closed.hidden = !!info.parent || a.send;
  closed.textContent = info.archived ? "This session is archived; unarchive it to send messages." : "This session has ended.";
  $("send").textContent = a.running ? "Send (delivered between steps)" : "Send";
  let action = S.actionState.get(info.id);
  if (action?.accepted && ((action.name === "stop" && !a.stop) || (action.name === "resume" && a.running) || (action.name === "archive" && info.archived === action.archived))) {
    S.actionState.delete(info.id); action = null;
  }
  for (const [id, label, name] of [["b-stop", "Stop", "stop"], ["b-resume", "Resume", "resume"], ["b-archive", "Archive", "archive"], ["b-unarchive", "Unarchive", "archive"]]) {
    const button = $(id);
    button.disabled = !!action;
    button.textContent = action?.name === name ? action.label : label;
  }
  $("composer-recipient").textContent = `Message to: ${info.title || info.id}`;
  const sending = S.sending.has(info.id);
  const message = S.messageState.get(info.id);
  const pendingReceipt = message?.accepted && message.recordedSeq === undefined && message.state !== "failed";
  $("msg").disabled = sending;
  $("send").disabled = sending || pendingReceipt || !S.rec?.initialComplete || !$("msg").value.trim();
  if (sending) $("send").textContent = "Sending…";
  else if (pendingReceipt) $("send").textContent = "Awaiting receipt…";
  $("send-state").textContent = message?.text || (!S.rec?.initialComplete ? "Loading the record before messages can be sent." : "");
}

function missionEntries() {
  const info = S.sessions.byId.get(S.openId);
  return [...S.inbox.items.values()].filter(e => e.mission === info?.mission || e.session === S.openId);
}

function renderOverview() {
  if (S.view !== "session" || !S.rec) return;
  const panel = $("mission-overview");
  if (!panel.firstElementChild) {
    panel.append(el("div", "overview-decisions"), el("section", "overview-section overview-plan"), el("section", "overview-section overview-changes"));
  }
  const entries = missionEntries();
  const model = C.missionOverview(S.rec.records.values(), S.ledger.state, entries, S.sinceSeq);
  reconcileInbox(panel.querySelector(".overview-decisions"), entries.filter(e => e.item.item_kind !== "finished"), "overview");
  const plan = panel.querySelector(".overview-plan");
  const body = document.createDocumentFragment();
  body.append(el("h2", "section-heading", "Current plan"));
  if (S.rec.error) {
    body.append(el("p", "error", "The record could not be loaded: " + S.rec.error));
    const retry = btn("Retry loading the record", "", () => loadRecords(S.rec, 0));
    retry.dataset.focusKey = "retry-record"; body.append(retry);
  }
  if (S.ledger.error) body.append(el("p", "error", "Mission state could not be refreshed: " + S.ledger.error));
  if (S.ledger.stale && S.ledger.state) body.append(el("p", "warn", "Showing the last recorded mission state; refreshing…"));
  const steps = S.ledger.state?.plan || [];
  if (!steps.length) body.append(el("p", "dim", S.ledger.model ? "The lead has not recorded a plan yet." : "Loading mission state…"));
  for (const step of steps) {
    const row = el("div", "plan-step");
    const mark = el("span", "mark", C.stepMark(step.status));
    mark.setAttribute("aria-label", step.status);
    const content = el("div");
    add(content, el("div", "", step.text), step.note ? el("p", "dim", step.note) : null);
    row.append(mark, content); body.append(row);
  }
  if (S.ledger.state) {
    const outstanding = el("p", "dim", `${model.counts.claimsOpen} open claims · ${model.counts.openObligations} open obligations`);
    body.append(outstanding);
    const inspect = btn("Review claims and evidence", "link", () => setSection("evidence"));
    inspect.dataset.focusKey = "overview-evidence";
    body.append(inspect);
  }
  preserveFocus(plan, () => plan.replaceChildren(body));
  const changes = panel.querySelector(".overview-changes");
  const history = document.createDocumentFragment();
  history.append(el("h2", "section-heading", S.sinceSeq === null ? "Recent recorded activity" : "Since your last visit"));
  if (S.rec.loading) history.append(el("p", "dim", "Loading the record…"));
  else if (!model.changes.length) history.append(el("p", "dim", S.sinceSeq === null ? "No activity has been recorded yet." : "No new activity has been recorded since your last visit."));
  for (const change of model.changes.slice(-10).reverse()) {
    const row = el("div", "change-item");
    const when = el("time", "dim", change.ts ? ago(change.ts) : "");
    if (change.ts) when.dateTime = new Date(change.ts).toISOString();
    const jump = btn(change.text, "link", () => jumpToRecord(change.seq));
    jump.dataset.focusKey = "change:" + change.seq;
    add(row, when, jump); history.append(row);
  }
  history.append(el("p", "dim", "Activity is derived from recorded events. Completed steps and matching quotes do not by themselves establish a claim."));
  preserveFocus(changes, () => changes.replaceChildren(history));
  if (S.section === "evidence") renderEvidence($("mission-evidence"));
}

function jumpToRecord(seq) {
  setSection("record");
  requestAnimationFrame(() => {
    const block = S.rec?.blocks.find(b => b.seq === seq || b.result?.seq === seq || b.resolved?.seq === seq);
    if (block && S.r) {
      S.follow = false;
      while (block.id < S.r.from) showEarlier();
      const node = S.r.nodes.get(block.id);
      if (node) { node.scrollIntoView({ block: "center" }); node.classList.add("record-highlight"); setTimeout(() => node.classList.remove("record-highlight"), 2500); }
    }
  });
}

function renderEvidence(panel) {
  const frag = document.createDocumentFragment();
  frag.append(el("h2", "section-heading", "Claims and source evidence"));
  frag.append(el("p", "dim", "Quote matching checks stored text. Claim status is recorded by the agent; it is separate from independent verification."));
  if (S.ledger.error) frag.append(el("p", "error", S.ledger.error));
  if (!S.ledger.model) frag.append(el("p", "dim", "Loading mission evidence…"));
  else if (!S.ledger.model.claims.length) frag.append(el("p", "dim", "No claims have been recorded yet."));
  for (const claim of S.ledger.model?.claims || []) {
    const section = el("section", "evidence-claim");
    section.append(el("h3", "", claim.text), el("p", "dim", `${claim.id} · recorded status: ${claim.status}`));
    if (claim.note) section.append(el("p", "", claim.note));
    if (!claim.evidence.length) section.append(el("p", "dim", "No source evidence attached."));
    for (const evidence of claim.evidence) section.append(evidenceCard(evidence));
    frag.append(section);
  }
  preserveFocus(panel, () => panel.replaceChildren(frag));
}

function evidenceCard(evidence) {
  const card = el("div", "ev" + (evidence.supports ? "" : " no"));
  card.append(el("div", "dim", `${evidence.attested ? "Quote matches stored output" : "Quote not attested"} · ${evidence.supports ? "supports" : "undermines"} · ${evidence.kind}`));
  if (evidence.quote) card.append(textBox(evidence.quote, "txt out"));
  if (evidence.blob) {
    const lines = /lines (\d+)–(\d+)/.exec(evidence.lines || "");
    const start = lines ? Number(lines[1]) : 1;
    const end = lines ? Number(lines[2]) : start;
    const source = btn(`${evidence.blob.slice(0, 16)} · ${evidence.lines || "source output"}`, "link evidence-source", () => openViewer(evidence.blob, "Source evidence", null, { start: Math.max(1, start - 3), end: Math.max(end + 3, start + 12), citeStart: start, citeEnd: end, session: evidence.session, call: evidence.call_id }));
    source.dataset.focusKey = "evidence:" + evidence.id;
    card.append(source);
  }
  if (evidence.note) card.append(el("p", "dim", evidence.note));
  return card;
}

// ---------------------------------------------------------------------------------------------
// Transcript blocks

function textBox(text, cls) {
  return el("pre", cls || "txt", text);
}

function buildBlock(b) {
  const root = el("div", "block " + b.kind + (b.detail ? " detail" : ""));
  b.ui = b.ui || {};
  switch (b.kind) {
    case "user": {
      if (b.author !== "user") add(root, el("div", "label", C.authorLabel(b.author)));
      add(root, textBox(b.text));
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
      if (b.reasoning) {
        const d = el("details", "reasoning");
        add(d, el("summary", "", `reasoning · ${b.reasoningLines} ${b.reasoningLines === 1 ? "line" : "lines"}`), textBox(b.reasoning));
        add(root, d);
      }
      if (b.text) {
        add(root, prose(b.text));
        const raw = el("details", "raw-response");
        add(raw, el("summary", "", "Raw response"), textBox(b.text));
        add(root, raw);
      }
      for (const n of b.cutCalls) add(root, el("div", "warn", `The reply was cut inside a call to ${n}; the call was not run.`));
      if (b.warning) add(root, el("div", b.warning.level === "bad" ? "bad" : "warn", b.warning.text));
      add(root, el("div", "foot", b.footer));
      break;
    }
    case "tool":
      buildTool(root, b);
      break;
    case "child_spawned": {
      root.classList.add("card");
      const h = el("div", "ch");
      add(h, el("strong", "", `agent started: ${b.role}`), el("span", "dim", b.mode), link(b.child, "#/s/" + encodeURIComponent(b.child)));
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
      add(h, el("strong", "", `agent ${C.outcomeWords(b.outcome)}`), link(b.child, "#/s/" + encodeURIComponent(b.child)), el("span", "dim", `${b.steps} steps`));
      add(root, h);
      add(root, collapsible(b, "report", b.report, 24));
      if (b.full) add(root, btn("open full report", "link", () => openViewer(b.full.id, "Full report")));
      break;
    }
    case "line": {
      root.classList.add(b.tone === "warn" ? "warn" : "dimline");
      root.textContent = b.text;
      if (b.blob) add(root, btn("open output", "link", () => openViewer(b.blob.id, "Job output")));
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
      root.classList.add("block-inbox");
      if (b.resolved) root.classList.add("done");
      add(root, inboxCard({ session: S.openId, item: b.item, opened_ms: b.ts }, b.resolved || S.answered.get(b.item.item_id)));
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

function collapsible(b, key, text, max) {
  const wrap = el("div");
  const all = !!b.ui[key];
  const c = C.clip(text, max);
  add(wrap, textBox(all ? text : c.text, "txt out"));
  if (c.clipped) {
    add(wrap, btn(all ? "show less" : `show all ${C.num(c.total)} lines`, "link", () => {
      b.ui[key] = !all;
      refresh(b);
    }));
  }
  return wrap;
}

function buildTool(root, b) {
  const res = b.result;
  const bad = res && res.status !== "ok";
  if (bad) root.classList.add("bad");
  const head = el("div", "thead");
  add(head, el("span", "name", b.name));
  const args = el("span", "args", b.argsLine || "");
  if (b.argsInvalid) args.title = "The model's arguments were not valid JSON; this is what it wrote.";
  add(head, args);
  if (res) {
    add(head, el("span", "stat " + (bad ? "bad" : "okc"), res.status));
    add(head, el("span", "dur", C.seconds(res.duration_ms)));
  } else if (b.state === "missing") {
    add(head, el("span", "stat warn", "no result"));
  } else {
    add(head, el("span", "stat dim", "running…"));
  }
  if (b.args !== undefined && b.args !== null) {
    add(head, btn(b.ui.args ? "hide args" : "args", "link", () => {
      b.ui.args = !b.ui.args;
      refresh(b);
    }));
  }
  add(root, head);
  const body = el("div", "tbody");
  if (b.ui.args) add(body, textBox(JSON.stringify(b.args, null, 2), "txt out"));
  if (res) {
    if (res.text === "") add(body, el("div", "dim", "(no output)"));
    else add(body, collapsible(b, "all", res.text, 24));
    const s = res.shown;
    if (s.words || s.blob) {
      const note = el("div", "tnote" + (s.cut ? " cutline" : ""));
      add(note, document.createTextNode(s.words ? s.words + " " : ""));
      if (s.blob) add(note, btn("open full output", "link", () => openViewer(s.blob, `Full output of ${b.name}`, s.total)));
      add(body, note);
    }
  } else if (b.state === "missing") {
    add(body, el("div", "tnote warn", "no result recorded"));
  } else {
    add(body, el("div", "tnote", "running…"));
  }
  add(root, body);
}

function refresh(b) {
  const R = S.r;
  if (!R || !R.nodes.has(b.id)) return;
  const old = R.nodes.get(b.id);
  const fresh = buildBlock(b);
  preserveFocus(old.parentElement, () => old.replaceWith(fresh));
  R.nodes.set(b.id, fresh);
}

function renderBlocks() {
  const store = S.rec;
  const R = S.r;
  if (!store || !R || S.view !== "session") return;
  const holder = $("blocks");
  const scroller = $("scroller");
  const total = store.blocks.length;
  const dirty = C.takeDirty(store);
  for (const i of dirty) if (i >= R.from && i < R.end) refresh(store.blocks[i]);

  if (total > R.end) {
    let newFrom = R.from;
    if (S.follow) newFrom = R.fresh ? C.initialFrom(total) : Math.max(R.from, C.trimFrom(total, R.from, C.MAX_RENDERED));
    R.fresh = false;
    for (let i = R.from; i < Math.min(newFrom, R.end); i++) {
      const n = R.nodes.get(i);
      if (n) n.remove();
      R.nodes.delete(i);
    }
    const frag = document.createDocumentFragment();
    for (let i = Math.max(R.end, newFrom); i < total; i++) {
      const n = buildBlock(store.blocks[i]);
      R.nodes.set(i, n);
      frag.append(n);
    }
    holder.append(frag);
    R.from = newFrom;
    R.end = total;
  }
  $("earlier").hidden = R.from === 0;
  $("btn-earlier").textContent = `Show earlier (${C.num(R.from)} more)`;
  if (S.follow) scroller.scrollTop = scroller.scrollHeight;
  $("jump").hidden = S.section !== "record" || S.follow;
}

function showEarlier() {
  const store = S.rec;
  const R = S.r;
  if (!store || R.from === 0) return;
  const scroller = $("scroller");
  const before = scroller.scrollHeight;
  const newFrom = C.earlierFrom(R.from);
  const frag = document.createDocumentFragment();
  for (let i = newFrom; i < R.from; i++) {
    const n = buildBlock(store.blocks[i]);
    R.nodes.set(i, n);
    frag.append(n);
  }
  $("blocks").prepend(frag);
  R.from = newFrom;
  scroller.scrollTop += scroller.scrollHeight - before;
  $("earlier").hidden = R.from === 0;
  $("btn-earlier").textContent = `Show earlier (${C.num(R.from)} more)`;
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
    const label = el("div", "label dim", "");
    const retry = el("div", "warn");
    const reasoning = el("pre", "txt dim");
    const text = el("pre", "txt");
    const calls = el("div");
    add(root, label, retry, reasoning, text, calls);
    holder.append(root);
    L = S.liveEl = { req: p.req_id, label, retry, reasoning, text, calls };
  }
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
  if (S.follow) $("scroller").scrollTop = $("scroller").scrollHeight;
}

function oneLineArgs(s) {
  return C.oneLine(s, 100000);
}

// ---------------------------------------------------------------------------------------------
// Inbox cards and view

function inboxCard(entry, resolved) {
  const item = entry.item;
  const key = "inbox:" + item.item_id;
  const card = el("div", "inbox-card");
  card.dataset.answerItem = item.item_id;
  const h = el("div", "ih");
  add(h, el("span", "kind", item.item_kind === "finished" ? "Result ready" : C.inboxKindWords(item.item_kind)));
  add(h, el("span", item.blocking ? "warn" : "dim", item.blocking ? "Needs an answer" : item.item_kind === "finished" ? "Review when ready" : "Work can continue"));
  if (entry.title) add(h, link(entry.title, C.sessionHash(entry.session)));
  if (entry.opened_ms) { const time = el("time", "dim", ago(entry.opened_ms)); time.dataset.opened = String(entry.opened_ms); time.dateTime = new Date(entry.opened_ms).toISOString(); h.append(time); }
  add(card, h, textBox(item.text, "txt prose-text"));
  if (resolved) {
    const given = el("div", "given");
    add(given, el("div", "label", resolved.answer === "" ? "Dismissed" : "Answered"));
    if (resolved.answer !== "") given.append(textBox(resolved.answer, "txt prose-text"));
    card.append(given);
    return card;
  }
  const err = el("p", "error");
  err.setAttribute("role", "alert");
  err.hidden = true;
  const form = el("div", "answer");
  form.dataset.blocking = String(!!item.blocking);
  const send = async (answer) => {
    if (S.answering.has(item.item_id)) return;
    S.answering.add(item.item_id);
    syncAnswerState(item.item_id);
    err.hidden = true;
    try {
      await api("POST", "/api/inbox/" + encodeURIComponent(item.item_id), { answer });
      S.answered.set(item.item_id, { answer });
      S.inbox.items.delete(item.item_id);
      if (C.clearDraftIfUnchanged(S.drafts, key, answer)) setDraft(key, "");
      updateInboxBadge();
      await loadInbox();
      if (document.contains(card)) card.replaceChildren(inboxCard(entry, { answer }));
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
    } finally {
      S.answering.delete(item.item_id);
      syncAnswerState(item.item_id);
    }
  };
  if (item.item_kind === "finished") {
    form.append(btn("Dismiss result", "answer-submit", () => send("")));
  } else {
    const ta = el("textarea");
    ta.rows = 2;
    ta.dataset.draftKey = key;
    ta.value = C.getDraft(S.drafts, key);
    ta.setAttribute("aria-label", "Answer for " + (entry.title || entry.session));
    const sendBtn = btn("Send answer", "primary answer-submit", () => send(ta.value));
    const sync = () => {
      setDraft(key, ta.value, ta);
      syncAnswerState(item.item_id);
    };
    ta.addEventListener("input", sync);
    if ((item.options || []).length) {
      const opts = el("div", "opts");
      for (const option of item.options) opts.append(btn(option, "", () => {
        ta.value = option; sync(); ta.focus();
      }));
      form.append(opts);
    }
    if ((item.options || []).length) {
      const edit = el("details", "answer-edit");
      const summary = el("summary", "dim", ta.value ? "Answer: " + C.oneLine(ta.value, 100) : "Write a custom answer");
      add(edit, summary, ta);
      add(form, edit, sendBtn);
    } else add(form, ta, sendBtn);
    form.append(el("div", "dim answer-recipient", "Reply to: " + (entry.title || entry.session)));
    sendBtn.disabled = !!item.blocking && !ta.value.trim();
  }
  add(card, form, err);
  return card;
}

function syncAnswerState(id) {
  const busy = S.answering.has(id);
  for (const card of document.querySelectorAll("[data-answer-item]")) {
    if (card.dataset.answerItem !== id) continue;
    const ta = card.querySelector("textarea");
    if (ta) ta.disabled = busy;
    for (const button of card.querySelectorAll("button")) {
      button.disabled = busy || (button.classList.contains("answer-submit") && card.querySelector(".answer")?.dataset.blocking === "true" && ta && !ta.value.trim());
      if (button.classList.contains("answer-submit")) button.textContent = busy ? "Sending…" : ta ? "Send answer" : "Dismiss result";
    }
    const summary = card.querySelector(".answer-edit summary");
    if (summary) summary.textContent = ta?.value ? "Answer: " + C.oneLine(ta.value, 100) : "Write a custom answer";
  }
}

function reconcileInbox(box, entries, context) {
  if (!box.cardNodes) box.cardNodes = new Map();
  const cards = box.cardNodes;
  const keep = new Set(entries.map(e => e.item.item_id));
  for (const id of cards.keys()) if (!keep.has(id)) cards.delete(id);
  const nodes = [];
  for (const entry of entries) {
    const id = entry.item.item_id;
    const signature = JSON.stringify([entry.session, entry.title, entry.item, S.answered.get(id)]);
    let saved = cards.get(id);
    if (!saved || saved.signature !== signature) {
      const wrap = el("div", "block inbox" + (entry.item.blocking ? " decision-card" : " informational"));
      wrap.append(inboxCard(entry, S.answered.get(id)));
      saved = { signature, node: wrap };
      cards.set(id, saved);
    }
    nodes.push(saved.node);
  }
  if (!nodes.length && context === "inbox") nodes.push(el("p", "dim", "Nothing is waiting for you."));
  preserveFocus(box, () => {
    nodes.forEach((node, i) => { if (box.children[i] !== node) box.insertBefore(node, box.children[i] || null); });
    while (box.children.length > nodes.length) box.lastElementChild.remove();
  });
  for (const entry of entries) syncAnswerState(entry.item.item_id);
}

function showInbox() {
  setView("inbox");
  renderInbox();
}

function renderInbox() {
  reconcileInbox($("inbox-list"), C.inboxSorted(S.inbox), "inbox");
  const granted = notificationsAvailable() && Notification.permission === "granted";
  $("notif-state").textContent = "Notifications: " + (granted ? "on" : "off");
  $("notif-btn").hidden = !notificationsAvailable() || Notification.permission !== "default";
}

// ---------------------------------------------------------------------------------------------
// New session form

function showNew() {
  setView("new");
  const role = $("f-role");
  if (role.options.length === 0) {
    for (const r of C.ROLES) role.append(new Option(r, r));
  }
  const model = $("f-model");
  model.replaceChildren();
  const models = (S.status && S.status.models) || [];
  for (const m of models) model.append(new Option(m.profile + (m.reachable ? "" : " (not reachable)"), m.profile));
  if (models.length === 0) model.append(new Option("default", ""));
  $("f-error").hidden = true;
}

async function submitNew(ev) {
  ev.preventDefault();
  const r = C.buildNewSession({
    workspace: $("f-workspace").value,
    message: $("f-message").value,
    role: $("f-role").value,
    model: $("f-model").value,
    title: $("f-title").value,
    unattended: $("f-unattended").checked,
  });
  const err = $("f-error");
  if (r.error) {
    err.textContent = r.error;
    err.hidden = false;
    return;
  }
  err.hidden = true;
  $("f-submit").disabled = true;
  try {
    const info = await api("POST", "/api/sessions", r.body);
    C.applySessionEvent(S.sessions, info);
    $("f-message").value = "";
    location.hash = "#/s/" + encodeURIComponent(info.id);
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  } finally {
    $("f-submit").disabled = false;
  }
}

// ---------------------------------------------------------------------------------------------
// Right column

function setTab(t) {
  S.tab = t;
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
  else if (S.tab === "context") loadWindow();
  else if (S.tab === "network" && S.net.length === 0) loadNet();
}

async function loadLedger() {
  const info = S.sessions.byId.get(S.openId);
  if (!info) return;
  S.ledger.mission = info.mission;
  const mission = info.mission;
  const request = ++S.requests.ledger;
  try {
    const v = await api("GET", "/api/missions/" + encodeURIComponent(mission) + "/ledger");
    if (request !== S.requests.ledger || S.ledger.mission !== mission) return;
    S.ledger = { mission, model: C.ledgerModel(v), state: v.state, error: null, stale: false };
  } catch (e) {
    if (request !== S.requests.ledger || S.ledger.mission !== mission) return;
    S.ledger = { ...S.ledger, error: e.message, stale: false };
  }
  if (S.tab === "ledger") want("right");
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
  const p = $("panel");
  for (const b of document.querySelectorAll("#tabs .tab")) b.classList.toggle("sel", b.dataset.tab === S.tab);
  const info = S.sessions.byId.get(S.openId);
  if (!info) {
    p.replaceChildren(el("p", "dim", "Open a session to see its state."));
    return;
  }
  if (S.tab === "ledger") return renderLedger(p);
  if (S.tab === "context") return renderContext(p);
  if (S.tab === "network") return renderNetwork(p);
  return renderSessionTab(p, info);
}

function renderLedger(p) {
  const L = S.ledger;
  if (L.error) return p.replaceChildren(el("p", "dim", L.error));
  if (!L.model) return p.replaceChildren(el("p", "dim", "loading…"));
  const m = L.model;
  if (m.empty) return p.replaceChildren(el("p", "dim", "This mission has no ledger entries yet."));
  const frag = document.createDocumentFragment();
  frag.append(h2("Goal"), el("div", "", m.goal || "(not set)"));
  if (m.constraints.length) {
    frag.append(h2("Constraints"), ul(...m.constraints.map((c) => li(el("span", "k", c.id), el("span", c.retired ? "retired" : "", c.text), c.retired ? el("span", "dim", ` (retired: ${c.retired})`) : null))));
  }
  if (m.plan.length) {
    frag.append(h2("Plan"), ul(...m.plan.map((s) => li(el("span", "k", C.stepMark(s.status) + " " + s.id), document.createTextNode(s.text), s.note ? el("div", "dim", s.note) : null))));
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
  p.replaceChildren(frag);
}

function meterEl(m) {
  const box = el("div", "meter big" + (m.over ? " over" : ""));
  const fill = el("span", "fill");
  fill.style.setProperty("width", m.inViewPct + "%");
  box.append(fill);
  if (m.floorPct !== null) {
    const t = el("span", "tick floor");
    t.style.setProperty("left", m.floorPct + "%");
    t.title = "floor: a re-weave folds down to here";
    box.append(t);
  }
  if (m.targetPct !== null) {
    const t = el("span", "tick target");
    t.style.setProperty("left", m.targetPct + "%");
    t.title = "target: a re-weave starts above here";
    box.append(t);
  }
  return box;
}

function renderContext(p) {
  const w = S.win.data;
  if (S.win.error && !w) return p.replaceChildren(el("p", "dim", S.win.error));
  if (!w) return p.replaceChildren(el("p", "dim", "loading…"));
  const frag = document.createDocumentFragment();
  const m = C.windowMeter(w);
  const sum = C.windowSummary(w);
  frag.append(meterEl(m));
  const nums = el("div", "nums");
  nums.append(
    numItem("in view", "~" + C.tokens(w.est_tokens)),
    numItem("last prompt", C.tokens(w.prompt_tokens)),
    numItem("cached", sum.cached || "n/a"),
    numItem("epoch", String(w.epoch)),
  );
  if (m.known) nums.append(numItem("window", C.tokens(w.context_window)));
  frag.append(nums);
  frag.append(el("div", "dim", `${sum.counts.live} live · ${sum.counts.stubbed} stubbed · ${sum.counts.reasoning_dropped} reasoning dropped · ${sum.counts.dropped} dropped · ${sum.pinned} pinned`));
  const bar = el("div", "nums");
  add(bar, btn("Fold now", "", async () => {
    await act(api("POST", "/api/sessions/" + encodeURIComponent(S.openId) + "/reweave"));
  }), btn("Refresh", "", loadWindow));
  const hide = el("label", "dim");
  const cb = el("input");
  cb.type = "checkbox";
  cb.checked = S.win.hideFolded;
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
    frag.append(btn(`Show earlier (${C.num(S.win.from)} more)`, "", () => {
      S.win.from = C.earlierFrom(S.win.from);
      want("right");
    }));
  }
  for (const r of rows.slice(S.win.from)) {
    const row = el("div", "wrow" + (r.folded ? " folded" : ""));
    add(row, el("span", "k", "#" + r.seq), el("span", "pv", (r.pinned ? "📌 " : "") + r.preview));
    add(row, el("span", "meta", `${r.kind.replace(/_/g, " ")} · `));
    row.lastChild.append(el("span", "st-" + r.state, r.stateWords), document.createTextNode(` · ${r.size}${r.pinned ? " · pinned" : ""}`));
    frag.append(row);
  }
  p.replaceChildren(frag);
}

function numItem(label, value) {
  const s = el("span", "", label + " ");
  s.append(el("b", "", value));
  return s;
}

function renderNetwork(p) {
  if (S.netError && S.net.length === 0) return p.replaceChildren(el("p", "dim", S.netError));
  if (S.net.length === 0) return p.replaceChildren(el("p", "dim", "No network decisions recorded for this session."));
  const t = el("table", "net");
  for (const e of S.net.slice(-500).reverse().map(C.netRow)) {
    const tr = el("tr", e.verdict);
    add(tr, el("td", "", clock(e.ts)), el("td", "", e.verdict), el("td", "", e.method), el("td", "", e.target), el("td", "", e.rule));
    t.append(tr);
  }
  p.replaceChildren(t);
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
  p.replaceChildren(kv);
}

// ---------------------------------------------------------------------------------------------
// Full output viewer

function openViewer(blob, title, total, source = {}) {
  const dialog = $("viewer");
  const first = Math.max(1, source.start || 1);
  S.viewer = { ...C.createViewer(blob, total), source, nextStart: first, nextEnd: source.end || first + C.LINES_PAGE - 1, findOffset: -1, opener: document.activeElement };
  $("viewer-title").textContent = title || "Stored output";
  $("viewer-text").textContent = "";
  $("viewer-info").textContent = "";
  $("viewer-error").textContent = "";
  $("viewer-find").value = "";
  $("viewer-start").value = String(source.citeStart || first);
  $("viewer-provenance").replaceChildren(document.createTextNode("Snapshot out:" + blob));
  if (source.session) {
    const producer = link(source.session, C.sessionHash(source.session, "record"));
    producer.addEventListener("click", closeViewer);
    $("viewer-provenance").append(document.createTextNode(" · producer: "), producer);
  }
  if (source.call) $("viewer-provenance").append(document.createTextNode(" · call " + source.call));
  $("viewer-standing").textContent = "Opening this stored snapshot is an operator action. It does not change model observation or verify the claim.";
  if (!dialog.open) dialog.showModal();
  $("viewer-close").focus();
  viewerMore();
}

function closeViewer() {
  const v = S.viewer;
  S.viewer = null;
  if ($("viewer").open) $("viewer").close();
  const replacement = v?.opener?.dataset.focusKey ? [...document.querySelectorAll("[data-focus-key]")]
    .find(n => n.dataset.focusKey === v.opener.dataset.focusKey && n.getClientRects().length && !n.closest("[inert]")) : null;
  const target = v?.opener && document.contains(v.opener) ? v.opener : replacement || $("mission-tab-" + S.section);
  if (target) target.focus({ preventScroll: true });
}

async function viewerMore() {
  const v = S.viewer;
  if (!v || v.busy || v.done) return;
  const range = v.chunks.length ? C.nextRange(v) : { start: v.nextStart, end: v.nextEnd };
  if (!range) return;
  v.busy = true;
  $("viewer-more").disabled = true;
  $("viewer-error").textContent = "Loading stored lines…";
  try {
    const view = await api("GET", C.linesUrl(v.blob, range.start, range.end));
    if (S.viewer !== v) return;
    if (C.applyLines(v, view)) {
      const text = view.text.endsWith("\n") || view.text === "" ? view.text : view.text + "\n";
      const lines = text.split("\n");
      if (lines[lines.length - 1] === "") lines.pop();
      lines.forEach((line, index) => {
        const row = el("span", "source-line" + ((view.first + index) >= v.source.citeStart && (view.first + index) <= v.source.citeEnd ? " cited-line" : ""));
        row.dataset.line = String(view.first + index);
        add(row, el("span", "line-number", String(view.first + index)), document.createTextNode(line + "\n"));
        $("viewer-text").append(row);
      });
    }
    $("viewer-info").textContent = `Lines ${C.num(v.first)}–${C.num(v.last)} of ${C.num(v.total)}`;
    $("viewer-error").textContent = "";
    $("viewer-start").max = String(Math.max(1, v.total));
  } catch (e) {
    if (S.viewer === v) $("viewer-error").textContent = e.message;
  } finally {
    v.busy = false;
    if (S.viewer === v) {
      $("viewer-more").disabled = false;
      $("viewer-more").hidden = v.done;
    }
  }
}

function viewerJump() {
  const v = S.viewer;
  const start = Number($("viewer-start").value);
  if (!v) return;
  if (!Number.isSafeInteger(start) || start < 1 || (v.total > 0 && start > v.total)) {
    $("viewer-error").textContent = `Choose a line from 1 to ${C.num(v.total || 1)}.`; return;
  }
  const source = { ...v.source, start: Math.max(1, start - 3), end: start + C.LINES_PAGE - 4, citeStart: start, citeEnd: start };
  const opener = v.opener;
  openViewer(v.blob, $("viewer-title").textContent, v.total, source);
  S.viewer.opener = opener;
  $("viewer-start").value = String(start);
}

function viewerFind() {
  const v = S.viewer;
  const query = $("viewer-find").value.toLocaleLowerCase();
  if (!v || !query) return;
  const lines = [...$("viewer-text").querySelectorAll(".source-line")];
  for (const line of lines) line.classList.remove("find-match");
  const from = v.findQuery === query ? v.findOffset + 1 : 0;
  const index = lines.findIndex((line, i) => i >= from && line.textContent.toLocaleLowerCase().includes(query));
  const wrapped = index < 0 ? lines.findIndex(line => line.textContent.toLocaleLowerCase().includes(query)) : index;
  v.findQuery = query; v.findOffset = wrapped;
  if (wrapped < 0) { $("viewer-error").textContent = "No match in the displayed lines. Load more or go to another range to search it."; return; }
  lines[wrapped].classList.add("find-match");
  lines[wrapped].scrollIntoView({ block: "center" });
  $("viewer-error").textContent = `Match at line ${lines[wrapped].dataset.line} · searching displayed lines only.`;
}

async function copyViewerReference() {
  const v = S.viewer;
  if (!v) return;
  const first = v.source.citeStart || v.first;
  const last = v.source.citeEnd || v.last;
  const reference = `out:${v.blob} lines ${first}–${last}${v.source.session ? " (" + v.source.session + (v.source.call ? ", call " + v.source.call : "") + ")" : ""}`;
  try { await navigator.clipboard.writeText(reference); $("viewer-error").textContent = "Source reference copied."; }
  catch { $("viewer-error").textContent = "Copy this reference: " + reference; }
}

function updateDelivery(id) {
  const state = S.messageState.get(id);
  if (!state || !S.rec || S.rec.session !== id || state.state === "failed") return;
  const records = [...S.rec.records.values()];
  const user = records.find(r => r.seq > state.afterSeq && r.kind === "user_message" && r.text === state.sentText);
  if (!user) return;
  state.recordedSeq = user.seq;
  const request = records.find(r => r.seq > user.seq && r.kind === "model_request" && (!r.purpose || r.purpose === "step"));
  state.state = request ? "delivered" : "queued";
  state.text = request ? "Delivered to a model step." : "Message recorded · queued for the next model step.";
}

async function sendMessage() {
  const id = S.openId;
  const key = "message:" + id;
  const text = $("msg").value;
  const previous = S.messageState.get(id);
  if (!id || !text.trim() || S.sending.has(id) || !S.rec?.initialComplete || (previous?.accepted && previous.recordedSeq === undefined && previous.state !== "failed")) return;
  const info = S.sessions.byId.get(id);
  if (!info || !C.sessionActions(info).send) return;
  C.setDraft(S.drafts, key, text);
  S.sending.add(id);
  S.messageState.set(id, { state: "sending", accepted: false, sentText: text, afterSeq: C.lastSeq(S.rec) ?? -1, text: "Sending to " + (info.title || id) + "…" });
  renderHeader();
  try {
    await api("POST", "/api/sessions/" + encodeURIComponent(id) + "/messages", { text });
    const state = S.messageState.get(id);
    state.accepted = true;
    if (state.state !== "delivered") { state.state = "queued"; state.text = "Message accepted · awaiting its recorded delivery."; }
    if (C.clearDraftIfUnchanged(S.drafts, key, text)) setDraft(key, "");
    if (S.openId === id) { updateDelivery(id); S.follow = true; }
  } catch (e) {
    const state = C.sendFailure(S.messageState.get(id), e.message, { rejected: e.status >= 400 && e.status < 500 });
    S.messageState.set(id, state);
    if (state.recordedSeq !== undefined && C.clearDraftIfUnchanged(S.drafts, key, text)) setDraft(key, "");
  } finally {
    S.sending.delete(id);
    if (S.openId === id) { renderHeader(); if (S.view === "session") $("msg").focus({ preventScroll: true }); }
  }
}

async function sessionAction(name, body) {
  const id = S.openId;
  if (!id || S.actionState.has(id)) return;
  const label = name === "stop" ? "Stopping…" : name === "resume" ? "Resuming…" : body?.archived ? "Archiving…" : "Unarchiving…";
  S.actionState.set(id, { name, label, archived: body?.archived, accepted: false });
  renderHeader();
  try {
    await api("POST", "/api/sessions/" + encodeURIComponent(id) + "/" + name, body);
    const action = S.actionState.get(id);
    action.accepted = true;
    action.label = name === "stop" ? "Stop requested" : name === "resume" ? "Resume requested" : label;
    await loadSessions();
  } catch (e) { S.actionState.delete(id); notice(e.message); }
  if (S.openId === id) renderHeader();
}

let drawerOpener = null;
function setDrawer(side, open) {
  const panel = $(side);
  const narrow = matchMedia("(max-width: 1099px)").matches;
  const mobile = matchMedia("(max-width: 699px)").matches;
  if (open) drawerOpener = document.activeElement;
  document.body.classList.toggle("show-" + side, open);
  const rightOpen = document.body.classList.contains("show-right");
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

function wire() {
  $("btn-inbox").addEventListener("click", () => {
    if (location.hash === "#/inbox") route();
    else location.hash = "#/inbox";
  });
  $("btn-new").addEventListener("click", () => {
    if (location.hash === "#/new") route();
    else location.hash = "#/new";
  });
  $("show-archived").addEventListener("change", (e) => {
    S.showArchived = e.target.checked;
    want("list");
  });
  $("open-left").addEventListener("click", () => { setDrawer("right", false); setDrawer("left", true); });
  $("close-left").addEventListener("click", () => setDrawer("left", false));
  const inspector = () => { setDrawer("left", false); setDrawer("right", !document.body.classList.contains("show-right")); };
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
  const missionTabs = [...document.querySelectorAll("#mission-tabs [data-view]")];
  for (const b of missionTabs) {
    b.addEventListener("click", () => setSection(b.dataset.view));
    b.addEventListener("keydown", e => tabKeys(e, missionTabs, tab => setSection(tab.dataset.view)));
  }

  $("scroller").addEventListener("scroll", () => {
    const s = $("scroller");
    const was = S.follow;
    S.follow = C.atEnd(s.scrollTop, s.clientHeight, s.scrollHeight);
    $("jump").hidden = S.section !== "record" || S.follow;
    if (S.follow && !was) want("blocks");
  });
  $("jump").addEventListener("click", () => {
    S.follow = true;
    want("blocks");
  });
  $("btn-earlier").addEventListener("click", showEarlier);
  $("details").addEventListener("change", (e) => $("blocks").classList.toggle("hide-details", !e.target.checked));

  $("b-stop").addEventListener("click", () => sessionAction("stop"));
  $("b-stop").title = "Stop this session and cancel its descendant agents and tracked jobs.";
  $("b-resume").addEventListener("click", () => sessionAction("resume"));
  $("b-archive").addEventListener("click", () => sessionAction("archive", { archived: true }));
  $("b-unarchive").addEventListener("click", () => sessionAction("archive", { archived: false }));

  const msg = $("msg");
  msg.addEventListener("input", () => { if (S.openId) C.setDraft(S.drafts, "message:" + S.openId, msg.value); renderHeader(); });
  $("send").addEventListener("click", sendMessage);
  msg.addEventListener("keydown", (e) => {
    if (C.composerAction({ key: e.key, shiftKey: e.shiftKey, isComposing: e.isComposing, text: msg.value }) !== "none") {
      e.preventDefault();
      sendMessage();
    }
  });

  $("new-form").addEventListener("submit", submitNew);
  $("notif-btn").addEventListener("click", async () => {
    try {
      await Notification.requestPermission();
    } catch {
      // refused or unsupported; the view says "off"
    }
    renderInbox();
  });
  $("viewer-close").addEventListener("click", closeViewer);
  $("viewer").addEventListener("cancel", e => { e.preventDefault(); closeViewer(); });
  $("viewer-jump").addEventListener("click", viewerJump);
  $("viewer-find-next").addEventListener("click", viewerFind);
  $("viewer-copy").addEventListener("click", copyViewerReference);
  $("viewer-controls").addEventListener("submit", e => { e.preventDefault(); if (document.activeElement === $("viewer-start")) viewerJump(); else viewerFind(); });
  $("viewer-more").addEventListener("click", viewerMore);
  window.addEventListener("hashchange", route);
  window.addEventListener("pagehide", saveSeen);
  window.addEventListener("resize", () => {
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
    if ($("viewer").open) return;
    const side = matchMedia("(max-width: 1099px)").matches && document.body.classList.contains("show-right") ? "right"
      : matchMedia("(max-width: 699px)").matches && document.body.classList.contains("show-left") ? "left" : null;
    if (e.key === "Escape" && side) { e.preventDefault(); setDrawer(side, false); }
    if (e.key === "Tab" && side) {
      const focusable = [...$(side).querySelectorAll("button:not([disabled]), a, input:not([disabled]), textarea:not([disabled]), select:not([disabled]), summary, [tabindex='0']")].filter(n => n.getClientRects().length);
      const first = focusable[0], last = focusable[focusable.length - 1];
      if (!first) return;
      if (e.shiftKey && (document.activeElement === first || !$(side).contains(document.activeElement))) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && (document.activeElement === last || !$(side).contains(document.activeElement))) { e.preventDefault(); first.focus(); }
    }
  });
}

async function start() {
  wire();
  setTab("ledger");
  setSection("overview", false);
  setDrawer("left", false);
  setDrawer("right", false);
  resizeInspector(Number(recalled("inspector-width", 360)) || 360);
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
}

start();
