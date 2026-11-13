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
  claimFilter: "all", // which claims the Evidence view lists
  view: "empty", // empty | session | inbox | new
  openId: null,
  rec: null, // record store of the open session
  r: null, // what is rendered of it: {from, end, nodes, fresh}
  follow: true,
  tab: "ledger",
  ledger: { mission: null, model: null, state: null, error: null, stale: true },
  win: { data: null, error: null, stale: true, hideFolded: false, from: null },
  rules: null, // the rules form of the open session: {session, box, note, hint, lists, reason, asking, shown}
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
    const missions = group.rows.filter((row) => !row.depth).length;
    // The space is not drawn between the two ends of the heading; it keeps them two words when read out.
    section.append(add(el("h2", "group-title"), el("span", "", group.label), document.createTextNode(" "), el("span", "group-count", String(missions))));
    for (const row of group.rows) {
      const { info, depth, agentCount, agentsRunning, expanded, attention } = row;
      const mark = C.stateMark(info, attention || inboxCount(info.id));
      const wrap = el("div", "mission-row");
      const a = el("a", `row d${Math.min(depth, 2)}${mark === "needs_you" ? " needs" : ""}${info.id === S.openId && S.view === "session" ? " sel" : ""}${info.archived ? " arch" : ""}`);
      a.setAttribute("href", C.sessionHash(info.id));
      a.dataset.focusKey = "session:" + info.id;
      if (info.id === S.openId) a.setAttribute("aria-current", "page");
      const t = el("div", "t");
      add(t, markEl(mark), el("span", "name", info.title || info.id));
      add(a, t, el("div", "sub", C.rowSummary(row, S.latest.get(info.id), S.now)));
      a.title = info.title || info.id;
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
  if (v !== "session") $("s-speed").textContent = "";
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
  S.rules = null;
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
      S.everConnected = true;
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
    renderDot();
    await new Promise((resolve) => setTimeout(resolve, C.reconnectDelayMs(attempt++)));
  }
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
  $("s-eyebrow").textContent = info.parent ? `Agent · ${info.role}` : "Mission";
  $("s-title").textContent = info.title || info.id;
  $("s-title").title = info.id;
  $("s-goal").textContent = S.ledger.state?.goal || (info.parent ? "Agent assignment · messages go to the mission lead." : "Mission goal has not been recorded yet.");
  const currentStep = S.ledger.state?.plan?.find(step => step.status === "doing");
  const standing = C.missionStanding(info, inboxCount(info.id), info.parent ? 0 : missionAgents(info).filter(agent => agent.status?.phase === "running").length);
  $("s-standing").replaceChildren(
    ...standing.pills.map(p => pill(p.text, p.tone, p.icon)),
    el("span", "dim", currentStep ? "Current step: " + currentStep.text : C.rowActivity(info, S.latest.get(info.id), S.now)),
  );
  const openClaims = (S.ledger.state?.claims || []).filter(claim => claim.status === "open").length;
  $("evidence-count").textContent = `${openClaims} open`;
  $("evidence-count").hidden = openClaims === 0;
  $("s-speed").textContent = S.rec ? C.sessionSpeed(S.rec.blocks).label : "";
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
  $("send").textContent = "Send";
  // A message is not an answer: say so while a question of this mission waits on the operator.
  const paused = missionEntries().some(entry => entry.item.blocking);
  const lead = C.rootNoun(info) === "lead";
  $("composer-help").textContent = "Enter sends · Shift+Enter adds a line."
    + (paused ? " A message does not answer the open question." : "") + (a.running ? (lead ? " It reaches the lead between steps." : " It is read between steps.") : "");
  $("composer-help").hidden = !a.send;
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

/** The agents of a mission, oldest first. */
function missionAgents(info) {
  return [...S.sessions.byId.values()]
    .filter(s => s.mission === info.mission && s.parent)
    .sort((a, b) => a.created_ms - b.created_ms || (a.id < b.id ? -1 : 1));
}

function renderOverview() {
  if (S.view !== "session" || !S.rec) return;
  const panel = $("mission-overview");
  if (!panel.firstElementChild) {
    const main = add(el("div", "overview-main"), el("div", "overview-decisions"), el("section", "overview-section overview-plan"), el("section", "overview-section overview-changes"));
    const rail = el("aside", "overview-rail");
    rail.setAttribute("aria-label", "Mission standing");
    panel.append(add(el("div", "overview-layout"), main, rail));
  }
  const entries = missionEntries();
  const model = C.missionOverview(S.rec.records.values(), S.ledger.state, entries, S.sinceSeq);
  reconcileInbox(panel.querySelector(".overview-decisions"), entries.filter(e => e.item.item_kind !== "finished"), "overview");
  for (const [selector, build] of [[".overview-plan", planSection], [".overview-changes", changesSection], [".overview-rail", railSection]]) {
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
  const record = link("Open full record", C.sessionHash(S.openId, "record"));
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
    if (agents.length) body.append(card("Agents", ...agents.map(sessionLink)));
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
  if (evidence.quote) card.append(textBox(evidence.quote, "txt out"));
  const producer = evidence.session ? S.sessions.byId.get(evidence.session) : null;
  const tool = evidence.session === S.openId ? S.rec?.calls.get(evidence.call_id)?.name : null;
  const from = el("span", "dim ev-from");
  if (evidence.session) {
    add(from, document.createTextNode("from "), tool ? el("code", "", tool) : document.createTextNode(evidence.call_id ? "call " + evidence.call_id : "a call"),
      document.createTextNode(" in "), link(producer?.title || evidence.session, C.sessionHash(evidence.session, "record")));
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
    card.append(add(el("div", "ev-source"), source, evidence.session ? from : null));
  } else {
    card.append(add(el("div", "ev-source"), el("span", "dim", "No stored source is attached to this item."), evidence.session ? from : null));
  }
  if (evidence.note) card.append(el("p", "ev-note", evidence.note));
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
      if (b.full) add(root, btn("open full report", "link", (e) => openViewer(b.full.id, "Full report", null, {}, e.currentTarget)));
      break;
    }
    case "line": {
      root.classList.add(b.tone === "warn" ? "warn" : "dimline");
      root.textContent = b.text;
      if (b.blob) add(root, btn("open output", "link", (e) => openViewer(b.blob.id, "Job output", null, {}, e.currentTarget)));
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
      add(root, inboxCard({ session: S.openId, title: S.sessions.byId.get(S.openId)?.title, item: b.item, opened_ms: b.ts }, b.resolved || S.answered.get(b.item.item_id), "record"));
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
      if (s.blob) add(note, btn("open full output", "link", (e) => openViewer(s.blob, `Full output of ${b.name}`, s.total, {}, e.currentTarget)));
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
  $("s-speed").textContent = C.sessionSpeed(store.blocks).label;
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
  add(card, h, textBox(item.text, "txt prose-text item-text"));
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
      if (document.contains(card)) card.replaceWith(inboxCard(entry, { answer }, context));
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
      await send("");
    });
    add(foot, words, approve, btn("Dismiss", "", () => send("")));
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
    add(words, el("span", "answer-hint"), el("span", "dim answer-recipient", "Reply to: " + (entry.title || entry.session)));
    add(foot, words, btn("Send answer", "primary answer-submit", () => send(ta.value)));
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
  const close = btn("Close as blocked", "small", async () => {
    const req = C.releaseRequest(entry.session, reason.value);
    if (req.error) return fail(err, req.error);
    close.disabled = true;
    err.hidden = true;
    try {
      await api("POST", req.path, req.body);
      // The release closes the mission and its open items; the lists are read again to show it.
      notice(C.RELEASED_WORDS + ".");
      loadInbox();
      loadLedger();
    } catch (e) {
      close.disabled = false;
      fail(err, e.message);
    }
  });
  add(confirm, reason, close, btn("Keep it open", "small", () => {
    confirm.hidden = true;
  }));
  for (const c of choices) {
    add(opts, btn(c.label, "", () => {
      err.hidden = true;
      if (c.action === "answer") {
        ta.value = c.answer;
        sync();
        send(ta.value, []);
      } else if (c.action === "provide") {
        ta.focus();
      } else {
        confirm.hidden = false;
        reason.focus();
      }
    }));
  }
  add(box, opts, confirm);
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
    if (submit) button.textContent = busy ? "Sending…" : !ta ? "Dismiss result" : !blocking && !draft.trim() ? "Dismiss" : "Send answer";
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
      wrap.append(inboxCard(entry, S.answered.get(id), context));
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
  else if (S.tab === "network") {
    if (S.net.length === 0) loadNet();
    if (S.ledger.stale || !S.ledger.model) loadLedger();
  }
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
    notice(req.error);
    return false;
  }
  b.disabled = true;
  form.note.textContent = "";
  const receipt = await act(api("POST", req.path, req.body));
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
  const rule = ruleInput("Standing rule for this mission");
  const addRule = btn("Add rule", "small", () => sendRule(form, addRule, C.ruleRequest(id, rule.value), [rule]));
  const appr = ruleInput("Approve something");
  const scope = ruleInput("What it covers (optional)");
  const addAppr = btn("Approve", "small", () => sendRule(form, addAppr, C.approvalRequest(id, appr.value, scope.value), [appr, scope]));
  add(form.box, h2("Rules and approvals"), add(el("div", "rule-row"), rule, addRule), add(el("div", "rule-row"), appr, scope, addAppr), form.note, form.hint, form.lists);
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
  const ask = (ruleId) => {
    form.asking = ruleId;
    form.reason.value = "";
    renderRuleLists(form, S.ledger.model);
    if (ruleId) form.reason.focus();
  };
  // The reason field is one node that outlives the redraws, so the text typed in it is kept.
  const typing = document.activeElement === form.reason;
  const nodes = [];
  if (lists.rules.length) {
    nodes.push(ul(...lists.rules.map((r) => {
      const item = li(el("span", "k", r.id), document.createTextNode(r.text + " "));
      if (r.id !== lists.asking) return add(item, btn("Withdraw", "small", () => ask(r.id)));
      const go = btn("Withdraw " + r.id, "small", async () => {
        if (await sendRule(form, go, C.withdrawRequest(form.session, r.id, form.reason.value))) ask(null);
      });
      return add(item, add(el("div", "rule-row"), form.reason, go, btn("Keep", "small", () => ask(null))));
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
  // A failed load (a damaged audit log among them) stays in view next to the decisions that arrive live.
  const error = S.netError ? [el("p", "error", S.netError)] : [];
  const granted = S.ledger.model ? [el("p", "dim", C.scopeLine(S.ledger.model))] : [];
  if (S.net.length === 0) {
    return p.replaceChildren(...granted, ...(error.length ? error : [el("p", "dim", "No network decisions recorded for this session.")]));
  }
  const t = el("table", "net");
  for (const e of S.net.slice(-500).reverse().map(C.netRow)) {
    const tr = el("tr", e.verdict);
    add(tr, el("td", "", clock(e.ts)), el("td", "", e.verdict), el("td", "", e.method), el("td", "", e.target), el("td", "", e.rule));
    t.append(tr);
  }
  p.replaceChildren(...granted, ...error, t);
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
  $("viewer-title").textContent = title || "Stored output";
  const provenance = $("viewer-provenance");
  provenance.replaceChildren();
  if (source.session) {
    const producer = link(source.producer || source.session, C.sessionHash(source.session, "record"));
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
    const view = await api("GET", C.linesUrl(v.blob, range.start, range.end));
    if (S.viewer !== v) return;
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
    $("viewer-info").textContent = v.last >= v.first ? `Lines ${C.num(v.first)}–${C.num(v.last)} of ${C.num(v.total)}` : "No lines stored";
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
  viewerStatus(`At line ${C.num(target.line)}. Copy reference now gives this line.`);
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
  const reference = C.viewerReference(v);
  try { await navigator.clipboard.writeText(reference); viewerStatus("Copied: " + reference); }
  catch { viewerStatus("Copy this reference: " + reference); }
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
  $("viewer-find-next").addEventListener("click", () => viewerFind(1));
  $("viewer-find-prev").addEventListener("click", () => viewerFind(-1));
  $("viewer-copy").addEventListener("click", copyViewerReference);
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
