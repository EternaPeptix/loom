// app.js: the DOM and the network. Every decision that can be wrong lives in core.js.
// Text from records, tools and the network is only ever put into the page with textContent or
// text nodes; nothing here parses markup.

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
  showArchived: false,
  view: "empty", // empty | session | inbox | new
  openId: null,
  rec: null, // record store of the open session
  r: null, // what is rendered of it: {from, end, nodes, fresh}
  follow: true,
  tab: "ledger",
  ledger: { mission: null, model: null, error: null, stale: true },
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

const MARKS = { running: "●", waiting: "◔", needs_you: "◆", stopped: "■", finished: "✓", failed: "✕", idle: "○" };
function markEl(mark) {
  const m = el("span", "mark mark-" + mark, MARKS[mark] || "?");
  m.title = C.markWords(mark);
  return m;
}
const clock = (ms) => new Date(ms).toLocaleTimeString();

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
  if (!r.ok) throw new Error(C.errorSentence(r.status, text));
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

const needs = { list: false, header: false, blocks: false, live: false, right: false };
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
}

// ---------------------------------------------------------------------------------------------
// Left column

function inboxCount(id) {
  return C.inboxCountFor(S.inbox, id);
}

function renderList() {
  const box = $("sessions");
  const rows = C.sessionRows(S.sessions, { showArchived: S.showArchived });
  const frag = document.createDocumentFragment();
  for (const { info, depth } of rows) {
    const mark = C.stateMark(info, inboxCount(info.id));
    const a = el("a", `row d${Math.min(depth, 2)}${mark === "needs_you" ? " needs" : ""}${info.id === S.openId && S.view === "session" ? " sel" : ""}${info.archived ? " arch" : ""}`);
    a.setAttribute("href", "#/s/" + encodeURIComponent(info.id));
    const t = el("div", "t");
    add(t, markEl(mark), el("span", "name", info.title || info.id));
    add(a, t, el("div", "sub", C.rowDetail(info, S.now)));
    frag.append(a);
  }
  if (rows.length === 0) frag.append(el("p", "dim pad", "No sessions yet."));
  box.replaceChildren(frag);
}

function renderDot() {
  const d = C.healthDot({ connected: S.connected, models: (S.status && S.status.models) || [] });
  const dot = $("dot");
  dot.className = "dot dot-" + d.state;
  dot.title = d.tip;
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
  want("list");
}

// ---------------------------------------------------------------------------------------------
// Navigation

function route() {
  let h = "";
  try {
    h = decodeURIComponent(location.hash || "");
  } catch {
    h = "";
  }
  document.body.classList.remove("show-left", "show-right");
  if (h.startsWith("#/s/")) return openSession(h.slice(4));
  if (h === "#/inbox") return showInbox();
  if (h === "#/new") return showNew();
  setView(S.openId ? "session" : "empty");
}

function setView(v) {
  S.view = v;
  $("view-empty").hidden = v !== "empty";
  $("view-session").hidden = v !== "session";
  $("view-inbox").hidden = v !== "inbox";
  $("view-new").hidden = v !== "new";
  want("list");
}

function openSession(id) {
  if (S.openId === id && S.rec) {
    setView("session");
    want("header", "blocks", "right");
    return;
  }
  S.openId = id;
  S.rec = C.createRecordStore(id);
  S.r = { from: 0, end: 0, nodes: new Map(), fresh: true };
  S.follow = true;
  S.net = [];
  S.netError = null;
  S.liveEl = null;
  S.win = { ...S.win, data: null, error: null, stale: true, from: null };
  S.ledger = { mission: null, model: null, error: null, stale: true };
  const opened = S.sessions.byId.get(id);
  S.ledger.mission = opened ? opened.mission : null;
  clear($("blocks"));
  clear($("live"));
  $("loading").hidden = false;
  $("earlier").hidden = true;
  setView("session");
  want("header", "blocks", "live", "right");
  loadRecords(S.rec, 0);
  loadNet();
  loadTab();
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
      want("blocks");
      if (page.next_after === null || page.next_after === undefined) break;
      after = page.next_after;
    }
    $("loading").hidden = true;
  } catch (e) {
    if (S.rec === store) {
      $("loading").hidden = false;
      $("loading").textContent = "Could not load the record: " + e.message;
    }
    store.loading = false;
    return;
  }
  store.loading = false;
  if (S.rec === store && C.missing(store) && tries < 5) loadRecords(store, tries + 1);
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
  for (const f of C.planEvent(ev, ctx())) {
    switch (f.fx) {
      case "session":
        C.applySessionEvent(S.sessions, f.info);
        want("list");
        break;
      case "status":
        C.applyStatus(S.sessions, f.session, f.status);
        want("list");
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
        const res = C.applyInboxRecord(S.inbox, f.session, f.record, (id) => S.sessions.byId.get(id));
        if (res === "opened") announce(S.inbox.items.get(f.record.item_id));
        updateInboxBadge();
        break;
      }
      case "apply_record":
        if (C.applyRecord(S.rec, f.record)) {
          want("blocks", "live", "header");
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
        if (S.tab === "ledger") loadLedger();
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
        for (const m of parser.feed(decoder.decode(value, { stream: true }))) {
          let ev;
          try {
            ev = JSON.parse(m.data);
          } catch {
            continue;
          }
          handleEvent(ev);
        }
      }
    } catch {
      // dropped or aborted: reconnect below
    }
    clearTimeout(idle);
    S.connected = false;
    renderDot();
    if (streamStopped) return;
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
  try {
    C.applySessionList(S.sessions, await api("GET", "/api/sessions?archived=true"));
    want("list", "header");
  } catch (e) {
    notice(e.message);
  }
}
async function loadInbox() {
  try {
    C.applyInboxList(S.inbox, await api("GET", "/api/inbox"));
    updateInboxBadge();
  } catch (e) {
    notice(e.message);
  }
}
async function loadStatus() {
  try {
    S.status = await api("GET", "/api/status");
    renderDot();
  } catch {
    // the dot shows the stream; a failed status poll changes nothing
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
  const m = $("s-mark");
  m.className = "mark mark-" + mark;
  m.textContent = MARKS[mark];
  $("s-words").textContent = C.markWords(mark);
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
      if (b.text) add(root, textBox(b.text));
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
      add(root, inboxCard({ session: S.openId, item: b.item, opened_ms: b.ts }, b.resolved));
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
  old.replaceWith(fresh);
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
  $("jump").hidden = S.follow;
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
  const card = el("div", "inbox-card");
  const h = el("div", "ih");
  add(h, el("span", "kind", C.inboxKindWords(item.item_kind)));
  if (item.blocking) add(h, el("span", "warn", "blocking"));
  if (entry.title) add(h, link(entry.title, "#/s/" + encodeURIComponent(entry.session)));
  if (entry.opened_ms) add(h, el("span", "dim", C.age(S.now, entry.opened_ms)));
  add(card, h, textBox(item.text));
  if (resolved) {
    const g = el("div", "given");
    add(g, el("div", "label", resolved.answer === "" ? "dismissed" : "answered"));
    if (resolved.answer !== "") add(g, textBox(resolved.answer));
    add(card, g);
    return card;
  }
  const err = el("p", "error");
  err.hidden = true;
  const form = el("div", "answer");
  const send = async (answer, buttons) => {
    err.hidden = true;
    for (const b of buttons) b.disabled = true;
    try {
      await api("POST", "/api/inbox/" + encodeURIComponent(item.item_id), { answer });
      loadInbox();
    } catch (e) {
      err.textContent = e.message;
      err.hidden = false;
      for (const b of buttons) b.disabled = false;
    }
  };
  if (item.item_kind === "finished") {
    const dismiss = btn("Dismiss", "", () => send("", [dismiss]));
    add(form, dismiss);
  } else {
    const ta = el("textarea");
    ta.rows = 2;
    ta.setAttribute("aria-label", "Answer");
    const sendBtn = btn("Send answer", "primary", () => send(ta.value, [sendBtn]));
    const sync = () => {
      sendBtn.disabled = item.blocking && ta.value.trim() === "";
    };
    ta.addEventListener("input", sync);
    sync();
    if ((item.options || []).length) {
      const opts = el("div", "opts");
      for (const o of item.options) {
        add(opts, btn(o, "", () => {
          ta.value = o;
          sync();
          ta.focus();
        }));
      }
      add(form, opts);
    }
    add(form, ta, sendBtn);
  }
  add(card, form, err);
  return card;
}

function showInbox() {
  setView("inbox");
  renderInbox();
}

function renderInbox() {
  const box = $("inbox-list");
  const items = C.inboxSorted(S.inbox);
  const frag = document.createDocumentFragment();
  if (items.length === 0) frag.append(el("p", "dim", "Nothing is waiting for you."));
  for (const e of items) {
    const wrap = el("div", "block inbox");
    add(wrap, inboxCard(e, null));
    frag.append(wrap);
  }
  box.replaceChildren(frag);
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
  for (const b of document.querySelectorAll("#tabs .tab")) b.classList.toggle("sel", b.dataset.tab === t);
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
  try {
    const v = await api("GET", "/api/missions/" + encodeURIComponent(mission) + "/ledger");
    if (S.ledger.mission !== mission) return;
    S.ledger = { mission, model: C.ledgerModel(v), error: null, stale: false };
  } catch (e) {
    S.ledger = { mission, model: null, error: e.message, stale: false };
  }
  if (S.tab === "ledger") want("right");
}

async function loadWindow() {
  const id = S.openId;
  if (!id) return;
  try {
    const w = await api("GET", "/api/sessions/" + encodeURIComponent(id) + "/window");
    if (S.openId !== id) return;
    S.win.data = w;
    S.win.error = null;
    S.win.stale = false;
  } catch (e) {
    S.win.error = e.message;
  }
  if (S.tab === "context") want("right");
}

async function loadNet() {
  const id = S.openId;
  if (!id) return;
  try {
    const list = await api("GET", "/api/sessions/" + encodeURIComponent(id) + "/net?limit=500");
    if (S.openId !== id) return;
    const live = S.net;
    S.net = [];
    for (const e of list) C.applyNet(S.net, e);
    for (const e of live) C.applyNet(S.net, e);
    S.netError = null;
  } catch (e) {
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
        const ev = el("div", "ev" + (e.supports ? "" : " no"));
        add(ev, el("div", "", `${e.attested ? "✓ attested" : "not attested"} · ${e.supports ? "supports" : "undermines"} · ${e.kind}${e.blob ? " · out:" + e.blob.slice(0, 16) : ""}${e.lines ? " · " + e.lines : ""}`));
        if (e.quote) add(ev, textBox(e.quote, "txt"));
        if (e.note) add(ev, el("div", "dim", e.note));
        add(item, ev);
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

function openViewer(blob, title, total) {
  S.viewer = C.createViewer(blob, total);
  $("viewer-title").textContent = title || "Full output";
  $("viewer-text").textContent = "";
  $("viewer-info").textContent = "";
  $("viewer").hidden = false;
  viewerMore();
}

async function viewerMore() {
  const v = S.viewer;
  if (!v || v.busy) return;
  const range = C.nextRange(v);
  if (!range) return;
  v.busy = true;
  $("viewer-more").disabled = true;
  try {
    const view = await api("GET", C.linesUrl(v.blob, range.start, range.end));
    if (S.viewer !== v) return;
    if (C.applyLines(v, view)) {
      const text = view.text.endsWith("\n") || view.text === "" ? view.text : view.text + "\n";
      $("viewer-text").append(document.createTextNode(text));
    }
    $("viewer-info").textContent = `lines ${C.num(v.first)}–${C.num(v.last)} of ${C.num(v.total)}`;
  } catch (e) {
    $("viewer-info").textContent = e.message;
  } finally {
    v.busy = false;
    $("viewer-more").disabled = false;
    $("viewer-more").hidden = v.done;
  }
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
  $("open-left").addEventListener("click", () => document.body.classList.add("show-left"));
  $("open-right").addEventListener("click", () => document.body.classList.add("show-right"));
  $("close-right").addEventListener("click", () => document.body.classList.remove("show-right"));
  $("scrim").addEventListener("click", () => document.body.classList.remove("show-left", "show-right"));
  $("notice-close").addEventListener("click", () => {
    $("notice").hidden = true;
  });
  for (const b of document.querySelectorAll("#tabs .tab")) b.addEventListener("click", () => setTab(b.dataset.tab));

  $("scroller").addEventListener("scroll", () => {
    const s = $("scroller");
    const was = S.follow;
    S.follow = C.atEnd(s.scrollTop, s.clientHeight, s.scrollHeight);
    $("jump").hidden = S.follow;
    if (S.follow && !was) want("blocks");
  });
  $("jump").addEventListener("click", () => {
    S.follow = true;
    want("blocks");
  });
  $("btn-earlier").addEventListener("click", showEarlier);
  $("details").addEventListener("change", (e) => $("blocks").classList.toggle("hide-details", !e.target.checked));

  const post = (path, body) => act(api("POST", "/api/sessions/" + encodeURIComponent(S.openId) + path, body));
  $("b-stop").addEventListener("click", () => post("/stop"));
  $("b-resume").addEventListener("click", () => post("/resume"));
  $("b-archive").addEventListener("click", async () => {
    await post("/archive", { archived: true });
    loadSessions();
  });
  $("b-unarchive").addEventListener("click", async () => {
    await post("/archive", { archived: false });
    loadSessions();
  });

  const msg = $("msg");
  const send = async () => {
    const text = msg.value;
    if (!text.trim()) return;
    msg.disabled = true;
    try {
      await api("POST", "/api/sessions/" + encodeURIComponent(S.openId) + "/messages", { text });
      msg.value = "";
      S.follow = true;
    } catch (e) {
      notice(e.message);
    } finally {
      msg.disabled = false;
      msg.focus();
    }
  };
  $("send").addEventListener("click", send);
  msg.addEventListener("keydown", (e) => {
    if (C.composerAction({ key: e.key, shiftKey: e.shiftKey, isComposing: e.isComposing, text: msg.value }) !== "none") {
      e.preventDefault();
      send();
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
  $("viewer-close").addEventListener("click", () => {
    $("viewer").hidden = true;
    S.viewer = null;
  });
  $("viewer-more").addEventListener("click", viewerMore);
  window.addEventListener("hashchange", route);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !$("viewer").hidden) {
      $("viewer").hidden = true;
      S.viewer = null;
    }
  });
}

async function start() {
  if (!(await signIn())) {
    lost();
    return;
  }
  wire();
  setTab("ledger");
  renderDot();
  connect();
  await Promise.all([loadSessions(), loadInbox(), loadStatus()]);
  route();
  setInterval(() => {
    S.now = Date.now();
    want("list");
  }, 30000);
  setInterval(loadStatus, 60000);
}

start();
