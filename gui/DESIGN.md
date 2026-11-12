# loom-desk — design

loom-desk is a native macOS app for watching and steering loom missions without a browser tab open.
The daemon already serves a complete web UI; loom-desk does **not** reimplement it. It is a native
shell that (1) manages the connection to a daemon that binds loopback on another host, (2) keeps a
menu-bar presence with live running/waiting counts, (3) raises an OS notification the moment a
mission needs a human, and (4) shows the daemon's own web UI in a `WKWebView`.

This document is normative. Where it and the code disagree, one is a bug.

## Why native, and why a shell

- The daemon binds `127.0.0.1` with a bearer token on purpose (see the main DESIGN §2, §12): the API
  is reachable only from the daemon's own machine. The operator runs loom on another host (where the
  model and the work are), so the app's real job is **connection management**: open an SSH port
  forward to that host, fetch the token, and point a webview at the forwarded port. The daemon still
  only ever accepts loopback requests; nothing about its security model changes.
- The web UI is good and strict-CSP; wrapping it beats forking it. loom-desk adds exactly what a
  browser tab cannot: a menu-bar glance, native notifications that fire while no window is focused,
  and tunnel lifecycle tied to the app.

## Toolchain (fixed)

- Swift 6, SwiftUI + AppKit + WebKit + UserNotifications, **system frameworks only — no SPM
  dependencies**, so it builds with `swiftc` against the system SDK with nothing to fetch.
- Deployment target `MACOSX_DEPLOYMENT_TARGET=14.0`.
- Built on the build host (`swiftc`), assembled into `loom-desk.app` by `gui/build.sh` (no Xcode
  project), ad-hoc codesigned, and copied to the operator's Mac. Never built on the operator's Mac.

## Shape

```
gui/
  DESIGN.md            this file (normative)
  README.md            how to build, install, first connect
  build.sh             swiftc → assemble loom-desk.app → ad-hoc codesign
  Info.plist           the app bundle's Info.plist (LSUIElement = true: menu-bar app, no Dock icon by default)
  src/
    App/LoomDeskApp.swift     @main: MenuBarExtra (counts + actions), the Window, app lifecycle, notifications
    App/AppState.swift        the observable app state: connections, the active connection, counts, status line
    Model/Connection.swift    a saved connection profile; load/save to Application Support; Keychain for secrets
    Net/Tunnel.swift          the ssh -N -L child process, port readiness, token fetch, teardown
    Net/DaemonClient.swift    minimal HTTP+SSE client to the tunneled daemon; publishes counts and inbox events
    UI/RootView.swift         the window: a connection bar on top, the web pane filling the rest
    UI/ConnectionsView.swift  add / edit / pick / connect a connection
    UI/WebPane.swift          NSViewRepresentable around WKWebView; loads the tunneled daemon UI
  Resources/                  optional icon assets
```

## Connection model (`Model/Connection.swift`)

A `Connection` is what the operator needs to reach one daemon:

```
struct Connection: Codable, Identifiable {
    var id: UUID
    var name: String            // "studio", shown in the sidebar and menu bar
    var mode: Mode              // .sshTunnel or .direct
    // .sshTunnel:
    var sshHost: String         // an ssh(1) destination: a Host alias or user@host
    var remotePort: Int         // the daemon's port on that host (default 7878)
    var tokenSource: TokenSource // .fetchOverSsh (run `cat ~/.loom/token` there) or .manual
    // .direct (daemon already reachable, e.g. local or an existing tunnel):
    var baseURL: String         // http://127.0.0.1:7878
    // secrets (token) are NOT in this struct; they live in the Keychain, keyed by id.
}
```

Connections persist to `~/Library/Application Support/loom-desk/connections.json` (0600). The token,
when stored, goes to the login Keychain (`kSecClassGenericPassword`, service `com.loom.desk`, account
= connection id), never to the JSON. A first run has no connections and shows the add-connection form.

## Tunnel (`Net/Tunnel.swift`)

For a `.sshTunnel` connection, `connect()`:

1. uses the daemon's own port number for the local end too (`<port>` = `remotePort`). The daemon only
   accepts its own port in the `Host` and `Origin` headers, so a different local port would have every
   request refused. First it waits (bounded, ~3 s) for the ssh child of the previous tunnel to exit,
   so that loom-desk's own dying listener is not taken for someone else's. If something then listens
   on 127.0.0.1:<port> (or ssh reports "Address already in use") the connection fails with a message
   naming the port, saying loom-desk needs it free for this connection, and what to do (close what
   uses it, or use a Direct connection). There is no random port and no pick-then-release. Other bind
   failures (e.g. "Permission denied" for a port below 1024) are reported with ssh's own words;
2. spawns `ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15
   -o ControlMaster=no -o ControlPath=none -L 127.0.0.1:<port>:127.0.0.1:<port> <sshHost>` as a
   `Process`, keeping the handle. Multiplexing is off so the listener always lives in this child,
   never in a ControlPersist master from the operator's ssh config that would outlive it and keep the
   port;
3. waits (poll-connect to the local port, up to ~10 s) until the forward is up and `/healthz` answers;
   a dead child or a timeout is an error whose message includes the ssh stderr;
4. if `tokenSource == .fetchOverSsh`, runs `ssh -o BatchMode=yes -o ControlMaster=no -o ControlPath=none
   <sshHost> cat ~/.loom/token`, trims it, and stores it (Keychain + memory). A token that is not 64
   lowercase-hex characters is an error. The child is checked again afterwards: if it exited during the
   fetch, the connect fails with ssh's last stderr line.

`baseURL` is then `http://127.0.0.1:<port>`. The app watches the ssh child for the whole life of the
link: if it exits while connecting or connected, the link becomes "disconnected" with ssh's last
stderr line (read once the stderr pipe has drained), and the web view is never loaded against a
forward whose ssh is gone (the child is re-checked immediately before every page load). A connect
that a newer one superseded never stops the newer one's ssh child. `disconnect()` terminates the ssh
process (SIGTERM, then SIGKILL after a short grace). The tunnel is torn down on disconnect,
on switching connections, and on app quit (`applicationWillTerminate`). Exactly one tunnel at a time.

A `.direct` connection skips all of this: `baseURL` is the configured URL and the token comes from the
Keychain or a prompt. The URL may use http only when its host is 127.0.0.1, localhost or [::1]; any other
host must use https, because the token travels in every request. A saved connection that breaks this is
shown as invalid, with the reason, and cannot be connected. `Info.plist` declares
`NSAppTransportSecurity` / `NSAllowsLocalNetworking` = true (nothing broader), so loopback http works for
names as well as IP literals.

Tunnel exit reports: `close(only:)` stops exactly the process it is given, even when a newer open() has
replaced it (without touching the current state). An unexpected-exit report is acted on only if its ssh
child is still the current one at the moment it is delivered on the main actor.

## Daemon client (`Net/DaemonClient.swift`)

Talks to the active `baseURL` with `Authorization: Bearer <token>`. Every attempt, and the snapshot after
an ended stream, is preceded by the `/healthz` nonce proof; a wrong proof fails the link and an
unreachable daemon is retried without the token being sent. Two jobs:

- **Counts**, for the menu bar and status line: subscribe to `GET /api/events` (SSE). Frames carry
  only `data:` (no `event:` line); the kind is the JSON `type` (`session`, `status`, `record`,
  `settled`, `lagged`, …). There is no `inbox` event: an inbox change shows up as a `record` of kind
  `inbox_opened` / `inbox_resolved` or a `status` whose `open_inbox` changed, and is answered by
  re-reading `GET /api/inbox`, the source of truth for the open set. Maintain a local map of
  sessions by id and a set of open inbox items; derive `running` (sessions whose phase is running),
  `waiting` (open blocking inbox items) and `active` (not ended/archived). If the SSE stream drops,
  fall back to polling `GET /api/sessions` and `GET /api/inbox` every few seconds and keep retrying
  the stream. All of this is read-only.
- **Notifications**: when a new **blocking** inbox item appears (kind `question`, `blocker`, or a
  parked session) that was not seen before, post a `UNUserNotification` (request authorization once at
  launch). Its title names the mission; its body is the item text, cut. Activating the notification
  brings the window forward and navigates the web pane to that session.

The client never writes: answering, stopping, approving all happen in the web UI the operator is
already looking at. loom-desk is a window and a notifier, not a second control surface. (A later
version may add quick-answer from the notification; out of scope for v1.)

## Web pane (`UI/WebPane.swift`)

A `WKWebView` wrapped in `NSViewRepresentable`. It logs in with a one-time code. First the daemon proves
its identity: `GET <baseURL>/healthz?nonce=<N>` (N = 64 random hex characters, no token sent) must
answer `{"ok": true, "proof": "<hex>"}` with proof = HMAC-SHA256 keyed with the token's bytes over the
ASCII `loom-healthz-v1:` followed by N, compared in constant time. This is done on connect, before every
login code request, and at the start of every attempt of the daemon client and again before the snapshot
that follows an ended stream (a wrong answer after connect turns the link to failed with that message).
When a 200 answer's proof is missing or wrong, or any other answer below 500 carries proof JSON (only a
200 proves, even when the proof in another answer is right), the token is not sent and the app says that
something answered but did not prove it is the daemon for this token, and that a daemon older than the
app must be restarted on the new version. A 5xx answer, a non-200 answer without proof JSON, or no
answer at all means the daemon is unreachable, and the token is not sent either. On connect, and before
a login code request, that fails the attempt: the link or the pane shows the error with "Reconnect to
retry" and the operator retries. The daemon client instead retries by itself; meanwhile the status line
reads "daemon unreachable, retrying" with the error, and the link is not shown as connected. Then the
app (which holds the token) sends `POST <baseURL>/api/login-codes` with `Authorization: Bearer <token>`;
the answer is `{"code": "<hex>", "expires_in_s": 60}` and the pane loads `<baseURL>/#code=<code>`. The
page exchanges the code itself; no cookie is involved and the token is never in a URL. A code is single
use and short-lived, so none is minted ahead of time: each newly built web view (on connect, on reload
or retry, and when SwiftUI builds the window's content again) asks for its own code, takes the URL once,
and loads exactly that one URL. Reload and retry build a new web view rather than reloading the old one:
the old document's code is spent, and loading another `#code=` URL into the same document would only
change its fragment (WebKit does not reload for that) and run nothing. There is no fallback for daemons
without login codes (they cannot prove their identity either): the token is never in a URL. Thereafter
the UI drives itself (same-origin XHR/SSE to the daemon, through the tunnel). The pane:

- restricts navigation to the `baseURL` origin (loopback): a navigation action to any other origin is
  cancelled and opened in the default browser instead (so links in fetched pages don't hijack the
  pane). Requests only ever leave for `127.0.0.1:<port>`.
- exposes reload (a new web view with a fresh code) and a "copy address" affordance that copies the
  daemon's base address only (scheme, host, port): no login code and no token reach the pasteboard;
- shows a clear state when there is no connection, when the tunnel is connecting, and when the daemon
  is unreachable (with the error and a retry), rather than a blank white view.

Do not inject scripts into the page or read its contents; the pane only navigates.

## App & menu bar (`App/LoomDeskApp.swift`, `App/AppState.swift`)

`@main` `App` with:

- a `MenuBarExtra` whose label is a short glyph plus counts (e.g. `◆ 2▸ 1!` meaning 2 running, 1
  waiting), red when anything is waiting. Its menu: the connection name and status; **Open loom** (show
  / focus the window); a connections submenu to switch; **Disconnect**; **Quit**. `LSUIElement` is
  true so the app lives in the menu bar; the main `Window` is opened on demand and on first launch.
- the main `Window` hosting `RootView` (a connection bar — active connection, state, reload — above
  the `WebPane`).
- notification setup (authorization, delegate that foregrounds the window and routes to a session).
- lifecycle: restore the last-used connection on launch and connect to it; tear the tunnel down on
  quit.

`AppState` is an `@MainActor @Observable` (or `ObservableObject`) holding: the connection list, the
active connection, the live counts, a human status string, and the current `baseURL`/token. The
tunnel and client write counts/status back into it on the main actor.

## build.sh

`gui/build.sh` (runs on the build host):

1. `swiftc` all of `src/**/*.swift` into one executable, `-O`, `-target arm64-apple-macos14.0`,
   linking SwiftUI/AppKit/WebKit/UserNotifications (they come from the SDK; no extra flags beyond the
   frameworks). Treat warnings as warnings, not errors.
2. assemble `dist/loom-desk.app/Contents/{MacOS/loom-desk, Info.plist, Resources/…}`.
3. `codesign --force --deep --sign - --options runtime dist/loom-desk.app` (ad-hoc).
4. print the bundle path and size.

`LOOM_BUILD_HOST` is required (a build host, or `local`); the script stops with a message otherwise.
`LOOM_SWIFTFLAGS` reaches the host quoted with `printf %q`, so a quote or `;` in it runs nothing there.

The app is copied to the operator's Mac with rsync; because it is ad-hoc signed and crosses machines,
`README.md` tells the operator to clear the quarantine attribute (`xattr -dr com.apple.quarantine`)
or open it once via right-click. No notarization (personal tool).

## What v1 does and does not do

Does: one connection at a time; SSH-tunnel and direct connections; token fetch and Keychain storage;
the web UI in a native window; menu-bar counts; notifications for blocking inbox items; tunnel tied to
app lifecycle. Does not (later, if wanted): quick-answer from the notification, multiple simultaneous
daemons, Windows/Linux (the web UI already serves those operators in a browser), auto-starting the
remote daemon.

## Tests / checks

No unit-test harness for a GUI this size; instead `build.sh` must produce a launching `.app`, and the
implementer verifies by hand on the build host where possible (a headless build host cannot show a
window, so: confirm it compiles and the bundle is well-formed with `codesign --verify` and
`plutil -lint Info.plist`, and that `Tunnel` and `DaemonClient`'s pure parsing helpers — token
validation, SSE line parsing, counts derivation — have small `#if DEBUG` self-checks or are factored
so they can be exercised). State in the report what was and was not run.
