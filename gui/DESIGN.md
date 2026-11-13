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
    var name: String            // "512S1", shown in the sidebar and menu bar
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

1. picks a free local TCP port on 127.0.0.1 (bind port 0, read it back, close);
2. spawns `ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes -o ServerAliveInterval=15
   -L 127.0.0.1:<localPort>:127.0.0.1:<remotePort> <sshHost>` as a `Process`, keeping the handle;
3. waits (poll-connect to the local port, up to ~10 s) until the forward is up; a dead child or a
   timeout is an error whose message includes the ssh stderr;
4. if `tokenSource == .fetchOverSsh`, runs `ssh -o BatchMode=yes <sshHost> cat ~/.loom/token`, trims
   it, and stores it (Keychain + memory). A token that is not 64 lowercase-hex characters is an error.

`baseURL` is then `http://127.0.0.1:<localPort>`. `disconnect()` terminates the ssh process (SIGTERM,
then SIGKILL after a short grace) and forgets the local port. The tunnel is torn down on disconnect,
on switching connections, and on app quit (`applicationWillTerminate`). Exactly one tunnel at a time.

A `.direct` connection skips all of this: `baseURL` is the configured URL and the token comes from the
Keychain or a prompt.

## Daemon client (`Net/DaemonClient.swift`)

Talks to the active `baseURL` with `Authorization: Bearer <token>`. Two jobs:

- **Counts**, for the menu bar and status line: subscribe to `GET /api/events` (SSE). Frames carry
  only `data:` (no `event:` line); the kind is the JSON `type` (`session`, `status`, `record`,
  `settled`, `lagged`, …). There is no `inbox` event: an inbox change shows up as a `record` of kind
  `inbox_opened` / `inbox_resolved` or a `status` whose `open_inbox` changed, and is answered by
  re-reading `GET /api/inbox`, the source of truth for the open set. Maintain a local map of
  sessions by id and a set of open inbox items; derive `running` (missions with a running lead or
  descendant agent), `runningAgents` (child sessions whose phase is running), `waiting` (open blocking inbox
  items) and `active` (root missions not ended/archived). If the SSE stream drops,
  fall back to polling `GET /api/sessions` and `GET /api/inbox` every few seconds and keep retrying
  the stream. All of this is read-only.
- **Freshness** is independent of attention. Counts are unknown until both session and inbox
  snapshots succeed. A failed resource refresh retains the last counts and exposes them as last
  known, with an updating age; another resource succeeding or an SSE event must not clear that
  failure. A full successful polling snapshot can make counts current while the stream reconnects.
  The connection dot is green only for a live stream with current data, amber for reconnecting or
  polling, and never changes colour merely because a mission needs an answer.
- **Notifications**: when a new **blocking** inbox item appears (kind `question`, `blocker`, or a
  parked session) that was not seen before, post a `UNUserNotification` (authorization is requested
  by the **Enable notifications…** menu action). Its title names the mission; its body is the item text, cut. Activating the notification
  brings the window forward and navigates the web pane to that session.

The client never writes: answering, stopping, approving all happen in the web UI the operator is
already looking at. loom-desk is a window and a notifier, not a second control surface. (A later
version may add quick-answer from the notification; out of scope for v1.)

## Web pane (`UI/WebPane.swift`)

A `WKWebView` wrapped in `NSViewRepresentable`. On connect (or when the operator picks a connection),
it loads `"<baseURL>/?token=<token>"` — the daemon answers 303 to `/` with the `loom_token` session
cookie (there is no `/auth` route). Thereafter the UI drives itself (same-origin XHR/SSE to the
daemon, through the tunnel). The pane:

- restricts navigation to the `baseURL` origin (loopback): a navigation action to any other origin is
  cancelled and opened in the default browser instead (so links in fetched pages don't hijack the
  pane). Requests only ever leave for `127.0.0.1:<localPort>`.
- exposes reload and a "copy web URL" affordance (the `baseURL` + token, for opening in a real
  browser if wanted);
- shows a clear state when there is no connection, when the tunnel is connecting, and when the daemon
  is unreachable (with the error and a retry), rather than a blank white view.

Do not inject scripts into the page or read its contents; the pane only navigates.

## App & menu bar (`App/LoomDeskApp.swift`, `App/AppState.swift`)

`@main` `App` with:

- a `MenuBarExtra` whose label names missions, agents, and items needing an answer (e.g.
  `2 missions · 4 agents · 1 needs you`), red when a current snapshot has blocking items. Unknown or
  stale counts are labelled `loom · state unknown`; the menu retains their last-known values.
  Its menu: the connection name and data freshness; **Open loom** (show
  / focus the window); a connections submenu to switch; **Disconnect**; **Quit**. `LSUIElement` is
  true so the app lives in the menu bar; the main `Window` is opened on demand and on first launch.
- the main `Window` hosting `RootView` (a connection bar — active connection, state, reload — above
  the `WebPane`).
- notification setup (an explicit **Enable notifications…** menu action requests authorization;
  the delegate foregrounds the window and routes to a session). Launch does not prompt for consent.
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
