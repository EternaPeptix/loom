# ferret-desk

A small native macOS app that keeps ferret in your menu bar: a count of what is running and what is
waiting for you, a Dock badge and native notification when a mission needs an answer, and the daemon's
own web UI in a window — locally or over an SSH tunnel when the daemon runs on another machine.

It does not reimplement the UI. The daemon already serves a complete one; ferret-desk is the shell that
reaches it, authenticates, watches `/api/events` for the counts, and shows the page.

## Connecting

- **Local daemon:** On first run, `ferret-desk` detects a local daemon via `~/.ferret/daemon.json` (or
  `http://127.0.0.1:7878/healthz`) and offers one-click local connection reading `~/.ferret/token`.
- **Over SSH:** An SSH-tunnel connection derives its browser URL and its ssh forward from one validated
  endpoint, so the ports cannot differ: it forwards `127.0.0.1:<port>` to `127.0.0.1:<port>` on the
  remote host, with the SAME port number at both ends (the daemon only accepts its own port in the
  `Host`/`Origin` headers). If that local port is busy the connection fails and names the port. Any
  forward, made by ferret-desk or by hand, must use the daemon's own port number on both ends, so stop
  whatever listens on that port (`lsof -nP -iTCP:<port> -sTCP:LISTEN` names it), or move one of the
  daemons to another port with `[daemon] bind` in its config (if you move the remote one, change the
  connection's port to match). The tunnel's ssh runs with connection sharing off (`ControlMaster=no`,
  `ControlPath=none`), so the forward ends with it.
- **Identity & tokens:** The app keeps tokens in the Keychain (reusing a cached Keychain token on
  reconnect before fetching `~/.ferret/token` over SSH again). Before the token is sent anywhere the
  daemon must prove it holds it (`GET /healthz?nonce=<64 hex>` answers an HMAC-SHA256 proof); the app
  then asks for a one-time code (`POST /api/login-codes`, bearer token) and loads
  `<base>/#code=<code>`; every web view, including the one Reload builds, gets its own fresh code while
  preserving your current mission route. A daemon that cannot prove its identity (one older than the
  app: restart it on the new version) gets no token, and there is no token-in-URL fallback. A daemon
  that refuses the address (HTTP 403: the local port is not its own) gets no token either; the
  connection fails and says so.
- **Direct URLs:** A Direct connection may use `http` only for `127.0.0.1`, `localhost` or `[::1]`;
  any other host needs `https`.
- The link button copies the daemon's base address only (`⇧⌘C`), never a code or token. A tunnel whose
  ssh process ends reconnects automatically with exponential backoff and actively probes on system wake.

## Shortcuts

- `⌘,` — Manage Connections (without disconnecting your active session)
- `⌘F` / `⌘G` / `⇧⌘G` — Find in page (Next / Previous)
- `⌘R` — Reload (mints a fresh login code while preserving your current route)
- `⌘[` / `⌘]` — Back / Forward (trackpad swipes also work)
- `⌘=` / `⌘-` / `⌘0` — Zoom In / Zoom Out / Actual Size (persisted across launches)
- `⇧⌘I` — Open Inbox
- `⇧⌘C` — Copy daemon base address
- `⌘W` — Hide the window without destroying the live view or unsent drafts (`⌘Q` quits and closes the tunnel)

## Build

```
FERRET_BUILD_HOST=<host> gui/build.sh --pull          # build on the build host, atomically copy to gui/dist & clear quarantine
open gui/dist/ferret-desk.app
```

`FERRET_BUILD_HOST` must be set (the build host, or `local`, which builds in place if you have the Xcode
toolchain on this machine). `FERRET_TARGET` defaults to `<uname -m>-apple-macos14.0` (`arm64` or
`x86_64`). `FERRET_OUT_DIR` overrides the output folder (useful for staging builds while `ferret-desk.app`
is running). `FERRET_SWIFTFLAGS` is passed to the host quoted with `printf %q`.

### Preserving Keychain access across rebuilds

By default `build.sh` ad-hoc signs (`FERRET_CODESIGN_ID=-`), which changes the app's code-signature hash
on every rebuild and causes macOS Keychain to re-prompt for saved tokens. To avoid repeat Keychain
prompts, create a one-time local Code Signing certificate in **Keychain Access → Certificate Assistant
→ Create a Certificate…** (e.g. name `ferret-desk`, type `Code Signing`) and build with:

```
FERRET_BUILD_HOST=local FERRET_CODESIGN_ID="ferret-desk" gui/build.sh
```

## Design

`gui/DESIGN.md` is normative. System frameworks only (SwiftUI, AppKit, WebKit, UserNotifications),
no package manager, no bundled browser.
