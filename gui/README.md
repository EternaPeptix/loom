# loom-desk

A small native macOS app that keeps loom in your menu bar: a count of what is running and what is
waiting for you, a notification when a mission needs an answer, and the daemon's own web UI in a
window — over an SSH tunnel when the daemon runs on another machine.

It does not reimplement the UI. The daemon already serves a complete one; loom-desk is the shell that
reaches it, authenticates, watches `/api/events` for the counts, and shows the page.

## Connecting

An SSH-tunnel connection forwards `127.0.0.1:<port>` to `127.0.0.1:<port>` on the remote host, with
the SAME port number at both ends (the daemon only accepts its own port in the `Host`/`Origin`
headers). If that local port is busy the connection fails and names the port: close whatever uses it
(`lsof -nP -iTCP:<port> -sTCP:LISTEN`), or use a Direct connection. The tunnel's ssh runs with
connection sharing off (`ControlMaster=no`, `ControlPath=none`), so the forward ends with it. The app
keeps the token in the Keychain. Before the token is sent anywhere the daemon must prove it holds it
(`GET /healthz?nonce=<64 hex>` answers an HMAC-SHA256 proof); the app then asks for a one-time code
(`POST /api/login-codes`, bearer token) and loads `<base>/#code=<code>`; every web view, including
the one Reload builds, gets its own fresh code. A daemon that cannot prove its identity (one older
than the app: restart it on the new version) gets no token, and there is no token-in-URL fallback.
A Direct connection may use http only for 127.0.0.1, localhost or [::1]; any other host needs https.
The link button copies the daemon's base address only, never a code or token. A tunnel whose ssh
process ends is shown as disconnected with ssh's last error line.

## Build

```
LOOM_BUILD_HOST=<host> gui/build.sh --pull          # build on the build host, copy gui/dist/loom-desk.app here
xattr -dr com.apple.quarantine gui/dist/loom-desk.app   # first run only
open gui/dist/loom-desk.app
```

`LOOM_BUILD_HOST` must be set (the build host, or `local`, which builds in place if you have the Xcode
toolchain on this machine). `LOOM_SWIFTFLAGS` is passed to the host quoted with `printf %q`.

## Design

`gui/DESIGN.md` is normative. System frameworks only (SwiftUI, AppKit, WebKit, UserNotifications),
no package manager, no bundled browser.
