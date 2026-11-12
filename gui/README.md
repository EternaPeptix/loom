# loom-desk

A small native macOS app that keeps loom in your menu bar: a count of what is running and what is
waiting for you, a notification when a mission needs an answer, and the daemon's own web UI in a
window — over an SSH tunnel when the daemon runs on another machine.

It does not reimplement the UI. The daemon already serves a complete one; loom-desk is the shell that
reaches it, authenticates, watches `/api/events` for the counts, and shows the page.

## Connecting

An SSH-tunnel connection forwards `127.0.0.1:<port>` to `127.0.0.1:<port>` on the remote host, with
the SAME port number at both ends (the daemon only accepts its own port in the `Host`/`Origin`
headers). If that local port is busy the connection fails and names the port: close whatever uses it,
or use a Direct connection. The app keeps the token in the Keychain and shows the UI by asking the
daemon for a one-time code (`POST /api/login-codes`, bearer token) and loading `<base>/#code=<code>`;
daemons without that route (404) get the older `<base>/?token=<token>` URL instead. A tunnel whose
ssh process ends is shown as disconnected with ssh's last error line.

## Build

```
gui/build.sh --pull          # build on the build host, copy gui/dist/loom-desk.app here
xattr -dr com.apple.quarantine gui/dist/loom-desk.app   # first run only
open gui/dist/loom-desk.app
```

`LOOM_BUILD_HOST=local gui/build.sh` builds in place if you have the Xcode toolchain on this machine.

## Design

`gui/DESIGN.md` is normative. System frameworks only (SwiftUI, AppKit, WebKit, UserNotifications),
no package manager, no bundled browser.
