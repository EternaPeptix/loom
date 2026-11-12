# loom-desk

A small native macOS app that keeps loom in your menu bar: a count of what is running and what is
waiting for you, a notification when a mission needs an answer, and the daemon's own web UI in a
window — over an SSH tunnel when the daemon runs on another machine.

It does not reimplement the UI. The daemon already serves a complete one; loom-desk is the shell that
reaches it, authenticates, watches `/api/events` for the counts, and shows the page.

## SSH connections

The local forwarded port matches the remote daemon port (7878 by default), because the daemon checks
the browser's exact Host and Origin. Only one connection is active at a time. If that local port is
occupied, stop the conflicting local service or tunnel and reconnect. If the listener already reaches
the intended daemon, configure a Direct connection to it instead. There is no automatic fallback to a
different local port; changing ports requires the remote daemon to listen on the same new port.

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
