# loom-desk

A small native macOS app that keeps loom in your menu bar: a count of what is running and what is
waiting for you, a notification when a mission needs an answer, and the daemon's own web UI in a
window — over an SSH tunnel when the daemon runs on another machine.

It does not reimplement the UI. The daemon already serves a complete one; loom-desk is the shell that
reaches it, authenticates, watches `/api/events` for the counts, and shows the page.

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
