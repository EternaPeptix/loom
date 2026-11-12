#!/bin/bash
# build.sh — compile loom-desk and assemble loom-desk.app.
#
# Run it from anywhere; like the repo's ./x it builds on the build host (swiftc lives there, not on
# the operator's Mac) and leaves the .app there. Pass --pull to also rsync the bundle to ./dist here.
#
#   LOOM_BUILD_HOST=<host> gui/build.sh   build on the host (required: a host name, or "local")
#   LOOM_BUILD_HOST=<host> gui/build.sh --pull       build, then copy dist/loom-desk.app back to this gui/dist
#   LOOM_BUILD_HOST=local gui/build.sh   build right here (needs swiftc)
#   LOOM_BUILD_HOST=<host> LOOM_SWIFTFLAGS=-DDEBUG gui/build.sh  debug variant: `loom-desk --self-check` runs the pure-helper checks
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HOST="${LOOM_BUILD_HOST:-}"
if [ -z "$HOST" ]; then
    echo "build.sh: LOOM_BUILD_HOST is not set. Set it to the build host (an ssh destination), or to \"local\" to build on this machine." >&2
    exit 2
fi
REMOTE="loom-build/gui"
APP="loom-desk"
TARGET="arm64-apple-macos14.0"

build_local() {
    local root="$1"
    cd "$root" || return 1
    local out="dist/$APP.app"
    rm -rf "$out"
    mkdir -p "$out/Contents/MacOS" "$out/Contents/Resources"
    # All Swift sources, compiled to one binary against the system frameworks.
    local srcs
    srcs=$(find src -name '*.swift' | sort)
    if [ -z "$srcs" ]; then echo "build.sh: no Swift sources under src/" >&2; return 2; fi
    # shellcheck disable=SC2086
    xcrun swiftc -O ${LOOM_SWIFTFLAGS:-} -target "$TARGET" \
        -framework SwiftUI -framework AppKit -framework WebKit -framework UserNotifications \
        -o "$out/Contents/MacOS/$APP" $srcs || return $?
    cp Info.plist "$out/Contents/Info.plist"
    [ -d Resources ] && cp -R Resources/. "$out/Contents/Resources/" 2>/dev/null
    plutil -lint "$out/Contents/Info.plist" >/dev/null || return 3
    codesign --force --deep --sign - --options runtime "$out" || return 4
    codesign --verify --deep --strict "$out" || return 5
    echo "built $root/$out ($(du -sh "$out" | cut -f1))"
}

if [ "$HOST" = "local" ]; then
    build_local "$HERE"; exit $?
fi

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")
"${SSH[@]}" "mkdir -p \$HOME/$REMOTE" || { echo "build.sh: cannot reach $HOST" >&2; exit 90; }
rsync -a --delete --exclude '/dist' "$HERE/" "$HOST:$REMOTE/" || { echo "build.sh: rsync failed" >&2; exit 91; }
# Build on the host (LOOM_BUILD_HOST=local makes that invocation compile in place, no further ssh).
# The flags are quoted with printf %q, as ./x does for its arguments, so the host's shell receives them
# as one value and a quote or `;` inside them cannot start another command.
QFLAGS="$(printf '%q' "${LOOM_SWIFTFLAGS:-}")"
"${SSH[@]}" "cd \$HOME/$REMOTE && LOOM_BUILD_HOST=local LOOM_SWIFTFLAGS=$QFLAGS bash build.sh" || exit $?

if [ "${1:-}" = "--pull" ]; then
    mkdir -p "$HERE/dist"
    rsync -a "$HOST:$REMOTE/dist/$APP.app" "$HERE/dist/" || exit 92
    echo "pulled to $HERE/dist/$APP.app — clear quarantine before first run: xattr -dr com.apple.quarantine '$HERE/dist/$APP.app'"
fi
