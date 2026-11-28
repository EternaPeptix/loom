#!/bin/bash
# build.sh — compile ferret-desk and assemble ferret-desk.app.
#
# Run it from anywhere; like the repo's ./x it builds on the build host (swiftc lives there, not on
# the operator's Mac) and leaves the .app there. Pass --pull to also rsync the bundle to ./dist here.
#
#   FERRET_BUILD_HOST=<host> gui/build.sh             build on the host (required: a host name, or "local")
#   FERRET_BUILD_HOST=<host> gui/build.sh --pull      build, then atomically copy dist/ferret-desk.app back to gui/dist
#   FERRET_BUILD_HOST=local gui/build.sh              build right here (needs swiftc)
#   FERRET_BUILD_HOST=local FERRET_CODESIGN_ID="ferret-desk" gui/build.sh
#                                                     sign with a reusable local cert so Keychain ACLs survive rebuilds
#   FERRET_BUILD_HOST=local FERRET_OUT_DIR=/tmp/out gui/build.sh
#                                                     write the .app bundle into a custom directory (non-destructive)
#   FERRET_BUILD_HOST=<host> FERRET_SWIFTFLAGS=-DDEBUG gui/build.sh
#                                                     debug variant: `ferret-desk --self-check` runs the pure-helper checks
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HOST="${FERRET_BUILD_HOST:-}"
if [ -z "$HOST" ]; then
    echo "build.sh: FERRET_BUILD_HOST is not set. Set it to the build host (an ssh destination), or to \"local\" to build on this machine." >&2
    exit 2
fi
REMOTE="ferret-build/gui"
APP="ferret-desk"
ARCH="$(uname -m)"
case "$ARCH" in
    arm64|x86_64) ;;
    *) ARCH="arm64" ;;
esac
TARGET="${FERRET_TARGET:-${ARCH}-apple-macos14.0}"
SIGN_ID="${FERRET_CODESIGN_ID:--}"

check_not_running() {
    local app_path="$1"
    if [ "${FERRET_ALLOW_LIVE_OVERWRITE:-0}" = "1" ]; then
        return 0
    fi
    if pgrep -f "$app_path/Contents/MacOS/$APP" >/dev/null 2>&1; then
        echo "build.sh: $app_path is currently running. Quit ferret-desk first, set FERRET_OUT_DIR=<dir> to build elsewhere, or set FERRET_ALLOW_LIVE_OVERWRITE=1." >&2
        return 10
    fi
    return 0
}

atomic_swap() {
    local stage="$1"
    local dest="$2"
    local prev="${dest}.prev.$$"
    rm -rf "$prev"
    if [ -e "$dest" ]; then
        mv "$dest" "$prev" || return 8
    fi
    if mv "$stage" "$dest"; then
        rm -rf "$prev"
        return 0
    else
        # Restore previous working bundle if swap failed.
        if [ -e "$prev" ]; then mv "$prev" "$dest" || true; fi
        return 9
    fi
}

build_local() {
    local root="$1"
    cd "$root" || return 1
    local out_dir="${FERRET_OUT_DIR:-$root/dist}"
    mkdir -p "$out_dir" || return 1
    local out="$out_dir/$APP.app"
    check_not_running "$out" || return $?

    # Compile and sign in a staging bundle so a failed build never deletes a working .app.
    local stage="$out_dir/.$APP.app.staging.$$"
    rm -rf "$stage"
    trap 'rm -rf "$stage"' RETURN
    mkdir -p "$stage/Contents/MacOS" "$stage/Contents/Resources" || return 1

    # All Swift sources, compiled to one binary against the system frameworks.
    local srcs
    srcs=$(find src -name '*.swift' | sort)
    if [ -z "$srcs" ]; then echo "build.sh: no Swift sources under src/" >&2; return 2; fi
    # shellcheck disable=SC2086
    xcrun swiftc -O ${FERRET_SWIFTFLAGS:-} -target "$TARGET" \
        -framework SwiftUI -framework AppKit -framework WebKit -framework UserNotifications \
        -o "$stage/Contents/MacOS/$APP" $srcs || return $?
    cp Info.plist "$stage/Contents/Info.plist" || return 7
    if [ -d Resources ]; then cp -R Resources/. "$stage/Contents/Resources/" || return 6; fi
    plutil -lint "$stage/Contents/Info.plist" >/dev/null || return 3
    codesign --force --deep --sign "$SIGN_ID" --options runtime "$stage" || return 4
    codesign --verify --deep --strict "$stage" || return 5

    atomic_swap "$stage" "$out" || return $?
    trap - RETURN
    echo "built $out ($(du -sh "$out" | cut -f1), target=$TARGET, sign=$SIGN_ID)"
}

if [ "$HOST" = "local" ]; then
    build_local "$HERE"; exit $?
fi

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")
"${SSH[@]}" "mkdir -p \$HOME/$REMOTE" || { echo "build.sh: cannot reach $HOST" >&2; exit 90; }
rsync -a --delete --exclude '/dist' "$HERE/" "$HOST:$REMOTE/" || { echo "build.sh: rsync failed" >&2; exit 91; }
# Build on the host (FERRET_BUILD_HOST=local makes that invocation compile in place, no further ssh).
# Flags are quoted with printf %q so the host's shell receives each as one literal value.
QFLAGS="$(printf '%q' "${FERRET_SWIFTFLAGS:-}")"
QTARGET="$(printf '%q' "${FERRET_TARGET:-}")"
QSIGN="$(printf '%q' "${FERRET_CODESIGN_ID:-}")"
"${SSH[@]}" "cd \$HOME/$REMOTE && FERRET_BUILD_HOST=local FERRET_SWIFTFLAGS=$QFLAGS FERRET_TARGET=$QTARGET FERRET_CODESIGN_ID=$QSIGN bash build.sh" || exit $?

if [ "${1:-}" = "--pull" ]; then
    OUT_DIR="${FERRET_OUT_DIR:-$HERE/dist}"
    mkdir -p "$OUT_DIR" || exit 92
    DEST="$OUT_DIR/$APP.app"
    check_not_running "$DEST" || exit $?
    PULL_STAGE="$OUT_DIR/.$APP.app.pull.$$"
    rm -rf "$PULL_STAGE"
    trap 'rm -rf "$PULL_STAGE"' EXIT
    rsync -a --delete "$HOST:$REMOTE/dist/$APP.app/" "$PULL_STAGE/" || exit 92
    xattr -dr com.apple.quarantine "$PULL_STAGE" 2>/dev/null || true
    atomic_swap "$PULL_STAGE" "$DEST" || exit 93
    trap - EXIT
    echo "pulled to $DEST (quarantine cleared)"
fi
