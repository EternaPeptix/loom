#!/bin/bash
# x — run cargo for this repo on a build host, so the operator's machine stays idle.
#
#   LOOM_BUILD_HOST=<ssh host> ./x test -p loom-core   run cargo on that host, output here
#   LOOM_BUILD_HOST=local ./x test -p loom-core        run cargo right here (plain `cargo` works too)
#   LOOM_LANE=tools LOOM_BUILD_HOST=<host> ./x test -p loom-tools
#                                                      private source copy + target dir (parallel work,
#                                                      no lock waits)
#   LOOM_BUILD_HOST=<host or local> ./x --pull-bin     build release and copy the `loom` binary to ./bin/loom
#
# LOOM_BUILD_HOST has no default: set it to an ssh host name (key-based login, no prompts) or to "local".
#
# The tree this script sits in is pushed with rsync before every run, to a directory that belongs to
# the lane. A new lane starts from a copy-on-write clone of the main lane's target dir, so it does not
# rebuild third-party crates. Cargo.lock is tracked; if the build host changes it, the changed file is
# copied back and one line says so.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
HOST="${LOOM_BUILD_HOST:-}"
LANE="${LOOM_LANE:-main}"
REMOTE="loom-build"

if [ -z "$HOST" ]; then
    echo "x: LOOM_BUILD_HOST is not set. Set it to the ssh host that should build, or to \"local\" to run cargo on this machine (plain cargo also works)." >&2
    exit 2
fi
case "$LANE" in *[!A-Za-z0-9_-]*|"") echo "x: LOOM_LANE must be [A-Za-z0-9_-]+" >&2; exit 2 ;; esac

# A binary copied across machines must be re-signed ad-hoc or Gatekeeper SIGKILLs it on launch.
resign() {
    if command -v codesign >/dev/null; then codesign --force --sign - "$1" 2>/dev/null || true; fi
}

if [ "$HOST" = "local" ]; then
    cd "$ROOT" || exit 2
    if [ "${1:-}" = "--pull-bin" ]; then
        cargo build --release -p loom-daemon || exit $?
        mkdir -p "$ROOT/bin"
        cp "$ROOT/target/release/loom" "$ROOT/bin/loom" || exit 91
        resign "$ROOT/bin/loom"
        ls -la "$ROOT/bin/loom"
        exit 0
    fi
    exec cargo "$@"
fi

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")

push() {
    "${SSH[@]}" "mkdir -p \$HOME/$REMOTE/src-$LANE" || return 89
    rsync -a --delete \
        --exclude '/target' --exclude '/.git' --exclude '/.claude' --exclude '/bin' --exclude '.DS_Store' \
        "$ROOT/" "$HOST:$REMOTE/src-$LANE/" || return 90
}
remote() {
    "${SSH[@]}" "cd \$HOME/$REMOTE && \
        if [ ! -d target-$LANE ] && [ -d target-main ]; then cp -Rc target-main target-$LANE 2>/dev/null || true; fi; \
        ulimit -n 16384 2>/dev/null; cd src-$LANE && export PATH=\$HOME/.cargo/bin:\$PATH MACOSX_DEPLOYMENT_TARGET=13.0 CARGO_TERM_COLOR=never \
        CARGO_TARGET_DIR=\$HOME/$REMOTE/target-$LANE && $1"
}
pull_lock() {
    local tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/x-lock.XXXXXX")" || return 0
    if rsync -a "$HOST:$REMOTE/src-$LANE/Cargo.lock" "$tmp" 2>/dev/null && [ -s "$tmp" ] && ! cmp -s "$tmp" "$ROOT/Cargo.lock"; then
        cp "$tmp" "$ROOT/Cargo.lock" && echo "x: Cargo.lock was updated from the build host." >&2
    fi
    rm -f "$tmp"
}

push
rc=$?
if [ "$rc" -eq 89 ]; then
    echo "x: cannot reach $HOST over ssh (key-based login without prompts is required). Check the host name, the network and your ssh key, or set LOOM_BUILD_HOST=local." >&2
    exit 89
elif [ "$rc" -ne 0 ]; then
    echo "x: rsync to $HOST failed. Check that rsync is installed on both machines and that $HOST has free disk space." >&2
    exit 90
fi

if [ "${1:-}" = "--pull-bin" ]; then
    remote "cargo build --release -p loom-daemon" || exit $?
    mkdir -p "$ROOT/bin"
    rsync -a "$HOST:$REMOTE/target-$LANE/release/loom" "$ROOT/bin/loom" || exit 91
    resign "$ROOT/bin/loom"
    pull_lock
    ls -la "$ROOT/bin/loom"
    exit 0
fi

args=""
for a in "$@"; do args="$args $(printf '%q' "$a")"; done
remote "cargo$args"
rc=$?
pull_lock
exit $rc
