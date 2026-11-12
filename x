#!/bin/bash
# x — run cargo for this repo on the build host, so the operator's machine stays idle.
#
#   ./x test -p loom-core                    run cargo there, output here
#   LOOM_LANE=tools ./x test -p loom-tools   private source copy + target dir (parallel work, no lock waits)
#   ./x --pull-bin                           build release and copy the `loom` binary to ./bin/loom
#   LOOM_BUILD_HOST=local ./x ...            run cargo right here instead
#
# The tree this script sits in is pushed with rsync before every run, to a directory that belongs to
# the lane. A new lane starts from a copy-on-write clone of the main lane's target dir, so it does not
# rebuild third-party crates. Cargo.lock is tracked; if the build host changes it, it is pulled back.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
HOST="${LOOM_BUILD_HOST:-512S1}"
LANE="${LOOM_LANE:-main}"
REMOTE="loom-build"

case "$LANE" in *[!A-Za-z0-9_-]*|"") echo "x: LOOM_LANE must be [A-Za-z0-9_-]+" >&2; exit 2 ;; esac

if [ "$HOST" = "local" ]; then
    cd "$ROOT" && exec cargo "$@"
fi

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")

push() {
    "${SSH[@]}" "mkdir -p \$HOME/$REMOTE/src-$LANE" || return 1
    rsync -a --delete \
        --exclude '/target' --exclude '/.git' --exclude '/.claude' --exclude '/bin' --exclude '.DS_Store' \
        "$ROOT/" "$HOST:$REMOTE/src-$LANE/"
}
remote() {
    "${SSH[@]}" "cd \$HOME/$REMOTE && \
        if [ ! -d target-$LANE ] && [ -d target-main ]; then cp -Rc target-main target-$LANE 2>/dev/null || true; fi; \
        ulimit -n 16384 2>/dev/null; cd src-$LANE && export PATH=\$HOME/.cargo/bin:\$PATH MACOSX_DEPLOYMENT_TARGET=13.0 CARGO_TERM_COLOR=never \
        CARGO_TARGET_DIR=\$HOME/$REMOTE/target-$LANE && $1"
}
pull_lock() {
    rsync -a "$HOST:$REMOTE/src-$LANE/Cargo.lock" "$ROOT/Cargo.lock" 2>/dev/null || true
}

push || { echo "x: rsync to $HOST failed" >&2; exit 90; }

if [ "${1:-}" = "--pull-bin" ]; then
    remote "cargo build --release -p loom-daemon" || exit $?
    mkdir -p "$ROOT/bin"
    rsync -a "$HOST:$REMOTE/target-$LANE/release/loom" "$ROOT/bin/loom" || exit 91
    # A binary copied across machines must be re-signed ad-hoc or Gatekeeper SIGKILLs it on launch.
    command -v codesign >/dev/null && codesign --force --sign - "$ROOT/bin/loom" 2>/dev/null || true
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
