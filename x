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
# In local mode --pull-bin takes the binary from $CARGO_TARGET_DIR (default ./target).
#
# The tree this script sits in is pushed with rsync before every run, to a directory that belongs to
# the lane. A new lane starts from a copy-on-write clone of the main lane's target dir, so it does not
# rebuild third-party crates. Cargo.lock is tracked; if the build host changes it, the changed file is
# copied back and one line says so.
#
# Exit codes of its own: 2 bad settings, 88 the build host was reached but the source directory could not
# be created there, 89 the build host cannot be reached over ssh, 90 rsync failed, 91 the binary could not
# be installed in ./bin. Any other code is cargo's.
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

# Install a built binary as ./bin/loom. The arguments are a copy command; the destination it is given is
# a file named `loom` in a fresh temporary directory inside ./bin. That copy is made executable and
# re-signed there and then renamed over ./bin/loom, so a daemon running from the old file is never
# rewritten in place.
install_bin() {
    local dir
    mkdir -p "$ROOT/bin" && dir="$(mktemp -d "$ROOT/bin/.install.XXXXXX")" || return 91
    if "$@" "$dir/loom" && chmod 755 "$dir/loom" && resign "$dir/loom" && mv -f "$dir/loom" "$ROOT/bin/loom"; then
        rmdir "$dir" 2>/dev/null
        ls -la "$ROOT/bin/loom"
        return 0
    fi
    rm -f "$dir/loom"
    rmdir "$dir" 2>/dev/null
    return 91
}

if [ "$HOST" = "local" ]; then
    cd "$ROOT" || exit 2
    if [ "${1:-}" = "--pull-bin" ]; then
        cargo build --release -p loom-daemon || exit $?
        built="${CARGO_TARGET_DIR:-$ROOT/target}/release/loom"
        if ! install_bin cp "$built"; then
            echo "x: could not copy $built to $ROOT/bin/loom. If cargo's target directory is configured elsewhere, set CARGO_TARGET_DIR to it and run again." >&2
            exit 91
        fi
        exit 0
    fi
    exec cargo "$@"
fi

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST")
ssh_rc=0

push() {
    "${SSH[@]}" "mkdir -p \$HOME/$REMOTE/src-$LANE"
    ssh_rc=$?
    # ssh exits 255 only when it cannot connect or log in; any other failure is the remote mkdir's.
    if [ "$ssh_rc" -eq 255 ]; then return 89; elif [ "$ssh_rc" -ne 0 ]; then return 88; fi
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
elif [ "$rc" -eq 88 ]; then
    echo "x: reached $HOST over ssh, but could not create ~/$REMOTE/src-$LANE there (remote exit $ssh_rc). Check the permissions of the home directory and the free disk space on $HOST." >&2
    exit 88
elif [ "$rc" -ne 0 ]; then
    echo "x: rsync to $HOST failed. Check that rsync is installed on both machines and that $HOST has free disk space." >&2
    exit 90
fi

if [ "${1:-}" = "--pull-bin" ]; then
    remote "cargo build --release -p loom-daemon" || exit $?
    if ! install_bin rsync -a "$HOST:$REMOTE/target-$LANE/release/loom"; then
        echo "x: could not copy the release binary from $HOST to $ROOT/bin/loom. Check the free disk space here and run again." >&2
        exit 91
    fi
    pull_lock
    exit 0
fi

args=""
for a in "$@"; do args="$args $(printf '%q' "$a")"; done
remote "cargo$args"
rc=$?
pull_lock
exit $rc
