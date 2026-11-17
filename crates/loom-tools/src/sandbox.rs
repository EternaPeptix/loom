//! The sandbox: one policy, applied to commands by the OS and to in-process file access by us.
//!
//! CONTRACT.
//!
//! ## Policy
//! - writable roots: the workspace, the session temp dir and `cfg.extra_writable`. System temp
//!   directories have no blanket write grant. Standard device literals remain writable;
//! - never writable, even inside a writable root: `<workspace>/.loom`, the loom home directory, the
//!   Git metadata of the next item, and `cfg.protected_paths` (relative entries are relative to the workspace). One exception: the
//!   session temp dir lies inside the loom home (`<loom home>/sessions/<id>/tmp`) and what is in it
//!   is writable all the same — but not the directory entry itself (it cannot be removed, renamed,
//!   replaced or made anew, yet tests as writable), and not a protected path that is the temp dir or
//!   lies inside it. A temp dir that is `/`, or is or contains the loom home, is refused at construction;
//! - Git metadata, so that a command cannot plant what Git runs as the operator (`core.fsmonitor` and the
//!   other commands a config names, hooks, a `commondir` or `gitdir` that points at a config of its own)
//!   on their next `git status`, commit or `git submodule update`, in the workspace, in a linked worktree
//!   outside it, or in a repository moved into place. In every writable root (the workspace, the session
//!   temp dir — the exception above does not reach it — and `cfg.extra_writable`), whether it exists yet or
//!   not, and comparing names as the volume folds case (APFS folds more than ASCII case: `ſ`, the Kelvin
//!   sign and the `ﬁ` ligature count as `s`, `k` and `fi`, so a name made with them is the same name):
//!   - no `.git` entry can be written, made, removed or renamed, nor, below one, `config`,
//!     `config.worktree`, `hooks`, `commondir` or `gitdir` (or anything below those) — of the repository,
//!     of a linked worktree's private gitdir (`.git/worktrees/<name>/…`) and of a submodule's repository
//!     (`.git/modules/<name>/…`, where `<name>` has one or more components; nested submodules'
//!     `…/modules/<name>/…` included);
//!   - nothing can be made or removed (renames included) at `.git/modules`, `.git/worktrees`, a direct child
//!     of either, or the same below `.git/modules/…/`: no rule judges what a directory moved into place
//!     holds, so a directory moved there would bring its own `config` and `hooks`;
//!   - for the same reason, below `.git/modules/<name>/` (and below the same in a submodule's repository)
//!     nothing can be made or removed except inside the repositories found there at construction, and inside
//!     those only outside their own `modules` and `worktrees` (which this rule covers in turn). A directory
//!     on the way to a repository that is not one (the `third_party` of a submodule named `third_party/x`) and
//!     a submodule repository made during the session (by the operator: it was not found) can neither be
//!     replaced nor have anything made in them; Git can write in the latter from the next session on. (The
//!     audit's review moved a copy carrying `core.fsmonitor` over a slash-named submodule's repository that
//!     the operator had set up mid-session, and the operator's next `git status` ran it.)
//!   - the hooks directory a repository's configuration names and the files it includes: `core.hooksPath`,
//!     `include.path` and `includeIf.<condition>.path` (whatever the condition), read from the `config` and
//!     `config.worktree` of every repository found and from the user's global configuration
//!     (`~/.gitconfig`, and `$XDG_CONFIG_HOME/git/config` or else `~/.config/git/config`), included files
//!     read in turn (at most 10 deep, each file once). A value is resolved as Git resolves it: `~/` from the
//!     home directory; a relative `hooksPath` from the top of the repository's working tree (the parent of a
//!     `.git` directory or of a linked worktree's `.git` file; for any other repository the repository
//!     itself); a relative include from the directory of the file that names it. Each one that lies in a
//!     writable root is a protected path (as written and as resolved), and so are `~/.gitconfig` and the
//!     `git` directory of the user's XDG configuration when they do. (Probed: with `core.hooksPath = .husky`
//!     a command wrote `.husky/post-checkout` and the operator's next checkout ran it.) These files are read
//!     without running Git: a syntax this reading does not understand protects nothing (a residual, in
//!     SECURITY.md, with the scripts a hook or a config names in the working tree, which stay writable).
//!
//!   Git's own writes still work in the workspace's repository and every existing submodule's: objects,
//!   refs, the index, `HEAD`, logs (not the configuration: `git branch --set-upstream-to` and the tracking of
//!   `git switch -c <b> <remote>/<b>` cannot be recorded). What a session cannot do, and must ask the operator
//!   for: `git init` or a clone that is not bare anywhere commands write (so are installs of dependencies
//!   from Git URLs by pip, npm, cargo or uv, which clone into the temp dir), `git worktree add`/`remove`/`prune`,
//!   and `git submodule add`/`init`/`update`/`deinit` (`update` of an initialized submodule too: it rewrites
//!   `core.worktree`); a bare repository, `<name>.git`, can be made and used with `--git-dir` and
//!   `--work-tree`. Existing repositories are found at construction without running Git or following a link
//!   to a directory: every directory in the workspace that is a repository (a regular file `HEAD` and an
//!   `objects` directory or a `commondir` file; a bare one included, and not searched further), every
//!   `.git` directory, and the target of every `.git` file's `gitdir:` when that target is a repository;
//!   then for each repository found, its `commondir` target (when it is a repository), every directory in its
//!   `worktrees`, and below its `modules` every directory that is a repository, whose own `worktrees` and
//!   `modules` are searched in turn. The `config`, `config.worktree`, `hooks`, `commondir` and `gitdir` of
//!   every repository found are protected paths, as found and as resolved, and Bubblewrap mounts every
//!   repository found read-only as a whole (`git_dirs`) — except one that is or contains the loom home or the
//!   user's home directory, which a pointer could otherwise name to mount what Bubblewrap hides back in (its
//!   private files stay protected). A directory of the workspace that cannot be read refuses construction with
//!   a sentence naming it; so do a pointer larger than 4096 bytes, more than 100000 workspace directories,
//!   and more than 4096 repositories and directories below `modules` together;
//! - mounting: commands cannot mount a file system over a directory: `file-mount` is denied, and so are the
//!   services that attach and mount disk images for a process, outside its sandbox
//!   (`com.apple.DiskArbitration.diskarbitrationd`, `com.apple.diskimagesiod`, `com.apple.diskimagesiod.ram`,
//!   `com.apple.diskmanagementd`). Probed on macOS 27: `hdiutil attach -mountpoint <dir>` of an image a
//!   command made mounted it over `.git/modules/<n>/hooks` (and over any directory the user owns: `~/.ssh`,
//!   `~/Library/LaunchAgents`, the loom home), and the operator's next Git command ran a hook from it; with
//!   these denied nothing is attached (`hdiutil attach` may still exit 0) and `diskutil` fails, while
//!   `hdiutil makehybrid` and `create` still work;
//! - preferences: commands cannot write a preference domain (`user-preference-write`): `cfprefsd` writes
//!   `~/Library/Preferences` for a process, outside its sandbox (probed: `defaults write <domain>` created the
//!   plist under a profile that denies writing there), and some preferences name a command another program
//!   runs as the operator (a terminal's startup command). Reading preferences is allowed;
//! - not readable: the whole loom home — its records, stored outputs, journals, logs, configuration,
//!   packs, `token` and `keys` among them — except the session temp dir and `<session dir>/analysis`, the
//!   harness's staging of binary-analysis inputs (readable, never writable; in an isolated replay: its
//!   staged workspace and temp instead), so a command or file tool cannot read another session's or its
//!   own log, a stored output, or an earlier mission's results, as Bubblewrap already hides the home. The
//!   loom home's own entry and each directory between it and those can be looked up (their metadata read)
//!   but not listed or read. Names are hidden as well as content: the home's files cannot be found by
//!   their file id (`fsgetpath`) or searched for by name (`searchfs`, denied everywhere as `file-search`),
//!   and only the direct children of those lookup directories (and what lies below a `node_modules` there,
//!   which loom never makes: npm and Node search `<ancestor>/node_modules/.bin` for commands) can be tested for existence — a missing one
//!   answers "no such file" (tools that walk up looking for `package.json`, `node_modules/.bin` or
//!   `pyproject.toml` treat any other error as fatal), one that exists still gives EPERM for its metadata
//!   and content; nothing deeper can be tested. A session's job output directory (`with_jobs_dir`; its commands' own stdout
//!   and stderr files are there) gives commands the metadata of what is in it and nothing more — `fstat` of an
//!   inherited descriptor is a metadata read, and without it `cat` fails and Python loses its output —
//!   so those files can be neither read nor listed. Also not readable: `<workspace>/.loom/oracle-secrets`,
//!   `cfg.unreadable_paths` (`~` expands to
//!   the home directory) and, unless `cfg.protect_credentials` is off, the user's credential stores
//!   (`CREDENTIAL_PATHS` under the home directory), their names hidden too. A credential store that is or contains the
//!   workspace is skipped, so the workspace stays readable; when the home directory is not known the
//!   stores cannot be located and construction is refused. A workspace that is or lies inside the loom
//!   home is refused at construction (only `isolated_replay` places one there). What is not readable is
//!   not writable either, wherever it lies (a command could otherwise rename it and read it under the new
//!   name); a hard link made where reads are allowed to a file that is not readable must not make it
//!   readable (test this on macOS: the profile is path-based);
//! - a directory where writes are allowed that holds a never-writable or not-readable path, or the
//!   session temp dir, cannot be removed or renamed, nor made as a link where it does not exist yet:
//!   that would carry what it holds out of its rule. A missing one can still be made by moving a
//!   directory into place, and a link already inside that directory then decides where a file
//!   written below it later from outside the sandbox lands;
//! - starting something outside the sandbox is denied: LaunchServices opens, Apple Events, launchd
//!   jobs;
//! - network: denied, except loopback connections to the egress proxy port (when there is one), to
//!   `cfg.loopback_ports` — or to every loopback port when `cfg.loopback_all` — and to
//!   `cfg.unix_sockets`. Listening on loopback is allowed. The daemon's own port (`cfg.daemon_port`, which
//!   the daemon sets; not a configuration key) is refused whatever allows it, at every address: Seatbelt
//!   counts the host's own addresses as loopback, and a command that read a `loom open` login code from the
//!   process list could otherwise redeem it. (Probed on macOS 27: after an allow of `(remote ip
//!   "localhost:*")` a deny of one port, written `localhost:<port>` or `*:<port>`, is not reliable — about two
//!   ports in five stay connectable, the same port every time — so with `cfg.daemon_port` the allow for
//!   `loopback_all` is written for TCP and UDP, `(remote tcp "localhost:*") (remote udp "localhost:*")`
//!   (loopback ICMP is not allowed then); with that allow, and with allows of single ports, a deny of
//!   `*:<port>` refused 127.0.0.1, ::1 and the host's own address on every port tried.)
//! - system services that fetch a URL for a process, outside its sandbox: when `[network] mode` is
//!   `deny_all` (`cfg.network_deny_all`, which the runtime sets; not a configuration key) commands cannot
//!   look up `com.apple.trustd.agent`, `com.apple.trustd`, `com.apple.ocspd`, `com.apple.nsurlsessiond` or
//!   `com.apple.nsurlsessiond.NSURLSessionProxyService`, nor WebKit's XPC services (`com.apple.WebKit.*`):
//!   probed on macOS 27, a background URL session started from `osascript -l JavaScript` and a `WKWebView`
//!   made there each fetched a URL from a listener the profile does not allow; denied, nothing arrives, and
//!   background URL sessions and WebKit-based tools fail. Certificate evaluation
//!   fetches the issuer a certificate names (its AIA `caIssuers` URL, which a command chooses), with DNS,
//!   through `com.apple.trustd.agent`: probed on macOS 27 with `security verify-cert -p ssl` under
//!   `(deny network*)`, the request reaches a listener unless that service is denied (denying
//!   `com.apple.trustd` alone does not stop it); `ocspd` is the older service for the same fetches. Denied,
//!   evaluation through Security.framework fails for every certificate, valid ones too
//!   (`SecTrustEvaluateWithError` returns false, errSecInternalComponent, so it fails closed), and so does
//!   `codesign --verify`; curl, Python and OpenSSL check certificates against their own files and are not
//!   affected. In the other network modes these services stay reachable: a residual, in SECURITY.md.
//!
//! All paths are made canonical when the sandbox is built (macOS: `/tmp` is `/private/tmp`); a
//! configured path that does not exist is kept as written after resolving its deepest existing
//! ancestor. On macOS, where volumes are case-insensitive by default, the rules that refuse (never
//! writable, not readable) are compared without regard to case; the rules that allow are compared
//! exactly, as they are everywhere else. A not-readable path that a link along it makes differ from
//! its canonical form is denied as written too, so the link cannot be swapped for a directory of a
//! command's own. macOS also names the data volume's folders under `/System/Volumes/Data`, and `realpath`
//! keeps that prefix where it was written: a canonical path that has it is given its usual form back when
//! that names the very same file (same device and inode), so rules written in the usual form judge it;
//! `check_read`, `check_write`, construction and every other user of the canonical form get this.
//!
//! ## `profile()`
//! The seatbelt profile text, `None` in modes `none` and `bubblewrap`. This form is verified on macOS 27 — keep its
//! structure (later rules win):
//!
//! ```text
//! (version 1)
//! (allow default)
//! (deny signal)
//! (allow signal (target same-sandbox))
//! (deny file-write*)
//! (allow file-write* (subpath "<writable root>") …)
//! (deny file-write* (subpath "<protected>") …)
//! (allow file-write* (subpath "<session temp dir>"))
//! (deny file-write-unlink file-write-create (literal "<session temp dir>"))
//! (deny file-write* (subpath "<protected, at or inside the temp dir>") …)
//! (deny file-write* (require-all (require-any (subpath "<writable root>") …) (regex #"^.*/[.]git(/((worktrees/[^/]+|modules/(.+/)?[^/]+)/)?(config|config[.]worktree|hooks|commondir|gitdir)(/.*)?)?$")))
//! (deny file-write-create file-write-unlink (require-all (require-any (subpath "<writable root>") …) (regex #"^.*/[.]git/(modules/.+/)?(modules|worktrees)(/[^/]+)?$")))
//! (deny file-write-create file-write-unlink (require-all (require-any (subpath "<writable root>") …) (regex #"^.*/[.]git/(modules/.+/)?modules/[^/]+/.+$") (require-not (require-all (subpath "<repository found below a modules directory>") (require-not (subpath "<it>/modules")) (require-not (subpath "<it>/worktrees")))) …))
//! (deny file-write* (subpath "<unreadable or credential store>") …)
//! (deny file-read* file-test-existence (subpath "<unreadable or credential store>") …)
//! (deny file-read* file-test-existence (subpath "<loom home>"))
//! (allow file-read-metadata file-test-existence (literal "<loom home>") (literal "<each directory between it and the session temp dir>") …)
//! (allow file-test-existence (regex #"^<each of those directories>/[^/]+$") (regex #"^<same>/node_modules/") …)   ; a missing name gives ENOENT, not EPERM
//! (allow file-read* file-test-existence (subpath "<session temp dir>") (subpath "<session dir>/analysis"))   ; a replay: its staged workspace and temp
//! (deny file-read* file-test-existence (subpath "<unreadable path in the home, or at, inside or around those>") …)
//! (allow file-read-metadata (subpath "<session dir>/jobs"))      ; only with `with_jobs_dir`: metadata, never content
//! (deny file-write-unlink (literal "<writable directory that holds one of the above>") …)
//! (deny file-write-create (require-all (vnode-type SYMLINK) (require-any (literal "<same directory>") …)))
//! (deny lsopen)
//! (deny appleevent-send)
//! (deny job-creation)
//! (deny file-search)
//! (deny file-mount)
//! (deny user-preference-write)
//! (deny mach-lookup (global-name "com.apple.DiskArbitration.diskarbitrationd") (global-name "com.apple.diskimagesiod") (global-name "com.apple.diskimagesiod.ram") (global-name "com.apple.diskmanagementd"))
//! (deny network*)
//! (allow network-outbound (remote ip "localhost:<port>")) …      ; or "localhost:*" for loopback_all (with
//!                                                                 ; `cfg.daemon_port`: `(remote tcp "localhost:*") (remote udp "localhost:*")`)
//! (allow network-outbound (remote unix-socket (path-literal "<socket>"))) …
//! (deny network-outbound (remote ip "*:<daemon port>"))          ; only with `cfg.daemon_port`
//! (allow network-bind (local ip "localhost:*"))
//! (allow network-inbound (local ip "localhost:*"))
//! (deny mach-lookup (global-name "com.apple.trustd.agent") (global-name "com.apple.trustd") (global-name "com.apple.ocspd") (global-name "com.apple.nsurlsessiond") (global-name "com.apple.nsurlsessiond.NSURLSessionProxyService") (xpc-service-name-prefix "com.apple.WebKit."))   ; only with `cfg.network_deny_all`
//! ```
//!
//! The Git regexes are written with every letter as a class of both cases (`[gG][iI][tT]`) and, where the
//! volume folds other characters to it, an alternation that adds them: `(s|S|ſ)`, `(k|K|K)` (U+212A)
//! and, for the two letters of `config`, `([fF][iI]|ﬁ)`. On macOS 27 Seatbelt was probed to match a path
//! as the volume folds it already (a regex or subpath written in lower case refuses `MODULES`, `moduleſ` and
//! `conﬁg`), so in the profile this is defence in depth against a version that does not; the file tools'
//! own `check_write` compares names with the same fold, and before it did, `write` could make
//! `.git/moduleſ/<n>/hooks/<hook>`, which Git then reads as `.git/modules/<n>/hooks/<hook>`. The writable
//! roots in them are those of `writable`, in its order. The exceptions of the third Git rule are the
//! repositories found below a `modules` directory, sorted (none: no `require-not`). Probed on macOS 27: the
//! nested `require-not` keeps commits in found submodules, nested ones included, working while a name below
//! `modules` outside them, or inside their own `modules`, cannot be made or moved.
//!
//! A process that leaves its command's process group (`setsid`, `daemon()`, `redis-server --daemonize
//! yes`, `tmux new -d`) is not tracked: `job_kill`, stop, the end of the session and daemon shutdown do
//! not stop it, although it stays under this profile.
//!
//! A sandboxed process can signal itself and the other processes of its sandbox, and nothing else:
//! not the harness, not other sessions, not any other process of the same user.
//!
//! `file-write-unlink` covers removing and renaming an entry, and renaming or swapping
//! (`renamex_np(RENAME_SWAP)`) another entry onto it; `file-write-create` covers making one where there
//! is none (a link, a rename, a clone). The other writes stay allowed, so `test -w "$TMPDIR"` holds,
//! and the tools that check the temp dir with `access(2)` before they use it (bash's heredocs among
//! them) put their files there.
//!
//! Paths are written as SBPL string literals: `\` and `"` are backslash-escaped; a path containing a
//! control character is an error at construction.
//!
//! ## `command(script)`
//! The program and arguments that run `script` with `/bin/bash -c`: in seatbelt mode
//! `/usr/bin/sandbox-exec -p <profile> /bin/bash -c <script>`; in mode `none`, `/bin/bash -c <script>`.
//! Linux `bubblewrap` uses the read-only/masked mounts and seccomp deny-all network policy in `linux`.
//! It requires an executable bwrap and refuses host proxy/loopback/socket grants, with no fallback.
//!
//! ## `check_read(path)` / `check_write(path)`
//! The same policy for the file tools, which run in this process. `path` must be absolute. The path
//! is resolved through symlinks (canonicalise the deepest existing ancestor, then append the rest;
//! `..` components that remain are an error) and the *resolved* path is tested, so a symlink inside
//! the workspace that points outside it does not grant access. Returns the resolved path, or a
//! sentence: which path, which rule refused it, and what is allowed (for writes, the writable roots).
//! `check_write` lets the session temp dir through the never-writable rules, as the profile does, and
//! refuses what is not readable and the temp dir entry itself wherever they lie. `check_read` refuses
//! everything under the loom home except the session temp dir and the analysis staging dir (a replay: its
//! staged workspace and temp), naming the loom home and what is readable as the reason without echoing what
//! lies there; in mode `none` the sentence says the file tools cannot read it, as commands are not confined. In mode `none` only
//! the never-writable and not-readable rules apply (the loom home rule included: it is the file tools'
//! own rule in that mode).
//!
//! `check_write` applies the Git rules of the policy as the profile does — in every mode, to the path as
//! given and as resolved, each judged relative to the writable root it lies in (the workspace when it lies
//! in none) — and treats every write as making the entry, since the file tools write by renaming a new file
//! into place. Its refusal says that the path is Git metadata that commands and file tools may not write or
//! create anywhere they write, because Git could run what it holds as the operator; that the operator is
//! the one to change repository configuration, add a worktree or set up a submodule
//! (`git worktree add`, `git submodule update --init`); and that a repository of the session's own can be
//! cloned bare (`git clone --bare <url> <dir>.git`) and used with `git --git-dir=<dir>.git --work-tree=<dir>`.
//!
//! ## `oracle_staging_root()` / `isolated_replay(workspace, tmp)`
//! Staging is `<loom home>/oracle-runs`, outside all session temp trees. The harness creates a private
//! random child with workspace/tmp siblings. Both must already exist under that protected root and
//! outside caller write grants. `none` is refused. The replay workspace is read-only and only its
//! separate temp is writable. Existing read/credential/network restrictions remain; Linux sources
//! are repinned. All prior workspace/temp/extra writable origins and `<loom home>/sessions` become
//! unreadable, including future sibling temp paths, so an interpreter cannot load actor-modified
//! originals instead of pinned copies. Inside the loom home only the staged workspace and temp are
//! readable (the caller's session temp dir is not). Read-only roles retain removed global extra writable paths
//! as internal metadata for this exclusion; normal verifier reads are unchanged. Any origin that
//! contains staging is refused, rather than allowing read exceptions inside an untrusted tree.
//! Linux refuses missing origins outside an already hidden private parent.
//!
//! ## `resolve(given)`
//! A path as the model wrote it → absolute: `~`/`~/x` expand to the home directory, a relative path
//! is joined to the workspace. No file-system access.
//!
//! ## `env(parent)`
//! The environment for commands: `parent` (the daemon's own variables) without any whose name
//! (case-insensitive) contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASSWD`, `PASSPHRASE`,
//! `CREDENTIAL`, `AUTH_TOKEN`, `COOKIE`, `SESSION_KEY` or `PRIVATE`, has `SESSION`, `AUTH`, `PASS`,
//! `JWT` or `WEBHOOK` as a part delimited by `_` or the ends of the name, ends in `_PAT`, `_DSN`,
//! `_PWD` or `_PW` (`PWD` and `OLDPWD` stay), is `DATABASE_URL`, `SSH_AUTH_SOCK` or listed in
//! `cfg.secret_env` (the `api_key_env` of every model profile), or starts with `LOOM_`, and without
//! any whose value holds a URL with a password in its user-info part (`scheme://user:password@host`):
//! every `://` in the value starts an authority that ends at `/`, `?`, `#`, `"`, `]` or white space.
//! A variable listed in `cfg.env_pass` is passed whatever its name and value. Bubblewrap additionally
//! always removes LD_*, DYLD_*, BASH_FUNC_*, BASH_ENV, ENV, SHELLOPTS and BASHOPTS before its trusted
//! host launcher; tools can set needed library variables inside the confined script. Added: `TERM=dumb`,
//! `NO_COLOR=1`, `PAGER=cat`, `GIT_PAGER=cat`, `GIT_TERMINAL_PROMPT=0`, `TMPDIR=<session temp dir>`.
//!
//! ## `describe()`
//! Two or three plain sentences for the system prompt: where commands may write, what they may not
//! read (loom's own files other than the session temp dir and the analysis staging dir, and credential
//! stores when protected), how network access works. Deterministic. In
//! mode `none` it says commands are not confined and what the file tools still refuse: the rule about loom's
//! own files is worded as the file tools' (`File tools also refuse to read loom's own files under …`), not
//! as one that binds commands. In seatbelt mode it also says that no Git repository can be made where
//! commands write and no Git configuration, hooks, worktree or submodule repository written, that the
//! operator does `git worktree add` and `git submodule update --init`, and that a bare clone
//! (`git clone --bare <url> <dir>.git`, used with `--git-dir`/`--work-tree`) works; and, with
//! `cfg.network_deny_all`, that programs that check certificates through macOS (Swift and Go programs,
//! `security`, `codesign --verify`) fail here, while curl and Python use their own certificate files, and
//! that WebKit-based tools and background URL sessions fail. In seatbelt mode it also says, in one sentence,
//! that `git submodule update` (any form) is the operator's, that upstream tracking cannot be recorded, that
//! dependencies from Git URLs (pip, npm, cargo, uv) cannot be installed (an archive URL can), that disk
//! images cannot be mounted (extract them instead) and that preferences cannot be written (`defaults write`).
//!
//! ## `preflight(cfg)`
//! Whether the configured mode can work on this host: seatbelt needs macOS and an executable
//! `/usr/bin/sandbox-exec`; bubblewrap needs Linux and `/usr/bin/bwrap`, without socket grants. The error is a sentence naming the problem and the alternatives; the
//! daemon refuses to start with it.
//!
//! Tests required: profile text for a representative config (exact string); escaping; canonical
//! paths; `check_write`/`check_read` accept and refuse per rule, including a symlink escape, a
//! not-yet-existing file in a writable dir, `..`, and the protected directory inside the workspace;
//! mode `none`; `resolve`; `env` scrubbing and `env_pass`; `check_read` refuses, in every mode, the
//! session's own and another session's `log.jsonl`, a stored output under `blobs/`, a mission journal,
//! `logs/`, `config.toml`, an installed pack, a listing of `<loom home>/sessions`, and a workspace
//! symlink that resolves into the loom home, while a file in the session temp dir is accepted; a
//! replay accepts its staged workspace and temp and refuses the caller's temp dir; a workspace inside
//! the loom home is refused at construction. Tests that execute `sandbox-exec` are
//! welcome when `/usr/bin/sandbox-exec` exists (skip otherwise): a write inside the workspace
//! succeeds, a write outside fails, a read of an unreadable path fails; `cat` of a session log, a blob
//! and `config.toml` and `ls` of `<loom home>/sessions` fail; in `$TMPDIR` a file can be written and
//! read back, `mkdir -p` and `cd` + `pwd -P` work; a hard link from `$TMPDIR` to a file under the
//! loom home (and to a credential store file) is refused or reads nothing; a command that asks the kernel for
//! the paths under the loom home by file id (`fsgetpath`) finds only the home, the directories down to the temp
//! dir and what is in it; through the production layout `cat`, `printf x | cat` and `python3 -c 'print(1)'`
//! keep their output, while `cat` and `ls` of the jobs directory fail; `check_read` and construction judge
//! a path written through `/System/Volumes/Data` as the plain one; the analysis staging dir is readable and
//! not writable; the `check_read` test also builds a Bubblewrap sandbox where that is possible.
//!
//! Git (built with real `git` where it runs, skipped otherwise, beside `check_write` cases on hand-made trees):
//! construction finds an external linked worktree's `.git/worktrees/<n>`, an initialized and a deinitialized
//! submodule's `.git/modules/<n>`, a submodule named `third/party` (with `third` recorded as not a repository),
//! and a nested submodule's `.git/modules/<a>/modules/<b>`, and gives them to Bubblewrap as `git_dirs`;
//! `check_write` refuses, in the workspace and in the temp dir, `commondir`, `gitdir` and `config.worktree` of
//! a worktree's gitdir, `config` and `hooks/post-checkout` of each of those submodules, `.git/modules/<new>`,
//! `.git/modules/<new>/hooks/x`, `.git/worktrees/<new>`, `.git/modules/third/<new>`, `<tmp>/x/.git` and
//! `<tmp>/x/.git/config`, each refusal naming the operator and the bare clone, and accepts `objects/` and
//! `refs/heads/` paths of the workspace's and the submodules' repositories, `<tmp>/x.git/config` and
//! `<tmp>/x.git/hooks/h`; and refuses every spelling the volume folds to a Git name (`.git/moduleſ/x/hooks`,
//! `.git/hooKs` with the Kelvin sign, `.git/hookſ`, `.git/conﬁg.worktree`, `.git/worktreeſ/w`, capitals included),
//! where the profile's two regexes (matched with the `regex` crate) and `git_metadata`/`git_container` agree on
//! each of them and on names that are none of theirs. Under `sandbox-exec`: each of those writes fails, as does making
//! `.git/moduleſ/x/hooks`, a Kelvin-sign `hooks` where `hooks` is missing and `.git/conﬁg.worktree`, in a repository
//! that has none of those names yet, while `.git/conﬂg` (a ligature that is not `fi`) can be made, and as does making
//! `.git/modules/<new>/hooks` with `mkdir -p`; moving a directory from `$TMPDIR` to `.git/modules/<new>`,
//! `.git/worktrees/<new>`, `.git/modules/third/<new>` and `.git/modules/<sub>/modules`; renaming `.git/modules`
//! and `.git/modules/<sub>` away; `git init` in `$TMPDIR`; and moving a bare repository to `$TMPDIR/<d>/.git` —
//! while a commit and a new branch in the workspace, in a submodule and in `third/party`, and
//! `git init --bare $TMPDIR/x.git`, succeed. End to end, with the operator's `git` run outside the sandbox
//! afterwards: a command that points the external worktree's `commondir` at a config of its own that sets
//! `core.fsmonitor`, or that moves a repository with such a config into the workspace and adds a gitlink for
//! it, does not make `git status` (in the worktree, in the workspace) run that command (a marker file it would
//! make stays absent; the same steps without the profile make it, or the test is skipped).
//!
//! Git, second round (the audit review's reproductions, each failing without its rule): with a slash-named
//! submodule `lib/foo` set up after construction (by the test, outside the sandbox), moving its repository
//! away and a copy that sets `core.fsmonitor` into its place fails, as does making anything in it, and the
//! operator's `git status` runs nothing; a found nested submodule's `modules/<a>/<c>` cannot be made while
//! objects in found submodules (nested ones too) and `.git/refs/heads/modules/x/y` in the workspace can;
//! `check_write` agrees on each. With `core.hooksPath = .husky` in the repository's config (and, in another
//! case, set through a file the config includes, and in a global config given by `HOME`/`XDG_CONFIG_HOME`),
//! `.husky/post-checkout` is a protected path and cannot be written by `check_write` or under the profile; a
//! value in quotes, with `~/`, and relative to a linked worktree's top are resolved as Git does; an include
//! cycle is read once. A bare repository the operator made in the workspace (`fixtures/remote.git`) is found
//! and its `hooks/pre-receive` cannot be written. A `.git` file whose `gitdir:` names a directory that is not a
//! repository (the user's home) and a `commondir` of `../../..` add nothing to `git_dirs`, and a repository
//! that contains the loom home is not in `git_dirs`. A workspace directory that cannot be read refuses
//! construction with a sentence that names it.
//!
//! Mounting and preferences (under `sandbox-exec`): `hdiutil attach -nobrowse -mountpoint <dir>` of an image
//! made with `hdiutil makehybrid` mounts nothing (checked with `mount`, as `hdiutil` may exit 0), and
//! `defaults write <unique domain> k v` leaves no value (read back outside the sandbox), while
//! `defaults read -g` works; without these rules both succeed (or the test is skipped).
//!
//! Network: the profile has the daemon-port deny after the allows exactly when `cfg.daemon_port` is set, and
//! the `mach-lookup` deny exactly when `cfg.network_deny_all`. Under `sandbox-exec`: with `loopback_all`, and
//! with the daemon port listed in `loopback_ports`, a connection to that port fails at 127.0.0.1 and ::1 (and
//! at the host's own address when it has one) while another loopback port still connects; a command that runs
//! `security verify-cert -p ssl` on a certificate whose AIA `caIssuers` names a unique URL on a local
//! listener makes no request reach it with `network_deny_all`, and does without it (otherwise skipped: the
//! host does not fetch); with `network_deny_all` the profile has the nsurlsessiond and WebKit denies too, and a
//! background URL session started from `osascript -l JavaScript` gets no request to a local listener the
//! profile does not allow (skipped when it does not reach it without them); `describe` says what is said above.

mod linux;

use loom_core::config::{SandboxCfg, SandboxMode};
use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};

const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// Device files commands may write to (redirections and pipes need these).
const DEVICE_LITERALS: [&str; 3] = ["/dev/null", "/dev/tty", "/dev/dtracehelper"];

const BWRAP: &str = "/usr/bin/bwrap";

const SECRET_WORDS: [&str; 10] =
    ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PASSPHRASE", "CREDENTIAL", "AUTH_TOKEN", "COOKIE", "SESSION_KEY"];
const SECRET_SUFFIXES: [&str; 4] = ["_PAT", "_DSN", "_PWD", "_PW"];
const SECRET_NAMES: [&str; 2] = ["DATABASE_URL", "SSH_AUTH_SOCK"];
/// Words that withhold a variable when they are a whole `_`-delimited part of its name.
const SECRET_PARTS: [&str; 5] = ["SESSION", "AUTH", "PASS", "JWT", "WEBHOOK"];

/// Credential stores, relative to the user's home directory, that commands and file tools may not read.
const CREDENTIAL_PATHS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gh",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".docker/config.json",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".git-credentials",
    ".config/git/credentials",
    ".password-store",
    ".config/op",
    ".cache/huggingface",
    ".huggingface",
    ".pgpass",
    ".my.cnf",
    ".mylogin.cnf",
    ".vault-token",
    ".terraform.d",
    ".config/rclone",
    ".s3cfg",
    ".boto",
    ".gem/credentials",
    ".m2/settings.xml",
    ".m2/settings-security.xml",
    ".gradle/gradle.properties",
    ".yarnrc.yml",
    ".composer/auth.json",
    ".codex/auth.json",
    ".claude.json",
    ".claude/.credentials.json",
    ".config/github-copilot",
    ".config/hub",
    ".config/glab-cli",
    ".oci",
    ".config/doctl",
    ".fly/config.yml",
    ".config/heroku",
    ".heroku",
    ".config/netlify",
    ".config/sops",
    ".age",
    ".config/age",
    ".bitcoin",
    ".ethereum",
    ".config/solana",
    ".wrangler",
    ".config/.wrangler",
    ".pulumi/credentials.json",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Google/Chrome Beta",
    "Library/Application Support/Google/Chrome Canary",
    "Library/Application Support/Chromium",
    "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Arc",
    "Library/Application Support/Vivaldi",
    "Library/Application Support/com.operasoftware.Opera",
    "Library/Application Support/Firefox",
    "Library/Application Support/Bitwarden",
    "Library/Application Support/Bitwarden CLI",
    "Library/Containers/com.bitwarden.desktop",
    "Library/Application Support/1Password",
    "Library/Application Support/Telegram Desktop",
    "Library/Application Support/Claude/claude_desktop_config.json",
    // Where tools that also keep an XDG location above store their logins on macOS.
    "Library/Application Support/doctl",
    "Library/Application Support/sops",
    "Library/Preferences/netlify",
    "Library/Preferences/.wrangler",
    "Library/Group Containers",
    "Library/Mail",
    "Library/Messages",
    "Library/Safari",
];

#[derive(Clone, Debug)]
pub struct Sandbox {
    mode: SandboxMode,
    linux_filter: Option<PathBuf>,
    linux_pins: Vec<linux::PinnedPath>,
    /// Every repository found at construction (read-only to Bubblewrap as a whole).
    git_dirs: Vec<PathBuf>,
    /// The repositories found below a `modules` directory: what the third Git rule leaves out.
    git_modules: Vec<PathBuf>,
    workspace: PathBuf,
    loom_home: PathBuf,
    oracle_staging_root: PathBuf,
    tmp_dir: PathBuf,
    /// An isolated replay: inside the loom home its staged workspace and temp are readable, not the temp dir alone.
    replay: bool,
    /// `<session dir>/analysis`: where the harness stages the files that binary-analysis backends read. Readable
    /// (never writable) to the session's commands when it lies inside the loom home; not in a replay.
    analysis_dir: PathBuf,
    /// The session's job-output directory when it lies inside the loom home: commands can take the metadata of
    /// what is in it (their own stdout and stderr files live there), never read or list it.
    jobs_dir: Option<PathBuf>,
    home: Option<PathBuf>,
    writable: Vec<PathBuf>,
    replay_untrusted: Vec<PathBuf>,
    protected: Vec<PathBuf>,
    unreadable: Vec<PathBuf>,
    credentials: Vec<PathBuf>,
    loopback_ports: Vec<u16>,
    loopback_all: bool,
    /// The daemon's own port, refused whatever else allows it.
    daemon_port: Option<u16>,
    /// Commands cannot reach the system services that fetch a URL for a process (certificate evaluation).
    network_deny_all: bool,
    unix_sockets: Vec<PathBuf>,
    env_pass: Vec<String>,
    secret_env: Vec<String>,
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

/// The files of a Git directory that name what Git runs or where its configuration is.
const GIT_PRIVATE: [&str; 5] = ["config", "config.worktree", "hooks", "commondir", "gitdir"];

/// Characters that the volume (APFS, the macOS default) takes for an ASCII letter besides its two cases: the long s
/// and the Kelvin sign. Probed on macOS 27; `char::to_lowercase` maps the Kelvin sign already, the long s it does not.
const FOLD_LETTERS: [(char, char); 2] = [('\u{17f}', 's'), ('\u{212a}', 'k')];

/// Characters that the volume takes for a run of ASCII letters (the sharp s and the Latin ligatures). The dotted and
/// dotless i, the fullwidth letters and the zero-width characters are not folded.
const FOLD_EXPANDS: [(char, &str); 9] = [
    ('\u{df}', "ss"),
    ('\u{1e9e}', "ss"),
    ('\u{fb00}', "ff"),
    ('\u{fb01}', "fi"),
    ('\u{fb02}', "fl"),
    ('\u{fb03}', "ffi"),
    ('\u{fb04}', "ffl"),
    ('\u{fb05}', "st"),
    ('\u{fb06}', "st"),
];

/// `name` as the volume compares it: lower case, with the characters of `FOLD_LETTERS` and `FOLD_EXPANDS` replaced
/// by the ASCII they stand for. Two names that name the same entry have the same fold; so does the ASCII name.
fn fold(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars().flat_map(char::to_lowercase) {
        if let Some((_, to)) = FOLD_LETTERS.iter().find(|(from, _)| *from == c) {
            out.push(*to);
        } else if let Some((_, to)) = FOLD_EXPANDS.iter().find(|(from, _)| *from == c) {
            out.push_str(to);
        } else {
            out.push(c);
        }
    }
    out
}

/// The folded names of `path` below `root`, when it lies in it.
fn names_below(path: &Path, root: &Path) -> Option<Vec<String>> {
    if !under(path, root) {
        return None;
    }
    let names = path.components().skip(root.components().count());
    Some(names.map(|c| fold(&c.as_os_str().to_string_lossy())).collect())
}

/// The SBPL regex text that matches `text` (a lower-case name) however the volume spells it, character by
/// character: a letter is both its cases and every character that folds to it (`(s|S|ſ)`), and a run of letters that
/// a character folds to is that run or the character (`([fF][iI]|ﬁ)`), over the whole stretch where such runs overlap.
fn fold_regex(text: &str) -> String {
    let chars: Vec<char> = text.chars().map(|c| c.to_ascii_lowercase()).collect();
    let mut out = String::new();
    let mut at = 0_usize;
    while at < chars.len() {
        let end = fold_span_end(&chars, at);
        let spellings = fold_spellings(chars.get(at..end).unwrap_or_default());
        match spellings.as_slice() {
            [one] => out.push_str(one),
            many => {
                out.push('(');
                out.push_str(&many.join("|"));
                out.push(')');
            }
        }
        at = end;
    }
    out
}

/// Where the stretch that starts at `at` and holds every run a folding character stands for ends (after `at`).
fn fold_span_end(chars: &[char], at: usize) -> usize {
    let mut end = at.saturating_add(1);
    let mut p = at;
    while p < end {
        for (_, to) in FOLD_EXPANDS {
            let to: Vec<char> = to.chars().collect();
            if chars.get(p..).is_some_and(|rest| rest.starts_with(&to)) {
                end = end.max(p.saturating_add(to.len()));
            }
        }
        p = p.saturating_add(1);
    }
    end.min(chars.len())
}

/// Every way to spell `chars` (lower-case ASCII), each as the regex text of the spelling.
fn fold_spellings(chars: &[char]) -> Vec<String> {
    let Some((&first, rest)) = chars.split_first() else { return vec![String::new()] };
    let head = fold_letter(first);
    let mut out: Vec<String> = fold_spellings(rest).into_iter().map(|tail| format!("{head}{tail}")).collect();
    for (from, to) in FOLD_EXPANDS {
        let to: Vec<char> = to.chars().collect();
        if chars.starts_with(&to) {
            let after = chars.get(to.len()..).unwrap_or_default();
            out.extend(fold_spellings(after).into_iter().map(|tail| format!("{from}{tail}")));
        }
    }
    out
}

/// The regex text for one character: a letter in both cases and every character that folds to it, else itself.
fn fold_letter(c: char) -> String {
    if c.is_ascii_alphabetic() {
        let upper = c.to_ascii_uppercase();
        let others: String =
            FOLD_LETTERS.iter().filter(|(_, to)| *to == c).map(|(from, _)| format!("|{from}")).collect();
        if others.is_empty() {
            format!("[{c}{upper}]")
        } else {
            format!("({c}|{upper}{others})")
        }
    } else if c.is_ascii_alphanumeric() {
        c.to_string()
    } else {
        format!("[{c}]")
    }
}

/// Git metadata that cannot be written, made, removed or renamed, at locations that do not exist yet as well,
/// as `path` lies below the writable root `root`: any `.git` entry, and below one the `config`,
/// `config.worktree`, `hooks`, `commondir` and `gitdir` of the repository, of a linked worktree's gitdir
/// (`worktrees/<name>/…`) and of a submodule's repository (`modules/<name>/…`, nested ones included). Names are
/// compared as the volume folds case (`fold`). The profile's first Git rule says the same.
fn git_metadata(path: &Path, root: &Path) -> bool {
    let Some(names) = names_below(path, root) else { return false };
    let private = |name: &String| GIT_PRIVATE.contains(&name.as_str());
    names.iter().enumerate().any(|(i, name)| {
        if name != ".git" {
            return false;
        }
        let rest = names.get(i.saturating_add(1)..).unwrap_or_default();
        match rest.first().map(String::as_str) {
            None => true,
            Some(first) if GIT_PRIVATE.contains(&first) => true,
            Some("worktrees") => rest.get(2).is_some_and(private),
            Some("modules") => rest.iter().skip(2).any(private),
            Some(_) => false,
        }
    })
}

/// Entries that cannot be made or removed (renames included) because no rule judges what a directory moved
/// there holds: `.git/modules`, `.git/worktrees`, a direct child of either, and the same below
/// `.git/modules/<name>/`. The profile's second Git rule says the same.
fn git_container(path: &Path, root: &Path) -> bool {
    let Some(names) = names_below(path, root) else { return false };
    let container = |name: &String| name == "modules" || name == "worktrees";
    names.iter().enumerate().any(|(i, name)| {
        if name != ".git" {
            return false;
        }
        let rest = names.get(i.saturating_add(1)..).unwrap_or_default();
        let Some(first) = rest.first() else { return false };
        if container(first) && rest.len() <= 2 {
            return true;
        }
        first == "modules"
            && rest.iter().enumerate().skip(2).any(|(k, name)| {
                container(name) && (rest.len() == k.saturating_add(1) || rest.len() == k.saturating_add(2))
            })
    })
}

/// Whether `path` has the shape the profile's third Git rule judges below the writable root `root`: a name below
/// `.git/modules/<name>/`. Its regex, `^.*/.git/(modules/.+/)?modules/[^/]+/.+$`, matches exactly the paths with
/// `modules` and at least two more components after a `.git` (the optional group adds nothing). The repositories
/// found below a `modules` directory are excepted from it (`Sandbox::git_refused`).
fn git_below_module(path: &Path, root: &Path) -> bool {
    let Some(names) = names_below(path, root) else { return false };
    names.iter().enumerate().any(|(i, name)| {
        let rest = names.get(i.saturating_add(1)..).unwrap_or_default();
        name == ".git" && rest.first().is_some_and(|first| first == "modules") && rest.len() >= 3
    })
}

/// What `git_directories` found: every repository (sorted), and those of them that lie below a `modules`
/// directory (sorted), which are the third Git rule's exceptions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct GitFound {
    repos: Vec<PathBuf>,
    modules: Vec<PathBuf>,
}

/// The directories in `dir`, found without following a link; none when `dir` is missing or is not a directory
/// itself (a link to one is not entered).
fn real_subdirs(dir: &Path) -> io::Result<Vec<PathBuf>> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Ok(Vec::new()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            out.push(entry.path());
        }
    }
    Ok(out)
}

/// A repository: a regular file `HEAD` and an `objects` directory or a `commondir` file (none of them a link).
fn is_repository(dir: &Path) -> bool {
    let kind = |name: &str| std::fs::symlink_metadata(dir.join(name)).ok();
    kind("HEAD").is_some_and(|m| m.is_file())
        && (kind("objects").is_some_and(|m| m.is_dir()) || kind("commondir").is_some_and(|m| m.is_file()))
}

/// Discover existing repositories without running host Git or following a link to a directory: every directory in
/// the workspace that is a repository (a bare one included; it is not searched further), every `.git` directory and
/// the target of every `.git` file's `gitdir:` when that target is a repository; then, for each repository found, its
/// `commondir` target (relative to it) when that is a repository, every directory in its `worktrees`, and every
/// repository below its `modules` (searched in turn the same way; a directory there that is not one is searched
/// further). Refuse an unreadable or oversized tree rather than silently leaving discovered metadata unprotected.
fn git_directories(workspace: &Path) -> io::Result<GitFound> {
    use std::collections::BTreeSet;
    let canon = |p: &Path| resolve_path(p, true).map_err(invalid);
    let unreadable = |dir: &Path, e: io::Error| {
        invalid(format!(
            "The workspace directory {} cannot be read ({e}). Make it readable, or choose a workspace without it, so \
             that Git metadata can be protected.",
            dir.display()
        ))
    };
    let pointer = |path: &Path| -> io::Result<Option<String>> {
        match std::fs::metadata(path) {
            Ok(m) if m.is_file() && m.len() <= 4096 => Ok(Some(std::fs::read_to_string(path)?)),
            Ok(m) if m.is_file() => Err(invalid(format!(
                "Git metadata pointer {} is larger than 4096 bytes. Inspect it before starting a session.",
                path.display()
            ))),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    };
    let mut pending = vec![workspace.to_path_buf()];
    let mut roots = Vec::new();
    let mut visited = 0_u64;
    while let Some(dir) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > 100_000 {
            return Err(invalid("The workspace has more than 100000 directories. Choose a smaller workspace so Git metadata can be protected.".to_string()));
        }
        if is_repository(&dir) {
            push_unique(&mut roots, canon(&dir)?);
            continue;
        }
        for entry in std::fs::read_dir(&dir).map_err(|e| unreadable(&dir, e))? {
            let entry = entry.map_err(|e| unreadable(&dir, e))?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|e| unreadable(&dir, e))?;
            if fold(&entry.file_name().to_string_lossy()) == ".git" {
                if path.is_dir() {
                    push_unique(&mut roots, canon(&path)?);
                } else if let Some(text) = pointer(&path)? {
                    if let Some(target) = text.trim().strip_prefix("gitdir:") {
                        let target = canon(&dir.join(target.trim()))?;
                        if is_repository(&target) {
                            push_unique(&mut roots, target);
                        }
                    }
                }
            } else if kind.is_dir() {
                pending.push(path);
            }
        }
    }
    let too_many = || {
        invalid(
            "More than 4096 Git repositories and directories that hold them were found below the Git metadata. \
             Inspect the repositories before starting a session."
                .to_string(),
        )
    };
    let mut repos = BTreeSet::new();
    let mut modules = BTreeSet::new();
    let mut other_dirs = 0_usize;
    let mut pending = Vec::new();
    for root in roots {
        if repos.insert(root.clone()) {
            pending.push(root);
        }
    }
    while let Some(dir) = pending.pop() {
        let mut found = Vec::new();
        if let Some(text) = pointer(&dir.join("commondir"))? {
            let target = canon(&dir.join(text.trim()))?;
            if is_repository(&target) {
                found.push(target);
            }
        }
        for worktree in real_subdirs(&dir.join("worktrees"))? {
            found.push(canon(&worktree)?);
        }
        let mut walk = vec![dir.join("modules")];
        while let Some(parent) = walk.pop() {
            for child in real_subdirs(&parent)? {
                if is_repository(&child) {
                    let child = canon(&child)?;
                    modules.insert(child.clone());
                    found.push(child);
                } else {
                    other_dirs = other_dirs.saturating_add(1);
                    walk.push(child);
                }
            }
            if repos.len().saturating_add(other_dirs) > 4096 {
                return Err(too_many());
            }
        }
        for repo in found {
            if repos.insert(repo.clone()) {
                pending.push(repo);
            }
        }
        if repos.len().saturating_add(other_dirs) > 4096 {
            return Err(too_many());
        }
    }
    Ok(GitFound { repos: repos.into_iter().collect(), modules: modules.into_iter().collect() })
}

/// A path that a Git configuration file names and Git reads or runs from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ConfigPath {
    /// `core.hooksPath`
    HooksPath(String),
    /// `include.path` or `includeIf.<condition>.path`, whatever the condition
    Include(String),
}

/// How long a configuration file this reading looks at can be; the rest of a longer one is not read.
const CONFIG_READ_LIMIT: u64 = 1 << 20;

/// How many files deep includes are followed (Git's own limit).
const CONFIG_INCLUDE_DEPTH: usize = 10;

/// The `core.hooksPath`, `include.path` and `includeIf.<condition>.path` values in the text of a Git configuration
/// file, in order. Section and key names are compared without regard to case; a section is `[name]`,
/// `[name "subsection"]` (backslash escapes the next character) or the old `[name.subsection]`; a value runs to the
/// end of the line and is quoted in part or whole with `"`, with the escapes `\n`, `\t`, `\b`, `\\` and `\"`, ends at
/// an unquoted `#` or `;`, loses its unquoted trailing white space, and goes on in the next line after a `\` at the
/// end of a line. A key may follow a section header in the same line. A line that is none of these is skipped.
fn config_paths(text: &str) -> Vec<ConfigPath> {
    let mut chars = text.strip_prefix('\u{feff}').unwrap_or(text).chars().peekable();
    let mut out = Vec::new();
    // The section in force: its name and whether it has a subsection; `None` before the first header and after a
    // header that could not be read.
    let mut section: Option<(String, bool)> = None;
    fn skip_line(chars: &mut std::iter::Peekable<std::str::Chars>) {
        for c in chars.by_ref() {
            if c == '\n' {
                break;
            }
        }
    }
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '#' || c == ';' {
            skip_line(&mut chars);
        } else if c == '[' {
            chars.next();
            section = config_header(&mut chars);
            if section.is_none() {
                skip_line(&mut chars);
            }
        } else if c.is_ascii_alphabetic() {
            let mut key = String::new();
            while let Some(&k) = chars.peek() {
                if !(k.is_ascii_alphanumeric() || k == '-') {
                    break;
                }
                key.push(k.to_ascii_lowercase());
                chars.next();
            }
            while chars.next_if(|k| *k == ' ' || *k == '\t').is_some() {}
            let value = if chars.next_if_eq(&'=').is_some() {
                config_value(&mut chars)
            } else {
                // A key with no `=` has no value.
                skip_line(&mut chars);
                None
            };
            let Some(value) = value else { continue };
            let Some((name, has_sub)) = &section else { continue };
            match (name.as_str(), *has_sub, key.as_str()) {
                ("core", false, "hookspath") => out.push(ConfigPath::HooksPath(value)),
                ("include", false, "path") | ("includeif", true, "path") => out.push(ConfigPath::Include(value)),
                _ => {}
            }
        } else {
            skip_line(&mut chars);
        }
    }
    out
}

/// The section a header opens, after its `[`: its lower-case name and whether it has a subsection. `None` when the
/// header is not one that can be read.
fn config_header(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<(String, bool)> {
    let mut name = String::new();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() || c == ']' || c == '"' || c == '\n' {
            break;
        }
        name.push(c.to_ascii_lowercase());
        chars.next();
    }
    if name.is_empty() {
        return None;
    }
    let mut has_sub = false;
    if chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
        while chars.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
        chars.next_if_eq(&'"')?;
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => {
                    chars.next().filter(|c| *c != '\n')?;
                }
                '\n' => return None,
                _ => {}
            }
        }
        has_sub = true;
    }
    chars.next_if_eq(&']')?;
    // The old form, `[section.subsection]`: the part after the first dot is a subsection.
    match name.split_once('.') {
        Some((section, _)) => Some((section.to_string(), true)),
        None => Some((name, has_sub)),
    }
}

/// The value after an `=`, up to the end of its line; `None` for one that cannot be read (the rest of its line is
/// skipped).
fn config_value(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<String> {
    while chars.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
    let mut out = String::new();
    // How much of `out` stays: trailing white space that is not quoted does not.
    let mut keep = 0_usize;
    let mut quoted = false;
    let mut bad = false;
    loop {
        match chars.next() {
            None | Some('\n') => {
                bad |= quoted;
                break;
            }
            Some('\\') => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{8}'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('\n') => continue,
                Some('\r') if chars.next_if_eq(&'\n').is_some() => continue,
                _ => {
                    bad = true;
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                    break;
                }
            },
            Some('"') => {
                quoted = !quoted;
                keep = out.len();
                continue;
            }
            Some('#' | ';') if !quoted => {
                for c in chars.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
                break;
            }
            Some(c) => {
                out.push(c);
                if quoted || !c.is_whitespace() {
                    keep = out.len();
                }
                continue;
            }
        }
        keep = out.len();
    }
    if bad {
        return None;
    }
    out.truncate(keep);
    Some(out)
}

/// The text of a configuration file, when it is a regular file; at most `CONFIG_READ_LIMIT` bytes of it.
fn read_config(path: &Path) -> Option<String> {
    use std::io::Read;
    std::fs::metadata(path).ok().filter(|m| m.is_file())?;
    let mut bytes = Vec::new();
    std::fs::File::open(path).ok()?.take(CONFIG_READ_LIMIT).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A path as a configuration names it: `~/` is the home directory, a relative one is taken from `base`.
fn config_value_path(value: &str, home: Option<&Path>, base: &Path) -> Option<PathBuf> {
    if value.is_empty() {
        return None;
    }
    if value == "~" {
        return home.map(Path::to_path_buf);
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return home.map(|h| h.join(rest));
    }
    let path = Path::new(value);
    Some(if path.is_absolute() { path.to_path_buf() } else { base.join(path) })
}

/// What the configuration files read from one starting point name.
#[derive(Debug, Default)]
struct ConfigFacts {
    /// The raw `core.hooksPath` values.
    hooks: Vec<String>,
    /// The files included, as written (absolute).
    includes: Vec<PathBuf>,
}

/// Read `files` and, in turn, the files they include (conditions ignored), each file once and at most
/// `CONFIG_INCLUDE_DEPTH` files deep.
fn read_config_files(files: &[PathBuf], home: Option<&Path>) -> ConfigFacts {
    fn follow(file: &Path, depth: usize, home: Option<&Path>, seen: &mut Vec<PathBuf>, facts: &mut ConfigFacts) {
        let key = resolve_path(file, true).unwrap_or_else(|_| file.to_path_buf());
        if seen.contains(&key) {
            return;
        }
        seen.push(key);
        let Some(text) = read_config(file) else { return };
        let dir = file.parent().unwrap_or(Path::new("/"));
        for item in config_paths(&text) {
            match item {
                ConfigPath::HooksPath(value) => facts.hooks.push(value),
                ConfigPath::Include(value) => {
                    let Some(target) = config_value_path(&value, home, dir) else { continue };
                    push_unique(&mut facts.includes, target.clone());
                    if depth < CONFIG_INCLUDE_DEPTH {
                        follow(&target, depth.saturating_add(1), home, seen, facts);
                    }
                }
            }
        }
    }
    let mut facts = ConfigFacts::default();
    let mut seen = Vec::new();
    for file in files {
        follow(file, 0, home, &mut seen, &mut facts);
    }
    facts
}

/// The top of the working tree that the repository `repo` belongs to: the parent of a `.git` directory or of the
/// `.git` file a linked worktree's private gitdir names; for any other repository the repository itself.
fn work_tree_top(repo: &Path) -> PathBuf {
    let is_dot_git = |p: &Path| p.file_name().is_some_and(|n| fold(&n.to_string_lossy()) == ".git");
    if is_dot_git(repo) {
        return repo.parent().unwrap_or(repo).to_path_buf();
    }
    if std::fs::metadata(repo.join("commondir")).is_ok_and(|m| m.is_file()) {
        let small = std::fs::metadata(repo.join("gitdir")).is_ok_and(|m| m.is_file() && m.len() <= 4096);
        let text = if small { std::fs::read_to_string(repo.join("gitdir")).ok() } else { None };
        if let Some(file) = text.map(|t| repo.join(t.trim())).filter(|f| is_dot_git(f)) {
            return file.parent().unwrap_or(repo).to_path_buf();
        }
    }
    repo.to_path_buf()
}

/// The paths the Git configuration names that must not be written, as written (absolute; each is protected when it
/// lies in a writable root): the hooks directory (`core.hooksPath`) and the files included (`include.path`,
/// `includeIf.<condition>.path`) by the `config` and `config.worktree` of every repository in `repos` and by the
/// user's global configuration, and that configuration itself, `~/.gitconfig` and the `git` directory of the XDG
/// configuration (`$XDG_CONFIG_HOME/git`, else `~/.config/git`). A relative hooks path is taken from the top of the
/// repository's working tree, for a global value from that of each repository; a relative include from the directory
/// of the file that names it.
fn git_config_paths(repos: &[PathBuf], home: Option<&Path>, xdg: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut global_files = Vec::new();
    if let Some(home) = home {
        global_files.push(home.join(".gitconfig"));
        out.push(home.join(".gitconfig"));
    }
    let xdg_dir = match xdg {
        Some(x) if x.is_absolute() => Some(x.join("git")),
        _ => home.map(|h| h.join(".config/git")),
    };
    if let Some(dir) = xdg_dir {
        global_files.push(dir.join("config"));
        out.push(dir);
    }
    let global = read_config_files(&global_files, home);
    out.extend(global.includes.iter().cloned());
    for repo in repos {
        let top = work_tree_top(repo);
        let facts = read_config_files(&[repo.join("config"), repo.join("config.worktree")], home);
        out.extend(facts.includes);
        for value in facts.hooks.iter().chain(&global.hooks) {
            out.extend(config_value_path(value, home, &top));
        }
    }
    out
}

/// The repositories `found` that are given to Bubblewrap as a whole: all but those that are or contain the loom home
/// or the user's home directory, which a pointer could name to mount back what Bubblewrap hides there.
fn mountable(found: &[PathBuf], loom_home: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    let holds = |repo: &Path| under(loom_home, repo) || home.is_some_and(|h| under(h, repo));
    found.iter().filter(|repo| !holds(repo)).cloned().collect()
}

/// macOS names the folders of the data volume `/System/Volumes/Data/...` as well, and `realpath` keeps that
/// form where it was written. The rules are written in the usual form, so a path in the alias form is
/// given its usual form back when that names the very same file (same device and inode); otherwise it
/// stays as it is.
fn without_data_volume(c: PathBuf) -> PathBuf {
    use std::os::unix::fs::MetadataExt;
    let Ok(rest) = c.strip_prefix("/System/Volumes/Data") else {
        return c;
    };
    if rest.as_os_str().is_empty() {
        return c;
    }
    let usual = Path::new("/").join(rest);
    match (std::fs::symlink_metadata(&usual), std::fs::symlink_metadata(&c)) {
        (Ok(a), Ok(b)) if a.dev() == b.dev() && a.ino() == b.ino() => usual,
        _ => c,
    }
}

/// Resolves symlinks in the deepest existing ancestor of `path` and appends the rest. A `..` in the
/// part that does not exist is an error when `lenient` is false and is applied lexically otherwise.
fn resolve_path(path: &Path, lenient: bool) -> Result<PathBuf, String> {
    let comps: Vec<Component> = path.components().collect();
    let mut base: Option<(PathBuf, usize)> = None;
    for n in (1..=comps.len()).rev() {
        let prefix: PathBuf = comps.iter().take(n).collect();
        if std::fs::symlink_metadata(&prefix).is_err() {
            continue;
        }
        match prefix.canonicalize() {
            Ok(c) => {
                base = Some((without_data_volume(c), n));
                break;
            }
            Err(_) if lenient => {
                base = Some((prefix, n));
                break;
            }
            Err(e) => {
                return Err(format!(
                    "{} cannot be resolved ({e}); it may be a symlink that points nowhere. Use a path whose links all resolve.",
                    prefix.display()
                ))
            }
        }
    }
    let (mut out, used) = base.unwrap_or_default();
    for c in comps.iter().skip(used) {
        match c {
            Component::ParentDir => {
                if !lenient {
                    return Err(format!(
                        "{} contains `..` after a component that does not exist, so it cannot be resolved. Write the path without `..`.",
                        path.display()
                    ));
                }
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

/// An absolute `path` as written, with `.` dropped and no link resolved; `None` when it has a `..`,
/// which only the canonical form resolves as the file system does.
fn lexical(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => return None,
            other => out.push(other.as_os_str()),
        }
    }
    Some(out)
}

/// A path as an SBPL string literal body; refuses what cannot be written safely.
fn sbpl(path: &Path) -> io::Result<String> {
    let s = path.to_str().ok_or_else(|| {
        invalid(format!("sandbox path {} is not valid UTF-8; use a path made of plain text.", path.display()))
    })?;
    if s.chars().any(char::is_control) {
        return Err(invalid(format!(
            "sandbox path {s:?} contains a control character; remove it from the configuration."
        )));
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `path` as the text of an SBPL regex that matches exactly it (regex metacharacters escaped); `None` for a
/// path that cannot be written inside `#"..."` or is not valid as a profile string.
fn regex_literal(path: &Path) -> Option<String> {
    let s = sbpl(path).ok()?;
    if s.contains('"') || s.contains('\\') {
        return None;
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if ".^$|()[]{}*+?".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    Some(out)
}

fn expand_home(given: &str, home: Option<&Path>) -> Option<PathBuf> {
    let home = home?;
    if given == "~" {
        Some(home.to_path_buf())
    } else {
        given.strip_prefix("~/").map(|rest| home.join(rest))
    }
}

/// Whether `path` is `rule` or lies under it, for a rule that refuses. Volumes on macOS are
/// case-insensitive by default, so there the comparison ignores case (over-blocking is acceptable);
/// elsewhere it is bytewise. Rules that allow are compared with `Path::starts_with` everywhere.
fn under(path: &Path, rule: &Path) -> bool {
    if !cfg!(target_os = "macos") {
        return path.starts_with(rule);
    }
    // Compared a character at a time: nothing is allocated for names that are valid UTF-8.
    let same = |a: Component, b: Component| {
        let (a, b) = (a.as_os_str().to_string_lossy(), b.as_os_str().to_string_lossy());
        a.chars().flat_map(char::to_lowercase).eq(b.chars().flat_map(char::to_lowercase))
    };
    let mut p = path.components();
    rule.components().all(|r| p.next().is_some_and(|c| c == r || same(c, r)))
}

/// Why `mode` cannot work on this host, if it cannot (`exec` is the seatbelt launcher).
fn preflight_at(mode: SandboxMode, exec: &Path, macos: bool) -> Result<(), String> {
    if mode == SandboxMode::None {
        return Ok(());
    }
    let runnable = exec.metadata().map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.is_file() && m.permissions().mode() & 0o111 != 0
    });
    if macos && runnable.unwrap_or(false) {
        return Ok(());
    }
    let why = if macos {
        format!("{} is missing or not executable", exec.display())
    } else {
        "this host is not macOS".to_string()
    };
    Err(format!(
        "[sandbox] mode = \"seatbelt\" cannot work here: {why}. Use macOS, or Linux [sandbox] mode = \"bubblewrap\" with deny-all command networking, or set [sandbox] mode = \"none\" \
         in the configuration knowing that commands are then not confined and can read and write anything this user can."
    ))
}

/// Checks that the configured sandbox mode can work on this host; the daemon refuses to start otherwise.
pub fn preflight(cfg: &SandboxCfg) -> Result<(), String> {
    if cfg.mode == SandboxMode::Bubblewrap {
        return linux::preflight(cfg, Path::new(BWRAP), cfg!(target_os = "linux"));
    }
    preflight_at(cfg.mode, Path::new(SANDBOX_EXEC), cfg!(target_os = "macos"))
}

/// Whether the environment variable `name` looks like it holds a secret and is withheld from commands.
fn secret_name(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.starts_with("LOOM_")
        || SECRET_NAMES.contains(&upper.as_str())
        || SECRET_SUFFIXES.iter().any(|s| upper.ends_with(s))
        || SECRET_WORDS.iter().any(|w| upper.contains(w))
        || upper.contains("PRIVATE")
        || upper.split('_').any(|part| SECRET_PARTS.contains(&part))
}

/// Whether `value` holds a URL with a password in its user-info part (`scheme://user:password@host`)
/// anywhere: every `://` starts an authority, which ends at `/`, `?`, `#`, `"`, `]` or white space. A
/// `,` does not end it, since a password may hold one; a list of URLs is caught at the `://` of each.
fn url_with_password(value: &str) -> bool {
    value.split("://").skip(1).any(|rest| {
        let end = |c: char| matches!(c, '/' | '?' | '#' | '"' | ']') || c.is_whitespace();
        let authority = rest.split(end).next().unwrap_or_default();
        authority
            .rsplit_once('@')
            .is_some_and(|(userinfo, _)| userinfo.split_once(':').is_some_and(|(_, password)| !password.is_empty()))
    })
}

fn join_list(paths: &[PathBuf]) -> String {
    paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
}

impl Sandbox {
    /// `proxy_port` is the session's egress proxy on loopback, when there is one.
    pub fn new(
        cfg: &SandboxCfg,
        workspace: &Path,
        tmp_dir: &Path,
        loom_home: &Path,
        proxy_port: Option<u16>,
    ) -> io::Result<Sandbox> {
        let var = |name: &str| match std::env::var_os(name) {
            Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
            _ => None,
        };
        Self::with_env(cfg, workspace, tmp_dir, loom_home, proxy_port, var("HOME"), var("XDG_CONFIG_HOME"))
    }

    /// `new` with the user's home directory given instead of read from `HOME`, and no `XDG_CONFIG_HOME`.
    #[cfg(test)]
    pub(crate) fn with_home(
        cfg: &SandboxCfg,
        workspace: &Path,
        tmp_dir: &Path,
        loom_home: &Path,
        proxy_port: Option<u16>,
        home: Option<PathBuf>,
    ) -> io::Result<Sandbox> {
        Self::with_env(cfg, workspace, tmp_dir, loom_home, proxy_port, home, None)
    }

    /// `new` with the user's home directory and `XDG_CONFIG_HOME` given instead of read from the environment.
    pub(crate) fn with_env(
        cfg: &SandboxCfg,
        workspace: &Path,
        tmp_dir: &Path,
        loom_home: &Path,
        proxy_port: Option<u16>,
        home: Option<PathBuf>,
        xdg_config_home: Option<PathBuf>,
    ) -> io::Result<Sandbox> {
        let canon = |p: &Path| resolve_path(p, true).map_err(invalid);
        let workspace = canon(workspace)?;
        let tmp_dir = canon(tmp_dir)?;
        let loom_home = canon(loom_home)?;
        // Everything in the temp dir is writable, so it cannot be a directory that holds anything else.
        if tmp_dir.parent().is_none() || under(&loom_home, &tmp_dir) {
            return Err(invalid(format!(
                "the session temp dir {} is the root directory, or is or contains the loom home {}; everything in the \
                 temp dir is writable, so give the session a directory of its own.",
                tmp_dir.display(),
                loom_home.display()
            )));
        }
        // The loom home is not readable, so a workspace inside it would be a workspace that cannot be read.
        if under(&workspace, &loom_home) {
            let who = if cfg.mode == SandboxMode::None { "file tools" } else { "commands and file tools" };
            return Err(invalid(format!(
                "the workspace {} is or lies inside the loom home {}, which {who} cannot read. \
                 Use a workspace outside the loom home.",
                workspace.display(),
                loom_home.display()
            )));
        }
        let home = match home {
            Some(h) => Some(canon(&h)?),
            None => None,
        };
        // A configured path: `~` expanded, relative ones taken from the workspace; `anchored` makes it canonical.
        let absolute = |given: &str| -> io::Result<PathBuf> {
            let p = match expand_home(given, home.as_deref()) {
                Some(p) => p,
                None if given == "~" || given.starts_with("~/") => {
                    return Err(invalid(format!(
                    "the sandbox path {given:?} needs the home directory, but HOME is not set; write the path in full."
                )))
                }
                None => PathBuf::from(given),
            };
            Ok(workspace.join(p))
        };
        let anchored = |given: &str| -> io::Result<PathBuf> { canon(&absolute(given)?) };

        let mut writable = vec![workspace.clone(), tmp_dir.clone()];
        for p in &cfg.extra_writable {
            push_unique(&mut writable, anchored(p)?);
        }
        let oracle_staging_root = canon(&loom_home.join("oracle-runs"))?;
        let mut replay_untrusted = Vec::new();
        for path in cfg.replay_untrusted_paths.iter().chain(&cfg.extra_writable) {
            let written = absolute(path)?;
            push_unique(&mut replay_untrusted, canon(&written)?);
            if let Some(written) = lexical(&written) {
                push_unique(&mut replay_untrusted, written);
            }
        }

        let GitFound { repos: found, modules: git_modules } = git_directories(&workspace)?;
        let git_dirs = mountable(&found, &loom_home, home.as_deref());
        let mut protected = vec![canon(&workspace.join(".loom"))?, loom_home.clone()];
        push_unique(&mut protected, workspace.join(".loom"));
        for dir in &found {
            for name in GIT_PRIVATE {
                let path = dir.join(name);
                push_unique(&mut protected, canon(&path)?);
                push_unique(&mut protected, path);
            }
        }
        // What a configuration makes Git run or read: the hooks directory and the files it includes.
        for path in git_config_paths(&found, home.as_deref(), xdg_config_home.as_deref()) {
            for form in [Some(canon(&path)?), lexical(&path)].into_iter().flatten() {
                if writable.iter().any(|root| under(&form, root)) {
                    push_unique(&mut protected, form);
                }
            }
        }
        for p in &cfg.protected_paths {
            push_unique(&mut protected, anchored(p)?);
        }

        // A not-readable path is kept as written as well when a link along it makes that differ: removed,
        // the link could be replaced by a directory of a command's own, which the canonical rule misses.
        let oracle_secrets = workspace.join(".loom/oracle-secrets");
        let mut unreadable = vec![loom_home.join("token"), loom_home.join("keys"), canon(&oracle_secrets)?];
        push_unique(&mut unreadable, oracle_secrets);
        for p in &cfg.unreadable_paths {
            let written = absolute(p)?;
            push_unique(&mut unreadable, canon(&written)?);
            if let Some(w) = lexical(&written) {
                push_unique(&mut unreadable, w);
            }
        }

        // The workspace stays readable: a credential path that is or contains it is skipped. The others are
        // kept as written too, as above.
        let mut credentials = Vec::new();
        if cfg.protect_credentials {
            let Some(h) = &home else {
                return Err(invalid(
                    "sandbox.protect_credentials is on, but the home directory is not known (HOME is not set), so the \
                     credential stores cannot be located. Start the daemon with HOME set, or set [sandbox] \
                     protect_credentials = false knowing that commands and file tools can then read them."
                        .to_string(),
                ));
            };
            for rel in CREDENTIAL_PATHS {
                let written = h.join(rel);
                let p = canon(&written)?;
                if !workspace.starts_with(&p) {
                    push_unique(&mut credentials, p);
                    push_unique(&mut credentials, written);
                }
            }
        }

        let mut loopback_ports = Vec::new();
        if let Some(p) = proxy_port {
            loopback_ports.push(p);
        }
        for p in &cfg.loopback_ports {
            push_unique(&mut loopback_ports, *p);
        }

        let mut unix_sockets = Vec::new();
        for p in &cfg.unix_sockets {
            push_unique(&mut unix_sockets, anchored(p)?);
        }

        let linux_filter = if cfg.mode == SandboxMode::Bubblewrap {
            if proxy_port.is_some() {
                return Err(invalid("Bubblewrap does not support a host proxy bridge. Pass no proxy port and use deny_all command networking.".to_string()));
            }
            linux::preflight(cfg, Path::new(BWRAP), cfg!(target_os = "linux")).map_err(invalid)?;
            if !workspace.join(".loom").is_dir() {
                return Err(invalid("Bubblewrap requires an existing workspace .loom directory so its contents, including future oracle secrets, can be hidden. Create the reserved directory before starting the session.".to_string()));
            }
            if !credentials.is_empty()
                && home.as_ref().is_some_and(|home| writable.iter().any(|root| under(home, root)))
            {
                return Err(invalid("Bubblewrap cannot use the whole user home as a writable root while protecting credentials. Choose a narrower workspace and extra_writable directories.".to_string()));
            }
            for path in unreadable.iter().chain(&credentials) {
                let hidden = under(path, &loom_home)
                    || under(path, &workspace.join(".loom"))
                    || (!credentials.is_empty()
                        && home.as_ref().is_some_and(|home| under(path, home))
                        && !writable.iter().any(|root| under(path, root)));
                if !path.exists() && !hidden {
                    return Err(invalid(format!("Bubblewrap cannot hide the missing unreadable path {}. Create it before starting the session or choose a scope whose parent can be hidden.", path.display())));
                }
            }
            Some(linux::prepare(&loom_home)?)
        } else {
            None
        };
        let linux_pins = if cfg.mode == SandboxMode::Bubblewrap {
            linux::pin(&writable, &protected, &unreadable, &credentials, &git_dirs)?
        } else {
            Vec::new()
        };
        // Every path that can reach a profile must be writable as a literal, whatever the mode.
        let git_paths = git_dirs.iter().chain(&git_modules);
        for p in writable
            .iter()
            .chain(&protected)
            .chain(&unreadable)
            .chain(&credentials)
            .chain(&unix_sockets)
            .chain(git_paths)
        {
            sbpl(p)?;
        }
        let analysis_dir = tmp_dir.parent().map(|p| p.join("analysis")).unwrap_or_default();
        Ok(Sandbox {
            mode: cfg.mode,
            linux_filter,
            linux_pins,
            git_dirs,
            git_modules,
            workspace,
            loom_home,
            oracle_staging_root,
            tmp_dir,
            replay: false,
            analysis_dir,
            jobs_dir: None,
            home,
            writable,
            replay_untrusted,
            protected,
            unreadable,
            credentials,
            loopback_ports,
            loopback_all: cfg.loopback_all,
            daemon_port: cfg.daemon_port,
            network_deny_all: cfg.network_deny_all,
            unix_sockets,
            env_pass: cfg.env_pass.clone(),
            secret_env: cfg.secret_env.clone(),
        })
    }

    pub fn mode(&self) -> SandboxMode {
        self.mode
    }

    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub fn tmp_dir(&self) -> &Path {
        &self.tmp_dir
    }

    /// `<session dir>/analysis`, the harness's staging for binary-analysis inputs: readable to commands and file
    /// tools (inside the loom home) but never writable to them.
    pub fn analysis_dir(&self) -> &Path {
        &self.analysis_dir
    }

    /// This sandbox with the session's job-output directory named. Commands' own stdout and stderr files are in
    /// it, so what lies inside the loom home is given a metadata-only exception there (`fstat` of an inherited
    /// descriptor is a metadata read); its content cannot be read nor can it be listed.
    pub fn with_jobs_dir(mut self, dir: &Path) -> io::Result<Sandbox> {
        let dir = resolve_path(dir, true).map_err(invalid)?;
        sbpl(&dir)?;
        self.jobs_dir = Some(dir);
        Ok(self)
    }

    /// Harness-owned staging lives outside all sessions, whose mutable temp trees are excluded from
    /// trusted replay reads. Callers create a private random child containing workspace/tmp siblings.
    pub fn oracle_staging_root(&self) -> &Path {
        &self.oracle_staging_root
    }

    /// Derive a replay policy over harness-owned staging directories outside the caller's write
    /// grants. Read/credential/network restrictions are retained; all old writable roots are unreadable.
    /// Workspace/temp must share a protected parent under `oracle_staging_root`. The new
    /// workspace is read-only and only the disjoint new temp is writable. `none` is refused.
    pub fn isolated_replay(&self, workspace: &Path, tmp: &Path) -> Result<Sandbox, String> {
        if self.mode == SandboxMode::None {
            return Err("An isolated replay needs an OS sandbox. Use seatbelt or bubblewrap; mode = \"none\" cannot enforce a read-only replay.".to_string());
        }
        let canonical = |path: &Path| -> Result<PathBuf, String> {
            if !path.is_dir() {
                return Err(format!("Replay directory {} does not exist. Create private staging directories outside the session temp first.", path.display()));
            }
            std::fs::canonicalize(path).map_err(|e| {
                format!("Replay directory {} cannot be resolved: {e}. Inspect it before retrying.", path.display())
            })
        };
        let workspace = canonical(workspace)?;
        let tmp = canonical(tmp)?;
        let private_parent = workspace.parent().filter(|parent| {
            Some(*parent) == tmp.parent()
                && parent.starts_with(&self.oracle_staging_root)
                && self.protected.iter().any(|root| under(parent, root))
        });
        if workspace.starts_with(&tmp)
            || tmp.starts_with(&workspace)
            || private_parent.is_none()
            || self.check_write(&workspace).is_ok()
            || self.check_write(&tmp).is_ok()
        {
            return Err("Replay workspace and temp must be separate private directories outside the caller's writable areas. Create them as siblings under the protected oracle staging root.".to_string());
        }
        let mut untrusted = Vec::new();
        let sessions = self.loom_home.join("sessions");
        for path in self.replay_untrusted.iter().chain(&self.writable).chain(std::iter::once(&sessions)) {
            push_unique(&mut untrusted, resolve_path(path, true)?);
            if let Some(written) = lexical(path) {
                push_unique(&mut untrusted, written);
            }
        }
        if untrusted.iter().any(|root| under(&workspace, root) || under(&tmp, root)) {
            return Err("An actor-writable origin contains the oracle staging directories. Choose narrower writable roots; trusted replay does not make read exceptions inside untrusted trees.".to_string());
        }
        if self.mode == SandboxMode::Bubblewrap {
            for origin in &untrusted {
                let hidden = under(origin, &self.loom_home)
                    || (!self.credentials.is_empty() && self.home.as_ref().is_some_and(|home| under(origin, home)))
                    || ["/tmp", "/var/tmp", "/run"].iter().any(|root| origin.starts_with(root));
                if !origin.exists() && !hidden {
                    return Err(format!("The untrusted replay origin {} is missing and Bubblewrap cannot reserve that future path. Create the actor directory before replay or choose a scope hidden by a private parent.", origin.display()));
                }
            }
        }
        let mut replay = self.clone();
        if self.mode == SandboxMode::Bubblewrap {
            loom_core::config::ensure_private_dir(&workspace.join(".loom"))
                .map_err(|e| format!("Replay state directory cannot be created: {e}. Inspect the staged workspace."))?;
        }
        replay.replay = true;
        replay.workspace = workspace.clone();
        replay.tmp_dir = tmp.clone();
        replay.writable = vec![workspace.clone(), tmp];
        for path in &untrusted {
            push_unique(&mut replay.unreadable, path.clone());
        }
        replay.replay_untrusted = untrusted;
        push_unique(&mut replay.protected, workspace.clone());
        let secrets = workspace.join(".loom/oracle-secrets");
        push_unique(&mut replay.unreadable, resolve_path(&secrets, true)?);
        push_unique(&mut replay.unreadable, secrets);
        let found = git_directories(&workspace)
            .map_err(|e| format!("Replay Git metadata cannot be protected: {e}. Inspect the staged workspace."))?;
        replay.git_dirs = mountable(&found.repos, &self.loom_home, self.home.as_deref());
        replay.git_modules = found.modules;
        if replay.mode == SandboxMode::Bubblewrap {
            replay.linux_pins = linux::pin(
                &replay.writable,
                &replay.protected,
                &replay.unreadable,
                &replay.credentials,
                &replay.git_dirs,
            )
            .map_err(|e| format!("Replay mounts cannot be pinned: {e}. Inspect the staged directories."))?;
        }
        Ok(replay)
    }

    pub fn profile(&self) -> Option<String> {
        if self.mode != SandboxMode::Seatbelt {
            return None;
        }
        // Paths were validated in `new`; one that fails here is left out rather than half written.
        let subpaths = |v: &[PathBuf]| {
            v.iter().filter_map(|p| sbpl(p).ok()).map(|s| format!(" (subpath \"{s}\")")).collect::<String>()
        };
        let mut out = String::from(
            "(version 1)\n(allow default)\n(deny signal)\n(allow signal (target same-sandbox))\n(deny file-write*)\n",
        );
        let literals: String = DEVICE_LITERALS.iter().map(|d| format!(" (literal \"{d}\")")).collect();
        out.push_str(&format!("(allow file-write*{}{literals})\n", subpaths(&self.writable)));
        if !self.protected.is_empty() {
            out.push_str(&format!("(deny file-write*{})\n", subpaths(&self.protected)));
        }
        // The session temp dir may lie inside a protected directory; this later rule wins. The directory
        // entry itself cannot be removed, renamed, replaced, or made anew once gone, so the next activation
        // of the session follows no link put there; a write deny would also make it test as unwritable.
        if let Ok(t) = sbpl(&self.tmp_dir) {
            out.push_str(&format!(
                "(allow file-write* (subpath \"{t}\"))\n(deny file-write-unlink file-write-create (literal \"{t}\"))\n"
            ));
        }
        let inside_tmp = self.inside_tmp_protected();
        if !inside_tmp.is_empty() {
            out.push_str(&format!("(deny file-write*{})\n", subpaths(&inside_tmp)));
        }
        out.push_str(&self.git_rules(&subpaths));
        // What cannot be read cannot be written, renamed or removed either: moved, it could be read
        // under another name.
        let unreadable: Vec<PathBuf> = self.unreadable.iter().chain(&self.credentials).cloned().collect();
        if !unreadable.is_empty() {
            let denied = subpaths(&unreadable);
            out.push_str(&format!("(deny file-write*{denied})\n(deny file-read* file-test-existence{denied})\n"));
        }
        // The whole loom home is unreadable but for what a session or replay works in: the home entry and the
        // directories down to it can be looked up (stat, `cd`, `pwd -P`), not listed. A not-readable path at,
        // inside or around what was opened again is denied once more, as the rule above would otherwise lose.
        if let Ok(h) = sbpl(&self.loom_home) {
            let open = self.open_in_home();
            let mut lookup = vec![self.loom_home.clone()];
            for dir in &open {
                for a in dir.ancestors().skip(1) {
                    if a != self.loom_home && under(a, &self.loom_home) {
                        push_unique(&mut lookup, a.to_path_buf());
                    }
                }
            }
            lookup.sort();
            let literals: String =
                lookup.iter().filter_map(|p| sbpl(p).ok()).map(|s| format!(" (literal \"{s}\")")).collect();
            // `file-read*` does not cover `file-test-existence`: without it a command could still ask the kernel
            // for the name of every file under the home by its id (`fsgetpath`), so the names are denied too.
            // A name that is missing from one of those directories must answer "no such file", not EPERM: tools
            // that look for `package.json`, `node_modules/.bin/sh` or `pyproject.toml` above the temp dir treat
            // anything but ENOENT as fatal (Node, libuv's PATH search, Python before 3.14). So the direct children
            // of each lookup directory can be tested for existence (the answer for one that exists is still
            // EPERM: its metadata and content stay unreadable), and so can what lies below a `node_modules` there:
            // npm puts `<each ancestor>/node_modules/.bin` on `PATH` and libuv ends its search at the first EPERM,
            // so `<ancestor>/node_modules/.bin/sh` must be ENOENT too. Loom never makes such a directory, so that
            // names nothing. Nothing else deeper can be tested, so `fsgetpath` of what the home holds still fails.
            let children: String = lookup
                .iter()
                .filter_map(|p| regex_literal(p))
                .map(|r| format!(" (regex #\"^{r}/[^/]+$\") (regex #\"^{r}/node_modules/\")"))
                .collect();
            out.push_str(&format!(
                "(deny file-read* file-test-existence (subpath \"{h}\"))\n\
                 (allow file-read-metadata file-test-existence{literals})\n\
                 (allow file-test-existence{children})\n\
                 (allow file-read* file-test-existence{})\n",
                subpaths(&open)
            ));
            // What is not readable stays so wherever it lies in the home, a direct child of a lookup directory
            // (`token`, `keys`) included: the rule above would otherwise let its name be tested.
            let again: Vec<PathBuf> = unreadable
                .iter()
                .filter(|u| under(u, &self.loom_home) || open.iter().any(|o| under(u, o) || under(o, u)))
                .cloned()
                .collect();
            if !again.is_empty() {
                out.push_str(&format!("(deny file-read* file-test-existence{})\n", subpaths(&again)));
            }
            // The job output files are the commands' own stdout and stderr: their metadata can be read (Python
            // and `cat` take it of the inherited descriptors), their content and the directory cannot.
            if let Some(jobs) = self.jobs_dir.as_ref().filter(|j| under(j, &self.loom_home)) {
                out.push_str(&format!("(allow file-read-metadata{})\n", subpaths(std::slice::from_ref(jobs))));
            }
        }
        // Nor can a directory that holds one be moved, or made as a link where it is missing.
        let holders = self.holders();
        if !holders.is_empty() {
            let literals: String =
                holders.iter().filter_map(|p| sbpl(p).ok()).map(|s| format!(" (literal \"{s}\")")).collect();
            out.push_str(&format!(
                "(deny file-write-unlink{literals})\n\
                 (deny file-write-create (require-all (vnode-type SYMLINK) (require-any{literals})))\n"
            ));
        }
        // Opening an application or URL through LaunchServices, driving one with Apple Events, or handing
        // launchd a job, runs code outside the sandbox.
        // `searchfs(2)` finds files by name across a volume, the home's among them.
        out.push_str("(deny lsopen)\n(deny appleevent-send)\n(deny job-creation)\n(deny file-search)\n");
        // A file system mounted over a directory (a disk image attached over `.git/hooks` or `~/.ssh`) escapes
        // every path rule; DiskArbitration and the disk-image services mount for a process outside its sandbox;
        // `cfprefsd` writes `~/Library/Preferences` for one.
        out.push_str(
            "(deny file-mount)\n(deny user-preference-write)\n\
             (deny mach-lookup (global-name \"com.apple.DiskArbitration.diskarbitrationd\") \
             (global-name \"com.apple.diskimagesiod\") (global-name \"com.apple.diskimagesiod.ram\") \
             (global-name \"com.apple.diskmanagementd\"))\n",
        );
        out.push_str("(deny network*)\n");
        if self.loopback_all && self.daemon_port.is_some() {
            // A later deny of one port is not reliable after an allow of `(remote ip "localhost:*")`: probed on
            // macOS 27, about two ports in five are still connectable. After an allow written for TCP and UDP it
            // holds for every port tried.
            out.push_str("(allow network-outbound (remote tcp \"localhost:*\") (remote udp \"localhost:*\"))\n");
        } else if self.loopback_all {
            out.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
        } else {
            for p in &self.loopback_ports {
                out.push_str(&format!("(allow network-outbound (remote ip \"localhost:{p}\"))\n"));
            }
        }
        for s in self.unix_sockets.iter().filter_map(|p| sbpl(p).ok()) {
            out.push_str(&format!("(allow network-outbound (remote unix-socket (path-literal \"{s}\")))\n"));
        }
        // After the allows, and written `*:<port>`: Seatbelt counts the host's own addresses as loopback, so the
        // deny names every address.
        if let Some(port) = self.daemon_port {
            out.push_str(&format!("(deny network-outbound (remote ip \"*:{port}\"))\n"));
        }
        out.push_str("(allow network-bind (local ip \"localhost:*\"))\n");
        out.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
        // Certificate evaluation fetches the issuer a certificate names through these services, outside the
        // sandbox; without them it fails closed. Background URL sessions and WebKit fetch a URL the same way.
        if self.network_deny_all {
            out.push_str(
                "(deny mach-lookup (global-name \"com.apple.trustd.agent\") (global-name \"com.apple.trustd\") \
                 (global-name \"com.apple.ocspd\") (global-name \"com.apple.nsurlsessiond\") \
                 (global-name \"com.apple.nsurlsessiond.NSURLSessionProxyService\") \
                 (xpc-service-name-prefix \"com.apple.WebKit.\"))\n",
            );
        }
        Some(out)
    }

    /// The Git rules of the profile, which must come after every allow and deny that concerns the session temp
    /// dir (the last matching rule wins): they hold in every writable root, the temp dir included. Every letter
    /// of a name is a class of both cases and of what the volume folds to it (`fold_regex`); `subpaths` writes
    /// ` (subpath "<path>")` for each of a list.
    fn git_rules(&self, subpaths: &dyn Fn(&[PathBuf]) -> String) -> String {
        let (git, worktrees, modules) = (fold_regex(".git"), fold_regex("worktrees"), fold_regex("modules"));
        let names = GIT_PRIVATE.map(fold_regex).join("|");
        let roots = format!("(require-any{})", subpaths(&self.writable));
        let mut out = format!(
            "(deny file-write* (require-all {roots} (regex #\"^.*/{git}(/(({worktrees}/[^/]+|{modules}/(.+/)?[^/]+)/)?({names})(/.*)?)?$\")))\n\
             (deny file-write-create file-write-unlink (require-all {roots} (regex #\"^.*/{git}/({modules}/.+/)?({modules}|{worktrees})(/[^/]+)?$\")))\n"
        );
        // What a directory moved below `.git/modules/<name>/` holds is judged by no rule: nothing can be made or
        // removed there but inside the repositories found below a `modules` directory (and in those only outside
        // their own `modules` and `worktrees`, which the rules above and this one cover in turn).
        let inside: String = self
            .git_modules
            .iter()
            .filter_map(|r| sbpl(r).ok())
            .map(|r| {
                format!(
                    " (require-not (require-all (subpath \"{r}\") (require-not (subpath \"{r}/modules\")) \
                     (require-not (subpath \"{r}/worktrees\"))))"
                )
            })
            .collect();
        out.push_str(&format!(
            "(deny file-write-create file-write-unlink (require-all {roots} \
             (regex #\"^.*/{git}/({modules}/.+/)?{modules}/[^/]+/.+$\"){inside}))\n"
        ));
        out
    }

    /// What is readable inside the loom home: the session temp dir and the analysis staging dir, or in a replay its
    /// staged workspace and temp.
    fn open_in_home(&self) -> Vec<PathBuf> {
        if self.replay {
            vec![self.workspace.clone(), self.tmp_dir.clone()]
        } else if under(&self.analysis_dir, &self.loom_home) {
            vec![self.tmp_dir.clone(), self.analysis_dir.clone()]
        } else {
            vec![self.tmp_dir.clone()]
        }
    }

    /// Protected paths that are the session temp dir or lie inside it; they stay protected.
    fn inside_tmp_protected(&self) -> Vec<PathBuf> {
        self.protected.iter().filter(|p| under(p, &self.tmp_dir)).cloned().collect()
    }

    /// The directories above a never-writable or not-readable path, or above the temp dir, that a
    /// command could otherwise remove or rename, or make as a link while missing (they lie where writes
    /// are allowed and no rule of the profile refuses them already): moving one would take what it holds
    /// out from under its rule. Sorted, so that the same policy gives the same profile.
    fn holders(&self) -> Vec<PathBuf> {
        let refused = |a: &Path| {
            a == self.tmp_dir.as_path()
                || self.unreadable.iter().chain(&self.credentials).any(|p| under(a, p))
                || self
                    .protected
                    .iter()
                    .any(|p| under(a, p) && (!a.starts_with(&self.tmp_dir) || under(p, &self.tmp_dir)))
        };
        let guarded = self.protected.iter().chain(&self.unreadable).chain(&self.credentials).chain([&self.tmp_dir]);
        let mut out = std::collections::BTreeSet::new();
        for a in guarded.flat_map(|p| p.ancestors().skip(1)) {
            if self.writable.iter().any(|w| a.starts_with(w)) && !refused(a) {
                out.insert(a.to_path_buf());
            }
        }
        out.into_iter().collect()
    }

    pub fn command(&self, script: &str) -> (String, Vec<String>) {
        if self.mode == SandboxMode::Bubblewrap {
            return linux::command(self, script);
        }
        match self.profile() {
            Some(profile) => (
                SANDBOX_EXEC.to_string(),
                vec!["-p".into(), profile, "/bin/bash".into(), "-c".into(), script.to_string()],
            ),
            None => ("/bin/bash".to_string(), vec!["-c".into(), script.to_string()]),
        }
    }

    fn resolved(&self, path: &Path) -> Result<PathBuf, String> {
        if !path.is_absolute() {
            return Err(format!(
                "{} is not an absolute path; give the full path (relative paths are taken from the workspace {}).",
                path.display(),
                self.workspace.display()
            ));
        }
        resolve_path(path, false)
    }

    pub fn check_read(&self, path: &Path) -> Result<PathBuf, String> {
        let r = self.resolved(path)?;
        if let Some(rule) = self.unreadable.iter().find(|u| under(&r, u)) {
            return Err(format!(
                "{} is not readable: {} is off limits to commands and file tools. Read something else, or ask the user to change `sandbox.unreadable_paths` if this is wrong.",
                r.display(),
                rule.display()
            ));
        }
        if let Some(rule) = self.credentials.iter().find(|u| under(&r, u)) {
            return Err(format!(
                "{} is not readable: {} is a credential store, off limits to commands and file tools. Read something else, or ask the user to set `sandbox.protect_credentials = false` if this is wrong.",
                r.display(),
                rule.display()
            ));
        }
        if under(&r, &self.loom_home) && !self.open_in_home().iter().any(|o| r.starts_with(o)) {
            let who = if self.mode == SandboxMode::None { "file tools" } else { "commands and file tools" };
            let (allowed, instead) = if self.replay {
                (
                    format!(
                        "this replay's staged workspace {} and temp dir {}",
                        self.workspace.display(),
                        self.tmp_dir.display()
                    ),
                    "the staged workspace or temp dir",
                )
            } else if self.open_in_home().len() > 1 {
                (
                    format!(
                        "the session temp dir {} and the analysis staging dir {}",
                        self.tmp_dir.display(),
                        self.analysis_dir.display()
                    ),
                    "the workspace or the session temp dir",
                )
            } else {
                (format!("the session temp dir {}", self.tmp_dir.display()), "the workspace or the session temp dir")
            };
            return Err(format!(
                "{} is not readable: it lies inside the loom home {}, which {who} cannot read except {allowed}. Read a file in {instead} instead.",
                r.display(),
                self.loom_home.display(),
            ));
        }
        Ok(r)
    }

    /// Whether the Git rules of the policy refuse `path`, as the profile does: each is judged relative to the
    /// writable root `path` lies in (the workspace when it lies in none), and every write counts as making the
    /// entry, as the file tools write by renaming a new file into place.
    fn git_refused(&self, path: &Path) -> bool {
        let mut roots: Vec<&Path> = self.writable.iter().map(PathBuf::as_path).filter(|w| under(path, w)).collect();
        if roots.is_empty() {
            roots.push(&self.workspace);
        }
        let inside_found = || {
            self.git_modules.iter().any(|repo| {
                under(path, repo) && !under(path, &repo.join("modules")) && !under(path, &repo.join("worktrees"))
            })
        };
        roots.iter().any(|root| git_metadata(path, root) || git_container(path, root))
            || (roots.iter().any(|root| git_below_module(path, root)) && !inside_found())
    }

    pub fn check_write(&self, path: &Path) -> Result<PathBuf, String> {
        let r = self.resolved(path)?;
        if self.git_refused(&r) || self.git_refused(path) {
            return Err(format!(
                "{} is Git metadata, which commands and file tools may not write or create anywhere they write, because \
                 Git could run what it holds as the operator. Ask the operator to change repository configuration, to \
                 add a worktree (`git worktree add`) or to set up a submodule (`git submodule update --init`). A \
                 repository of your own can be cloned bare, `git clone --bare <url> <dir>.git`, and used with \
                 `git --git-dir=<dir>.git --work-tree=<dir>`.",
                path.display()
            ));
        }
        if self.mode == SandboxMode::Bubblewrap && self.git_dirs.iter().any(|dir| under(&r, dir)) {
            return Err(format!("{} is in Git metadata mounted read-only by Bubblewrap. Ask the operator to update Git metadata outside the session.", r.display()));
        }
        // The session temp dir is writable even when it lies inside a protected directory.
        let in_tmp = r.starts_with(&self.tmp_dir) && !self.inside_tmp_protected().iter().any(|p| under(&r, p));
        if let Some(rule) = self.protected.iter().find(|p| !in_tmp && under(&r, p)) {
            return Err(format!(
                "{} is protected: nothing under {} can be written by commands or file tools. Write elsewhere in the workspace.",
                r.display(),
                rule.display()
            ));
        }
        // What cannot be read cannot be written either, wherever it lies, as in the profile.
        if let Some(rule) = self.unreadable.iter().find(|u| under(&r, u)) {
            return Err(format!(
                "{} is not writable: {} is off limits to commands and file tools, for writing as well as reading. Write somewhere else, or ask the user to change `sandbox.unreadable_paths` if this is wrong.",
                r.display(),
                rule.display()
            ));
        }
        if let Some(rule) = self.credentials.iter().find(|u| under(&r, u)) {
            return Err(format!(
                "{} is not writable: {} is a credential store, off limits to commands and file tools. Write somewhere else, or ask the user to set `sandbox.protect_credentials = false` if this is wrong.",
                r.display(),
                rule.display()
            ));
        }
        // Writing a path replaces its entry, which the profile refuses for the temp dir itself.
        if under(&r, &self.tmp_dir) && under(&self.tmp_dir, &r) {
            return Err(format!(
                "{} is the session temp dir itself, which cannot be replaced or removed. Write to a path inside it instead, such as {}.",
                r.display(),
                self.tmp_dir.join("name").display()
            ));
        }
        // The temp dir is a writable root, so what lies in it passes here.
        if self.mode != SandboxMode::None {
            let device = DEVICE_LITERALS.iter().any(|d| r == Path::new(d));
            if !device && !self.writable.iter().any(|w| r.starts_with(w)) {
                let shown = if r == path { String::new() } else { format!(" (resolved from {})", path.display()) };
                return Err(format!(
                    "{}{shown} is outside the writable areas. Writes are allowed only under: {}. Choose a path under one of them.",
                    r.display(),
                    join_list(&self.writable)
                ));
            }
        }
        Ok(r)
    }

    pub fn resolve(&self, given: &str) -> PathBuf {
        match expand_home(given, self.home.as_deref()) {
            Some(p) => p,
            None => self.workspace.join(given),
        }
    }

    pub fn env(&self, parent: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let mut out: BTreeMap<String, String> = parent
            .iter()
            .filter(|(name, value)| {
                // These would execute agent-writable files in the trusted host launcher before bwrap.
                let upper = name.to_uppercase();
                if self.mode == SandboxMode::Bubblewrap
                    && (upper.starts_with("LD_")
                        || upper.starts_with("DYLD_")
                        || upper.starts_with("BASH_FUNC_")
                        || matches!(upper.as_str(), "BASH_ENV" | "ENV" | "SHELLOPTS" | "BASHOPTS"))
                {
                    return false;
                }
                self.env_pass.iter().any(|p| p == *name)
                    || !(secret_name(name) || self.secret_env.iter().any(|n| n == *name) || url_with_password(value))
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in
            [("TERM", "dumb"), ("NO_COLOR", "1"), ("PAGER", "cat"), ("GIT_PAGER", "cat"), ("GIT_TERMINAL_PROMPT", "0")]
        {
            out.insert(k.to_string(), v.to_string());
        }
        out.insert("TMPDIR".to_string(), self.tmp_dir.display().to_string());
        out
    }

    pub fn describe(&self) -> String {
        let protected = join_list(&self.protected);
        let unreadable = join_list(&self.unreadable);
        // In mode `none` nothing confines commands, so the credential rule is stated as the file tools' own.
        let stores = "~/.ssh, ~/.aws, ~/.gnupg, cloud, registry, database, model-hub and AI-tool logins, password \
                      managers, wallets, keychains, the profiles of common browsers, mail and chat data, and similar";
        let credentials = match (self.credentials.is_empty(), self.mode) {
            (true, _) => String::new(),
            (false, SandboxMode::None) => {
                format!(" They also refuse to read or write credential directories ({stores}).")
            }
            (false, SandboxMode::Seatbelt | SandboxMode::Bubblewrap) => {
                format!(" Credential directories ({stores}) are off limits to read and to write.")
            }
        };
        // In the production layout the temp dir lies inside the loom home, which is protected.
        let tmp = &self.tmp_dir;
        let exception = if self.protected.iter().any(|p| under(tmp, p))
            && !self.inside_tmp_protected().iter().any(|p| under(tmp, p))
        {
            format!(" The one exception is the session temp dir {}: what is in it can be written.", tmp.display())
        } else {
            String::new()
        };
        let home = self.loom_home.display();
        let file_tools_only = self.mode == SandboxMode::None;
        let own = match (self.replay, file_tools_only) {
            (true, true) => format!(
                " File tools also refuse to read loom's own files under {home}, except this replay's staged workspace and temp dir {tmp}.",
                tmp = tmp.display()
            ),
            (true, false) => format!(
                "Loom's own files under {home} are not readable, except this replay's staged workspace and temp dir {tmp}.",
                tmp = tmp.display()
            ),
            (false, _) => {
                let analysis = if self.open_in_home().len() > 1 {
                    format!(" and the analysis staging dir {}", self.analysis_dir.display())
                } else {
                    String::new()
                };
                if file_tools_only {
                    format!(
                        " File tools also refuse to read loom's own files under {home} (logs, records, stored outputs, configuration), except the session temp dir {tmp}{analysis}.",
                        tmp = tmp.display()
                    )
                } else {
                    format!(
                        "Loom's own files under {home} (logs, records, stored outputs, configuration) are not readable, except the session temp dir {tmp}{analysis}.",
                        tmp = tmp.display()
                    )
                }
            }
        };
        if self.mode == SandboxMode::None {
            return format!(
                "Commands are not confined by an operating-system sandbox: they can read and write anything this user can. \
                 File tools still refuse to write under {protected} and to read or write {unreadable}.{exception}{credentials}{own}"
            );
        }
        if self.mode == SandboxMode::Bubblewrap {
            return format!("Commands run in Linux bubblewrap with a read-only host filesystem, writable roots {}, a private /tmp, and all socket creation/connections denied. Protected paths {protected} and discovered Git metadata remain read-only; credential paths are hidden. {own}{exception} New Git repositories must be created by the operator outside the session. File tools additionally refuse Git config and hook writes.", join_list(&self.writable));
        }
        let git = " No Git repository can be made where commands write, and no Git configuration, hooks, worktree or \
                   submodule repository can be written or moved into place: ask the operator to run `git worktree add` \
                   or `git submodule update --init`. A bare clone works (`git clone --bare <url> <dir>.git`, used with \
                   `git --git-dir=<dir>.git --work-tree=<dir>`). `git submodule update` (any form) is the operator's, \
                   upstream tracking (`git branch --set-upstream-to`, `git switch -c <b> <remote>/<b>`) cannot be \
                   recorded, dependencies from Git URLs (pip, npm, cargo, uv) cannot be installed (an archive URL \
                   can), disk images cannot be mounted (extract them instead) and preferences cannot be written \
                   (`defaults write`).";
        let certificates = if self.network_deny_all {
            " Programs that check certificates through macOS (Swift and Go programs, `security`, `codesign --verify`) \
              fail here; curl and Python use their own certificate files and are not affected. WebKit-based tools and \
              background URL sessions fail here too."
        } else {
            ""
        };
        let ports = if self.loopback_all {
            "any loopback port".to_string()
        } else if self.loopback_ports.is_empty() {
            "no loopback port".to_string()
        } else {
            format!("loopback ports {}", self.loopback_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", "))
        };
        let sockets = if self.unix_sockets.is_empty() {
            String::new()
        } else {
            format!(" and the unix sockets {}", join_list(&self.unix_sockets))
        };
        format!(
            "Commands and file tools may write only under {}; writes under {protected} are refused even there.{exception} \
             {unreadable} cannot be read or written. {own}{credentials}{git} \
             Direct network access is blocked except connections to {ports}{sockets}; reach other hosts through the proxy named in the environment, if there is one.{certificates}",
            join_list(&self.writable)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    struct Fx {
        _dir: tempfile::TempDir,
        root: PathBuf,
        ws: PathBuf,
        tmp: PathBuf,
        home: PathBuf,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().canonicalize().expect("canonical");
        let (ws, tmp, home) = (root.join("ws"), root.join("tmp"), root.join("home"));
        for d in [&ws, &tmp, &home, &ws.join(".loom"), &home.join("keys")] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::write(home.join("token"), "t0ken").expect("write");
        std::fs::write(home.join("other"), "visible").expect("write");
        std::fs::write(home.join("keys").join("k"), "k").expect("write");
        Fx { _dir: dir, root, ws, tmp, home }
    }

    /// The production layout: the session temp dir lies inside the loom home.
    fn fx_prod() -> Fx {
        let mut f = fx();
        f.tmp = f.home.join("sessions").join("s1").join("tmp");
        std::fs::create_dir_all(&f.tmp).expect("mkdir");
        std::fs::write(f.home.join("sessions/s1/log.jsonl"), "{}").expect("write");
        f
    }

    /// A sandbox whose user home directory is `fake_home` instead of the real one.
    fn build_home(f: &Fx, c: &SandboxCfg, fake_home: &Path) -> Sandbox {
        Sandbox::with_home(c, &f.ws, &f.tmp, &f.home, None, Some(fake_home.to_path_buf())).expect("sandbox")
    }

    // The Git rules' names, written out: a letter is a class of both cases, and where the volume folds other
    // characters to it (the long s, the Kelvin sign U+212A, the `fi` ligature) an alternation that adds them.
    const G: &str = "[.][gG][iI][tT]";
    const WT: &str = "[wW][oO][rR](k|K|\u{212a})[tT][rR][eE][eE](s|S|\u{17f})";
    const MO: &str = "[mM][oO][dD][uU][lL][eE](s|S|\u{17f})";
    const NAMES: &str = "[cC][oO][nN]([fF][iI]|\u{fb01})[gG]|\
                         [cC][oO][nN]([fF][iI]|\u{fb01})[gG][.][wW][oO][rR](k|K|\u{212a})[tT][rR][eE][eE]|\
                         [hH][oO][oO](k|K|\u{212a})(s|S|\u{17f})|[cC][oO][mM][mM][oO][nN][dD][iI][rR]|[gG][iI][tT][dD][iI][rR]";

    /// The three Git rules over the writable roots `roots` (each written ` (subpath "…")`); `found` is the
    /// text of the third rule's exceptions, one for each repository found below a `modules` directory.
    fn git_lines_with(roots: &str, found: &str) -> String {
        format!(
            "(deny file-write* (require-all (require-any{roots}) (regex #\"^.*/{G}(/(({WT}/[^/]+|{MO}/(.+/)?[^/]+)/)?({NAMES})(/.*)?)?$\")))\n\
             (deny file-write-create file-write-unlink (require-all (require-any{roots}) (regex #\"^.*/{G}/({MO}/.+/)?({MO}|{WT})(/[^/]+)?$\")))\n\
             (deny file-write-create file-write-unlink (require-all (require-any{roots}) (regex #\"^.*/{G}/({MO}/.+/)?{MO}/[^/]+/.+$\"){found}))\n"
        )
    }

    /// The same with no repository found below a `modules` directory.
    fn git_lines(roots: &str) -> String {
        git_lines_with(roots, "")
    }

    /// The exception the third rule makes for the repository `dir`.
    fn git_exception(dir: &Path) -> String {
        let d = s(dir);
        format!(
            " (require-not (require-all (subpath \"{d}\") (require-not (subpath \"{d}/modules\")) (require-not (subpath \"{d}/worktrees\"))))"
        )
    }

    /// The rules after `(deny file-search)` that every profile has.
    const MOUNT_LINES: &str = "(deny file-mount)\n(deny user-preference-write)\n\
         (deny mach-lookup (global-name \"com.apple.DiskArbitration.diskarbitrationd\") (global-name \"com.apple.diskimagesiod\") (global-name \"com.apple.diskimagesiod.ram\") (global-name \"com.apple.diskmanagementd\"))\n";

    /// The `mach-lookup` deny that only `network_deny_all` adds.
    const FETCH_SERVICES: &str = "(deny mach-lookup (global-name \"com.apple.trustd.agent\") (global-name \"com.apple.trustd\") (global-name \"com.apple.ocspd\") (global-name \"com.apple.nsurlsessiond\") (global-name \"com.apple.nsurlsessiond.NSURLSessionProxyService\") (xpc-service-name-prefix \"com.apple.WebKit.\"))\n";

    fn cfg(mode: SandboxMode) -> SandboxCfg {
        SandboxCfg { mode, ..SandboxCfg::default() }
    }

    fn build(f: &Fx, c: &SandboxCfg, proxy: Option<u16>) -> Sandbox {
        Sandbox::new(c, &f.ws, &f.tmp, &f.home, proxy).expect("sandbox")
    }

    fn s(p: &Path) -> &str {
        p.to_str().expect("utf-8 path")
    }

    #[test]
    fn profile_has_the_verified_shape() {
        let f = fx();
        let c = SandboxCfg {
            extra_writable: vec![format!("{}/extra", s(&f.root))],
            protected_paths: vec!["secrets".into()],
            unreadable_paths: vec![format!("{}/hidden", s(&f.root))],
            loopback_ports: vec![9000, 8080],
            unix_sockets: vec![format!("{}/run.sock", s(&f.root))],
            protect_credentials: false,
            ..cfg(SandboxMode::Seatbelt)
        };
        let sb = build(&f, &c, Some(8080));
        let r = s(&f.root);
        // The directories that hold the denied paths and could be moved: the workspace (it holds `.loom`)
        // and, when the fixture lies in a system temp location, every directory from there down to it.
        let mut holders: Vec<&Path> = f.ws.ancestors().filter(|a| *a == f.ws).collect();
        holders.reverse();
        let holders: String = holders.iter().map(|a| format!(" (literal \"{}\")", s(a))).collect();
        let git = git_lines(&format!(" (subpath \"{r}/ws\") (subpath \"{r}/tmp\") (subpath \"{r}/extra\")"));
        let rx = regex_literal(&f.root).expect("regex-safe path");
        let expected = format!(
            "(version 1)\n(allow default)\n(deny signal)\n(allow signal (target same-sandbox))\n(deny file-write*)\n\
             (allow file-write* (subpath \"{r}/ws\") (subpath \"{r}/tmp\") (subpath \"{r}/extra\") (literal \"/dev/null\") (literal \"/dev/tty\") (literal \"/dev/dtracehelper\"))\n\
             (deny file-write* (subpath \"{r}/ws/.loom\") (subpath \"{r}/home\") (subpath \"{r}/ws/secrets\"))\n\
             (allow file-write* (subpath \"{r}/tmp\"))\n\
             (deny file-write-unlink file-write-create (literal \"{r}/tmp\"))\n\
             {git}\
             (deny file-write* (subpath \"{r}/home/token\") (subpath \"{r}/home/keys\") (subpath \"{r}/ws/.loom/oracle-secrets\") (subpath \"{r}/hidden\"))\n\
             (deny file-read* file-test-existence (subpath \"{r}/home/token\") (subpath \"{r}/home/keys\") (subpath \"{r}/ws/.loom/oracle-secrets\") (subpath \"{r}/hidden\"))\n\
             (deny file-read* file-test-existence (subpath \"{r}/home\"))\n\
             (allow file-read-metadata file-test-existence (literal \"{r}/home\"))\n\
             (allow file-test-existence (regex #\"^{rx}/home/[^/]+$\") (regex #\"^{rx}/home/node_modules/\"))\n\
             (allow file-read* file-test-existence (subpath \"{r}/tmp\"))\n\
             (deny file-read* file-test-existence (subpath \"{r}/home/token\") (subpath \"{r}/home/keys\"))\n\
             (deny file-write-unlink{holders})\n\
             (deny file-write-create (require-all (vnode-type SYMLINK) (require-any{holders})))\n\
             (deny lsopen)\n(deny appleevent-send)\n(deny job-creation)\n(deny file-search)\n\
             {MOUNT_LINES}\
             (deny network*)\n\
             (allow network-outbound (remote ip \"localhost:8080\"))\n\
             (allow network-outbound (remote ip \"localhost:9000\"))\n\
             (allow network-outbound (remote unix-socket (path-literal \"{r}/run.sock\")))\n\
             (allow network-bind (local ip \"localhost:*\"))\n\
             (allow network-inbound (local ip \"localhost:*\"))\n"
        );
        let actual = sb.profile().expect("profile");
        assert_eq!(actual, expected);
        // Neither the daemon port nor the certificate services are mentioned unless the configuration says so.
        assert!(!actual.contains(FETCH_SERVICES) && !actual.contains("network-outbound (remote ip \"*:"));
        let (prog, args) = sb.command("echo hi");
        assert_eq!(prog, "/usr/bin/sandbox-exec");
        assert_eq!(args[0], "-p");
        assert_eq!(args[1], actual);
        assert_eq!(&args[2..], ["/bin/bash", "-c", "echo hi"]);
    }

    #[test]
    fn profile_denies_launch_services_apple_events_and_launchd_jobs() {
        let f = fx();
        let p = build(&f, &cfg(SandboxMode::Seatbelt), None).profile().expect("profile");
        for rule in ["(deny lsopen)\n", "(deny appleevent-send)\n", "(deny job-creation)\n"] {
            assert!(p.contains(rule), "{rule} is missing: {p}");
        }
    }

    #[test]
    fn temp_dir_inside_the_loom_home_is_writable_but_nothing_else_there() {
        let f = fx_prod();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let p = sb.profile().expect("profile");
        let deny = p.find("(deny file-write* (subpath \"").expect("protected deny");
        let allow = p.rfind(&format!("(allow file-write* (subpath \"{}\"))\n", s(&f.tmp))).expect("tmp allow");
        assert!(allow > deny, "the temp-dir allow must come after the protected deny: {p}");
        let entry = p
            .rfind(&format!("(deny file-write-unlink file-write-create (literal \"{}\"))\n", s(&f.tmp)))
            .expect("tmp entry deny");
        assert!(entry > allow, "the deny for the temp dir entry must come after its allow: {p}");
        // Only removing, renaming and making it anew are refused: a write deny would make it test as unwritable.
        assert!(!p.contains(&format!("(deny file-write* (literal \"{}\"))", s(&f.tmp))), "{p}");
        for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
            let sb = build(&f, &cfg(mode), None);
            assert!(sb.check_write(&f.tmp.join("x")).is_ok());
            assert!(sb.check_write(&f.tmp.join("new/dir/x")).is_ok());
            // The entry itself is refused, as the profile refuses it.
            let e = sb.check_write(&f.tmp).expect_err("the temp dir itself");
            assert!(e.contains("session temp dir itself") && e.contains(&format!("{}/name", s(&f.tmp))), "{e}");
            assert!(sb.check_write(&f.home.join("sessions/s1/log.jsonl")).is_err());
            assert!(sb.check_write(&f.home.join("sessions/s1/tmpx")).is_err());
            assert!(sb.check_write(&f.home.join("sessions/s1/x")).is_err());
            assert!(sb.check_write(&f.home.join("other")).is_err());
        }
    }

    #[test]
    fn protected_path_inside_the_temp_dir_stays_protected() {
        let f = fx();
        // A temp dir that is the workspace itself must not unprotect `.loom`.
        let sb = Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &f.ws, &f.home, None).expect("sandbox");
        assert!(sb.check_write(&f.ws.join("a")).is_ok());
        assert!(sb.check_write(&f.ws.join(".loom/x")).is_err());
        let p = sb.profile().expect("profile");
        let last_allow = p.rfind("(allow file-write*").expect("allow");
        let last_deny = p.rfind(&format!("(deny file-write* (subpath \"{}/.loom\"))", s(&f.ws))).expect("deny");
        assert!(last_deny > last_allow, "{p}");
        // Nor does a temp dir that is itself a protected directory become writable.
        let dot = f.ws.join(".loom");
        let sb = Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &dot, &f.home, None).expect("sandbox");
        assert!(sb.check_write(&dot.join("x")).is_err());
        let p = sb.profile().expect("profile");
        let last_allow = p.rfind("(allow file-write*").expect("allow");
        let last_deny = p.rfind(&format!("(deny file-write* (subpath \"{}\"))", s(&dot))).expect("deny");
        assert!(last_deny > last_allow, "{p}");
        let none = Sandbox::new(&cfg(SandboxMode::None), &f.ws, &dot, &f.home, None).expect("sandbox");
        assert!(none.check_write(&dot.join("x")).is_err());
    }

    #[test]
    fn a_temp_dir_that_holds_the_loom_home_is_refused() {
        let f = fx();
        for tmp in [f.home.as_path(), f.root.as_path(), Path::new("/")] {
            for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
                let e = Sandbox::new(&cfg(mode), &f.ws, tmp, &f.home, None).expect_err("temp dir over the loom home");
                assert!(e.to_string().contains("session temp dir") && e.to_string().contains(s(&f.home)), "{e}");
            }
        }
        // A directory of its own inside the loom home is where it belongs.
        let inside = f.home.join("sessions/s1/tmp");
        assert!(Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &inside, &f.home, None).is_ok());
    }

    #[test]
    fn credentials_are_unreadable_by_default() {
        let f = fx();
        let fake = f.root.join("fakehome");
        std::fs::create_dir_all(fake.join(".ssh")).expect("mkdir");
        std::fs::write(fake.join(".ssh/id"), "private").expect("write");
        std::fs::write(fake.join(".netrc"), "machine x").expect("write");
        std::fs::write(fake.join("notes"), "fine").expect("write");
        let sb = build_home(&f, &cfg(SandboxMode::Seatbelt), &fake);
        // The refusal names the setting that governs it, which is not `unreadable_paths`.
        let e = sb.check_read(&fake.join(".ssh/id")).expect_err("ssh");
        assert!(e.contains("not readable") && e.contains("credential store"), "{e}");
        assert!(e.contains("`sandbox.protect_credentials = false`") && !e.contains("unreadable_paths"), "{e}");
        assert!(sb.check_read(&fake.join(".netrc")).is_err());
        assert!(sb.check_read(&fake.join(".aws/credentials")).is_err());
        assert!(sb.check_read(&fake.join("Library/Keychains/login.keychain-db")).is_err());
        assert!(sb.check_read(&fake.join("notes")).is_ok());
        // A store named by its file leaves the rest of its directory readable.
        assert!(sb.check_read(&fake.join(".claude/settings.json")).is_ok());
        assert!(sb.check_read(&fake.join("Library/Application Support/Claude/logs/main.log")).is_ok());
        for rel in [
            ".cache/huggingface/token",
            ".huggingface/token",
            ".pgpass",
            ".my.cnf",
            ".mylogin.cnf",
            ".vault-token",
            ".terraform.d/credentials.tfrc.json",
            ".config/rclone/rclone.conf",
            ".s3cfg",
            ".boto",
            ".gem/credentials",
            ".m2/settings.xml",
            ".m2/settings-security.xml",
            ".gradle/gradle.properties",
            ".yarnrc.yml",
            ".composer/auth.json",
            ".codex/auth.json",
            ".claude.json",
            ".claude/.credentials.json",
            ".config/github-copilot/apps.json",
            ".config/hub/hosts",
            ".config/glab-cli/config.yml",
            ".oci/config",
            ".config/doctl/config.yaml",
            ".fly/config.yml",
            ".config/heroku/x",
            ".heroku/accounts",
            ".config/netlify/config.json",
            ".config/sops/age/keys.txt",
            ".age/key",
            ".config/age/key",
            ".bitcoin/wallet.dat",
            ".ethereum/keystore",
            ".config/solana/id.json",
            ".wrangler/config",
            ".config/.wrangler/config",
            ".pulumi/credentials.json",
            "Library/Application Support/doctl/config.yaml",
            "Library/Application Support/sops/age/keys.txt",
            "Library/Preferences/netlify/config.json",
            "Library/Preferences/.wrangler/config/default.toml",
            "Library/Application Support/Google/Chrome Beta/Default/Cookies",
            "Library/Application Support/Google/Chrome Canary/Default/Cookies",
            "Library/Application Support/Chromium/Default/Login Data",
            "Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
            "Library/Application Support/Microsoft Edge/Default/Login Data",
            "Library/Application Support/Arc/User Data/Default/Cookies",
            "Library/Application Support/Vivaldi/Default/Cookies",
            "Library/Application Support/com.operasoftware.Opera/Cookies",
            "Library/Application Support/Bitwarden/data.json",
            "Library/Application Support/Bitwarden CLI/data.json",
            "Library/Containers/com.bitwarden.desktop/Data/Library/Application Support/Bitwarden/data.json",
            "Library/Application Support/1Password/x",
            "Library/Application Support/Telegram Desktop/tdata/key_datas",
            "Library/Application Support/Claude/claude_desktop_config.json",
            "Library/Group Containers/group.x/vault",
            "Library/Mail/V10/x",
            "Library/Messages/chat.db",
        ] {
            assert!(sb.check_read(&fake.join(rel)).is_err(), "{rel} must be unreadable");
            assert!(sb.check_write(&fake.join(rel)).is_err(), "{rel} must be unwritable");
        }
        let p = sb.profile().expect("profile");
        assert!(p.contains(&format!("(subpath \"{}/.ssh\")", s(&fake))), "{p}");
        assert!(p.contains(&format!("(subpath \"{}/.pgpass\")", s(&fake))), "{p}");
        let d = sb.describe();
        assert!(d.contains("Credential directories") && d.contains("the profiles of common browsers"), "{d}");
        // Mode none keeps the read rule for the file tools, and says that it is theirs alone.
        let none = build_home(&f, &cfg(SandboxMode::None), &fake);
        assert!(none.check_read(&fake.join(".ssh/id")).is_err());
        let d = none.describe();
        assert!(
            d.contains("They also refuse to read or write credential directories") && !d.contains("off limits"),
            "{d}"
        );
        // Switched off, nothing is added.
        let off = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        let sb = build_home(&f, &off, &fake);
        assert!(sb.check_read(&fake.join(".ssh/id")).is_ok());
        assert!(!sb.profile().expect("profile").contains(".ssh"));
        assert!(!sb.describe().contains("Credential directories"));
    }

    #[test]
    fn a_workspace_inside_a_credential_directory_stays_readable() {
        let f = fx();
        let fake = f.root.join("fakehome2");
        let ws = fake.join(".config/gh/project");
        std::fs::create_dir_all(&ws).expect("mkdir");
        std::fs::create_dir_all(fake.join(".ssh")).expect("mkdir");
        let sb = Sandbox::with_home(&cfg(SandboxMode::Seatbelt), &ws, &f.tmp, &f.home, None, Some(fake.clone()))
            .expect("sandbox");
        assert!(sb.check_read(&ws.join("src.rs")).is_ok());
        assert!(sb.check_read(&fake.join(".config/gh/hosts.yml")).is_ok());
        assert!(sb.check_read(&fake.join(".ssh/id")).is_err());
        assert!(!sb.profile().expect("profile").contains(&format!("(subpath \"{}/.config/gh\")", s(&fake))));
    }

    #[test]
    fn credential_protection_needs_a_home_directory() {
        let f = fx();
        // Without a home directory the stores cannot be located; protecting nothing in silence is not an option.
        for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
            let e = Sandbox::with_home(&cfg(mode), &f.ws, &f.tmp, &f.home, None, None).expect_err("no home directory");
            let e = e.to_string();
            assert!(e.contains("HOME") && e.contains("protect_credentials = false"), "{e}");
        }
        let off = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        let sb = Sandbox::with_home(&off, &f.ws, &f.tmp, &f.home, None, None).expect("sandbox");
        assert!(!sb.describe().contains("redential"), "{}", sb.describe());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn protected_and_unreadable_rules_ignore_case_on_macos() {
        let f = fx();
        // A workspace with no `.loom` yet, and configured paths that do not exist: `realpath` restores the
        // spelling of what is on disk, so only for a missing path does the comparison itself decide.
        let (ws, fake) = (f.root.join("bare"), f.root.join("fakehome3"));
        for d in [&ws, &fake] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        let c = SandboxCfg {
            protected_paths: vec!["secrets".into()],
            unreadable_paths: vec![format!("{}/hidden", s(&f.root))],
            ..cfg(SandboxMode::Seatbelt)
        };
        let sb = Sandbox::with_home(&c, &ws, &f.tmp, &f.home, None, Some(fake.clone())).expect("sandbox");
        assert!(sb.check_write(&ws.join(".LOOM/x")).is_err());
        assert!(sb.check_write(&ws.join(".Loom")).is_err());
        assert!(sb.check_write(&ws.join("SECRETS/x")).is_err());
        assert!(sb.check_write(&ws.join(".loomy")).is_ok());
        assert!(sb.check_write(&ws.join("Secret")).is_ok());
        assert!(sb.check_read(&f.root.join("HIDDEN/x")).is_err());
        assert!(sb.check_read(&f.root.join("Hidden")).is_err());
        assert!(sb.check_read(&fake.join(".SSH/id")).is_err());
        assert!(sb.check_read(&f.root.join("hidden2")).is_ok());
        assert!(!ws.join(".loom").exists() && !ws.join("secrets").exists() && !f.root.join("hidden").exists());
        // Letters outside ASCII fold too, and a longer name is not a match.
        let rule = Path::new("/a/école");
        assert!(under(Path::new("/A/ÉCOLE/x"), rule) && under(Path::new("/a/École"), rule));
        assert!(!under(Path::new("/a/écoles"), rule) && !under(Path::new("/a"), rule));
    }

    #[test]
    fn loopback_all_replaces_port_rules() {
        let f = fx();
        let c = SandboxCfg { loopback_all: true, loopback_ports: vec![9000], ..cfg(SandboxMode::Seatbelt) };
        let p = build(&f, &c, Some(8080)).profile().expect("profile");
        assert!(p.contains("(allow network-outbound (remote ip \"localhost:*\"))\n"));
        assert!(!p.contains("localhost:9000"));
    }

    #[test]
    fn special_characters_are_escaped_and_control_characters_refused() {
        let f = fx();
        let odd = f.root.join("a\"b\\c");
        std::fs::create_dir_all(&odd).expect("mkdir");
        let sb = Sandbox::new(&cfg(SandboxMode::Seatbelt), &odd, &f.tmp, &f.home, None).expect("sandbox");
        let p = sb.profile().expect("profile");
        assert!(p.contains(&format!("(subpath \"{}/a\\\"b\\\\c\")", s(&f.root))), "{p}");

        let bad = f.root.join("new\nline");
        std::fs::create_dir_all(&bad).expect("mkdir");
        let err = Sandbox::new(&cfg(SandboxMode::Seatbelt), &bad, &f.tmp, &f.home, None).expect_err("control char");
        assert!(err.to_string().contains("control character"), "{err}");
    }

    #[test]
    fn paths_are_canonical() {
        let f = fx();
        let link = f.root.join("link");
        symlink(&f.ws, &link).expect("symlink");
        let c = SandboxCfg { extra_writable: vec![format!("{}/newdir", s(&link))], ..cfg(SandboxMode::Seatbelt) };
        let sb = Sandbox::new(&c, &link, &f.tmp, &f.home, None).expect("sandbox");
        assert_eq!(sb.workspace(), f.ws);
        assert_eq!(sb.tmp_dir(), f.tmp);
        let p = sb.profile().expect("profile");
        assert!(p.contains(&format!("(subpath \"{}/newdir\")", s(&f.ws))), "{p}");
        assert!(!p.contains(s(&link)), "{p}");
        // `..` in a configured path that does not exist is applied lexically.
        let c = SandboxCfg { extra_writable: vec!["/usr/local/loomtest/a/../b".into()], ..cfg(SandboxMode::Seatbelt) };
        let p = build(&f, &c, None).profile().expect("profile");
        assert!(p.contains("(subpath \"/usr/local/loomtest/b\")"), "{p}");
    }

    #[test]
    fn check_write_follows_the_policy() {
        let f = fx();
        let c = SandboxCfg {
            extra_writable: vec!["/usr/local/loomtest".into()],
            protected_paths: vec!["/usr/local/loomtest/p".into(), "ws-protected".into()],
            ..cfg(SandboxMode::Seatbelt)
        };
        let sb = build(&f, &c, None);
        // Accepted: existing file, a file that does not exist yet (in a directory that does not
        // exist either), the session temp dir, an extra root, a device.
        assert_eq!(sb.check_write(&f.ws.join("a.txt")), Ok(f.ws.join("a.txt")));
        assert_eq!(sb.check_write(&f.ws.join("new/dir/a.txt")), Ok(f.ws.join("new/dir/a.txt")));
        assert!(sb.check_write(&f.tmp.join("x")).is_ok());
        // Not the temp dir itself, although it is a writable root: the profile refuses to replace it.
        assert!(sb.check_write(&f.tmp).expect_err("temp dir entry").contains("session temp dir itself"));
        assert!(sb.check_write(Path::new("/usr/local/loomtest/a/b")).is_ok());
        assert!(sb.check_write(Path::new("/dev/null")).is_ok());
        // Refused: outside, the protected directory, the loom home, configured protected paths.
        let e = sb.check_write(Path::new("/usr/bin/x")).expect_err("outside");
        assert!(e.contains("/usr/bin/x") && e.contains("outside the writable areas") && e.contains(s(&f.ws)), "{e}");
        let e = sb.check_write(&f.ws.join(".loom/events")).expect_err("protected");
        assert!(e.contains("protected") && e.contains(".loom"), "{e}");
        assert!(sb.check_write(&f.ws.join(".loom")).is_err());
        assert!(sb.check_write(&f.home.join("anything")).is_err());
        assert!(sb.check_write(Path::new("/usr/local/loomtest/p/q")).is_err());
        assert!(sb.check_write(&f.ws.join("ws-protected/q")).is_err());
        // A sibling whose name merely starts like a protected one is fine.
        assert!(sb.check_write(&f.ws.join(".loomy")).is_ok());
        // A writable root is matched exactly, on every platform: only the rules that refuse ignore case.
        assert!(sb.check_write(Path::new("/usr/local/LOOMTEST/a")).is_err());
        // Relative paths and `..` that cannot be resolved.
        assert!(sb.check_write(Path::new("rel/x")).expect_err("relative").contains("absolute"));
        let e = sb.check_write(&f.ws.join("nothere/../x")).expect_err("dotdot");
        assert!(e.contains(".."), "{e}");
        // `..` through existing directories is resolved, and the resolved path is judged.
        std::fs::create_dir_all(f.ws.join("sub")).expect("mkdir");
        assert!(sb.check_write(&f.ws.join("sub/../ok")).is_ok());
        assert!(sb.check_write(&f.ws.join("sub/../.loom/x")).is_err());
        let up = f.ws.join("sub/../../../../../../../../usr/bin/x");
        assert!(sb.check_write(&up).is_err());
    }

    #[test]
    fn check_write_resolves_symlinks() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        symlink("/usr/bin", f.ws.join("esc")).expect("symlink");
        let e = sb.check_write(&f.ws.join("esc/newfile")).expect_err("escape");
        assert!(e.contains("/usr/bin/newfile") && e.contains("resolved from"), "{e}");
        // A link to the protected directory is the protected directory.
        symlink(f.ws.join(".loom"), f.ws.join("sneaky")).expect("symlink");
        assert!(sb.check_write(&f.ws.join("sneaky/x")).is_err());
        // A link that stays inside is fine.
        std::fs::create_dir_all(f.ws.join("sub")).expect("mkdir");
        symlink(f.ws.join("sub"), f.ws.join("inside")).expect("symlink");
        assert_eq!(sb.check_write(&f.ws.join("inside/x")), Ok(f.ws.join("sub/x")));
        // A dangling link cannot be judged and is refused with advice.
        symlink("/nonexistent-loom-target", f.ws.join("dangling")).expect("symlink");
        let e = sb.check_write(&f.ws.join("dangling")).expect_err("dangling");
        assert!(e.contains("points nowhere"), "{e}");
    }

    #[test]
    fn check_read_refuses_credentials_and_configured_paths() {
        let f = fx();
        let c = SandboxCfg {
            unreadable_paths: vec![format!("{}/hidden", s(&f.root)), "~/.loomtest-ssh".into()],
            ..cfg(SandboxMode::Seatbelt)
        };
        let sb = build(&f, &c, None);
        assert!(sb.check_read(&f.home.join("token")).expect_err("token").contains("not readable"));
        assert!(sb.check_read(&f.home.join("keys/k")).is_err());
        let e = sb.check_read(&f.root.join("hidden/x")).expect_err("configured");
        assert!(e.contains("`sandbox.unreadable_paths`") && !e.contains("protect_credentials"), "{e}");
        // Nothing else in the loom home is readable either.
        assert!(sb.check_read(&f.home.join("other")).expect_err("loom home").contains("loom home"));
        assert!(sb.check_read(&f.ws.join("anything")).is_ok());
        assert!(sb.check_read(Path::new("/usr/bin/env")).is_ok());
        // A link cannot be used to read around the rule.
        symlink(f.home.join("token"), f.ws.join("tok")).expect("symlink");
        assert!(sb.check_read(&f.ws.join("tok")).is_err());
        if let Some(h) = &sb.home {
            assert!(sb.check_read(&h.join(".loomtest-ssh/id")).is_err());
        }
    }

    #[test]
    fn what_cannot_be_read_cannot_be_written_either() {
        let f = fx();
        // The workspace is the home directory, so the credential stores lie inside a writable root; so do
        // a configured unreadable path in the workspace and one that `extra_writable` covers.
        let c = SandboxCfg {
            unreadable_paths: vec!["hidden".into(), "hidden/inner".into(), format!("{}/extra/deny", s(&f.root))],
            extra_writable: vec![format!("{}/extra", s(&f.root))],
            ..cfg(SandboxMode::Seatbelt)
        };
        let (ws, root) = (s(&f.ws), s(&f.root));
        for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
            let c = SandboxCfg { mode, ..c.clone() };
            let sb = Sandbox::with_home(&c, &f.ws, &f.tmp, &f.home, None, Some(f.ws.clone())).expect("sandbox");
            let e = sb.check_write(&f.ws.join("hidden/x")).expect_err("unreadable");
            assert!(e.contains("not writable") && e.contains("`sandbox.unreadable_paths`"), "{e}");
            assert!(sb.check_write(&f.ws.join("hidden")).is_err());
            assert!(sb.check_write(&f.root.join("extra/deny/x")).is_err());
            let e = sb.check_write(&f.ws.join(".ssh/config")).expect_err("credential");
            assert!(e.contains("credential store") && e.contains("`sandbox.protect_credentials = false`"), "{e}");
            assert!(sb.check_write(&f.ws.join(".ssh")).is_err());
            assert!(sb.check_write(&f.ws.join(".config/gh/hosts.yml")).is_err());
            assert!(sb.check_write(&f.ws.join(".config/other")).is_ok());
            assert!(sb.check_write(&f.root.join("extra/ok")).is_ok());
            // The loom home's own entries keep its message: `sandbox.unreadable_paths` does not govern them.
            for entry in ["token", "keys/k"] {
                let e = sb.check_write(&f.home.join(entry)).expect_err("loom home entry");
                assert!(e.contains("is protected") && !e.contains("unreadable_paths"), "{e}");
            }
        }
        let sb = Sandbox::with_home(&c, &f.ws, &f.tmp, &f.home, None, Some(f.ws.clone())).expect("sandbox");
        let p = sb.profile().expect("profile");
        let writes = p
            .lines()
            .find(|l| l.starts_with("(deny file-write* (subpath") && l.contains("/hidden\""))
            .expect("write deny");
        for denied in
            [format!("{ws}/hidden"), format!("{root}/extra/deny"), format!("{ws}/.ssh"), format!("{ws}/.config/gh")]
        {
            assert!(writes.contains(&format!("(subpath \"{denied}\")")), "{denied}: {p}");
        }
        // Nor can the directories that hold them be moved: the workspace, `.config`, `Library`, the extra root.
        let held = p.lines().rfind(|l| l.starts_with("(deny file-write-unlink")).expect("holders");
        for dir in [
            ws.to_string(),
            format!("{ws}/.config"),
            format!("{ws}/Library/Application Support"),
            format!("{root}/extra"),
        ] {
            assert!(held.contains(&format!("(literal \"{dir}\")")), "{dir}: {p}");
        }
        // A directory that a rule of its own already covers is not listed: a denied one, the loom home.
        for dir in [format!("{ws}/hidden"), s(&f.home).to_string()] {
            assert!(!held.contains(&format!("(literal \"{dir}\")")), "{dir}: {p}");
        }
    }

    #[test]
    fn a_denied_path_reached_through_a_link_is_denied_as_written_too() {
        let f = fx();
        // The workspace is the home directory: `.ssh` and a configured path are links, and so is `.cargo`,
        // which holds `.cargo/credentials`.
        for d in ["Sync/ssh", "Sync/cargo", "Sync/hidden"] {
            std::fs::create_dir_all(f.ws.join(d)).expect("mkdir");
        }
        let links = [(".ssh", "Sync/ssh"), (".cargo", "Sync/cargo"), ("hidden", "Sync/hidden")];
        for (link, target) in links {
            symlink(f.ws.join(target), f.ws.join(link)).expect("symlink");
        }
        let c = SandboxCfg { unreadable_paths: vec!["./hidden".into()], ..cfg(SandboxMode::Seatbelt) };
        let sb = Sandbox::with_home(&c, &f.ws, &f.tmp, &f.home, None, Some(f.ws.clone())).expect("sandbox");
        let p = sb.profile().expect("profile");
        let ws = s(&f.ws);
        // Removed, the link could be replaced by a directory of the command's own: both spellings are denied.
        for rule in ["(deny file-write* (subpath", "(deny file-read* file-test-existence (subpath"] {
            let line = p.lines().find(|l| l.starts_with(rule) && l.contains("/Sync/ssh\"")).expect(rule);
            for denied in [".ssh", "Sync/ssh", ".cargo/credentials", "Sync/cargo/credentials", "hidden", "Sync/hidden"]
            {
                assert_eq!(line.matches(&format!("(subpath \"{ws}/{denied}\")")).count(), 1, "{denied}: {p}");
            }
            // A path that no link makes differ is listed once.
            assert_eq!(line.matches(&format!("(subpath \"{ws}/.aws\")")).count(), 1, "{p}");
        }
        // The link above a denied path is a directory that holds one, as is its target.
        let unlink = p.lines().rfind(|l| l.starts_with("(deny file-write-unlink")).expect("holders");
        let create = p.lines().find(|l| l.contains("(vnode-type SYMLINK)")).expect("holders");
        for held in [unlink, create] {
            for dir in [format!("{ws}/.cargo"), format!("{ws}/Sync/cargo")] {
                assert!(held.contains(&format!("(literal \"{dir}\")")), "{dir}: {p}");
            }
        }
        // The file tools see the same: once the link is gone, the name as written is still refused.
        std::fs::remove_file(f.ws.join(".ssh")).expect("rm");
        std::fs::create_dir(f.ws.join(".ssh")).expect("mkdir");
        assert!(sb.check_read(&f.ws.join(".ssh/id")).is_err() && sb.check_write(&f.ws.join(".ssh/id")).is_err());
        assert!(sb.check_read(&f.ws.join("Sync/hidden/x")).is_err() && sb.check_read(&f.ws.join("Sync/other")).is_ok());
    }

    #[test]
    fn mode_none_has_no_process_profile_and_keeps_file_guards() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::None), None);
        assert_eq!(sb.mode(), SandboxMode::None);
        assert!(sb.profile().is_none());
        assert_eq!(sb.command("ls -l"), ("/bin/bash".to_string(), vec!["-c".to_string(), "ls -l".to_string()]));
        assert!(sb.check_write(Path::new("/usr/bin/x")).is_ok());
        assert!(sb.check_write(&f.ws.join(".loom/x")).is_err());
        assert!(sb.check_write(&f.home.join("x")).is_err());
        assert!(sb.check_read(&f.home.join("token")).is_err());
        assert!(sb.check_read(Path::new("/usr/bin/env")).is_ok());
        assert!(sb.describe().contains("not confined"));
    }

    #[test]
    fn preflight_checks_the_launcher_and_the_platform() {
        let f = fx();
        let missing = f.root.join("no-sandbox-exec");
        let e = preflight_at(SandboxMode::Seatbelt, &missing, true).expect_err("missing");
        assert!(e.contains("missing or not executable") && e.contains("macOS") && e.contains("mode = \"none\""), "{e}");
        let plain = f.root.join("plain-file");
        std::fs::write(&plain, "x").expect("write");
        assert!(preflight_at(SandboxMode::Seatbelt, &plain, true).is_err());
        let e = preflight_at(SandboxMode::Seatbelt, Path::new("/bin/sh"), false).expect_err("not macOS");
        assert!(e.contains("not macOS") && e.contains("mode = \"none\""), "{e}");
        assert!(preflight_at(SandboxMode::None, &missing, false).is_ok());
        assert!(preflight_at(SandboxMode::Seatbelt, Path::new("/bin/sh"), true).is_ok());
        if available() {
            assert!(preflight(&cfg(SandboxMode::Seatbelt)).is_ok());
        }
    }

    #[test]
    fn resolve_expands_home_and_joins_relative_paths() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::None), None);
        assert_eq!(sb.resolve("a/b.txt"), f.ws.join("a/b.txt"));
        assert_eq!(sb.resolve("/etc/hosts"), PathBuf::from("/etc/hosts"));
        assert_eq!(sb.resolve("../up"), f.ws.join("../up"));
        if let Some(h) = sb.home.clone() {
            assert_eq!(sb.resolve("~"), h);
            assert_eq!(sb.resolve("~/x/y"), h.join("x/y"));
        }
        assert_eq!(sb.resolve("~other/x"), f.ws.join("~other/x"));
    }

    #[test]
    fn env_scrubs_secrets_and_sets_fixed_variables() {
        let f = fx();
        let c = SandboxCfg { env_pass: vec!["MY_API_KEY".into()], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, None);
        let parent: BTreeMap<String, String> = [
            ("PATH", "/usr/bin"),
            ("HOME", "/h"),
            ("OPENAI_API_KEY", "x"),
            ("MY_API_KEY", "kept"),
            ("github_token", "x"),
            ("DB_PASSWORD", "x"),
            ("PASSWD_FILE", "x"),
            ("AWS_SECRET_ACCESS_KEY", "x"),
            ("SOME_CREDENTIALS", "x"),
            ("LOOM_HOME", "x"),
            ("loom_x", "x"),
            ("TERM", "xterm"),
            ("PAGER", "less"),
            ("GH_PAT", "x"),
            ("SENTRY_DSN", "x"),
            ("MYSQL_PWD", "x"),
            ("PWD", "/w"),
            ("OLDPWD", "/o"),
            ("DATABASE_URL", "x"),
            ("SSH_AUTH_SOCK", "x"),
            ("GITHUB_AUTH_TOKEN_X", "x"),
            ("SESSION_COOKIE_JAR", "x"),
            ("MY_SESSION_KEY_V", "x"),
            ("DATABASE_HOST", "kept-host"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let env = sb.env(&parent);
        let keys: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "DATABASE_HOST",
                "GIT_PAGER",
                "GIT_TERMINAL_PROMPT",
                "HOME",
                "MY_API_KEY",
                "NO_COLOR",
                "OLDPWD",
                "PAGER",
                "PATH",
                "PWD",
                "TERM",
                "TMPDIR"
            ]
        );
        assert_eq!(env["MY_API_KEY"], "kept");
        // `env_pass` overrides the new rules too.
        let c = SandboxCfg { env_pass: vec!["GH_PAT".into(), "SSH_AUTH_SOCK".into()], ..cfg(SandboxMode::Seatbelt) };
        let passed = build(&f, &c, None).env(&parent);
        assert_eq!((passed["GH_PAT"].as_str(), passed["SSH_AUTH_SOCK"].as_str()), ("x", "x"));
        assert_eq!(env["TERM"], "dumb");
        assert_eq!(env["PAGER"], "cat");
        assert_eq!(env["GIT_TERMINAL_PROMPT"], "0");
        assert_eq!(env["NO_COLOR"], "1");
        assert_eq!(env["TMPDIR"], s(&f.tmp));
    }

    #[test]
    fn env_withholds_sessions_auth_urls_with_passwords_and_profile_key_variables() {
        let f = fx();
        let c = SandboxCfg {
            secret_env: vec!["MYSERVER_ACCESS".into()],
            env_pass: vec!["PASSED_PASS".into()],
            ..cfg(SandboxMode::Seatbelt)
        };
        let sb = build(&f, &c, None);
        let withheld = [
            ("BW_SESSION", "x"),
            ("OP_SESSION_myaccount", "x"),
            ("DOCKER_AUTH_CONFIG", "x"),
            ("NPM_CONFIG__AUTH", "x"),
            ("npm_config__auth", "x"),
            ("REDIS_URL", "redis://:hunter2@h:6379/0"),
            ("MONGODB_URI", "mongodb+srv://u:pw@cluster.example/db"),
            ("TEST_DATABASE_URL", "postgres://u:pw@h/db"),
            ("AMQP_URL", "amqp://guest:guest@h:5672"),
            ("SLACK_WEBHOOK_URL", "https://hooks.example/x"),
            ("SMTP_PASS", "x"),
            ("CI_JOB_JWT", "x"),
            ("MY_PRIVATE_THING", "x"),
            ("TERM_SESSION_ID", "x"),
            ("XDG_SESSION_TYPE", "tty"),
            ("MYSERVER_ACCESS", "x"),
            ("BORG_PASSPHRASE", "x"),
            ("GPG_PASSPHRASE", "x"),
            ("PASSPHRASE", "x"),
            ("DB_PW", "x"),
            ("ADMIN_PW", "x"),
            ("INNOCENT_NAME", "https://user:secret@host/path"),
            // The password is found wherever a URL starts in the value, and a `,` in it does not hide it.
            ("JDBC", "jdbc:mysql://root:pw@db:3306/app"),
            ("ES_HOSTS", "[\"https://elastic:pw@es:9200\"]"),
            ("SENTINELS", "redis://s1:26379,redis://:pw@s2:26379"),
            ("PG", "postgres://u:p,w@h/db"),
        ];
        let kept = [
            ("PATH", "/usr/bin"),
            ("HOME", "/h"),
            ("PWD", "/w"),
            ("OLDPWD", "/o"),
            ("LANG", "C"),
            ("PASSED_PASS", "x"),
            ("PASSIVE", "x"),
            ("SERVER_URL", "https://host/path"),
            ("REMOTE", "https://user@host/path"),
            ("ADDR", "redis://h:6379/0"),
            ("MIRRORS", "https://a.example:443,https://u@b.example"),
            ("NEXT", "https://a.example/x?to=http://b.example"),
        ];
        let parent: BTreeMap<String, String> =
            withheld.iter().chain(&kept).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let env = sb.env(&parent);
        for (k, _) in &withheld {
            assert!(!env.contains_key(*k), "{k} must be withheld");
        }
        for (k, _) in &kept {
            assert!(env.contains_key(*k), "{k} must be kept");
        }
        // `env_pass` overrides a password-bearing URL too.
        let c = SandboxCfg { env_pass: vec!["REDIS_URL".into()], ..cfg(SandboxMode::Seatbelt) };
        assert!(build(&f, &c, None).env(&parent).contains_key("REDIS_URL"));
    }

    #[test]
    fn describe_is_deterministic_and_states_the_policy() {
        let f = fx();
        let c = SandboxCfg { loopback_ports: vec![9000], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, Some(8080));
        let d = sb.describe();
        assert_eq!(d, sb.describe());
        assert!(d.contains(s(&f.ws)) && d.contains(".loom") && d.contains("token") && d.contains("8080, 9000"), "{d}");
        let all = SandboxCfg { loopback_all: true, ..cfg(SandboxMode::Seatbelt) };
        assert!(build(&f, &all, None).describe().contains("any loopback port"));
        // The temp dir does not lie inside a protected directory here, so there is no exception to state.
        assert!(!d.contains("exception"), "{d}");
    }

    #[test]
    fn describe_names_the_temp_dir_as_the_exception_in_the_production_layout() {
        let f = fx_prod();
        let exception =
            format!("The one exception is the session temp dir {}: what is in it can be written.", s(&f.tmp));
        for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
            let d = build(&f, &cfg(mode), None).describe();
            assert!(d.contains(s(&f.home)) && d.contains(&exception), "{d}");
        }
        let d = build(&f, &cfg(SandboxMode::Seatbelt), None).describe();
        let (writable, refused) =
            (d.find(s(&f.tmp)).expect("writable"), d.find("are refused even there").expect("refused"));
        assert!(writable < refused && d.find(&exception).is_some_and(|e| e > refused), "{d}");
        // A temp dir that is itself protected has no exception.
        let dot = f.ws.join(".loom");
        let d = Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &dot, &f.home, None).expect("sandbox").describe();
        assert!(!d.contains("exception"), "{d}");
    }

    #[test]
    fn test_environment_builds() {
        let e = crate::testutil::env();
        assert_eq!(e.ctx.sandbox.mode(), SandboxMode::None);
    }

    #[test]
    fn session_temp_is_the_only_default_temp_write_grant() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        assert!(sb.check_write(&f.tmp.join("own")).is_ok());
        assert!(sb.check_write(&f.root.join("sibling-session.tmp")).is_err());
        let profile = sb.profile().unwrap();
        assert!(!profile.contains("(subpath \"/private/tmp\")"));
        assert!(!profile.contains("(subpath \"/private/var/folders\")"));
    }

    #[test]
    fn nested_and_future_git_metadata_are_protected_without_blocking_source_edits() {
        let f = fx();
        let git = f.ws.join("nested/.git");
        std::fs::create_dir_all(git.join("hooks")).unwrap();
        std::fs::write(git.join("config"), "original").unwrap();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        for path in [
            git.join("config"),
            git.join("config.worktree"),
            git.join("hooks/pre-commit"),
            f.ws.join("new/.git/config"),
            f.ws.join("new/.GIT/hooks/tool"),
            f.ws.join("new/.git"),
        ] {
            assert!(sb.check_write(&path).is_err(), "{}", path.display());
        }
        assert!(sb.check_write(&f.ws.join("nested/source.rs")).is_ok());
        assert!(sb.check_write(&git.join("objects/object")).is_ok());
        if available() {
            assert!(!run(&sb, &f.ws, "echo changed > nested/.git/config").0);
            assert!(!run(&sb, &f.ws, "echo changed > nested/.git/hooks/pre-commit").0);
            assert!(!run(&sb, &f.ws, "mkdir -p new/.git").0);
        }
    }

    #[test]
    fn isolated_replay_only_writes_private_temp_and_keeps_original_read_network_policy() {
        let f = fx_prod();
        let caller = build(&f, &cfg(SandboxMode::Seatbelt), Some(8080));
        let private = caller.oracle_staging_root().join("oracle-private");
        let ws = private.join("workspace");
        let tmp = private.join("tmp");
        for path in [&ws, &tmp] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::fs::write(ws.join("source"), "original").unwrap();
        std::fs::write(f.ws.join("actor-source"), "mutable original").unwrap();
        assert!(caller.check_write(&ws.join("source")).is_err());
        assert!(caller.check_write(&tmp.join("fake-result")).is_err());
        let replay = caller.isolated_replay(&ws, &tmp).unwrap();
        assert!(replay.check_write(&ws.join("source")).is_err());
        assert!(replay.check_write(&f.tmp.join("old-temp")).is_err());
        assert!(replay.check_write(&tmp.join("own-result")).is_ok());
        assert!(replay.check_read(&f.home.join("token")).is_err());
        assert!(replay.check_read(&f.ws.join("actor-source")).is_err());
        assert!(replay.check_read(&f.tmp.join("mutable-dependency")).is_err());
        assert!(replay.check_read(&f.home.join("sessions/another-agent/tmp/import.py")).is_err());
        assert!(replay.check_read(&ws.join("source")).is_ok());
        assert_eq!(caller.loopback_ports, replay.loopback_ports);
        assert_eq!(caller.unix_sockets, replay.unix_sockets);
        assert!(caller.isolated_replay(&f.ws, &f.tmp).is_err());
        let unconfined = build(&f, &cfg(SandboxMode::None), None);
        assert!(unconfined.isolated_replay(&ws, &tmp).is_err());
        if available() {
            assert!(!run(&caller, &f.ws, &format!("echo fake > '{}/fake-result'", tmp.display())).0);
            assert!(!run(&replay, &ws, "chmod 666 source; echo modified > source").0);
            assert!(!run(&replay, &ws, &format!("cat '{}/actor-source'", f.ws.display())).0);
            assert!(run(&replay, &ws, "cat source").0);
            assert_eq!(std::fs::read_to_string(ws.join("source")).unwrap(), "original");
            assert!(run(&replay, &ws, "echo genuine > \"$TMPDIR/result\"").0);
        }
    }

    #[test]
    fn replay_retains_judges_actor_origins_without_changing_ordinary_reads_and_rejects_broad_origins() {
        let f = fx_prod();
        let extra = f.root.join("actor-cache");
        std::fs::create_dir(&extra).unwrap();
        std::fs::write(extra.join("dependency.py"), "mutable library").unwrap();
        let cfg = SandboxCfg {
            protected_paths: vec![f.ws.display().to_string()],
            replay_untrusted_paths: vec![extra.display().to_string()],
            ..cfg(SandboxMode::Seatbelt)
        };
        let judge = build(&f, &cfg, None);
        assert!(judge.check_read(&extra.join("dependency.py")).is_ok());
        assert!(judge.check_write(&extra.join("dependency.py")).is_err());
        let private = judge.oracle_staging_root().join("retained-origins");
        let (ws, tmp) = (private.join("workspace"), private.join("tmp"));
        for path in [&ws, &tmp] {
            std::fs::create_dir_all(path).unwrap();
        }
        let replay = judge.isolated_replay(&ws, &tmp).unwrap();
        assert!(replay.check_read(&extra.join("dependency.py")).is_err());
        if available() {
            assert!(!run(&replay, &ws, &format!("cat '{}/dependency.py'", extra.display())).0);
        }
        let mut broad = judge.clone();
        broad.replay_untrusted.push(f.root.clone());
        assert!(broad.isolated_replay(&ws, &tmp).is_err());
    }

    #[test]
    fn oracle_secrets_are_denied_before_creation_and_through_symlinks() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let secrets = f.ws.join(".loom/oracle-secrets");
        assert!(sb.check_read(&secrets.join("key")).is_err());
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(secrets.join("key"), "test-only-secret").unwrap();
        let alias = f.ws.join("alias-key");
        symlink(secrets.join("key"), &alias).unwrap();
        assert!(sb.check_read(&alias).is_err());
        let judge = |real: &Path| sb.check_read(real).map(|_| ());
        assert!(crate::files::open_readable(&alias, &judge).is_err());
    }

    #[test]
    fn git_profile_handles_quoted_and_regex_special_workspace_names() {
        if !available() {
            return;
        }
        let f = fx();
        let ws = f.ws.join("quote\" [literal] (dir)");
        std::fs::create_dir(&ws).unwrap();
        let sb = Sandbox::new(&cfg(SandboxMode::Seatbelt), &ws, &f.tmp, &f.home, None).unwrap();
        let (ok, text) = run(&sb, &ws, "echo source > source.txt");
        assert!(ok, "{text}");
        assert!(!run(&sb, &ws, "mkdir -p nested/.git").0);
    }

    #[test]
    fn linked_worktree_gitdir_and_commondir_config_hooks_and_pointers_are_protected() {
        let f = fx();
        let worktree = f.ws.join("metadata/worktrees/one");
        let common = f.ws.join("metadata");
        std::fs::create_dir_all(worktree.join("hooks")).unwrap();
        std::fs::create_dir_all(common.join("hooks")).unwrap();
        std::fs::write(f.ws.join(".git"), "gitdir: metadata/worktrees/one\n").unwrap();
        std::fs::write(worktree.join("commondir"), "../..\n").unwrap();
        std::fs::write(worktree.join("HEAD"), "ref: refs/heads/one\n").unwrap();
        std::fs::create_dir_all(common.join("objects")).unwrap();
        std::fs::write(common.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(common.join("config"), "original").unwrap();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        for root in [&worktree, &common] {
            for name in ["config", "config.worktree", "hooks/pre-commit", "commondir", "gitdir"] {
                assert!(sb.check_write(&root.join(name)).is_err(), "{root:?}/{name}");
            }
        }
        if available() {
            assert!(!run(&sb, &f.ws, "echo changed > metadata/config").0);
            assert!(!run(&sb, &f.ws, "echo changed > metadata/worktrees/one/commondir").0);
            assert!(!run(&sb, &f.ws, "echo changed > .git").0);
        }
    }

    #[test]
    fn readonly_role_can_write_own_temp_but_not_workspace_or_sibling_temp() {
        let f = fx();
        let cfg = SandboxCfg { protected_paths: vec![f.ws.display().to_string()], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &cfg, None);
        assert!(sb.check_write(&f.ws.join("source.rs")).is_err());
        assert!(sb.check_write(&f.root.join("sibling.tmp")).is_err());
        assert!(sb.check_write(&f.tmp.join("scratch")).is_ok());
        if available() {
            assert!(!run(&sb, &f.ws, "echo changed > source.rs").0);
            assert!(!run(&sb, &f.ws, &format!("echo changed > {}/sibling.tmp", f.root.display())).0);
            assert!(run(&sb, &f.ws, "echo scratch > \"$TMPDIR/own\"").0);
        }
    }

    // ---- tests that run commands under the generated profile ----

    fn available() -> bool {
        Path::new(SANDBOX_EXEC).exists()
    }

    /// (succeeded, stdout + stderr)
    fn run(sb: &Sandbox, cwd: &Path, script: &str) -> (bool, String) {
        let (prog, args) = sb.command(script);
        let out = Command::new(prog).args(args).current_dir(cwd).env("TMPDIR", &sb.tmp_dir).output().expect("run");
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        (out.status.success(), text)
    }

    /// A directory that is not under any writable root (the home directory of the user running the tests).
    fn outside() -> Option<tempfile::TempDir> {
        let home = std::env::var_os("HOME")?;
        tempfile::Builder::new().prefix("loom-sbx-").tempdir_in(home).ok()
    }

    #[test]
    fn commands_write_only_where_allowed() {
        if !available() {
            return;
        }
        let Some(out) = outside() else { return };
        let out_dir = out.path().canonicalize().expect("canonical");
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (ws, tmp, od) = (s(&f.ws), s(&f.tmp), s(&out_dir));

        assert!(run(&sb, &f.ws, &format!("echo x > {ws}/ok.txt")).0);
        assert_eq!(std::fs::read_to_string(f.ws.join("ok.txt")).expect("read"), "x\n");
        assert!(run(&sb, &f.ws, &format!("echo x > {tmp}/ok.txt")).0);
        assert!(run(&sb, &f.ws, "mktemp \"${TMPDIR:-/private/tmp}/loom.XXXXXX\" >/dev/null && echo x > rel.txt").0);

        // Outside every root.
        let (ok, text) = run(&sb, &f.ws, &format!("echo x > {od}/no.txt"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(!out_dir.join("no.txt").exists());

        // The protected directory: no writes, no rename.
        let (ok, text) = run(&sb, &f.ws, &format!("echo x > {ws}/.loom/events"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(!f.ws.join(".loom/events").exists());
        let (ok, text) = run(&sb, &f.ws, &format!("mv {ws}/.loom {ws}/moved"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(f.ws.join(".loom").is_dir() && !f.ws.join("moved").exists());
        assert!(!run(&sb, &f.ws, &format!("echo x > {}/h.txt", s(&f.home))).0);

        // Through a symlink that points outside.
        symlink(&out_dir, f.ws.join("esc")).expect("symlink");
        let (ok, text) = run(&sb, &f.ws, &format!("echo x > {ws}/esc/via.txt"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(!out_dir.join("via.txt").exists());
    }

    #[test]
    fn commands_write_to_a_temp_dir_inside_the_loom_home() {
        if !available() {
            return;
        }
        let f = fx_prod();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let env = sb.env(&BTreeMap::new());
        assert_eq!(env["TMPDIR"], s(&f.tmp));
        let (ok, text) = run(&sb, &f.ws, &format!("echo x > {}/t.txt && mktemp {}/m.XXXXXX", s(&f.tmp), s(&f.tmp)));
        assert!(ok, "{text}");
        assert!(f.tmp.join("t.txt").exists());
        // It tests as writable (`access(2)`), so the tools that check it so before they use it do use it,
        // and `mkdir -p` of it succeeds although making it anew is refused.
        let tmp = s(&f.tmp);
        let script = format!(
            "export TMPDIR={tmp}; mkdir -p \"$TMPDIR\" && test -w \"$TMPDIR\" || {{ echo 'TMPDIR is not writable'; exit 3; }}\n\
             f=$(mktemp \"$TMPDIR/h.XXXXXX\") && cat > \"$f\" <<EOF\nheredoc\nEOF\ncat \"$f\""
        );
        let (ok, text) = run(&sb, &f.ws, &script);
        assert!(ok && text == "heredoc\n", "{text}");
        // Nothing else in the loom home became writable.
        let log = f.home.join("sessions/s1/log.jsonl");
        let (ok, text) = run(&sb, &f.ws, &format!("echo x >> {}", s(&log)));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert_eq!(std::fs::read_to_string(&log).expect("read"), "{}");
        assert!(!run(&sb, &f.ws, &format!("echo x > {}/sessions/s1/new", s(&f.home))).0);
    }

    #[test]
    fn commands_cannot_replace_the_temp_dir_itself() {
        if !available() {
            return;
        }
        let f = fx_prod();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (tmp, ws) = (s(&f.tmp), s(&f.ws));
        // A link in its place would be followed when the session is next activated.
        let (ok, text) = run(&sb, &f.ws, &format!("rmdir {tmp}"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        let (ok, text) = run(&sb, &f.ws, &format!("mv {tmp} {ws}/moved"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        // Nor can another entry be renamed onto it, or a link swapped into its place in one step
        // (`renameatx_np` with RENAME_SWAP, syscall 488). The temp dir is still empty here, so a
        // rename onto it fails for the profile alone. Outside the sandbox both work.
        if Path::new("/usr/bin/perl").exists() {
            let rename = "/usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or die \"rename: $!\\n\"'";
            let swap = "/usr/bin/perl -e 'syscall(488, -2, $ARGV[0], -2, $ARGV[1], 2) == 0 or die \"swap: $!\\n\"'";
            std::fs::create_dir(f.ws.join("empty")).expect("mkdir");
            symlink(&f.ws, f.ws.join("link")).expect("symlink");
            let (ok, text) = run(&sb, &f.ws, &format!("{rename} {ws}/empty {tmp}"));
            assert!(!ok && text.contains("Operation not permitted"), "{text}");
            let (ok, text) = run(&sb, &f.ws, &format!("{swap} {ws}/link {tmp}"));
            assert!(!ok && text.contains("Operation not permitted"), "{text}");
            assert!(f.ws.join("empty").is_dir() && f.ws.join("link").is_symlink());
            let none = build(&f, &cfg(SandboxMode::None), None);
            std::fs::create_dir_all(f.ws.join("c1/c2")).expect("mkdir");
            let (ok, text) = run(&none, &f.ws, &format!("{rename} {ws}/empty {ws}/c1/c2 && {swap} {ws}/link {ws}/c1"));
            assert!(ok && f.ws.join("c1").is_symlink() && !f.ws.join("empty").exists(), "{text}");
        } else {
            skipped("commands_cannot_replace_the_temp_dir_itself", "no /usr/bin/perl to rename and swap with");
        }
        let (_, text) = run(&sb, &f.ws, &format!("rm -rf {tmp}; ln -s {ws} {tmp}"));
        assert!(text.contains("Operation not permitted"), "{text}");
        assert!(std::fs::symlink_metadata(&f.tmp).expect("temp dir").file_type().is_dir(), "the temp dir was replaced");
        assert!(!f.ws.join("moved").exists());
        // What is in it can still be created, renamed and removed.
        let inside = format!(
            "d=$(mktemp -d {tmp}/d.XXXXXX) && echo x > $d/f && mkdir -p {tmp}/a/b && mv $d {tmp}/a/b/d && rm -r {tmp}/a"
        );
        let (ok, text) = run(&sb, &f.ws, &inside);
        assert!(ok, "{text}");
        // Gone, it cannot be made anew from inside: not as a link, and not by moving something into place.
        std::fs::remove_dir_all(&f.tmp).expect("rm");
        std::fs::create_dir(f.ws.join("d")).expect("mkdir");
        for script in [format!("ln -s {ws} {tmp}"), format!("mv {ws}/d {tmp}"), format!("mkdir {tmp}")] {
            let (ok, text) = run(&sb, &f.ws, &script);
            assert!(!ok && text.contains("Operation not permitted"), "{script}: {text}");
            assert!(std::fs::symlink_metadata(&f.tmp).is_err(), "{script} made the temp dir");
        }
    }

    #[test]
    fn commands_cannot_read_credentials_unless_protection_is_off() {
        if !available() {
            return;
        }
        let f = fx();
        let fake = f.root.join("fakehome4");
        std::fs::create_dir_all(fake.join(".ssh")).expect("mkdir");
        std::fs::write(fake.join(".ssh/id"), "private-key").expect("write");
        let sb = build_home(&f, &cfg(SandboxMode::Seatbelt), &fake);
        let id = format!("{}/.ssh/id", s(&fake));
        let (ok, text) = run(&sb, &f.ws, &format!("cat {id}"));
        assert!(!ok && text.contains("Operation not permitted") && !text.contains("private-key"), "{text}");
        assert!(!run(&sb, &f.ws, &format!("ls {}/.ssh", s(&fake))).0);
        let off = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        let (ok, text) = run(&build_home(&f, &off, &fake), &f.ws, &format!("cat {id}"));
        assert!(ok && text == "private-key", "{text}");
    }

    /// Says on the test run's own stderr, which is not captured, that a test could compare nothing on this host.
    fn skipped(test: &str, why: &str) {
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "sandbox test `{test}` skipped: {why}");
    }

    /// Whether this process is in a GUI login session. In any other (over ssh, say) LaunchServices opens
    /// nothing and launchd takes no jobs, sandbox or not, so a refusal there says nothing about the profile.
    fn gui_session() -> bool {
        let name = Command::new("/bin/launchctl").arg("managername").output();
        name.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "Aqua")
    }

    #[test]
    fn launch_services_open_is_refused_under_the_profile() {
        if !available() || !Path::new("/usr/bin/open").exists() {
            return;
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        // The profile compiles with the launch rules and bash runs under it.
        assert!(run(&sb, &f.ws, "true").0);
        if !gui_session() {
            let why = "not a GUI session, where `open` fails with or without the sandbox; \
                       the profile text is the evidence";
            return skipped("launch_services_open_is_refused_under_the_profile", why);
        }
        // Terminal runs an executable `.command` file that LaunchServices opens. There is no control run
        // outside the sandbox: it would really open Terminal.
        let script = f.ws.join("opened.command");
        std::fs::write(&script, format!("#!/bin/sh\ntouch {}/ran\n", s(&f.ws))).expect("write");
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).expect("chmod");
        let (ok, text) = run(&sb, &f.ws, &format!("/usr/bin/open -g {}", s(&script)));
        assert!(!ok, "{text}");
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert!(!f.ws.join("ran").exists(), "the script ran outside the sandbox");
    }

    #[test]
    fn launchd_jobs_are_refused_under_the_profile() {
        if !available() || !Path::new("/bin/launchctl").exists() {
            return;
        }
        if !gui_session() {
            let why = "not a GUI session, where launchd refuses a submitted job with or without the sandbox; \
                       the profile text is the evidence";
            return skipped("launchd_jobs_are_refused_under_the_profile", why);
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        // A job that launchd accepted would run outside the sandbox. There is no control run (it would
        // register a real job on this host), and the label is removed whatever happened.
        let label = format!("loom.sandbox-test.{}", std::process::id());
        let escaped = f.ws.join("escaped");
        let submit = format!("/bin/launchctl submit -l {label} -- /usr/bin/touch {}", s(&escaped));
        let (ok, text) = run(&sb, &f.ws, &submit);
        std::thread::sleep(std::time::Duration::from_millis(500));
        let ran = escaped.exists();
        let _ = Command::new("/bin/launchctl").args(["remove", &label]).output();
        assert!(!ok, "launchd accepted a job from inside the sandbox: {text}");
        assert!(!ran, "the job ran outside the sandbox");
    }

    #[test]
    fn commands_cannot_read_denied_paths() {
        if !available() {
            return;
        }
        let f = fx();
        let hidden = f.root.join("hidden");
        std::fs::create_dir_all(&hidden).expect("mkdir");
        std::fs::write(hidden.join("f"), "secret").expect("write");
        let c = SandboxCfg { unreadable_paths: vec![s(&hidden).to_string()], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, None);
        let h = s(&f.home);
        let (ok, text) = run(&sb, &f.ws, &format!("cat {h}/token"));
        assert!(!ok && text.contains("Operation not permitted") && !text.contains("t0ken"), "{text}");
        assert!(!run(&sb, &f.ws, &format!("ls {h}/keys")).0);
        assert!(!run(&sb, &f.ws, &format!("cat {}/f", s(&hidden))).0);
        assert!(!run(&sb, &f.ws, &format!("ls {}", s(&hidden))).0);
        let (ok, text) = run(&sb, &f.ws, &format!("cat {h}/other"));
        assert!(!ok && text.contains("Operation not permitted") && !text.contains("visible"), "{text}");
    }

    /// `path` written through the data volume (`/System/Volumes/Data/...`), when macOS has it that way.
    #[cfg(target_os = "macos")]
    fn data_volume(path: &Path) -> Option<PathBuf> {
        let aliased = Path::new("/System/Volumes/Data").join(path.strip_prefix("/").ok()?);
        aliased.exists().then_some(aliased)
    }

    /// The production layout with another session, a stored output, a mission journal, logs, configuration and a pack.
    fn fx_home_files() -> Fx {
        let f = fx_prod();
        for (rel, body) in [
            ("sessions/s2/log.jsonl", "OTHER-LOG"),
            ("sessions/s2/tmp/note", "other temp"),
            ("blobs/aa/x", "STORED-OUTPUT"),
            ("missions/m1/journal.jsonl", "JOURNAL"),
            ("logs/daemon.log", "DAEMON-LOG"),
            ("config.toml", "CONFIG"),
            ("packs/p1/pack.toml", "PACK"),
        ] {
            let p = f.home.join(rel);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(p, body).expect("write");
        }
        f
    }

    #[test]
    fn check_read_refuses_the_whole_loom_home_but_the_session_temp_dir_in_every_mode() {
        let f = fx_home_files();
        std::fs::write(f.tmp.join("mine"), "fine").expect("write");
        symlink(f.home.join("sessions/s1/log.jsonl"), f.ws.join("log-link")).expect("symlink");
        symlink(f.home.join("sessions"), f.ws.join("sessions-link")).expect("symlink");
        let mut modes = vec![SandboxMode::Seatbelt, SandboxMode::None];
        // Built with `expect` (in `build`): where bubblewrap can exist, a failure to build it is a failure here.
        if cfg!(target_os = "linux") && Path::new(BWRAP).exists() {
            modes.push(SandboxMode::Bubblewrap);
        }
        for mode in modes {
            let sb = build(&f, &cfg(mode), None);
            for rel in [
                "sessions/s1/log.jsonl",
                "sessions/s2/log.jsonl",
                "sessions/s2/tmp/note",
                "blobs/aa/x",
                "missions/m1/journal.jsonl",
                "logs/daemon.log",
                "logs",
                "config.toml",
                "packs/p1/pack.toml",
                "sessions",
                "sessions/s1",
                "other",
                "",
            ] {
                let path = f.home.join(rel);
                let e = sb.check_read(&path).expect_err(rel);
                assert!(e.contains("not readable") && e.contains(&format!("loom home {}", s(&f.home))), "{rel}: {e}");
                assert!(!e.contains("OTHER-LOG") && !e.contains("STORED-OUTPUT"), "{e}");
            }
            // A link in the workspace that resolves into the loom home grants nothing.
            assert!(sb.check_read(&f.ws.join("log-link")).is_err());
            assert!(sb.check_read(&f.ws.join("sessions-link/s2/log.jsonl")).is_err());
            // macOS also names the data volume's folders under `/System/Volumes/Data`: the same files, the same refusal.
            #[cfg(target_os = "macos")]
            if let Some(data) = data_volume(&f.home) {
                for rel in
                    ["sessions/s2/log.jsonl", "blobs/aa/x", "config.toml", "logs", "sessions", "", "token", "keys/k"]
                {
                    let e = sb.check_read(&data.join(rel)).expect_err(rel);
                    assert!(e.contains("not readable") && e.contains(s(&f.home)), "{rel}: {e}");
                }
                let alias_tmp = Path::new("/System/Volumes/Data").join(f.tmp.strip_prefix("/").expect("absolute"));
                assert!(sb.check_read(&alias_tmp.join("mine")).is_ok());
            }
            // The session temp dir and the workspace are readable.
            assert!(sb.check_read(&f.tmp.join("mine")).is_ok());
            assert!(sb.check_read(&f.tmp.join("not/yet/there")).is_ok());
            assert!(sb.check_read(&f.tmp).is_ok());
            assert!(sb.check_read(&f.ws.join("anything")).is_ok());
        }
    }

    #[test]
    fn a_workspace_that_is_or_lies_inside_the_loom_home_is_refused() {
        let f = fx_prod();
        let inside = f.home.join("sessions/s1/ws");
        std::fs::create_dir_all(&inside).expect("mkdir");
        symlink(&inside, f.root.join("ws-link")).expect("symlink");
        #[allow(unused_mut)]
        let mut workspaces = vec![f.home.clone(), f.home.join("sessions"), inside.clone(), f.root.join("ws-link")];
        // The same directories written through the data volume.
        #[cfg(target_os = "macos")]
        workspaces.extend([&f.home, &inside].into_iter().filter_map(|p| data_volume(p)));
        for ws in workspaces {
            for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
                let e = Sandbox::new(&cfg(mode), &ws, &f.tmp, &f.home, None).expect_err("workspace in the loom home");
                let e = e.to_string();
                assert!(
                    e.contains("workspace") && e.contains(s(&f.home)) && e.contains("outside the loom home"),
                    "{e}"
                );
            }
        }
        // A workspace that holds the loom home is not inside it.
        assert!(Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.root, &f.tmp, &f.home, None).is_ok());
    }

    #[test]
    fn the_profile_hides_the_loom_home_but_the_session_temp_dir_and_its_ancestors_can_be_looked_up() {
        let f = fx_prod();
        let c = SandboxCfg { unreadable_paths: vec![format!("{}/secret", s(&f.tmp))], ..cfg(SandboxMode::Seatbelt) };
        let jobs = f.home.join("sessions/s1/jobs");
        let p = build(&f, &c, None).with_jobs_dir(&jobs).expect("jobs dir").profile().expect("profile");
        let (h, t, a) = (s(&f.home), s(&f.tmp), format!("{}/sessions/s1/analysis", s(&f.home)));
        // Names are hidden as well as content: `file-read*` alone leaves `fsgetpath` and `searchfs` their way.
        let deny = p.find(&format!("(deny file-read* file-test-existence (subpath \"{h}\"))\n")).expect("home deny");
        let meta_line =
            format!("(allow file-read-metadata file-test-existence (literal \"{h}\") (literal \"{h}/sessions\") (literal \"{h}/sessions/s1\"))\n");
        let meta = p.find(&meta_line).expect("lookup of the ancestors, not listing and not the temp dir");
        let allow = p
            .find(&format!("(allow file-read* file-test-existence (subpath \"{t}\") (subpath \"{a}\"))\n"))
            .expect("temp dir and analysis staging read");
        let again = p
            .rfind(&format!("(subpath \"{t}/secret\")"))
            .filter(|&at| {
                p[..at].rsplit('\n').next().is_some_and(|l| l.starts_with("(deny file-read* file-test-existence"))
            })
            .expect("unreadable inside the temp dir");
        let jobs_allow =
            p.find(&format!("(allow file-read-metadata (subpath \"{h}/sessions/s1/jobs\"))\n")).expect("jobs metadata");
        assert!(deny < meta && meta < allow && allow < again && again < jobs_allow, "later rules win: {p}");
        // The credential and configured denials precede the home rule; they are all above the allow.
        let first =
            p.find(&format!("(deny file-read* file-test-existence (subpath \"{h}/token\")")).expect("token deny");
        assert!(first < deny, "{p}");
        // The jobs directory gets the metadata of what is in it and nothing else: no read, not even its existence.
        assert_eq!(p.matches(&format!("{h}/sessions/s1/jobs")).count(), 1, "{p}");
        // The temp dir itself is given a full read grant, never a metadata-only one.
        assert!(
            p.lines()
                .filter(|l| l.starts_with("(allow file-read-metadata"))
                .all(|l| !l.contains(&format!("(literal \"{t}\")"))),
            "{p}"
        );
        // Searching the volume by name is denied for everything.
        assert!(p.contains("(deny file-search)\n"), "{p}");
        // Without a jobs directory there is no such line.
        let plain = build(&f, &c, None).profile().expect("profile");
        assert!(!plain.contains("jobs"), "{plain}");
    }

    #[test]
    fn a_replay_reads_its_staged_workspace_and_temp_and_not_the_callers_temp_dir() {
        let f = fx_home_files();
        let jobs = f.home.join("sessions/s1/jobs");
        let caller = build(&f, &cfg(SandboxMode::Seatbelt), None).with_jobs_dir(&jobs).expect("jobs dir");
        let private = caller.oracle_staging_root().join("run-1");
        let (ws, tmp) = (private.join("workspace"), private.join("tmp"));
        for d in [&ws, &tmp] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::write(ws.join("source"), "original").expect("write");
        std::fs::write(tmp.join("result"), "mine").expect("write");
        std::fs::write(f.tmp.join("caller-file"), "caller").expect("write");
        {
            let replay = caller.isolated_replay(&ws, &tmp).expect("replay");
            assert!(replay.check_read(&ws.join("source")).is_ok());
            assert!(replay.check_read(&tmp.join("result")).is_ok());
            assert!(replay.check_read(&f.tmp.join("caller-file")).is_err());
            assert!(replay.check_read(&f.home.join("sessions/s2/log.jsonl")).is_err());
            assert!(replay.check_read(&f.home.join("blobs/aa/x")).is_err());
            assert!(replay.check_read(&private.join("..").join("other-run")).is_err());
            assert!(replay.describe().contains("replay"), "{}", replay.describe());
            // The refusal names what is readable: the staged workspace and temp, not the caller's temp dir.
            let e = replay.check_read(&f.home.join("blobs/aa/x")).expect_err("loom home");
            assert!(e.contains("this replay's staged workspace") && e.contains(s(&ws)) && e.contains(s(&tmp)), "{e}");
            assert!(!e.contains(s(&f.tmp)) && !e.contains("STORED-OUTPUT"), "{e}");
            let p = replay.profile().expect("profile");
            let (h, o) = (s(&f.home), s(caller.oracle_staging_root()));
            assert!(
                p.contains(&format!(
                    "(allow file-read-metadata file-test-existence (literal \"{h}\") (literal \"{o}\") (literal \"{}\"))\n",
                    s(&private)
                )),
                "{p}"
            );
            assert!(
                p.contains(&format!(
                    "(allow file-read* file-test-existence (subpath \"{}\") (subpath \"{}\"))\n",
                    s(&ws),
                    s(&tmp)
                )),
                "{p}"
            );
            assert!(p.lines().filter(|l| l.starts_with("(allow file-read*")).all(|l| !l.contains(s(&f.tmp))), "{p}");
            // The caller's job files keep their metadata exception, after the denial of the sessions directory.
            let sessions = p.rfind(&format!("(subpath \"{h}/sessions\")")).expect("sessions denied");
            let jobs_allow = p.find(&format!("(allow file-read-metadata (subpath \"{}\"))\n", s(&jobs))).expect("jobs");
            assert!(sessions < jobs_allow, "{p}");
        }
        if available() {
            let replay = caller.isolated_replay(&ws, &tmp).expect("replay");
            let (ok, text) = run(&replay, &ws, "cat source; cat \"$TMPDIR/result\"");
            assert!(ok && text == "originalmine", "{text}");
            assert!(!run(&replay, &ws, &format!("cat {}/caller-file", s(&f.tmp))).0);
            assert!(!run(&replay, &ws, &format!("cat {}/blobs/aa/x", s(&f.home))).0);
        }
    }

    #[test]
    fn describe_says_loom_own_files_are_not_readable() {
        let f = fx_prod();
        for mode in [SandboxMode::Seatbelt, SandboxMode::None, SandboxMode::Bubblewrap] {
            // Bubblewrap cannot be built on every host; its text needs only the fields describe reads.
            let sb = match Sandbox::new(&cfg(mode), &f.ws, &f.tmp, &f.home, None) {
                Ok(sb) => sb,
                Err(_) if mode == SandboxMode::Bubblewrap => continue,
                Err(e) => panic!("{e}"),
            };
            let d = sb.describe();
            let analysis = format!("{}/sessions/s1/analysis", s(&f.home));
            if mode == SandboxMode::None {
                // Commands are not confined in this mode: the rule is the file tools' own, and is worded as theirs.
                assert!(
                    d.contains("File tools also refuse to read loom's own files under")
                        && d.contains(s(&f.tmp))
                        && !d.contains("Loom's own files")
                        && !d.contains("not readable"),
                    "{d}"
                );
            } else {
                assert!(d.contains("Loom's own files") && d.contains("not readable") && d.contains(s(&f.tmp)), "{d}");
            }
            assert!(d.contains(&format!("the analysis staging dir {analysis}")), "{d}");
        }
        // A replay (never in mode none) names its staged workspace and temp instead.
        let caller = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let private = caller.oracle_staging_root().join("run-d");
        let (ws, tmp) = (private.join("workspace"), private.join("tmp"));
        for d in [&ws, &tmp] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        let d = caller.isolated_replay(&ws, &tmp).expect("replay").describe();
        assert!(
            d.contains("except this replay's staged workspace and temp dir") && !d.contains("analysis staging"),
            "{d}"
        );
    }

    #[test]
    fn commands_cannot_read_the_loom_home_but_work_in_the_session_temp_dir() {
        if !available() {
            return;
        }
        let f = fx_home_files();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let h = s(&f.home);
        for rel in
            ["sessions/s1/log.jsonl", "sessions/s2/log.jsonl", "blobs/aa/x", "config.toml", "missions/m1/journal.jsonl"]
        {
            let (ok, text) = run(&sb, &f.ws, &format!("cat {h}/{rel}"));
            assert!(
                !ok && text.contains("Operation not permitted") && !text.contains("LOG") && !text.contains("STORED"),
                "{rel}: {text}"
            );
        }
        for dir in ["sessions", "blobs", "", "sessions/s2"] {
            assert!(!run(&sb, &f.ws, &format!("ls '{h}/{dir}'")).0, "{dir} is listable");
        }
        // The home entry and the directories down to the temp dir can be looked up, not listed.
        for dir in ["", "/sessions", "/sessions/s1"] {
            let (ok, text) = run(&sb, &f.ws, &format!("stat -f %N '{h}{dir}'"));
            assert!(ok && text.trim() == format!("{h}{dir}"), "{dir}: {text}");
        }
        // The temp dir works: write and read back, mkdir -p, cd and pwd -P, a tool that makes a temp file.
        let (ok, text) = run(&sb, &f.ws, "echo hi > \"$TMPDIR/f\" && cat \"$TMPDIR/f\"");
        assert!(ok && text == "hi\n", "{text}");
        let (ok, text) = run(&sb, &f.ws, "mkdir -p \"$TMPDIR/a/b/c\" && cd \"$TMPDIR/a/b/c\" && pwd -P");
        assert!(ok && text.trim() == format!("{}/a/b/c", s(&f.tmp)), "{text}");
        let (ok, text) = run(&sb, &f.ws, "cd \"$TMPDIR\" && pwd -P && ls");
        assert!(ok && text.starts_with(s(&f.tmp)) && text.contains('f'), "{text}");
        if Path::new("/usr/bin/python3").exists() {
            let script = "python3 -c 'import tempfile; f = tempfile.NamedTemporaryFile(); f.write(b\"x\"); f.flush(); print(f.name)'";
            let (ok, text) = run(&sb, &f.ws, script);
            assert!(ok && text.trim().starts_with(s(&f.tmp)), "{text}");
        }
    }

    fn node() -> Option<&'static str> {
        ["/opt/homebrew/bin/node", "/usr/local/bin/node"].into_iter().find(|n| Path::new(n).exists())
    }

    #[test]
    fn the_profile_lets_the_names_next_to_the_lookup_directories_be_tested_not_read() {
        let f = fx_home_files();
        let (h, t) = (s(&f.home).to_string(), s(&f.tmp).to_string());
        let rx = |d: &str| format!(" (regex #\"^{}/[^/]+$\")", d.replace('.', "\\."));
        let p = build(&f, &cfg(SandboxMode::Seatbelt), None).profile().expect("profile");
        let both = |d: &str| format!("{} (regex #\"^{}/node_modules/\")", rx(d), d.replace('.', "\\."));
        let line = format!(
            "(allow file-test-existence{}{}{})\n",
            both(&h),
            both(&format!("{h}/sessions")),
            both(&format!("{h}/sessions/s1"))
        );
        let at = p.find(&line).expect("children of the lookup directories can be tested for existence");
        let deny = p.find(&format!("(deny file-read* file-test-existence (subpath \"{h}\"))\n")).expect("home deny");
        let open = p.find(&format!("(allow file-read* file-test-existence (subpath \"{t}\")")).expect("open");
        assert!(deny < at && at < open, "{p}");
        // Never read or metadata: only the existence test.
        assert!(!p.lines().any(|l| l.contains("(regex #\"^") && l.contains("file-read")), "{p}");
        // The token stays denied after that rule.
        assert!(
            p.rfind(&format!("(deny file-read* file-test-existence (subpath \"{h}/token\")")).expect("token") > at,
            "{p}"
        );
    }

    /// A missing name next to the temp dir's ancestors is "no such file", not EPERM: what exists is still refused.
    #[test]
    fn missing_names_above_the_temp_dir_are_not_found_and_existing_ones_are_refused() {
        if !available() || !Path::new("/usr/bin/python3").exists() {
            return;
        }
        let f = fx_home_files();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let probe = "import errno, os, sys\n\
                     for rel in sys.argv[1:]:\n\
                     \x20   try:\n\
                     \x20       open(os.path.join(os.environ['TMPDIR'], rel)).close()\n\
                     \x20       print(rel, 'OK')\n\
                     \x20   except OSError as e:\n\
                     \x20       print(rel, errno.errorcode[e.errno])\n";
        let py = f.root.join("probe.py");
        std::fs::write(&py, probe).expect("write");
        let (ok, text) = run(
            &sb,
            &f.ws,
            &format!(
                "python3 -I '{}' ../package.json ../../package.json ../../../package.json ../log.jsonl ../../s2 ../../../token ../../../blobs/aa/x ../../../blobs/zz/x",
                s(&py)
            ),
        );
        assert!(ok, "{text}");
        for (rel, want) in [
            ("../package.json", "ENOENT"),
            ("../../package.json", "ENOENT"),
            ("../../../package.json", "ENOENT"),
            ("../log.jsonl", "EPERM"),
            ("../../s2", "EPERM"),
            ("../../../token", "EPERM"),
            ("../../../blobs/aa/x", "EPERM"),
            // Deeper than the children of a lookup directory: still refused, found or not.
            ("../../../blobs/zz/x", "EPERM"),
        ] {
            assert!(text.contains(&format!("{rel} {want}\n")), "{rel} should be {want}: {text}");
        }
        let (ok, text) = run(&sb, &f.ws, "ls \"$TMPDIR/../nope\"");
        assert!(!ok && text.contains("No such file") && !text.contains("not permitted"), "{text}");
        // Python before 3.14 raises on EPERM when it walks up looking for a project root.
        let walk = "python3 -c \"from pathlib import Path; c=Path.cwd(); print([str(d) for d in [c,*c.parents] if (d/'pyproject.toml').is_file() or (d/'.git').exists()])\"";
        let (ok, text) = run(&sb, &f.tmp, walk);
        assert!(ok && text.trim() == "[]", "{text}");
    }

    /// Node treats anything but ENOENT as fatal when it looks for a `package.json` above a script, and libuv ends
    /// its `PATH` search at the first error that is not ENOENT: the production and the replay layout must run both.
    #[test]
    fn node_runs_scripts_and_spawns_commands_from_the_temp_dir_and_in_a_replay() {
        let Some(node) = node().filter(|_| available()) else { return };
        let f = fx_home_files();
        let caller = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let spawn = "require('child_process').execFileSync('sh',['-c','echo spawn-ok'],{stdio:'inherit'})";
        let tmp_script = format!(
            "cd \"$TMPDIR\" && printf \"console.log('js ok')\\n\" > a.js && {node} a.js && {node} \"$TMPDIR/a.js\" && \
             {node} -e \"require(process.env.TMPDIR+'/a.js')\" && mkdir -p sub && cp a.js sub/ && {node} sub/a.js && \
             PATH=\"$TMPDIR/../node_modules/.bin:$TMPDIR/../../node_modules/.bin:$TMPDIR/../../../node_modules/.bin:$PATH\" {node} -e \"{spawn}\""
        );
        let (ok, text) = run(&caller, &f.ws, &tmp_script);
        assert!(ok && text.matches("js ok").count() == 4 && text.contains("spawn-ok"), "{text}");
        // A script in the workspace and one in the temp dir run from the workspace too.
        std::fs::write(f.tmp.join("b.js"), "console.log('b ok')").expect("write");
        let (ok, text) = run(&caller, &f.ws, &format!("{node} \"$TMPDIR/b.js\""));
        assert!(ok && text.trim() == "b ok", "{text}");

        // The replay layout: staged under the home's oracle-runs, with no pinned package.json.
        let private = caller.oracle_staging_root().join("run-node");
        let (ws, tmp) = (private.join("workspace"), private.join("tmp"));
        for d in [&ws, &tmp] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::write(ws.join("check.js"), "console.log('check ok')").expect("write");
        std::fs::write(ws.join("package.json"), "{\"scripts\":{\"test\":\"node check.js\"}}").expect("write");
        std::fs::create_dir_all(ws.join("bare")).expect("mkdir");
        std::fs::write(ws.join("bare/check.js"), "console.log('bare ok')").expect("write");
        let replay = caller.isolated_replay(&ws, &tmp).expect("replay");
        let (ok, text) = run(&replay, &ws, &format!("{node} check.js && cd bare && {node} check.js"));
        assert!(ok && text.contains("check ok") && text.contains("bare ok"), "{text}");
        let npm = node.replace("/node", "/npm");
        let npm_env = format!("PATH={}:$PATH", Path::new(node).parent().expect("dir").display());
        if Path::new(&npm).exists() {
            let (ok, text) = run(&replay, &ws, &format!("{npm_env} {npm} test"));
            assert!(ok && text.contains("check ok"), "{text}");
            // An npm script in a package in the production temp dir runs (npm spawns `sh` by name).
            let (ok, text) = run(
                &caller,
                &f.ws,
                &format!(
                    "mkdir -p \"$TMPDIR/np\" && cd \"$TMPDIR/np\" && printf '{{\"name\":\"np\",\"scripts\":{{\"test\":\"echo test-ran\"}}}}' > package.json && {npm_env} {npm} test"
                ),
            );
            assert!(ok && text.contains("test-ran"), "{text}");
        }
    }

    /// `~/.fly` and `~/.pulumi` are protected as their credential files: with their `bin` directories on `PATH`
    /// (the installers do that) libuv would end its search at the first EPERM and Node could spawn nothing by name.
    #[test]
    fn a_credential_tools_bin_directory_on_path_does_not_stop_node_spawning_commands() {
        let Some(node) = node().filter(|_| available()) else { return };
        let f = fx_home_files();
        let fake = f.root.join("fakehome-bin");
        for d in [".fly/bin", ".pulumi/bin"] {
            std::fs::create_dir_all(fake.join(d)).expect("mkdir");
        }
        std::fs::write(fake.join(".fly/config.yml"), "access_token: SECRET").expect("write");
        std::fs::write(fake.join(".pulumi/credentials.json"), "SECRET").expect("write");
        let sb = build_home(&f, &cfg(SandboxMode::Seatbelt), &fake);
        let spawn = "require('child_process').execFileSync('sh',['-c','echo spawn-ok'],{stdio:'inherit'})";
        let (fl, pu) = (s(&fake.join(".fly/bin")).to_string(), s(&fake.join(".pulumi/bin")).to_string());
        for cwd in [&f.ws, &f.tmp] {
            let (ok, text) = run(&sb, cwd, &format!("PATH={fl}:{pu}:/usr/bin:/bin {node} -e \"{spawn}\""));
            assert!(ok && text.contains("spawn-ok"), "{text}");
        }
        // The credential files are still refused, and so is a name that exists next to them.
        for rel in [".fly/config.yml", ".pulumi/credentials.json"] {
            let (ok, text) = run(&sb, &f.ws, &format!("cat '{}/{rel}'", s(&fake)));
            assert!(!ok && text.contains("Operation not permitted") && !text.contains("SECRET"), "{rel}: {text}");
        }
        assert!(sb.check_read(&fake.join(".fly/config.yml")).is_err());
        assert!(sb.check_read(&fake.join(".pulumi/credentials.json")).is_err());
    }

    /// The kernel can name a file by its id (`fsgetpath`), whatever the profile says of reading it, unless the
    /// existence of what is under the loom home is denied as well. Ids near the home's own are asked for.
    #[test]
    fn commands_cannot_list_the_loom_home_by_file_id() {
        if !available() || !Path::new("/usr/bin/python3").exists() {
            return;
        }
        let f = fx_home_files();
        let fake = f.root.join("fakehome-ids");
        std::fs::create_dir_all(fake.join(".ssh")).expect("mkdir");
        std::fs::write(fake.join(".ssh/id"), "CRED-SECRET").expect("write");
        std::fs::write(f.home.join("token"), "t0ken").expect("write");
        std::fs::write(f.tmp.join("note"), "mine").expect("write");
        let script = f.tmp.join("ids.py");
        std::fs::write(
            &script,
            "import ctypes, os, sys\n\
             libc = ctypes.CDLL(None)\n\
             buf = ctypes.create_string_buffer(2200)\n\
             out = ctypes.create_string_buffer(1024)\n\
             for root in sys.argv[1:]:\n\
             \x20   if libc.statfs(root.encode(), buf) != 0:\n\
             \x20       continue\n\
             \x20   fsid = (ctypes.c_int32 * 2).from_buffer_copy(buf.raw[48:56])\n\
             \x20   ino = os.stat(root).st_ino\n\
             \x20   for i in range(max(1, ino - 100), ino + 5000):\n\
             \x20       if libc.fsgetpath(out, 1024, ctypes.byref(fsid), ctypes.c_uint64(i)) > 0:\n\
             \x20           print('FOUND ' + out.value.decode(errors='replace'))\n",
        )
        .expect("write");
        let sb = build_home(&f, &cfg(SandboxMode::Seatbelt), &fake);
        let (h, t) = (s(&f.home).to_string(), s(&f.tmp).to_string());
        let (ok, text) = run(&sb, &f.ws, &format!("python3 -I '{}' '{h}' '{}'", s(&script), s(&fake)));
        assert!(ok, "{text}");
        let found: Vec<&str> = text.lines().filter_map(|l| l.strip_prefix("FOUND ")).collect();
        // The probe works: the home, the temp dir and what is in it are named.
        assert!(found.contains(&h.as_str()) && found.iter().any(|p| p.ends_with("/tmp/note")), "{text}");
        // The home, the directories to the temp dir, and their direct children (a missing name must be ENOENT, so
        // those can be tested for existence); `token` is denied again and nothing deeper is named.
        let allowed = [h.clone(), format!("{h}/sessions"), format!("{h}/sessions/s1")];
        let child_of_lookup = |p: &str| {
            [h.clone(), format!("{h}/sessions"), format!("{h}/sessions/s1")]
                .iter()
                .any(|d| p.strip_prefix(&format!("{d}/")).is_some_and(|r| !r.contains('/')))
                && p != format!("{h}/token")
        };
        // Other tests make files on the same volume at the same time: only what lies in this fixture is judged.
        let (root, creds) = (s(&f.root).to_string(), format!("{}/.ssh", s(&fake)));
        for path in found.iter().filter(|p| p.starts_with(&root)) {
            let own = path.starts_with(&format!("{t}/")) || *path == t;
            let under_home = *path == h || path.starts_with(&format!("{h}/"));
            assert!(
                !under_home || own || child_of_lookup(path) || allowed.iter().any(|a| a == path),
                "named by file id: {path}"
            );
            assert!(
                !(*path == creds || path.starts_with(&format!("{creds}/"))),
                "a credential store was named: {path}"
            );
        }
    }

    #[test]
    fn a_hard_link_from_the_temp_dir_does_not_make_what_is_not_readable_readable() {
        if !available() {
            return;
        }
        let f = fx_home_files();
        let fake = f.root.join("fakehome-links");
        std::fs::create_dir_all(fake.join(".ssh")).expect("mkdir");
        std::fs::write(fake.join(".ssh/id"), "CRED-SECRET").expect("write");
        std::fs::write(f.ws.join("plain"), "plain").expect("write");
        let sb = build_home(&f, &cfg(SandboxMode::Seatbelt), &fake);
        let h = s(&f.home);
        let sources = [
            (format!("{h}/sessions/s1/log.jsonl"), "{}"),
            (format!("{h}/sessions/s2/log.jsonl"), "OTHER-LOG"),
            (format!("{h}/blobs/aa/x"), "STORED-OUTPUT"),
            (format!("{h}/token"), "t0ken"),
            (format!("{}/.ssh/id", s(&fake)), "CRED-SECRET"),
        ];
        for (src, secret) in sources {
            for link in ["ln", "ln -s", "cp -c", "cp -l"] {
                let script = format!("{link} '{src}' \"$TMPDIR/l\" && cat \"$TMPDIR/l\"");
                let (ok, text) = run(&sb, &f.ws, &script);
                assert!(!(ok && text.contains(secret)), "`{link}` made {src} readable: {text}");
                let _ = std::fs::remove_file(f.tmp.join("l"));
            }
        }
        // The control: a link to a readable file reads.
        let (ok, text) = run(&sb, &f.ws, &format!("ln '{}/plain' \"$TMPDIR/l\" && cat \"$TMPDIR/l\"", s(&f.ws)));
        assert!(ok && text == "plain", "{text}");
    }

    #[test]
    fn commands_cannot_move_or_remove_a_denied_path_inside_the_workspace() {
        if !available() {
            return;
        }
        let f = fx();
        let ws = s(&f.ws);
        // A configured unreadable directory and credential stores, all inside the workspace, which is the
        // home directory here.
        for d in ["hidden", ".ssh", ".aws", ".config/gh"] {
            std::fs::create_dir_all(f.ws.join(d)).expect("mkdir");
        }
        std::fs::write(f.ws.join("hidden/f"), "secret").expect("write");
        std::fs::write(f.ws.join(".ssh/id"), "private-key").expect("write");
        std::fs::write(f.ws.join(".config/gh/hosts.yml"), "gh-token").expect("write");
        // `.kube` is a link to a credential store, `.cargo` a link above one.
        for (link, file) in [(".kube", "config"), (".cargo", "credentials")] {
            std::fs::create_dir_all(f.ws.join("Sync").join(link)).expect("mkdir");
            std::fs::write(f.ws.join("Sync").join(link).join(file), "linked-secret").expect("write");
            symlink(f.ws.join("Sync").join(link), f.ws.join(link)).expect("symlink");
        }
        let c = SandboxCfg { unreadable_paths: vec!["hidden".into()], ..cfg(SandboxMode::Seatbelt) };
        let sb = build_home(&f, &c, &f.ws);
        for (dir, file, content) in [("hidden", "f", "secret"), (".ssh", "id", "private-key")] {
            // Moved, it could be read under the new name.
            let (ok, text) = run(&sb, &f.ws, &format!("mv {ws}/{dir} {ws}/moved && cat {ws}/moved/{file}"));
            assert!(!ok && text.contains("Operation not permitted") && !text.contains(content), "{dir}: {text}");
            let (_, text) = run(&sb, &f.ws, &format!("rm -rf {ws}/{dir}; echo x > {ws}/{dir}/new"));
            assert!(text.contains("Operation not permitted"), "{dir}: {text}");
            assert_eq!(std::fs::read_to_string(f.ws.join(dir).join(file)).expect("still there"), content);
            assert!(!f.ws.join("moved").exists() && !f.ws.join(dir).join("new").exists());
            assert!(sb.check_write(&f.ws.join(dir).join("new")).is_err());
        }
        // An empty one cannot be removed and replaced either.
        let (ok, text) = run(&sb, &f.ws, &format!("rmdir {ws}/.aws && ln -s {ws} {ws}/.aws"));
        assert!(!ok && text.contains("Operation not permitted"), "{text}");
        assert!(f.ws.join(".aws").is_dir() && !f.ws.join(".aws").is_symlink());
        // Nor can a directory that holds one be moved: not `.config`, and not the workspace itself.
        let (ok, text) = run(&sb, &f.ws, &format!("mv {ws}/.config {ws}/c2 && cat {ws}/c2/gh/hosts.yml"));
        assert!(!ok && text.contains("Operation not permitted") && !text.contains("gh-token"), "{text}");
        let (ok, text) = run(&sb, &f.ws, &format!("mv {ws} {}/ws2", s(&f.root)));
        assert!(!ok && f.ws.join("hidden/f").exists(), "{text}");
        // A link to a credential store, or above one, cannot be removed or moved to make way for a
        // directory of the command's own.
        for script in
            [format!("rm {ws}/.kube && mkdir {ws}/.kube"), format!("mv {ws}/.cargo {ws}/c3 && mkdir {ws}/.cargo")]
        {
            let (ok, text) = run(&sb, &f.ws, &script);
            assert!(
                !ok && text.contains("Operation not permitted") && !text.contains("linked-secret"),
                "{script}: {text}"
            );
        }
        assert!(f.ws.join(".kube").is_symlink() && f.ws.join(".cargo").is_symlink() && !f.ws.join("c3").exists());
        // A missing directory above one (`.docker` holds `.docker/config.json`) cannot be made as a link that
        // would send the store elsewhere; as a directory it can, and the store in it stays denied.
        std::fs::create_dir(f.ws.join("elsewhere")).expect("mkdir");
        let (ok, text) = run(&sb, &f.ws, &format!("ln -s {ws}/elsewhere {ws}/.docker"));
        assert!(!ok && text.contains("Operation not permitted") && !f.ws.join(".docker").exists(), "{text}");
        let (ok, text) = run(&sb, &f.ws, &format!("mkdir {ws}/.docker && echo x > {ws}/.docker/config.json"));
        assert!(!ok && f.ws.join(".docker").is_dir() && !f.ws.join(".docker/config.json").exists(), "{text}");
        // What is not denied stays free to move.
        std::fs::create_dir_all(f.ws.join(".config/other")).expect("mkdir");
        let (ok, text) = run(&sb, &f.ws, &format!("mv {ws}/.config/other {ws}/other && rm -r {ws}/other"));
        assert!(ok, "{text}");
    }

    #[test]
    fn devices_and_pipes_work() {
        if !available() {
            return;
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (ok, text) = run(
            &sb,
            &f.ws,
            "echo hidden > /dev/null; echo abc | tr a-c A-C | cat; ls /nonexistent-dir 2>/dev/null; true",
        );
        assert!(ok && text == "ABC\n", "{text}");
    }

    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    }

    fn connects(sb: &Sandbox, cwd: &Path, host: &str, port: u16) -> bool {
        run(sb, cwd, &format!("/usr/bin/nc -z -w 2 {host} {port}")).0
    }

    #[test]
    fn network_is_limited_to_the_listed_loopback_ports() {
        if !available() {
            return;
        }
        let f = fx();
        let allowed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let other = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let (pa, po) = (allowed.local_addr().expect("addr").port(), other.local_addr().expect("addr").port());
        let c = SandboxCfg { loopback_ports: vec![pa], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, None);
        assert!(connects(&sb, &f.ws, "127.0.0.1", pa));
        assert!(!connects(&sb, &f.ws, "127.0.0.1", po));
        // Outside the sandbox both are reachable, so the refusal above is the profile's doing.
        let none = build(&f, &cfg(SandboxMode::None), None);
        assert!(connects(&none, &f.ws, "127.0.0.1", po));
        // The proxy port counts as an allowed port, and loopback_all opens every loopback port.
        let via_proxy = build(&f, &cfg(SandboxMode::Seatbelt), Some(po));
        assert!(connects(&via_proxy, &f.ws, "127.0.0.1", po));
        assert!(!connects(&via_proxy, &f.ws, "127.0.0.1", pa));
        let all = build(&f, &SandboxCfg { loopback_all: true, ..cfg(SandboxMode::Seatbelt) }, None);
        assert!(connects(&all, &f.ws, "127.0.0.1", pa) && connects(&all, &f.ws, "127.0.0.1", po));
    }

    /// An address of this host that is not loopback, found without sending anything.
    fn host_address() -> Option<std::net::IpAddr> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect("192.0.2.1:9").ok()?;
        let ip = sock.local_addr().ok()?.ip();
        (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
    }

    #[test]
    fn non_loopback_addresses_are_refused_under_seatbelt() {
        if !available() {
            return;
        }
        let test = "non_loopback_addresses_are_refused_under_seatbelt";
        let Some(ip) = host_address() else { return skipped(test, "this host has no address besides loopback") };
        let Ok(listener) = std::net::TcpListener::bind((ip, 0)) else {
            return skipped(test, &format!("cannot listen on {ip}"));
        };
        let port = listener.local_addr().expect("addr").port();
        let f = fx();
        let host = ip.to_string();
        // Control: outside the sandbox the host's own address is reachable.
        let none = build(&f, &cfg(SandboxMode::None), None);
        if !connects(&none, &f.ws, &host, port) {
            return skipped(test, &format!("{host}:{port} cannot be reached even outside the sandbox"));
        }
        // (With `loopback_all` the host's own address counts as localhost to the profile; that is not tested.)
        assert!(!connects(&build(&f, &cfg(SandboxMode::Seatbelt), None), &f.ws, &host, port));
    }

    #[test]
    fn names_that_resolve_outside_the_sandbox_do_not_resolve_under_seatbelt() {
        if !available() {
            return;
        }
        let f = fx();
        let resolves = |mode: SandboxMode, name: &str| {
            let script = format!("/usr/bin/dscacheutil -q host -a name {name}");
            run(&build(&f, &cfg(mode), None), &f.ws, &script).1.contains("ip_address")
        };
        // A name in /etc/hosts is answered from that file by the process itself, sandbox or not, so it
        // proves nothing; the name has to be one that only the resolver daemon knows.
        let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default().to_lowercase();
        let in_hosts = |name: &str| {
            let (name, entries) = (name.to_lowercase(), hosts.lines().map(|l| l.split('#').next().unwrap_or_default()));
            entries.flat_map(|l| l.split_whitespace().skip(1)).any(|n| n == name)
        };
        // This host's own names: `hostname` in full and in short.
        let mut own = [&[][..], &["-s"][..]].into_iter().filter_map(|args: &[&str]| {
            let out = Command::new("/bin/hostname").args(args).output().ok()?;
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let plain = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
            plain.then_some(name)
        });
        let Some(name) = own.find(|n| !in_hosts(n) && resolves(SandboxMode::None, n)) else {
            return skipped(
                "names_that_resolve_outside_the_sandbox_do_not_resolve_under_seatbelt",
                "no name of this host resolves through the resolver daemon",
            );
        };
        assert!(!resolves(SandboxMode::Seatbelt, &name), "{name} resolved under seatbelt");
    }

    #[test]
    fn commands_may_listen_on_loopback_but_need_permission_to_connect_to_themselves() {
        if !available() {
            return;
        }
        let f = fx();
        let port = free_port();
        let listen = format!("(/usr/bin/nc -l 127.0.0.1 {port} </dev/null >/dev/null 2>&1 &); sleep 1; ");
        let connect = format!("/usr/bin/nc -z -w 2 127.0.0.1 {port}");
        let with = build(&f, &SandboxCfg { loopback_ports: vec![port], ..cfg(SandboxMode::Seatbelt) }, None);
        assert!(run(&with, &f.ws, &format!("{listen}{connect}")).0);
        let without = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (ok, _) = run(&without, &f.ws, &format!("{listen}{connect}"));
        assert!(!ok);
        // Clean up the listener the second run left behind.
        let _ = std::net::TcpStream::connect(("127.0.0.1", port));
    }

    fn pid_alive(pid: i32) -> bool {
        // SAFETY: signal 0 only tests for existence.
        unsafe { libc::kill(pid, 0) == 0 }
    }

    #[test]
    fn commands_may_signal_their_own_processes() {
        if !available() {
            return;
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let script = "sleep 300 & c=$!; kill -0 $c || exit 11; kill $c || exit 12; wait $c 2>/dev/null; \
                      if kill -0 $c 2>/dev/null; then exit 13; fi; echo killed";
        let (ok, text) = run(&sb, &f.ws, script);
        assert!(ok && text.trim() == "killed", "{text}");
    }

    #[test]
    fn commands_cannot_signal_processes_outside_the_sandbox() {
        if !available() {
            return;
        }
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let mut outside = std::process::Command::new("/bin/sleep").arg("300").spawn().expect("spawn sleep");
        let pid = i32::try_from(outside.id()).expect("pid");
        let (ok, text) = run(&sb, &f.ws, &format!("kill -9 {pid}"));
        let still_alive = pid_alive(pid);
        let _ = outside.kill();
        let _ = outside.wait();
        assert!(!ok, "kill should have failed: {text}");
        assert!(text.contains("Operation not permitted"), "{text}");
        assert!(still_alive, "the process outside the sandbox was signalled");
        // The same signal from outside the sandbox works, so the refusal above is the profile's doing.
        let mut other = std::process::Command::new("/bin/sleep").arg("300").spawn().expect("spawn sleep");
        let pid = i32::try_from(other.id()).expect("pid");
        let (ok, text) = run(&build(&f, &cfg(SandboxMode::None), None), &f.ws, &format!("kill -9 {pid}"));
        assert!(ok, "{text}");
        let _ = other.wait();
    }

    // ---- Git metadata ----

    /// Runs `git` in `dir` as the operator would, with no global configuration; whether it succeeded.
    fn git_ok(dir: &Path, args: &[&str]) -> bool {
        let mut git = Command::new("git");
        git.args(["-c", "protocol.file.allow=always"]).args(args).current_dir(dir);
        for (name, value) in GIT_ENV {
            git.env(name, value);
        }
        for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
            git.env_remove(name);
        }
        git.output().is_ok_and(|o| o.status.success())
    }

    const GIT_ENV: [(&str, &str); 7] = [
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_AUTHOR_NAME", "t"),
        ("GIT_AUTHOR_EMAIL", "t@t"),
        ("GIT_COMMITTER_NAME", "t"),
        ("GIT_COMMITTER_EMAIL", "t@t"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ];

    /// The same environment for a script run under the profile.
    const GIT_SH: &str =
        "export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t \
                          GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t GIT_TERMINAL_PROMPT=0; ";

    fn git_runs() -> bool {
        Command::new("git").arg("--version").output().is_ok_and(|o| o.status.success())
    }

    /// The workspace is a repository with an external linked worktree `<root>/feature`, the submodules `sub`,
    /// `sub2` (deinitialized), `third/party` and `nest` (which has a submodule `inner` of its own). False when
    /// `git` could not make it.
    fn git_fixture(f: &Fx) -> bool {
        let (ws, root) = (&f.ws, &f.root);
        let (src, nest_src, inner_src) = (root.join("subsrc"), root.join("nestsrc"), root.join("innersrc"));
        for d in [&src, &nest_src, &inner_src] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        let (src_s, nest_s, inner_s) = (s(&src), s(&nest_src), s(&inner_src));
        let steps: Vec<(&PathBuf, Vec<&str>)> = vec![
            (&src, vec!["init", "-q"]),
            (&src, vec!["commit", "-q", "--allow-empty", "-m", "s"]),
            (&inner_src, vec!["init", "-q"]),
            (&inner_src, vec!["commit", "-q", "--allow-empty", "-m", "i"]),
            (&nest_src, vec!["init", "-q"]),
            (&nest_src, vec!["submodule", "add", "-q", inner_s, "inner"]),
            (&nest_src, vec!["commit", "-q", "-m", "n"]),
            (ws, vec!["init", "-q"]),
            (ws, vec!["commit", "-q", "--allow-empty", "-m", "init"]),
            (ws, vec!["worktree", "add", "-q", "../feature"]),
            (ws, vec!["submodule", "add", "-q", src_s, "sub"]),
            (ws, vec!["submodule", "add", "-q", src_s, "sub2"]),
            (ws, vec!["submodule", "add", "-q", src_s, "third/party"]),
            (ws, vec!["submodule", "add", "-q", nest_s, "nest"]),
            (ws, vec!["submodule", "update", "-q", "--init", "--recursive"]),
            (ws, vec!["commit", "-q", "-m", "subs"]),
            (ws, vec!["submodule", "deinit", "-q", "-f", "sub2"]),
        ];
        steps.iter().all(|(dir, args)| git_ok(dir, args))
    }

    fn written(f: &Fx, rel: &str) -> PathBuf {
        f.ws.join(".git").join(rel)
    }

    #[test]
    fn construction_finds_worktree_gitdirs_and_every_submodule_repository() {
        let test = "construction_finds_worktree_gitdirs_and_every_submodule_repository";
        let f = fx();
        if !git_runs() || !git_fixture(&f) {
            return skipped(test, "git cannot make the fixture");
        }
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        for rel in [
            "",
            "worktrees/feature",
            "modules/sub",
            "modules/sub2",
            "modules/third/party",
            "modules/nest",
            "modules/nest/modules/inner",
        ] {
            let dir = written(&f, rel);
            assert!(sb.git_dirs.contains(&dir), "{} is not among {:?}", dir.display(), sb.git_dirs);
            for name in GIT_PRIVATE {
                assert!(sb.protected.contains(&dir.join(name)), "{}/{name} is not protected", dir.display());
            }
        }
        // The repositories below a `modules` directory (`third` is none) are the third rule's exceptions, sorted.
        let below: Vec<PathBuf> =
            ["modules/nest", "modules/nest/modules/inner", "modules/sub", "modules/sub2", "modules/third/party"]
                .iter()
                .map(|r| written(&f, r))
                .collect();
        assert_eq!(sb.git_modules, below);
        let profile = sb.profile().expect("profile");
        let exceptions: String = below.iter().map(|d| git_exception(d)).collect();
        let roots = format!(" (subpath \"{}\") (subpath \"{}\")", s(&f.ws), s(&f.tmp));
        assert!(profile.contains(&git_lines_with(&roots, &exceptions)), "{profile}");
        assert_eq!(profile.matches("(require-not (require-all (subpath").count(), 5, "{profile}");
        // Nothing of the above depends on the mode: Bubblewrap gets the same repositories.
        let none = build(&f, &cfg(SandboxMode::None), None);
        assert_eq!(none.git_dirs, sb.git_dirs);
    }

    #[test]
    fn check_write_refuses_git_metadata_in_the_workspace_and_the_temp_dir_and_accepts_what_git_writes() {
        let test = "check_write_refuses_git_metadata_in_the_workspace_and_the_temp_dir_and_accepts_what_git_writes";
        let f = fx();
        if !git_runs() || !git_fixture(&f) {
            return skipped(test, "git cannot make the fixture");
        }
        for mode in [SandboxMode::Seatbelt, SandboxMode::None] {
            let sb = build(&f, &cfg(mode), None);
            let mut refused = Vec::new();
            for rel in ["worktrees/feature", "modules/sub", "modules/sub2", "modules/third/party", "modules/nest"] {
                let private: &[&str] = if rel.starts_with("worktrees") {
                    &["commondir", "gitdir", "config.worktree"]
                } else {
                    &["config", "hooks/post-checkout", "hooks"]
                };
                refused.extend(private.iter().map(|n| written(&f, &format!("{rel}/{n}"))));
            }
            refused.extend(
                ["modules/nest/modules/inner/config", "modules/nest/modules/inner/hooks/pre-commit"]
                    .map(|r| written(&f, r)),
            );
            refused.push(f.ws.join(".git"));
            for new in [
                "modules/new",
                "modules/new/hooks/x",
                "modules/new/config",
                "worktrees/new",
                "worktrees/new/commondir",
                "modules/third/new",
                "modules/sub/modules",
                "modules/sub/modules/new",
                "modules",
                "worktrees",
                "modules/sub",
                "worktrees/feature",
            ] {
                refused.push(written(&f, new));
            }
            // Written in capitals or inside the temp dir: the same.
            refused.push(f.ws.join(".GIT/Modules/sub/HOOKS/x"));
            for root in [&f.tmp, &f.ws.join("deep/er")] {
                refused.extend(
                    [
                        ".git",
                        ".git/config",
                        ".git/hooks/post-commit",
                        ".git/worktrees/w/commondir",
                        ".git/worktrees/w/gitdir",
                        ".git/worktrees/w/config.worktree",
                        ".git/modules/a/hooks/h",
                        ".git/modules/a/b/c/config",
                        ".git/modules/a/modules/b/hooks/h",
                        ".git/modules/new",
                        ".git/worktrees/new",
                        "x/.git",
                        "x/.git/config",
                    ]
                    .map(|r| root.join(r)),
                );
            }
            for path in &refused {
                let e = sb.check_write(path).expect_err(&format!("{mode:?}: {} is refused", path.display()));
                assert!(
                    e.contains("Git metadata")
                        && e.contains("operator")
                        && e.contains("git clone --bare <url> <dir>.git"),
                    "{e}"
                );
                assert!(e.contains("git worktree add") && e.contains("git submodule update --init"), "{e}");
            }
            for ok in [
                "objects/ab/cdef",
                "refs/heads/feature",
                "HEAD",
                "index",
                "logs/HEAD",
                "worktrees/feature/HEAD",
                "worktrees/feature/index",
                "modules/sub/objects/ab/cdef",
                "modules/sub/refs/heads/x",
                "modules/sub/HEAD",
                "modules/sub2/refs/heads/x",
                "modules/third/party/refs/heads/nb/x",
                "modules/third/party/objects/ab/cd",
                "modules/nest/modules/inner/refs/heads/x",
            ] {
                let path = written(&f, ok);
                assert!(sb.check_write(&path).is_ok(), "{mode:?}: {} is accepted", path.display());
            }
            for ok in [
                f.ws.join("sub/file.txt"),
                f.ws.join("third/party/lib.rs"),
                f.ws.join("src/main.rs"),
                f.tmp.join("x.git/config"),
                f.tmp.join("x.git/hooks/h"),
                f.tmp.join("x/gitignore"),
            ] {
                assert!(sb.check_write(&ok).is_ok(), "{mode:?}: {} is accepted", ok.display());
            }
        }
    }

    /// A repository and directories that are not one, made by hand below `<ws>/.git/modules`.
    fn hand_made(f: &Fx) -> PathBuf {
        let git = f.ws.join(".git");
        let repo = |dir: &Path| {
            std::fs::create_dir_all(dir.join("objects")).expect("mkdir");
            std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").expect("write");
        };
        repo(&git);
        repo(&git.join("modules/sub"));
        repo(&git.join("modules/third/party"));
        repo(&git.join("modules/third/deeper/more/repo"));
        // A worktree's gitdir has a `commondir` file instead of `objects`.
        let w = git.join("modules/viaw");
        std::fs::create_dir_all(&w).expect("mkdir");
        std::fs::write(w.join("HEAD"), "x").expect("write");
        std::fs::write(w.join("commondir"), "../..").expect("write");
        // Not repositories: no `HEAD`, no `objects`, a `HEAD` directory.
        std::fs::create_dir_all(git.join("modules/headless/objects")).expect("mkdir");
        std::fs::create_dir_all(git.join("modules/noobjects")).expect("mkdir");
        std::fs::write(git.join("modules/noobjects/HEAD"), "x").expect("write");
        std::fs::create_dir_all(git.join("modules/dirhead/HEAD")).expect("mkdir");
        std::fs::create_dir_all(git.join("modules/dirhead/objects")).expect("mkdir");
        git
    }

    #[test]
    fn discovery_applies_the_repository_test_and_never_follows_a_link_to_a_directory() {
        let f = fx();
        let git = hand_made(&f);
        // A link to a repository, and a link where `worktrees` and `modules` of another repository would be.
        let elsewhere = f.root.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("objects")).expect("mkdir");
        std::fs::write(elsewhere.join("HEAD"), "x").expect("write");
        symlink(&elsewhere, git.join("modules/linked")).expect("link");
        std::fs::create_dir_all(elsewhere.join("modules/hidden/objects")).expect("mkdir");
        std::fs::write(elsewhere.join("modules/hidden/HEAD"), "x").expect("write");
        symlink(elsewhere.join("modules"), git.join("modules/viaw/modules")).expect("link");
        symlink(&elsewhere, git.join("worktrees")).expect("link");
        let found = git_directories(&f.ws).expect("found");
        let repos: Vec<PathBuf> =
            ["", "modules/sub", "modules/third/deeper/more/repo", "modules/third/party", "modules/viaw"]
                .iter()
                .map(|r| git.join(r))
                .collect();
        assert_eq!(found.repos, repos);
        // Every one below a `modules` directory is an exception of the third rule, the workspace's own is not.
        assert_eq!(found.modules, repos[1..].to_vec());
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let profile = sb.profile().expect("profile");
        let exceptions: String = repos[1..].iter().map(|d| git_exception(d)).collect();
        assert!(
            profile.contains(&exceptions) && profile.matches("(require-not (require-all").count() == 4,
            "{profile}"
        );
        // Below `.git/modules/<name>/` nothing can be made but inside the repositories found, and in them anything
        // outside their own `modules` and `worktrees`.
        for new in [
            "modules/third/new",
            "modules/third/new/hooks",
            "modules/third/deeper/new",
            "modules/headless/new",
            "modules/noobjects/x",
            "modules/sub/modules/x/y",
            "modules/sub/worktrees/x/y",
        ] {
            assert!(sb.check_write(&git.join(new)).is_err(), "{new}");
        }
        for ok in [
            "modules/third/party/refs/x",
            "modules/third/deeper/more/repo/refs/x",
            "modules/viaw/refs/x",
            "modules/sub/refs/heads/nb/x",
        ] {
            assert!(sb.check_write(&git.join(ok)).is_ok(), "{ok}");
        }
    }

    #[test]
    fn discovery_finds_every_repository_in_the_workspace_and_bare_ones_are_not_searched_further() {
        let f = fx();
        // A bare repository the operator made, and a `.git` directory inside it that is no concern of Git's.
        let bare = f.ws.join("fixtures/remote.git");
        std::fs::create_dir_all(bare.join("objects")).expect("mkdir");
        std::fs::create_dir_all(bare.join("hooks")).expect("mkdir");
        std::fs::write(bare.join("HEAD"), "ref: refs/heads/main\n").expect("write");
        std::fs::create_dir_all(bare.join("deeper/.git")).expect("mkdir");
        // A directory that is not a repository: a `HEAD` and nothing else.
        std::fs::create_dir_all(f.ws.join("almost")).expect("mkdir");
        std::fs::write(f.ws.join("almost/HEAD"), "x").expect("write");
        let found = git_directories(&f.ws).expect("found");
        assert_eq!(found.repos, std::slice::from_ref(&bare));
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        assert_eq!(sb.git_dirs, std::slice::from_ref(&bare));
        assert!(sb.protected.contains(&bare.join("hooks")) && sb.protected.contains(&bare.join("config")));
        for hook in ["hooks/pre-receive", "config"] {
            assert!(sb.check_write(&bare.join(hook)).is_err(), "{hook}");
        }
        assert!(sb.check_write(&bare.join("refs/heads/main")).is_ok());
        assert!(sb.check_write(&f.ws.join("almost/x")).is_ok());
        // Under the profile too.
        if available() {
            let (ok, text) = run(&sb, &f.ws, "echo '#!/bin/sh' > fixtures/remote.git/hooks/pre-receive");
            assert!(!ok, "a hook of a bare repository was written: {text}");
            let (ok, text) =
                run(&sb, &f.ws, "mkdir -p fixtures/remote.git/refs/heads && echo x > fixtures/remote.git/refs/heads/b");
            assert!(ok, "{text}");
        }
    }

    #[test]
    fn a_pointer_counts_only_when_it_names_a_repository_and_no_repository_that_holds_a_home_is_mounted() {
        let f = fx();
        // `.git` files that name the user's home (not a repository) and a `commondir` of `../../..`.
        std::fs::create_dir_all(f.ws.join("a")).expect("mkdir");
        std::fs::write(f.ws.join("a/.git"), format!("gitdir: {}\n", s(&f.home))).expect("write");
        let git = f.ws.join("b/.git");
        std::fs::create_dir_all(git.join("objects")).expect("mkdir");
        std::fs::write(git.join("HEAD"), "x").expect("write");
        std::fs::write(git.join("commondir"), "../../..\n").expect("write");
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        assert_eq!(sb.git_dirs, std::slice::from_ref(&git));
        assert!(!sb.protected.contains(&f.home.join("config")), "{:?}", sb.protected);
        // A repository that contains the loom home (the fixture's root, which holds the workspace as well) is found
        // and protected, but not given to Bubblewrap; one that contains the user's home is treated the same.
        let outer = f.root.join("outer");
        let (inner_home, inner_ws) = (outer.join("lm"), outer.join("w"));
        for d in [&inner_home, &inner_ws.join(".loom"), &outer.join("objects")] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        std::fs::write(outer.join("HEAD"), "x").expect("write");
        std::fs::write(inner_ws.join(".git"), format!("gitdir: {}\n", s(&outer))).expect("write");
        let tmp = f.root.join("tmp2");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let make = |home: &Path| {
            Sandbox::with_home(
                &SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) },
                &inner_ws,
                &tmp,
                &inner_home,
                None,
                Some(home.to_path_buf()),
            )
            .expect("sandbox")
        };
        let sb = make(&f.home);
        assert!(sb.git_dirs.is_empty(), "{:?}", sb.git_dirs);
        assert!(sb.protected.contains(&outer.join("config")) && sb.protected.contains(&outer.join("hooks")));
        // The same repository, with the loom home elsewhere: it holds the user's home instead.
        let elsewhere = f.root.join("elsewhere-home");
        std::fs::create_dir_all(&elsewhere).expect("mkdir");
        let sb = Sandbox::with_home(
            &SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) },
            &inner_ws,
            &tmp,
            &elsewhere,
            None,
            Some(inner_home.clone()),
        )
        .expect("sandbox");
        assert!(sb.git_dirs.is_empty(), "{:?}", sb.git_dirs);
    }

    #[test]
    fn a_workspace_directory_that_cannot_be_read_refuses_construction_with_a_sentence_that_names_it() {
        use std::os::unix::fs::PermissionsExt;
        let f = fx();
        let locked = f.ws.join("src/locked");
        std::fs::create_dir_all(&locked).expect("mkdir");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        // A process that can read it anyway (root) makes this vacuous.
        let readable = std::fs::read_dir(&locked).is_ok();
        let made = Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &f.tmp, &f.home, None);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        if readable {
            return skipped("a_workspace_directory_that_cannot_be_read", "this user reads any directory");
        }
        let e = made.expect_err("refused").to_string();
        assert!(e.contains(s(&locked)) && e.contains("cannot be read") && e.contains("Make it readable"), "{e}");
    }

    #[test]
    fn discovery_refuses_more_than_4096_repositories_and_directories_below_modules() {
        let f = fx();
        let git = f.ws.join(".git");
        std::fs::create_dir_all(git.join("objects")).expect("mkdir");
        std::fs::write(git.join("HEAD"), "x").expect("write");
        for i in 0..4096 {
            std::fs::create_dir_all(git.join(format!("modules/d{i}"))).expect("mkdir");
        }
        // The repository itself is one more than 4096 together with the directories.
        let e = Sandbox::new(&cfg(SandboxMode::Seatbelt), &f.ws, &f.tmp, &f.home, None).expect_err("too many");
        assert!(e.to_string().contains("4096"), "{e}");
        std::fs::remove_dir(git.join("modules/d0")).expect("rmdir");
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        assert!(sb.git_modules.is_empty());
    }

    #[test]
    fn git_rules_hold_in_every_writable_root_and_are_judged_relative_to_it() {
        let f = fx();
        let extra = f.root.join("extra");
        std::fs::create_dir_all(&extra).expect("mkdir");
        let c = SandboxCfg { extra_writable: vec![s(&extra).to_string()], ..cfg(SandboxMode::Seatbelt) };
        let sb = build(&f, &c, None);
        for root in [&f.ws, &f.tmp, &extra] {
            assert!(sb.check_write(&root.join("p/.git/config")).is_err(), "{}", root.display());
            assert!(sb.check_write(&root.join("p/.git/modules/m")).is_err(), "{}", root.display());
            assert!(sb.check_write(&root.join("p/src/.gitignore")).is_ok(), "{}", root.display());
            assert!(sb.check_write(&root.join("p/.git/objects/ab")).is_ok(), "{}", root.display());
        }
        let profile = sb.profile().expect("profile");
        let roots = format!(" (subpath \"{}\") (subpath \"{}\") (subpath \"{}\")", s(&f.ws), s(&f.tmp), s(&extra));
        assert!(profile.contains(&git_lines(&roots)), "{profile}");
        assert!(Sandbox::new(&cfg(SandboxMode::None), &f.ws, &f.tmp, &f.home, None)
            .expect("sandbox")
            .check_write(&f.tmp.join("x/.git"))
            .is_err());
    }

    /// Every spelling of `name` that the volume takes for it, with a few of them: its own, in capitals, each
    /// position replaced by each equivalent in turn, and every position replaced at once.
    fn fold_variants(name: &str) -> Vec<String> {
        let chars: Vec<char> = name.chars().collect();
        // What can stand at `at`: (spelling, characters of `name` it takes).
        let choices = |at: usize| -> Vec<(String, usize)> {
            let c = chars.get(at).copied().unwrap_or('.');
            let mut out = vec![(c.to_string(), 1), (c.to_ascii_uppercase().to_string(), 1)];
            out.extend(FOLD_LETTERS.iter().filter(|(_, to)| *to == c).map(|(from, _)| (from.to_string(), 1)));
            let rest: String = chars.iter().skip(at).collect();
            out.extend(
                FOLD_EXPANDS
                    .iter()
                    .filter(|(_, to)| rest.starts_with(to))
                    .map(|(from, to)| (from.to_string(), to.len())),
            );
            out
        };
        let mut out = vec![name.to_string(), name.to_uppercase()];
        for pos in 0..chars.len() {
            for (alt, took) in choices(pos).into_iter().skip(2) {
                let before: String = chars.iter().take(pos).collect();
                let after: String = chars.iter().skip(pos + took).collect();
                out.push(format!("{before}{alt}{after}"));
            }
        }
        let mut all = String::new();
        let mut at = 0;
        while at < chars.len() {
            let (alt, took) = choices(at).pop().unwrap_or((String::new(), 1));
            all.push_str(&alt);
            at += took;
        }
        out.push(all);
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn fold_is_the_volumes_and_the_regex_matches_what_it_folds() {
        assert_eq!(fold("Module\u{17f}"), "modules");
        assert_eq!(fold("HOO\u{212a}S"), "hooks");
        assert_eq!(fold("con\u{fb01}g.worktree"), "config.worktree");
        assert_eq!(fold("\u{fb03}"), "ffi");
        assert_eq!(fold("\u{df}"), "ss");
        // Not folded by the volume: the dotted and dotless i, the fullwidth s, a zero-width joiner.
        for other in ["g\u{130}t", "g\u{131}t", "module\u{ff53}", "mo\u{200d}dules"] {
            assert!(!fold(other).is_ascii(), "{other}");
        }
        assert_eq!(fold_regex("modules"), "[mM][oO][dD][uU][lL][eE](s|S|\u{17f})");
        assert_eq!(fold_regex("hooks"), "[hH][oO][oO](k|K|\u{212a})(s|S|\u{17f})");
        assert_eq!(fold_regex("config"), "[cC][oO][nN]([fF][iI]|\u{fb01})[gG]");
        assert_eq!(fold_regex(".git"), "[.][gG][iI][tT]");
        // Runs that overlap are spelled every way.
        let re = regex::Regex::new(&format!("^{}$", fold_regex("ffi"))).expect("regex");
        for yes in ["ffi", "FFI", "\u{fb00}i", "f\u{fb01}", "\u{fb03}", "F\u{fb01}"] {
            assert!(re.is_match(yes), "{yes}");
        }
        for no in ["fi", "\u{fb01}", "ff", "\u{fb02}i"] {
            assert!(!re.is_match(no), "{no}");
        }
        let re = regex::Regex::new(&format!("^{}$", fold_regex("sst"))).expect("regex");
        for yes in ["sst", "\u{df}t", "s\u{fb06}", "\u{17f}\u{fb05}", "\u{17f}\u{17f}T"] {
            assert!(re.is_match(yes), "{yes}");
        }
    }

    #[test]
    fn the_regexes_and_the_name_checks_agree_on_every_fold_of_the_git_names() {
        let f = fx();
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let profile = sb.profile().expect("profile");
        let rules: Vec<regex::Regex> = profile
            .lines()
            .filter_map(|l| {
                if !l.contains("(regex #\"^.*/") {
                    return None;
                }
                let start = l.find("(regex #\"")? + "(regex #\"".len();
                let end = l.rfind("\")))")?;
                Some(regex::Regex::new(l.get(start..end)?).expect("the profile's regex"))
            })
            .collect();
        assert_eq!(rules.len(), 3, "{profile}");
        let root = &f.ws;
        let names: Vec<&str> = GIT_PRIVATE.iter().copied().chain(["modules", "worktrees"]).collect();
        let mut paths = Vec::new();
        for gitv in fold_variants(".git") {
            paths.push(format!("{gitv}/config"));
            paths.push(gitv.clone());
        }
        for name in &names {
            for v in fold_variants(name) {
                for prefix in
                    ["", "worktrees/w/", "modules/a/", "modules/a/b/", "modules/a/modules/b/", "modules/", "worktrees/"]
                {
                    for suffix in ["", "/x", "/x/y"] {
                        paths.push(format!(".git/{prefix}{v}{suffix}"));
                    }
                }
            }
        }
        for m in fold_variants("modules") {
            for w in fold_variants("worktrees") {
                paths.push(format!(".git/{w}/n/commondir"));
                paths.push(format!(".git/{m}/n/{w}/x"));
            }
            for p in ["config", "hooks"].iter().flat_map(|n| fold_variants(n)) {
                paths.push(format!(".git/{m}/evil/{p}"));
                paths.push(format!(".git/{m}/{p}"));
            }
        }
        for p in ["worktrees", "modules"].iter().flat_map(|n| fold_variants(n)) {
            for q in ["commondir", "gitdir", "config.worktree"].iter().flat_map(|n| fold_variants(n)) {
                paths.push(format!(".git/{p}/w/{q}"));
            }
        }
        // Names that are none of theirs.
        for other in [
            "objects",
            "refs/heads/x",
            "modulez/x/hooks",
            "hooks2",
            "modules2/x",
            "configs",
            "worktree/x/config",
            "conf\u{fb02}g",
            "g\u{130}t",
        ] {
            paths.push(format!(".git/{other}"));
        }
        let mut refused = 0_usize;
        for rel in &paths {
            let full = root.join(rel);
            let text = full.to_string_lossy().to_string();
            let (meta, container) = (git_metadata(&full, root), git_container(&full, root));
            let below = git_below_module(&full, root);
            let hit = |re: &regex::Regex| re.is_match(&text);
            assert_eq!(hit(rules.first().expect("rule")), meta, "metadata rule and git_metadata on {text}");
            assert_eq!(hit(rules.get(1).expect("rule")), container, "container rule and git_container on {text}");
            assert_eq!(hit(rules.get(2).expect("rule")), below, "third rule and git_below_module on {text}");
            if meta || container || below {
                refused += 1;
                assert!(sb.check_write(&full).is_err(), "{text}");
            }
        }
        assert!(refused > 500, "{refused}");
        // And the ones that matter, by hand.
        for rel in [
            ".git/module\u{17f}/x/hooks",
            ".git/hoo\u{212a}s",
            ".git/hook\u{17f}/x",
            ".git/con\u{fb01}g.worktree",
            ".git/worktree\u{17f}/w",
            ".git/modules/x/con\u{fb01}g",
            ".GIT/MODULE\u{17f}/x/CON\u{fb01}G",
        ] {
            assert!(sb.check_write(&root.join(rel)).is_err(), "{rel}");
        }
        assert!(sb.check_write(&root.join(".git/objects/ab/cdef")).is_ok());
    }

    #[test]
    fn names_the_volume_folds_to_the_git_names_cannot_be_made_under_the_profile() {
        let test = "names_the_volume_folds_to_the_git_names_cannot_be_made_under_the_profile";
        if !available() {
            return skipped(test, "sandbox-exec is missing");
        }
        let f = fx();
        // A repository with none of the names yet: an existing entry is judged by the name it is stored under, so
        // what the profile has to refuse is making one under another spelling.
        let git = f.ws.join(".git");
        std::fs::create_dir_all(git.join("objects")).expect("mkdir");
        std::fs::write(git.join("HEAD"), "ref: refs/heads/main\n").expect("write");
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        for attempt in [
            "mkdir -p .git/module\u{17f}/x/hooks",
            "mkdir -p .git/hoo\u{212a}s",
            "mkdir -p .git/hook\u{17f}",
            "echo x > .git/con\u{fb01}g.worktree",
            "mkdir -p .git/worktree\u{17f}/w",
        ] {
            let (ok, text) = run(&sb, &f.ws, attempt);
            assert!(!ok, "`{attempt}` succeeded under the profile: {text}");
        }
        for (ok_script, what) in [
            ("mkdir -p .git/objects/ab && echo x > .git/refs-x", "a name that is none of them"),
            ("mkdir -p .git/con\u{fb02}g", "a ligature that is not `fi`"),
        ] {
            let (ok, text) = run(&sb, &f.ws, ok_script);
            assert!(ok, "{what}: `{ok_script}` failed under the profile: {text}");
        }
    }

    #[test]
    fn the_git_rules_come_after_every_rule_about_the_temp_dir() {
        let f = fx_prod();
        let inside = f.tmp.join("kept");
        let c = SandboxCfg { protected_paths: vec![s(&inside).to_string()], ..cfg(SandboxMode::Seatbelt) };
        let profile = build(&f, &c, None).profile().expect("profile");
        let last = |needle: &str| profile.rfind(needle).unwrap_or_else(|| panic!("{needle} is missing: {profile}"));
        let (rule, container) = (
            profile.find("(deny file-write* (require-all").expect("rule"),
            last("(deny file-write-create file-write-unlink (require-all"),
        );
        for earlier in [
            format!("(allow file-write* (subpath \"{}\"))", s(&f.tmp)),
            format!("(deny file-write-unlink file-write-create (literal \"{}\"))", s(&f.tmp)),
            format!("(deny file-write* (subpath \"{}\"))", s(&inside)),
        ] {
            assert!(rule > last(&earlier) && container > rule, "{earlier} must come before the Git rules: {profile}");
        }
        let unreadable = last("(deny file-read* file-test-existence (subpath");
        assert!(container < unreadable, "{profile}");
    }

    #[test]
    fn git_commands_under_the_profile_cannot_plant_what_git_runs() {
        let test = "git_commands_under_the_profile_cannot_plant_what_git_runs";
        if !available() {
            return;
        }
        let f = fx();
        if !git_runs() || !git_fixture(&f) {
            return skipped(test, "git cannot make the fixture");
        }
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let attempts = [
            // The files Git reads configuration, hooks and pointers from.
            "echo x > .git/worktrees/feature/commondir",
            "echo x >> .git/worktrees/feature/gitdir",
            "echo x > .git/worktrees/feature/config.worktree",
            "echo x >> .git/modules/sub/config",
            "echo x > .git/modules/sub/hooks/post-checkout",
            "echo x >> .git/modules/sub2/config",
            "echo x > .git/modules/sub2/hooks/post-checkout",
            "echo x > .git/modules/third/party/hooks/post-checkout",
            "echo x > .git/modules/nest/modules/inner/hooks/post-checkout",
            "echo x >> .git/config",
            "echo x > .git/hooks/pre-commit",
            "mkdir -p .git/modules/new/hooks",
            "mkdir -p .git/modules/third/new/hooks",
            // A directory made elsewhere and moved into place brings its own `config` and `hooks`.
            "mkdir -p $TMPDIR/m/hooks && mv $TMPDIR/m .git/modules/new",
            "mkdir -p $TMPDIR/m/hooks && mv $TMPDIR/m .git/worktrees/new",
            "mkdir -p $TMPDIR/m/hooks && mv $TMPDIR/m .git/modules/third/new",
            "mkdir -p $TMPDIR/m/hooks && mv $TMPDIR/m .git/modules/sub/modules",
            "mkdir -p $TMPDIR/m/hooks && mv $TMPDIR/m .git/modules/nest/modules/new",
            // And what holds a rule's path cannot be moved away.
            "mv .git/modules .git/modules-away",
            "mv .git/modules/sub .git/sub-away",
            "mv .git/worktrees .git/worktrees-away",
            // Nor can a repository be made where commands write, or one moved in.
            "git init -q $TMPDIR/x",
            "git init -q nested",
            "git init -q --bare $TMPDIR/e.git && mkdir $TMPDIR/e && mv $TMPDIR/e.git $TMPDIR/e/.git",
            "git init -q --bare $TMPDIR/e.git && mkdir -p evil.git && mv $TMPDIR/e.git evil.git/.git",
            "mkdir -p $TMPDIR/d/.GIT && mv $TMPDIR/d nested-dir",
        ];
        for attempt in attempts {
            let (ok, text) = run(&sb, &f.ws, &format!("{GIT_SH}{attempt}"));
            assert!(!ok, "`{attempt}` succeeded under the profile: {text}");
        }
        // Git's own writes still work: a commit and a branch in the workspace and in each existing submodule, a
        // bare repository for the session's own use.
        for script in [
            "echo a > a.txt && git add a.txt && git commit -qm a && git branch nb/x",
            "cd sub && echo a > a && git add a && git commit -qm a && git branch nb/x",
            "cd third/party && echo a > a && git add a && git commit -qm a && git branch nb/x",
            "cd nest/inner && echo a > a && git add a && git commit -qm a && git branch nb/x",
            "git init -q --bare $TMPDIR/x.git && git --git-dir=$TMPDIR/x.git rev-parse --git-dir",
        ] {
            let (ok, text) = run(&sb, &f.ws, &format!("{GIT_SH}{script}"));
            assert!(ok, "`{script}` failed under the profile: {text}");
        }
        // Outside the profile the same attempts work, so the refusals above are the profile's doing.
        let none = build(&f, &cfg(SandboxMode::None), None);
        let (ok, text) =
            run(&none, &f.ws, &format!("{GIT_SH}mkdir -p $TMPDIR/m/hooks && mv $TMPDIR/m .git/modules/new"));
        assert!(ok, "{text}");
    }

    /// Steps that a command might take to make the operator's next `git status` run its code: both end with
    /// `marker` made by a `core.fsmonitor` that Git runs as the operator.
    fn fsmonitor_attacks(marker: &Path) -> [String; 2] {
        let config = format!("[core]\\n\\tfsmonitor = touch {}; false\\n\\trepositoryformatversion = 0\\n", s(marker));
        [
            // The external worktree's `commondir` points at a copy of the repository whose config runs it.
            format!(
                "mkdir -p $TMPDIR/evil && cp -R .git/* $TMPDIR/evil/ && printf '{config}' >> $TMPDIR/evil/config \
                 && echo $TMPDIR/evil > .git/worktrees/feature/commondir"
            ),
            // A repository made elsewhere is moved into the workspace and a gitlink added for it.
            format!(
                "git init -q $TMPDIR/evil && git -C $TMPDIR/evil commit -q --allow-empty -m e \
                 && git -C $TMPDIR/evil config core.fsmonitor 'touch {}; false' && mv $TMPDIR/evil evil \
                 && git update-index --add --cacheinfo 160000,$(git -C evil rev-parse HEAD),evil",
                s(marker)
            ),
        ]
    }

    #[test]
    fn what_a_command_plants_does_not_run_in_the_operators_next_git_command() {
        let test = "what_a_command_plants_does_not_run_in_the_operators_next_git_command";
        if !available() {
            return;
        }
        let ran = |mode: SandboxMode, step: usize| -> Option<bool> {
            let f = fx();
            if !git_runs() || !git_fixture(&f) {
                return None;
            }
            let marker = f.root.join("pwned");
            let script = &fsmonitor_attacks(&marker)[step];
            let sb = build(&f, &cfg(mode), None);
            let _ = run(&sb, &f.ws, &format!("{GIT_SH}{script}"));
            // The operator's own Git, outside the sandbox.
            for dir in [f.root.join("feature"), f.ws.clone()] {
                git_ok(&dir, &["status"]);
            }
            Some(marker.exists())
        };
        for step in 0..2 {
            match ran(SandboxMode::None, step) {
                None => return skipped(test, "git cannot make the fixture"),
                Some(false) => return skipped(test, &format!("step {step} does not make Git run its code here")),
                Some(true) => {}
            }
            assert_eq!(ran(SandboxMode::Seatbelt, step), Some(false), "step {step} ran code under the profile");
        }
    }

    // ---- Git, second round ----

    /// A name that no other run of the tests makes.
    fn unique(what: &str) -> String {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        format!("{what}-{}-{nanos}", std::process::id())
    }

    #[test]
    fn the_config_reader_reads_sections_keys_and_values_as_git_does() {
        let hooks = |v: &str| ConfigPath::HooksPath(v.to_string());
        let include = |v: &str| ConfigPath::Include(v.to_string());
        let read = |text: &str| config_paths(text);
        // Names are compared without regard to case; a key may follow the header in its line.
        assert_eq!(read("[core]\n\thooksPath = .husky\n"), [hooks(".husky")]);
        assert_eq!(read("[CORE]\nHOOKSpath=.husky"), [hooks(".husky")]);
        assert_eq!(read("[core] hooksPath = x\n"), [hooks("x")]);
        assert_eq!(read("\u{feff}[core]\r\nhooksPath = x\r\n"), [hooks("x")]);
        // Values: quotes keep what they hold, comments end an unquoted value, escapes, continuation.
        assert_eq!(read("[core]\nhooksPath = \"~/my hooks\"  \n"), [hooks("~/my hooks")]);
        assert_eq!(read("[core]\nhooksPath = a\"b c\"d # comment\n"), [hooks("ab cd")]);
        assert_eq!(read("[core]\nhooksPath = x ; y\n"), [hooks("x")]);
        assert_eq!(read("[core]\nhooksPath = x#y\n"), [hooks("x")]);
        assert_eq!(read("[core]\nhooksPath = \"x # y ; z\"\n"), [hooks("x # y ; z")]);
        assert_eq!(read("[core]\nhooksPath = \"x \" \n"), [hooks("x ")]);
        assert_eq!(read("[core]\nhooksPath = a\\\nb\n"), [hooks("ab")]);
        assert_eq!(read("[core]\nhooksPath = a\\\r\nb\r\n"), [hooks("ab")]);
        assert_eq!(read("[core]\nhooksPath = \"a\\\\b\\\"c\\td\"\n"), [hooks("a\\b\"c\td")]);
        assert_eq!(read("[core]\nhooksPath =\n"), [hooks("")]);
        // Includes, with and without a condition, in every spelling of a subsection.
        let text = "[include]\npath = a.inc\n[includeIf \"gitdir:~/work/\"]\n\tpath = ~/b.inc\n\
                    [includeif.gitdir:/x/]\npath = c.inc\n[includeIf \"gitdir:C:\\\\x\\\"y\"]\npath = d.inc\n\
                    [includeIf \"onbranch:main\"]\npath = \"e f.inc\"\n";
        assert_eq!(
            read(text),
            [include("a.inc"), include("~/b.inc"), include("c.inc"), include("d.inc"), include("e f.inc")]
        );
        // Things that name no such path, or that cannot be read: nothing, and what follows is still read.
        for none in [
            "[core \"sub\"]\nhooksPath = x\n",
            "[include \"sub\"]\npath = x\n",
            "[include.sub]\npath = x\n",
            "[includeIf]\npath = x\n",
            "[other]\nhooksPath = x\npath = y\n",
            "[core]\nhooksPathExtra = x\nhooksPat = y\n",
            "[core]\nhooksPath\n",
            "hooksPath = x\n[core]\n",
            "[core]\n[other]\nhooksPath = x\n",
            "# [core]\n; hooksPath = x\n",
            "[core]\n# hooksPath = x\n",
            "[core\nhooksPath = x\n",
            "[core]\nhooksPath = \"x\n",
            "[core]\nhooksPath = a\\qb\n",
        ] {
            assert_eq!(read(none), [], "{none:?}");
        }
        assert_eq!(read("[core]\nhooksPath = \"x\n[core]\nhooksPath = y\n"), [hooks("y")]);
        assert_eq!(read("[core]\nhooksPath = a\\qb\nhooksPath = ok\n"), [hooks("ok")]);
        assert_eq!(read("[core\n[core]\nhooksPath = ok\n"), [hooks("ok")]);
        assert_eq!(read("[core]\nbare\nhooksPath = ok\n"), [hooks("ok")]);
    }

    #[test]
    fn config_files_are_followed_ten_deep_each_file_once_and_values_are_resolved_as_git_does() {
        let f = fx();
        let dir = f.root.join("inc");
        std::fs::create_dir_all(&dir).expect("mkdir");
        for k in 0..13 {
            let text = format!("[core]\nhooksPath = h{k}\n[include]\npath = c{}\n", k + 1);
            std::fs::write(dir.join(format!("c{k}")), text).expect("write");
        }
        let facts = read_config_files(&[dir.join("c0")], None);
        // The first file and ten that it includes in turn; the eleventh is named and not read.
        assert_eq!(facts.hooks, (0..=10).map(|k| format!("h{k}")).collect::<Vec<_>>());
        assert_eq!(facts.includes, (1..=11).map(|k| dir.join(format!("c{k}"))).collect::<Vec<_>>());
        // A cycle, an include named twice and a file given twice are read once.
        std::fs::write(dir.join("a"), "[core]\nhooksPath = a\n[include]\npath = b\n").expect("write");
        std::fs::write(dir.join("b"), "[core]\nhooksPath = b\n[include]\npath = a\npath = ./b\n").expect("write");
        let facts = read_config_files(&[dir.join("a"), dir.join("a"), dir.join("b")], None);
        assert_eq!(facts.hooks, ["a", "b"]);
        // `~/` is the home directory, a relative path is taken from the base, a missing file is named all the same.
        let home = f.root.join("h");
        assert_eq!(config_value_path("~/x", Some(&home), &dir), Some(home.join("x")));
        assert_eq!(config_value_path("~/x", None, &dir), None);
        assert_eq!(config_value_path("~", Some(&home), &dir), Some(home.clone()));
        assert_eq!(config_value_path("x/y", Some(&home), &dir), Some(dir.join("x/y")));
        assert_eq!(config_value_path("/x/y", Some(&home), &dir), Some(PathBuf::from("/x/y")));
        assert_eq!(config_value_path("", Some(&home), &dir), None);
        std::fs::write(dir.join("m"), "[include]\npath = missing.inc\n").expect("write");
        assert_eq!(read_config_files(&[dir.join("m")], None).includes, [dir.join("missing.inc")]);
        // What is not a regular file is not read (a directory, a link to nothing).
        assert!(read_config(&dir).is_none() && read_config(&dir.join("none")).is_none());
    }

    /// A repository by hand in `dir` (`HEAD` and `objects`) with `config`.
    fn hand_repo(dir: &Path, config: &str) {
        std::fs::create_dir_all(dir.join("objects")).expect("mkdir");
        std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").expect("write");
        if !config.is_empty() {
            std::fs::write(dir.join("config"), config).expect("write");
        }
    }

    /// A sandbox whose user home directory and `XDG_CONFIG_HOME` are given.
    fn build_env(f: &Fx, home: &Path, xdg: Option<&Path>) -> Sandbox {
        let c = cfg(SandboxMode::Seatbelt);
        Sandbox::with_env(&c, &f.ws, &f.tmp, &f.home, None, Some(home.to_path_buf()), xdg.map(Path::to_path_buf))
            .expect("sandbox")
    }

    fn refused_as_protected(sb: &Sandbox, path: &Path) {
        let e = sb.check_write(path).expect_err(&format!("{} is refused", path.display()));
        assert!(e.contains("protected") || e.contains("Git metadata"), "{e}");
        let profile = sb.profile().expect("profile");
        let covered =
            sb.protected.iter().any(|p| under(path, p) && profile.contains(&format!("(subpath \"{}\")", s(p))));
        assert!(covered || sb.git_refused(path), "{} is in no rule of {profile}", path.display());
    }

    #[test]
    fn the_hooks_directory_and_the_files_a_configuration_includes_are_protected() {
        let f = fx();
        let git = f.ws.join(".git");
        let uhome = f.root.join("uhome");
        std::fs::create_dir_all(&uhome).expect("mkdir");
        // `core.hooksPath` relative to the top of the working tree, in the repository's own configuration.
        hand_repo(&git, "[core]\n\thooksPath = .husky\n");
        let sb = build_env(&f, &uhome, None);
        assert!(sb.protected.contains(&f.ws.join(".husky")), "{:?}", sb.protected);
        for hook in [".husky/post-checkout", ".husky", ".husky/_/husky.sh"] {
            refused_as_protected(&sb, &f.ws.join(hook));
        }
        for ok in ["src/a.rs", ".husky-not/x", "husky/x"] {
            assert!(sb.check_write(&f.ws.join(ok)).is_ok(), "{ok}");
        }
        // As written and as resolved: a link in the workspace to where hooks are written still protects what it
        // names, and the target it leads to.
        let elsewhere = f.root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).expect("mkdir");
        std::fs::write(git.join("config"), format!("[core]\nhooksPath = {}\n", s(&elsewhere))).expect("write");
        let sb = build_env(&f, &uhome, None);
        assert!(!sb.protected.contains(&elsewhere), "outside every writable root: {:?}", sb.protected);
        symlink(&elsewhere, f.ws.join("linked")).expect("link");
        std::fs::write(git.join("config"), "[core]\nhooksPath = linked/hooks\n").expect("write");
        let sb = build_env(&f, &uhome, None);
        assert!(sb.protected.contains(&f.ws.join("linked/hooks")), "{:?}", sb.protected);
        assert!(!sb.protected.contains(&elsewhere.join("hooks")), "the target is outside the roots");
        std::fs::remove_file(f.ws.join("linked")).expect("unlink");
        // The hooks directory in the temp dir is a writable root too; `~/` is the user's home directory; a value
        // in quotes is read as Git reads it.
        std::fs::write(git.join("config"), format!("[core]\nhooksPath = \"{}/th ooks\"\n", s(&f.tmp))).expect("write");
        assert!(build_env(&f, &uhome, None).protected.contains(&f.tmp.join("th ooks")));
        let inside = f.ws.join("h");
        std::fs::write(git.join("config"), "[core]\n\thooksPath = \"~/hk\" # the hooks\n").expect("write");
        let sb = build_env(&f, &inside, None);
        assert!(sb.protected.contains(&inside.join("hk")), "{:?}", sb.protected);
        // `/dev/null` (hooks off) and `~/` with no home protect nothing and are no error.
        std::fs::write(git.join("config"), "[core]\nhooksPath = /dev/null\n").expect("write");
        assert!(!build_env(&f, &uhome, None).protected.iter().any(|p| p.starts_with("/dev")));
        std::fs::write(git.join("config"), "[core]\nhooksPath = ~/hk\n").expect("write");
        let c = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        let sb = Sandbox::with_env(&c, &f.ws, &f.tmp, &f.home, None, None, None).expect("sandbox");
        assert!(!sb.protected.iter().any(|p| p.ends_with("hk")), "{:?}", sb.protected);
    }

    #[test]
    fn an_included_file_and_what_it_sets_are_protected() {
        let f = fx();
        let git = f.ws.join(".git");
        let uhome = f.root.join("uhome");
        std::fs::create_dir_all(&uhome).expect("mkdir");
        let outside = f.root.join("outside.inc");
        // An include is relative to the directory of the file that names it (`.git/` here), `includeIf` counts
        // whatever its condition, and the included file's own hooks path and includes are read in turn.
        let config = format!(
            "[include]\n\tpath = ../shared.inc\n[includeIf \"gitdir:/never/\"]\n\tpath = conditional.inc\n\
             [include]\n\tpath = {}\n",
            s(&outside)
        );
        hand_repo(&git, &config);
        std::fs::write(f.ws.join("shared.inc"), "[core]\nhooksPath = shared-hooks\n[include]\npath = nested.inc\n")
            .expect("write");
        std::fs::write(git.join("conditional.inc"), "[core]\nhooksPath = ~/never\n").expect("write");
        std::fs::write(&outside, "[core]\nhooksPath = outside-hooks\n").expect("write");
        let sb = build_env(&f, &uhome, None);
        for protected in ["shared.inc", "shared-hooks", ".git/conditional.inc", "nested.inc"] {
            assert!(sb.protected.contains(&f.ws.join(protected)), "{protected}: {:?}", sb.protected);
            refused_as_protected(&sb, &f.ws.join(protected));
        }
        assert!(sb.protected.contains(&f.ws.join("outside-hooks")), "{:?}", sb.protected);
        // Where the include lies outside every writable root nothing is added for it; its value still is.
        assert!(!sb.protected.contains(&outside), "{:?}", sb.protected);
        assert!(sb.check_write(&f.ws.join("src/a.rs")).is_ok());
    }

    #[test]
    fn the_global_configuration_is_read_from_home_and_xdg_config_home() {
        let f = fx();
        hand_repo(&f.ws.join(".git"), "");
        let uhome = f.root.join("uhome");
        let xdg = f.root.join("xdg");
        for d in [&uhome, &xdg.join("git")] {
            std::fs::create_dir_all(d).expect("mkdir");
        }
        // A relative value in the global configuration is taken from the top of each repository found.
        std::fs::write(uhome.join(".gitconfig"), "[core]\nhooksPath = global-hooks\n[include]\npath = ~/more\n")
            .expect("write");
        std::fs::write(uhome.join("more"), "[core]\nhooksPath = more-hooks\n").expect("write");
        std::fs::write(xdg.join("git/config"), format!("[core]\nhooksPath = {}/xdg-hooks\n", s(&f.tmp)))
            .expect("write");
        let sb = build_env(&f, &uhome, Some(&xdg));
        for protected in [f.ws.join("global-hooks"), f.ws.join("more-hooks"), f.tmp.join("xdg-hooks")] {
            assert!(sb.protected.contains(&protected), "{}: {:?}", protected.display(), sb.protected);
            refused_as_protected(&sb, &protected.join("post-commit"));
        }
        // The user's configuration files are protected when they lie in a writable root, the XDG ones where
        // `XDG_CONFIG_HOME` says, else under `~/.config/git`.
        assert!(!sb.protected.iter().any(|p| p.ends_with(".gitconfig") || p.ends_with("git")), "{:?}", sb.protected);
        let home_in_ws = f.ws.join("home");
        std::fs::create_dir_all(home_in_ws.join(".config/git")).expect("mkdir");
        std::fs::write(home_in_ws.join(".config/git/config"), "[core]\nhooksPath = from-xdg-default\n").expect("write");
        let sb = build_env(&f, &home_in_ws, None);
        for protected in [".gitconfig", ".config/git", "from-xdg-default"] {
            let path = if protected == "from-xdg-default" { f.ws.join(protected) } else { home_in_ws.join(protected) };
            assert!(sb.protected.contains(&path), "{}: {:?}", path.display(), sb.protected);
        }
        refused_as_protected(&sb, &home_in_ws.join(".gitconfig"));
        refused_as_protected(&sb, &home_in_ws.join(".config/git/ignore"));
        // With `XDG_CONFIG_HOME` set the default location is not the one read, and its own `git` directory is.
        let xdg_in_ws = f.ws.join("xdgdir");
        let sb = build_env(&f, &home_in_ws, Some(&xdg_in_ws));
        assert!(sb.protected.contains(&xdg_in_ws.join("git")), "{:?}", sb.protected);
        assert!(!sb.protected.contains(&home_in_ws.join(".config/git")), "{:?}", sb.protected);
        assert!(!sb.protected.contains(&f.ws.join("from-xdg-default")), "{:?}", sb.protected);
        // A relative `XDG_CONFIG_HOME` is not a place Git looks.
        let sb = build_env(&f, &home_in_ws, Some(Path::new("relative")));
        assert!(sb.protected.contains(&home_in_ws.join(".config/git")), "{:?}", sb.protected);
    }

    #[test]
    fn a_relative_hooks_path_is_taken_from_the_top_of_the_working_tree() {
        let f = fx();
        let uhome = f.root.join("uhome");
        std::fs::create_dir_all(&uhome).expect("mkdir");
        let git = f.ws.join(".git");
        hand_repo(&git, "[core]\nhooksPath = main-hooks\n");
        // A linked worktree: its private gitdir names its `.git` file, and its `config.worktree` is read.
        let (top, private) = (f.ws.join("wt"), git.join("worktrees/w"));
        std::fs::create_dir_all(&top).expect("mkdir");
        std::fs::create_dir_all(&private).expect("mkdir");
        std::fs::write(private.join("HEAD"), "ref: refs/heads/w\n").expect("write");
        std::fs::write(private.join("commondir"), "../..\n").expect("write");
        std::fs::write(private.join("gitdir"), format!("{}/.git\n", s(&top))).expect("write");
        std::fs::write(private.join("config.worktree"), "[core]\nhooksPath = wt-hooks\n").expect("write");
        std::fs::write(top.join(".git"), format!("gitdir: {}\n", s(&private))).expect("write");
        // A bare repository and a submodule repository: the repository itself.
        let bare = f.ws.join("fx/remote.git");
        hand_repo(&bare, "[core]\nhooksPath = rel\n");
        hand_repo(&git.join("modules/sub"), "[core]\nhooksPath = sub-hooks\n");
        let sb = build_env(&f, &uhome, None);
        for protected in
            [f.ws.join("main-hooks"), top.join("wt-hooks"), bare.join("rel"), git.join("modules/sub/sub-hooks")]
        {
            assert!(sb.protected.contains(&protected), "{}: {:?}", protected.display(), sb.protected);
        }
        assert!(!sb.protected.contains(&f.ws.join("wt-hooks")), "{:?}", sb.protected);
        assert_eq!(work_tree_top(&git), f.ws);
        assert_eq!(work_tree_top(&private), top);
        assert_eq!(work_tree_top(&bare), bare);
        // The same, as the file tools' and the profile's rules.
        refused_as_protected(&sb, &top.join("wt-hooks/post-merge"));
        refused_as_protected(&sb, &bare.join("rel/pre-receive"));
    }

    /// The husky case: the operator's Git runs `.husky/post-checkout`, which a command wrote. Whether the hook ran
    /// after `git checkout -b x`, with the command run under `mode`; `None` when Git cannot make the repository.
    fn husky_hook_ran(mode: SandboxMode) -> Option<bool> {
        let f = fx();
        let ws = &f.ws;
        let marker = f.root.join("husky-ran");
        let steps: [&[&str]; 3] =
            [&["init", "-q"], &["commit", "-q", "--allow-empty", "-m", "i"], &["config", "core.hooksPath", ".husky"]];
        if !git_runs() || !steps.iter().all(|a| git_ok(ws, a)) {
            return None;
        }
        let sb = build(&f, &cfg(mode), None);
        let plant = format!(
            "mkdir -p .husky && printf '#!/bin/sh\\ntouch {}\\n' > .husky/post-checkout && chmod +x .husky/post-checkout",
            s(&marker)
        );
        let (planted, _) = run(&sb, ws, &format!("{GIT_SH}{plant}"));
        assert_eq!(planted, mode == SandboxMode::None, "the hook was planted under the wrong mode ({mode:?})");
        git_ok(ws, &["checkout", "-q", "-b", "x"]);
        Some(marker.exists())
    }

    #[test]
    fn a_hook_a_command_writes_to_the_configured_hooks_directory_does_not_run() {
        let test = "a_hook_a_command_writes_to_the_configured_hooks_directory_does_not_run";
        if !available() {
            return;
        }
        match husky_hook_ran(SandboxMode::None) {
            None => return skipped(test, "git cannot make the fixture"),
            Some(false) => return skipped(test, "a hook in the configured directory does not run here"),
            Some(true) => {}
        }
        assert_eq!(husky_hook_ran(SandboxMode::Seatbelt), Some(false), "the planted hook ran");
    }

    #[test]
    fn construction_protects_the_hooks_directory_under_the_profile() {
        if !available() {
            return;
        }
        let f = fx();
        hand_repo(&f.ws.join(".git"), "[core]\nhooksPath = .husky\n[include]\npath = ../shared.inc\n");
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        for attempt in [
            "mkdir .husky",
            "mkdir -p .husky/_ && echo x > .husky/_/h",
            "echo x > shared.inc",
            "mkdir -p $TMPDIR/hk && mv $TMPDIR/hk .husky",
        ] {
            assert!(!run(&sb, &f.ws, attempt).0, "`{attempt}` succeeded under the profile");
        }
        let (ok, text) = run(&sb, &f.ws, "mkdir -p src && echo x > src/a && echo x > .husky-other");
        assert!(ok, "{text}");
    }

    /// The workspace is a repository (`git init`, one commit) and `lib/foo` a repository set up as a submodule
    /// *after* the sandbox was built, by the operator (outside it). False when Git cannot make that.
    fn slash_named_submodule_after_construction(f: &Fx, mode: SandboxMode) -> Option<Sandbox> {
        let steps: [&[&str]; 2] = [&["init", "-q"], &["commit", "-q", "--allow-empty", "-m", "i"]];
        if !git_runs() || !steps.iter().all(|a| git_ok(&f.ws, a)) {
            return None;
        }
        let src = f.root.join("libsrc");
        std::fs::create_dir_all(&src).expect("mkdir");
        let made = git_ok(&src, &["init", "-q"]) && git_ok(&src, &["commit", "-q", "--allow-empty", "-m", "s"]);
        let sb = build(f, &cfg(mode), None);
        let added = made && git_ok(&f.ws, &["submodule", "add", "-q", s(&src), "lib/foo"]);
        let added = added && git_ok(&f.ws, &["commit", "-q", "-m", "lib"]);
        (added && f.ws.join(".git/modules/lib/foo/HEAD").is_file()).then_some(sb)
    }

    #[test]
    fn a_submodule_set_up_after_construction_cannot_be_replaced_by_a_copy_with_a_config_of_its_own() {
        let test = "a_submodule_set_up_after_construction_cannot_be_replaced_by_a_copy_with_a_config_of_its_own";
        if !available() {
            return;
        }
        // The audit review's steps: move the repository away, copy it with `core.fsmonitor` set, move the copy in.
        let attack = |mode: SandboxMode| -> Option<(bool, bool)> {
            let f = fx();
            let marker = f.root.join("fsmonitor-ran");
            let sb = slash_named_submodule_after_construction(&f, mode)?;
            let script = format!(
                "mv .git/modules/lib/foo $TMPDIR/foo.orig && cp -R $TMPDIR/foo.orig $TMPDIR/evil && \
                 printf '[core]\\n\\tfsmonitor = touch {}\\n' >> $TMPDIR/evil/config && \
                 mv $TMPDIR/evil .git/modules/lib/foo",
                s(&marker)
            );
            let (done, _) = run(&sb, &f.ws, &format!("{GIT_SH}{script}"));
            git_ok(&f.ws, &["status"]);
            Some((done, marker.exists()))
        };
        match attack(SandboxMode::None) {
            None => return skipped(test, "git cannot make the fixture"),
            Some((true, true)) => {}
            Some(other) => return skipped(test, &format!("the same steps do not make Git run it here: {other:?}")),
        }
        assert_eq!(attack(SandboxMode::Seatbelt), Some((false, false)), "the copy was moved into place and ran");
        // Nothing can be made or removed in it either, and what Git itself writes there still can be.
        let f = fx();
        let Some(sb) = slash_named_submodule_after_construction(&f, SandboxMode::Seatbelt) else {
            return skipped(test, "git cannot make the fixture");
        };
        for attempt in [
            "mkdir .git/modules/lib/foo/x",
            "touch .git/modules/lib/foo/y",
            "mv .git/modules/lib/foo/objects $TMPDIR/o",
            "mv .git/modules/lib/foo $TMPDIR/o",
            "mv .git/modules/lib $TMPDIR/o",
            "rm -rf .git/modules/lib/foo/refs",
            "mkdir -p $TMPDIR/m && mv $TMPDIR/m .git/modules/lib/foo/m",
            "mkdir -p .git/modules/lib/bar/hooks",
        ] {
            assert!(!run(&sb, &f.ws, &format!("{GIT_SH}{attempt}")).0, "`{attempt}` succeeded under the profile");
        }
        for rel in
            ["modules/lib/foo/x", "modules/lib/foo/objects/ab", "modules/lib/foo/refs/heads/x", "modules/lib/bar"]
        {
            assert!(sb.check_write(&written(&f, rel)).is_err(), "{rel}");
        }
        // From the next session on it is found, and Git's writes there work.
        let next = build(&f, &cfg(SandboxMode::Seatbelt), None);
        assert!(next.git_modules.contains(&written(&f, "modules/lib/foo")), "{:?}", next.git_modules);
        let (ok, text) =
            run(&next, &f.ws, &format!("{GIT_SH}cd lib/foo && echo a > a && git add a && git commit -qm a"));
        assert!(ok, "{text}");
        assert!(next.check_write(&written(&f, "modules/lib/foo/objects/ab")).is_ok());
    }

    #[test]
    fn below_a_found_submodule_only_the_repositories_found_can_be_written_and_the_rest_of_the_git_directory_can() {
        let test = "below_a_found_submodule_only_the_repositories_found_can_be_written";
        let f = fx();
        if !git_runs() || !git_fixture(&f) {
            return skipped(test, "git cannot make the fixture");
        }
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let refused = [
            "modules/sub/modules/a/c",
            "modules/nest/modules/a/c",
            "modules/nest/modules/inner/modules/a/c",
            "modules/nest/modules/inner/modules",
            "modules/nest/modules/a",
            "modules/third/a/b",
            "modules/sub/worktrees/a/b",
        ];
        let accepted = [
            "modules/sub/objects/ab/cd",
            "modules/nest/modules/inner/objects/ab/cd",
            "modules/nest/objects/ab/cd",
            "refs/heads/modules/x/y",
            "objects/modules/x/y",
            "logs/refs/heads/modules/x/y",
        ];
        for rel in refused {
            assert!(sb.check_write(&written(&f, rel)).is_err(), "{rel} is refused by check_write");
        }
        for rel in accepted {
            assert!(sb.check_write(&written(&f, rel)).is_ok(), "{rel} is accepted by check_write");
        }
        if !available() {
            return;
        }
        // A branch named like a module in the workspace's own repository, and a commit in a nested submodule.
        for script in [
            "git branch modules/x/y && git branch -d modules/x/y",
            "cd nest/inner && echo b > b && git add b && git commit -qm b",
        ] {
            let (ok, text) = run(&sb, &f.ws, &format!("{GIT_SH}{script}"));
            assert!(ok, "`{script}` failed under the profile: {text}");
        }
        for rel in refused {
            let script = format!("mkdir -p .git/{rel}");
            assert!(!run(&sb, &f.ws, &script).0, "`{script}` succeeded under the profile");
        }
        for rel in accepted {
            let script = format!("mkdir -p .git/{rel}/new && touch .git/{rel}/new/f && rm -r .git/{rel}/new");
            let (ok, text) = run(&sb, &f.ws, &script);
            assert!(ok, "`{script}` failed under the profile: {text}");
        }
    }

    // ---- mounting and preferences ----

    /// Whether `dir` is a mount point now, as `mount` says (`hdiutil` may exit 0 and mount nothing).
    fn mounted(dir: &Path) -> bool {
        let out = Command::new("/sbin/mount").output().expect("mount");
        String::from_utf8_lossy(&out.stdout).contains(&format!(" on {} ", s(dir)))
    }

    /// Makes an image with `hdiutil makehybrid` and attaches it at a directory, in a command run under `mode`;
    /// whether it is mounted afterwards (and then detached). `None` when `hdiutil` cannot make the image.
    fn image_mounted(mode: SandboxMode) -> Option<bool> {
        let f = fx();
        let (img, mp) = (f.tmp.join("img"), f.tmp.join("mp"));
        std::fs::create_dir_all(&img).expect("mkdir");
        std::fs::create_dir_all(&mp).expect("mkdir");
        std::fs::write(img.join("f"), "x").expect("write");
        let sb = build(&f, &cfg(mode), None);
        let script = format!(
            "hdiutil makehybrid -quiet -iso -joliet -hfs -o $TMPDIR/h.iso {} && \
             hdiutil attach -nobrowse -mountpoint {} $TMPDIR/h.iso",
            s(&img),
            s(&mp)
        );
        run(&sb, &f.ws, &script);
        if !f.tmp.join("h.iso").is_file() {
            return None;
        }
        let was = mounted(&mp);
        if was {
            let _ = Command::new("hdiutil").args(["detach", "-force", s(&mp)]).output();
        }
        Some(was)
    }

    #[test]
    fn a_disk_image_cannot_be_mounted_by_a_command() {
        let test = "a_disk_image_cannot_be_mounted_by_a_command";
        if !available() || !Path::new("/usr/bin/hdiutil").exists() {
            return;
        }
        match image_mounted(SandboxMode::None) {
            None => return skipped(test, "hdiutil cannot make the image here"),
            Some(false) => return skipped(test, "an image is not mounted here even outside the sandbox"),
            Some(true) => {}
        }
        // The image is made under the profile too (`image_mounted` is `None` when it is not), so the refusal is
        // the attach's.
        assert_eq!(image_mounted(SandboxMode::Seatbelt), Some(false), "an image was mounted under the profile");
    }

    #[test]
    fn a_preference_domain_cannot_be_written_by_a_command_while_preferences_can_be_read() {
        let test = "a_preference_domain_cannot_be_written_by_a_command_while_preferences_can_be_read";
        if !available() || !Path::new("/usr/bin/defaults").exists() {
            return;
        }
        let f = fx();
        let domain = format!("com.loom-test.{}", unique("p"));
        let read_back = || {
            Command::new("/usr/bin/defaults").args(["read", &domain, "k"]).output().is_ok_and(|o| o.status.success())
        };
        let write = |mode: SandboxMode| {
            let sb = build(&f, &cfg(mode), None);
            run(&sb, &f.ws, &format!("defaults write {domain} k v"))
        };
        let control = write(SandboxMode::None).0 && read_back();
        let _ = Command::new("/usr/bin/defaults").args(["delete", &domain]).output();
        if !control {
            return skipped(test, "defaults does not write a domain here even outside the sandbox");
        }
        let (_, text) = write(SandboxMode::Seatbelt);
        let stored = read_back();
        let _ = Command::new("/usr/bin/defaults").args(["delete", &domain]).output();
        assert!(!stored, "a command wrote a preference under the profile: {text}");
        let sb = build(&f, &cfg(SandboxMode::Seatbelt), None);
        let (ok, text) = run(&sb, &f.ws, "defaults read -g > /dev/null");
        assert!(ok, "reading preferences must work: {text}");
    }

    // ---- network ----

    #[test]
    fn the_profile_denies_the_daemon_port_and_the_certificate_services_exactly_when_told_to() {
        let f = fx();
        let base = SandboxCfg {
            loopback_ports: vec![9000],
            unix_sockets: vec![format!("{}/run.sock", s(&f.root))],
            protect_credentials: false,
            ..cfg(SandboxMode::Seatbelt)
        };
        let plain = build(&f, &base, None).profile().expect("profile");
        let port = "(deny network-outbound (remote ip \"*:7777\"))\n";
        let services = FETCH_SERVICES;
        let bind = "(allow network-bind (local ip \"localhost:*\"))\n";
        let tail = format!("{bind}(allow network-inbound (local ip \"localhost:*\"))\n");
        assert!(plain.ends_with(&tail) && !plain.contains("*:7777") && !plain.contains("trustd"), "{plain}");
        assert!(plain.contains(MOUNT_LINES), "{plain}");
        let only_port = SandboxCfg { daemon_port: Some(7777), ..base.clone() };
        let only_port = build(&f, &only_port, None).profile().expect("profile");
        assert_eq!(only_port, plain.replace(bind, &format!("{port}{bind}")));
        let only_services = SandboxCfg { network_deny_all: true, ..base.clone() };
        let only_services = build(&f, &only_services, None).profile().expect("profile");
        assert_eq!(only_services, format!("{plain}{services}"));
        let both = SandboxCfg { daemon_port: Some(7777), network_deny_all: true, ..base };
        let both = build(&f, &both, None).profile().expect("profile");
        // After the allows (the last is the unix socket), before the bind and inbound allows; the services last.
        let socket = both.find("(allow network-outbound (remote unix-socket").expect("socket");
        let (deny, bind_at) = (both.find(port).expect("port deny"), both.find(bind).expect("bind"));
        assert!(socket < deny && deny < bind_at, "{both}");
        assert!(both.ends_with(&format!("{tail}{services}")), "{both}");
        assert_eq!(both, plain.replace(bind, &format!("{port}{bind}")) + services);
        // `loopback_all` is written first and the deny still follows it; with a daemon port the allow is written
        // for TCP and UDP (a deny of one port after an allow written `ip` is not reliable).
        let all = SandboxCfg { loopback_all: true, daemon_port: Some(7777), ..cfg(SandboxMode::Seatbelt) };
        let all = build(&f, &all, None).profile().expect("profile");
        let wildcard = "(allow network-outbound (remote tcp \"localhost:*\") (remote udp \"localhost:*\"))\n";
        assert!(all.find(wildcard).expect("allow") < all.find(port).expect("deny"), "{all}");
        assert!(!all.contains("(remote ip \"localhost:*\")"), "{all}");
        let no_port = SandboxCfg { loopback_all: true, ..cfg(SandboxMode::Seatbelt) };
        let no_port = build(&f, &no_port, None).profile().expect("profile");
        assert!(no_port.contains("(allow network-outbound (remote ip \"localhost:*\"))\n"), "{no_port}");
        // Bubblewrap has no profile; mode none neither.
        assert!(build(&f, &SandboxCfg { daemon_port: Some(1), ..cfg(SandboxMode::None) }, None).profile().is_none());
    }

    #[test]
    fn the_daemon_port_is_refused_at_every_address_while_other_loopback_ports_connect() {
        if !available() {
            return;
        }
        let test = "the_daemon_port_is_refused_at_every_address_while_other_loopback_ports_connect";
        let f = fx();
        // Several ports, one after the other: a deny of one port that holds for some ports only was seen.
        for _ in 0..10 {
            let daemon = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = daemon.local_addr().expect("addr").port();
            let other = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let other_port = other.local_addr().expect("addr").port();
            // The same port on the other addresses of this host, where they can be had.
            let v6 = std::net::TcpListener::bind(("::1", port)).ok();
            let own = host_address().and_then(|ip| std::net::TcpListener::bind((ip, port)).ok().map(|l| (ip, l)));
            let mut hosts = vec!["127.0.0.1".to_string()];
            hosts.extend(v6.as_ref().map(|_| "::1".to_string()));
            hosts.extend(own.as_ref().map(|(ip, _)| ip.to_string()));
            let none = build(&f, &cfg(SandboxMode::None), None);
            hosts.retain(|h| {
                let reachable = connects(&none, &f.ws, h, port);
                if !reachable {
                    skipped(test, &format!("{h}:{port} cannot be reached even outside the sandbox"));
                }
                reachable
            });
            assert!(hosts.iter().any(|h| h == "127.0.0.1"), "loopback must be reachable outside the sandbox");
            let variants = [
                SandboxCfg { loopback_all: true, daemon_port: Some(port), ..cfg(SandboxMode::Seatbelt) },
                SandboxCfg {
                    loopback_ports: vec![port, other_port],
                    daemon_port: Some(port),
                    ..cfg(SandboxMode::Seatbelt)
                },
            ];
            for c in &variants {
                let sb = build(&f, c, None);
                for h in &hosts {
                    assert!(!connects(&sb, &f.ws, h, port), "{h}:{port} connected under {c:?}");
                }
                assert!(
                    connects(&sb, &f.ws, "127.0.0.1", other_port),
                    "another loopback port must still connect: {c:?}"
                );
                // As a proxy port too: the allow of the proxy does not outrank the deny.
                assert!(!connects(
                    &Sandbox::new(c, &f.ws, &f.tmp, &f.home, Some(port)).expect("sandbox"),
                    &f.ws,
                    "127.0.0.1",
                    port
                ));
            }
            // Without the daemon port the very same configuration connects, so the deny is what refuses it.
            for c in &variants {
                let open = SandboxCfg { daemon_port: None, ..c.clone() };
                let sb = build(&f, &open, None);
                for h in hosts.iter().filter(|h| h.as_str() == "127.0.0.1" || h.as_str() == "::1") {
                    assert!(connects(&sb, &f.ws, h, port), "{h}:{port} must connect without the deny: {open:?}");
                }
            }
            drop((daemon, other, v6, own));
        }
    }

    /// A certificate for `leaf.example` whose `caIssuers` names `url`, made with the system's `openssl`.
    fn aia_certificate(dir: &Path, url: &str) -> Option<PathBuf> {
        std::fs::create_dir_all(dir).ok()?;
        let extensions = format!(
            "[v3]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n\
             subjectAltName=DNS:leaf.example\nauthorityInfoAccess=caIssuers;URI:{url}\n"
        );
        std::fs::write(dir.join("ext.cnf"), extensions).ok()?;
        let openssl = |args: &[&str]| {
            Command::new("/usr/bin/openssl").args(args).current_dir(dir).output().is_ok_and(|o| o.status.success())
        };
        let made = openssl(&[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-subj",
            "/CN=loom-test-ca",
            "-days",
            "2",
        ]) && openssl(&[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
            "-subj",
            "/CN=leaf.example",
        ]) && openssl(&[
            "x509",
            "-req",
            "-in",
            "leaf.csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            "ext.cnf",
            "-extensions",
            "v3",
            "-out",
            "leaf.pem",
        ]);
        made.then(|| dir.join("leaf.pem"))
    }

    #[test]
    fn certificate_evaluation_fetches_no_url_for_a_command_under_deny_all() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        let test = "certificate_evaluation_fetches_no_url_for_a_command_under_deny_all";
        if !available() || !Path::new("/usr/bin/security").exists() || !Path::new("/usr/bin/openssl").exists() {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (requests, stop) = (requests.clone(), stop.clone());
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                while !stop.load(Ordering::SeqCst) {
                    let Ok((mut conn, _)) = listener.accept() else {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    };
                    let _ = conn.set_nonblocking(false);
                    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let mut line = String::new();
                    if BufReader::new(&conn).read_line(&mut line).is_ok() {
                        if let Ok(mut seen) = requests.lock() {
                            seen.push(line.trim().to_string());
                        }
                    }
                    let _ = conn.write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                }
            })
        };
        let fetched = |path: &str, wait: u64| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);
            loop {
                if requests.lock().is_ok_and(|seen| seen.iter().any(|l| l.contains(path))) {
                    return true;
                }
                if std::time::Instant::now() > deadline {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        };
        let f = fx();
        let stamp = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos())
        );
        let verify = |sb: &Sandbox, name: &str| -> Option<(String, bool)> {
            let path = format!("/loom-aia-{name}-{stamp}.cer");
            let leaf =
                aia_certificate(&sb.tmp_dir.join(format!("cert-{name}")), &format!("http://127.0.0.1:{port}{path}"))?;
            let script = format!("/usr/bin/security verify-cert -c {} -p ssl -s leaf.example", s(&leaf));
            Some((path, run(sb, &f.ws, &script).0))
        };
        let c = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        (|| {
            // Control: without the setting the service fetches the URL the certificate names.
            let Some((path, _)) = verify(&build(&f, &c, None), "control") else {
                return skipped(test, "openssl cannot make the certificates");
            };
            if !fetched(&path, 10) {
                return skipped(test, "this host does not fetch the issuer of a certificate for a sandboxed command");
            }
            let denied = SandboxCfg { network_deny_all: true, ..c.clone() };
            let Some((path, _)) = verify(&build(&f, &denied, None), "denied") else {
                return skipped(test, "openssl cannot make the certificates");
            };
            assert!(!fetched(&path, 6), "the URL a certificate names was fetched for a command under deny_all");
        })();
        stop.store(true, Ordering::SeqCst);
        let _ = thread.join();
    }

    #[test]
    fn a_background_url_session_fetches_nothing_for_a_command_under_deny_all() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};
        let test = "a_background_url_session_fetches_nothing_for_a_command_under_deny_all";
        if !available() || !Path::new("/usr/bin/osascript").exists() {
            return;
        }
        // The profile allows no loopback port, so a fetch that arrives here was made outside the sandbox.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (requests, stop) = (requests.clone(), stop.clone());
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                while !stop.load(Ordering::SeqCst) {
                    let Ok((mut conn, _)) = listener.accept() else {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        continue;
                    };
                    let _ = conn.set_nonblocking(false);
                    let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let mut line = String::new();
                    if BufReader::new(&conn).read_line(&mut line).is_ok() {
                        if let Ok(mut seen) = requests.lock() {
                            seen.push(line.trim().to_string());
                        }
                    }
                    let _ = conn.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi");
                }
            })
        };
        let fetched = |path: &str, wait: u64| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait);
            loop {
                if requests.lock().is_ok_and(|seen| seen.iter().any(|l| l.contains(path))) {
                    return true;
                }
                if std::time::Instant::now() > deadline {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        };
        let f = fx();
        // A background session made and started from JavaScript for Automation, kept alive for a few seconds.
        let start = |c: &SandboxCfg, name: &str| -> String {
            let id = unique(&format!("loom-session-{name}"));
            let path = format!("/{id}");
            let js = format!(
                "ObjC.import(\"Foundation\");\n\
                 var cfg = $.NSClassFromString(\"NSURLSessionConfiguration\").backgroundSessionConfigurationWithIdentifier(\"{id}\");\n\
                 var session = $.NSClassFromString(\"NSURLSession\").sessionWithConfiguration(cfg);\n\
                 var task = session.downloadTaskWithURL($.NSURL.URLWithString(\"http://127.0.0.1:{port}{path}\"));\n\
                 task.resume;\n\
                 $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(6));\n"
            );
            std::fs::write(f.tmp.join(format!("{name}.js")), js).expect("write");
            run(&build(&f, c, None), &f.ws, &format!("osascript -l JavaScript $TMPDIR/{name}.js"));
            path
        };
        let c = SandboxCfg { protect_credentials: false, ..cfg(SandboxMode::Seatbelt) };
        (|| {
            // Control: without the setting the session service fetches the URL for the command.
            let path = start(&c, "control");
            if !fetched(&path, 10) {
                return skipped(test, "this host does not fetch a background session's URL for a sandboxed command");
            }
            let denied = SandboxCfg { network_deny_all: true, ..c.clone() };
            assert!(build(&f, &denied, None).profile().expect("profile").contains(FETCH_SERVICES));
            let path = start(&denied, "denied");
            assert!(!fetched(&path, 8), "a background URL session fetched a URL for a command under deny_all");
        })();
        stop.store(true, Ordering::SeqCst);
        let _ = thread.join();
    }

    #[test]
    fn describe_states_the_git_rules_and_the_certificate_services() {
        let f = fx();
        let seatbelt = build(&f, &cfg(SandboxMode::Seatbelt), None).describe();
        for needle in [
            "No Git repository can be made where commands write",
            "no Git configuration, hooks, worktree or submodule repository",
            "`git worktree add`",
            "`git submodule update --init`",
            "`git clone --bare <url> <dir>.git`",
            "--git-dir=<dir>.git --work-tree=<dir>",
            "`git submodule update` (any form) is the operator's",
            "upstream tracking",
            "cannot be recorded",
            "dependencies from Git URLs (pip, npm, cargo, uv) cannot be installed (an archive URL can)",
            "disk images cannot be mounted (extract them instead)",
            "preferences cannot be written (`defaults write`)",
        ] {
            assert!(seatbelt.contains(needle), "{needle}: {seatbelt}");
        }
        assert!(!seatbelt.contains("codesign") && !seatbelt.contains("WebKit"), "{seatbelt}");
        let deny_all = SandboxCfg { network_deny_all: true, ..cfg(SandboxMode::Seatbelt) };
        let d = build(&f, &deny_all, None).describe();
        assert!(
            d.contains("Swift and Go programs, `security`, `codesign --verify`") && d.contains("curl and Python"),
            "{d}"
        );
        assert!(d.contains("WebKit-based tools and background URL sessions fail"), "{d}");
        assert_eq!(d, build(&f, &deny_all, None).describe());
        // The Git sentence is the seatbelt description's; mode none does not confine commands.
        let none = build(&f, &SandboxCfg { network_deny_all: true, ..cfg(SandboxMode::None) }, None).describe();
        assert!(!none.contains("No Git repository") && !none.contains("codesign"), "{none}");
        assert!(!none.contains("disk images") && !none.contains("WebKit") && !none.contains("defaults"), "{none}");
    }
}
