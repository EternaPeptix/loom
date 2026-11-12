# Security

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository: open the repository's Security tab
and choose "Report a vulnerability" (a security advisory). Please do not open a public issue for
something exploitable. Say which version or commit you ran, what you did, and what you saw. If
private reporting is not enabled on the repository you are looking at, open an issue that asks for a
private channel and contains no details.

## What loom is built to resist

loom is a tool for **one operator** who runs it on their own machine against a model server they
trust with their prompts. It assumes the operator is not an adversary and the other local accounts are
not trusted. The adversary it is built against is the **model and the content the model reads**: tool
output, files, web pages and other agents' reports can all contain instructions, and the model can make
mistakes or be talked into harmful commands. loom limits what a command the model runs can do, keeps
the records the model cannot edit, and does not let model text pass as the operator's or the
harness's.

### Files on disk

- The loom home and every directory the harness creates under it are mode 0700, and every file it creates
  there (session logs, status and meta files, blobs and their indexes, job output, the egress audit file,
  journals, the daemon file, the daemon log) is mode 0600, set at creation. At start the daemon tightens the
  home, `keys/`, `sessions/`, `missions/`, `blobs/` and `logs/` to 0700 if an earlier version or the operator
  left them looser, so other local accounts can no longer open anything below them. A descriptor another
  account opened before that keeps working (a `tail -f` on an old session log goes on reading what is appended),
  and files written by earlier versions are not rewritten: they keep their mode behind those directories, and
  `chmod -R go-rwx ~/.loom` tightens them as well.

### The daemon and its API

- The daemon listens on a loopback address only. It refuses to start on a name that resolves to a
  non-loopback address.
- Every API request must carry the API token as `Authorization: Bearer <token>`, or a web-session
  secret obtained with it. There are no cookies. The token is 32 random bytes in `~/.loom/token`
  (mode 0600), created atomically. Anyone who can read that file as your user can drive the daemon,
  so the protection is that of your account.
- Requests must name the daemon's own address in `Host` and, for anything that changes state, an
  allowed `Origin`. This stops a web page you visit from reaching the API through your browser.
- The web page is opened with `loom open`, which trades the token for a single-use login code (valid
  60 seconds) and then a web-session secret kept in memory by the daemon and in the tab's session
  storage. The token is never put on a command line or in a URL.
- Before the `loom` command or the desktop app sends the token to a listener, the listener must prove it
  holds the token (an HMAC answer on `/healthz`). A different program on the daemon's port cannot
  collect the token this way. The exception is the global flag `--unverified-daemon`: with it, the
  `loom` command sends the token to a listener that gave no proof (it prints a warning). It exists only
  to stop a daemon from a version that cannot give the proof; do not use it otherwise.
- To use a daemon on another machine, forward its port over SSH. Do not change the bind address to a
  non-loopback one; the daemon will not accept it.

### What a command run by the model can and cannot do

On macOS, with `[sandbox] mode = "seatbelt"` (the default), commands run under `sandbox-exec`:

- **Writes** are allowed only in the session's workspace, the session's temporary directory, the
  system temporary locations (`/private/tmp` and `/private/var/folders`), any `extra_writable`
  directories, and the device files `/dev/null`, `/dev/tty` and `/dev/dtracehelper`. `~/.loom`
  (including the token, keys, logs and every session record), `<workspace>/.loom` and your
  `protected_paths` are never writable, with one exception: the session's temporary directory lies in
  `~/.loom` (`sessions/<id>/tmp`), and everything inside it is writable, though the directory entry
  itself cannot be removed, renamed or replaced. A directory that holds a protected path cannot be
  renamed or removed.
- **Credential stores are unreadable and unwritable** by default (`protect_credentials = true`): `~/.ssh`,
  `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.config/gcloud`, `~/.azure`, `~/.kube`,
  `~/.docker/config.json`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, cargo and git credential files, password
  stores and password-manager data, cloud, registry, model-hub, AI-tool and database client credentials
  (`~/.cache/huggingface`, `~/.claude.json`, `~/.pgpass`, `~/.vault-token`, `~/.m2/settings.xml`,
  `~/.config/rclone`, and more), wallets, the macOS Keychains and Cookies folders, Mail, Messages,
  Telegram, Group Containers and the Chrome, Chromium, Brave, Edge, Arc, Vivaldi, Opera, Firefox and
  Safari profiles. So are
  the loom token and keys and your `unreadable_paths`. A listed directory that is or contains the
  workspace is skipped.
- **The network** is closed except for loopback connections to the egress proxy (and any ports or sockets
  you list). The proxy applies `[network]`: by default (`deny_all`) it forwards nothing. It resolves
  names itself, refuses private, loopback and link-local addresses (including IPv4 addresses hidden in
  IPv6 forms) unless you list them, applies the deny list to the resolved address, and records every
  decision in a hash-chained audit file. Commands that listen on loopback can be reached by other
  local processes.
- **Scope is the operator's.** The agent can ask for hosts with `request_scope`, which opens an inbox
  item and changes nothing. Hosts are granted only by the operator, per session, with a record in the
  ledger; a grant dies with the session. `loom release` records that the operator closed a mission
  without the goal established, with a reason, and it is shown as that, not as finished.
- **No LaunchServices opens, Apple Events or launchd jobs**, so a command cannot start a program
  outside the sandbox that way.
- **Signals** can reach only processes inside the sandbox.
- Environment variables whose names look like secrets are not passed to commands.

Commands run with your user id. The sandbox is the only barrier between them and everything your user
can read.

### Records

Sessions are append-only logs in which each record names the hash of the previous one, and mission
state is a journal sealed with an HMAC key kept outside the workspace. These make tampering and
truncation detectable, not impossible: see the limits below.

## Known limits

These are the places where loom does less than the text above might suggest.

- **Reads are allowed by default.** The sandbox denies reads of the credential list, the loom token
  and keys, and `unreadable_paths`. Everything else your user can read, a command can read: your
  documents, shell history, other projects, source trees, tokens kept in files that are not on the
  list, and anything under a directory that is or contains the workspace. Set the workspace to the
  smallest directory that works, and add paths to `unreadable_paths`.
- **The seatbelt profile starts from allow-everything and subtracts.** It denies writes, the listed
  reads, the network and the launch routes above. What it does not name is allowed: running programs,
  reading system information, local inter-process communication. A new macOS facility is open until the
  profile is extended. `sandbox-exec` is deprecated by Apple, though it still works. The denials of
  LaunchServices, Apple Events and launchd jobs were checked to compile into the profile but have
  not been exercised from a graphical login session.
- **The file tools run in the daemon, outside the OS sandbox.** They apply the same rules themselves.
  `read`, `write` and `edit` check the real path of what they actually opened, not a path checked
  earlier: a file is opened and then judged by the path the system gives for the open file, and a write
  opens the directory, judges its real path with the file name, and creates and renames the file
  relative to that open directory. A command that swaps a directory for a link during such a call gets
  no content and no file out of it; it can still learn whether a path there exists and what kind of
  file it is. `glob` and `grep` check each path and then open it by name, so a command that swaps a
  link in between can in principle make them list or read through it. They also judge a path in the
  form it was given, with links resolved: macOS shows `/Users`, `/private` and the other folders of the
  data volume under `/System/Volumes/Data` too, and given a path in that form, which the rules are not
  written in, `glob` and `grep` list and read what the rules refuse; `read`, `write` and `edit` judge
  the name the system gives for the open file, which is the usual one. All of them refuse to touch
  anything that is not a regular file.
- **Without macOS there is no sandbox.** On other systems the daemon starts only with
  `[sandbox] mode = "none"`, and then commands are unconfined. The file tools still refuse the protected
  and credential paths, and the network proxy still exists, but a command can ignore it. Do not run
  loom in that mode on a machine or account you care about.
- **Environment scrubbing is by name and by URL.** Names with a secret word, session, auth, pass, jwt,
  webhook or private parts, every model profile's `api_key_env`, and values that are URLs with a
  password in them are withheld. A secret in a variable called something else, in another form, is
  passed through. `env_pass` passes more.
- **A process that leaves its command's process group is not tracked.** After `setsid`, `daemon()`,
  `redis-server --daemonize yes` or `tmux new -d`, `job_kill`, stop, the end of the session and daemon
  shutdown do not stop it, although it stays under the seatbelt profile.
- **The configured network policy is per daemon**, and is read at start. In `allowlist` mode a
  listed host can be used by every session. Data can be sent to an allowed host. On top of it the
  operator can grant a session more hosts while it runs (`loom scope`): a grant is per session,
  recorded in the mission's ledger, and ends with the session. The agent can ask (`request_scope`) but
  cannot grant; only an operator request reaches the grant, and the model's tools cannot make one.
- **A network-specific NAT64 prefix is an ordinary IPv6 prefix to the proxy.** The proxy looks through
  the well-known NAT64 prefix `64:ff9b::/96` (and `64:ff9b:1::/96`) to the IPv4 address it carries, but
  not through a prefix your network chose for itself. Listing such a prefix in `allow_private` admits
  every IPv4 address behind it, private ones included, and IPv4 `deny` entries do not cover addresses
  inside it.
- **A missing holder directory can still be moved into place.** A writable directory that holds a
  protected or unreadable path cannot be removed, renamed or made as a link. If it does not exist yet,
  a command can still create it by moving another directory into its place, and a link already inside
  that moved directory then decides where a file written below it later, by something outside the
  sandbox, lands.
- **A command can talk to anything on loopback that you allow** (`loopback_ports`, `loopback_all`,
  `unix_sockets`), including services that run as you.
- **Tamper evidence has gaps.** Deleting a session's records together with their directory, deleting
  `journal.head` together with the last entries of its mission journal, deleting a mission journal and
  its `journal.head` together, or restoring an older matching pair, cannot be detected. A process
  running as you outside the sandbox can read the journal key and forge entries.
  The audit file for requests that name no known session (`logs/net-unattributed.jsonl`) has no reader
  in the API yet.
- **The verifier is another model.** A `finish` that passes the verifier has been checked against
  stored output, with its quotes compared byte for byte, but the verdict is still a model's judgement.
- **The web UI trusts the daemon.** It is served with a strict content-security policy and no inline
  script, but a bug in it would be a bug in a page that holds a bearer secret.
- **The operator's machine and account are trusted.** Another process of your user, or anyone who can
  read `~/.loom/token`, has the daemon's full power. Disk encryption, account separation and keeping the
  token file private are your job.

## Telemetry

loom makes no network requests of its own. Model requests go to the server in your configuration, and
tool traffic goes through the egress proxy under your `[network]` policy.
