#!/usr/bin/env python3
"""Import DeepSeek Harness (DSH) v4 sessions into loom as read-only archive sessions.

A DSH session and a loom session have different, incompatible models, so loom cannot *resume* a DSH
session. What this does is faithfully convert the DSH transcript into a loom event log that is marked
ended, so the conversation is present, browsable and searchable inside loom (CLI and web UI) — history,
not a live session.

Usage:
    import-dsh.py --dsh ~/.dsh/sessions --loom ~/.loom [--workspace SUBSTR] [--limit N] [--model NAME]
                  [--dry-run]

Requires the `zstd` command on PATH (DSH session files are zstd-compressed; install it with
`brew install zstd`). Python 3 standard library only.

It writes, per DSH session, a loom session dir under <loom>/sessions/s-dsh<id>/ with log.jsonl
(hash-chained), meta.json and status.json. Directories are created 0700 and files 0600; every file is
written to a temporary file next to its final name and renamed into place, so a crash never leaves a
half-written file. Re-running rewrites the same ids (idempotent) and keeps the `archived` flag an
existing meta.json already has. One failing session is reported and the others still import; the
summary line counts them and the exit code is 1 if any failed. A session whose decompressed size
exceeds 512 MiB is refused. Restart the daemon afterwards so it rescans the sessions directory.
"""
import argparse, hashlib, json, os, sys, glob, subprocess, datetime, shutil, tempfile

ZERO = "0" * 64
# Largest decompressed session accepted; a bigger one is almost certainly not a normal transcript.
MAX_DECOMPRESSED = 512 * 1024 * 1024
# The log schema number this importer writes (crates/loom-core/src/event.rs, SCHEMA). A log with a
# higher number is read-only for the daemon, so this must not run ahead of it.
SCHEMA = 1


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def text_of(content) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    out = []
    for b in content:
        if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str):
            out.append(b["text"])
    return "".join(out)


def tool_calls_of(content):
    calls = []
    if isinstance(content, list):
        for b in content:
            if isinstance(b, dict) and b.get("type") in ("tool-call", "tool_use", "tool_call"):
                calls.append({
                    "call_id": str(b.get("id") or b.get("callId") or ""),
                    "name": str(b.get("name") or ""),
                    "arguments": b.get("arguments") if isinstance(b.get("arguments"), str) else json.dumps(b.get("arguments") or b.get("input") or {}),
                    "complete": True,
                })
    return calls


def klass(name: str) -> str:
    n = (name or "").lower()
    if n in ("read", "out_read", "web_fetch", "cve_lookup", "advisory_lookup"):
        return "read"
    if n in ("glob", "grep", "out_grep", "ls", "list", "cve_search", "search"):
        return "nav"
    if n in ("write", "edit", "apply_patch", "create", "multiedit"):
        return "write"
    return "exec"


def to_ms(v, default=0):
    if isinstance(v, (int, float)):
        return max(0, int(v if v > 1e11 else v * 1000))  # seconds -> ms heuristic; never negative
    if isinstance(v, str):
        try:
            s = v.replace("Z", "+00:00")
            return max(0, int(datetime.datetime.fromisoformat(s).timestamp() * 1000))
        except Exception:
            return default
    return default


def parse_line(raw: bytes):
    line = raw.decode("utf-8", "replace").strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except Exception:
        return None


def decompress(path: str):
    """Yield the JSON objects of a zstd-compressed JSONL file as a stream, refusing more than
    MAX_DECOMPRESSED bytes of decompressed output."""
    with tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen(["zstd", "-dc", "--", path], stdout=subprocess.PIPE, stderr=err)
        except FileNotFoundError:
            raise RuntimeError("the `zstd` command is not installed; install it (for example `brew install zstd`) and run again")
        total = 0
        too_big = False
        try:
            pending = b""
            while True:
                chunk = proc.stdout.readline(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DECOMPRESSED:
                    too_big = True
                    break
                pending += chunk
                if pending.endswith(b"\n"):
                    obj, pending = parse_line(pending), b""
                    if obj is not None:
                        yield obj
            if not too_big and pending:
                obj = parse_line(pending)
                if obj is not None:
                    yield obj
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.stdout.close()
            rc = proc.wait()
        if too_big:
            raise RuntimeError(
                f"the session is larger than {MAX_DECOMPRESSED // (1024 * 1024)} MiB decompressed, "
                "which is more than this importer accepts; it was not imported"
            )
        if rc != 0:
            err.seek(0)
            raise RuntimeError("zstd could not decompress the file: " + err.read().decode("utf-8", "replace").strip()[:200])


def convert(dsh_path: str, uuid: str):
    """Return (records, header) where records are loom event dicts WITHOUT seq/prev/ts chaining yet."""
    header = None
    body = []
    call_names = {}
    for d in decompress(dsh_path):
        t = d.get("type")
        if header is None and t == "session":
            header = d
            continue
        data = d.get("data") or {}
        ts = to_ms(d.get("time"), 0)
        if t == "user/message":
            txt = text_of(data.get("content"))
            if txt.strip():
                body.append(("user", ts, {"kind": "user_message", "text": txt}))
        elif t == "assistant/message":
            msg = data.get("message") or {}
            content = msg.get("content")
            txt = text_of(content)
            calls = tool_calls_of(content)
            for c in calls:
                call_names[c["call_id"]] = c["name"]
            if txt.strip() or calls:
                body.append(("model", ts, {
                    "kind": "model_response",
                    "req_id": f"dsh-{data.get('turn','?')}-{data.get('step','?')}",
                    "text": txt,
                    "tool_calls": calls,
                    "finish": "tool_calls" if calls else "stop",
                }))
        elif t == "tool/result":
            msg = data.get("message") or {}
            cid = str(msg.get("toolCallId") or (msg.get("source") or {}).get("callId") or "")
            txt = text_of(msg.get("content"))
            name = call_names.get(cid, "tool")
            body.append(("tool", ts, {
                "kind": "tool_result",
                "call_id": cid,
                "name": name,
                "status": "ok",
                "text": txt,
                "class": klass(name),
            }))
        # skipped: tool/call (already in assistant message), step/*, turn/*, request/header,
        # job/*, agent/inbox/spliced — bookkeeping that does not render as conversation.
    return body, header


def build_log(body, header, sid, mission, workspace, model, created_ms, title):
    """Chain the records into loom log bytes: one compact JSON object per line, each `prev` the SHA-256
    of the previous line's bytes without its newline."""
    start_event = {
        "kind": "session_start",
        "session": sid,
        "mission": mission,
        "parent": None,
        "workspace": workspace,
        "pack": "core",
        "role": "chat",
        "termination": "free",
        "model": {"profile": "imported", "model": model, "context_window": 1048576},
        "reasoning_replay": "none",
        "system_prompt": (
            "Read-only archive of a DeepSeek Harness (DSH) session imported into loom. "
            f"Original DSH session {header.get('id') if header else '?'}, workspace {workspace}."
        ),
        "tools": [],
        "budget": {},
        "unattended": False,
        "title": title,
        "schema": SCHEMA,
    }
    records = [("harness", created_ms, start_event)]
    records += body
    records.append(("harness", records[-1][1] if records else created_ms, {
        "kind": "session_end", "outcome": "done",
        "detail": f"imported from DSH session {header.get('id') if header else '?'} ({len(body)} records)",
    }))

    lines = []
    prev = ZERO
    for seq, (author, ts, ev) in enumerate(records):
        rec = {"seq": seq, "ts_ms": int(ts or created_ms), "author": author, "prev": prev}
        rec.update(ev)
        # The bytes hashed are the bytes written: encode once, and write them in binary mode.
        line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "replace")
        prev = sha256_hex(line)
        lines.append(line)
    n_steps = sum(1 for a, _, e in records if e.get("kind") == "model_response")
    return b"\n".join(lines) + b"\n", n_steps


def mkdir_private(path: str):
    """Create `path` and any missing parents with mode 0700."""
    if os.path.isdir(path):
        return
    parent = os.path.dirname(path)
    if parent and parent != path:
        mkdir_private(parent)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass


def write_atomic(path: str, data: bytes):
    """Write `data` to a 0600 temporary file in the same directory, then rename it over `path`."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".import-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def existing_archived(meta_path: str) -> bool:
    """The `archived` flag of an already imported session, so a re-run does not undo an archive."""
    try:
        with open(meta_path, "rb") as f:
            return json.load(f).get("archived") is True
    except Exception:
        return False


def import_one(p, a, counts):
    """Convert and write one session. Raises on any failure; the caller reports it and goes on."""
    uuid = os.path.basename(os.path.dirname(p)).replace("session-", "")
    sid = "s-dsh" + uuid.replace("-", "")[:13]
    mission = "m-dsh" + uuid.replace("-", "")[:13]
    body, header = convert(p, uuid)
    if not body:
        print(f"  skip {uuid[:8]}: no conversation records", file=sys.stderr)
        counts["skipped"] += 1
        return
    header = header or {}
    workspace = header.get("cwd") or "unknown"
    created_ms = to_ms(header.get("createdAt"), body[0][1] or 0)
    first_user = next((e["text"] for _, _, e in body if e.get("kind") == "user_message"), "")
    title = "[DSH] " + " ".join(first_user.split())[:80]
    log, n_steps = build_log(body, header, sid, mission, workspace, a.model, created_ms, title)

    if a.dry_run:
        print(f"  would import {uuid[:8]} -> {sid} ({len(body)} recs, {n_steps} steps) ws={workspace}", file=sys.stderr)
        counts["done"] += 1
        return

    sdir = os.path.join(a.loom, "sessions", sid)
    mkdir_private(os.path.join(sdir, "tmp"))
    meta_path = os.path.join(sdir, "meta.json")
    meta = {
        "id": sid, "mission": mission, "parent": None, "workspace": workspace,
        "pack": "core", "role": "chat", "profile": "imported", "model": a.model,
        "context_window": 1048576, "title": title, "created_ms": created_ms,
        "mode": None, "awaited": False, "unattended": False, "archived": existing_archived(meta_path),
    }
    status = {
        "phase": "ended", "step": n_steps, "last_end": "finished", "outcome": "done",
        "fork_point": None, "epoch": 0, "prompt_tokens": 0, "cached_tokens": 0,
        "completion_tokens_total": 0, "open_inbox": 0,
    }
    write_atomic(os.path.join(sdir, "log.jsonl"), log)
    write_atomic(meta_path, json.dumps(meta, indent=2).encode("utf-8"))
    write_atomic(os.path.join(sdir, "status.json"), json.dumps(status, indent=2).encode("utf-8"))
    counts["done"] += 1
    print(f"  imported {uuid[:8]} -> {sid}  ({len(body)} recs, {n_steps} steps)  {title[:50]}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(
        description="Import DSH sessions into loom as read-only archives. Needs the `zstd` command on PATH."
    )
    ap.add_argument("--dsh", default=os.path.expanduser("~/.dsh/sessions"))
    ap.add_argument("--loom", default=os.path.expanduser("~/.loom"))
    ap.add_argument("--workspace", default=None, help="only sessions whose DSH workspace dir contains this substring")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--model", default="dsv41", help="model name recorded in the imported sessions (default: dsv41)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    files = []
    for p in glob.glob(os.path.join(a.dsh, "*", "*", "session.v4.jsonl.zstd")):
        if a.workspace and a.workspace.lower() not in p.lower():
            continue
        files.append(p)
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    if a.limit:
        files = files[: a.limit]

    if files and shutil.which("zstd") is None:
        print("import-dsh: the `zstd` command is not installed; install it (for example `brew install zstd`) and run again.", file=sys.stderr)
        return 2

    print(f"{len(files)} DSH session(s) to import", file=sys.stderr)
    counts = {"done": 0, "skipped": 0, "failed": 0}
    for p in files:
        try:
            import_one(p, a, counts)
        except Exception as e:
            counts["failed"] += 1
            print(f"  FAILED {os.path.basename(os.path.dirname(p))[:16]}: {e}", file=sys.stderr)

    print(f"done: {counts['done']} imported, {counts['skipped']} skipped, {counts['failed']} failed (of {len(files)})", file=sys.stderr)
    return 1 if counts["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
