#!/usr/bin/env python3
"""Import DeepSeek Harness (DSH) v4 sessions into loom as read-only archive sessions.

A DSH session and a loom session have different, incompatible models, so loom cannot *resume* a DSH
session. What this does is faithfully convert the DSH transcript into a loom event log that is marked
ended, so the conversation is present, browsable and searchable inside loom (CLI and web UI) — history,
not a live session.

Usage:
    import-dsh.py --dsh ~/.dsh/sessions --loom ~/.loom [--workspace SUBSTR] [--limit N] [--dry-run]

It writes, per DSH session, a loom session dir under <loom>/sessions/s-dsh<id>/ with log.jsonl
(hash-chained), meta.json and status.json. Re-running overwrites the same ids (idempotent). Restart
the daemon afterwards so it rescans the sessions directory.
"""
import argparse, hashlib, json, os, sys, glob, subprocess, datetime

ZERO = "0" * 64


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
        return int(v if v > 1e11 else v * 1000)  # seconds -> ms heuristic
    if isinstance(v, str):
        try:
            s = v.replace("Z", "+00:00")
            return int(datetime.datetime.fromisoformat(s).timestamp() * 1000)
        except Exception:
            return default
    return default


def decompress(path: str):
    out = subprocess.run(["zstd", "-dc", path], capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.decode()[:200])
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line:
            try:
                yield json.loads(line)
            except Exception:
                continue


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
    """Chain the records into loom log lines."""
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
        line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
        prev = sha256_hex(line.encode("utf-8"))
        lines.append(line)
    n_steps = sum(1 for a, _, e in records if e.get("kind") == "model_response")
    return "\n".join(lines) + "\n", n_steps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsh", default=os.path.expanduser("~/.dsh/sessions"))
    ap.add_argument("--loom", default=os.path.expanduser("~/.loom"))
    ap.add_argument("--workspace", default=None, help="only sessions whose DSH workspace dir contains this substring")
    ap.add_argument("--limit", type=int, default=0)
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

    print(f"{len(files)} DSH session(s) to import", file=sys.stderr)
    done = 0
    for p in files:
        uuid = os.path.basename(os.path.dirname(p)).replace("session-", "")
        sid = "s-dsh" + uuid.replace("-", "")[:13]
        mission = "m-dsh" + uuid.replace("-", "")[:13]
        try:
            body, header = convert(p, uuid)
        except Exception as e:
            print(f"  skip {uuid[:8]}: {e}", file=sys.stderr)
            continue
        if not body:
            print(f"  skip {uuid[:8]}: no conversation records", file=sys.stderr)
            continue
        header = header or {}
        workspace = header.get("cwd") or "unknown"
        created_ms = to_ms(header.get("createdAt"), body[0][1] or 0)
        # title from first user message
        first_user = next((e["text"] for _, _, e in [(x[0], x[1], x[2]) for x in body] if e.get("kind") == "user_message"), "")
        title = "[DSH] " + " ".join(first_user.split())[:80]
        model = "dsv41"
        log, n_steps = build_log(body, header, sid, mission, workspace, model, created_ms, title)

        if a.dry_run:
            print(f"  would import {uuid[:8]} -> {sid} ({len(body)} recs, {n_steps} steps) ws={workspace}", file=sys.stderr)
            done += 1
            continue

        sdir = os.path.join(a.loom, "sessions", sid)
        os.makedirs(os.path.join(sdir, "tmp"), exist_ok=True)
        with open(os.path.join(sdir, "log.jsonl"), "w") as f:
            f.write(log)
        meta = {
            "id": sid, "mission": mission, "parent": None, "workspace": workspace,
            "pack": "core", "role": "chat", "profile": "imported", "model": model,
            "context_window": 1048576, "title": title, "created_ms": created_ms,
            "mode": None, "awaited": False, "unattended": False, "archived": False,
        }
        with open(os.path.join(sdir, "meta.json"), "w") as f:
            json.dump(meta, f, indent=2)
        status = {
            "phase": "ended", "step": n_steps, "last_end": "finished", "outcome": "done",
            "fork_point": None, "epoch": 0, "prompt_tokens": 0, "cached_tokens": 0,
            "completion_tokens_total": 0, "open_inbox": 0,
        }
        with open(os.path.join(sdir, "status.json"), "w") as f:
            json.dump(status, f, indent=2)
        done += 1
        print(f"  imported {uuid[:8]} -> {sid}  ({len(body)} recs, {n_steps} steps)  {title[:50]}", file=sys.stderr)

    print(f"done: {done}/{len(files)}", file=sys.stderr)


if __name__ == "__main__":
    main()
