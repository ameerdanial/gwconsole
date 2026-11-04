"""Append-only JSONL audit log of every change made through the console, and searching it for the
Activity page (filters by text, user, result, category and time; newest first, paged)."""
from __future__ import annotations

import json
import os
import time
from collections import deque
import logging

log = logging.getLogger("gwconsole.audit")


class Audit:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def log(self, user: str, action: str, target: str, ok: bool, detail: str = "", ip: str = ""):
        rec = {"ts": int(time.time()), "user": user, "ip": ip, "action": action, "target": target,
               "ok": bool(ok), "detail": (detail or "")[:4000]}
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError as e:  # never let audit I/O break an operation
            log.error("audit log write failed (%s): %s", self.path, e)

    def search(self, **filters) -> dict:
        return search_file(self.path, **filters)

    def tail(self, n: int = 200) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            lines = deque(f, maxlen=n)
        out = []
        for l in reversed(lines):
            try:
                out.append(json.loads(l))
            except ValueError:
                pass
        return out


# Activity categories, by the start of the action name
CATEGORIES = {
    "signin": ("login", "signed out", "password change"),
    "config": ("config ", "haproxy change", "haproxy fix-socket"),
    "server": ("server→", "haproxy reload", "haproxy restart"),
    "tunnel": ("tunnel ", "hostname ", "dns ", "cf tunnel"),
    "monitor": ("monitor site", "watch service", "unwatch service", "service restart", "weekly summary", "alert ack",
                "mute", "unmute"),
    "settings": ("user ", "session revoke", "node ", "cf account", "settings change", "notify settings", "setup",
                 "monitor settings", "access", "preferences"),
    "updates": ("update ", "backup ", "restore", "cloudflared update"),
}


def category(action: str) -> str:
    for cat, prefixes in CATEGORIES.items():
        if action.startswith(prefixes):
            return cat
    return "other"


def _lines_backwards(path: str, chunk: int = 65536):
    """Yield the file's lines from the last to the first without reading it all into memory."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        pos, rest = f.tell(), b""
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + rest
            lines = buf.split(b"\n")
            rest = lines.pop(0)
            for line in reversed(lines):
                if line.strip():
                    yield line
        if rest.strip():
            yield rest


def search_file(path: str, q: str = "", user: str = "", result: str = "", cat: str = "", since: int = 0,
            hide_logins: bool = False, offset: int = 0, limit: int = 50) -> dict:
    items, matched, hidden, users = [], 0, 0, set()
    q = q.strip().lower()
    if not os.path.exists(path):
        return {"items": [], "matched": 0, "hidden_signins": 0, "more": False, "users": []}
    for raw in _lines_backwards(path):
        try:
            r = json.loads(raw)
        except ValueError:
            continue
        if since and r.get("ts", 0) < since:
            break                          # the file is in time order
        users.add(r.get("user", ""))
        c = category(r.get("action", ""))
        if hide_logins and c == "signin" and cat != "signin":
            hidden += 1
            continue
        if cat and c != cat:
            continue
        if user and r.get("user") != user:
            continue
        if result == "ok" and not r.get("ok") or result == "failed" and r.get("ok"):
            continue
        if q and q not in " ".join(str(r.get(k, "")) for k in ("action", "target", "detail", "user", "ip")).lower():
            continue
        matched += 1
        if offset < matched <= offset + limit:
            items.append({**r, "cat": c})
    return {"items": items, "matched": matched, "hidden_signins": hidden, "more": matched > offset + limit,
            "users": sorted(u for u in users if u and u != "?")}

