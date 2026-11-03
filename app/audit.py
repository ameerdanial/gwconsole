"""Append-only JSONL audit log of every change made through the console."""
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
