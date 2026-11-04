"""Config history and drift detection.

Every config file the dashboard manages (haproxy.cfg, each tunnel's config.yml) is mirrored into
a local git repository (/var/lib/gwconsole/config-history): one commit per change, authored by the
dashboard user who made it — or "outside the dashboard" when someone edited the file over SSH.
The last known hash of each file is kept in the database; a periodic check raises a
"changed outside the dashboard" alert until the change is accepted or applied over.
"""
from __future__ import annotations

import asyncio
import contextvars
import os
import re
import subprocess
import time

from . import configops

ACTOR: contextvars.ContextVar[str] = contextvars.ContextVar("gwc_actor", default="system")
NOTE: contextvars.ContextVar[str] = contextvars.ContextVar("gwc_note", default="")


def repo_dir(db_path: str) -> str:
    return os.path.join(os.path.dirname(db_path), "config-history")


def _git(repo: str, *args: str, input: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "HOME": repo, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, input=input, env=env, timeout=30)


def _rel(node: str, path: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.\-]+", "_", path.strip("/"))
    return f"{re.sub(r'[^A-Za-z0-9_.-]+', '_', node)}/{safe}"


def _ensure(repo: str):
    if not os.path.isdir(os.path.join(repo, ".git")):
        os.makedirs(repo, exist_ok=True)
        _git(repo, "init", "-q")
        _git(repo, "config", "user.name", "gwconsole")
        _git(repo, "config", "user.email", "gwconsole@localhost")
        _git(repo, "config", "commit.gpgsign", "false")


def record_sync(repo: str, node: str, path: str, content: str, author: str, message: str) -> str | None:
    """Write the file into the history repo and commit it if it changed. Returns the commit id."""
    try:
        _ensure(repo)
        rel = _rel(node, path)
        full = os.path.join(repo, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        _git(repo, "add", "--", rel)
        if _git(repo, "diff", "--cached", "--quiet").returncode == 0:
            return None
        who = re.sub(r"[<>\n]", "", author)[:60] or "system"
        r = _git(repo, "commit", "-q", "--author", f"{who} <{re.sub(r'[^A-Za-z0-9_.-]', '_', who)}@gwconsole>",
                 "-m", f"{node}:{path}: {message}"[:300])
        if r.returncode != 0:
            return None
        return _git(repo, "rev-parse", "--short", "HEAD").stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def log_sync(repo: str, limit: int = 50, node: str = "") -> list[dict]:
    if not os.path.isdir(os.path.join(repo, ".git")):
        return []
    args = ["log", f"-{int(limit)}", "--format=%h%x1f%at%x1f%an%x1f%s", "--name-only"]
    if node:
        args += ["--", _rel(node, "x").split("/")[0] + "/"]
    out, cur = [], None
    for line in _git(repo, *args).stdout.splitlines():
        if "\x1f" in line:
            h, at, an, s = line.split("\x1f", 3)
            cur = {"id": h, "at": int(at), "author": an, "subject": s, "files": []}
            out.append(cur)
        elif line.strip() and cur:
            cur["files"].append(line.strip())
    return out


def show_sync(repo: str, commit: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{4,40}", commit):
        raise ValueError("bad commit id")
    r = _git(repo, "show", "--format=%an, %ad%n%s%n", "--date=format:%Y-%m-%d %H:%M", commit)
    if r.returncode != 0:
        raise KeyError("commit not found")
    return r.stdout


# ---- hooks used by the rest of the app -----------------------------------------------
def on_applied(store, db_path: str, node: str, path: str, content: str, stage: str):
    """Called after the dashboard wrote a config file: remember its hash and commit it."""
    store.put(f"cfg_hash:{node}:{path}", configops.sha(content))
    store.put(f"cfg_drift:{node}:{path}", None)
    note = NOTE.get()
    record_sync(repo_dir(db_path), node, path, content, ACTOR.get(),
                ("restored/rolled back" if stage != "applied" else "changed in the dashboard") + (f" — {note}" if note else ""))


async def check_drift(st) -> list[dict]:
    """Compare every managed config with its last known hash. Returns drift alerts."""
    from .cloudflared import TunnelConfig
    from .haproxy import HAProxyConfig
    from .sshpool import NodeError
    targets = [(n.name, HAProxyConfig(st.pool, st.s, n)) for n in st.s.haproxy_nodes]
    for n in st.s.cloudflared_nodes:
        try:
            for t in await st.inv.tunnels(n):
                if not t.remote and t.config_path:
                    targets.append((n.name, TunnelConfig(st.pool, st.s, n, t)))
        except NodeError:
            pass
    alerts = []
    repo = repo_dir(st.base.db_path)
    for node, tg in targets:
        try:
            content = await tg.read()
        except Exception:
            continue
        h = configops.sha(content)
        k = f"{node}:{tg.path}"
        known = st.store.get(f"cfg_hash:{k}")
        drift = st.store.get(f"cfg_drift:{k}")
        if known is None:
            st.store.put(f"cfg_hash:{k}", h)
            await asyncio.to_thread(record_sync, repo, node, tg.path, content, "baseline", "first copy kept by the dashboard")
            continue
        if h == known:
            if drift:
                st.store.put(f"cfg_drift:{k}", None)
            continue
        if not drift or drift.get("hash") != h:
            drift = {"hash": h, "at": int(time.time())}
            st.store.put(f"cfg_drift:{k}", drift)
            await asyncio.to_thread(record_sync, repo, node, tg.path, content, "outside the dashboard",
                                    "changed outside the dashboard (detected)")
        alerts.append({"key": f"cfg.drift|{k}", "kind": "cfg.drift", "sev": "warn", "node": node, "where": k,
                       "msg": f"{tg.path} was changed outside the dashboard — review it in Edit config → History, then accept it on the Alerts page"})
    return alerts


def accept(st, key: str):
    """'node:path' — take the current file as the new known version."""
    drift = st.store.get(f"cfg_drift:{key}")
    if not drift:
        raise KeyError("no unaccepted change for that file")
    st.store.put(f"cfg_hash:{key}", drift["hash"])
    st.store.put(f"cfg_drift:{key}", None)
