"""System APIs: version and What's new, update check / install (through the root helper),
backups (list, back up now, passphrase-protected download) and the post-update banner."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from fastapi import APIRouter, Body, Request
from fastapi.responses import Response

from . import __version__, backup
from .state import audit, need, shielded, st, user

router = APIRouter(prefix="/api")
APP_DIR = Path(__file__).resolve().parent.parent
HELPER_DIR = os.environ.get("GWC_HELPER_DIR", "/var/lib/gwconsole/helper")
STATE_DIR = os.environ.get("GWC_HELPER_STATE", "/var/lib/gwconsole-helper")
BACKUP_DIR = os.environ.get("GWC_BACKUP_DIR", backup.BAK)
VER_RE = re.compile(r"^v\d{1,3}\.\d{1,3}\.\d{1,3}$")


def changelog_section(version: str) -> str:
    for p in (APP_DIR / "CHANGELOG.md",):
        try:
            text = p.read_text()
        except OSError:
            continue
        out, on = [], False
        for line in text.splitlines():
            if line.startswith("## ["):
                if on:
                    break
                on = line.startswith(f"## [{version}]")
            if on:
                out.append(line)
        return "\n".join(out).strip()
    return ""


def _vt(v: str) -> tuple:
    try:
        return tuple(int(x) for x in str(v).lstrip("v").split(".")[:3])
    except ValueError:
        return (0,)


def changelog() -> list[dict]:
    """Every release in CHANGELOG.md: version, date, type, one-line summary, Added/Changed/Fixed items."""
    try:
        text = (APP_DIR / "CHANGELOG.md").read_text()
    except OSError:
        return []
    out, cur, sec, item = [], None, None, None
    for line in text.splitlines():
        m = re.match(r"^## \[(\d+\.\d+\.\d+)\](?:\s*-\s*(\d{4}-\d{2}-\d{2}))?(.*)$", line)
        if m:
            cur = {"version": m.group(1), "date": m.group(2) or "", "note": m.group(3).strip(" ()"),
                   "sections": {}, "summary": ""}
            out.append(cur)
            sec = item = None
            continue
        if line.startswith("## "):
            cur = None
            continue
        if cur is None:
            continue
        m = re.match(r"^### (.+)$", line)
        if m:
            name = m.group(1).split("/")[0].strip()
            sec = cur["sections"].setdefault(name, [])
            item = None
            continue
        if sec is None:
            continue
        if re.match(r"^- ", line):
            item = line[2:].strip()
            sec.append(item)
        elif line.startswith("  ") and line.strip() and sec:
            if re.match(r"^\s+- ", line):
                continue                     # sub-points stay in the full notes
            sec[-1] = (sec[-1] + " " + line.strip()).strip()
    for r in out:
        x, y, z = (int(p) for p in r["version"].split("."))
        r["type"] = "first" if (x, y, z) == (1, 0, 0) else ("patch" if z else ("major" if y == 0 and z == 0 else "minor"))
        heads = [re.match(r"^\*\*(.+?)\*\*", i) for i in r["sections"].get("Added", [])]
        names = [h.group(1).rstrip(".:") for h in heads if h][:4]
        if not names:
            pool = r["sections"].get("Fixed") or r["sections"].get("Changed") or r["sections"].get("Added") or []
            names = [re.sub(r"[*`]", "", i).split(":")[0].split(". ")[0][:80] for i in pool][:3]
        r["summary"] = "; ".join(names)
        r["counts"] = {k.lower(): len(v) for k, v in r["sections"].items()}
    return out


def update_history() -> list[dict]:
    """Upgrades and rollbacks done by the helper, plus version changes seen at start-up (e.g. from the CLI)."""
    items = []
    try:
        with open(os.path.join(STATE_DIR, "history.jsonl")) as f:
            for line in f:
                try:
                    items.append(json.loads(line))
                except ValueError:
                    pass
    except OSError:
        pass
    for r in st.store.db.q("SELECT * FROM update_history ORDER BY at DESC LIMIT 50"):
        # skip start-up records the helper already logged (same target within 15 minutes)
        if any(str(i.get("to", "")).lstrip("v") == r["to_v"] and abs(int(i.get("at", 0)) - r["at"]) < 900
               for i in items):
            continue
        items.append({"at": r["at"], "kind": r["kind"], "from": r["from_v"], "to": r["to_v"], "by": r["by"],
                      "result": r["result"], "seconds": r["seconds"]})
    return sorted(items, key=lambda i: -int(i.get("at", 0)))[:30]


def helper_status() -> dict:
    try:
        with open(os.path.join(STATE_DIR, "status.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def helper_log(lines: int = 300) -> str:
    try:
        with open(os.path.join(STATE_DIR, "update.log")) as f:
            return "".join(f.readlines()[-lines:])
    except OSError:
        return ""


def request_helper(line: str):
    """Hand one request to the root helper (picked up by gwconsole-helper.path)."""
    os.makedirs(HELPER_DIR, exist_ok=True)
    tmp = os.path.join(HELPER_DIR, f".request.{os.getpid()}")
    with open(tmp, "w") as f:
        f.write(line + "\n")
    os.replace(tmp, os.path.join(HELPER_DIR, "request"))


def pending() -> float | None:
    try:
        return os.stat(os.path.join(HELPER_DIR, "request")).st_mtime
    except OSError:
        return None


def _source() -> str:
    try:
        return "git" if (APP_DIR / "SOURCE").read_text().strip() else "tarball"
    except OSError:
        return "git" if (APP_DIR / ".git").exists() else "tarball"


def record_running_version():
    """On startup: remember which version ran before, for the 'Updated to …' banner."""
    prev = st.store.get("running_version")
    if prev != __version__:
        if prev is None:
            # first start of 1.3+: an older version ran before only if users already existed
            old = st.store.db.one("SELECT 1 FROM users WHERE created_at < ?", (int(time.time()) - 120,))
            prev = "an earlier version" if old else None
        if prev:
            st.store.put("updated_from", {"from": prev, "to": __version__, "at": int(time.time())})
        st.store.db.x("INSERT INTO update_history (at, kind, from_v, to_v, by, result) VALUES (?,?,?,?,?,?)",
                      (int(time.time()), "upgrade" if prev else "install",
                       prev if prev and prev[0].isdigit() else None, __version__, "installer", "done"))
        st.store.put("running_version", __version__)


def whatsnew_pending(username: str) -> dict | None:
    u = st.store.get("updated_from")
    if not u or u.get("to") != __version__:
        return None
    if st.store.get(f"seen_version:{username}") == __version__:
        return None
    return u


def _host_info() -> dict:
    import platform
    pretty = ""
    try:
        for line in open("/etc/os-release"):
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    try:
        up = int(time.time() - os.stat(f"/proc/{os.getpid()}").st_ctime)
    except OSError:
        up = None
    return {"hostname": platform.node(), "os": pretty or platform.system(), "python": platform.python_version(),
            "running": up}


@router.get("/system")
async def system(request: Request):
    u = user(request)
    out = {"version": __version__, "source": _source(), "whatsnew": changelog_section(__version__)}
    try:
        out["build"] = (APP_DIR / "BUILD").read_text().strip()
    except OSError:
        out["build"] = ""
    if u["role"] == "superadmin":
        s = helper_status()
        out["update"] = {k: s.get(k) for k in ("current", "latest", "available", "checked_at", "checked_by", "error",
                                                "state", "target", "message", "started_at", "finished_at", "source")}
        # only versions newer than the one running (the helper's list can be from before an upgrade)
        out["update"]["available"] = [a for a in s.get("available") or [] if _vt(a.get("version", "")) > _vt(__version__)]
        out["pending"] = pending()
        out["settings"] = {k: st.store.general()[k] for k in ("update_check", "auto_update_patch", "update_notify")}
        out["history"] = update_history()
        out["installed"] = next((i for i in out["history"] if str(i.get("to", "")).lstrip("v") == __version__
                                 and i.get("result") == "done"), None)
        out["host"] = _host_info()
    out["releases"] = changelog()
    return out


@router.post("/system/update/check")
async def update_check(request: Request):
    need(request, "superadmin")
    request_helper(f"check by {user(request)['username']}")
    return {"ok": True}


@router.post("/system/update/install")
async def update_install(request: Request, body: dict = Body(...)):
    need(request, "superadmin")
    v = str(body.get("version", ""))
    s = helper_status()
    if not VER_RE.match(v) or v not in {a["version"] for a in s.get("available") or []}:
        raise ValueError("that version isn't available — check for updates again")
    if s.get("state") == "running":
        raise ValueError("an update is already running")
    request_helper(f"upgrade {v} by {user(request)['username']}")
    audit(request, "update start", v, True, f"from {__version__}")
    return {"ok": True}


@router.get("/system/update/status")
async def update_status(request: Request):
    need(request, "superadmin")
    s = helper_status()
    return {"state": s.get("state"), "message": s.get("message"), "target": s.get("target"), "pending": pending(),
            "log": helper_log(), "version": __version__}


@router.post("/whatsnew/seen")
async def whatsnew_seen(request: Request):
    st.store.put(f"seen_version:{user(request)['username']}", __version__)
    return {"ok": True}


# ---- backups -----------------------------------------------------------------------
@router.get("/admin/backups")
async def backups(request: Request):
    need(request, "superadmin")
    g = st.store.general()
    return {"items": backup.listing(BACKUP_DIR), "last": helper_status().get("last_backup"), "pending": pending(),
            "settings": {k: g[k] for k in ("nightly_backup", "backup_copy_node", "backup_copy_dir")},
            "nodes": [n["name"] for n in st.store.node_rows()]}


@router.post("/admin/backups/run")
async def backup_now(request: Request):
    need(request, "superadmin")
    request_helper(f"backup by {user(request)['username']}")
    audit(request, "backup start", "dashboard", True)
    return {"ok": True}


@router.post("/admin/backups/download")
async def backup_download(request: Request, body: dict = Body(...)):
    need(request, "superadmin")
    name = str(body.get("name", ""))
    if not backup.NAME_RE.match(name) or name not in {x["name"] for x in backup.listing(BACKUP_DIR)}:
        raise KeyError("backup not found")
    data = open(os.path.join(BACKUP_DIR, name), "rb").read()
    blob = backup.encrypt(data, str(body.get("passphrase", "")))
    audit(request, "backup download", name, True)
    out = name.replace(".tar.gz", ".gwcbak")
    return Response(blob, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{out}"'})


# ---- node software versions -------------------------------------------------------
@router.get("/versions")
async def node_versions(request: Request):
    from .versions import versions
    return {"items": await versions(st)}


@router.post("/cloudflared/{node}/update")
@shielded
async def cloudflared_update(request: Request, node: str):
    from .versions import update_cloudflared
    need(request, "operator")
    n = next((x for x in st.s.cloudflared_nodes if x.name == node), None)
    if not n:
        raise KeyError(f"cloudflared node {node} not found")
    lines: list[str] = []
    lock = st.locks.setdefault(node, __import__("asyncio").Lock())
    async with lock:
        ok = await update_cloudflared(st, n, lines.append)
    out = "\n".join(l for l in lines if l)
    audit(request, "cloudflared update", node, ok, out)
    st.inv.invalidate(node)
    return {"ok": ok, "output": out}


# ---- config history (local git mirror of every managed config file) ----------------
@router.get("/admin/config-history")
async def config_history(request: Request, node: str = "", limit: int = 60):
    import asyncio
    from . import history
    need(request, "superadmin")
    repo = history.repo_dir(st.base.db_path)
    return {"items": await asyncio.to_thread(history.log_sync, repo, max(1, min(int(limit), 300)), node), "repo": repo}


@router.get("/admin/config-history/{commit}")
async def config_history_show(request: Request, commit: str):
    import asyncio
    from . import history
    need(request, "superadmin")
    return {"text": await asyncio.to_thread(history.show_sync, history.repo_dir(st.base.db_path), commit)}
