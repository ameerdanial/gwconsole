"""System APIs: version and What's new, update check / install (through the root helper), backups (list with
a nightly-style check, back up now, passphrase-protected download, restore from the list or an upload) and the post-update banner."""
from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import Response

from . import __version__, backup
from .state import audit, need, scope, shielded, st, user

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
        hs = helper_status()        # started from Settings → About (or nightly): credit who asked for it
        by = (hs.get("by") if str(hs.get("target", "")).lstrip("v") == __version__
              and time.time() - int(hs.get("started_at") or 0) < 1800 else None) or "installer"
        st.store.db.x("INSERT INTO update_history (at, kind, from_v, to_v, by, result) VALUES (?,?,?,?,?,?)",
                      (int(time.time()), "upgrade" if prev else "install",
                       prev if prev and prev[0].isdigit() else None, __version__, by, "done"))
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
        for line in Path("/etc/os-release").read_text().splitlines():
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
_verify_cache: dict = {}
SPOOL_TTL = 3600


def spool_dir() -> str:
    """Uploaded backups wait here (owned by the dashboard user) until restored or for an hour."""
    d = os.path.join(os.path.dirname(st.base.db_path), "restore-spool")
    os.makedirs(d, mode=0o700, exist_ok=True)
    t = time.time()
    for n in os.listdir(d):
        try:
            if t - os.path.getmtime(os.path.join(d, n)) > SPOOL_TTL:
                os.unlink(os.path.join(d, n))
        except OSError:
            pass
    return d


def _listed(name: str) -> str:
    if not backup.NAME_RE.match(name) or name not in {x["name"] for x in backup.listing(BACKUP_DIR)}:
        raise KeyError("backup not found")
    return os.path.join(BACKUP_DIR, name)


def _preview(data: bytes, name: str) -> dict:
    """What restoring this backup brings back and what is lost (users, nodes, activity added since)."""
    try:
        key = Path(st.base.secret_key_file).read_bytes()
    except OSError:
        key = None
    info = backup.inspect(data, key, name=name)
    if not info["created_ts"] and backup.NAME_RE.match(name):     # upgrade backups have no marker: use the file's time
        try:
            info["created_ts"] = int(os.path.getmtime(os.path.join(BACKUP_DIR, name)))
        except OSError:
            pass
    cur_users = {u["username"] for u in st.store.users()}
    cur_nodes = {n["name"] for n in st.store.node_rows()}
    created = info["created_ts"]
    newer = st.audit.search(since=created, limit=1)["matched"] if created else 0
    return {"name": name, **info, "users": len(info["users"]), "nodes": len(info["nodes"]),
            "newer_than_running": bool(info["version"]) and backup.vt(info["version"]) > backup.vt(__version__),
            "lost": {"users": sorted(cur_users - set(info["users"])), "nodes": sorted(cur_nodes - set(info["nodes"])),
                     "activity": newer}}


def backup_alerts() -> list[dict]:
    """A warning when the newest backup can't be opened or its database is damaged (checked once per file)."""
    items = [b for b in backup.listing(BACKUP_DIR) if b["kind"] == "backup"]
    if not items:
        return []
    b = items[0]
    try:
        r = backup.verify_file(os.path.join(BACKUP_DIR, b["name"]), _verify_cache)
    except OSError:
        return []
    if r["ok"]:
        return []
    return [{"key": f"backup.broken|{b['name']}", "kind": "backup.broken", "sev": "warn", "node": "", "where": "dashboard backups",
             "msg": f"the newest backup {b['name']} is damaged ({r['error'] or 'unknown error'}) — run Back up now and check the disk"}]


@router.get("/admin/backups")
async def backups(request: Request):
    need(request, "superadmin")
    g = st.store.general()
    items = backup.listing(BACKUP_DIR)
    for b in items:                              # each backup is opened and checked once (cached)
        b.update(await asyncio.to_thread(backup.verify_file, os.path.join(BACKUP_DIR, b["name"]), _verify_cache))
    hs = helper_status()
    return {"items": items, "last": hs.get("last_backup"), "pending": pending(), "restore": hs.get("restore"),
            "settings": {k: g[k] for k in ("nightly_backup", "backup_copy_node", "backup_copy_dir")},
            "nodes": [n["name"] for n in st.store.node_rows()]}


@router.get("/admin/backups/{name}/preview")
async def backup_preview(request: Request, name: str):
    need(request, "superadmin")
    data = await asyncio.to_thread(backup.open_bytes, _listed(name))
    return await asyncio.to_thread(_preview, data, name)


@router.post("/admin/backups/upload")
async def backup_upload(request: Request):
    """Step 1 of restoring from a file: the raw upload (a .gwcbak or .tar.gz, up to 200 MB) goes to the spool
    folder. Nothing is decrypted or changed yet."""
    need(request, "superadmin")
    uid = secrets.token_hex(8)
    path = os.path.join(spool_dir(), f"upload-{uid}.raw")
    size = 0
    with open(path, "wb") as f:
        async for chunk in request.stream():
            size += len(chunk)
            if size > backup.MAX_UPLOAD:
                f.close()
                os.unlink(path)
                raise HTTPException(413, "that file is bigger than 200 MB — it isn't a Gateway Console backup")
            f.write(chunk)
    if not size:
        os.unlink(path)
        raise ValueError("the file is empty")
    with open(path, "rb") as f:
        encrypted = f.read(len(backup.MAGIC)) == backup.MAGIC
    return {"upload_id": uid, "encrypted": encrypted, "size": size}


@router.post("/admin/backups/upload/{uid}/open")
async def backup_upload_open(request: Request, uid: str, body: dict = Body(default={})):
    """Step 2: decrypt (if it's a .gwcbak) and check it; the checked .tar.gz replaces the raw upload."""
    need(request, "superadmin")
    if not re.fullmatch(r"[0-9a-f]{16}", uid):
        raise KeyError("upload not found")
    raw = os.path.join(spool_dir(), f"upload-{uid}.raw")
    plain = os.path.join(spool_dir(), f"upload-{uid}.tar.gz")
    if not os.path.exists(raw) and os.path.exists(plain):
        data = backup.open_bytes(plain)
    else:
        if not os.path.exists(raw):
            raise KeyError("that upload has expired — choose the file again")
        data = backup.open_bytes(raw)
        if data.startswith(backup.MAGIC):
            data = backup.decrypt(data, str(body.get("passphrase", "")))       # ValueError → "wrong passphrase"
        try:
            backup.check_archive(data)
        except Exception as e:
            raise ValueError(f"this isn't a usable Gateway Console backup: {e}") from e
        old = os.umask(0o077)
        try:
            Path(plain).write_bytes(data)
        finally:
            os.umask(old)
        os.unlink(raw)
    return await asyncio.to_thread(_preview, data, f"upload-{uid}.tar.gz")


@router.post("/admin/backups/restore")
async def backup_restore(request: Request, body: dict = Body(...)):
    """Restore a listed backup or a checked upload through the root helper, after the password, the current
    two-step code (when it's on) and typing RESTORE."""
    need(request, "superadmin")
    from .auth import verify_password
    u = user(request)
    full = st.store.user_by_id(u["id"]) or {}
    if str(body.get("confirm", "")).strip() != "RESTORE":
        raise ValueError("type RESTORE to confirm")
    if not verify_password(str(body.get("password", "")), full.get("pw_hash", "")):
        audit(request, "restore refused", str(body.get("name", ""))[:80], False, "wrong password")
        raise ValueError("wrong password")
    if full.get("totp_on") and not st.store.twofa_check(u["id"], code=str(body.get("code") or "")):
        audit(request, "restore refused", str(body.get("name", ""))[:80], False, "wrong two-step code")
        raise ValueError("that two-step code doesn't match")
    name = str(body.get("name", ""))
    if re.fullmatch(r"upload-[0-9a-f]{16}\.tar\.gz", name):
        path = os.path.join(spool_dir(), name)
        if not os.path.isfile(path):
            raise KeyError("that upload has expired — choose the file again")
    else:
        path = _listed(name)
    info = await asyncio.to_thread(_preview, backup.open_bytes(path), name)
    if info["newer_than_running"]:
        raise ValueError(f"this backup was made by v{info['version']}, newer than this dashboard (v{__version__}) — update first")
    if not info["db_ok"]:
        raise ValueError(f"the database in this backup is damaged ({info['db_error']}) — pick another backup")
    if (helper_status().get("restore") or {}).get("state") == "running":
        raise ValueError("a restore is already running")
    request_helper(f"restore {name} by {u['username']}")
    audit(request, "restore requested", name, True, f"v{info['version'] or '?'} backup from {info['created'] or '?'}"
          f"{'' if info['same_key'] is not False else ' (from another dashboard: different secret.key)'}")
    return {"ok": True, "name": name}


@router.get("/admin/backups/restore/status")
async def restore_status(request: Request):
    need(request, "superadmin")
    return {"restore": helper_status().get("restore"), "pending": pending()}


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
    data = Path(BACKUP_DIR, name).read_bytes()
    blob = backup.encrypt(data, str(body.get("passphrase", "")))
    audit(request, "backup download", name, True)
    out = name.replace(".tar.gz", ".gwcbak")
    return Response(blob, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{out}"'})


# ---- node software versions -------------------------------------------------------
@router.get("/versions")
async def node_versions(request: Request):
    from .versions import versions
    scope(request).need_all("Node software versions")
    return {"items": await versions(st)}


@router.post("/cloudflared/{node}/update")
@shielded
async def cloudflared_update(request: Request, node: str):
    from .versions import update_cloudflared
    need(request, "operator")
    scope(request).need_all("Updating cloudflared")
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
