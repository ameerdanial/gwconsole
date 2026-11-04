"""Root-side helper for in-dashboard updates, backups and restores (run by systemd as root, never by the web app).

The dashboard runs unprivileged, so it can only ask: it writes one short line to
/var/lib/gwconsole/helper/request and the gwconsole-helper.path unit starts this script.
Accepted requests (anything else is ignored):
    check by <user>
    upgrade vX.Y.Z by <user>
    backup by <user>
    restore <backup file name> by <user>     (a file in /var/backups/gwconsole, or an upload in the spool folder)
Results go to /var/lib/gwconsole-helper/ (root-owned, readable by the gwconsole group):
status.json (update state, available versions with their changelog) and update.log.

  python3 helper.py                 handle a pending request (gwconsole-helper.service)
  python3 helper.py --scheduled     daily: check for updates (+ auto-install patch releases if enabled),
                                    nightly backup and copy (gwconsole-update-check.service)
Standard library only, so it keeps working even while /opt/gwconsole is being replaced.
"""
from __future__ import annotations

import glob
import grp
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

APP = "/opt/gwconsole"
ETC = "/etc/gwconsole"
REQ = "/var/lib/gwconsole/helper/request"
STATE = "/var/lib/gwconsole-helper"
STATUS = f"{STATE}/status.json"
LOG = f"{STATE}/update.log"
DB = "/var/lib/gwconsole/gwconsole.db"
BAK = "/var/backups/gwconsole"
REQ_RE = re.compile(r"^(check|backup|upgrade (v\d{1,3}\.\d{1,3}\.\d{1,3})|restore ((?:gwconsole-[A-Za-z0-9.\-]{1,120}|upload-[0-9a-f]{16})\.tar\.gz)) "
                    r"by ([A-Za-z0-9_.@-]{1,48})$")
SPOOL = "/var/lib/gwconsole/restore-spool"     # uploads, written by the dashboard user; re-checked here
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_COMMAND": "ssh -o BatchMode=yes -o ConnectTimeout=15"}


def vt(v: str) -> tuple:
    return tuple(int(x) for x in v.lstrip("v").split("."))


def _gid() -> int:
    try:
        return grp.getgrnam("gwconsole").gr_gid
    except KeyError:
        return 0


def ensure_state():
    os.makedirs(STATE, exist_ok=True)
    st = os.lstat(STATE)
    if stat.S_ISLNK(st.st_mode):
        sys.exit("refusing: state dir is a symlink")
    os.chown(STATE, 0, _gid())
    os.chmod(STATE, 0o750)


def load_status() -> dict:
    try:
        with open(STATUS) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_status(d: dict):
    tmp = f"{STATUS}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    os.chown(tmp, 0, _gid())
    os.replace(tmp, STATUS)


def update(**kw):
    d = load_status()
    d.update(kw)
    save_status(d)
    return d


def record(**kw):
    """Append one upgrade/rollback to history.jsonl (shown under Update history; last 50 kept)."""
    path = f"{STATE}/history.jsonl"
    try:
        with open(path) as f:
            lines = f.readlines()[-49:]
    except OSError:
        lines = []
    lines.append(json.dumps({"at": int(time.time()), **kw}) + "\n")
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "w") as f:
        f.writelines(lines)
    os.chown(tmp, 0, _gid())
    os.replace(tmp, path)


def log(msg: str, reset: bool = False):
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if reset else os.O_APPEND) | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "a") as f:
        f.write(msg if msg.endswith("\n") else msg + "\n")
    os.chown(LOG, 0, _gid())


def read_request() -> tuple[str, str, str] | None:
    """One line, regular file, no symlinks — then delete it."""
    try:
        fd = os.open(REQ, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        if os.path.islink(REQ):
            os.unlink(REQ)
        return None
    try:
        st = os.fstat(fd)
        data = os.read(fd, 300).decode("utf-8", "replace") if stat.S_ISREG(st.st_mode) and st.st_size <= 300 else ""
    finally:
        os.close(fd)
        try:
            os.unlink(REQ)
        except OSError:
            pass
    m = REQ_RE.match(data.strip())
    if not m:
        return None
    action = m.group(1).split()[0]
    return action, m.group(2) or m.group(3) or "", m.group(4)


def current() -> str:
    try:
        return "v" + Path(f"{APP}/VERSION").read_text().strip()
    except OSError:
        return "v0.0.0"


def source() -> str:
    try:
        s = Path(f"{APP}/SOURCE").read_text().strip()
        return s if os.path.isdir(f"{s}/.git") else ""
    except OSError:
        return ""


def git(src: str, *args, timeout=90) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", src, *args], capture_output=True, text=True, timeout=timeout, env=GIT_ENV)


def changelog_section(text: str, version: str) -> str:
    v = version.lstrip("v")
    out, on = [], False
    for line in text.splitlines():
        if line.startswith("## ["):
            if on:
                break
            on = line.startswith(f"## [{v}]")
        if on:
            out.append(line)
    return "\n".join(out).strip()


def settings() -> dict:
    try:
        con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True, timeout=5)
        row = con.execute("SELECT value FROM settings WHERE key='general'").fetchone()
        con.close()
        return json.loads(row[0]) if row else {}
    except (sqlite3.Error, ValueError):
        return {}


# ---------------------------------------------------------------- check
def check(by: str = "schedule") -> dict:
    cur = current()
    src = source()
    base = {"current": cur, "checked_at": int(time.time()), "checked_by": by, "source": "git" if src else "tarball"}
    if not src:
        return update(**base, available=[], latest=cur,
                      error="Installed from a release tarball — updates from the dashboard need a git clone (see README).")
    r = git(src, "fetch", "--quiet", "--tags", "--force", "origin")
    if r.returncode != 0:
        return update(**base, error=f"Could not reach the repository: {(r.stderr or r.stdout).strip()[:300]}")
    tags = [t for t in git(src, "tag", "-l", "v[0-9]*").stdout.split() if re.fullmatch(r"v\d+\.\d+\.\d+", t)]
    newer = sorted((t for t in tags if vt(t) > vt(cur)), key=vt, reverse=True)
    avail = []
    for t in newer[:10]:
        notes = changelog_section(git(src, "show", f"{t}:CHANGELOG.md").stdout, t)
        date = re.search(r"\] - (\d{4}-\d{2}-\d{2})", notes)
        avail.append({"version": t, "date": date.group(1) if date else "", "notes": notes})
    return update(**base, available=avail, latest=newer[0] if newer else cur, error="")


# ---------------------------------------------------------------- upgrade (with automatic rollback)
def listen_url() -> str:
    try:
        cfg = Path(f"{ETC}/config.yaml").read_text()
    except OSError:
        cfg = ""
    lm = re.search(r"^listen:\s*([^\s#]+)", cfg, re.M)
    pm = re.search(r"^port:\s*(\d+)", cfg, re.M)
    host = lm.group(1) if lm else "127.0.0.1"
    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
    return f"http://{'[' + host + ']' if ':' in host else host}:{pm.group(1) if pm else '8088'}/api/health"


def healthy(version: str, wait: int = 90) -> bool:
    url, end = listen_url(), time.time() + wait
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if json.loads(r.read()).get("version") == version.lstrip("v"):
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def run_logged(cmd: list[str], timeout: int = 900) -> int:
    fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    try:
        p = subprocess.run(cmd, stdout=fd, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, timeout=timeout,
                           env={**GIT_ENV, "TERM": "dumb"})
        return p.returncode
    except subprocess.TimeoutExpired:
        log(f"timed out after {timeout}s")
        return 124
    finally:
        os.close(fd)


def upgrade(target: str, by: str):
    cur = current()
    st = load_status()
    if st.get("state") == "running":
        return
    if vt(target) <= vt(cur) and not st.get("allow_downgrade"):
        return update(state="failed", message=f"{target} is not newer than {cur}")
    src = source()
    if not src:
        return update(state="failed", message="installed from a tarball: no git clone to upgrade from")
    start = time.time()
    log(f"== {time.strftime('%Y-%m-%d %H:%M:%S')}  upgrade {cur} → {target}  (requested by {by})", reset=True)
    update(state="running", target=target, from_version=cur, started_at=int(start), by=by, message="installing…")
    rc = run_logged(["/usr/local/bin/gwconsole", "upgrade", target, "--yes"])
    log(f"-- installer finished (exit {rc}); waiting for the new version to answer…")
    if rc == 0 and healthy(target):
        log(f"== {target} is up and healthy")
        update(state="done", message=f"Updated {cur} → {target}", finished_at=int(time.time()), current=target,
               available=[a for a in st.get("available", []) if vt(a["version"]) > vt(target)],
               latest=st.get("latest", target))
        record(kind="upgrade", **{"from": cur, "to": target}, by=by, result="done", seconds=int(time.time() - start))
        return
    log(f"!! {target} did not come up healthy — rolling back to {cur}")
    update(message="rolling back…")
    backups = sorted((b for b in glob.glob(f"{BAK}/gwconsole-{cur.lstrip('v')}-*.tar.gz") if os.path.getmtime(b) >= start - 5),
                     key=os.path.getmtime)
    subprocess.run(["systemctl", "stop", "gwconsole"], capture_output=True)
    if backups:
        log(f"-- restoring settings and database from {backups[0]}")
        run_logged(["tar", "xzf", backups[0], "-C", "/"])
    else:
        log("-- no backup from this upgrade found; keeping current settings")
    r = git(src, "-c", "advice.detachedHead=false", "checkout", "--quiet", "--force", cur)
    if r.returncode != 0:
        log(r.stderr)
    rc2 = run_logged(["bash", f"{src}/install.sh", "--upgrade"])
    ok = rc2 == 0 and healthy(cur)
    log(f"== rollback {'finished: back on ' + cur if ok else 'FAILED — check: journalctl -u gwconsole'}")
    record(kind="upgrade", **{"from": cur, "to": target}, by=by, result="rolled_back" if ok else "failed",
           seconds=int(time.time() - start))
    update(state="rolled_back" if ok else "failed", finished_at=int(time.time()), current=current(),
           message=(f"{target} failed to start, so the dashboard went back to {cur}. Nothing was lost; see the log."
                    if ok else "The update and the rollback both failed — see the log and run: gwconsole status"))


# ---------------------------------------------------------------- restore (requested from Settings → Backups)
def restore(name: str, by: str):
    """Restore a listed backup or an uploaded one through `gwconsole restore` (which checks the archive itself,
    saves the current state first, and puts it back if the restored dashboard doesn't start)."""
    if load_status().get("restore", {}).get("state") == "running":
        return
    folder = SPOOL if name.startswith("upload-") else BAK
    path = os.path.join(folder, os.path.basename(name))
    start = int(time.time())
    try:
        st_ = os.lstat(path)
    except OSError:
        return update(restore={"state": "failed", "name": name, "by": by, "at": start, "message": "backup file not found"})
    if not stat.S_ISREG(st_.st_mode) or st_.st_size > 200 * 1024 * 1024:
        return update(restore={"state": "failed", "name": name, "by": by, "at": start, "message": "not a regular file, or too big"})
    log(f"== {time.strftime('%Y-%m-%d %H:%M:%S')}  restore {name}  (requested by {by})", reset=True)
    update(restore={"state": "running", "name": name, "by": by, "at": start, "message": "restoring…"})
    rc = run_logged(["/usr/local/bin/gwconsole", "restore", path, "--by", by])
    state = {0: "done", 3: "rolled_back"}.get(rc, "failed")
    msg = {"done": f"Restored {name}", "rolled_back": "The restored dashboard didn't start — the previous state was put back"}.get(
        state, "The restore didn't run — see the log")
    update(restore={"state": state, "name": name, "by": by, "at": start, "finished_at": int(time.time()), "message": msg,
                    "log": tail_log()})
    record(kind="restore", name=name, by=by, result=state, seconds=int(time.time()) - start)
    if folder == SPOOL:
        try:
            os.unlink(path)
        except OSError:
            pass


def tail_log(n: int = 40) -> str:
    try:
        with open(LOG) as f:
            return "".join(f.readlines()[-n:])[-4000:]
    except OSError:
        return ""


# ---------------------------------------------------------------- backups (requested or nightly)
def backup(by: str = "schedule") -> str:
    r = subprocess.run(["/usr/local/bin/gwconsole", "backup", "--quiet"], capture_output=True, text=True, timeout=300)
    out = (r.stdout + r.stderr).strip()
    d = load_status()
    d["last_backup"] = {"at": int(time.time()), "ok": r.returncode == 0, "by": by, "output": out[-1000:]}
    save_status(d)
    return out


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (it is started by systemd)")
    ensure_state()
    if "--scheduled" in sys.argv:
        s = settings()
        if s.get("nightly_backup", True):
            backup()
        if s.get("update_check", True):
            d = check()
            if s.get("auto_update_patch") and not d.get("error"):
                cur = vt(current())
                patch = [a["version"] for a in d.get("available", []) if vt(a["version"])[:2] == cur[:2]]
                if patch:
                    upgrade(max(patch, key=vt), "automatic patch update")
        return
    req = read_request()
    if not req:
        return
    action, version, by = req
    if action == "check":
        check(by)
    elif action == "backup":
        backup(by)
    elif action == "restore":
        restore(version, by)
    elif action == "upgrade":
        avail = {a["version"] for a in load_status().get("available", [])}
        if version not in avail:
            update(state="failed", message=f"{version} is not an available update — check again")
            return
        upgrade(version, by)


if __name__ == "__main__":
    main()
