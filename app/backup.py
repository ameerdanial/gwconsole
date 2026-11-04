"""Backups of the dashboard itself: settings, keys and the database in one .tar.gz.

  make()       consistent snapshot (SQLite online backup) of /etc/gwconsole + the database + audit log
  encrypt()    passphrase-protected copy for downloading (scrypt + AES-256-GCM, file starts with GWCBAK1)
  restore()    put a backup (plain or encrypted) back in place; refuses anything outside the two folders
  inspect()    what a backup holds (version, date, users, nodes, accounts) and whether its database is intact
  copy()       copy a backup to a managed node over SSH with the dashboard key and the node's pinned host key
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

BAK = "/var/backups/gwconsole"
MAGIC = b"GWCBAK1\n"
NAME_RE = re.compile(r"^gwconsole-[A-Za-z0-9.\-]+\.tar\.gz$")
KEEP = {"backup": 14, "upgrade": 10, "restore": 5}


def kind_of(name: str) -> str:
    if name.startswith("gwconsole-backup-"):
        return "backup"
    return "restore" if name.startswith("gwconsole-before-restore-") else "upgrade"


def listing(bak: str = BAK) -> list[dict]:
    out = []
    try:
        names = os.listdir(bak)
    except OSError:
        return out
    for n in names:
        if NAME_RE.match(n):
            st = os.stat(os.path.join(bak, n))
            out.append({"name": n, "size": st.st_size, "at": int(st.st_mtime), "kind": kind_of(n)})
    return sorted(out, key=lambda x: x["at"], reverse=True)


def make(etc: str, db_path: str, audit_log: str, version: str, bak: str = BAK, prefix: str = "backup") -> str:
    """Write <bak>/gwconsole-<prefix>-<version>-<ts>.tar.gz and prune old ones of that kind."""
    os.makedirs(bak, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    out = os.path.join(bak, f"gwconsole-{prefix}-{version}-{ts}.tar.gz")
    with tempfile.TemporaryDirectory() as tmp:
        snap = os.path.join(tmp, "gwconsole.db")
        if os.path.exists(db_path):
            src = sqlite3.connect(db_path, timeout=15)
            dst = sqlite3.connect(snap)
            with dst:
                src.backup(dst)
            src.close()
            dst.close()
        old = os.umask(0o077)
        try:
            with tarfile.open(out, "w:gz") as tar:
                for f in sorted(os.listdir(etc)) if os.path.isdir(etc) else []:
                    p = os.path.join(etc, f)
                    if os.path.isfile(p) and not os.path.islink(p):
                        tar.add(p, arcname=f"etc/gwconsole/{f}")
                if os.path.exists(snap):
                    tar.add(snap, arcname="var/lib/gwconsole/gwconsole.db")
                if os.path.isfile(audit_log):
                    tar.add(audit_log, arcname="var/lib/gwconsole/audit.log")
                info = tarfile.TarInfo("GWCONSOLE-BACKUP")
                body = f"gwconsole {version}\ncreated {time.strftime('%Y-%m-%d %H:%M:%S %z')}\n".encode()
                info.size, info.mtime = len(body), int(time.time())
                tar.addfile(info, io.BytesIO(body))
        finally:
            os.umask(old)
    _perms(out)
    prune(bak, prefix)
    return out


def _perms(path: str):
    try:
        import grp
        gid = grp.getgrnam("gwconsole").gr_gid
        if os.geteuid() == 0:
            os.chown(path, 0, gid)
            os.chown(os.path.dirname(path), 0, gid)
            os.chmod(os.path.dirname(path), 0o750)
        os.chmod(path, 0o640)
    except (KeyError, OSError):
        pass


def prune(bak: str, prefix: str):
    kind = {"backup": "backup", "before-restore": "restore"}.get(prefix, "upgrade")
    keep = KEEP[kind]
    files = sorted((x for x in listing(bak) if x["kind"] == kind),
                   key=lambda x: x["at"], reverse=True)
    for x in files[keep:]:
        try:
            os.unlink(os.path.join(bak, x["name"]))
        except OSError:
            pass


def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def encrypt(data: bytes, passphrase: str) -> bytes:
    if len(passphrase) < 8:
        raise ValueError("use a passphrase of at least 8 characters")
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, data, MAGIC)


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        return blob
    salt, nonce, ct = blob[8:24], blob[24:36], blob[36:]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(nonce, ct, MAGIC)
    except Exception:
        raise ValueError("wrong passphrase (or the file is damaged)")


def check_archive(data: bytes) -> list[str]:
    """The files a restore puts back: regular files directly in etc/gwconsole/ or var/lib/gwconsole/.

    Upgrade backups made by install.sh also hold the two folders themselves and what's below them
    (config history, the upload spool): those entries are skipped, never extracted. Anything else
    (links, devices, `..`, absolute paths, other folders) means the archive is refused."""
    names = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            n = m.name[2:] if m.name.startswith("./") else m.name
            if n == "GWCONSOLE-BACKUP":
                continue
            root = next((r for r in ("etc/gwconsole", "var/lib/gwconsole") if n.rstrip("/") == r or n.startswith(r + "/")), None)
            if root is None or ".." in n.split("/"):
                raise ValueError(f"unexpected entry in backup: {m.name}")
            rest = n[len(root):].strip("/").split("/") if n.rstrip("/") != root else []
            if not rest:                                          # the folder itself
                if not m.isdir():
                    raise ValueError(f"unexpected entry in backup: {m.name}")
                continue
            if len(rest) > 1 or m.isdir():                        # a sub-folder and what's in it: skipped
                continue
            if not (m.isfile() and re.fullmatch(r"[A-Za-z0-9_.\-]+", rest[0]) and n == m.name):
                raise ValueError(f"unexpected entry in backup: {m.name}")
            names.append(n)
    if "etc/gwconsole/secret.key" not in names:
        raise ValueError("this doesn't look like a Gateway Console backup (no secret.key)")
    return names


def restore(data: bytes, root: str = "/") -> list[str]:
    names = check_archive(data)
    for ext in ("-wal", "-shm"):          # the current database's journal must not be applied to the restored copy
        try:                              # (a journal inside the backup, if any, is put back below)
            os.unlink(os.path.join(root, "var/lib/gwconsole/gwconsole.db" + ext))
        except OSError:
            pass
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for name in names:
            m = tar.getmember(name)
            dest = os.path.join(root, name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with tar.extractfile(m) as src, open(dest + ".restore", "wb") as out:
                shutil.copyfileobj(src, out)
            os.replace(dest + ".restore", dest)
    return names


def copy(path: str, node: dict, key_file: str, dest_dir: str, keep: int = 14) -> str:
    """scp a backup to a node (pinned host key) and keep the newest `keep` there."""
    if not re.fullmatch(r"/[A-Za-z0-9_./\-]{1,200}", dest_dir) or ".." in dest_dir:
        raise ValueError("backup folder on the node must be an absolute path")
    host, port, user = node["host"], int(node.get("port") or 22), node.get("user") or "root"
    with tempfile.NamedTemporaryFile("w", delete=False) as kh:
        if node.get("host_key"):
            kh.write(f"{host if port == 22 else f'[{host}]:{port}'} {node['host_key']}\n")
        khp = kh.name
    opts = ["-i", key_file, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "IdentitiesOnly=yes"]
    opts += ["-o", f"UserKnownHostsFile={khp}", "-o", "StrictHostKeyChecking=yes"] if node.get("host_key") else \
        ["-o", "UserKnownHostsFile=/etc/gwconsole/known_hosts", "-o", "StrictHostKeyChecking=yes"]
    sudo = "sudo -n " if node.get("sudo") else ""
    q = lambda s: "'" + s.replace("'", "'\\''") + "'"
    try:
        r = subprocess.run(["ssh", *opts, "-p", str(port), f"{user}@{host}",
                            f"umask 077; {sudo}mkdir -p {q(dest_dir)} && {sudo}chmod 700 {q(dest_dir)} && cat | {sudo}tee {q(dest_dir + '/' + os.path.basename(path))} >/dev/null"
                            f" && cd {q(dest_dir)} && ls -1t gwconsole-backup-*.tar.gz 2>/dev/null | tail -n +{keep + 1} | xargs -r {sudo}rm -f"],
                           stdin=open(path, "rb"), capture_output=True, text=True, timeout=180)
    finally:
        os.unlink(khp)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:300] or f"ssh exit {r.returncode}")
    return f"copied to {user}@{host}:{dest_dir}/{os.path.basename(path)}"


MAX_UPLOAD = 200 * 1024 * 1024
VERSION_RE = re.compile(r"^gwconsole (\d+\.\d+\.\d+)", re.MULTILINE)


def vt(v: str) -> tuple:
    try:
        return tuple(int(x) for x in str(v).lstrip("v").split("."))
    except ValueError:
        return (0, 0, 0)


def inspect(data: bytes, current_key: bytes | None = None, name: str = "") -> dict:
    """What a (decrypted) backup holds, without changing anything: the version that made it, when, counts of
    users / nodes / Cloudflare accounts read from its database copy (opened read-only in a temp folder),
    PRAGMA integrity_check, and whether its secret.key is the one this dashboard uses."""
    names = check_archive(data)
    out = {"files": len(names), "version": "", "created": "", "created_ts": 0, "users": [], "nodes": [], "cf_accounts": 0,
           "db_ok": None, "db_error": "", "same_key": None}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        try:
            marker = tar.extractfile("GWCONSOLE-BACKUP").read().decode(errors="replace")
            m = VERSION_RE.search(marker)
            out["version"] = m.group(1) if m else ""
            c = re.search(r"^created (.+)$", marker, re.MULTILINE)
            out["created"] = c.group(1).strip() if c else ""
            try:
                out["created_ts"] = int(datetime.strptime(out["created"], "%Y-%m-%d %H:%M:%S %z").timestamp())
            except ValueError:
                pass
        except KeyError:
            pass
        if not out["version"]:                       # upgrade backups have no marker: gwconsole-<version>-<time>.tar.gz
            m = re.match(r"gwconsole-(\d{1,3}\.\d{1,3}\.\d{1,3})-\d{8}-\d{6}\.tar\.gz$", os.path.basename(name or ""))
            out["version"] = m.group(1) if m else ""
        key = tar.extractfile("etc/gwconsole/secret.key").read()
        if current_key is not None:
            out["same_key"] = hashlib.sha256(key.strip()).digest() == hashlib.sha256(current_key.strip()).digest()
        if "var/lib/gwconsole/gwconsole.db" in names:
            with tempfile.TemporaryDirectory() as tmp:
                p = os.path.join(tmp, "check.db")
                with open(p, "wb") as f:
                    f.write(tar.extractfile("var/lib/gwconsole/gwconsole.db").read())
                try:
                    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
                    try:
                        res = con.execute("PRAGMA integrity_check").fetchone()[0]
                        out["db_ok"] = res == "ok"
                        out["db_error"] = "" if res == "ok" else str(res)[:200]
                        out["users"] = [r[0] for r in con.execute("SELECT username FROM users ORDER BY username")]
                        out["nodes"] = [r[0] for r in con.execute("SELECT name FROM nodes ORDER BY name")]
                        out["cf_accounts"] = con.execute("SELECT COUNT(*) FROM cf_accounts").fetchone()[0]
                    finally:
                        con.close()
                except sqlite3.Error as e:
                    out["db_ok"], out["db_error"] = False, str(e)[:200]
        else:
            out["db_ok"], out["db_error"] = False, "no database in this backup"
    return out


def verify_file(path: str, cache: dict) -> dict:
    """Nightly / on-listing check of one backup file, cached by name + size + mtime."""
    st_ = os.stat(path)
    k = f"{os.path.basename(path)}:{st_.st_size}:{int(st_.st_mtime)}"
    if k in cache:
        return cache[k]
    try:
        info = inspect(open_bytes(path), name=path)
        r = {"ok": bool(info["db_ok"]), "error": info["db_error"], "version": info["version"]}
    except (OSError, ValueError, tarfile.TarError, KeyError) as e:
        r = {"ok": False, "error": str(e)[:200], "version": ""}
    cache[k] = r
    return r


def open_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def summary_json(info: dict) -> str:
    return json.dumps({k: info.get(k) for k in ("version", "created", "users", "nodes", "cf_accounts", "db_ok")})
