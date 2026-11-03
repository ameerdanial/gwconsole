"""Backups of the dashboard itself: settings, keys and the database in one .tar.gz.

  make()       consistent snapshot (SQLite online backup) of /etc/gwconsole + the database + audit log
  encrypt()    passphrase-protected copy for downloading (scrypt + AES-256-GCM, file starts with GWCBAK1)
  restore()    put a backup (plain or encrypted) back in place; refuses anything outside the two folders
  copy()       copy a backup to a managed node over SSH with the dashboard key and the node's pinned host key
"""
from __future__ import annotations

import io
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time

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
    """Members must be regular files under etc/gwconsole/ or var/lib/gwconsole/ — nothing else."""
    names = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.name == "GWCONSOLE-BACKUP":
                continue
            ok = (m.isfile() and re.fullmatch(r"(etc/gwconsole|var/lib/gwconsole)/[A-Za-z0-9_.\-]+", m.name)
                  and ".." not in m.name)
            if not ok:
                raise ValueError(f"unexpected entry in backup: {m.name}")
            names.append(m.name)
    if "etc/gwconsole/secret.key" not in names:
        raise ValueError("this doesn't look like a Gateway Console backup (no secret.key)")
    return names


def restore(data: bytes, root: str = "/") -> list[str]:
    names = check_archive(data)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for name in names:
            m = tar.getmember(name)
            dest = os.path.join(root, name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if name.endswith("gwconsole.db"):
                for ext in ("-wal", "-shm"):
                    try:
                        os.unlink(dest + ext)
                    except OSError:
                        pass
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
