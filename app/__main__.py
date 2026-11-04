"""Command-line entry point.

  python -m app serve                  run the web server (what the systemd unit does)
  python -m app check                  test SSH to every node and every Cloudflare token
  python -m app create-admin [user]    create a superadmin (first install / locked out)
  python -m app reset-password <user>  set a new password for a user
  python -m app reset-2fa <user>       turn off a user's two-step sign-in (lost phone); they set it up again
      (both take --password-stdin to read the password from a pipe, used by install.sh)
  python -m app users                  list users and roles
  python -m app hashpw                 print a scrypt hash (for config.yaml, legacy)
  python -m app version                print the installed version
  python -m app backup [--quiet]       snapshot settings, keys and database (+ copy to a node if set)
  python -m app restore <file>         put a backup back (stops/starts the service; asks for the passphrase)
  python -m app allow-all              remove the "allowed networks" sign-in restriction (locked out)
"""
from __future__ import annotations

import asyncio
import getpass
import re
import sys


def _n(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"

def _ask_password() -> str:
    from .store import check_password_strength
    if "--password-stdin" in sys.argv:
        pw = sys.stdin.readline().rstrip("\r\n")
    else:
        pw = getpass.getpass("New password: ")
        if pw != getpass.getpass("Repeat: "):
            sys.exit("passwords do not match")
    try:
        check_password_strength(pw)
    except ValueError as e:
        sys.exit(str(e))
    return pw


def _store():
    from .config import load
    from .db import DB
    from .store import Store
    from .vault import Vault, VaultError
    base = load()
    try:
        vault = Vault(base.secret_key_file)
    except VaultError:
        vault = None          # user commands don't need secrets
    return base, Store(DB(base.db_path), vault)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--password-")]
    cmd = args[0] if args else "serve"
    arg = args[1] if len(args) > 1 else ""
    if cmd in ("version", "--version", "-V"):
        from . import __version__
        print(__version__)
    elif cmd == "hashpw":
        from .auth import hash_password
        print(hash_password(_ask_password()))
    elif cmd == "create-admin":
        _, store = _store()
        name = arg or input("Username: ").strip()
        if store.user(name):
            sys.exit(f"user {name} already exists — use: gwconsole reset-password {name}")
        try:
            store.create_user(name, _ask_password(), "superadmin", must_change=False)
        except ValueError as e:
            sys.exit(str(e))
        print(f"superadmin {name} created")
    elif cmd == "reset-password":
        if not arg:
            sys.exit("usage: reset-password <user>")
        _, store = _store()
        u = store.user(arg)
        if not u:
            sys.exit(f"no user {arg}")
        store.set_password(u["id"], _ask_password(), must_change=False)
        store.db.x("UPDATE users SET disabled=0 WHERE id=?", (u["id"],))
        store.drop_user_sessions(u["id"])
        print(f"password for {arg} changed, account enabled, sessions signed out")
    elif cmd == "reset-2fa":
        if not arg:
            sys.exit("usage: reset-2fa <user>")
        base, store = _store()
        u = store.user(arg)
        if not u:
            sys.exit(f"no user {arg}")
        store.twofa_off(u["id"])
        store.drop_user_sessions(u["id"])
        from .audit import Audit
        Audit(base.audit_log).log("host", "2fa reset", arg, True, "gwconsole reset-2fa on the dashboard host")
        req = " (their role requires it, so they set it up again right after signing in)" if store.twofa_required_for(u["role"]) else ""
        print(f"two-step sign-in for {arg} is off, sessions signed out{req}")
    elif cmd == "users":
        _, store = _store()
        for u in store.users():
            state = "disabled" if u["disabled"] else ("must change pw" if u["must_change"] else "active")
            extra = ("2fa " if u["totp_on"] else "") + ("scoped" if u["scope_mode"] == "pick" else "")
            print(f"{u['username']:<24} {u['role']:<11} {state:<15} {extra}")
    elif cmd == "check":
        asyncio.run(_check())
    elif cmd == "backup":
        _backup("--quiet" in sys.argv)
    elif cmd == "restore":
        if not arg:
            sys.exit("usage: restore <backup file> [--by <user>]")
        by = sys.argv[sys.argv.index("--by") + 1] if "--by" in sys.argv[3:-1] else "host"
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,48}", by):
            sys.exit("bad --by")
        _restore(arg, by=by)
    elif cmd == "allow-all":
        _, store = _store()
        store.set_general({"allowed_networks": ""})
        _fix_db_owner(store)
        print("sign-in is allowed from any address again")
    elif cmd == "serve":
        import uvicorn

        from .config import load
        s = load()
        uvicorn.run("app.main:app", host=s.listen, port=s.port, proxy_headers=False, log_level="info")
    else:
        sys.exit(__doc__)


def _fix_db_owner(store=None):
    """CLI commands run as root: never leave database files the service can't write."""
    import glob
    import os
    import pwd

    from .config import load
    try:
        u = pwd.getpwnam("gwconsole")
    except KeyError:
        return
    db = load().db_path
    for f in glob.glob(db + "*"):
        try:
            if os.stat(f).st_uid == 0:
                os.chown(f, u.pw_uid, u.pw_gid)
        except OSError:
            pass


def _backup(quiet: bool):
    import os

    from . import __version__, backup
    from .config import load
    base = load()
    etc = os.path.dirname(os.environ.get("GWC_CONFIG", "/etc/gwconsole/config.yaml"))
    path = backup.make(etc, base.db_path, base.audit_log, __version__)
    print(path)
    _, store = _store()
    g = store.general()
    if g.get("backup_copy_node"):
        row = next((n for n in store.node_rows() if n["name"] == g["backup_copy_node"]), None)
        try:
            if not row:
                raise RuntimeError(f"node {g['backup_copy_node']} no longer exists")
            print(backup.copy(path, row, base.ssh_key_file, g["backup_copy_dir"]))
        except (RuntimeError, ValueError, OSError) as e:
            print(f"copy to {g['backup_copy_node']} failed: {e}")
            _fix_db_owner()
            sys.exit(2)
    _fix_db_owner()


def _restore(path: str, yes: bool = True, by: str = "host"):
    """Put a backup back: check it, save the current state first, stop, restore, fix owners, start, and wait
    for the dashboard to answer. If it doesn't come back within 60 s, the saved state is put back (exit 3)."""
    import json
    import os
    import subprocess
    import time
    import urllib.request

    from . import __version__, backup
    from .audit import Audit
    from .config import load
    if os.geteuid() != 0:
        sys.exit("run as root")
    base = load()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)      # never follow a link planted in the spool folder
    except OSError as e:
        sys.exit(f"can't open the backup: {e}")
    with os.fdopen(fd, "rb") as f:
        blob = f.read(backup.MAX_UPLOAD + 1)
    if len(blob) > backup.MAX_UPLOAD:
        sys.exit("not a usable backup: bigger than 200 MB")
    if blob.startswith(backup.MAGIC):
        pw = os.environ.get("GWC_BACKUP_PASSPHRASE") or getpass.getpass("Passphrase: ")
        try:
            blob = backup.decrypt(blob, pw)
        except ValueError as e:
            sys.exit(str(e))
    try:
        info = backup.inspect(blob, name=path)
    except Exception as e:
        sys.exit(f"not a usable backup: {e}")
    if info["version"] and backup.vt(info["version"]) > backup.vt(__version__):
        sys.exit(f"this backup was made by v{info['version']}, newer than the installed v{__version__} — update first, then restore")
    if not info["db_ok"]:
        sys.exit(f"the database in this backup is damaged ({info['db_error']}) — pick another backup")
    print(f"backup made by v{info['version'] or '?'} on {info['created'] or '?'}: {info['files']} files, "
          f"{len(info['users'])} users, {len(info['nodes'])} nodes")
    etc = os.path.dirname(os.environ.get("GWC_CONFIG", "/etc/gwconsole/config.yaml"))

    def fix_and_start():
        for cmd in (["chown", "root:gwconsole", "/etc/gwconsole", "/etc/gwconsole/config.yaml", "/etc/gwconsole/secret.key"],
                    ["chmod", "640", "/etc/gwconsole/config.yaml", "/etc/gwconsole/secret.key"],
                    ["chown", "gwconsole:gwconsole", "/etc/gwconsole/id_ed25519"], ["chmod", "600", "/etc/gwconsole/id_ed25519"],
                    ["chown", "-R", "gwconsole:gwconsole", "/var/lib/gwconsole"]):
            subprocess.run(cmd, check=False, capture_output=True)
        subprocess.run(["systemctl", "start", "gwconsole"], check=False)

    def answers(wait: int = 60) -> bool:
        host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(base.listen, base.listen)
        url, end = f"http://{'[' + host + ']' if ':' in host else host}:{base.port}/api/health", time.time() + wait
        while time.time() < end:
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    if json.loads(r.read()).get("ok"):
                        return True
            except Exception:
                pass
            time.sleep(2)
        return False

    safety = backup.make(etc, base.db_path, base.audit_log, __version__, prefix="before-restore")
    print(f"current state saved first: {safety}")
    Audit(base.audit_log).log(by, "restore start", os.path.basename(path), True, f"saved the current state as {os.path.basename(safety)}")
    subprocess.run(["systemctl", "stop", "gwconsole"], check=False)
    backup.restore(blob)
    fix_and_start()
    if answers():
        Audit(base.audit_log).log(by, "restore done", os.path.basename(path), True,
                                  f"restored a v{info['version'] or '?'} backup from {info['created'] or '?'}; current state saved as {os.path.basename(safety)}")
        print("restored and started — sign in with the accounts from that backup")
        return
    print("!! the dashboard didn't answer within 60 s after the restore — putting the saved state back")
    subprocess.run(["systemctl", "stop", "gwconsole"], check=False)
    backup.restore(backup.open_bytes(safety))
    fix_and_start()
    ok = answers()
    Audit(base.audit_log).log(by, "restore rolled back", os.path.basename(path), False,
                              "the restored dashboard didn't start; the previous state was put back" + ("" if ok else " (and it isn't answering either — check gwconsole logs)"))
    print("rolled back to the state before the restore" + ("" if ok else " — but the dashboard still isn't answering; run: gwconsole logs"))
    sys.exit(3)


async def _check():
    from .cfapi import Cloudflare
    from .inventory import Inventory
    from .sshpool import NodeError, SSHPool
    base, store = _store()
    if store.vault is None:
        sys.exit("secret key missing: re-run install.sh")
    store.import_from_yaml(base)
    s = store.runtime(base)
    pool = SSHPool(s)
    print(f"config OK — {_n(len(s.haproxy_nodes), 'haproxy node')}, {_n(len(s.cloudflared_nodes), 'cloudflared node')}, "
          f"{_n(len(s.cf_accounts), 'CF account')}, {_n(len(store.users()), 'user')}")
    for n in s.haproxy_nodes:
        try:
            r = await pool.run(n, f"{n.haproxy_bin} -v | head -1; command -v socat >/dev/null || echo 'WARN: socat missing'; "
                                  f"test -S {n.stats_socket} || echo 'WARN: stats socket {n.stats_socket} not found'")
            print(f"[ok]   haproxy {n.name}: {r.text}")
        except NodeError as e:
            print(f"[FAIL] haproxy {n.name}: {e}")
    for n in s.cloudflared_nodes:
        try:
            r = await pool.run(n, f"{n.cloudflared_bin} --version | head -1")
            print(f"[ok]   cloudflared {n.name}: {r.text}")
            for t in await Inventory(s, pool).tunnels(n):
                r = await pool.run(n, f"systemctl is-active {t.unit}")
                kind = "token-run" if t.remote else t.config_path
                print(f"       - {t.name} [{t.source}] {t.unit}: {r.text}  ({kind})")
        except NodeError as e:
            print(f"[FAIL] cloudflared {n.name}: {e}")
    cf = Cloudflare(s)
    for a in s.cf_accounts.values():
        try:
            t = await cf.tunnels(a)
            z = await cf.zones(a)
            print(f"[ok]   CF {a.name}: {_n(len(t), 'tunnel')}, {_n(len(z), 'zone')}")
        except Exception as e:
            print(f"[FAIL] CF {a.name}: {e}")
    await cf.close()
    await pool.close()


if __name__ == "__main__":
    main()
