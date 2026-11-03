"""Command-line entry point.

  python -m app serve                  run the web server (what the systemd unit does)
  python -m app check                  test SSH to every node and every Cloudflare token
  python -m app create-admin [user]    create a superadmin (first install / locked out)
  python -m app reset-password <user>  set a new password for a user
  python -m app users                  list users and roles
  python -m app hashpw                 print a scrypt hash (for config.yaml, legacy)
  python -m app version                print the installed version
"""
from __future__ import annotations

import asyncio
import getpass
import sys


def _ask_password() -> str:
    from .store import check_password_strength
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
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    arg = sys.argv[2] if len(sys.argv) > 2 else ""
    if cmd in ("version", "--version", "-V"):
        from . import __version__
        print(__version__)
    elif cmd == "hashpw":
        from .auth import hash_password
        print(hash_password(_ask_password()))
    elif cmd == "create-admin":
        _, store = _store()
        name = arg or input("Username: ").strip()
        store.create_user(name, _ask_password(), "superadmin", must_change=False)
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
    elif cmd == "users":
        _, store = _store()
        for u in store.users():
            state = "disabled" if u["disabled"] else ("must change pw" if u["must_change"] else "active")
            print(f"{u['username']:<24} {u['role']:<11} {state}")
    elif cmd == "check":
        asyncio.run(_check())
    elif cmd == "serve":
        import uvicorn
        from .config import load
        s = load()
        uvicorn.run("app.main:app", host=s.listen, port=s.port, proxy_headers=False, log_level="info")
    else:
        sys.exit(__doc__)


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
    print(f"config OK — {len(s.haproxy_nodes)} haproxy node(s), {len(s.cloudflared_nodes)} cloudflared node(s), "
          f"{len(s.cf_accounts)} CF account(s), {len(store.users())} user(s)")
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
            print(f"[ok]   CF {a.name}: {len(t)} tunnel(s), {len(z)} zone(s)")
        except Exception as e:
            print(f"[FAIL] CF {a.name}: {e}")
    await cf.close()
    await pool.close()


if __name__ == "__main__":
    main()
