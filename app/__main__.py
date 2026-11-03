"""CLI:  python -m app [serve|hashpw|check|version]"""
from __future__ import annotations

import asyncio
import getpass
import sys


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd in ("version", "--version", "-V"):
        from . import __version__
        print(__version__)
    elif cmd == "hashpw":
        from .auth import hash_password
        pw = getpass.getpass("New password: ")
        if pw != getpass.getpass("Repeat: "):
            sys.exit("passwords do not match")
        if len(pw) < 10:
            sys.exit("use at least 10 characters")
        print(hash_password(pw))
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
    from .config import load
    from .sshpool import NodeError, SSHPool
    from .cfapi import Cloudflare, CFError
    s = load()
    pool = SSHPool(s)
    print(f"config OK — {len(s.haproxy_nodes)} haproxy node(s), {len(s.cloudflared_nodes)} cloudflared node(s), "
          f"{len(s.cf_accounts)} CF account(s)")
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
            from .inventory import Inventory
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
