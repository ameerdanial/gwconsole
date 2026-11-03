"""Shared runtime state and request helpers used by every API module:
the live Settings, SSH pool, Cloudflare client, database store, role checks and audit."""
from __future__ import annotations

import asyncio
import functools

from fastapi import HTTPException, Request

from .audit import Audit
from .auth import Sessions
from .cfapi import Cloudflare
from .config import Settings
from .inventory import Inventory
from .sshpool import SSHPool
from .store import ROLE_LEVEL, Store

COOKIE = "gwc_session"


class State:
    base: Settings          # bootstrap settings from config.yaml
    s: Settings             # runtime settings (bootstrap + database)
    store: Store
    pool: SSHPool
    cf: Cloudflare
    logins: Sessions        # brute-force guard for /api/login
    audit: Audit
    inv: Inventory
    locks: dict
    engine: object          # alerts.Engine

    async def reload(self):
        """Rebuild runtime settings after nodes / accounts / general settings change."""
        old_pool, old_cf = self.pool, self.cf
        self.s = self.store.runtime(self.base)
        self.pool = SSHPool(self.s)
        self.cf = Cloudflare(self.s)
        self.inv = Inventory(self.s, self.pool)
        async def _close_later():          # let in-flight operations on the old pool finish
            await asyncio.sleep(120)
            await old_pool.close()
            await old_cf.close()
        asyncio.get_running_loop().create_task(_close_later())


st = State()


def user(request: Request) -> dict:
    return getattr(request.state, "user", None) or {"username": "?", "role": "viewer"}


def need(request: Request, role: str):
    """Raise 403 unless the signed-in user has at least `role`."""
    u = user(request)
    if ROLE_LEVEL.get(u.get("role"), -1) < ROLE_LEVEL[role]:
        raise HTTPException(403, f"your role ({u.get('role')}) can't do this; needs {role}")


def ip(r: Request) -> str:
    return r.client.host if r.client else ""


def audit(r: Request, action: str, target: str, ok: bool, detail: str = ""):
    st.audit.log(user(r).get("username", "?"), action, target, ok, detail, ip(r))


def shielded(fn):
    """Run a mutating endpoint to completion even if the browser disconnects mid-way."""
    @functools.wraps(fn)
    async def w(*a, **kw):
        return await asyncio.shield(asyncio.ensure_future(fn(*a, **kw)))
    return w
