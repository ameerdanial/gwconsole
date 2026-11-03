"""FastAPI application: startup, login and role guard, and the gateway APIs
(overview, HAProxy, tunnels, config editor, activity). Alerts and admin APIs live in
api_alerts.py and api_admin.py."""
from __future__ import annotations

import asyncio
import dataclasses
import logging
import re
import shlex
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, cloudflared, configops, haproxy, history, hpcfg, sites, tunnelops
from .alerts import Engine
from .api_admin import router as admin_router
from .api_alerts import active_alerts, router as alerts_router
from .api_haproxy import router as haproxy_router
from .api_monitor import enrich_tunnels, router as monitor_router
from .api_system import record_running_version, router as system_router, whatsnew_pending
from .audit import Audit
from .auth import Sessions
from .cfapi import CFError, Cloudflare
from .collect import build_alerts, collect_all, kpis, resolve_edge, tunnel_ref, tunnels_full
from .config import load
from .db import DB
from .inventory import Inventory
from .monitor import Monitor
from .sshpool import NodeError, SSHPool
from .state import COOKIE, audit, ip, need, shielded, st, user
from .store import Store, ip_allowed
from .vault import Vault, VaultError

STATIC = Path(__file__).parent / "static"
log = logging.getLogger("gwconsole")
OPEN_PATHS = {"/api/login", "/api/health"}
MUST_CHANGE_OK = {"/api/me", "/api/account/password", "/api/logout"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    base = load()
    db = DB(base.db_path)
    try:
        vault = Vault(base.secret_key_file, create=True)
    except VaultError as e:
        log.error("%s", e)
        raise
    st.base, st.store = base, Store(db, vault)
    imported = st.store.import_from_yaml(base)
    if imported:
        log.warning("imported from config.yaml into the database: %s (manage them in Settings from now on)", imported)
    st.s = st.store.runtime(base)
    st.pool = SSHPool(st.s)
    st.cf = Cloudflare(st.s)
    st.inv = Inventory(st.s, st.pool)
    st.logins = Sessions(1)
    st.audit = Audit(st.s.audit_log)
    st.locks = {}
    if not st.store.users():
        log.error("no users exist yet: run 'gwconsole create-admin' on this host")
    record_running_version()
    configops.ON_APPLIED = lambda node, path, content, stage: history.on_applied(st.store, base.db_path, node, path, content, stage)
    st.engine = Engine()
    st.monitor = Monitor()
    if not getattr(app.state, "no_engine", False):
        st.engine.start()
        st.monitor.start()
    yield
    await st.monitor.stop()
    await st.engine.stop()
    await st.pool.close()
    await st.cf.close()
    db.close()


app = FastAPI(title="Gateway Console", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.include_router(monitor_router)
app.include_router(alerts_router)
app.include_router(admin_router)
app.include_router(haproxy_router)
app.include_router(system_router)


# ---- auth, roles & error handling ---------------------------------------------
@app.middleware("http")
async def guard(request: Request, call_next):
    p = request.url.path
    if p.startswith("/api/") and p not in OPEN_PATHS:
        if st.store and not ip_allowed(ip(request), st.store.general().get("allowed_networks", "")):
            return JSONResponse({"error": "not allowed from this network"}, status_code=403)
        u = st.store.session(request.cookies.get(COOKIE))
        if not u:
            return JSONResponse({"error": "not logged in"}, status_code=401)
        if request.method != "GET" and request.headers.get("x-gwc") != "1":
            return JSONResponse({"error": "missing X-GWC header"}, status_code=403)
        if u["must_change"] and p not in MUST_CHANGE_OK:
            return JSONResponse({"error": "change your password first", "must_change": True}, status_code=403)
        request.state.user = u
        history.ACTOR.set(u["username"])
    resp = await call_next(request)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/prepare-node.sh")
async def prepare_script():
    """The node setup script, so a node can run: curl -fsSL http://<dashboard>/prepare-node.sh | bash -s -- …
    It holds no secrets (the dashboard's public key is passed as an argument)."""
    from .api_admin import PREP_SCRIPT
    return FileResponse(PREP_SCRIPT, media_type="text/x-shellscript")


@app.get("/api/health")
async def health():
    """Unauthenticated liveness probe (install.sh waits on it). Says nothing about nodes."""
    return {"ok": True, "version": __version__}


@app.post("/api/login")
async def login(request: Request, body: dict = Body(...)):
    addr = ip(request)
    g = st.store.general()
    if not ip_allowed(addr, g.get("allowed_networks", "")):
        st.audit.log(str(body.get("user", "?")), "login", "-", False, "address not in allowed networks", addr)
        return JSONResponse({"error": "sign-in isn't allowed from this network"}, status_code=403)
    if st.logins.locked(addr):
        return JSONResponse({"error": "too many attempts, wait 5 minutes"}, status_code=429)
    name, pw = str(body.get("user", "")), str(body.get("password", ""))
    u = st.store.verify(name, pw)
    if not u:
        st.logins.fail(addr)
        await asyncio.sleep(1)
        st.audit.log(name or "?", "login", "-", False, "", addr)
        if st.logins.locked(addr) and g.get("signin_alerts", True):
            asyncio.ensure_future(st.engine.announce(
                f"Sign-in blocked: too many failed attempts from {addr} (last tried user '{name[:40]}'). That address is locked out for 5 minutes."))
        return JSONResponse({"error": "invalid credentials"}, status_code=401)
    seen = st.store.get(f"seen_ips:{u['username']}", []) or []
    if addr not in seen:
        if seen and g.get("signin_alerts", True):
            ua = request.headers.get("user-agent", "")[:80]
            asyncio.ensure_future(st.engine.announce(f"New sign-in: {u['username']} from {addr}, an address not used before ({ua})."))
        st.store.put(f"seen_ips:{u['username']}", ([addr] + seen)[:20])
    tok = st.store.create_session(u["id"], st.s.session_hours, addr, request.headers.get("user-agent", ""))
    st.store.touch_login(u["id"])
    st.audit.log(u["username"], "login", "-", True, "", addr)
    resp = JSONResponse({"user": u["username"], "role": u["role"], "must_change": bool(u["must_change"])})
    resp.set_cookie(COOKIE, tok, httponly=True, samesite="strict", max_age=st.s.session_hours * 3600,
                    secure=request.url.scheme == "https")
    return resp


@app.post("/api/logout")
async def logout(request: Request):
    st.store.drop_session(request.cookies.get(COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/api/me")
async def me(request: Request):
    u = user(request)
    from .api_admin import setup_pending
    return {"user": u["username"], "role": u["role"], "must_change": u["must_change"], "version": __version__,
            "setup": u["role"] == "superadmin" and setup_pending(), "updated": whatsnew_pending(u["username"])}


@app.get("/api/inventory")
async def inventory():
    async def node(n):
        try:
            ts = await st.inv.tunnels(n)
        except (NodeError, OSError):
            ts = []
        return {"name": n.name, "host": n.host, "site": n.site, "base_dir": n.tunnel_base_dir,
                "tunnels": [{"name": t.name, "unit": t.unit, "config_path": t.config_path,
                             "remote": t.remote} for t in ts]}
    return {
        "haproxy": [{"name": n.name, "host": n.host, "site": n.site, "config_path": n.config_path}
                    for n in st.s.haproxy_nodes],
        "cloudflared": await asyncio.gather(*(node(n) for n in st.s.cloudflared_nodes)),
        "cf_accounts": list(st.s.cf_accounts),
    }


# ---- overview ------------------------------------------------------------------
@app.get("/api/overview")
async def overview():
    hp, tun = await collect_all()
    if st.engine.last_run:
        alerts = active_alerts()
    else:  # engine hasn't finished its first round yet: show live evaluation
        alerts = [dict(a, id=None, acked_by=None, muted=False) for a in build_alerts(hp, tun, bool(st.s.cf_accounts))[0]]
    return {"kpi": kpis(hp, tun), "alerts": alerts, "haproxy": hp, "tunnels": tun}


# ---- HAProxy ----------------------------------------------------------------
@app.get("/api/haproxy/{node}")
async def hp_status(node: str):
    n = st.s.haproxy(node)
    out, text = await asyncio.gather(haproxy.status(st.pool, n),
                                     configops.read_file(st.pool, n, n.config_path), return_exceptions=True)
    if isinstance(out, BaseException):
        raise out
    if not isinstance(text, BaseException):
        # servers whose drain / maintenance is written in haproxy.cfg ("kept after restart")
        flags = hpcfg.server_flags(text)
        for be in out.get("backends", []):
            for s in be["servers"]:
                f = flags.get(f"{be['name']}/{s['name']}") or {}
                s["kept"] = "maint" if f.get("disabled") else ("drain" if f.get("weight") == "0" else "")
    return out


async def _persist_state(request: Request, n, be: str, srv: str, state: str) -> str:
    """Write maint → 'disabled', drain → 'weight 0', ready → neither into haproxy.cfg without reloading,
    so the state survives a reload or restart. The original weight is remembered for 'ready'."""
    key = f"hp_weight:{n.name}/{be}/{srv}"
    async with _lock(n.name):
        text = await configops.read_file(st.pool, n, n.config_path)
        cur = hpcfg.server_flags(text).get(f"{be}/{srv}")
        if cur is None:
            raise ValueError(f"server {be}/{srv} is not in {n.config_path} (added at runtime?)")
        if state == "maint":
            new = hpcfg.set_server_flags(text, be, srv, disabled=True)
        elif state == "drain":
            if cur["weight"] != "0":
                st.store.put(key, cur["weight"])
            new = hpcfg.set_server_flags(text, be, srv, disabled=False, weight="0")
        else:
            w = cur["weight"]
            if w == "0":
                w = st.store.get(key, "") or ""
            new = hpcfg.set_server_flags(text, be, srv, disabled=False, weight=w)
            st.store.db.x("DELETE FROM settings WHERE key=?", (key,))
        if new == text:
            return "already in haproxy.cfg"
        svc = shlex.quote(n.service)
        r = await configops.apply(st.pool, n, cfg_path=n.config_path, content=new, base_hash=configops.sha(text),
                                  backup_dir=n.backup_dir, prefix="haproxy.cfg",
                                  validate_cmd=f"{shlex.quote(n.haproxy_bin)} -c -f {{file}}",
                                  activate_cmd="true", check_cmd=f"systemctl is-active --quiet {svc}",
                                  settle=0, keep=st.s.keep_backups)
        sites.forget_models()
        if not r.get("ok"):
            raise ValueError("couldn't save it in haproxy.cfg: " + (r.get("error") or r.get("output") or "failed")[-300:])
        return "saved in haproxy.cfg (no reload needed)"


@app.post("/api/haproxy/{node}/server")
async def hp_server(request: Request, node: str, body: dict = Body(...)):
    need(request, "operator")
    n = st.s.haproxy(node)
    be, srv, state = str(body.get("backend")), str(body.get("server")), str(body.get("state"))
    keep = body.get("keep", True) is not False
    try:
        msg = await haproxy.set_server_state(st.pool, n, be, srv, state)
        if keep:
            msg = f"{msg} · {await _persist_state(request, n, be, srv, state)}"
    except (NodeError, ValueError) as e:
        audit(request, f"server→{state}", f"{node}:{be}/{srv}", False, str(e))
        raise
    audit(request, f"server→{state}{' (kept)' if keep else ''}", f"{node}:{be}/{srv}", True, msg)
    return {"ok": True, "output": msg, "kept": keep}


@app.post("/api/haproxy/{node}/service")
@shielded
async def hp_service(request: Request, node: str, body: dict = Body(...)):
    need(request, "operator")
    action = str(body.get("action"))
    r = await haproxy.service_action(st.pool, st.s.haproxy(node), action)
    audit(request, f"haproxy {action}", node, r["ok"], r["output"])
    return r


INSTALL_SOCAT = ("command -v socat >/dev/null && echo 'socat: present' || { "
                 "if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq socat >/dev/null; "
                 "elif command -v dnf >/dev/null; then dnf install -y -q socat >/dev/null; "
                 "else yum install -y -q socat >/dev/null; fi && echo 'socat: installed' || echo 'socat: install failed'; }")


@app.post("/api/haproxy/{node}/fix-socket")
@shielded
async def hp_fix_socket(request: Request, node: str):
    """Add (or raise to level admin) the stats socket in haproxy.cfg's global section and install
    socat, using the normal safe apply: validate → backup → write → reload → rollback on failure."""
    need(request, "operator")
    n = st.s.haproxy(node)
    tg = haproxy.HAProxyConfig(st.pool, st.s, n)
    steps = []
    async with _lock(node):
        r = await st.pool.run(n, INSTALL_SOCAT, timeout=180, critical=True)
        steps.append(r.out.strip() or r.text)
        cur = await tg.read()
        new, sock, what = haproxy.ensure_admin_socket(cur, n.stats_socket)
        res = {"ok": True, "stage": "noop"}
        if what == "ok":
            steps.append(f"stats socket {sock} is already level admin")
        else:
            await st.pool.run(n, f"mkdir -p {shlex.quote(str(Path(sock).parent))}")
            res = await tg.apply(new, configops.sha(cur))
            steps.append({"applied": f"✔ {'added' if what == 'added' else 'raised to level admin'}: stats socket {sock} "
                                     f"(backup {res.get('backup')}) and reloaded HAProxy",
                          "validate": "✘ haproxy -c rejected the change — nothing changed",
                          "rolled_back": "✘ HAProxy failed to reload — rolled back",
                          "conflict": "✘ haproxy.cfg changed meanwhile — try again"}.get(res["stage"], res["stage"]))
            if not res["ok"]:
                steps.append(res.get("output", ""))
        if res["ok"]:
            await asyncio.sleep(1)
            chk = await st.pool.run(n, f"test -S {shlex.quote(sock)}")
            steps.append(f"✔ socket {sock} is up" if chk.ok else f"⚠ {sock} not present yet — check 'systemctl status {n.service}'")
            if sock != n.stats_socket and chk.ok:
                st.store.save_node("haproxy", dataclasses.replace(n, stats_socket=sock), old_name=n.name)
                await st.reload()
                steps.append(f"✔ node setting updated: stats socket = {sock}")
    ok = res["ok"]
    out = "\n".join(x for x in steps if x)
    audit(request, "haproxy fix-socket", node, ok, f"stage={res['stage']} backup={res.get('backup')}\n{out}")
    return {"ok": ok, "output": out}


@app.get("/api/haproxy/{node}/logs")
async def hp_logs(node: str, source: str = "service", lines: int = 200):
    return {"text": await haproxy.logs(st.pool, st.s.haproxy(node), source, lines)}


# ---- cloudflared --------------------------------------------------------------
@app.get("/api/tunnels")
async def tunnels():
    data, hp = await asyncio.gather(
        tunnels_full(with_dns=True),
        asyncio.gather(*(haproxy.status(st.pool, n) for n in st.s.haproxy_nodes), return_exceptions=True))
    hp = [h for h in hp if isinstance(h, dict)]
    return await enrich_tunnels(data, hp)


def _lock(node: str) -> asyncio.Lock:
    return st.locks.setdefault(node, asyncio.Lock())


@app.post("/api/tunnels/{node}/{tunnel}/service")
@shielded
async def tun_service(request: Request, node: str, tunnel: str, body: dict = Body(...)):
    need(request, "operator")
    n, t = await st.inv.get(node, tunnel)
    action = str(body.get("action"))
    r = await cloudflared.service_action(st.pool, n, t, action)
    audit(request, f"tunnel {action}", f"{node}:{tunnel}", r["ok"], r["output"])
    st.cf.cache.drop_prefix("tun")
    return r


@app.get("/api/tunnels/{node}/{tunnel}/logs")
async def tun_logs(node: str, tunnel: str, lines: int = 200):
    n, t = await st.inv.get(node, tunnel)
    return {"text": await cloudflared.logs(st.pool, n, t, lines)}


@app.post("/api/tunnels/{node}/{tunnel}/test")
async def tun_test(node: str, tunnel: str, body: dict = Body(...)):
    n, t = await st.inv.get(node, tunnel)
    return await cloudflared.test_rule(st.pool, n, t, str(body.get("url", "")))


async def _local_tunnel(n, t) -> dict:
    local = await cloudflared.status(st.pool, n, [t], st.inv.token_ids)
    return local["tunnels"][0]


@app.post("/api/tunnels/{node}/{tunnel}/dns")
@shielded
async def tun_dns(request: Request, node: str, tunnel: str, body: dict = Body(...)):
    need(request, "operator")
    n, t = await st.inv.get(node, tunnel)
    hostname = str(body.get("hostname", "")).strip().lower()
    lt = await _local_tunnel(n, t)
    if hostname not in {r["hostname"].lower() for r in lt["config"]["ingress"] if r["hostname"]}:
        raise ValueError(f"{hostname} is not an ingress hostname of {tunnel}")
    acc, edge = await resolve_edge(node, t, tunnel_ref(node, lt))
    if not acc or not edge:
        raise ValueError("tunnel not found in any configured Cloudflare account")
    try:
        msg = await st.cf.route_dns(acc, edge["id"], hostname, overwrite=True)
    except CFError as e:
        audit(request, "dns route", f"{tunnel}:{hostname}", False, str(e))
        raise
    audit(request, "dns route", f"{tunnel}:{hostname}", True, msg)
    return {"ok": True, "output": msg}


@app.post("/api/tunnels/{node}/{tunnel}/dns/delete")
async def tun_dns_delete(request: Request, node: str, tunnel: str, body: dict = Body(...)):
    """Delete an orphan DNS record: it points at this tunnel but no ingress rule serves it."""
    need(request, "operator")
    n, t = await st.inv.get(node, tunnel)
    hostname = str(body.get("hostname", "")).strip().lower()
    lt = await _local_tunnel(n, t)
    if hostname in {r["hostname"].lower() for r in lt["config"]["ingress"] if r["hostname"]}:
        raise ValueError(f"{hostname} still has an ingress rule — remove the hostname instead")
    acc, edge = await resolve_edge(node, t, tunnel_ref(node, lt))
    if not acc or not edge:
        raise ValueError("tunnel not found in any configured Cloudflare account")
    try:
        gone = await st.cf.delete_records_for_tunnel(acc, edge["id"], only=hostname)
    except CFError as e:
        audit(request, "dns delete", f"{tunnel}:{hostname}", False, str(e))
        raise
    audit(request, "dns delete", f"{tunnel}:{hostname}", bool(gone), ", ".join(gone))
    if not gone:
        raise ValueError(f"no DNS record for {hostname} points at {tunnel}")
    return {"ok": True, "output": f"Deleted {', '.join(gone)}"}


# ---- tunnel lifecycle ---------------------------------------------------------
@app.post("/api/tunnels/{node}/create")
@shielded
async def tun_create(request: Request, node: str, body: dict = Body(...)):
    need(request, "operator")
    n = st.s.cfd(node)
    name = str(body.get("name", "")).strip().lower()
    if not tunnelops.TUNNEL_NAME_RE.match(name):
        raise ValueError("name: 2-40 chars, lowercase letters, digits and dashes")
    acc = st.s.cf_accounts.get(str(body.get("account", "")))
    if not acc:
        raise ValueError("pick a Cloudflare account")
    hostname = str(body.get("hostname") or "").strip().lower()
    service = str(body.get("service") or "").strip()
    if hostname:
        hostname = tunnelops.check_hostname(hostname)
        service = tunnelops.check_service(service)
    route_dns = bool(body.get("route_dns", True))
    steps: list[str] = []
    async with _lock(node):
        existing = await st.inv.tunnels(n, fresh=True)
        if any(t.name == name for t in existing):
            raise ValueError(f"a tunnel named {name} already exists on {node}")
        cf_list = await st.cf.tunnels(acc)
        if any(t["name"] == name for t in cf_list):
            raise ValueError(f"Cloudflare account {acc.name} already has a tunnel named {name}")
        pre = await tunnelops.preflight_create(st.pool, n, name, st.inv.bins.get(n.name, n.cloudflared_bin))
        tid, secret = await st.cf.create_tunnel(acc, name)
        steps.append(f"✔ created tunnel {name} ({tid}) in Cloudflare account {acc.name}")
        try:
            r = await tunnelops.install_tunnel(st.pool, n, name, pre, acc.account_id, tid, secret, hostname, service)
        except Exception as e:  # SSH dropped etc.
            r = {"ok": False, "stage": "ssh", "output": str(e)}
        if not r["ok"]:
            steps.append(f"✘ install on {node} failed at '{r['stage']}':\n{r['output']}")
            try:
                await st.cf.delete_tunnel(acc, tid)
                steps.append("↩ rolled back: deleted the tunnel in Cloudflare; local files removed")
            except (CFError, httpx.HTTPError) as e:
                steps.append(f"⚠ could not delete tunnel {tid} in Cloudflare ({e}) — delete it under 'Not on a managed node'")
            st.inv.invalidate(node)
            audit(request, "tunnel create", f"{node}:{name}", False, "\n".join(steps))
            return {"ok": False, "output": "\n".join(steps)}
        steps.append(f"✔ wrote {pre['dir']}/ (credentials 600, config.yml) and {r['unit']}")
        steps.append(f"✔ {r['unit']} enabled and active")
        if hostname and route_dns:
            try:
                steps.append("✔ " + await st.cf.route_dns(acc, tid, hostname))
            except (CFError, httpx.HTTPError) as e:
                steps.append(f"⚠ DNS route for {hostname} failed: {e} (tunnel is up; use 'Create route' later)")
        st.inv.invalidate(node)
        st.cf.cache.drop_prefix("tun")
    audit(request, "tunnel create", f"{node}:{name}", True, "\n".join(steps))
    return {"ok": True, "output": "\n".join(steps), "name": name}


@app.post("/api/tunnels/{node}/{tunnel}/delete")
@shielded
async def tun_delete(request: Request, node: str, tunnel: str, body: dict = Body(...)):
    need(request, "operator")
    n, t = await st.inv.get(node, tunnel)
    if str(body.get("confirm", "")) != t.name:
        raise ValueError(f"type the tunnel name ({t.name}) to confirm")
    delete_cf, delete_dns = bool(body.get("delete_cf", True)), bool(body.get("delete_dns", False))
    steps: list[str] = []
    async with _lock(node):
        lt = await _local_tunnel(n, t)
        acc, edge = await resolve_edge(node, t, tunnel_ref(node, lt))
        creds = str(lt["config"].get("credentials_file") or "")
        res = await tunnelops.remove_local(st.pool, n, t, creds, st.inv.fragments.get((node, t.name), ""))
        steps.append(res["output"])
        steps.append(f"✔ files archived in {res['archive']} on {node}")
        if (delete_cf or delete_dns) and not (acc and edge):
            steps.append("⚠ tunnel not found in any configured Cloudflare account — nothing deleted there")
        if acc and edge:
            if delete_dns:
                try:
                    gone = await st.cf.delete_records_for_tunnel(acc, edge["id"])
                    steps.append(f"✔ deleted DNS records: {', '.join(gone) if gone else 'none pointed at this tunnel'}")
                except (CFError, httpx.HTTPError) as e:
                    steps.append(f"⚠ DNS cleanup failed: {e}")
            if delete_cf:
                try:
                    await asyncio.sleep(2)  # let the edge notice the connector is gone
                    steps.append("✔ " + await st.cf.delete_tunnel(acc, edge["id"]))
                except (CFError, httpx.HTTPError) as e:
                    steps.append(f"⚠ Cloudflare delete failed: {e} — retry under 'Not on a managed node'")
        st.inv.invalidate(node)
        st.cf.cache.drop_prefix("tun")
    ok = not any(x.startswith("⚠") for x in steps)
    audit(request, "tunnel delete", f"{node}:{tunnel}", ok, "\n".join(steps))
    return {"ok": ok, "output": "\n".join(steps)}


@app.post("/api/cf/{account}/tunnels/{tunnel_id}/delete")
@shielded
async def cf_tunnel_delete(request: Request, account: str, tunnel_id: str, body: dict = Body(...)):
    """Delete a Cloudflare tunnel that is not running on any managed node."""
    need(request, "operator")
    acc = st.s.cf_accounts.get(account)
    if not acc:
        raise KeyError(f"unknown account {account}")
    tun = await tunnels_full(with_dns=False)
    if any(t.get("edge") and t["edge"]["id"] == tunnel_id for nd in tun["nodes"] for t in nd.get("tunnels", [])):
        raise ValueError("this tunnel runs on a managed node — use its Delete button on that node instead")
    cf_t = next((t for t in await st.cf.tunnels(acc) if t["id"] == tunnel_id), None)
    if not cf_t:
        raise KeyError("tunnel not found")
    if str(body.get("confirm", "")) != cf_t["name"]:
        raise ValueError(f"type the tunnel name ({cf_t['name']}) to confirm")
    if cf_t["connections"]:
        ips = ", ".join(sorted({c["origin_ip"] for c in cf_t["connections"] if c["origin_ip"]}))
        raise ValueError(f"{cf_t['name']} still has live connections (from {ips or 'unknown'}) — it is running somewhere. "
                         "Stop that cloudflared first.")
    steps = []
    if body.get("delete_dns"):
        gone = await st.cf.delete_records_for_tunnel(acc, tunnel_id)
        steps.append(f"✔ deleted DNS records: {', '.join(gone) if gone else 'none'}")
    steps.append("✔ " + await st.cf.delete_tunnel(acc, tunnel_id, cleanup_connections=False))
    audit(request, "cf tunnel delete", f"{account}:{cf_t['name']}", True, "\n".join(steps))
    return {"ok": True, "output": "\n".join(steps)}


@app.post("/api/tunnels/{node}/{tunnel}/hostname")
@shielded
async def tun_hostname(request: Request, node: str, tunnel: str, body: dict = Body(...)):
    need(request, "operator")
    n, t = await st.inv.get(node, tunnel)
    action = str(body.get("action", ""))
    hostname = tunnelops.check_hostname(str(body.get("hostname", "")))
    tg = cloudflared.TunnelConfig(st.pool, st.s, n, t)
    async with _lock(node):
        cur = await tg.read()
        new = tunnelops.edit_ingress(cur, action, hostname, service=str(body.get("service", "")),
                                     path=str(body.get("path") or ""), no_tls_verify=bool(body.get("no_tls_verify")),
                                     http_host_header=str(body.get("http_host_header") or ""))
        r = await tg.apply(new, configops.sha(cur))
        notes = []
        if r["ok"] and (body.get("route_dns") if action == "add" else body.get("delete_dns")):
            lt = await _local_tunnel(n, t)
            acc, edge = await resolve_edge(node, t, tunnel_ref(node, lt))
            try:
                if not acc or not edge:
                    raise CFError("tunnel not found in any configured Cloudflare account")
                if action == "add":
                    notes.append("✔ " + await st.cf.route_dns(acc, edge["id"], hostname))
                else:
                    gone = await st.cf.delete_records_for_tunnel(acc, edge["id"], only=hostname)
                    notes.append(f"✔ deleted DNS record {hostname}" if gone else f"DNS: no CNAME for {hostname} pointed at this tunnel")
            except (CFError, httpx.HTTPError) as e:
                notes.append(f"⚠ DNS step failed: {e}")
    head = {"applied": f"✔ {hostname} {'added to' if action == 'add' else 'removed from'} {tunnel}; tunnel restarted",
            "validate": "✘ validation failed — nothing changed",
            "rolled_back": "✘ tunnel failed to start — rolled back to the previous config",
            "conflict": "✘ config changed on the server meanwhile — try again"}.get(r["stage"], r["stage"])
    out = "\n".join([head, *notes, "", r.get("output", "")]).strip()
    audit(request, f"hostname {action}", f"{node}:{tunnel}:{hostname}", r["ok"],
          f"stage={r['stage']} backup={r.get('backup')} {r.get('diff_stats', '')}\n{out}")
    st.cf.cache.drop_prefix("tun")
    return {"ok": r["ok"], "output": out, "backup": r.get("backup")}


# ---- config editor (generic; opened as a side panel in the UI) -------------------
async def _target(kind: str, ref: str):
    if kind == "haproxy":
        return haproxy.HAProxyConfig(st.pool, st.s, st.s.haproxy(ref))
    if kind == "tunnel":
        node, _, tun = ref.partition(":")
        n, t = await st.inv.get(node, tun)
        return cloudflared.TunnelConfig(st.pool, st.s, n, t)
    raise KeyError(f"unknown config kind {kind}")


@app.get("/api/cfg/{kind}/{ref}")
async def cfg_read(kind: str, ref: str):
    tg = await _target(kind, ref)
    content = await tg.read()
    return {"label": tg.label, "path": tg.path, "content": content, "hash": configops.sha(content)}


@app.post("/api/cfg/{kind}/{ref}/validate")
async def cfg_validate(request: Request, kind: str, ref: str, body: dict = Body(...)):
    need(request, "operator")
    return await (await _target(kind, ref)).validate(str(body.get("content", "")))


@app.post("/api/cfg/{kind}/{ref}/diff")
async def cfg_diff(kind: str, ref: str, body: dict = Body(...)):
    tg = await _target(kind, ref)
    cur = await tg.read()
    content = str(body.get("content", ""))
    if not content.endswith("\n"):
        content += "\n"
    d = configops.unified_diff(cur, content, tg.path)
    return {"diff": d, **configops.diff_stats(d), "current_hash": configops.sha(cur)}


@app.post("/api/cfg/{kind}/{ref}/apply")
@shielded
async def cfg_apply(request: Request, kind: str, ref: str, body: dict = Body(...)):
    need(request, "operator")
    tg = await _target(kind, ref)
    content = str(body.get("content", ""))
    if not content.endswith("\n"):
        content += "\n"
    history.NOTE.set(str(body.get("note") or "")[:120])
    r = await tg.apply(content, body.get("base_hash"))
    if r["stage"] != "noop":
        note = str(body.get("note") or "")[:120]
        audit(request, "config apply", tg.label, r["ok"],
              f"stage={r['stage']} backup={r.get('backup')} {r.get('diff_stats', '')}"
              f"{' note=' + note if note else ''}\n{r['output']}")
    if r["ok"]:
        r["hash"] = configops.sha(content)
    if kind == "tunnel":
        st.cf.cache.drop_prefix("tun")
    return r


BACKUP_RE = re.compile(r"backup=(\S+)")
STATS_RE = re.compile(r"'added': (\d+), 'removed': (\d+)")


@app.get("/api/cfg/{kind}/{ref}/backups")
async def cfg_backups(kind: str, ref: str):
    """Backups, enriched from the audit log with who made the change that created each one."""
    items = await (await _target(kind, ref)).backups()
    by_backup = {}
    for a in st.audit.tail(3000):
        m = BACKUP_RE.search(a.get("detail") or "")
        if m and m.group(1) not in ("None", ""):
            s = STATS_RE.search(a["detail"])
            by_backup.setdefault(m.group(1), {"user": a["user"], "action": a["action"], "target": a["target"],
                                              "added": int(s.group(1)) if s else None,
                                              "removed": int(s.group(2)) if s else None, "ok": a["ok"]})
    for b in items:
        b["change"] = by_backup.get(b["name"])
    return {"backups": items}


@app.get("/api/cfg/{kind}/{ref}/backups/{name}")
async def cfg_backup(kind: str, ref: str, name: str):
    return {"name": name, "content": await (await _target(kind, ref)).read_backup(name)}


# ---- activity -------------------------------------------------------------------
@app.get("/api/audit")
async def audit_list(n: int = 200):
    return {"items": st.audit.tail(max(1, min(n, 2000)))}


@app.exception_handler(HTTPException)
async def http_exc(request, exc):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def req_exc(request, exc):
    first = (exc.errors() or [{}])[0]
    where = ".".join(str(x) for x in first.get("loc", []) if x not in ("body", "path", "query"))
    return JSONResponse({"error": f"invalid request{' (' + where + ')' if where else ''}: {first.get('msg', '')}"},
                        status_code=422)


@app.exception_handler(NodeError)
async def node_exc(request, exc):
    return JSONResponse({"error": str(exc)}, status_code=502)


@app.exception_handler(CFError)
async def cf_exc(request, exc):
    return JSONResponse({"error": f"Cloudflare: {exc}"}, status_code=502)


@app.exception_handler(KeyError)
async def key_exc(request, exc):
    return JSONResponse({"error": str(exc).strip("'\"")}, status_code=404)


@app.exception_handler(ValueError)
async def val_exc(request, exc):
    return JSONResponse({"error": str(exc)}, status_code=400)


@app.exception_handler(VaultError)
async def vault_exc(request, exc):
    return JSONResponse({"error": str(exc)}, status_code=500)
