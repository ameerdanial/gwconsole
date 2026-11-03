"""Gateway Console — central dashboard for HAProxy + cloudflared gateways."""
from __future__ import annotations

import asyncio
import functools
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, cloudflared, configops, haproxy, tunnelops
from .audit import Audit
from .auth import Sessions, verify_password
from .cfapi import CFError, Cloudflare
from .config import CFAccount, Settings, Tunnel, load
from .inventory import Inventory
from .sshpool import NodeError, SSHPool

STATIC = Path(__file__).parent / "static"
COOKIE = "gwc_session"


class State:
    s: Settings
    pool: SSHPool
    cf: Cloudflare
    sessions: Sessions
    audit: Audit
    inv: Inventory
    locks: dict


st = State()


@asynccontextmanager
async def lifespan(app: FastAPI):
    st.s = load()
    st.pool = SSHPool(st.s)
    st.cf = Cloudflare(st.s)
    st.sessions = Sessions(st.s.session_hours)
    st.audit = Audit(st.s.audit_log)
    st.inv = Inventory(st.s, st.pool)
    st.locks = {}
    yield
    await st.pool.close()
    await st.cf.close()


app = FastAPI(title="Gateway Console", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ---- auth & error handling --------------------------------------------------
@app.middleware("http")
async def guard(request: Request, call_next):
    p = request.url.path
    if p.startswith("/api/") and p != "/api/login":
        user = st.sessions.get(request.cookies.get(COOKIE))
        if not user:
            return JSONResponse({"error": "not logged in"}, status_code=401)
        if request.method != "GET" and request.headers.get("x-gwc") != "1":
            return JSONResponse({"error": "missing X-GWC header"}, status_code=403)
        request.state.user = user
    resp = await call_next(request)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def shielded(fn):
    """Run a mutating endpoint to completion even if the browser disconnects mid-way."""
    @functools.wraps(fn)
    async def w(*a, **kw):
        return await asyncio.shield(asyncio.ensure_future(fn(*a, **kw)))
    return w


def _ip(r: Request) -> str:
    return r.client.host if r.client else ""


def _audit(r: Request, action: str, target: str, ok: bool, detail: str = ""):
    st.audit.log(getattr(r.state, "user", "?"), action, target, ok, detail, _ip(r))


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.post("/api/login")
async def login(request: Request, body: dict = Body(...)):
    ip = _ip(request)
    if st.sessions.locked(ip):
        return JSONResponse({"error": "too many attempts, wait 5 minutes"}, status_code=429)
    user, pw = str(body.get("user", "")), str(body.get("password", ""))
    stored = st.s.users.get(user)
    if not stored or not verify_password(pw, stored):
        st.sessions.fail(ip)
        await asyncio.sleep(1)
        st.audit.log(user or "?", "login", "-", False, "", ip)
        return JSONResponse({"error": "invalid credentials"}, status_code=401)
    tok = st.sessions.create(user)
    st.audit.log(user, "login", "-", True, "", ip)
    resp = JSONResponse({"user": user})
    resp.set_cookie(COOKIE, tok, httponly=True, samesite="strict", max_age=st.s.session_hours * 3600,
                    secure=request.url.scheme == "https")
    return resp


@app.post("/api/logout")
async def logout(request: Request):
    st.sessions.drop(request.cookies.get(COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/api/me")
async def me(request: Request):
    return {"user": request.state.user, "version": __version__}


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


# ---- aggregation ------------------------------------------------------------
async def _safe(coro, node):
    try:
        return await coro
    except (NodeError, OSError) as e:
        return {"node": node.name, "host": node.host, "site": getattr(node, "site", ""), "error": str(e)}


def _match_edge(cf_tunnels: list[dict], ref: str) -> dict | None:
    if not ref:
        return None
    for t in cf_tunnels:
        if t["id"] == ref or t["name"] == ref:
            return t
    return None


def _tunnel_ref(n_name: str, t: dict) -> str:
    return t["config"].get("tunnel", "") or st.inv.token_ids.get((n_name, t["name"]), "")


def _pick_edge(edge: dict, account: str, ref: str) -> tuple[str, dict | None, str | None]:
    """Find the CF tunnel for a local tunnel: explicit account, else search every account."""
    if account:
        a = edge.get(account) or {"tunnels": [], "error": "unknown account"}
        return account, _match_edge(a["tunnels"], ref), a["error"]
    errs = []
    for name, a in edge.items():
        m = _match_edge(a["tunnels"], ref)
        if m:
            return name, m, None
        if a["error"]:
            errs.append(f"{name}: {a['error']}")
    return "", None, ("; ".join(errs) or None)


async def resolve_edge(n_name: str, t: Tunnel, ref: str) -> tuple[CFAccount | None, dict | None]:
    edge = await st.cf.all_tunnels()
    acc_name, e, _ = _pick_edge(edge, t.cf_account, ref)
    return (st.s.cf_accounts.get(acc_name) if acc_name else None), e


async def _node_status(n):
    ts = await st.inv.tunnels(n)
    return await cloudflared.status(st.pool, n, ts, st.inv.token_ids)


async def tunnels_full(with_dns: bool = True) -> dict:
    nodes, edge = await asyncio.gather(
        asyncio.gather(*(_safe(_node_status(n), n) for n in st.s.cloudflared_nodes)),
        st.cf.all_tunnels())

    async def dns_for(t):
        acc = st.s.cf_accounts.get(t["cf_account"])
        e = t.get("edge")
        if not acc or not e:
            return
        hosts = sorted({r["hostname"] for r in t["config"].get("ingress", []) if r["hostname"]})
        try:
            t["dns"] = await st.cf.route_report(acc, e["id"], hosts)
        except (CFError, httpx.HTTPError) as ex:
            t["dns"] = {"error": str(ex) or type(ex).__name__, "routes": [], "orphans": []}

    jobs, matched = [], set()
    for n in nodes:
        for t in n.get("tunnels", []):
            acc_name, e, err = _pick_edge(edge, t["cf_account"], _tunnel_ref(n["node"], t))
            t["cf_account_auto"] = not t["cf_account"] and bool(acc_name)
            t["cf_account"] = acc_name
            t["edge"], t["edge_error"] = e, (None if e else err)
            if e:
                matched.add(e["id"])
            if with_dns:
                jobs.append(dns_for(t))
    await asyncio.gather(*jobs)
    unmanaged = [{"account": a, **t} for a, v in edge.items() for t in v["tunnels"] if t["id"] not in matched]
    return {"nodes": nodes, "unmanaged": unmanaged,
            "accounts": {k: {"error": v["error"], "count": len(v["tunnels"])} for k, v in edge.items()}}


def build_alerts(hp: list[dict], tun: dict) -> list[dict]:
    a = []

    def add(sev, where, msg):
        a.append({"sev": sev, "where": where, "msg": msg})

    for n in hp:
        if n.get("error"):
            add("crit", n["node"], n["error"])
            continue
        if n["service"]["active"] != "active":
            add("crit", n["node"], f"haproxy service is {n['service']['active']}")
        if n.get("stats_error"):
            add("warn", n["node"], n["stats_error"])
        for be in n.get("backends", []):
            if be.get("status") == "DOWN":
                add("crit", f"{n['node']} / {be['name']}", "backend DOWN — no servers available")
            for s in be["servers"]:
                if s["status"].startswith("DOWN"):
                    add("warn", f"{n['node']} / {be['name']}/{s['name']}",
                        f"server {s['status']} ({s.get('check_status') or 'no check'} {s.get('check_desc') or ''})".strip())
    for acc, v in tun["accounts"].items():
        if v["error"]:
            add("warn", f"CF account {acc}", v["error"])
    for n in tun["nodes"]:
        if n.get("error"):
            add("crit", n["node"], n["error"])
            continue
        for t in n["tunnels"]:
            w = f"{n['node']} / {t['name']}"
            if t["service"]["active"] != "active":
                add("crit", w, f"{t['unit']} is {t['service']['active']}")
            if t["config"].get("error"):
                add("crit", w, t["config"]["error"])
            e = t.get("edge")
            if st.s.cf_accounts and not e and not t.get("edge_error"):
                add("warn", w, "tunnel not found in any configured Cloudflare account (check 'tunnel:' in config.yml)")
            if e and e["status"] in ("down", "inactive"):
                add("crit", w, f"Cloudflare edge status: {e['status']}")
            elif e and e["status"] == "degraded":
                add("warn", w, f"Cloudflare edge status: degraded ({len(e['connections'])} connections)")
            for r in (t.get("dns") or {}).get("routes", []):
                if r["status"] != "ok":
                    add("warn", w, f"DNS {r['hostname']}: {r['detail']}")
    order = {"crit": 0, "warn": 1}
    return sorted(a, key=lambda x: order.get(x["sev"], 2))


@app.get("/api/overview")
async def overview():
    hp, tun = await asyncio.gather(
        asyncio.gather(*(_safe(haproxy.status(st.pool, n), n) for n in st.s.haproxy_nodes)),
        tunnels_full(with_dns=True))
    servers = [s for n in hp for be in n.get("backends", []) for s in be["servers"]]
    tunnels = [t for n in tun["nodes"] for t in n.get("tunnels", [])]
    kpi = {
        "haproxy_up": sum(1 for n in hp if not n.get("error") and n["service"]["active"] == "active"),
        "haproxy_total": len(hp),
        "servers_up": sum(1 for s in servers if s["status"].startswith("UP") or s["status"] == "no check"),
        "servers_total": len(servers),
        "servers_maint": sum(1 for s in servers if "MAINT" in s["status"] or s["status"] == "DRAIN"),
        "tunnels_ok": sum(1 for t in tunnels if t["service"]["active"] == "active"
                          and (not t.get("edge") or t["edge"]["status"] == "healthy")),
        "tunnels_total": len(tunnels),
        "conns": sum(int(n["info"].get("CurrConns") or 0) for n in hp if not n.get("error")),
    }
    return {"kpi": kpi, "alerts": build_alerts(hp, tun), "haproxy": hp, "tunnels": tun}


# ---- HAProxy ----------------------------------------------------------------
@app.get("/api/haproxy/{node}")
async def hp_status(node: str):
    return await haproxy.status(st.pool, st.s.haproxy(node))


@app.post("/api/haproxy/{node}/server")
async def hp_server(request: Request, node: str, body: dict = Body(...)):
    n = st.s.haproxy(node)
    be, srv, state = str(body.get("backend")), str(body.get("server")), str(body.get("state"))
    try:
        msg = await haproxy.set_server_state(st.pool, n, be, srv, state)
    except (NodeError, ValueError) as e:
        _audit(request, f"server→{state}", f"{node}:{be}/{srv}", False, str(e))
        raise
    _audit(request, f"server→{state}", f"{node}:{be}/{srv}", True, msg)
    return {"ok": True, "output": msg}


@app.post("/api/haproxy/{node}/service")
@shielded
async def hp_service(request: Request, node: str, body: dict = Body(...)):
    action = str(body.get("action"))
    r = await haproxy.service_action(st.pool, st.s.haproxy(node), action)
    _audit(request, f"haproxy {action}", node, r["ok"], r["output"])
    return r


@app.get("/api/haproxy/{node}/logs")
async def hp_logs(node: str, source: str = "service", lines: int = 200):
    return {"text": await haproxy.logs(st.pool, st.s.haproxy(node), source, lines)}


# ---- cloudflared --------------------------------------------------------------
@app.get("/api/tunnels")
async def tunnels():
    return await tunnels_full(with_dns=True)


def _lock(node: str) -> asyncio.Lock:
    return st.locks.setdefault(node, asyncio.Lock())


@app.post("/api/tunnels/{node}/{tunnel}/service")
@shielded
async def tun_service(request: Request, node: str, tunnel: str, body: dict = Body(...)):
    n, t = await st.inv.get(node, tunnel)
    action = str(body.get("action"))
    r = await cloudflared.service_action(st.pool, n, t, action)
    _audit(request, f"tunnel {action}", f"{node}:{tunnel}", r["ok"], r["output"])
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
    n, t = await st.inv.get(node, tunnel)
    hostname = str(body.get("hostname", "")).strip().lower()
    lt = await _local_tunnel(n, t)
    if hostname not in {r["hostname"].lower() for r in lt["config"]["ingress"] if r["hostname"]}:
        raise ValueError(f"{hostname} is not an ingress hostname of {tunnel}")
    acc, edge = await resolve_edge(node, t, _tunnel_ref(node, lt))
    if not acc or not edge:
        raise ValueError("tunnel not found in any configured Cloudflare account")
    try:
        msg = await st.cf.route_dns(acc, edge["id"], hostname, overwrite=True)
    except CFError as e:
        _audit(request, "dns route", f"{tunnel}:{hostname}", False, str(e))
        raise
    _audit(request, "dns route", f"{tunnel}:{hostname}", True, msg)
    return {"ok": True, "output": msg}


# ---- tunnel lifecycle ---------------------------------------------------------
@app.post("/api/tunnels/{node}/create")
@shielded
async def tun_create(request: Request, node: str, body: dict = Body(...)):
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
            _audit(request, "tunnel create", f"{node}:{name}", False, "\n".join(steps))
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
    _audit(request, "tunnel create", f"{node}:{name}", True, "\n".join(steps))
    return {"ok": True, "output": "\n".join(steps), "name": name}


@app.post("/api/tunnels/{node}/{tunnel}/delete")
@shielded
async def tun_delete(request: Request, node: str, tunnel: str, body: dict = Body(...)):
    n, t = await st.inv.get(node, tunnel)
    if str(body.get("confirm", "")) != t.name:
        raise ValueError(f"type the tunnel name ({t.name}) to confirm")
    delete_cf, delete_dns = bool(body.get("delete_cf", True)), bool(body.get("delete_dns", False))
    steps: list[str] = []
    async with _lock(node):
        lt = await _local_tunnel(n, t)
        acc, edge = await resolve_edge(node, t, _tunnel_ref(node, lt))
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
    _audit(request, "tunnel delete", f"{node}:{tunnel}", ok, "\n".join(steps))
    return {"ok": ok, "output": "\n".join(steps)}


@app.post("/api/cf/{account}/tunnels/{tunnel_id}/delete")
@shielded
async def cf_tunnel_delete(request: Request, account: str, tunnel_id: str, body: dict = Body(...)):
    """Delete a Cloudflare tunnel that is not running on any managed node."""
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
    _audit(request, "cf tunnel delete", f"{account}:{cf_t['name']}", True, "\n".join(steps))
    return {"ok": True, "output": "\n".join(steps)}


@app.post("/api/tunnels/{node}/{tunnel}/hostname")
@shielded
async def tun_hostname(request: Request, node: str, tunnel: str, body: dict = Body(...)):
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
            acc, edge = await resolve_edge(node, t, _tunnel_ref(node, lt))
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
    _audit(request, f"hostname {action}", f"{node}:{tunnel}:{hostname}", r["ok"], out)
    st.cf.cache.drop_prefix("tun")
    return {"ok": r["ok"], "output": out, "backup": r.get("backup")}


# ---- config editor (generic) ------------------------------------------------
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
async def cfg_validate(kind: str, ref: str, body: dict = Body(...)):
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
    tg = await _target(kind, ref)
    content = str(body.get("content", ""))
    if not content.endswith("\n"):
        content += "\n"
    r = await tg.apply(content, body.get("base_hash"))
    if r["stage"] != "noop":
        _audit(request, "config apply", tg.label, r["ok"],
               f"stage={r['stage']} backup={r.get('backup')} {r.get('diff_stats', '')}\n{r['output']}")
    if r["ok"]:
        r["hash"] = configops.sha(content)
    if kind == "tunnel":
        st.cf.cache.drop_prefix("tun")
    return r


@app.get("/api/cfg/{kind}/{ref}/backups")
async def cfg_backups(kind: str, ref: str):
    return {"backups": await (await _target(kind, ref)).backups()}


@app.get("/api/cfg/{kind}/{ref}/backups/{name}")
async def cfg_backup(kind: str, ref: str, name: str):
    return {"name": name, "content": await (await _target(kind, ref)).read_backup(name)}


# ---- audit ------------------------------------------------------------------
@app.get("/api/audit")
async def audit(n: int = 200):
    return {"items": st.audit.tail(max(1, min(n, 2000)))}


@app.exception_handler(HTTPException)
async def http_exc(request, exc):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


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
