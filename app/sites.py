"""Public hostnames and where they go.

Finds every hostname from tunnel ingress rules and HAProxy host rules, and works out each one's
route end to end: Cloudflare → tunnel → origin service → HAProxy frontend → backend → servers.
Used by the CF Tunnels page (route column, Hostnames tab) and by Monitoring (which sites to check).
"""
from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

from . import configops, hpcfg
from .sshpool import NodeError
from .state import st

HP_TTL = 60
_hp_cache: dict = {"at": 0.0, "nodes": (), "data": {}}
ANY = {"", "*", "0.0.0.0", "::", "[::]"}


async def hp_models(fresh: bool = False) -> dict[str, dict]:
    """node → {host, frontends, backends, error}, parsed from each HAProxy node's config (cached 60 s)."""
    names = tuple(n.name for n in st.s.haproxy_nodes)
    c = _hp_cache
    if not fresh and c["nodes"] == names and time.time() - c["at"] < HP_TTL:
        return c["data"]

    async def one(n):
        try:
            d = hpcfg.parse(await configops.read_file(st.pool, n, n.config_path))
            return n.name, {"host": n.host, "frontends": d["frontends"], "backends": d["backends"], "error": None}
        except (NodeError, OSError, ValueError) as e:
            return n.name, {"host": n.host, "frontends": [], "backends": [], "error": str(e)}

    data = dict(await asyncio.gather(*(one(n) for n in st.s.haproxy_nodes)))
    c.update(at=time.time(), nodes=names, data=data)
    return data


def forget_models():
    _hp_cache["at"] = 0.0


async def hp_view(sc, node: str, model: dict | None = None):
    """One HAProxy node seen through a user's scoped access (scope.HPView)."""
    from .scope import HPView, routes
    if model is None:
        model = (await hp_models()).get(node) or {"frontends": [], "backends": []}
    return HPView(sc, node, model, routes(st.store.db))


async def prime_scope(sc):
    """Work out the user's own backends on every HAProxy node, so text targets (alerts, activity) can be matched."""
    if not sc.all:
        for node, m in (await hp_models()).items():
            await hp_view(sc, node, m)
    return sc


async def filter_hp_status(sc, status: dict) -> dict:
    """Runtime stats of one HAProxy node, cut down to what a scoped user may see; locked backends are marked."""
    if sc.all or not isinstance(status, dict):
        return status
    v = await hp_view(sc, status.get("node", ""))
    out = dict(status)
    out["frontends"] = [f for f in status.get("frontends") or [] if f.get("name") in v.frontends]
    out["backends"] = [{**b, "locked": b.get("name") not in v.own_backends} for b in status.get("backends") or []
                       if v.backend_visible(b.get("name", ""))]
    out["scoped"] = True
    return out


def filter_tunnels(sc, data: dict) -> dict:
    """The CF Tunnels data cut down to a scoped user's tunnels, and their hostnames on other tunnels."""
    if sc.all:
        return data
    nodes = []
    for n in data.get("nodes", []):
        ts = []
        for t in n.get("tunnels", []):
            hosts = [r.get("hostname") or "" for r in (t.get("config") or {}).get("ingress", [])]
            if sc.tunnel_ok(n["node"], t["name"]):
                ts.append({**t, "scope": "full"})
            elif any(sc.host_ok(h) for h in hosts if h):
                cfg = dict(t.get("config") or {})
                cfg["ingress"] = [r for r in cfg.get("ingress", []) if r.get("hostname") and sc.host_ok(r["hostname"])]
                dns = t.get("dns")
                if isinstance(dns, dict):
                    dns = {**dns, "routes": [r for r in dns.get("routes") or [] if sc.host_ok(r.get("hostname", ""))],
                           "orphans": [r for r in dns.get("orphans") or []
                                       if sc.host_ok(r if isinstance(r, str) else r.get("hostname", r.get("name", "")))]}
                week = [0] * len(t.get("requests_week") or [])     # only their hostnames' traffic
                for r in cfg["ingress"]:
                    week = [a + b for a, b in zip(week, r.get("week") or [0] * len(week), strict=False)]
                ts.append({**t, "config": cfg, "dns": dns, "scope": "routes", "requests_week": week,
                           "requests_today": week[-1] if week else 0, "ready_connections": None})
        if ts:
            nodes.append({**n, "tunnels": ts})
    return {**data, "nodes": nodes, "unmanaged": [], "accounts": {}, "scoped": True}


def split_service(service: str) -> tuple[str, str, int | None]:
    """'http://10.0.10.21:8080' → ('http', '10.0.10.21', 8080). Non-network services → (scheme, '', None)."""
    s = (service or "").strip()
    if "://" not in s:
        return s.split(":", 1)[0], "", None
    u = urlsplit(s)
    port = u.port or {"http": 80, "https": 443, "ssh": 22, "rdp": 3389}.get(u.scheme)
    return u.scheme, (u.hostname or ""), port


def _bind_parts(addr: str) -> tuple[str, int | None]:
    a = addr.split("@", 1)[-1]            # ipv4@:80
    host, _, port = a.rpartition(":")
    try:
        return host.strip("[]"), int(port)
    except ValueError:
        return host, None


LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}


def is_loopback(host: str) -> bool:
    return host in LOOPBACK or host.startswith("127.")


def find_frontend(models: dict, ip: str, port: int | None, origin_host: str = "") -> tuple[str, dict] | None:
    """The HAProxy frontend listening on ip:port, if one of the managed nodes is that address.
    A loopback address (localhost) means the machine cloudflared runs on (`origin_host`), so it only
    matches an HAProxy node on that same machine."""
    if not ip or not port:
        return None
    loop = is_loopback(ip)
    for node, m in models.items():
        same = m["host"] == ip or (loop and (m["host"] == origin_host or is_loopback(m["host"])))
        for fe in m["frontends"]:
            for b in fe.get("binds") or []:
                for one in str(b.get("addr", "")).split(","):
                    bip, bport = _bind_parts(one)
                    if bport != port:
                        continue
                    if (bip in ANY and same) or bip == ip and (not loop or same):
                        return node, fe
    return None


def backend_for(fe: dict, hostname: str) -> tuple[str, str]:
    """(backend, 'rule' | 'default' | '') — which backend a request for `hostname` ends up in."""
    h = (hostname or "").lower()
    for r in fe.get("rules") or []:
        if r.get("cond") in ("host", "sni") and r.get("action") == "backend":
            if h in {v.lower() for v in str(r.get("value", "")).split()}:
                return r.get("target", ""), "rule"
    return fe.get("default_backend", ""), ("default" if fe.get("default_backend") else "")


def route(models: dict, hostname: str, service: str, origin_host: str = "") -> dict:
    """Where one ingress rule's traffic goes after cloudflared (`origin_host` = the cloudflared node)."""
    scheme, ip, port = split_service(service)
    kind = "http" if scheme in ("http", "https") else ("tcp" if port else "other")
    r = {"service": service, "kind": kind, "hp_node": "", "frontend": "", "backend": "", "how": "", "direct": True}
    f = find_frontend(models, ip, port, origin_host)
    if f:
        node, fe = f
        be, how = backend_for(fe, hostname)
        r.update(hp_node=node, frontend=fe["name"], backend=be, how=how, direct=False)
    return r


def servers_up(hp_status: list[dict], node: str, backend: str) -> tuple[int, int] | None:
    for n in hp_status:
        if n.get("node") != node:
            continue
        for be in n.get("backends", []):
            if be["name"] == backend:
                srv = be["servers"]
                up = sum(1 for s in srv if s["status"].startswith("UP") or s["status"] == "no check")
                return up, len(srv)
    return None


async def discover(tunnels: dict | None = None) -> list[dict]:
    """Every public hostname: [{host, kind, source, internal, route, tunnel}] (one per hostname)."""
    from .collect import tunnels_full
    if tunnels is None:
        tunnels = await tunnels_full(with_dns=False)
    models = await hp_models()
    out: dict[str, dict] = {}
    for n in tunnels.get("nodes", []):
        for t in n.get("tunnels", []):
            for rule in t["config"].get("ingress", []):
                h = (rule.get("hostname") or "").lower()
                if not h or "*" in h or h in out:
                    continue
                rt = route(models, h, rule.get("service", ""), n.get("host", ""))
                if rt["kind"] == "other":
                    continue
                o = rule.get("origin") or {}
                rt["origin"] = {k: o[k] for k in ("httpHostHeader", "originServerName", "noTLSVerify") if k in o}
                # localhost on the cloudflared machine can only be checked from that machine
                if is_loopback(split_service(rule.get("service", ""))[1]):
                    rt["via_node"] = n["node"]
                out[h] = {"host": h, "kind": rt["kind"], "source": "tunnel", "path": rule.get("path") or "",
                          "internal": rule.get("service", ""), "route": rt,
                          "tunnel": {"node": n["node"], "name": t["name"], "account": t.get("cf_account", "")}}
    for node, m in models.items():                      # hosts HAProxy routes that no tunnel publishes
        for fe in m["frontends"]:
            binds = [_bind_parts(b.get("addr", "").split(",")[0]) + (b.get("ssl"),) for b in fe.get("binds") or []]
            if not binds:
                continue
            for r in fe.get("rules") or []:
                if r.get("cond") not in ("host", "sni") or r.get("action") != "backend":
                    continue
                for h in str(r.get("value", "")).lower().split():
                    if "*" in h or h.startswith(".") or h in out:
                        continue
                    _, port, ssl = binds[0]
                    tcp = fe.get("mode") == "tcp" or r.get("cond") == "sni"
                    scheme = "tcp" if tcp and r.get("cond") != "sni" else ("https" if ssl or r.get("cond") == "sni" else "http")
                    internal = f"{scheme}://{m['host']}:{port}"
                    out[h] = {"host": h, "kind": "tcp" if scheme == "tcp" else "http", "source": "haproxy", "path": "",
                              "internal": internal,
                              "route": {"service": internal, "kind": "http", "hp_node": node, "frontend": fe["name"],
                                        "backend": r.get("target", ""), "how": "rule", "direct": False},
                              "tunnel": None}
    return sorted(out.values(), key=lambda x: x["host"])
